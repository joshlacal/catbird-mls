//! Complete account-level group leaves using the requester's durable consent.
//!
//! A leave remains pending until another account removes every requester leaf
//! in an MLS Commit. Inventory is only discovery; a fresh point read supplies
//! the exact current consent, coordinates, device roster, and metadata.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::api_client::MLSAPIClient;
use super::canonical_transport::{
    canonical_commit_aad_bytes, CanonicalOperation, CleanChatSigningContext,
};
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::lifecycle::lifecycle_coordinates;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::pagination::PaginationGuard;
use super::storage::MLSStorageBackend;

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(message.into())
}

fn bytes(value: &Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .or_else(|| value["$bytes"].as_str())
        .ok_or_else(|| invalid("Group leave state contains missing cryptographic bytes."))?;
    STANDARD
        .decode(encoded)
        .map_err(|e| OrchestratorError::Serialization(e.to_string()))
}

/// Select one request against a single authoritative state. Processing a
/// request changes the state version, so the caller re-reads before any later
/// attempt and never submits multiple requests from an obsolete snapshot.
fn eligible_request<'a>(
    response: &'a Value,
    cid: &str,
    did: &str,
    device: &str,
) -> Result<Option<&'a Value>> {
    let state = &response["state"];
    if state["conversationKind"] != "group" {
        return Ok(None);
    }
    let prior = lifecycle_coordinates(&state["coordinates"], cid)?;
    if prior["lifecycle"] != "active" {
        return Ok(None);
    }
    let participants = state["participants"]
        .as_array()
        .ok_or_else(|| invalid("Group participants are missing."))?;
    let leaves = state["leaves"]
        .as_array()
        .ok_or_else(|| invalid("Group device membership is missing."))?;
    if !participants
        .iter()
        .any(|p| p["userDid"] == did && p["status"] == "active")
        || !leaves.iter().any(|l| {
            l["userDid"] == did && l["deviceId"] == device && l["deviceStatus"] == "active"
        })
    {
        return Ok(None);
    }
    let Some(requests) = response["pendingLeaveRequests"].as_array() else {
        return Ok(None);
    };
    Ok(requests.iter().find(|request| {
        let Some(requester) = request["requesterDid"].as_str().filter(|r| *r != did) else {
            return false;
        };
        let Some(participant) = participants
            .iter()
            .find(|p| p["userDid"] == requester && p["status"] == "active")
        else {
            return false;
        };
        let last_admin = participant["role"] == "admin"
            && !participants.iter().any(|p| {
                p["userDid"] != requester && p["status"] == "active" && p["role"] == "admin"
            });
        !last_admin
            && leaves.iter().any(|l| l["userDid"] == requester)
            && request["conversationId"] == cid
            && request["status"] == "pending"
            && request["leaveRequestId"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            && request["expiresAt"]
                .as_str()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .is_some_and(|t| t > chrono::Utc::now())
            && lifecycle_coordinates(&request["prior"], cid).ok().as_ref() == Some(&prior)
    }))
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Find pending leaves across the entire paginated conversation inventory.
    /// A broken conversation must not prevent progress in healthy groups.
    pub async fn fulfill_pending_group_leaves(&self) -> Result<usize> {
        self.check_shutdown().await?;
        let mut cursor = None;
        let mut ids = HashSet::new();
        let mut pagination = PaginationGuard::for_conversations("pending group leaves");
        loop {
            let page = self
                .api_client()
                .get_conversations(100, cursor.as_deref())
                .await?;
            pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
            ids.extend(page.conversations.into_iter().map(|c| c.conversation_id));
            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }
        let mut fulfilled = 0;
        for cid in ids {
            self.check_shutdown().await?;
            match self.fulfill_pending_group_leave(&cid).await {
                Ok(true) => fulfilled += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(conversation_id = %cid, %error, "Pending group leave remains unfulfilled")
                }
            }
        }
        Ok(fulfilled)
    }

    /// Fulfill at most one exact, current request. `true` means the server
    /// confirmed the removal and the new local epoch was durably projected.
    pub async fn fulfill_pending_group_leave(&self, conversation_id: &str) -> Result<bool> {
        self.check_shutdown().await?;
        // Follow the receive path's lock order: incoming Commit processing
        // must not advance the group while this Commit waits for its ACK.
        let inbound_lock = self.inbound_processing_lock(conversation_id).await;
        let Ok(_inbound_guard) = inbound_lock.try_lock() else {
            return Ok(false);
        };
        let lock = self.rejoin_lock(conversation_id).await;
        let Ok(_guard) = lock.try_lock() else {
            return Ok(false);
        };
        if self
            .reset_blocks_non_reset_transition_locked(conversation_id)
            .await?
        {
            return Ok(false);
        }
        if let Ok(resolved) = self.resolve_conversation_context(conversation_id).await {
            if let Some(output) = self
                .replay_prepared_control_locked(&resolved.group_id)
                .await?
            {
                return Ok(output["entry"]["$type"]
                    == "blue.catbird.chat.defs#leaveCommitFulfillmentEntry");
            }
        }
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let response = self.fetch_conversation_lifecycle(conversation_id).await?;
        let Some(request) = eligible_request(&response, conversation_id, &did, &device)? else {
            return Ok(false);
        };
        let requester = request["requesterDid"].as_str().unwrap();
        let state = &response["state"];
        let snapshot_seq = state["snapshotSeq"]
            .as_u64()
            .filter(|seq| (1..=9_007_199_254_740_991).contains(seq))
            .ok_or_else(|| invalid("Group state is missing its authoritative entry sequence."))?;
        let prior = lifecycle_coordinates(&state["coordinates"], conversation_id)?;
        let group = bytes(&prior["groupId"])?;
        let group_hex = hex::encode(&group);
        if self
            .pending_staged_commits()
            .lock()
            .await
            .contains_key(&group_hex)
        {
            return Ok(false);
        }
        let epoch = self.mls_context().get_epoch(group.clone())?;
        if epoch != prior["epoch"].as_u64().unwrap()
            || self.mls_context().get_confirmation_tag(group.clone())?
                != bytes(&prior["confirmationTag"])?
            || self.mls_context().get_group_context_hash(group.clone())?
                != bytes(&prior["groupContextHash"])?
        {
            return Err(invalid(
                "Sync this group's latest messages before completing a member's leave.",
            ));
        }
        let identities = self.mls_context().group_member_identities(group.clone())?;
        let expected_actor = format!("{did}#{device}").into_bytes();
        if !identities.contains(&expected_actor) {
            return Ok(false);
        }
        let mut device_ids = state["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|leaf| leaf["userDid"] == requester)
            .map(|leaf| {
                leaf["deviceId"]
                    .as_str()
                    .ok_or_else(|| invalid("Requester leaf is missing its device ID."))
                    .and_then(|id| {
                        uuid::Uuid::parse_str(id)
                            .map_err(|_| invalid("Requester leaf has an invalid device ID."))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        device_ids.sort();
        if device_ids.is_empty()
            || device_ids.len() > 100
            || device_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(invalid("Requester device membership is inconsistent."));
        }
        let removals: Vec<Vec<u8>> = device_ids
            .iter()
            .map(|id| format!("{requester}#{id}").into_bytes())
            .collect();
        let local_requester: HashSet<_> = identities
            .iter()
            .filter(|id| {
                std::str::from_utf8(id).ok().is_some_and(|id| {
                    super::credential_binding::credential_root_did(id) == requester
                })
            })
            .cloned()
            .collect();
        if local_requester != removals.iter().cloned().collect() {
            return Err(invalid(
                "Sync this group's device membership before completing a member's leave.",
            ));
        }
        let mut projection = self
            .storage()
            .get_group_state(&group_hex)
            .await?
            .ok_or_else(|| {
                invalid("Group state is missing; sync before completing a member's leave.")
            })?;
        if projection.epoch != epoch {
            return Err(invalid("Group state is not yet synchronized."));
        }
        let next_epoch = epoch
            .checked_add(1)
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or_else(|| invalid("Group epoch limit reached."))?;
        let next_version = prior["stateVersion"]
            .as_u64()
            .unwrap()
            .checked_add(1)
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or_else(|| invalid("Group state version limit reached."))?;
        let mut snapshot = state["metadataSnapshot"].clone();
        let version = snapshot["metadataVersion"]
            .as_u64()
            .ok_or_else(|| invalid("Group metadata version is missing."))?;
        let metadata = self.decrypt_metadata_snapshot_value(&snapshot, &group, version)?;
        let prior_nonce = bytes(&snapshot["nonce"])?;
        let cid = uuid::Uuid::parse_str(conversation_id)
            .map_err(|_| invalid("Conversation ID is invalid."))?;
        let transition = uuid::Uuid::new_v4();
        let mut aad_prior = prior.clone();
        aad_prior["conversationId"] = json!(STANDARD.encode(cid.as_bytes()));
        let aad = json!({"conversationId": STANDARD.encode(cid.as_bytes()), "generation": prior["generation"], "protocolVersion":"1", "transitionId": STANDARD.encode(transition.as_bytes()), "prior": aad_prior});
        let aad_bytes = canonical_commit_aad_bytes(&aad)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(identity.as_bytes().to_vec())?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&did)
            .await?
            .filter(|n| *n >= 1)
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        let removed =
            self.mls_context()
                .remove_members_with_aad(group.clone(), removals, Some(aad_bytes))?;
        // Before submission a failed build can discard its pending commit.
        // Once submitted, cancellation or a lost response must preserve the
        // pending MLS state: one's own accepted Commit cannot be reprocessed
        // after that state is discarded.
        let may_discard = AtomicBool::new(true);
        let cleanup = scopeguard::guard((), |_| {
            if may_discard.load(Ordering::Relaxed) {
                let _ = self.mls_context().clear_pending_commit(group.clone());
            }
        });
        let tag = removed
            .next_confirmation_tag
            .ok_or_else(|| invalid("Removal produced no confirmation tag."))?;
        let context_hash = removed
            .next_group_context_hash
            .ok_or_else(|| invalid("Removal produced no group context hash."))?;
        let mut next = prior.clone();
        next["epoch"] = json!(next_epoch);
        next["stateVersion"] = json!(next_version);
        next["confirmationTag"] = json!(STANDARD.encode(&tag));
        next["groupContextHash"] = json!(STANDARD.encode(&context_hash));
        let key: [u8; 32] = self
            .mls_context()
            .export_metadata_key_from_pending(group.clone(), next_epoch)?
            .try_into()
            .map_err(|_| invalid("Pending metadata key length is invalid."))?;
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        if prior_nonce == nonce {
            nonce[0] ^= 1;
        }
        let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
            &key, &group, next_epoch, version, &nonce, &metadata,
        )
        .map_err(|e| invalid(&format!("Could not encrypt group metadata: {e:?}")))?;
        if ciphertext.len() != bytes(&snapshot["ciphertext"])?.len() {
            return Err(invalid("Removal unexpectedly changed group metadata."));
        }
        snapshot["coordinate"] = json!({"conversationId":STANDARD.encode(cid.as_bytes()), "generation":next["generation"], "groupId":next["groupId"], "epoch":next_epoch, "groupContextHash":next["groupContextHash"], "confirmationTag":next["confirmationTag"]});
        snapshot["nonce"] = json!(STANDARD.encode(nonce));
        snapshot["ciphertext"] = json!(STANDARD.encode(&ciphertext));
        snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&ciphertext)));
        snapshot["ciphertextSize"] = json!(ciphertext.len());
        let body = json!({
            "$type":"blue.catbird.chat.defs#leaveCommitFulfillmentBody", "signatureDomain":"CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0",
            "leaveRequestId":request["leaveRequestId"], "transitionId":transition.to_string(), "idempotencyKey":transition.to_string(),
            "actorDid":did, "actorDeviceId":device, "authGeneration":auth_generation,
            "keyId":super::canonical_transport::derive_key_id(&public_key), "prior":prior, "next":next, "aad":aad,
            "manifest":{"participantChanges":[{"$type":"blue.catbird.chat.defs#removeParticipant","userDid":requester}], "leafChanges":device_ids.iter().map(|id| json!({"$type":"blue.catbird.chat.defs#removeLeaf","userDid":requester,"deviceId":id.to_string()})).collect::<Vec<_>>()},
            "commit":{"framing":"mlsMessage","contentType":"publicMessageCommit","bytes":STANDARD.encode(&removed.commit_data),"sha256":STANDARD.encode(Sha256::digest(&removed.commit_data))},
            "metadataSnapshot":snapshot, "signedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)
        });
        let prepared = self
            .prepare_clean_chat_signed_request(
                CleanChatSigningContext {
                    actor_did: did.clone(),
                    device_id: device.clone(),
                    auth_generation: Some(auth_generation),
                },
                CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        projection.conversation_id = conversation_id.into();
        projection.group_id = group_hex.clone();
        projection.epoch = next_epoch;
        projection
            .members
            .retain(|id| super::credential_binding::credential_root_did(id) != requester);
        // A journal write can fail after becoming durable. Preserve MLS pending
        // state before attempting it, including cancellation during persistence.
        may_discard.store(false, Ordering::Relaxed);
        self.journal_prepared_control_with_snapshot(prepared, projection, snapshot_seq)
            .await?;
        let confirmed = self
            .replay_prepared_control_locked(&group_hex)
            .await?
            .is_some();
        scopeguard::ScopeGuard::into_inner(cleanup);
        if confirmed {
            self.cleanup_epoch_secrets_if_needed(conversation_id, &group_hex, next_epoch)
                .await;
        }
        Ok(confirmed)
    }
}
