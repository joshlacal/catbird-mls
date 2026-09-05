//! Account moderation keeps MLS device removal and participant policy separate.
//! The epoch-changing step is journaled before transport. A failed policy step
//! leaves a truthful zero-leaf participant and can be retried without another
//! MLS Commit; there is no successful account-removal result until fresh state
//! confirms that every requested participant has gone.
use super::canonical_transport::{
    canonical_commit_aad_bytes, CanonicalOperation, CleanChatSigningContext,
};
use super::lifecycle::lifecycle_coordinates;
use super::{
    api_client::MLSAPIClient,
    credentials::CredentialStore,
    error::{OrchestratorError, Result},
    mls_provider::MlsCryptoContext,
    orchestrator::MLSOrchestrator,
    storage::MLSStorageBackend,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(message.into())
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    value
        .as_str()
        .or_else(|| value["$bytes"].as_str())
        .and_then(|v| STANDARD.decode(v).ok())
        .ok_or_else(|| invalid("Group state contains missing cryptographic bytes."))
}
fn authorize<'a>(state: &'a Value, cid: &str, did: &str, device: &str) -> Result<&'a Vec<Value>> {
    if state["conversationKind"] != "group"
        || lifecycle_coordinates(&state["coordinates"], cid)?["lifecycle"] != "active"
    {
        return Err(invalid(
            "Members can only be removed from an active group conversation.",
        ));
    }
    let participants = state["participants"]
        .as_array()
        .ok_or_else(|| invalid("Group participants are missing."))?;
    let leaves = state["leaves"].as_array().ok_or_else(|| {
        invalid("Group device membership is missing. Sync before removing a member.")
    })?;
    if !participants
        .iter()
        .any(|p| p["userDid"] == did && p["status"] == "active" && p["role"] == "admin")
        || !leaves.iter().any(|l| {
            l["userDid"] == did && l["deviceId"] == device && l["deviceStatus"] == "active"
        })
    {
        return Err(invalid(
            "An active group administrator device is required to remove members.",
        ));
    }
    Ok(participants)
}
impl<
        S: MLSStorageBackend + 'static,
        A: MLSAPIClient + 'static,
        C: CredentialStore + 'static,
        M: MlsCryptoContext + 'static,
    > MLSOrchestrator<S, A, C, M>
{
    /// Remove account membership, including every currently admitted device.
    pub async fn remove_accounts(
        &self,
        conversation_id: &str,
        member_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        if member_dids.is_empty() {
            return Ok(());
        }
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let accounts: BTreeSet<String> = member_dids
            .iter()
            .map(|id| super::credential_binding::credential_root_did(id).to_string())
            .collect();
        if accounts.len() != member_dids.len() || accounts.len() > 100 || accounts.contains(&did) {
            return Err(invalid(
                "Choose distinct other members to remove; use Leave to exit yourself.",
            ));
        }
        let resolved = self
            .resolve_legacy_group_identifier(conversation_id)
            .await?;
        let conversation_id = resolved.conversation_id.as_str();
        let inbound = self.inbound_processing_lock(conversation_id).await;
        let _inbound_guard = inbound.lock().await;
        let transition = self.rejoin_lock(conversation_id).await;
        let _transition_guard = transition.lock().await;
        if self
            .reset_blocks_non_reset_transition_locked(conversation_id)
            .await?
            || self.is_local_conversation_terminal(conversation_id).await?
        {
            return Err(invalid("Restore active access before removing a member."));
        }
        self.replay_prepared_control_locked(&resolved.group_id)
            .await?;
        let response = self.fetch_conversation_lifecycle(conversation_id).await?;
        let state = &response["state"];
        let participants = authorize(state, conversation_id, &did, &device)?;
        let prior = lifecycle_coordinates(&state["coordinates"], conversation_id)?;
        let group = bytes(&prior["groupId"])?;
        let group_hex = hex::encode(&group);
        if group_hex != resolved.group_id {
            return Err(invalid("Sync the current group before removing a member."));
        }
        if !accounts
            .iter()
            .any(|target| participants.iter().any(|p| p["userDid"] == *target))
        {
            if let Some(conversation) = self.conversations().lock().await.get_mut(conversation_id) {
                conversation.members.retain(|member| {
                    !accounts.contains(super::credential_binding::credential_root_did(&member.did))
                });
            }
            return Ok(());
        }
        if !self
            .device_group_matches_current_state(conversation_id, state)
            .await?
        {
            return Err(invalid(
                "Sync the group's latest messages before removing a member.",
            ));
        }
        if self
            .pending_staged_commits()
            .lock()
            .await
            .contains_key(&group_hex)
        {
            return Err(invalid(
                "A group update is still pending. Sync before removing a member.",
            ));
        }
        let mut targets = Vec::new();
        for leaf in state["leaves"].as_array().unwrap() {
            let target = leaf["userDid"]
                .as_str()
                .ok_or_else(|| invalid("Group member identity is missing."))?;
            if accounts.contains(target) {
                let id = uuid::Uuid::parse_str(leaf["deviceId"].as_str().unwrap_or_default())
                    .map_err(|_| invalid("Group member device ID is invalid."))?;
                targets.push((target.to_string(), id));
            }
        }
        targets.sort();
        if targets.len() > 100 || targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("Group device membership is inconsistent."));
        }
        if !targets.is_empty() {
            self.remove_account_leaves_locked(
                conversation_id,
                state,
                &prior,
                &accounts,
                &targets,
                &did,
                &device,
            )
            .await?;
        }
        // The generic Commit deliberately leaves participants active. Re-read
        // policy authority and the zero-leaf condition after its confirmed merge.
        let policy_result = self
            .remove_zero_leaf_accounts_locked(
                conversation_id,
                &accounts,
                &did,
                &device,
                &group_hex,
                prior["generation"].as_u64().unwrap(),
            )
            .await;
        if let Err(error) = policy_result {
            tracing::warn!(conversation_id, %error, "Account removal awaits a fresh policy retry");
            return Err(invalid("conversation_member_removal_pending: Member removal is incomplete. Try Remove member again to finish removing their account and devices."));
        }
        if let Some(conversation) = self.conversations().lock().await.get_mut(conversation_id) {
            conversation.members.retain(|member| {
                !accounts.contains(super::credential_binding::credential_root_did(&member.did))
            });
        }
        Ok(())
    }
    async fn remove_account_leaves_locked(
        &self,
        conversation_id: &str,
        state: &Value,
        prior: &Value,
        accounts: &BTreeSet<String>,
        targets: &[(String, uuid::Uuid)],
        did: &str,
        device: &str,
    ) -> Result<()> {
        let snapshot_seq = state["snapshotSeq"]
            .as_u64()
            .filter(|n| (1..=9_007_199_254_740_991).contains(n))
            .ok_or_else(|| invalid("Group state is missing its authoritative entry sequence."))?;
        let group = bytes(&prior["groupId"])?;
        let group_hex = hex::encode(&group);
        let epoch = self.mls_context().get_epoch(group.clone())?;
        if epoch != prior["epoch"].as_u64().unwrap()
            || self.mls_context().get_confirmation_tag(group.clone())?
                != bytes(&prior["confirmationTag"])?
            || self.mls_context().get_group_context_hash(group.clone())?
                != bytes(&prior["groupContextHash"])?
        {
            return Err(invalid(
                "Sync this group's latest messages before removing a member.",
            ));
        }
        let identities = self.mls_context().group_member_identities(group.clone())?;
        let expected_actor = format!("{did}#{device}").into_bytes();
        if !identities.contains(&expected_actor) {
            return Err(invalid("This device is not an active group member."));
        }
        let removals: Vec<Vec<u8>> = targets
            .iter()
            .map(|(did, id)| format!("{did}#{id}").into_bytes())
            .collect();
        let local_targets: HashSet<_> = identities
            .iter()
            .filter(|id| {
                std::str::from_utf8(id).ok().is_some_and(|id| {
                    accounts.contains(super::credential_binding::credential_root_did(id))
                })
            })
            .cloned()
            .collect();
        if local_targets != removals.iter().cloned().collect() {
            return Err(invalid(
                "Sync the group's device membership before removing a member.",
            ));
        }
        let mut projection = self
            .storage()
            .get_group_state(&group_hex)
            .await?
            .ok_or_else(|| invalid("Group state is missing; sync before removing a member."))?;
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
            .get_auth_generation(did)
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
            "$type":"blue.catbird.chat.defs#commitTransitionBody", "signatureDomain":"CATBIRD-CHAT-COMMIT\0",
            "transitionId":transition.to_string(), "idempotencyKey":transition.to_string(),
            "actorDid":did, "actorDeviceId":device, "authGeneration":auth_generation,
            "keyId":super::canonical_transport::derive_key_id(&public_key), "prior":prior, "next":next, "aad":aad,
            "manifest":{"participantChanges":[], "leafChanges":targets.iter().map(|(did,id)| json!({"$type":"blue.catbird.chat.defs#removeLeaf","userDid":did,"deviceId":id.to_string()})).collect::<Vec<_>>()},
            "commit":{"framing":"mlsMessage","contentType":"publicMessageCommit","bytes":STANDARD.encode(&removed.commit_data),"sha256":STANDARD.encode(Sha256::digest(&removed.commit_data))},
            "metadataSnapshot":snapshot, "signedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)
        });
        let prepared = self
            .prepare_clean_chat_signed_request(
                CleanChatSigningContext {
                    actor_did: did.to_string(),
                    device_id: device.to_string(),
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
            .retain(|id| !accounts.contains(super::credential_binding::credential_root_did(id)));
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
        if !confirmed {
            return Err(invalid(
                "The device removal is still awaiting confirmation. Try Remove member again.",
            ));
        }
        Ok(())
    }
    async fn remove_zero_leaf_accounts_locked(
        &self,
        cid: &str,
        accounts: &BTreeSet<String>,
        did: &str,
        device: &str,
        expected_group: &str,
        expected_generation: u64,
    ) -> Result<()> {
        let response = self.fetch_conversation_lifecycle(cid).await?;
        let state = &response["state"];
        let participants = authorize(state, cid, did, device)?;
        let prior = lifecycle_coordinates(&state["coordinates"], cid)?;
        if hex::encode(bytes(&prior["groupId"])?) != expected_group
            || prior["generation"].as_u64() != Some(expected_generation)
        {
            return Err(invalid("Group generation changed during member removal."));
        }
        let remaining: Vec<_> = accounts
            .iter()
            .filter(|target| participants.iter().any(|p| p["userDid"] == target.as_str()))
            .collect();
        if remaining.is_empty() {
            return Ok(());
        }
        if state["leaves"].as_array().unwrap().iter().any(|leaf| {
            leaf["userDid"]
                .as_str()
                .is_some_and(|did| accounts.contains(did))
        }) {
            return Err(invalid("A member device was admitted during removal. Retry against the latest group state."));
        }
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior["stateVersion"]
            .as_u64()
            .unwrap()
            .checked_add(1)
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or_else(|| invalid("Group state version limit reached."))?);
        let identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(identity.as_bytes().to_vec())?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(did)
            .await?
            .filter(|n| *n >= 1)
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        let transition_id = uuid::Uuid::new_v4().to_string();
        let body = json!({"$type":"blue.catbird.chat.defs#policyTransitionBody","signatureDomain":"CATBIRD-CHAT-POLICY\0","transitionId":transition_id,"idempotencyKey":transition_id,"actorDid":did,"actorDeviceId":device,"keyId":super::canonical_transport::derive_key_id(&public_key),"authGeneration":auth_generation,"prior":prior,"next":next,"participantChanges":remaining.iter().map(|target| json!({"$type":"blue.catbird.chat.defs#removeParticipant","userDid":target})).collect::<Vec<_>>(),"signedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)});
        let prepared = self
            .prepare_clean_chat_signed_request(
                CleanChatSigningContext {
                    actor_did: did.into(),
                    device_id: device.into(),
                    auth_generation: Some(auth_generation),
                },
                CanonicalOperation::SubmitTransition,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let reply = self.api_client().submit_prepared_request(prepared).await?;
        if reply.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "Account removal policy returned status {}",
                reply.status
            )));
        }
        let response = self.fetch_conversation_lifecycle(cid).await?;
        let state = &response["state"];
        let after = lifecycle_coordinates(&state["coordinates"], cid)?;
        if hex::encode(bytes(&after["groupId"])?) != expected_group
            || after["generation"] != prior["generation"]
            || state["participants"]
                .as_array()
                .ok_or_else(|| invalid("Group participants are missing."))?
                .iter()
                .any(|p| {
                    p["userDid"]
                        .as_str()
                        .is_some_and(|did| accounts.contains(did))
                })
        {
            return Err(invalid(
                "Account removal has not yet been confirmed by current group state.",
            ));
        }
        Ok(())
    }
}
