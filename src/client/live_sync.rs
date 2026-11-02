//! Live `sync()` reconciliation engine for `CatbirdMlsClient` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`, `C33`).
//!
//! Executes strictly outside `MlsAccountDb::write_tx` (`I6`) across four phases:
//! 1. `getConversations` -> `C33` incoming direct-request Welcome/introduction import + pending group invite acceptance.
//! 2. `getPendingWelcomes` -> `I4`-verified `StagedWelcome` join + `acknowledgeWelcome`.
//! 3. `getLeafRecoveryInbox` -> `I4`-verified `add_members` commit + `#leafRecoveryFulfillmentBody`.
//! 4. `getEntries` -> `I2`-ordered Commit / Metadata / Application / Acceptance / AccountDeleted reconciliation + `I14` `acknowledge_entries_up_to`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::client::chat_wire;
use crate::client::traits::PlatformChangeEvent;
use crate::client::QueuedLabyrinthArchivePayload;
use crate::error::MLSError;
use crate::messaging::receive::{
    extract_plaintext_body_and_verify_aad, handle_account_deleted_event,
};
use crate::metadata::derive_metadata_key_from_group;
use crate::orchestrator::canonical_transport::{
    canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use crate::orchestrator::direct_request_bootstrap::{
    DirectRequestBootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
};
use crate::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider;
use crate::push::{root_did_from_credential_bytes, AuthorizedPeerDeviceKey};
use crate::storage::{
    ConversationRow, KvWriteOverlay, MessageRow, OpenMlsKvStorage, RequestRow, RusqliteKvBackend,
};

use super::native_client::CatbirdMlsClient;

fn build_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .build()
}

impl CatbirdMlsClient {
    /// Reconcile conversations, `C33` direct requests, pending `Welcome`s, leaf-recovery requests,
    /// and ordered `getEntries` deltas from the home `mls-ds` (`Spec §6.3`, `I2`, `I4`, `I6`, `I13`, `I14`).
    pub fn sync(&self) -> Result<u32, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(0);
        };
        let Ok((signer, auth_generation)) = self.load_enrolled_signer_and_auth_gen() else {
            return Ok(0);
        };

        let mut total_applied: u32 = 0;

        // Phase 1: `getConversations` -> C33 incoming direct requests + group invitation acceptance.
        let (conv_applied, inventory_session_id) =
            self.sync_conversations_list(&canonical_dev_id, &signer, auth_generation)?;
        total_applied = total_applied.saturating_add(conv_applied);

        // Phase 2: `getPendingWelcomes` -> StagedWelcome join + acknowledgeWelcome.
        total_applied = total_applied.saturating_add(self.sync_pending_welcomes(
            &canonical_dev_id,
            &signer,
            auth_generation,
            inventory_session_id.as_deref(),
        )?);

        // Phase 3: `getLeafRecoveryInbox` -> fulfill leaf recovery requests.
        total_applied = total_applied.saturating_add(self.fulfill_leaf_recovery_inbox(
            &canonical_dev_id,
            &signer,
            auth_generation,
            inventory_session_id.as_deref(),
        )?);

        // Phase 4: `getEntries` for every known conversation -> decrypt + acknowledgeEntries.
        let convos = self.db.read_tx(|tx| tx.list_conversations(None, 200))?;
        for convo in convos {
            total_applied = total_applied.saturating_add(self.sync_conversation_entries(
                &canonical_dev_id,
                &signer,
                &convo,
            )?);
        }

        if total_applied > 0 {
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        }
        Ok(total_applied)
    }

    fn sync_conversations_list(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
    ) -> Result<(u32, Option<String>), MLSError> {
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversations",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("limit", "100"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ],
            canonical_dev_id,
            signer,
        )?;
        let inventory_session_id = resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let Some(items) = resp
            .get("items")
            .or_else(|| resp.get("conversations"))
            .or_else(|| resp.get("states"))
            .and_then(|v| v.as_array())
        else {
            return Ok((0, inventory_session_id));
        };

        let mut count = 0u32;
        for item in items {
            let state = item.get("state").unwrap_or(item);
            let coords = state.get("coordinates").unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| state.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let kind = state
                .get("conversationKind")
                .or_else(|| state.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("group");
            let sequencer_did = state
                .get("sequencerDid")
                .or_else(|| state.get("authorityDid"))
                .and_then(|v| v.as_str())
                .unwrap_or(&self.config.home_ds_did);

            let has_local = self.db.read_tx(|tx| tx.get_conversation(cid))?.is_some();

            if kind == "direct" && !has_local {
                if self.import_incoming_c33_direct_request(
                    canonical_dev_id,
                    signer,
                    cid,
                    sequencer_did,
                )? {
                    count = count.saturating_add(1);
                }
                continue;
            }

            // If we have a pending group invitation in `participants`, accept it so the inviter
            // receives our leaf recovery request in `getLeafRecoveryInbox`.
            if kind == "group" {
                if let Some(participants) = state.get("participants").and_then(|v| v.as_array()) {
                    if let Some(me) = participants.iter().find(|p| {
                        p.get("userDid").and_then(|u| u.as_str()) == Some(&self.normalized_did)
                            && p.get("status").and_then(|s| s.as_str()) == Some("pending")
                    }) {
                        if let Some(prov) = me.get("invitationProvenance") {
                            if let Err(e) = self.accept_group_invitation(
                                canonical_dev_id,
                                signer,
                                auth_generation,
                                cid,
                                coords,
                                prov,
                            ) {
                                if !e.to_string().contains("HTTP 409") {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok((count, inventory_session_id))
    }

    fn accept_group_invitation(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        cid: &str,
        coords: &Value,
        invitation_provenance: &Value,
    ) -> Result<(), MLSError> {
        let prior = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;
        let prior_sv = prior
            .get("stateVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior_sv + 1);
        let transition_id = self.hooks.uuid_v4().to_string();
        let recovery_request_id = self.hooks.uuid_v4().to_string();
        let body = json!({
            "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
            "signatureDomain": "CATBIRD-CHAT-ACCEPT\0",
            "transitionId": transition_id,
            "recoveryRequestId": recovery_request_id,
            "idempotencyKey": transition_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_generation,
            "signedAt": self.hooks.now_rfc3339_millis(),
            "prior": prior,
            "next": next,
            "invitationProvenance": invitation_provenance,
        });
        let _ = self.submit_signed_chat_op(
            canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::AcceptConversation,
            &body,
            signer,
        )?;
        Ok(())
    }

    fn import_incoming_c33_direct_request(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        cid: &str,
        sequencer_did_fallback: &str,
    ) -> Result<bool, MLSError> {
        let entries_val = self.query_signed_chat_ds(
            "blue.catbird.chat.getEntries",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("afterSeq", "0"),
                ("conversationId", cid),
                ("limit", "100"),
            ],
            canonical_dev_id,
            signer,
        )?;
        let Some(entries) = entries_val.get("entries").and_then(|v| v.as_array()) else {
            return Ok(false);
        };
        let Some(raw_dr_entry) = entries.iter().find(|e| {
            e.get("$type").and_then(|t| t.as_str())
                == Some("blue.catbird.chat.defs#directRequestEntry")
                || e.get("entryKind").and_then(|t| t.as_str()) == Some("directRequest")
                || e.get("directRequest").is_some()
        }) else {
            return Ok(false);
        };

        let pub_wrapper = raw_dr_entry
            .get("signedRequest")
            .or_else(|| raw_dr_entry.get("directRequest"))
            .unwrap_or(raw_dr_entry);
        let p_body = pub_wrapper.get("body").unwrap_or(pub_wrapper);
        let sender_did = p_body
            .get("actorDid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDid".to_string()))?;
        let sender_device_id = p_body
            .get("actorDeviceId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDeviceId".to_string()))?;
        let request_id = p_body
            .get("requestId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing requestId".to_string()))?;
        let first_message_id = p_body
            .get("firstMessageId")
            .and_then(|v| v.as_str())
            .unwrap_or(request_id);

        // Enforce `I4` (`ADR-009`): verify sender device key in PDS `blue.catbird.chat.device` BEFORE Welcome join!
        let sender_pds_keys = self.fetch_and_cache_authorized_pds_device_keys(sender_did)?;
        let candidate_key = chat_wire::json_bytes(
            &p_body["artifacts"]["metadataSnapshot"]["authorProof"]["signaturePublicKey"],
        )?;
        let sender_scoped_id = format!("{sender_did}#{sender_device_id}");
        chat_wire::verify_leaf_slice_i4(
            sender_scoped_id.as_bytes(),
            &candidate_key,
            &sender_pds_keys,
        )?;

        let pub_norm = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(pub_wrapper).map_err(|e| MLSError::Internal(e.to_string()))?,
            "signedDirectRequestPublication",
            false,
        )
        .map_err(|e| MLSError::Cryptography(format!("normalize C33 publication: {e}")))?;
        let pub_norm_bytes =
            serde_json::to_vec(&pub_norm).map_err(|e| MLSError::Internal(e.to_string()))?;
        let verified_pub = dr_transcript::verify_received_signed_request(
            DirectRequestKind::Publish,
            &pub_norm_bytes,
            &candidate_key,
        )
        .map_err(|e| MLSError::Cryptography(format!("verify C33 publication signature: {e}")))?;

        let vp = verified_pub.body();
        let ctx_val = json!({
            "protocolVersion": "2",
            "requestId": vp["requestId"],
            "firstMessageId": vp["firstMessageId"],
            "conversationId": vp["conversationId"],
            "origin": vp["origin"],
            "actorDid": vp["actorDid"],
            "actorDeviceId": vp["actorDeviceId"],
            "actorKeyId": vp["keyId"],
            "recipientDid": vp["recipientDid"],
            "preparationDigest": vp["preparationDigest"],
        });
        let context_json =
            serde_json::to_vec(&ctx_val).map_err(|e| MLSError::Internal(e.to_string()))?;
        let context_hash = dr_transcript::direct_request_context_hash(&context_json)
            .map_err(|e| MLSError::Cryptography(format!("C33 context_hash: {e}")))?;
        let expected_ctx_hash = chat_wire::json_bytes(&vp["contextHash"])?;
        if expected_ctx_hash.as_slice() != context_hash {
            return Err(MLSError::Cryptography(
                "C33 contextHash mismatch".to_string(),
            ));
        }

        let artifact = &vp["artifacts"];
        let mut local_pkg_ref: Option<Vec<u8>> = None;
        let deliveries_arr = artifact["welcome"]["deliveries"]
            .as_array()
            .ok_or_else(|| MLSError::invalid_input("C33 welcome missing deliveries"))?;
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(deliveries_arr.len());
        for d in deliveries_arr {
            let r = chat_wire::json_bytes(&d["provenance"]["keyPackageRef"])?;
            if d.get("recipientDid").and_then(|v| v.as_str()) == Some(self.normalized_did.as_str())
                && d.get("recipientDeviceId").and_then(|v| v.as_str()) == Some(canonical_dev_id)
            {
                local_pkg_ref = Some(r.clone());
            }
            refs.push(r);
        }
        let import_until = chrono::DateTime::parse_from_rfc3339(
            vp["importUntil"]
                .as_str()
                .ok_or_else(|| MLSError::invalid_input("C33 missing importUntil"))?,
        )
        .map_err(|e| MLSError::invalid_input(format!("C33 importUntil: {e}")))?
        .timestamp()
        .max(0) as u64;

        let bootstrap = DirectRequestBootstrap {
            context_json,
            context_hash,
            coordinates: vp["next"].clone(),
            import_until,
            expected_package_refs: refs.clone(),
            genesis_group_info: chat_wire::json_bytes(&artifact["genesisGroupInfo"]["bytes"])?,
            add_commit: chat_wire::json_bytes(&artifact["addCommit"]["bytes"])?,
            final_group_info: chat_wire::json_bytes(&artifact["finalGroupInfo"]["bytes"])?,
            welcome: chat_wire::json_bytes(&artifact["welcome"]["opaqueWelcome"])?,
            metadata_nonce: chat_wire::json_bytes(&artifact["metadataSnapshot"]["nonce"])?,
            metadata_ciphertext: chat_wire::json_bytes(
                &artifact["metadataSnapshot"]["ciphertext"],
            )?,
            initial_ciphertext: chat_wire::json_bytes(&artifact["initialCiphertext"])?,
        };

        let own_pds_keys = self.fetch_and_cache_authorized_pds_device_keys(&self.normalized_did)?;
        let mut all_auth_keys = sender_pds_keys;
        all_auth_keys.extend(own_pds_keys);

        let welcome_input = DirectRequestWelcomeInput {
            bootstrap: bootstrap.clone(),
            publication_request: pub_norm_bytes.clone(),
            actor_signature_public_key: candidate_key,
            preparation_request_digest: [0u8; 32],
            local_identity: format!("{}#{}", self.normalized_did, canonical_dev_id).into_bytes(),
            local_package_ref: local_pkg_ref
                .or_else(|| refs.into_iter().next())
                .unwrap_or_default(),
            published_receipt: Vec::new(),
            receipt_authority_did: sequencer_did_fallback.to_string(),
            receipt_authority_key: Vec::new(),
        };

        let entry_seq = raw_dr_entry
            .get("seq")
            .and_then(|v| v.as_i64())
            .unwrap_or(1)
            .max(1);
        let effective_seq_did = raw_dr_entry
            .get("sequencerDid")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                let sender_ds = self.resolve_peer_home_ds_did(sender_did)?;
                let own_ds = self.config.home_ds_did.trim();
                if !own_ds.is_empty() && own_ds <= sender_ds.as_str() {
                    Some(own_ds.to_string())
                } else {
                    Some(sender_ds)
                }
            })
            .unwrap_or_else(|| sequencer_did_fallback.to_string());
        let dr_rcpt_json = raw_dr_entry
            .get("sequencerReceipt")
            .and_then(|r| serde_json::to_string(r).ok());
        let now_ms = self.hooks.now_ms();
        let pub_norm_str = String::from_utf8(pub_norm_bytes)
            .map_err(|e| MLSError::Internal(format!("C33 pub UTF-8: {e}")))?;
        let coords_canon = chat_wire::canonicalize_wire_coordinate(&vp["next"], Some(cid))?;
        let coords_str =
            serde_json::to_string(&coords_canon).map_err(|e| MLSError::Internal(e.to_string()))?;

        self.db.write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mls_welcome = MlsMessageIn::tls_deserialize_exact(&bootstrap.welcome)
                .map_err(|e| MLSError::Cryptography(format!("deserialize C33 Welcome: {e:?}")))?;
            let MlsMessageBodyIn::Welcome(welcome) = mls_welcome.extract() else {
                return Err(MLSError::Cryptography(
                    "C33 opaqueWelcome is not an MLS Welcome".to_string(),
                ));
            };
            let staged = crate::sim_hooks::build_staged_welcome_at(
                &provider,
                &build_join_config(),
                welcome,
                None,
                (now_ms.max(0) as u64) / 1_000,
            )
            .map_err(|e| MLSError::Cryptography(format!("stage C33 Welcome: {e:?}")))?;

            let sender_member = staged.welcome_sender().map_err(|e| {
                MLSError::Cryptography(format!("C33 welcome_sender lookup failed: {e:?}"))
            })?;
            chat_wire::verify_leaf_slice_i4(
                sender_member.credential().serialized_content(),
                sender_member.signature_key().as_slice(),
                &all_auth_keys,
            )?;

            let mut group = staged
                .into_group(&provider)
                .map_err(|e| MLSError::Cryptography(format!("into_group C33 Welcome: {e:?}")))?;
            for m in group.members() {
                chat_wire::verify_leaf_slice_i4(
                    m.credential.serialized_content(),
                    m.signature_key.as_slice(),
                    &all_auth_keys,
                )?;
            }

            let group_id = group.group_id().as_slice().to_vec();
            let epoch = group.epoch().as_u64() as i64;
            let intro_json =
                match decrypt_introduction_with_provider(&provider, &mut group, &welcome_input)? {
                    DirectRequestIntroductionResult::Ready { plaintext } => {
                        let intro_val = dr_transcript::decode_direct_request_introduction(
                            &plaintext,
                        )
                        .map_err(|e| MLSError::Cryptography(format!("decode C33 intro: {e}")))?;
                        let txt = intro_val.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        json!({ "text": txt }).to_string()
                    }
                    DirectRequestIntroductionResult::Unavailable { code } => {
                        json!({ "text": format!("[unavailable:{code}]") }).to_string()
                    }
                };

            let space_uri = Some(format!(
                "at://{effective_seq_did}/space/blue.catbird.labyrinth.conversation/{cid}-0"
            ));
            let convo_row = ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                generation: 0,
                epoch,
                last_seq: entry_seq,
                sequencer_did: effective_seq_did.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: 1,
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&convo_row)?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, now_ms)?;
            tx.put_account_meta(
                &format!("c33_publication_json:{cid}"),
                &pub_norm_str,
                now_ms,
            )?;

            let is_incoming = sender_did != self.normalized_did;
            tx.upsert_request(&RequestRow {
                request_id: request_id.to_string(),
                conversation_id: cid.to_string(),
                sender_did: sender_did.to_string(),
                recipient_did: self.normalized_did.clone(),
                consent: if is_incoming {
                    "incomingPending".to_string()
                } else {
                    "outgoingPending".to_string()
                },
                first_message_id: Some(first_message_id.to_string()),
                first_message_archived: false,
                payload_json: intro_json.clone(),
                expires_at_ms: (import_until as i64).saturating_mul(1000),
                updated_at_ms: now_ms,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.to_string(),
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                epoch,
                seq: entry_seq,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_device_id.to_string(),
                plaintext_json: intro_json.clone(),
                created_at_ms: now_ms,
                is_own: !is_incoming,
            })?;

            // Stage C33 opening message so `accept_direct_request` archives it ONLY after consent!
            let staged_opening = QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id.to_string(),
                conversation_id: cid.to_string(),
                group_id_hex: hex::encode(&group_id),
                epoch,
                seq: entry_seq,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_device_id.to_string(),
                sequencer_did: effective_seq_did,
                space_uri,
                plaintext_json: intro_json.clone(),
                labyrinth_frame_json: intro_json,
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: None,
                sequencer_receipt_json: dr_rcpt_json,
                created_at_ms: now_ms,
            };
            tx.put_account_meta(
                &format!("c33_pending_opening:{cid}"),
                &serde_json::to_string(&staged_opening)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(())
        })?;

        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        self.notify_change(PlatformChangeEvent::MessagesUpdated {
            conversation_id: cid.to_string(),
        });
        Ok(true)
    }

    fn acquire_inventory_session_id(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Option<String>, MLSError> {
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversations",
            &[
                ("actorDeviceId", canonical_dev_id),
                ("limit", "1"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ],
            canonical_dev_id,
            signer,
        )?;
        Ok(resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned))
    }

    fn sync_pending_welcomes(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        inventory_session_id: Option<&str>,
    ) -> Result<u32, MLSError> {
        let owned_sid = if inventory_session_id.is_none() {
            self.acquire_inventory_session_id(canonical_dev_id, signer)?
        } else {
            None
        };
        let mut q_pairs: Vec<(&str, &str)> = vec![("actorDeviceId", canonical_dev_id)];
        if let Some(sid) = inventory_session_id.or(owned_sid.as_deref()) {
            q_pairs.push(("inventorySessionId", sid));
        }
        q_pairs.extend_from_slice(&[
            ("limit", "100"),
            ("supportedProtocolVersions", "1"),
            ("supportedProtocolVersions", "2"),
        ]);
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getPendingWelcomes",
            &q_pairs,
            canonical_dev_id,
            signer,
        )?;
        let Some(welcomes) = resp
            .get("items")
            .or_else(|| resp.get("welcomes"))
            .or_else(|| resp.get("deliveries"))
            .and_then(|v| v.as_array())
        else {
            return Ok(0);
        };

        let mut joined = 0u32;
        for raw_item in welcomes {
            let w_env = raw_item
                .get("welcome")
                .filter(|v| v.is_object() && v.get("welcomeId").is_some())
                .unwrap_or(raw_item);
            let welcome_id = w_env
                .get("welcomeId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let coords = w_env.get("coordinates").unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| w_env.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let transition_seq = w_env
                .get("transitionSeq")
                .or_else(|| w_env.get("seq"))
                .and_then(|v| v.as_i64())
                .unwrap_or(1);
            let sequencer_did = w_env
                .get("sequencerDid")
                .and_then(|v| v.as_str())
                .unwrap_or(&self.config.home_ds_did);
            let coords_canon = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;

            let already_joined = self.db.read_tx(|tx| tx.get_conversation(cid))?.is_some();
            if already_joined {
                let is_dr_welcome = w_env.get("$type").and_then(|t| t.as_str())
                    == Some("blue.catbird.chat.defs#directRequestWelcomeView");
                let has_pending_request = self.db.read_tx(|tx| {
                    Ok(tx
                        .list_requests(None)?
                        .iter()
                        .any(|r| r.conversation_id == cid && r.consent != "accepted"))
                })?;
                let status_str = w_env.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if !welcome_id.is_empty()
                    && status_str != "acknowledged"
                    && !is_dr_welcome
                    && !has_pending_request
                {
                    let ack_body = json!({
                        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                        "welcomeId": welcome_id,
                        "transitionSeq": transition_seq,
                        "coordinates": coords_canon,
                        "actorDid": self.normalized_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": derive_key_id(signer.public()),
                        "authGeneration": auth_generation,
                        "idempotencyKey": self.hooks.uuid_v4().to_string(),
                        "signedAt": self.hooks.now_rfc3339_millis(),
                    });
                    let _ = self.submit_signed_chat_op(
                        canonical_dev_id,
                        Some(auth_generation),
                        CanonicalOperation::AcknowledgeWelcome,
                        &ack_body,
                        signer,
                    );
                }
                continue;
            }

            let mut candidate_dids = BTreeMap::new();
            chat_wire::collect_dids_from_json(w_env, &mut candidate_dids);
            candidate_dids.insert(self.normalized_did.clone(), ());
            let mut all_auth_keys: Vec<AuthorizedPeerDeviceKey> = Vec::new();
            for did in candidate_dids.keys() {
                let keys = self.fetch_and_cache_authorized_pds_device_keys(did)?;
                all_auth_keys.extend(keys);
            }

            let welcome_bytes_res = w_env
                .get("opaqueWelcome")
                .or_else(|| w_env.get("welcome").and_then(|w| w.get("opaqueWelcome")))
                .or_else(|| w_env.get("bytes"))
                .ok_or_else(|| MLSError::invalid_input("pending welcome missing opaqueWelcome"))
                .and_then(chat_wire::json_bytes);
            let Ok(welcome_bytes) = welcome_bytes_res else {
                continue;
            };

            let meta_snap_opt = w_env.get("metadataSnapshot");
            let now_ms = self.hooks.now_ms();
            let coords_str = serde_json::to_string(&coords_canon)
                .map_err(|e| MLSError::Internal(e.to_string()))?;

            // Pre-extract member DIDs from StagedWelcome over KvWriteOverlay inside `read_tx` so OpenMLS's
            // one-time KeyPackageBundle deletion during `new_from_welcome` never touches SQLite during peek.
            let extra_dids: Vec<String> = self.db.read_tx(|tx| {
                let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                let storage = OpenMlsKvStorage::new(overlay);
                let provider = self.hooks.openmls_provider(storage);
                let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
                let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                    return Err(MLSError::Cryptography("not Welcome".to_string()));
                };
                let staged = crate::sim_hooks::build_staged_welcome_at(
                    &provider,
                    &build_join_config(),
                    welcome,
                    None,
                    (now_ms.max(0) as u64) / 1_000,
                )
                .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))?;
                let mut found = Vec::new();
                if let Ok(sender) = staged.welcome_sender() {
                    if let Ok((d, _)) =
                        root_did_from_credential_bytes(sender.credential().serialized_content())
                    {
                        found.push(d);
                    }
                }
                for m in staged.members() {
                    if let Ok((d, _)) =
                        root_did_from_credential_bytes(m.credential.serialized_content())
                    {
                        found.push(d);
                    }
                }
                Ok(found)
            })?;
            for d in extra_dids {
                if candidate_dids.insert(d.clone(), ()).is_none() {
                    let keys = self.fetch_and_cache_authorized_pds_device_keys(&d)?;
                    all_auth_keys.extend(keys);
                }
            }

            self.db.write_tx(|tx| {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
                let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                    return Err(MLSError::Cryptography("not Welcome".to_string()));
                };
                let staged = crate::sim_hooks::build_staged_welcome_at(
                    &provider,
                    &build_join_config(),
                    welcome,
                    None,
                    (now_ms.max(0) as u64) / 1_000,
                )
                .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))?;
                let sender = staged
                    .welcome_sender()
                    .map_err(|e| MLSError::Cryptography(format!("welcome_sender: {e:?}")))?;
                chat_wire::verify_leaf_slice_i4(
                    sender.credential().serialized_content(),
                    sender.signature_key().as_slice(),
                    &all_auth_keys,
                )?;
                let mut group = staged
                    .into_group(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("into_group: {e:?}")))?;
                for m in group.members() {
                    chat_wire::verify_leaf_slice_i4(
                        m.credential.serialized_content(),
                        m.signature_key.as_slice(),
                        &all_auth_keys,
                    )?;
                }

                let mut decrypted_title: Option<String> = None;
                if let Some(snap) = meta_snap_opt {
                    if let Some((m_epoch, m_ver, meta)) =
                        chat_wire::try_decrypt_group_metadata_snapshot(&mut group, &provider, snap)
                    {
                        let meta_row =
                            chat_wire::group_metadata_row_from_v1(cid, m_ver, m_epoch, &meta, now_ms)?;
                        decrypted_title = meta_row.title.clone();
                        tx.upsert_group_metadata(&meta_row)?;
                    }
                    if let Ok(snap_s) = serde_json::to_string(snap) {
                        tx.put_account_meta(
                            &format!("metadata_snapshot_json:{cid}"),
                            &snap_s,
                            now_ms,
                        )?;
                    }
                }

                let gen_i64 = coords_canon
                    .get("generation")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let row = ConversationRow {
                    conversation_id: cid.to_string(),
                    group_id: group.group_id().as_slice().to_vec(),
                    generation: gen_i64,
                    epoch: group.epoch().as_u64() as i64,
                    last_seq: transition_seq,
                    sequencer_did: sequencer_did.to_string(),
                    space_uri: Some(format!(
                        "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{cid}-{gen_i64}"
                    )),
                    title: decrypted_title,
                    unread_count: 0,
                    updated_at_ms: now_ms,
                };
                tx.upsert_conversation(&row)?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, now_ms)
            })?;

            if !welcome_id.is_empty() {
                let ack_body = json!({
                    "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                    "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                    "welcomeId": welcome_id,
                    "transitionSeq": transition_seq,
                    "coordinates": coords_canon,
                    "actorDid": self.normalized_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_generation,
                    "idempotencyKey": self.hooks.uuid_v4().to_string(),
                    "signedAt": self.hooks.now_rfc3339_millis(),
                });
                let _ = self.submit_signed_chat_op(
                    canonical_dev_id,
                    Some(auth_generation),
                    CanonicalOperation::AcknowledgeWelcome,
                    &ack_body,
                    signer,
                )?;
            }
            joined = joined.saturating_add(1);
        }
        Ok(joined)
    }

    pub(crate) fn fulfill_leaf_recovery_inbox(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        inventory_session_id: Option<&str>,
    ) -> Result<u32, MLSError> {
        let owned_sid = if inventory_session_id.is_none() {
            self.acquire_inventory_session_id(canonical_dev_id, signer)?
        } else {
            None
        };
        let mut q_pairs: Vec<(&str, &str)> = vec![("actorDeviceId", canonical_dev_id)];
        if let Some(sid) = inventory_session_id.or(owned_sid.as_deref()) {
            q_pairs.push(("inventorySessionId", sid));
        }
        q_pairs.extend_from_slice(&[
            ("limit", "100"),
            ("supportedProtocolVersions", "1"),
            ("supportedProtocolVersions", "2"),
        ]);
        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getLeafRecoveryInbox",
            &q_pairs,
            canonical_dev_id,
            signer,
        )?;
        let Some(requests) = resp
            .get("items")
            .or_else(|| resp.get("requests"))
            .or_else(|| resp.get("inbox"))
            .and_then(|v| v.as_array())
        else {
            return Ok(0);
        };

        let mut fulfilled = 0u32;
        for raw_req in requests {
            let req = raw_req
                .get("request")
                .filter(|v| v.is_object() && v.get("recoveryRequestId").is_some())
                .unwrap_or(raw_req);
            let Some(cid) = req
                .get("conversationId")
                .or_else(|| {
                    req.get("boundCoordinate")
                        .and_then(|c| c.get("conversationId"))
                })
                .or_else(|| req.get("coordinates").and_then(|c| c.get("conversationId")))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Ok(convo_uuid) = uuid::Uuid::parse_str(cid) else {
                continue;
            };
            let Some(recovery_request_id) = req
                .get("recoveryRequestId")
                .or_else(|| req.get("requestId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(target_did) = req
                .get("requesterDid")
                .or_else(|| req.get("userDid"))
                .or_else(|| req.get("targetDid"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(target_device_id) = req
                .get("requesterDeviceId")
                .or_else(|| req.get("deviceId"))
                .or_else(|| req.get("targetDeviceId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let kp_obj = req
                .get("reservation")
                .and_then(|r| r.get("keyPackage"))
                .or_else(|| req.get("keyPackage"))
                .unwrap_or(req);
            let Ok(kp_bytes) = chat_wire::json_bytes(&kp_obj["bytes"]) else {
                continue;
            };
            let Ok(kp_ref) = chat_wire::json_bytes(&kp_obj["keyPackageRef"]) else {
                continue;
            };

            // Enforce `I4` (`ADR-009`): verify target leaf's KeyPackage against PDS `blue.catbird.chat.device`!
            let target_pds_keys = self.fetch_and_cache_authorized_pds_device_keys(target_did)?;
            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize recovery KP: {e:?}")))?
                    .extract()
            else {
                continue;
            };
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_slice_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                &target_pds_keys,
            )?;

            let prior_coords = if let Some(c) = req
                .get("boundCoordinate")
                .or_else(|| req.get("coordinates"))
                .or_else(|| req.get("prior"))
            {
                chat_wire::canonicalize_wire_coordinate(c, Some(cid))?
            } else {
                self.load_or_build_conversation_coords(cid)?
            };
            let prior_sv = prior_coords
                .get("stateVersion")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let prior_epoch = prior_coords
                .get("epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let prior_gen = prior_coords
                .get("generation")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
            let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;

            let transition_uuid = self.hooks.uuid_v4();
            let transition_id = transition_uuid.to_string();
            let welcome_id = self.hooks.uuid_v4().to_string();
            let now_ms = self.hooks.now_ms();

            // Stage `add_members` + `merge_pending_commit` over `KvWriteOverlay` inside `read_tx` (`I6`)
            // so an HTTP 409 / network failure never forks local OpenMLS epoch state!
            let built = self.db.read_tx(|tx| {
                let Some(convo) = tx.get_conversation(cid)? else {
                    return Ok(None);
                };
                let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = self.hooks.openmls_provider(storage);
                let validated_kp = crate::sim_hooks::validate_key_package_at(
                    kp_in,
                    provider.crypto(),
                    ProtocolVersion::Mls10,
                    (now_ms.max(0) as u64) / 1_000,
                )
                .map_err(|e| MLSError::Cryptography(format!("validate recovery KP: {e:?}")))?;
                let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                else {
                    return Ok(None);
                };

                let aad_prior = chat_wire::build_aad_prior_coordinate(
                    &convo_uuid,
                    &convo.group_id,
                    prior_gen,
                    prior_sv,
                    prior_epoch as i64,
                    &prior_gch,
                    &prior_ctag,
                );
                let commit_aad_val = json!({
                    "protocolVersion": "1",
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "generation": prior_gen,
                    "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                    "prior": aad_prior,
                });
                let commit_aad_bytes =
                    canonical_commit_aad_bytes(&commit_aad_val).map_err(|e| {
                        MLSError::Cryptography(format!("canonical_commit_aad_bytes: {e}"))
                    })?;

                group.set_aad(commit_aad_bytes);
                let (commit_out, welcome_out, _) = group
                    .add_members(&provider, signer, &[validated_kp])
                    .map_err(|e| MLSError::Cryptography(format!("recovery add_members: {e:?}")))?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("merge recovery commit: {e:?}")))?;
                group.set_aad(Vec::new());

                let commit_bytes = commit_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                let welcome_bytes = welcome_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize welcome: {e:?}")))?;
                let next_epoch = group.epoch().as_u64();
                let (next_gch, next_ctag) =
                    chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let meta_row = tx.get_group_metadata(cid)?;
                let meta_ver = meta_row
                    .as_ref()
                    .map(|m| m.metadata_version.max(1) as u64)
                    .unwrap_or(1);
                let title_s = meta_row
                    .as_ref()
                    .and_then(|m| m.title.clone())
                    .unwrap_or_default();
                let desc_s = meta_row
                    .as_ref()
                    .and_then(|m| m.description.clone())
                    .unwrap_or_default();
                let avatar_opt = meta_row
                    .as_ref()
                    .and_then(chat_wire::space_avatar_from_metadata_row);
                let meta_key = derive_metadata_key_from_group(
                    &mut group,
                    provider.crypto(),
                    provider.storage(),
                    &convo.group_id,
                    next_epoch,
                )
                .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                    tx,
                    cid,
                    &meta_key,
                    &convo.group_id,
                    &convo_uuid,
                    prior_gen,
                    next_epoch,
                    &next_gch,
                    &next_ctag,
                    &transition_id,
                    meta_ver,
                    canonical_dev_id,
                    auth_generation,
                    signer.public(),
                    &title_s,
                    &desc_s,
                    avatar_opt,
                )?;
                drop(provider);
                let kv_batch = overlay.into_batch();
                Ok(Some((
                    kv_batch,
                    convo.group_id,
                    commit_aad_val,
                    commit_bytes,
                    welcome_bytes,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                )))
            })?;

            let Some((
                kv_batch,
                group_id,
                commit_aad_val,
                commit_bytes,
                welcome_bytes,
                next_epoch,
                next_gch,
                next_ctag,
                carried_snap,
            )) = built
            else {
                continue;
            };

            let next_coords = json!({
                "conversationId": cid,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });

            let fulfill_body = json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
                "transitionId": transition_id,
                "recoveryRequestId": recovery_request_id,
                "idempotencyKey": transition_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_generation,
                "signedAt": self.hooks.now_rfc3339_millis(),
                "prior": prior_coords,
                "next": next_coords,
                "aad": commit_aad_val,
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": [{
                        "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                        "userDid": target_did,
                        "deviceId": target_device_id,
                        "recoveryRequestId": recovery_request_id,
                        "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                    }],
                    "leafRecoveryRequestId": recovery_request_id,
                    "welcomeBundle": {
                        "welcomeId": welcome_id,
                        "framing": "mlsMessage",
                        "contentType": "welcome",
                        "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome_bytes) },
                        "sha256": STANDARD.encode(Sha256::digest(&welcome_bytes)),
                        "deliveries": [{
                            "recipientDid": target_did,
                            "recipientDeviceId": target_device_id,
                            "provenance": {
                                "recoveryRequestId": recovery_request_id,
                                "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                            }
                        }]
                    }
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
                },
                "metadataSnapshot": carried_snap.clone(),
            });

            let resp_val = match self.submit_signed_chat_op(
                canonical_dev_id,
                Some(auth_generation),
                CanonicalOperation::SubmitTransition,
                &fulfill_body,
                signer,
            ) {
                Ok(val) => val,
                Err(e) if e.to_string().contains("HTTP 409") => {
                    // Concurrent peer transition superseded `boundCoordinate`; discard overlay cleanly!
                    continue;
                }
                Err(e) => return Err(e),
            };

            let authoritative_seq = resp_val
                .get("seq")
                .or_else(|| resp_val.pointer("/entry/seq"))
                .and_then(|v| v.as_i64());
            let coords_str = serde_json::to_string(&next_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let snap_str = serde_json::to_string(&carried_snap)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            if crate::buggify!("after_http_2xx_before_db_commit") {
                return Err(MLSError::Internal(
                    "sim buggify: after_http_2xx_before_db_commit".to_string(),
                ));
            }
            self.db.write_tx(|tx| {
                kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                if let Some(mut c) = tx.get_conversation(cid)? {
                    c.epoch = next_epoch as i64;
                    if let Some(seq) = authoritative_seq {
                        if seq == c.last_seq + 1 {
                            c.last_seq = seq;
                        }
                    }
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(&format!("metadata_snapshot_json:{cid}"), &snap_str, now_ms)?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, now_ms)
            })?;
            fulfilled = fulfilled.saturating_add(1);
        }

        Ok(fulfilled)
    }

    pub(crate) fn sync_conversation_entries(
        &self,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        convo: &ConversationRow,
    ) -> Result<u32, MLSError> {
        let cid = convo.conversation_id.as_str();
        if uuid::Uuid::parse_str(cid)
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .is_none()
        {
            return Ok(0);
        }

        let mut sorted_entries: Vec<Value> = Vec::new();
        let mut cursor_seq = convo.last_seq.max(0);
        for _ in 0..50 {
            let after_seq_str = cursor_seq.to_string();
            let resp = self.query_signed_chat_ds(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("afterSeq", &after_seq_str),
                    ("conversationId", cid),
                    ("limit", "100"),
                ],
                canonical_dev_id,
                signer,
            )?;
            let Some(page_entries) = resp.get("entries").and_then(|v| v.as_array()) else {
                break;
            };
            if page_entries.is_empty() {
                break;
            }
            let page_len = page_entries.len();
            let page_max_seq = page_entries
                .iter()
                .filter_map(|e| e.get("seq").and_then(|s| s.as_i64()))
                .max()
                .unwrap_or(cursor_seq);
            sorted_entries.extend(page_entries.iter().cloned());
            if page_len < 100 || page_max_seq <= cursor_seq {
                break;
            }
            cursor_seq = page_max_seq;
        }
        if sorted_entries.is_empty() {
            return Ok(0);
        }

        sorted_entries.sort_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));
        sorted_entries.dedup_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));

        // Pre-fetch PDS `blue.catbird.chat.device` keys (`I4`) for all DIDs referenced in batch
        // plus all current local `MlsGroup` members.
        let mut candidate_dids = BTreeMap::new();
        for entry in &sorted_entries {
            chat_wire::collect_dids_from_json(entry, &mut candidate_dids);
        }
        let existing_member_dids: Vec<String> = self.db.read_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let mut found = Vec::new();
            if let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group members: {e:?}")))?
            {
                for m in group.members() {
                    if let Ok((d, _)) =
                        root_did_from_credential_bytes(m.credential.serialized_content())
                    {
                        found.push(d);
                    }
                }
            }
            Ok(found)
        })?;
        for d in existing_member_dids {
            candidate_dids.insert(d, ());
        }
        let mut auth_keys_by_did: BTreeMap<String, Vec<AuthorizedPeerDeviceKey>> = BTreeMap::new();
        for did in candidate_dids.keys() {
            let keys = self.fetch_and_cache_authorized_pds_device_keys(did)?;
            auth_keys_by_did.insert(did.clone(), keys);
        }
        let flat_auth_keys: Vec<AuthorizedPeerDeviceKey> = auth_keys_by_did
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let mut max_seq = convo.last_seq;
        let mut applied_count = 0u32;
        let mut saw_c33_accept = false;
        let mut was_kicked = false;

        for entry in &sorted_entries {
            let entry_seq = entry.get("seq").and_then(|v| v.as_i64()).unwrap_or(max_seq);
            let entry_type = entry
                .get("$type")
                .or_else(|| entry.get("entryKind"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let signed_req = entry.get("signedRequest").unwrap_or(entry);
            let body = signed_req.get("body").unwrap_or(signed_req);
            let body_type = body.get("$type").and_then(|v| v.as_str()).unwrap_or("");
            let now_ms = self.hooks.now_ms();

            if entry_type.ends_with("accountDeletedEntry") || entry_type == "accountDeleted" {
                if let Some(deleted_did) = entry
                    .get("deletedDid")
                    .or_else(|| body.get("actorDid"))
                    .and_then(|v| v.as_str())
                {
                    let _ = handle_account_deleted_event(&self.db, deleted_did);
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("directRequestAcceptanceEntry")
                || body_type.ends_with("directRequestAcceptanceBody")
                || entry_type.ends_with("participantAcceptanceEntry")
                || body_type.ends_with("participantAcceptanceBody")
            {
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());
                self.db.write_tx(|tx| {
                    let mut reqs = tx.list_requests(None)?;
                    for r in &mut reqs {
                        if r.conversation_id == cid {
                            r.consent = "accepted".to_string();
                            r.updated_at_ms = now_ms;
                            tx.upsert_request(r)?;
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, now_ms)?;
                    }
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                saw_c33_accept = true;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("policyTransitionEntry")
                || body_type.ends_with("policyTransitionBody")
            {
                if let Some(nc) = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok())
                {
                    let s = serde_json::to_string(&nc)
                        .map_err(|e| MLSError::Internal(e.to_string()))?;
                    self.db.write_tx(|tx| {
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, now_ms)?;
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("metadataEntry")
                || body_type.ends_with("metadataTransitionBody")
            {
                let snap_opt = body
                    .get("metadataSnapshot")
                    .or_else(|| entry.get("metadataSnapshot"));
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());
                self.db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(());
                    };
                    if let Some(snap) = snap_opt {
                        let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                        let provider = self.hooks.openmls_provider(storage);
                        if let Some(mut group) =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        {
                            if let Some((m_epoch, m_ver, meta)) =
                                chat_wire::try_decrypt_group_metadata_snapshot(
                                    &mut group, &provider, snap,
                                )
                            {
                                let meta_row = chat_wire::group_metadata_row_from_v1(
                                    cid, m_ver, m_epoch, &meta, now_ms,
                                )?;
                                c.title = meta_row.title.clone();
                                tx.upsert_group_metadata(&meta_row)?;
                            }
                        }
                        if let Ok(snap_s) = serde_json::to_string(snap) {
                            tx.put_account_meta(
                                &format!("metadata_snapshot_json:{cid}"),
                                &snap_s,
                                now_ms,
                            )?;
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, now_ms)?;
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)
                })?;
                self.notify_change(PlatformChangeEvent::GroupMetadataUpdated {
                    conversation_id: cid.to_string(),
                });
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("commitEntry")
                || entry_type.ends_with("leafRecoveryFulfillmentEntry")
                || body_type.ends_with("commitTransitionBody")
                || body_type.ends_with("leafRecoveryFulfillmentBody")
            {
                let actor_did = body
                    .get("actorDid")
                    .or_else(|| entry.get("actorDid"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let actor_dev = body
                    .get("actorDeviceId")
                    .or_else(|| entry.get("actorDeviceId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_own_echo = actor_did == self.normalized_did && actor_dev == canonical_dev_id;
                let commit_bytes_opt = body
                    .get("commit")
                    .or_else(|| entry.get("commit"))
                    .and_then(|c| c.get("bytes"))
                    .and_then(|b| chat_wire::json_bytes(b).ok());
                let snap_opt = body
                    .get("metadataSnapshot")
                    .or_else(|| entry.get("metadataSnapshot"));
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());

                let self_removed = self.db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(false);
                    };
                    let mut removed_self = false;
                    if !is_own_echo {
                        if let Some(ref commit_bytes) = commit_bytes_opt {
                            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                            let provider = self.hooks.openmls_provider(storage);
                            if let Some(mut group) = MlsGroup::load(
                                provider.storage(),
                                &GroupId::from_slice(&c.group_id),
                            )
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                            {
                                let msg_in = MlsMessageIn::tls_deserialize_exact(commit_bytes)
                                    .map_err(|e| {
                                        MLSError::Cryptography(format!("deserialize Commit: {e:?}"))
                                    })?;
                                let proto = msg_in.try_into_protocol_message().map_err(|e| {
                                    MLSError::Cryptography(format!("commit protocol msg: {e:?}"))
                                })?;
                                if proto.epoch().as_u64() == group.epoch().as_u64() {
                                    let processed =
                                        group.process_message(&provider, proto).map_err(|e| {
                                            MLSError::Cryptography(format!("process Commit: {e:?}"))
                                        })?;
                                    let commit_sender = processed.sender().clone();
                                    if let ProcessedMessageContent::StagedCommitMessage(staged) =
                                        processed.into_content()
                                    {
                                        chat_wire::verify_staged_commit_slice_i4(
                                            &group,
                                            &commit_sender,
                                            &staged,
                                            &flat_auth_keys,
                                        )?;
                                        removed_self = staged.self_removed();
                                        group.merge_staged_commit(&provider, *staged).map_err(
                                            |e| {
                                                MLSError::Cryptography(format!(
                                                    "merge_staged_commit: {e:?}"
                                                ))
                                            },
                                        )?;
                                        c.epoch = group.epoch().as_u64() as i64;
                                    }
                                }
                                if let Some(snap) = snap_opt {
                                    if let Some((m_epoch, m_ver, meta)) =
                                        chat_wire::try_decrypt_group_metadata_snapshot(
                                            &mut group, &provider, snap,
                                        )
                                    {
                                        let meta_row = chat_wire::group_metadata_row_from_v1(
                                            cid, m_ver, m_epoch, &meta, now_ms,
                                        )?;
                                        c.title = meta_row.title.clone();
                                        tx.upsert_group_metadata(&meta_row)?;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(snap) = snap_opt {
                        if let Ok(snap_s) = serde_json::to_string(snap) {
                            tx.put_account_meta(
                                &format!("metadata_snapshot_json:{cid}"),
                                &snap_s,
                                now_ms,
                            )?;
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, now_ms)?;
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                    Ok(removed_self)
                })?;

                if self_removed {
                    was_kicked = true;
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("applicationMessageEntry")
                || entry_type.ends_with("applicationEntry")
                || body_type.ends_with("applicationSendBody")
                || body.get("applicationMessage").is_some()
                || entry.get("applicationMessage").is_some()
            {
                if entry.get("payloadPruned").and_then(|v| v.as_bool()) == Some(true) {
                    self.db.write_tx(|tx| {
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }

                let msg_id = body
                    .get("messageId")
                    .or_else(|| entry.get("messageId"))
                    .or_else(|| entry.get("entryId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if msg_id.is_empty() {
                    max_seq = max_seq.max(entry_seq);
                    continue;
                }

                let already_have = self.db.read_tx(|tx| tx.get_message(msg_id))?.is_some();
                if already_have {
                    self.db.write_tx(|tx| {
                        tx.conn()
                            .execute(
                                "UPDATE messages SET seq = ?1 WHERE message_id = ?2;",
                                rusqlite::params![entry_seq, msg_id],
                            )
                            .map_err(|e| MLSError::Internal(format!("update echo seq: {e}")))?;
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = now_ms;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    max_seq = max_seq.max(entry_seq);
                    continue;
                }

                // Enforce `I13`: require & resolve sequencer receipt key strictly outside `write_tx` (`I6`)!
                let rcpt_val = entry
                    .get("sequencerReceipt")
                    .filter(|v| v.is_object())
                    .ok_or_else(|| {
                        MLSError::Cryptography(format!(
                            "I13: applicationEntry {msg_id} at seq {entry_seq} missing sequencerReceipt"
                        ))
                    })?;
                let rcpt_kid = rcpt_val
                    .get("kid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("#mls-receipt-1");
                let rcpt_sec1 = self
                    .resolve_sequencer_receipt_key(&convo.sequencer_did, rcpt_kid)?
                    .ok_or_else(|| {
                        MLSError::Cryptography(format!(
                            "I13: unable to resolve `{}` DID document for #mls-receipt-1 verification",
                            convo.sequencer_did
                        ))
                    })?;
                let expected_rcpt_entry_id = entry
                    .get("entryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(msg_id);

                let app_obj = body
                    .get("applicationMessage")
                    .or_else(|| entry.get("applicationMessage"))
                    .unwrap_or(entry);
                let ct_bytes = chat_wire::json_bytes(
                    app_obj
                        .get("bytes")
                        .or_else(|| entry.get("ciphertext"))
                        .ok_or_else(|| {
                            MLSError::invalid_input("applicationMessageEntry missing bytes")
                        })?,
                )?;

                self.db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(());
                    };
                    let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                    let provider = self.hooks.openmls_provider(storage);
                    let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    else {
                        return Ok(());
                    };
                    let msg_in = MlsMessageIn::tls_deserialize_exact(&ct_bytes).map_err(|e| {
                        MLSError::Cryptography(format!("deserialize app msg: {e:?}"))
                    })?;
                    let proto = msg_in
                        .try_into_protocol_message()
                        .map_err(|e| MLSError::Cryptography(format!("app protocol msg: {e:?}")))?;
                    let msg_epoch = proto.epoch().as_u64() as i64;
                    let processed = group
                        .process_message(&provider, proto)
                        .map_err(|e| MLSError::Cryptography(format!("decrypt app msg: {e:?}")))?;
                    let sender_cred = processed.credential().clone();
                    let aad_bytes = processed.aad().to_vec();

                    // Verify sender leaf binding against PDS `blue.catbird.chat.device` (`I4`)!
                    let sender_id_str = std::str::from_utf8(sender_cred.serialized_content())
                        .map_err(|_| MLSError::Cryptography("non-UTF8 credential".to_string()))?;
                    let (sender_did, sender_dev_id) = sender_id_str
                        .split_once('#')
                        .ok_or_else(|| MLSError::Cryptography("unscoped credential".to_string()))?;
                    let member = group
                        .members()
                        .find(|m| {
                            m.credential.serialized_content() == sender_cred.serialized_content()
                        })
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "I4: applicationMessage sender leaf not in group roster"
                                    .to_string(),
                            )
                        })?;
                    chat_wire::verify_leaf_slice_i4(
                        member.credential.serialized_content(),
                        member.signature_key.as_slice(),
                        &flat_auth_keys,
                    )?;

                    let ProcessedMessageContent::ApplicationMessage(app_msg) =
                        processed.into_content()
                    else {
                        return Err(MLSError::Cryptography(
                            "expected ApplicationMessage".to_string(),
                        ));
                    };
                    let (display_body, json_str, verified_commitment_opt) =
                        extract_plaintext_body_and_verify_aad(&app_msg.into_bytes(), &aad_bytes)?;
                    let _ = display_body;
                    let verified_commitment = verified_commitment_opt.ok_or_else(|| {
                        MLSError::Cryptography(
                            "I13: applicationEntry missing verified AAD archiveCommitment"
                                .to_string(),
                        )
                    })?;

                    let (rcpt_seq, _, _) = chat_wire::parse_and_verify_i13_sequencer_receipt(
                        rcpt_val,
                        &rcpt_sec1,
                        &c.sequencer_did,
                        cid,
                        &c.group_id,
                        msg_epoch.max(0) as u64,
                        expected_rcpt_entry_id,
                        &verified_commitment,
                    )?;
                    if rcpt_seq as i64 != entry_seq {
                        return Err(MLSError::Cryptography(format!(
                            "I13: receipt seq {rcpt_seq} != entry seq {entry_seq}"
                        )));
                    }

                    tx.insert_message(&MessageRow {
                        message_id: msg_id.to_string(),
                        conversation_id: cid.to_string(),
                        group_id: c.group_id.clone(),
                        epoch: msg_epoch,
                        seq: entry_seq,
                        sender_did: sender_did.to_string(),
                        sender_device_id: sender_dev_id.to_string(),
                        plaintext_json: json_str,
                        created_at_ms: now_ms,
                        is_own: sender_did == self.normalized_did,
                    })?;
                    c.last_seq = c.last_seq.max(entry_seq);
                    if sender_did != self.normalized_did {
                        c.unread_count = c.unread_count.saturating_add(1);
                    }
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)
                })?;

                self.notify_change(PlatformChangeEvent::MessagesUpdated {
                    conversation_id: cid.to_string(),
                });
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            // Other control entries: advance cursor cleanly.
            self.db.write_tx(|tx| {
                if let Some(mut c) = tx.get_conversation(cid)? {
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                }
                Ok(())
            })?;
            max_seq = max_seq.max(entry_seq);
        }

        if saw_c33_accept {
            let _ = self.archive_accepted_opening_messages(cid);
            self.notify_change(PlatformChangeEvent::RequestsUpdated);
        }
        if was_kicked {
            let _ = self.rescue_conversation_on_kick(cid);
        }
        if max_seq >= 1 && applied_count > 0 && !was_kicked {
            self.acknowledge_entries_up_to(cid, max_seq)?;
        }

        Ok(applied_count)
    }
}
