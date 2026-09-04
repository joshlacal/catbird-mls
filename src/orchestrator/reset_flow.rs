//! Clean-chat conversation reset driven entirely by server state.
//!
//! A device that lost its MLS group (reinstall, storage reset) cannot use
//! External Commit under `blue.catbird.chat.*` — no endpoint returns
//! GroupInfo — and can only be re-added by a *live* MLS leaf of another
//! participant fulfilling its leaf-recovery request. When no such leaf exists
//! the conversation is dead for everyone. The server's answer is
//! `requestReset` + `activateReset`: any active admin device may call both
//! without holding a leaf, becomes the sole genesis leaf of the successor
//! generation, and every other active participant re-adds itself through its
//! own leaf recovery against that fresh leaf.
//!
//! Everything here reads the coordinate it echoes back from the server, never
//! from local MLS state, so it works from a blank device.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::MLSError;

use super::api_client::MLSAPIClient;
use super::canonical_transport::{CanonicalOperation, PreparedRequest};
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::pagination::PaginationGuard;
use super::storage::MLSStorageBackend;
use super::types::*;

/// Server `RECOVERY_RESERVATION_TTL_MILLIS`: an open leaf-recovery request
/// nobody fulfils within this window expires. Once it has, waiting longer
/// cannot help — escalate to a reset.
pub(crate) const LEAF_RECOVERY_TTL: Duration = Duration::from_secs(300);

/// Outcome of [`MLSOrchestrator::reset_conversation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetOutcome {
    /// This device activated the successor generation and now holds its
    /// genesis leaf at `epoch`.
    Activated { epoch: u64 },
    /// A reset request is pending on the server; this device is not an admin
    /// and must wait for an admin device to activate.
    Requested,
}

/// The slice of `blue.catbird.chat.defs#conversationState` the reset flow
/// needs, kept as raw JSON so coordinates are echoed back byte-exact.
#[derive(Debug, Clone)]
pub(crate) struct ServerConversationState {
    pub conversation_id: String,
    pub kind: String,
    pub coordinates: serde_json::Value,
    pub participants: Vec<serde_json::Value>,
    /// `None` when the server response carried no `leaves` array; the
    /// escalation policy then never assumes nobody can add us.
    pub leaves: Option<Vec<serde_json::Value>>,
    pub metadata_version: u64,
}

impl ServerConversationState {
    pub(crate) fn from_state_json(conversation_id: &str, state: &serde_json::Value) -> Result<Self> {
        let missing = |field: &str| {
            OrchestratorError::Api(format!("conversation state missing {field}"))
        };
        Ok(Self {
            conversation_id: conversation_id.to_string(),
            kind: state
                .get("conversationKind")
                .and_then(|v| v.as_str())
                .ok_or_else(|| missing("conversationKind"))?
                .to_string(),
            coordinates: state.get("coordinates").cloned().ok_or_else(|| missing("coordinates"))?,
            participants: state
                .get("participants")
                .and_then(|v| v.as_array())
                .cloned()
                .ok_or_else(|| missing("participants"))?,
            leaves: state
                .get("leaves")
                .and_then(|v| v.as_array())
                .cloned(),
            metadata_version: state
                .get("metadataSnapshot")
                .and_then(|m| m.get("metadataVersion"))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| missing("metadataSnapshot.metadataVersion"))?,
        })
    }

    fn participant(&self, user_did: &str) -> Option<&serde_json::Value> {
        self.participants
            .iter()
            .find(|p| p.get("userDid").and_then(|v| v.as_str()) == Some(user_did))
    }

    /// `(role, status)` of `user_did`, or an error when it is not a participant.
    pub(crate) fn own_role_status(&self, user_did: &str) -> Result<(String, String)> {
        let me = self.participant(user_did).ok_or_else(|| {
            OrchestratorError::Api(format!(
                "{user_did} is not a participant of {}",
                self.conversation_id
            ))
        })?;
        let field = |name: &str| me.get(name).and_then(|v| v.as_str()).unwrap_or("").to_string();
        Ok((field("role"), field("status")))
    }

    /// True only when the server told us the leaf set and no *other*
    /// participant holds an unrevoked MLS leaf — i.e. nobody but our own
    /// (possibly dead) devices could fulfil an `add` leaf recovery for us.
    /// Unknown leaves never count as "nobody".
    pub(crate) fn nobody_else_can_add(&self, user_did: &str) -> bool {
        self.leaves.as_ref().is_some_and(|leaves| {
            !leaves.iter().any(|leaf| {
                leaf.get("userDid").and_then(|v| v.as_str()) != Some(user_did)
                    && leaf.get("deviceStatus").and_then(|v| v.as_str()) != Some("revoked")
            })
        })
    }

    /// True when the server still lists an unrevoked leaf for this exact
    /// device — leaf recovery must then be `replace`, not `add`. Unknown
    /// leaves default to `add`.
    pub(crate) fn own_device_holds_leaf(&self, user_did: &str, device_id: &str) -> bool {
        self.leaves.as_ref().is_some_and(|leaves| {
            leaves.iter().any(|leaf| {
                leaf.get("userDid").and_then(|v| v.as_str()) == Some(user_did)
                    && leaf.get("deviceId").and_then(|v| v.as_str()) == Some(device_id)
                    && leaf.get("deviceStatus").and_then(|v| v.as_str()) != Some("revoked")
            })
        })
    }

    fn coordinate_i64(&self, field: &str) -> Result<i64> {
        self.coordinates
            .get(field)
            .and_then(|v| v.as_i64())
            .ok_or_else(|| OrchestratorError::Api(format!("coordinates.{field} missing")))
    }

    fn coordinate_bytes(&self, field: &str) -> Result<Vec<u8>> {
        json_bytes(self.coordinates.get(field))
            .ok_or_else(|| OrchestratorError::Api(format!("coordinates.{field} missing")))
    }

    /// The server's current coordinate re-encoded canonically, with
    /// `stateVersion`/`lifecycle` overridable to derive `retired`.
    fn coordinate_json(&self, state_version: i64, lifecycle: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "confirmationTag": { "$bytes": STANDARD.encode(self.coordinate_bytes("confirmationTag")?) },
            "conversationId": self.conversation_id,
            "epoch": self.coordinate_i64("epoch")?,
            "generation": self.coordinate_i64("generation")?,
            "groupContextHash": { "$bytes": STANDARD.encode(self.coordinate_bytes("groupContextHash")?) },
            "groupId": { "$bytes": STANDARD.encode(self.coordinate_bytes("groupId")?) },
            "lifecycle": lifecycle,
            "stateVersion": state_version
        }))
    }

    pub(crate) fn prior_json(&self) -> Result<serde_json::Value> {
        self.coordinate_json(self.coordinate_i64("stateVersion")?, "active")
    }

    fn retired_json(&self) -> Result<serde_json::Value> {
        self.coordinate_json(self.coordinate_i64("stateVersion")? + 1, "superseded")
    }

    /// `resetActivationManifest.participants`: the server roster echoed back
    /// exactly (order, status, role, provenance). The server rejects any
    /// deviation rather than sorting.
    fn manifest_participants(&self) -> Vec<serde_json::Value> {
        self.participants
            .iter()
            .map(|p| {
                let mut entry = serde_json::json!({
                    "userDid": p.get("userDid").cloned().unwrap_or_default(),
                    "role": p.get("role").cloned().unwrap_or_default(),
                    "status": p.get("status").cloned().unwrap_or_default(),
                });
                if let Some(prov) = p.get("invitationProvenance") {
                    entry["invitationProvenance"] = prov.clone();
                }
                entry
            })
            .collect()
    }
}

/// Decode a clean-chat bytes field: `{"$bytes": b64}` or a bare base64 string.
fn json_bytes(value: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    let encoded = value?;
    let text = encoded
        .get("$bytes")
        .and_then(|b| b.as_str())
        .or_else(|| encoded.as_str())?;
    STANDARD.decode(text).ok()
}

fn is_reset_already_pending(error: &OrchestratorError) -> bool {
    matches!(error, OrchestratorError::ServerError { body, .. } if body.contains("ResetAlreadyPending"))
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Current server view of `convo_id` from the device-admitted inventory
    /// (`getConversations`), which a leafless device may still read.
    pub(crate) async fn fetch_server_conversation_state(
        &self,
        convo_id: &str,
    ) -> Result<ServerConversationState> {
        let actor_device_id = self.require_actor_device_id().await?;
        let mut cursor: Option<String> = None;
        let mut pagination = PaginationGuard::for_conversations("reset state lookup");
        loop {
            let mut path = format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={actor_device_id}&limit=100"
            );
            if let Some(cursor) = &cursor {
                path.push_str("&pageCursor=");
                path.push_str(cursor);
            }
            let response = self
                .api_client()
                .submit_prepared_request(PreparedRequest {
                    operation: CanonicalOperation::GetConversations,
                    path,
                    method: "GET".to_string(),
                    body: None,
                })
                .await?;
            if response.status != 200 {
                return Err(OrchestratorError::ServerError {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                });
            }
            let page: serde_json::Value = serde_json::from_slice(&response.body)
                .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
            let items = page.get("items").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let next = page
                .get("nextPageCursor")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            pagination.observe_page(items.len(), next.as_deref())?;
            for item in &items {
                let state = item.get("state").unwrap_or(item);
                let id = state
                    .get("coordinates")
                    .and_then(|c| c.get("conversationId"))
                    .and_then(|v| v.as_str());
                if id == Some(convo_id) {
                    return ServerConversationState::from_state_json(convo_id, state);
                }
            }
            cursor = next;
            if cursor.is_none() {
                return Err(OrchestratorError::ConversationNotFound(format!(
                    "server inventory does not contain {convo_id}"
                )));
            }
        }
    }

    /// Reset `convo_id` from a device that has no usable local MLS state.
    ///
    /// Records a `requestReset` at the server's exact current coordinate
    /// (reusing one already pending) and, when this device is an active admin,
    /// activates the successor generation immediately: a fresh local group,
    /// its genesis GroupInfo, and a fresh empty metadata snapshot are submitted
    /// through `activateReset`. On success the local conversation mapping
    /// points at the new group and the conversation is `Active` again.
    pub async fn reset_conversation(&self, convo_id: &str, reason: &str) -> Result<ResetOutcome> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let convo_id = self.resolve_conversation_uuid(convo_id).await?;
        let state = self.fetch_server_conversation_state(&convo_id).await?;
        let (role, status) = state.own_role_status(&user_did)?;
        if status != "active" {
            return Err(OrchestratorError::InvalidInput(format!(
                "cannot reset {convo_id}: participant status is {status}"
            )));
        }
        let reset_request_id = self.ensure_reset_request(&state, reason).await?;
        if role != "admin" {
            crate::warn_log!(
                "[RESET] convo={} reset requested ({}); activation needs an admin device",
                convo_id,
                reason
            );
            return Ok(ResetOutcome::Requested);
        }
        // The activation's metadata author proof must name the seq the
        // activation entry lands at: one past the current entry tail (which
        // now includes the request entry when we appended one).
        let origin_seq = self.latest_entry_seq(&convo_id).await? + 1;
        let epoch = self
            .activate_reset(&user_did, &state, &reset_request_id, origin_seq)
            .await?;
        crate::info_log!("[RESET] convo={} activated successor generation ({})", convo_id, reason);
        Ok(ResetOutcome::Activated { epoch })
    }

    async fn resolve_conversation_uuid(&self, conversation_id: &str) -> Result<String> {
        if uuid::Uuid::parse_str(conversation_id).is_ok() {
            return Ok(conversation_id.to_string());
        }
        let resolved = self.resolve_legacy_group_identifier(conversation_id).await?;
        uuid::Uuid::parse_str(&resolved.conversation_id)
            .map(|u| u.to_string())
            .map_err(|e| OrchestratorError::InvalidInput(e.to_string()))
    }

    /// Re-admit this leafless device: ask a live leaf of another participant
    /// to add (or replace) our leaf, or reset when that can never succeed.
    ///
    /// Only a live leaf of *another* participant can fulfil our request. When
    /// no such leaf exists, or our open request already outlived the server
    /// TTL unfulfilled, waiting cannot help — an admin device resets the
    /// conversation instead. Every coordinate comes from `state`, never from
    /// local MLS state, so this works from a blank device.
    ///
    /// Returns `{"epoch": n}` when a reset was activated here, otherwise the
    /// server's leaf-recovery output or `{"leafRecovery": "open"}`.
    pub(crate) async fn recover_leaf_or_reset(
        &self,
        state: &ServerConversationState,
        user_did: &str,
    ) -> Result<serde_json::Value> {
        let convo_id = state.conversation_id.as_str();
        let (role, _) = state.own_role_status(user_did)?;
        let waited = self.recovery_tracker().lock().await.leaf_recovery_wait(convo_id);
        let nobody_can_add_us = state.nobody_else_can_add(user_did);
        let waited_out = waited.is_some_and(|w| w >= LEAF_RECOVERY_TTL);
        if role == "admin" && (nobody_can_add_us || waited_out) {
            crate::warn_log!(
                "[RESET] convo={} leaf recovery cannot succeed (nobody_else_can_add={}, waited={:?}); resetting",
                convo_id,
                nobody_can_add_us,
                waited
            );
            return match self.reset_conversation(convo_id, "localStateLost").await? {
                ResetOutcome::Activated { epoch } => Ok(serde_json::json!({ "epoch": epoch })),
                ResetOutcome::Requested => Ok(serde_json::json!({ "reset": "requested" })),
            };
        }
        if waited.is_some_and(|w| w < LEAF_RECOVERY_TTL) {
            // Our add request is still open server-side; re-requesting only
            // earns LeafRecoveryAlreadyOpen.
            return Ok(serde_json::json!({ "leafRecovery": "open" }));
        }
        let actor_device_id = self.require_actor_device_id().await?;
        let kind = if state.own_device_holds_leaf(user_did, &actor_device_id) {
            "replace"
        } else {
            "add"
        };
        let result = self.request_leaf_recovery(state, kind).await;
        let mut tracker = self.recovery_tracker().lock().await;
        match &result {
            Ok(_) => tracker.note_leaf_recovery_requested(convo_id),
            Err(err) if err.to_string().contains("LeafRecoveryAlreadyOpen") => {
                // Opened by an earlier process of ours; start the clock now so
                // an unfulfilled request still escalates.
                if tracker.leaf_recovery_wait(convo_id).is_none() {
                    tracker.note_leaf_recovery_requested(convo_id);
                }
                return Ok(serde_json::json!({ "leafRecovery": "open" }));
            }
            Err(_) => {}
        }
        result
    }

    /// Submit `requestReset` bound to the server's current coordinate and
    /// return the pending request id; adopt an existing pending request when
    /// the server reports `ResetAlreadyPending`.
    pub(crate) async fn ensure_reset_request(&self, state: &ServerConversationState, reason: &str) -> Result<String> {
        let reason = match reason {
            "localStateLost" | "poisonedState" | "epochDivergence" | "manualRecovery" => reason,
            _ => "manualRecovery",
        };
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self.require_auth_generation(&user_did).await?;
        let key_id = self.own_key_id().await?;
        let reset_request_id = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "idempotencyKey": reset_request_id,
            "keyId": key_id,
            "prior": state.prior_json()?,
            "reason": reason,
            "resetRequestId": reset_request_id,
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });
        let response = self
            .submit_signed_clean_chat_request(
                CanonicalOperation::RequestReset,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status == 200 {
            let output: serde_json::Value = serde_json::from_slice(&response.body)
                .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
            // Mock/legacy servers may omit the echoed view; our id is the id.
            return Ok(output
                .get("resetRequest")
                .and_then(|r| r.get("resetRequestId"))
                .and_then(|v| v.as_str())
                .unwrap_or(&reset_request_id)
                .to_string());
        }
        let error = OrchestratorError::ServerError {
            status: response.status,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        };
        if !is_reset_already_pending(&error) {
            return Err(error);
        }
        self.pending_reset_request_id(state).await?.ok_or(error)
    }

    /// The id of an unexpired pending reset request bound to the server's
    /// current coordinate, from `getConversationState`.
    async fn pending_reset_request_id(&self, state: &ServerConversationState) -> Result<Option<String>> {
        let actor_device_id = self.require_actor_device_id().await?;
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::GetConversationState,
                path: format!(
                    "/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={actor_device_id}&conversationId={}",
                    state.conversation_id
                ),
                method: "GET".to_string(),
                body: None,
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        let output: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let current_group = state.coordinate_bytes("groupId")?;
        let current_generation = state.coordinate_i64("generation")?;
        let current_state_version = state.coordinate_i64("stateVersion")?;
        Ok(output
            .get("pendingResetRequests")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .find(|request| {
                let prior = request.get("prior");
                request.get("status").and_then(|v| v.as_str()) == Some("pending")
                    && prior.and_then(|p| p.get("generation")).and_then(|v| v.as_i64()) == Some(current_generation)
                    && prior.and_then(|p| p.get("stateVersion")).and_then(|v| v.as_i64()) == Some(current_state_version)
                    && json_bytes(prior.and_then(|p| p.get("groupId"))).as_deref() == Some(current_group.as_slice())
            })
            .and_then(|request| request.get("resetRequestId").and_then(|v| v.as_str()))
            .map(str::to_string))
    }

    /// Seq of the last entry in `convo_id`'s log, paged to the tail.
    async fn latest_entry_seq(&self, convo_id: &str) -> Result<u64> {
        let actor_device_id = self.require_actor_device_id().await?;
        let mut after_seq = 0u64;
        let mut pagination = PaginationGuard::for_messages("reset entry tail");
        loop {
            let response = self
                .api_client()
                .submit_prepared_request(PreparedRequest {
                    operation: CanonicalOperation::GetEntries,
                    path: format!(
                        "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={actor_device_id}&conversationId={convo_id}&afterSeq={after_seq}&limit=100"
                    ),
                    method: "GET".to_string(),
                    body: None,
                })
                .await?;
            if response.status != 200 {
                return Err(OrchestratorError::ServerError {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                });
            }
            let page: serde_json::Value = serde_json::from_slice(&response.body)
                .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
            let entries = page.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let next = page.get("nextAfterSeq").and_then(|v| v.as_u64());
            let has_more = page.get("hasMore").and_then(|v| v.as_bool()).unwrap_or(false);
            let next_cursor = next.map(|n| n.to_string());
            pagination.observe_page(entries.len(), next_cursor.as_deref())?;
            after_seq = entries
                .iter()
                .filter_map(|e| e.get("seq").and_then(|v| v.as_u64()))
                .fold(after_seq, u64::max)
                .max(next.unwrap_or(0));
            if !has_more || entries.is_empty() {
                return Ok(after_seq);
            }
        }
    }

    async fn activate_reset(
        &self,
        user_did: &str,
        state: &ServerConversationState,
        reset_request_id: &str,
        origin_seq: u64,
    ) -> Result<u64> {
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self.require_auth_generation(user_did).await?;
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        let key_id = super::canonical_transport::derive_key_id(&public_key);
        let identity_bytes = scoped_identity.into_bytes();
        let prior_group_id = state.coordinate_bytes("groupId")?;

        let mut new_group_id = vec![0u8; 32];
        loop {
            rand::thread_rng().fill_bytes(&mut new_group_id);
            if new_group_id != prior_group_id {
                break;
            }
        }
        self.mls_context().create_group_with_id(
            identity_bytes.clone(),
            new_group_id.clone(),
            Some(self.config().group_config.clone()),
        )?;

        match self
            .submit_reset_activation(user_did, &actor_device_id, auth_generation, &key_id, &public_key, &identity_bytes, state, reset_request_id, &new_group_id, origin_seq)
            .await
        {
            Ok(()) => {}
            Err(error) => {
                if let Err(cleanup) = self.mls_context().delete_group(new_group_id.clone()) {
                    tracing::warn!(
                        convo_id = %state.conversation_id,
                        error = %cleanup,
                        "reset activation failed and the candidate group could not be deleted"
                    );
                }
                return Err(error);
            }
        }

        self.adopt_reset_successor(user_did, state, &new_group_id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_reset_activation(
        &self,
        user_did: &str,
        actor_device_id: &str,
        auth_generation: i64,
        key_id: &str,
        public_key: &[u8],
        identity_bytes: &[u8],
        state: &ServerConversationState,
        reset_request_id: &str,
        new_group_id: &[u8],
        origin_seq: u64,
    ) -> Result<()> {
        let group_info = self
            .mls_context()
            .export_group_info(new_group_id.to_vec(), identity_bytes.to_vec())?;
        if super::recovery::advertised_group_id_from_group_info(&group_info)? != new_group_id {
            return Err(OrchestratorError::InvalidInput("exported GroupInfo group ID mismatch".into()));
        }
        if self.mls_context().get_epoch(new_group_id.to_vec())? != 0 {
            return Err(OrchestratorError::InvalidInput("genesis GroupInfo epoch must be zero".into()));
        }
        let confirmation_tag = self.mls_context().get_confirmation_tag(new_group_id.to_vec())?;
        let group_context_hash = self.mls_context().get_group_context_hash(new_group_id.to_vec())?;

        // Fresh empty metadata at version prior+1, keyed by the successor
        // group's epoch-0 exporter — the shape the server accepts from an
        // activator that cannot decrypt the retired generation's snapshot.
        let metadata_version = state.metadata_version + 1;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let metadata_key: [u8; 32] = self
            .mls_context()
            .export_metadata_key(new_group_id.to_vec(), 0)?
            .as_slice()
            .try_into()
            .map_err(|_| OrchestratorError::Mls(MLSError::Internal("metadata key length mismatch".into())))?;
        let ciphertext = crate::metadata::encrypt_metadata_snapshot_with_nonce(
            &metadata_key,
            new_group_id,
            0,
            metadata_version,
            &nonce,
            &crate::metadata::GroupMetadataV1 {
                version: 1,
                title: String::new(),
                description: String::new(),
                avatar_blob_locator: None,
                avatar_content_type: None,
            },
        )
        .map_err(|e| OrchestratorError::Mls(MLSError::Internal(format!("encrypt metadata snapshot: {e:?}"))))?;

        let convo_uuid = uuid::Uuid::parse_str(&state.conversation_id)
            .map_err(|e| OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}")))?;
        let generation = state.coordinate_i64("generation")? + 1;
        let transition_id = uuid::Uuid::new_v4().to_string();
        let successor = serde_json::json!({
            "confirmationTag": { "$bytes": STANDARD.encode(&confirmation_tag) },
            "conversationId": state.conversation_id,
            "epoch": 0,
            "generation": generation,
            "groupContextHash": { "$bytes": STANDARD.encode(&group_context_hash) },
            "groupId": { "$bytes": STANDARD.encode(new_group_id) },
            "lifecycle": "active",
            "stateVersion": 0
        });
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#resetActivationBody",
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "authGeneration": auth_generation,
            "conversationKind": state.kind,
            "genesisGroupInfo": {
                "bytes": { "$bytes": STANDARD.encode(&group_info) },
                "contentType": "groupInfo",
                "framing": "mlsMessage",
                "sha256": STANDARD.encode(Sha256::digest(&group_info))
            },
            "idempotencyKey": transition_id,
            "keyId": key_id,
            "manifest": {
                "actorLeaf": {
                    "deviceId": actor_device_id,
                    "leafOrigin": "genesis",
                    "userDid": user_did
                },
                "participants": state.manifest_participants()
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": auth_generation,
                    "authorDeviceId": actor_device_id,
                    "authorDid": user_did,
                    "authorKeyId": key_id,
                    "deviceStatusAtOrigin": "active",
                    "originSeq": origin_seq,
                    "originTransitionId": transition_id,
                    "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(public_key) }
                },
                "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&confirmation_tag) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": 0,
                    "generation": generation,
                    "groupContextHash": { "$bytes": STANDARD.encode(&group_context_hash) },
                    "groupId": { "$bytes": STANDARD.encode(new_group_id) }
                },
                "metadataVersion": metadata_version,
                "nonce": { "$bytes": STANDARD.encode(nonce) },
                "originTransitionId": transition_id
            },
            "prior": state.prior_json()?,
            "resetRequestId": reset_request_id,
            "retired": state.retired_json()?,
            "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "successor": successor,
            "transitionId": transition_id
        });
        let response = self
            .submit_signed_clean_chat_request(
                CanonicalOperation::ActivateReset,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        Ok(())
    }

    /// Point every local projection at the successor group and clear the
    /// recovery bookkeeping that was gating the dead generation.
    async fn adopt_reset_successor(
        &self,
        user_did: &str,
        state: &ServerConversationState,
        new_group_id: &[u8],
    ) -> Result<u64> {
        let convo_id = state.conversation_id.as_str();
        let group_id_hex = hex::encode(new_group_id);
        let members: Vec<String> = state
            .participants
            .iter()
            .filter_map(|p| p.get("userDid").and_then(|v| v.as_str()).map(str::to_string))
            .collect();

        // `ensure_conversation_exists` never rebinds an existing row's group
        // (both platforms treat a differing group as an idempotent legacy
        // row). The durable rebinding contract is mark + complete reset
        // pending, which projects the mapping, epoch, Active tag, and clears
        // the rejoin flag in one backend commit.
        let reset_generation = i32::try_from(state.coordinate_i64("generation")? + 1)
            .map_err(|_| OrchestratorError::InvalidInput("reset generation overflow".into()))?;
        self.storage()
            .ensure_conversation_exists(user_did, convo_id, &group_id_hex)
            .await?;
        self.storage()
            .mark_reset_pending(
                convo_id,
                &group_id_hex,
                reset_generation,
                chrono::Utc::now().timestamp_millis(),
            )
            .await?;
        if !self
            .storage()
            .complete_reset_pending(convo_id, reset_generation, &group_id_hex, 0)
            .await?
        {
            return Err(OrchestratorError::ResetCompletionNotCommitted {
                convo_id: convo_id.to_string(),
                reset_generation,
                reason: "backend rejected the activated successor generation".to_string(),
            });
        }
        let group_state = GroupState {
            group_id: group_id_hex.clone(),
            conversation_id: convo_id.to_string(),
            epoch: 0,
            members: members.clone(),
        };
        self.storage().set_group_state(&group_state).await?;

        self.group_states()
            .lock()
            .await
            .insert(group_id_hex.clone(), group_state);
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), ConversationState::Active);
        {
            let mut conversations = self.conversations().lock().await;
            let view = conversations
                .entry(convo_id.to_string())
                .or_insert_with(|| ConversationView {
                    group_id: group_id_hex.clone(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: Vec::new(),
                    metadata: None,
                    created_at: None,
                    updated_at: Some(chrono::Utc::now()),
                    sequencer_did: None,
                });
            view.group_id = group_id_hex;
            view.epoch = 0;
            view.members = state
                .participants
                .iter()
                .filter_map(|p| {
                    let did = p.get("userDid").and_then(|v| v.as_str())?.to_string();
                    let role = if p.get("role").and_then(|v| v.as_str()) == Some("admin") {
                        MemberRole::Admin
                    } else {
                        MemberRole::Member
                    };
                    Some(MemberView { did, role })
                })
                .collect();
        }
        {
            let mut tracker = self.recovery_tracker().lock().await;
            tracker.clear_for_fresh_reset(convo_id);
            tracker.clear_leaf_recovery_wait(convo_id);
        }
        Ok(0)
    }

    async fn require_auth_generation(&self, user_did: &str) -> Result<i64> {
        let auth_generation = self
            .credentials()
            .get_auth_generation(user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential("auth_generation must be >= 1".into()));
        }
        Ok(auth_generation)
    }

    async fn own_key_id(&self) -> Result<String> {
        let scoped_identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(scoped_identity.as_bytes().to_vec())?;
        Ok(super::canonical_transport::derive_key_id(&public_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(leaves: serde_json::Value) -> ServerConversationState {
        ServerConversationState::from_state_json(
            "11111111-1111-4111-9111-111111111111",
            &serde_json::json!({
                "conversationKind": "direct",
                "coordinates": {
                    "conversationId": "11111111-1111-4111-9111-111111111111",
                    "generation": 2,
                    "stateVersion": 3,
                    "groupId": { "$bytes": STANDARD.encode([7u8; 32]) },
                    "epoch": 5,
                    "groupContextHash": STANDARD.encode([8u8; 32]),
                    "confirmationTag": { "$bytes": STANDARD.encode([9u8; 32]) },
                    "lifecycle": "active"
                },
                "participants": [
                    { "userDid": "did:plc:alice", "role": "admin", "status": "active", "leafCount": 1 },
                    { "userDid": "did:plc:bob", "role": "admin", "status": "pending", "leafCount": 0,
                      "invitationProvenance": { "invitationTransitionId": "t1", "invitedByDid": "did:plc:alice", "invitedByDeviceId": "d1" } }
                ],
                "leaves": leaves,
                "metadataSnapshot": { "metadataVersion": 4 },
                "snapshotSeq": 9
            }),
        )
        .unwrap()
    }

    #[test]
    fn prior_and_retired_echo_server_coordinate() {
        let s = state(serde_json::json!([]));
        let prior = s.prior_json().unwrap();
        assert_eq!(prior["generation"], 2);
        assert_eq!(prior["stateVersion"], 3);
        assert_eq!(prior["epoch"], 5);
        assert_eq!(prior["lifecycle"], "active");
        assert_eq!(prior["groupId"]["$bytes"], STANDARD.encode([7u8; 32]));
        assert_eq!(prior["groupContextHash"]["$bytes"], STANDARD.encode([8u8; 32]));
        let retired = s.retired_json().unwrap();
        assert_eq!(retired["stateVersion"], 4);
        assert_eq!(retired["lifecycle"], "superseded");
        assert_eq!(retired["groupId"], prior["groupId"]);
    }

    #[test]
    fn manifest_preserves_roster_and_provenance() {
        let s = state(serde_json::json!([]));
        let manifest = s.manifest_participants();
        assert_eq!(manifest.len(), 2);
        assert!(manifest[0].get("invitationProvenance").is_none());
        assert_eq!(manifest[1]["status"], "pending");
        assert_eq!(manifest[1]["invitationProvenance"]["invitationTransitionId"], "t1");
        assert!(manifest[0].get("leafCount").is_none());
    }

    #[test]
    fn nobody_else_can_add_detection() {
        let own_only = state(serde_json::json!([
            { "userDid": "did:plc:alice", "deviceId": "dead", "leafOrigin": "genesis", "keyId": "k", "deviceStatus": "active" }
        ]));
        assert!(own_only.nobody_else_can_add("did:plc:alice"));
        let revoked_peer = state(serde_json::json!([
            { "userDid": "did:plc:bob", "deviceId": "x", "leafOrigin": "keyPackage", "keyId": "k", "deviceStatus": "revoked" }
        ]));
        assert!(revoked_peer.nobody_else_can_add("did:plc:alice"));
        let live_peer = state(serde_json::json!([
            { "userDid": "did:plc:bob", "deviceId": "x", "leafOrigin": "keyPackage", "keyId": "k", "deviceStatus": "active" }
        ]));
        assert!(!live_peer.nobody_else_can_add("did:plc:alice"));
        assert_eq!(live_peer.own_role_status("did:plc:bob").unwrap(), ("admin".into(), "pending".into()));

        // A response without `leaves` says nothing; never assume nobody can help.
        let mut unknown = state(serde_json::json!([]));
        unknown.leaves = None;
        assert!(!unknown.nobody_else_can_add("did:plc:alice"));
    }
}
