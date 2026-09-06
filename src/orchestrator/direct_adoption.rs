//! Resolve duplicate direct creation through caller-visible inventory, then
//! restore this device's access without discarding retained conversation data.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

use super::api_client::MLSAPIClient;
use super::canonical_transport::{CanonicalOperation, PreparedRequest};
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::pagination::PaginationGuard;
use super::storage::MLSStorageBackend;
use super::types::{ConversationState, ConversationView};

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Presence of an OpenMLS group object alone also covers stale or removed
    /// state. A usable device must match the current server crypto coordinate
    /// and still appear by its exact credential in both available rosters.
    pub(crate) async fn device_group_matches_current_state(
        &self,
        conversation_id: &str,
        state: &Value,
    ) -> Result<bool> {
        let coordinate =
            super::lifecycle::lifecycle_coordinates(&state["coordinates"], conversation_id)?;
        if coordinate["lifecycle"] != "active" {
            return Ok(false);
        }
        let user_did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if !state["participants"]
            .as_array()
            .is_some_and(|participants| {
                participants
                    .iter()
                    .any(|p| p["userDid"].as_str() == Some(&user_did) && p["status"] == "active")
            })
        {
            return Ok(false);
        }
        if state["leaves"].as_array().is_some_and(|leaves| {
            !leaves.iter().any(|leaf| {
                leaf["userDid"].as_str() == Some(&user_did)
                    && leaf["deviceId"].as_str() == Some(&device)
                    && leaf["deviceStatus"].as_str() != Some("revoked")
            })
        }) {
            return Ok(false);
        }
        let group = STANDARD
            .decode(coordinate["groupId"].as_str().unwrap())
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let own_identity = self.require_scoped_identity().await?;
        Ok(
            self.mls_context().get_epoch(group.clone()).ok() == coordinate["epoch"].as_u64()
                && self
                    .mls_context()
                    .group_member_identities(group.clone())
                    .ok()
                    .is_some_and(|members| {
                        members
                            .iter()
                            .any(|member| member.as_slice() == own_identity.as_bytes())
                    })
                && self
                    .mls_context()
                    .get_confirmation_tag(group.clone())
                    .ok()
                    .map(|tag| STANDARD.encode(tag))
                    .as_deref()
                    == coordinate["confirmationTag"].as_str()
                && self
                    .mls_context()
                    .get_group_context_hash(group)
                    .ok()
                    .map(|hash| STANDARD.encode(hash))
                    .as_deref()
                    == coordinate["groupContextHash"].as_str(),
        )
    }

    /// A duplicate error contains no authorized conversation ID. Discover it
    /// only in this device's admitted inventory, for the exact direct DID pair.
    pub(crate) async fn visible_existing_direct_result(
        &self,
        peer_did: &str,
    ) -> Result<Option<Value>> {
        let user_did = self.require_user_did().await?;
        let peer_did = super::credential_binding::credential_root_did(peer_did);
        if peer_did == user_did {
            return Ok(None);
        }
        let device = self.require_actor_device_id().await?;
        let mut cursor: Option<String> = None;
        let mut pagination =
            PaginationGuard::for_conversations("existing direct conversation lookup");
        loop {
            let mut path = format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={device}&limit=100"
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
                    method: "GET".into(),
                    body: None,
                })
                .await?;
            if response.status != 200 {
                return Err(OrchestratorError::ServerError {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                });
            }
            let page: Value = serde_json::from_slice(&response.body)
                .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
            let items = page["items"].as_array().ok_or_else(|| {
                OrchestratorError::Api("Conversation inventory is missing items.".into())
            })?;
            let next = page["nextPageCursor"].as_str().map(str::to_owned);
            pagination.observe_page(items.len(), next.as_deref())?;
            for item in items {
                let state = item.get("state").unwrap_or(item);
                if state["conversationKind"] != "direct"
                    || state["coordinates"]["lifecycle"] != "active"
                {
                    continue;
                }
                let Some(participants) = state["participants"].as_array() else {
                    continue;
                };
                if participants.len() != 2
                    || !participants
                        .iter()
                        .any(|p| p["userDid"].as_str() == Some(&user_did))
                    || !participants
                        .iter()
                        .any(|p| p["userDid"].as_str() == Some(&peer_did))
                {
                    continue;
                }
                let conversation_id =
                    state["coordinates"]["conversationId"]
                        .as_str()
                        .ok_or_else(|| {
                            OrchestratorError::Api("Existing direct conversation has no ID.".into())
                        })?;
                crate::chat_v2::ids::uuid::ConversationId::parse(conversation_id).map_err(|e| {
                    OrchestratorError::InvalidInput(format!(
                        "Existing conversation ID is invalid: {e}"
                    ))
                })?;
                let coordinates = super::lifecycle::lifecycle_coordinates(
                    &state["coordinates"],
                    conversation_id,
                )?;
                return Ok(Some(json!({
                    "$type": "blue.catbird.chat.defs#existingDirectConversationResult",
                    "conversationKind": "direct", "conversationId": conversation_id,
                    "coordinates": coordinates,
                })));
            }
            cursor = next;
            if cursor.is_none() {
                return Ok(None);
            }
        }
    }

    /// Existing account membership is not proof that this device can decrypt.
    /// Keep the conversation accessible and persist the recovery state while
    /// accepting an invitation or asking an existing leaf to add this device.
    pub(crate) async fn adopt_existing_direct_conversation(
        &self,
        conversation_id: &str,
        expected_group_id: &str,
    ) -> Result<ConversationView> {
        let user_did = self.require_user_did().await?;
        let cached = self
            .conversations()
            .lock()
            .await
            .get(conversation_id)
            .cloned();
        let stored = self
            .storage()
            .get_conversation(&user_did, conversation_id)
            .await?;
        let view = match cached
            .filter(|view| view.group_id == expected_group_id)
            .or_else(|| {
                stored
                    .clone()
                    .filter(|view| view.group_id == expected_group_id)
            }) {
            Some(view) => view,
            None => self.fetch_conversation_for_convo(conversation_id).await?,
        };
        if view.group_id != expected_group_id {
            return Err(OrchestratorError::InvalidInput(format!(
                "existingDirectConversationResult groupId mismatch: coordinate specifies '{expected_group_id}', but server conversation view returned '{}'", view.group_id
            )));
        }
        // The storage identity gate repairs stale group mappings and revives
        // soft-deleted rows while preserving their child messages and history.
        self.storage()
            .ensure_conversation_exists(&user_did, conversation_id, expected_group_id)
            .await?;
        let previous_state = self
            .storage()
            .get_conversation_state(conversation_id)
            .await?;
        let recovery_protected = matches!(
            previous_state,
            Some(
                ConversationState::Quarantined { .. }
                    | ConversationState::ResetPending { .. }
                    | ConversationState::ForkDetected
            )
        );
        let healthy = if recovery_protected {
            false
        } else {
            match self.fetch_conversation_lifecycle(conversation_id).await {
                Ok(snapshot) => {
                    let current_matches = super::lifecycle::lifecycle_coordinates(
                        &snapshot["state"]["coordinates"],
                        conversation_id,
                    )
                    .ok()
                    .and_then(|coordinate| STANDARD.decode(coordinate["groupId"].as_str()?).ok())
                    .is_some_and(|bytes| hex::encode(bytes) == expected_group_id);
                    current_matches
                        && self
                            .device_group_matches_current_state(conversation_id, &snapshot["state"])
                            .await
                            .unwrap_or(false)
                }
                Err(_) => false,
            }
        };
        let state = if recovery_protected {
            previous_state.unwrap()
        } else if healthy {
            self.storage().clear_rejoin_flag(conversation_id).await?;
            ConversationState::Active
        } else {
            ConversationState::NeedsRejoin
        };
        self.storage()
            .set_conversation_state(conversation_id, state.clone())
            .await?;
        if !healthy && !recovery_protected {
            self.storage().mark_needs_rejoin(conversation_id).await?;
        }
        self.conversations()
            .lock()
            .await
            .insert(conversation_id.to_owned(), view.clone());
        self.conversation_states()
            .lock()
            .await
            .insert(conversation_id.to_owned(), state);
        if !healthy && !recovery_protected {
            // Starting this exact direct chat expresses consent to its existing
            // invitation. Acceptance obtains a fresh point read and verifies
            // immutable invitation provenance before signing the operation.
            if let Err(error) = self.accept_conversation(conversation_id).await {
                tracing::warn!(conversation_id, error = %error, "Existing direct conversation needs device access; retaining recoverable view");
            }
        }
        // A reset may have activated a successor while restoring access.
        Ok(self
            .conversations()
            .lock()
            .await
            .get(conversation_id)
            .cloned()
            .unwrap_or(view))
    }
}
