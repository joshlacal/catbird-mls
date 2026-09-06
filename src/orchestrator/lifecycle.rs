//! Conversation exit uses the server's account membership and coordinates.
//! It must remain usable after a device loses its local MLS group.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::api_client::MLSAPIClient;
use super::canonical_transport::{CanonicalOperation, PreparedRequest};
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;

/// A durable group leave needs another account's current MLS leaf to commit
/// the removal. Callers must retain local state and show pending until then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaveOutcome {
    Left,
    Pending { leave_request_id: String },
}

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(message.to_owned())
}

/// Normalize wire bytes while requiring every coordinate field; never invent
/// epoch, generation, state version, or cryptographic values for an exit CAS.
pub(crate) fn lifecycle_coordinates(value: &Value, conversation_id: &str) -> Result<Value> {
    if value["conversationId"].as_str() != Some(conversation_id) {
        return Err(invalid(
            "Conversation state belongs to a different conversation.",
        ));
    }
    let mut coordinates = json!({"conversationId": conversation_id});
    for name in ["epoch", "generation", "stateVersion"] {
        let number = value[name]
            .as_u64()
            .filter(|number| *number <= 9_007_199_254_740_991)
            .ok_or_else(|| {
                invalid("Conversation state has invalid coordinates. Please refresh and try again.")
            })?;
        coordinates[name] = json!(number);
    }
    for name in ["groupId", "confirmationTag", "groupContextHash"] {
        let encoded = value[name]
            .as_str()
            .or_else(|| value[name]["$bytes"].as_str())
            .ok_or_else(|| invalid("Conversation state is missing cryptographic coordinates."))?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| invalid("Conversation coordinates contain invalid bytes."))?;
        if bytes.len() != 32 {
            return Err(invalid(
                "Conversation coordinates contain an invalid byte length.",
            ));
        }
        coordinates[name] = json!(STANDARD.encode(bytes));
    }
    let lifecycle = value["lifecycle"]
        .as_str()
        .filter(|l| matches!(*l, "active" | "superseded"))
        .ok_or_else(|| invalid("Conversation state has an invalid lifecycle."))?;
    coordinates["lifecycle"] = json!(lifecycle);
    Ok(coordinates)
}

fn next_coordinates(prior: &Value, close: bool) -> Result<Value> {
    let version = prior["stateVersion"].as_u64().unwrap();
    if version == 9_007_199_254_740_991 {
        return Err(invalid(
            "This conversation has reached its state version limit.",
        ));
    }
    let mut next = prior.clone();
    next["stateVersion"] = json!(version + 1);
    if close {
        next["lifecycle"] = json!("superseded");
    }
    Ok(next)
}

fn leave_request_is_live(request: &Value) -> bool {
    let timestamp = |field: &str| {
        request[field]
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    };
    let (Some(requested), Some(expires)) = (timestamp("requestedAt"), timestamp("expiresAt"))
    else {
        return false;
    };
    let now = chrono::Utc::now();
    expires > now
        && requested <= now + chrono::Duration::minutes(1)
        && expires > requested
        && expires - requested <= chrono::Duration::hours(24) + chrono::Duration::seconds(1)
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Fresh control-plane point read, available even to leafless participants.
    pub(crate) async fn fetch_conversation_lifecycle(
        &self,
        conversation_id: &str,
    ) -> Result<Value> {
        let device = self.require_actor_device_id().await?;
        let response = self.api_client().submit_prepared_request(PreparedRequest {
            operation: CanonicalOperation::GetConversationState,
            path: format!("/xrpc/blue.catbird.chat.getConversationState?actorDeviceId={device}&conversationId={conversation_id}"),
            method: "GET".into(), body: None,
        }).await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))
    }

    /// Close a direct chat, immediately leave a zero-leaf group, or submit
    /// durable consent for another member to remove all this account's leaves.
    pub async fn leave_conversation(&self, conversation_id: &str) -> Result<LeaveOutcome> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let conversation_id =
            match crate::chat_v2::ids::uuid::ConversationId::parse(conversation_id) {
                Ok(id) => id.to_string(),
                Err(_) => {
                    self.resolve_legacy_group_identifier(conversation_id)
                        .await?
                        .conversation_id
                }
            };
        let transition_lock = self.rejoin_lock(&conversation_id).await;
        let _guard = transition_lock.lock().await;
        let mut replaces_operation = None;
        let mut previous_prior = None;
        let mut replay_error = None;
        if let Some(record) = self.current_account_exit_locked(&conversation_id).await? {
            let saved = record.wrapper()?;
            replaces_operation = saved["signedRequest"]["body"]["transitionId"]
                .as_str()
                .map(str::to_owned);
            previous_prior = Some(lifecycle_coordinates(
                &saved["signedRequest"]["body"]["prior"],
                &conversation_id,
            )?);
            match self.finish_account_exit_locked(record).await {
                Ok(true) => return Ok(LeaveOutcome::Left),
                Ok(false) => {}
                Err(error) => replay_error = Some(error),
            }
        }
        // This durable state was already projected from verified terminal
        // evidence; a bare inventory tombstone or 404 never creates it.
        if self.is_local_conversation_closed(&conversation_id).await? {
            return Ok(LeaveOutcome::Left);
        }
        let response = self.fetch_conversation_lifecycle(&conversation_id).await?;
        let state = &response["state"];
        let prior = lifecycle_coordinates(&state["coordinates"], &conversation_id)?;
        if prior["lifecycle"] != "active" {
            return Err(invalid(
                "This conversation is no longer active. Refresh your conversations.",
            ));
        }
        let kind = state["conversationKind"]
            .as_str()
            .filter(|k| matches!(*k, "direct" | "group"))
            .ok_or_else(|| invalid("Conversation state is missing its kind."))?;
        let participants = state["participants"]
            .as_array()
            .ok_or_else(|| invalid("Conversation state is missing its participants."))?;
        let own = participants.iter().find(|p| p["userDid"].as_str() == Some(&user_did))
            .ok_or_else(|| invalid("Your account is no longer a participant in this conversation. Refresh your conversations."))?;
        if previous_prior.as_ref() == Some(&prior) {
            return Err(replay_error.unwrap_or_else(|| {
                invalid("The earlier exit still needs confirmation. Refresh before retrying.")
            }));
        }
        let active_admin = own["status"] == "active" && own["role"] == "admin";
        let close = kind == "direct" || (participants.len() == 1 && active_admin);
        if kind == "group"
            && !close
            && active_admin
            && !participants.iter().any(|p| {
                p["userDid"].as_str() != Some(&user_did)
                    && p["status"] == "active"
                    && p["role"] == "admin"
            })
        {
            return Err(invalid(
                "Make another member an admin before leaving this group.",
            ));
        }
        // Account-level leaf count is authoritative. A phone without its own
        // MLS group may still have sibling-device leaves that must be removed.
        let leaf_count = if close {
            0
        } else {
            own["leafCount"].as_u64().ok_or_else(|| invalid("Conversation state is missing your device membership count. Refresh and try again."))?
        };
        if !close && leaf_count > 0 {
            if let Some(pending) =
                response["pendingLeaveRequests"]
                    .as_array()
                    .and_then(|requests| {
                        requests.iter().find(|request| {
                            request["conversationId"].as_str() == Some(&conversation_id)
                                && request["requesterDid"].as_str() == Some(&user_did)
                                && request["status"] == "pending"
                                && leave_request_is_live(request)
                                && lifecycle_coordinates(&request["prior"], &conversation_id)
                                    .ok()
                                    .as_ref()
                                    == Some(&prior)
                        })
                    })
            {
                let leave_request_id = pending["leaveRequestId"]
                    .as_str()
                    .ok_or_else(|| invalid("Pending leave is missing its request ID."))?;
                crate::chat_v2::ids::uuid::ConversationId::parse(leave_request_id)
                    .map_err(|_| invalid("Pending leave has an invalid request ID."))?;
                return Ok(LeaveOutcome::Pending {
                    leave_request_id: leave_request_id.to_owned(),
                });
            }
        }

        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .filter(|generation| *generation >= 1)
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        let identity = self.require_scoped_identity().await?;
        let public_key = self
            .mls_context()
            .identity_public_key(identity.as_bytes().to_vec())?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut body = json!({
            "actorDid": user_did, "actorDeviceId": actor_device_id,
            "authGeneration": auth_generation,
            "keyId": super::canonical_transport::derive_key_id(&public_key),
            "idempotencyKey": request_id, "prior": prior,
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });
        let operation = if close {
            body["$type"] = json!("blue.catbird.chat.defs#conversationCloseBody");
            body["signatureDomain"] = json!("CATBIRD-CHAT-CLOSE\0");
            body["transitionId"] = json!(request_id);
            body["conversationKind"] = json!(kind);
            body["retired"] = next_coordinates(&prior, true)?;
            CanonicalOperation::CloseConversation
        } else if leaf_count == 0 {
            body["$type"] = json!("blue.catbird.chat.defs#zeroLeafLeaveBody");
            body["signatureDomain"] = json!("CATBIRD-CHAT-LEAVE-ZERO-LEAF\0");
            body["transitionId"] = json!(request_id);
            body["next"] = next_coordinates(&prior, false)?;
            CanonicalOperation::RequestLeave
        } else {
            body["$type"] = json!("blue.catbird.chat.defs#leaveRequestBody");
            body["signatureDomain"] = json!("CATBIRD-CHAT-LEAVE-REQUEST\0");
            body["leaveRequestId"] = json!(request_id);
            CanonicalOperation::RequestLeave
        };
        if close || leaf_count == 0 {
            let request = self
                .prepare_clean_chat_signed_request(
                    super::CleanChatSigningContext {
                        actor_did: user_did.clone(),
                        device_id: actor_device_id,
                        auth_generation: Some(auth_generation),
                    },
                    operation,
                    serde_json::to_vec(&body)
                        .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
                )
                .await
                .map_err(|e| OrchestratorError::Api(e.to_string()))?;
            let record = super::account_exit::AccountExitRecord {
                request_body: request
                    .body
                    .ok_or_else(|| invalid("The signed exit request is missing its body."))?,
                accepted_response: None,
                local_completion: false,
                replaces_operation,
                reset_evidence: None,
            };
            self.mls_context().put_account_exit(&record)?;
            if self.finish_account_exit_locked(record).await? {
                return Ok(LeaveOutcome::Left);
            }
            return Err(invalid("Your earlier exit completed, and the account was invited again. Refresh before leaving the new membership."));
        }
        let response = self
            .submit_signed_clean_chat_request(
                operation,
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
        let response: Value = serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let result = &response["result"];
        let request = &result["leaveRequest"];
        if result["$type"] != "blue.catbird.chat.defs#durableLeaveRequestResult"
            || request["leaveRequestId"].as_str() != Some(&request_id)
            || request["conversationId"].as_str() != Some(&conversation_id)
            || request["requesterDid"].as_str() != Some(&user_did)
            || request["status"] != "pending"
            || !leave_request_is_live(request)
            || lifecycle_coordinates(&request["prior"], &conversation_id)? != prior
        {
            return Err(invalid(
                "The server did not confirm your pending leave request.",
            ));
        }
        Ok(LeaveOutcome::Pending {
            leave_request_id: request_id,
        })
    }
}
