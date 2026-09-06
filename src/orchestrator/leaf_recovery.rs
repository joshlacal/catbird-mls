//! Exact device-owned recovery work is scheduling evidence, not MLS admission.

use serde_json::Value;

use crate::atproto::blue_catbird::chat::{
    get_leaf_recovery_inbox::GetLeafRecoveryInboxError,
    request_leaf_recovery::RequestLeafRecoveryError,
};
use crate::chat_v2::ids::uuid::CanonicalUuid;

use super::api_client::MLSAPIClient;
use super::canonical_transport::{CanonicalOperation, GatewayResponse, PreparedRequest};
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::lifecycle::lifecycle_coordinates;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::pagination::PaginationGuard;
use super::reset_flow::ServerConversationState;
use super::storage::MLSStorageBackend;

pub(crate) fn already_open(response: &GatewayResponse) -> bool {
    response.status == 400
        && matches!(
            serde_json::from_slice::<RequestLeafRecoveryError>(&response.body),
            Ok(RequestLeafRecoveryError::LeafRecoveryAlreadyOpen(_))
        )
}

fn retryable_session_error(error: &OrchestratorError) -> bool {
    let OrchestratorError::ServerError { status: 400, body } = error else {
        return false;
    };
    matches!(
        serde_json::from_str::<GetLeafRecoveryInboxError>(body),
        Ok(GetLeafRecoveryInboxError::InventorySessionMismatch(_)
            | GetLeafRecoveryInboxError::InventorySessionExpired(_))
    )
}

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(message.into())
}

fn query_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Read the exact actor's open request at the caller's current coordinate.
    /// A concurrent inventory may invalidate its capability; reconstruct that
    /// read once for the two explicit session errors. Never turn a failed proof
    /// read into absence or infer membership from this retained request.
    pub(crate) async fn own_open_leaf_recovery(
        &self,
        state: &ServerConversationState,
        kind: &str,
    ) -> Result<Option<Value>> {
        self.check_shutdown().await?;
        if !matches!(kind, "add" | "replace") {
            return Err(invalid("invalid leaf recovery kind"));
        }
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if state.own_role_status(&did)?.1 != "active" || state.coordinates["lifecycle"] != "active"
        {
            return Err(invalid("leaf recovery requires active account membership"));
        }
        let coordinate = lifecycle_coordinates(&state.coordinates, &state.conversation_id)?;
        for attempt in 0..2 {
            match self
                .own_open_leaf_recovery_attempt(
                    &state.conversation_id,
                    &coordinate,
                    &did,
                    &device,
                    kind,
                )
                .await
            {
                Err(error) if attempt == 0 && retryable_session_error(&error) => continue,
                result => return result,
            }
        }
        unreachable!("bounded recovery inventory attempts always return")
    }

    async fn recovery_read_json(
        &self,
        operation: CanonicalOperation,
        path: String,
    ) -> Result<Value> {
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation,
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
        serde_json::from_slice(&response.body)
            .map_err(|error| OrchestratorError::Serialization(error.to_string()))
    }

    async fn own_open_leaf_recovery_attempt(
        &self,
        conversation_id: &str,
        coordinate: &Value,
        did: &str,
        device: &str,
        kind: &str,
    ) -> Result<Option<Value>> {
        let inventory = self
            .recovery_read_json(
                CanonicalOperation::GetConversations,
                format!(
                    "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={device}&limit=100"
                ),
            )
            .await?;
        let session = inventory["inventorySessionId"]
            .as_str()
            .filter(|value| (32..=512).contains(&value.len()))
            .ok_or_else(|| invalid("invalid recovery inventory session"))?;
        let event_cursor = inventory["snapshotEventCursor"]
            .as_str()
            .filter(|value| (1..=512).contains(&value.len()))
            .ok_or_else(|| invalid("invalid recovery inventory event cursor"))?;
        let mut cursor: Option<String> = None;
        let mut pages = PaginationGuard::for_conversations("own leaf recovery inbox");
        loop {
            let mut path = format!("/xrpc/blue.catbird.chat.getLeafRecoveryInbox?actorDeviceId={device}&inventorySessionId={}&limit=100", query_value(session));
            if let Some(cursor) = &cursor {
                path.push_str("&pageCursor=");
                path.push_str(&query_value(cursor));
            }
            let page = self
                .recovery_read_json(CanonicalOperation::GetLeafRecoveryInbox, path)
                .await?;
            if page["inventorySessionId"].as_str() != Some(session)
                || page["snapshotEventCursor"].as_str() != Some(event_cursor)
                || page["snapshotExpiresAt"] != inventory["snapshotExpiresAt"]
            {
                return Err(invalid("recovery inbox changed inventory session"));
            }
            let items = page["items"]
                .as_array()
                .ok_or_else(|| invalid("missing recovery inbox items"))?;
            let next = page["nextPageCursor"].as_str().map(str::to_owned);
            pages.observe_page(items.len(), next.as_deref())?;
            for item in items {
                let request = item.get("recovery").unwrap_or(item);
                if request["conversationId"].as_str() == Some(conversation_id)
                    && request["requesterDid"].as_str() == Some(did)
                    && request["requesterDeviceId"].as_str() == Some(device)
                    && request["recoveryKind"].as_str() == Some(kind)
                    && request["status"] == "open"
                    && request["recoveryRequestId"]
                        .as_str()
                        .is_some_and(|id| CanonicalUuid::parse(id).is_ok())
                    && request["expiresAt"]
                        .as_str()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .is_some_and(|expires| expires > chrono::Utc::now())
                    && lifecycle_coordinates(&request["boundCoordinate"], conversation_id)
                        .ok()
                        .as_ref()
                        == Some(coordinate)
                {
                    return Ok(Some(request.clone()));
                }
            }
            if page["hasMore"] == true && next.is_none() {
                return Err(invalid("recovery inbox missing continuation"));
            }
            cursor = next;
            if cursor.is_none() {
                return Ok(None);
            }
        }
    }
}
