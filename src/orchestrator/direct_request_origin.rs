//! A legacy pending direct can be upgraded only from a fresh exact policy snapshot.
use crate::orchestrator::*;
use serde_json::{json, Value};
fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Legacy direct request origin is uncertain".into())
}
pub(super) fn legacy_origin(state: &Value, owner: &str, recipient: &str) -> Result<Option<Value>> {
    if state["conversationKind"] != "direct"
        || state["coordinates"]["lifecycle"] != "active"
        || !state["directRequest"].is_null()
    {
        return Ok(None);
    }
    let participants = state["participants"].as_array().ok_or_else(invalid)?;
    if participants.len() != 2 {
        return Ok(None);
    }
    let Some(actor) = participants.iter().find(|p| p["userDid"] == owner) else {
        return Ok(None);
    };
    let Some(peer) = participants.iter().find(|p| p["userDid"] == recipient) else {
        return Ok(None);
    };
    if actor["status"] != "active"
        || peer["status"] != "pending"
        || peer["leafCount"].as_u64() != Some(0)
        || peer["invitationProvenance"]["invitedByDid"] != owner
    {
        return Ok(None);
    }
    if state["leaves"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .any(|l| l["userDid"] == recipient)
    {
        return Ok(None);
    }
    state["snapshotSeq"]
        .as_u64()
        .and_then(|s| s.checked_add(1))
        .ok_or_else(invalid)?;
    Ok(Some(
        json!({"$type":"blue.catbird.chat.defs#legacyPendingDirectOrigin", "exactPrior":state["coordinates"], "originalInvitationProvenance":peer["invitationProvenance"]}),
    ))
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(super) async fn discover_direct_request_origin(
        &self,
        owner: &str,
        recipient: &str,
    ) -> Result<Option<Value>> {
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let page = self
                .api_client()
                .get_conversations(100, cursor.as_deref())
                .await?;
            for conversation in page.conversations {
                let Some(state) = conversation.canonical_state else {
                    continue;
                };
                let state: Value = serde_json::from_slice(
                    &canonical_transport::encode_conversation_state(&state)
                        .map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
                if legacy_origin(&state, owner, recipient)?.is_none() {
                    continue;
                }
                let cid = state["coordinates"]["conversationId"]
                    .as_str()
                    .ok_or_else(invalid)?;
                let response = self.fetch_conversation_lifecycle(cid).await?;
                let fresh = response["state"].clone();
                let typed = canonical_transport::decode_conversation_state(
                    &serde_json::to_vec(&fresh).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
                if typed.coordinates.conversation_id.as_str() != cid {
                    return Err(invalid());
                }
                if legacy_origin(&fresh, owner, recipient)?.is_some() {
                    return Ok(Some(fresh));
                }
                // A raced acceptance is left to the server's ExistingDirect result.
                return Ok(None);
            }
            let Some(next) = page.cursor else {
                return Ok(None);
            };
            if !seen.insert(next.clone()) {
                return Err(invalid());
            }
            cursor = Some(next);
        }
        Err(invalid())
    }
}
