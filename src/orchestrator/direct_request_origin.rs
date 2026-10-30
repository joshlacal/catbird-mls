//! A legacy pending direct can be upgraded only from a fresh exact policy snapshot.
use crate::orchestrator::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Legacy direct request origin is uncertain".into())
}
/// Reads may present coordinate bytes as bare base64 or `{"$bytes":…}`; the
/// signed `exactPrior` must be the typed coordinate with bare standard base64,
/// the same form direct-request signing and the server's comparison require.
fn signing_prior(coordinates: &Value) -> Result<Value> {
    let typed = canonical_transport::decode_conversation_coordinates(
        &serde_json::to_vec(coordinates).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    Ok(json!({
        "conversationId": typed.conversation_id,
        "generation": typed.generation,
        "stateVersion": typed.state_version,
        "groupId": STANDARD.encode(&typed.group_id),
        "epoch": typed.epoch,
        "groupContextHash": STANDARD.encode(&typed.group_context_hash),
        "confirmationTag": STANDARD.encode(&typed.confirmation_tag),
        "lifecycle": typed.lifecycle,
    }))
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
        json!({"$type":"blue.catbird.chat.defs#legacyPendingDirectOrigin", "exactPrior":signing_prior(&state["coordinates"])?, "originalInvitationProvenance":peer["invitationProvenance"]}),
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::transcript::direct_request::{direct_request_signing_bytes, DirectRequestKind};

    const OWNER: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const PEER: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

    fn state(bytes: impl Fn([u8; 32]) -> Value) -> Value {
        json!({
            "conversationKind":"direct",
            "coordinates":{
                "conversationId":"0f8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d3e","generation":0,"stateVersion":0,
                "groupId":bytes([1;32]),"epoch":0,"groupContextHash":bytes([2;32]),
                "confirmationTag":bytes([3;32]),"lifecycle":"active"
            },
            "participants":[
                {"userDid":OWNER,"status":"active","leafCount":1},
                {"userDid":PEER,"status":"pending","leafCount":0,"invitationProvenance":{
                    "invitationTransitionId":"5a8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d3f",
                    "invitedByDid":OWNER,"invitedByDeviceId":"7b8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d40"}}
            ],
            "leaves":[{"userDid":OWNER}],
            "snapshotSeq":1
        })
    }

    #[test]
    fn exact_prior_is_signable_for_bare_and_wrapped_read_bytes() {
        let bare = legacy_origin(&state(|b| json!(STANDARD.encode(b))), OWNER, PEER)
            .unwrap()
            .unwrap();
        let wrapped = legacy_origin(&state(|b| json!({"$bytes":STANDARD.encode(b)})), OWNER, PEER)
            .unwrap()
            .unwrap();
        assert_eq!(bare, wrapped);
        assert_eq!(bare["exactPrior"]["groupId"], STANDARD.encode([1u8; 32]));
        let body = json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":OWNER,"actorDeviceId":"7b8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d40",
            "keyId":"ChpfB6uoAvCQm0BYLspL_66UCUK_qQI4ZsHFdqmj8yg","authGeneration":1,
            "requestId":"1a8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d41",
            "firstMessageId":"2a8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d42",
            "conversationId":"0f8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d3e","recipientDid":PEER,
            "origin":wrapped,"profile":"encryptedIntroduction1",
            "idempotencyKey":"1a8e0c8e-6d0b-4b8e-9d6e-4b2b8a1c2d41",
            "signedAt":"2026-09-23T12:00:00.000Z"
        });
        direct_request_signing_bytes(
            DirectRequestKind::Prepare,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    }
}
