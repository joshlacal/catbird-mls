//! Fresh group invitation references are links, not acceptance authority.
use crate::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, VerifiedMutation,
};
use crate::orchestrator::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Group invitation proof is unavailable or inconsistent".into())
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub async fn get_group_invitation_reference(
        &self,
        cid: &str,
        recipient: &str,
    ) -> Result<Option<GroupInvitationReference>> {
        self.check_shutdown().await?;
        crate::chat_v2::ids::CanonicalUuid::parse(cid).map_err(|_| invalid())?;
        crate::chat_v2::ids::BareDid::parse(recipient).map_err(|_| invalid())?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let response = self.fetch_conversation_lifecycle(cid).await?;
        let state = &response["state"];
        let typed = canonical_transport::decode_conversation_state(
            &serde_json::to_vec(state).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        if typed.coordinates.conversation_id.as_str() != cid {
            return Err(invalid());
        }
        if typed.conversation_kind.as_str() != "group"
            || typed.coordinates.lifecycle.as_str() != "active"
        {
            return Ok(None);
        }
        let participants = state["participants"].as_array().ok_or_else(invalid)?;
        if !participants
            .iter()
            .any(|p| p["userDid"] == owner && p["status"] == "active")
        {
            return Err(invalid());
        }
        let matching = participants
            .iter()
            .filter(|p| p["userDid"] == recipient)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(invalid());
        }
        let Some(participant) = matching.first().filter(|p| p["status"] == "pending") else {
            return Ok(None);
        };
        let provenance = &participant["invitationProvenance"];
        let transition = provenance["invitationTransitionId"]
            .as_str()
            .ok_or_else(invalid)?;
        let actor = provenance["invitedByDid"].as_str().ok_or_else(invalid)?;
        let actor_device = provenance["invitedByDeviceId"]
            .as_str()
            .ok_or_else(invalid)?;
        // A note composer may only attach the calling account's own invitation.
        if actor != owner || recipient == owner {
            return Err(invalid());
        }
        let mut after = 0u64;
        for _ in 0..64 {
            let page = self
                .request_query(
                    CanonicalOperation::GetEntries,
                    format!(
                        "actorDeviceId={device}&conversationId={cid}&afterSeq={after}&limit=100"
                    ),
                )
                .await?;
            let entries = page["entries"].as_array().ok_or_else(invalid)?;
            let mut scanned = after;
            for original in entries {
                let seq = original["seq"]
                    .as_u64()
                    .filter(|s| *s > scanned)
                    .ok_or_else(invalid)?;
                scanned = seq;
                if original["conversationId"] != cid {
                    return Err(invalid());
                }
                if original["signedRequest"]["body"]["transitionId"] != transition {
                    continue;
                }
                let entry = super::projection::request_control_entry(original.clone())?;
                let body = &entry["signedRequest"]["body"];
                let (kind, changes) = match original["$type"].as_str() {
                    Some("blue.catbird.chat.defs#creationEntry")
                        if body["conversationKind"] == "group" =>
                    {
                        (
                            SignedMutationKind::Creation,
                            &body["manifest"]["participants"],
                        )
                    }
                    Some("blue.catbird.chat.defs#policyEntry") => (
                        SignedMutationKind::PolicyTransition,
                        &body["participantChanges"],
                    ),
                    _ => return Err(invalid()),
                };
                let change = changes
                    .as_array()
                    .ok_or_else(invalid)?
                    .iter()
                    .filter(|p| p["userDid"] == recipient)
                    .collect::<Vec<_>>();
                if change.len() != 1
                    || change[0]["status"] != "pending"
                    || change[0]["invitationProvenance"] != *provenance
                    || body["actorDid"] != actor
                    || body["actorDeviceId"] != actor_device
                    || body["next"]["conversationId"] != cid
                    || body["next"]["groupId"] != state["coordinates"]["groupId"]
                    || body["next"]["generation"] != state["coordinates"]["generation"]
                    || body["next"]["stateVersion"].as_u64()
                        > state["coordinates"]["stateVersion"].as_u64()
                    || seq > state["snapshotSeq"].as_u64().ok_or_else(invalid)?
                {
                    return Err(invalid());
                }
                if kind == SignedMutationKind::PolicyTransition
                    && change[0]["$type"] != "blue.catbird.chat.defs#addParticipant"
                {
                    return Err(invalid());
                }
                let strict = decode_strict_json(&serde_json::to_vec(body).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
                let projected = project_signed_body(kind, &strict).map_err(|_| invalid())?;
                let signature: [u8; 64] = STANDARD
                    .decode(
                        entry["signedRequest"]["signature"]
                            .as_str()
                            .ok_or_else(invalid)?,
                    )
                    .map_err(|_| invalid())?
                    .try_into()
                    .map_err(|_| invalid())?;
                let key = self
                    .request_historical_device_key(
                        actor,
                        actor_device,
                        body["keyId"].as_str().ok_or_else(invalid)?,
                    )
                    .await?;
                VerifiedMutation::verify(projected, signature, &key).map_err(|_| invalid())?;
                return Ok(Some(GroupInvitationReference {
                    authority_did: "did:web:chat.catbird.blue".into(),
                    conversation_id: cid.into(),
                    invitation_transition_id: transition.into(),
                    invited_by_did: actor.into(),
                    invited_by_device_id: actor_device.into(),
                    recipient_did: recipient.into(),
                }));
            }
            if page["hasMore"] != true {
                return Err(invalid());
            }
            let next = page["nextAfterSeq"]
                .as_u64()
                .filter(|n| *n >= scanned && *n > after)
                .ok_or_else(invalid)?;
            after = next;
        }
        Err(invalid())
    }
}
