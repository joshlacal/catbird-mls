//! Canonical request controls share the ordinary page cursor, but never the
//! ordinary MLS decrypt path. A page advances only after protected proof commit.
use super::projection::{
    request_control_entry, verify_request_publication_entry, DirectRequestProjection,
};
use crate::chat_v2::transcript::direct_request as transcript;
use crate::orchestrator::*;
use serde_json::Value;
fn invalid() -> OrchestratorError {
    OrchestratorError::InvalidInput("Invalid canonical request control".into())
}
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn consume_request_control(
        &self,
        envelope: &IncomingEnvelope,
    ) -> Result<Option<Message>> {
        let raw = envelope
            .canonical_entry_json
            .as_deref()
            .ok_or_else(invalid)?;
        crate::chat_v2::transcript::decode_strict_json(raw.as_bytes()).map_err(|_| invalid())?;
        let entry: Value = serde_json::from_str(raw).map_err(|_| invalid())?;
        let expected = IncomingEnvelope::from_canonical_entry(&entry, &envelope.conversation_id)?
            .ok_or_else(invalid)?;
        if expected.canonical_entry_json.is_none()
            || !envelope.ciphertext.is_empty()
            || expected.sender_did != envelope.sender_did
            || expected.timestamp != envelope.timestamp
            || expected.server_message_id != envelope.server_message_id
            || expected.server_sequence != envelope.server_sequence
            || expected.server_epoch != envelope.server_epoch
        {
            return Err(invalid());
        }
        let cid = &envelope.conversation_id;
        if entry["$type"] == "blue.catbird.chat.defs#conversationCloseEntry" {
            let canonical = super::projection::normalized_close_entry(entry.clone())?;
            if !self.replay_verified_request_close(cid, &canonical).await? {
                // A valid signed intent is not proof that the server committed
                // it. Re-read the exact immutable canonical row before close.
                let device = self.require_actor_device_id().await?;
                let seq = envelope.server_sequence.ok_or_else(invalid)?;
                let page = self
                    .request_query(
                        CanonicalOperation::GetEntries,
                        format!(
                            "actorDeviceId={device}&conversationId={cid}&afterSeq={}&limit=1",
                            seq.checked_sub(1).ok_or_else(invalid)?
                        ),
                    )
                    .await?;
                let rows = page["entries"].as_array().ok_or_else(invalid)?;
                if rows.len() != 1 || rows[0]["$type"] != entry["$type"] {
                    return Err(invalid());
                }
                let committed = super::projection::normalized_close_entry(rows[0].clone())?;
                if super::projection::DirectRequestCloseProof::hash(&committed)?
                    != super::projection::DirectRequestCloseProof::hash(&canonical)?
                {
                    return Err(invalid());
                }
            }
            let group = super::super::welcome_ack::bytes(
                &canonical["signedRequest"]["body"]["prior"]["groupId"],
            )?;
            if !self
                .consume_verified_conversation_close(
                    cid,
                    &hex::encode(group),
                    &canonical["tombstone"],
                    &canonical,
                )
                .await?
            {
                return Err(invalid());
            }
            return Ok(None);
        }
        self.require_direct_request_support()?;
        // This fetch independently verifies the publication receipt and any
        // policy-only acceptance commit receipt before considering row identity.
        Box::pin(self.refresh_request_preview(cid)).await?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let lock = self.direct_request_operation_lock(cid).await;
        let guard = lock.lock().await;
        let raw = self
            .mls_context()
            .read_direct_request_projection(cid)?
            .ok_or_else(invalid)?;
        let mut projection = DirectRequestProjection::decode(&raw, &owner, &device)?;
        let kind = entry["$type"].as_str().ok_or_else(invalid)?.to_owned();
        let entry = request_control_entry(entry)?;
        match kind.as_str() {
            "blue.catbird.chat.defs#directRequestEntry" => {
                let receipt: Value = serde_json::from_slice(&projection.publication_receipt)
                    .map_err(|_| invalid())?;
                let hash = verify_request_publication_entry(
                    &entry,
                    &projection.publication,
                    &projection.sender_public_key,
                    &receipt["body"]["receipt"],
                )?;
                if let Some(old) = &projection.publication_entry {
                    let old_hash = transcript::direct_request_entry_hash(
                        &serde_json::to_vec(old).map_err(|_| invalid())?,
                    )
                    .map_err(|_| invalid())?;
                    if old_hash != hash {
                        return Err(invalid());
                    }
                } else {
                    projection.publication_entry = Some(entry);
                    if !self
                        .mls_context()
                        .compare_exchange_direct_request_projection(
                            cid,
                            Some(&raw),
                            &projection.encode()?,
                        )?
                    {
                        return Err(invalid());
                    }
                }
            }
            "blue.catbird.chat.defs#directRequestAcceptanceEntry" => {
                let proof: Value = serde_json::from_slice(
                    projection.acceptance_proof.as_ref().ok_or_else(invalid)?,
                )
                .map_err(|_| invalid())?;
                let hash = transcript::direct_request_acceptance_entry_hash(
                    &serde_json::to_vec(&entry).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
                let retained = transcript::direct_request_acceptance_entry_hash(
                    &serde_json::to_vec(&proof["entry"]).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
                if hash != retained {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        self.mls_context().ensure_storage_durable()?;
        let view = projection.view(&owner, &device)?;
        drop(guard);
        self.materialize_accepted_request_introduction(&view).await
    }
    pub(crate) async fn materialize_accepted_request_introduction(
        &self,
        view: &DirectRequestView,
    ) -> Result<Option<Message>> {
        if view.consent != RequestConsent::Accepted {
            return Ok(None);
        }
        let Some(RequestPreview::Ready { text, .. }) = &view.preview else {
            return Ok(None);
        };
        let metadata = view.introduction.as_ref().ok_or_else(invalid)?;
        let id = view.first_message_id.as_ref().ok_or_else(invalid)?;
        if self.storage().message_exists(id).await? {
            return Ok(None);
        }
        let message = Message {
            id: id.clone(),
            conversation_id: view.conversation_id.clone(),
            sender_did: metadata.sender_did.clone(),
            text: text.clone(),
            timestamp: metadata.received_at.parse().map_err(|_| invalid())?,
            epoch: metadata.epoch,
            sequence_number: metadata.sequence_number,
            is_own: metadata.sender_did == self.require_user_did().await?,
            delivery_status: None,
            payload_json: None,
        };
        self.storage().store_message(&message).await?;
        Ok(Some(message))
    }
}
