//! Protected request projection backed by signed publication and consent proof.
use super::super::direct_request_types::*;
use crate::chat_v2::transcript::direct_request::{
    resolve_direct_request_receipt_key_for_authority,
    verify_received_signed_request as verify_signed_request,
    verify_signed_request_for_authority, DirectRequestKind,
};
use crate::orchestrator::{OrchestratorError, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectRequestProjection {
    pub owner_did: String,
    pub device_id: String,
    pub trusted_authority_document: Vec<u8>,
    pub publication: Vec<u8>,
    #[serde(default)]
    pub publication_entry: Option<Value>,
    pub sender_public_key: Vec<u8>,
    pub publication_receipt: Vec<u8>,
    pub crypto: RequestCrypto,
    pub preview: Option<RequestPreview>,
    pub acceptance_proof: Option<Vec<u8>>,
    pub recipient_public_key: Option<Vec<u8>>,
    pub pending_acceptance: Option<Vec<u8>>,
    #[serde(default)]
    pub close_proof: Option<DirectRequestCloseProof>,
}
fn invalid() -> OrchestratorError {
    OrchestratorError::Storage("Invalid request projection proof".into())
}
impl DirectRequestProjection {
    pub fn decode(raw: &[u8], owner: &str, device: &str) -> Result<Self> {
        let value: Self = serde_json::from_slice(raw).map_err(|_| invalid())?;
        value.view(owner, device)?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.view(&self.owner_did, &self.device_id)?;
        serde_json::to_vec(self).map_err(|_| invalid())
    }
    pub fn view(&self, owner: &str, device: &str) -> Result<DirectRequestView> {
        if self.owner_did != owner || self.device_id != device {
            return Err(invalid());
        }
        let publication = verify_signed_request(
            DirectRequestKind::Publish,
            &self.publication,
            &self.sender_public_key,
        )
        .map_err(|_| invalid())?;
        let envelope: Value =
            serde_json::from_slice(&self.publication_receipt).map_err(|_| invalid())?;
        let method = envelope["body"]["keyId"].as_str().ok_or_else(invalid)?;
        let auth_did = {
            let val: Value = serde_json::from_slice(&self.trusted_authority_document)
                .map_err(|_| invalid())?;
            val["id"].as_str().ok_or_else(invalid)?.to_string()
        };
        let authority_key = resolve_direct_request_receipt_key_for_authority(
            &auth_did,
            &self.trusted_authority_document,
            method,
        )
        .map_err(|_| invalid())?;
        let receipt = verify_signed_request_for_authority(
            &auth_did,
            DirectRequestKind::Outcome,
            &self.publication_receipt,
            &authority_key,
        )
        .map_err(|_| invalid())?;
        let receipt = &receipt.body()["receipt"];
        let body = publication.body();
        if receipt["$type"] != "blue.catbird.chat.defs#directRequestPublishedReceipt"
            || receipt["requestId"] != body["requestId"]
            || receipt["conversationId"] != body["conversationId"]
            || receipt["firstMessageId"] != body["firstMessageId"]
            || receipt["coordinates"] != body["next"]
            || receipt["requestKind"] != "publish"
            || receipt["actorDid"] != body["actorDid"]
            || receipt["actorDeviceId"] != body["actorDeviceId"]
            || receipt["actorKeyId"] != body["keyId"]
            || receipt["authGeneration"] != body["authGeneration"]
            || receipt["requestDigest"] != STANDARD.encode(publication.request_digest())
        {
            return Err(invalid());
        }
        let mut consent = if body["actorDid"] == owner {
            RequestConsent::OutgoingPending
        } else if body["recipientDid"] == owner {
            RequestConsent::IncomingPending
        } else {
            return Err(invalid());
        };
        let mut coordinate = body["next"].clone();
        match (&self.acceptance_proof, &self.recipient_public_key) {
            (Some(proof), Some(recipient_key)) => {
                let value: Value = serde_json::from_slice(proof).map_err(|_| invalid())?;
                let method = value["receipt"]["body"]["keyId"]
                    .as_str()
                    .ok_or_else(invalid)?;
                let key = resolve_direct_request_receipt_key_for_authority(
                    &auth_did,
                    &self.trusted_authority_document,
                    method,
                )
                .map_err(|_| invalid())?;
                let verified =
                    crate::chat_v2::transcript::direct_request::verify_received_direct_request_acceptance_proof_for_authority(
                        &auth_did,
                        proof,
                        &key,
                        recipient_key,
                    )
                    .map_err(|_| invalid())?;
                if accepted["prior"] != coordinate
                    || accepted["requestId"] != body["requestId"]
                    || accepted["actorDid"] != body["recipientDid"]
                {
                    return Err(invalid());
                }
                coordinate = accepted["next"].clone();
                consent = RequestConsent::Accepted;
            }
            (None, None) => {}
            _ => return Err(invalid()),
        }
        if let Some(proof) = &self.close_proof {
            coordinate = proof.verify(&publication, &coordinate)?;
            consent = RequestConsent::Closed;
        }
        if let Some(entry) = &self.publication_entry {
            verify_request_publication_entry(
                entry,
                &self.publication,
                &self.sender_public_key,
                receipt,
            )?;
        }
        let introduction = RequestIntroductionMetadata {
            sender_did: body["actorDid"].as_str().ok_or_else(invalid)?.into(),
            sender_device_id: body["actorDeviceId"].as_str().ok_or_else(invalid)?.into(),
            received_at: receipt["recordedAt"].as_str().ok_or_else(invalid)?.into(),
            epoch: body["next"]["epoch"].as_u64().ok_or_else(invalid)?,
            sequence_number: body["artifacts"]["metadataSnapshot"]["authorProof"]["originSeq"]
                .as_u64()
                .filter(|s| *s > 0)
                .ok_or_else(invalid)?,
        };
        Ok(DirectRequestView {
            introduction: Some(introduction),
            conversation_id: body["conversationId"].as_str().ok_or_else(invalid)?.into(),
            first_message_id: Some(body["firstMessageId"].as_str().ok_or_else(invalid)?.into()),
            consent,
            crypto: self.crypto,
            preview: self.preview.clone(),
            capabilities: RequestCapabilities::derive(
                consent,
                self.crypto,
                matches!(self.preview, Some(RequestPreview::Ready { .. })),
            ),
            state_version: coordinate["stateVersion"].as_u64().ok_or_else(invalid)?,
            generation: coordinate["generation"].as_u64().ok_or_else(invalid)?,
        })
    }
}

/// Historical authorized key snapshot from the existing canonical close
/// verifier. This is v1 terminal-entry authority, not an ES256 request receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectRequestCloseProof {
    pub entry: Value,
    pub actor_public_key: Vec<u8>,
    pub entry_sha256: [u8; 32],
    pub publication_digest: [u8; 32],
    pub verified_prior: Value,
}
pub(crate) fn normalized_close_entry(mut entry: Value) -> Result<Value> {
    for (pointer, expected) in [
        ("/$type", "blue.catbird.chat.defs#conversationCloseEntry"),
        (
            "/signedRequest/body/$type",
            "blue.catbird.chat.defs#conversationCloseBody",
        ),
    ] {
        if let Some(tag) = entry.pointer(pointer) {
            if tag != expected {
                return Err(invalid());
            }
        }
    }
    entry["$type"] = Value::String("blue.catbird.chat.defs#conversationCloseEntry".into());
    entry["signedRequest"]["body"]["$type"] =
        Value::String("blue.catbird.chat.defs#conversationCloseBody".into());
    crate::chat_v2::transcript::direct_request::normalize_read_bytes(
        "conversationCloseEntry",
        &mut entry,
    )
    .map_err(|_| invalid())?;
    Ok(entry)
}
impl DirectRequestCloseProof {
    /// Caller normalizes the read-boundary entry once before hashing or replay.
    pub(crate) fn hash(entry: &Value) -> Result<[u8; 32]> {
        use crate::chat_v2::transcript::{
            control_entry_fingerprint, decode_strict_json, project_ref, project_signed_body,
            ControlEntryKind, ControlServerFields, EntryRow, SignedMutationKind, SigningTranscript,
        };
        // The stored row has explicit entry/body tags for verification. Plain
        // schema references are untagged; validate each optional tag before
        // removing it for the canonical outer-entry projection.
        let mut plain = entry.clone();
        for (pointer, expected) in [
            ("", "conversationCloseEntry"),
            ("/signedRequest", "signedConversationClose"),
            ("/tombstone", "conversationCloseTombstone"),
        ] {
            let object = plain
                .pointer_mut(pointer)
                .and_then(Value::as_object_mut)
                .ok_or_else(invalid)?;
            if let Some(tag) = object.remove("$type") {
                if tag != format!("blue.catbird.chat.defs#{expected}") {
                    return Err(invalid());
                }
            }
        }
        let strict = decode_strict_json(&serde_json::to_vec(&plain).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        project_ref("conversationCloseEntry", &strict, false).map_err(|_| invalid())?;
        let body = decode_strict_json(
            &serde_json::to_vec(&entry["signedRequest"]["body"]).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let transcript = SigningTranscript::build_for(
            SignedMutationKind::ConversationClose,
            &project_signed_body(SignedMutationKind::ConversationClose, &body)
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let tombstone =
            decode_strict_json(&serde_json::to_vec(&plain["tombstone"]).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let fields = ControlServerFields::single(
            ControlEntryKind::ConversationClose,
            "tombstone",
            project_ref("conversationCloseTombstone", &tombstone, false).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let row = EntryRow {
            entry_id: *uuid::Uuid::parse_str(entry["entryId"].as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?
                .as_bytes(),
            conversation_id: *uuid::Uuid::parse_str(
                entry["conversationId"].as_str().ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?
            .as_bytes(),
            seq: entry["seq"].as_u64().ok_or_else(invalid)?,
            request_digest: *transcript.request_digest(),
            signature: STANDARD
                .decode(
                    entry["signedRequest"]["signature"]
                        .as_str()
                        .ok_or_else(invalid)?,
                )
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?,
            received_at: entry["receivedAt"].as_str().ok_or_else(invalid)?.to_owned(),
        };
        Ok(
            *control_entry_fingerprint(ControlEntryKind::ConversationClose, &row, &fields)
                .map_err(|_| invalid())?
                .fingerprint()
                .as_bytes(),
        )
    }
    fn verify(
        &self,
        publication: &crate::chat_v2::transcript::direct_request::VerifiedDirectRequest,
        current: &Value,
    ) -> Result<Value> {
        use crate::chat_v2::transcript::{
            decode_strict_json, project_signed_body, SignedMutationKind, VerifiedMutation,
        };
        if self.publication_digest != *publication.request_digest()
            || Self::hash(&self.entry)? != self.entry_sha256
        {
            return Err(invalid());
        }
        let body = &self.entry["signedRequest"]["body"];
        let origin = publication.body();
        if body["conversationKind"] != "direct"
            || (body["actorDid"] != origin["actorDid"]
                && body["actorDid"] != origin["recipientDid"])
            || body["prior"] != self.verified_prior
            || self.verified_prior["conversationId"] != origin["conversationId"]
            || self.verified_prior["groupId"] != origin["next"]["groupId"]
            || self.verified_prior["generation"] != origin["next"]["generation"]
            || self.verified_prior["stateVersion"].as_u64() < current["stateVersion"].as_u64()
            || self.verified_prior["epoch"].as_u64() < current["epoch"].as_u64()
        {
            return Err(invalid());
        }
        let record = crate::orchestrator::account_exit::AccountExitRecord {
            request_body: serde_json::to_vec(
                &serde_json::json!({"signedRequest":self.entry["signedRequest"]}),
            )
            .map_err(|_| invalid())?,
            accepted_response: Some(
                serde_json::json!({"result":{"entry":self.entry,"tombstone":self.entry["tombstone"]}}),
            ),
            local_completion: true,
            replaces_operation: None,
            reset_evidence: None,
        };
        record.validate().map_err(|_| invalid())?;
        let strict = decode_strict_json(&serde_json::to_vec(body).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let canonical = project_signed_body(SignedMutationKind::ConversationClose, &strict)
            .map_err(|_| invalid())?;
        let signature: [u8; 64] = STANDARD
            .decode(
                self.entry["signedRequest"]["signature"]
                    .as_str()
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        VerifiedMutation::verify(canonical, signature, &self.actor_public_key)
            .map_err(|_| invalid())?;
        Ok(body["retired"].clone())
    }
}

/// Normalize a tagged read entry of any kind through the one schema-directed
/// read normalizer, then drop the known outer entry tag.
pub(crate) fn request_control_entry(entry: Value) -> Result<Value> {
    let name = entry["$type"]
        .as_str()
        .and_then(|tag| tag.strip_prefix("blue.catbird.chat.defs#"))
        .ok_or_else(invalid)?;
    let raw = serde_json::to_vec(&entry).map_err(|_| invalid())?;
    let mut canonical =
        crate::chat_v2::transcript::direct_request::normalize_read_presentation(&raw, name, true)
            .map_err(|_| invalid())?;
    canonical
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("$type");
    Ok(canonical)
}
pub(crate) fn verify_request_publication_entry(
    entry: &Value,
    publication: &[u8],
    key: &[u8],
    receipt: &Value,
) -> Result<[u8; 32]> {
    let raw = serde_json::to_vec(entry).map_err(|_| invalid())?;
    let hash = crate::chat_v2::transcript::direct_request::direct_request_entry_hash(&raw)
        .map_err(|_| invalid())?;
    let expected = verify_signed_request(DirectRequestKind::Publish, publication, key)
        .map_err(|_| invalid())?;
    let actual = verify_signed_request(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&entry["signedRequest"]).map_err(|_| invalid())?,
        key,
    )
    .map_err(|_| invalid())?;
    if actual.request_digest() != expected.request_digest()
        || entry["conversationId"] != expected.body()["conversationId"]
        || entry["seq"]
            != expected.body()["artifacts"]["metadataSnapshot"]["authorProof"]["originSeq"]
        || entry["receivedAt"] != receipt["recordedAt"]
    {
        return Err(invalid());
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;

    fn sample_close_entry() -> Value {
        let tombstone = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseTombstone",
            "conversationId": "11111111-1111-4111-9111-111111111111",
            "conversationKind": "direct",
            "retired": {
                "conversationId": "11111111-1111-4111-9111-111111111111",
                "groupId": STANDARD.encode([2u8; 32]),
                "generation": 0,
                "epoch": 0,
                "stateVersion": 1,
                "groupContextHash": STANDARD.encode([3u8; 32]),
                "confirmationTag": STANDARD.encode([4u8; 32]),
                "lifecycle": "superseded"
            },
            "closedByDid": "did:plc:alicefixtureaaaaaaaaaaaa",
            "closedByDeviceId": "72727272-7272-4272-b272-727272727272",
            "terminalSeq": 10,
            "closedAt": "2026-07-22T12:34:56.000Z"
        });
        json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry",
            "entryId": "66666666-6666-4666-a666-666666666666",
            "conversationId": "11111111-1111-4111-9111-111111111111",
            "seq": 10,
            "signedRequest": {
                "body": {
                    "$type": "blue.catbird.chat.defs#conversationCloseBody",
                    "actorDid": "did:plc:alicefixtureaaaaaaaaaaaa",
                    "actorDeviceId": "72727272-7272-4272-b272-727272727272",
                    "authGeneration": 1,
                    "conversationKind": "direct",
                    "idempotencyKey": "67676767-6767-4767-a767-676767676767",
                    "keyId": "OQpJSMbjoMkp9Mz8qJRGo6zAieMT1g9qNZJr8WtW6i8",
                    "prior": {
                        "conversationId": "11111111-1111-4111-9111-111111111111",
                        "groupId": STANDARD.encode([2u8; 32]),
                        "generation": 0,
                        "epoch": 0,
                        "stateVersion": 0,
                        "groupContextHash": STANDARD.encode([3u8; 32]),
                        "confirmationTag": STANDARD.encode([4u8; 32]),
                        "lifecycle": "active"
                    },
                    "retired": {
                        "conversationId": "11111111-1111-4111-9111-111111111111",
                        "groupId": STANDARD.encode([2u8; 32]),
                        "generation": 0,
                        "epoch": 0,
                        "stateVersion": 1,
                        "groupContextHash": STANDARD.encode([3u8; 32]),
                        "confirmationTag": STANDARD.encode([4u8; 32]),
                        "lifecycle": "superseded"
                    },
                    "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
                    "signedAt": "2026-07-22T12:34:55.000Z",
                    "transitionId": "03adfab0-b088-4e86-b992-0f611d2eb64a"
                },
                "signature": STANDARD.encode([5u8; 64])
            },
            "receivedAt": "2026-07-22T12:34:56.000Z",
            "tombstone": tombstone
        })
    }

    #[test]
    fn close_proof_hash_matches_normalized_read_bytes_and_rejects_forged_tags() {
        let canonical = sample_close_entry();
        let canonical_hash = DirectRequestCloseProof::hash(&canonical).unwrap();

        // Server read-boundary entry presents byte fields as {"$bytes": "..."}
        let mut read_entry = canonical.clone();
        read_entry["signedRequest"]["signature"] = json!({
            "$bytes": canonical["signedRequest"]["signature"]
        });
        let read_hash = DirectRequestCloseProof::hash(&normalized_close_entry(read_entry.clone()).unwrap()).unwrap();
        assert_eq!(canonical_hash, read_hash);

        // Mismatched signature fails to match the original hash
        let mut mismatched = canonical.clone();
        mismatched["signedRequest"]["signature"] = json!(STANDARD.encode([99u8; 64]));
        let mismatched_hash = DirectRequestCloseProof::hash(&mismatched).unwrap();
        assert_ne!(canonical_hash, mismatched_hash);

        // Mismatched read entry also hashes to the mismatched hash
        let mut mismatched_read = mismatched.clone();
        mismatched_read["signedRequest"]["signature"] = json!({
            "$bytes": mismatched["signedRequest"]["signature"]
        });
        assert_eq!(mismatched_hash, DirectRequestCloseProof::hash(&normalized_close_entry(mismatched_read).unwrap()).unwrap());
        let mut forged_tag = read_entry.clone();
        forged_tag["$type"] = json!("blue.catbird.chat.defs#directRequestEntry");
        assert!(normalized_close_entry(forged_tag.clone()).is_err());
        forged_tag["$type"] = canonical["$type"].clone();
        forged_tag["signedRequest"]["body"]["$type"] =
            json!("blue.catbird.chat.defs#directRequestBody");
        assert!(normalized_close_entry(forged_tag).is_err());
    }
}
