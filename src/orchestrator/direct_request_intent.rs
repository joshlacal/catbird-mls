//! Encrypted pre-reservation intent. Transport retries must use the same bytes.
use super::super::direct_request_types::DirectRequestInput;
use crate::chat_v2::transcript::direct_request::{verify_signed_request, DirectRequestKind};
use crate::orchestrator::{OrchestratorError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestIntent {
    pub input: DirectRequestInput,
    pub actor_did: String,
    pub actor_device_id: String,
    pub actor_public_key: Vec<u8>,
    /// Immutable signed wrapper, persisted BEFORE the prepare RPC is invoked.
    pub prepare_wrapper: Vec<u8>,
    #[serde(default)]
    pub legacy_origin_snapshot: Option<serde_json::Value>,
    /// Authenticated authority document retained before reservation, permitting
    /// exact receipt verification across offline restart and key rotation.
    pub trusted_authority_document: Vec<u8>,
    /// Exact bytes received from the authenticated authority. Storing them does
    /// not grant trust: every resume re-verifies signature and request bindings.
    pub preparation_response: Option<Vec<u8>>,
    pub cancel_wrapper: Option<Vec<u8>>,
    pub publication_wrapper: Option<Vec<u8>>,
    pub terminal_response: Option<Vec<u8>>,
    pub publication_attempted: bool,
    pub cancellation_requested: bool,
    pub projection_completed: bool,
    pub previous_attempts: Vec<DirectRequestTerminalAttempt>,
}

fn invalid() -> OrchestratorError {
    OrchestratorError::Storage("Invalid direct request ownership record".into())
}
impl DirectRequestIntent {
    pub fn validate(&self, owner: &str, device: &str) -> Result<()> {
        super::validate_direct_request_input(&self.input)?;
        validate_authority_document(&self.trusted_authority_document)?;
        for attempt in &self.previous_attempts {
            attempt.validate(owner, device)?;
        }
        if self.actor_did != owner
            || self.actor_device_id != device
            || owner == self.input.recipient_did
        {
            return Err(invalid());
        }
        let prepare = verify_signed_request(
            DirectRequestKind::Prepare,
            &self.prepare_wrapper,
            &self.actor_public_key,
        )
        .map_err(|_| invalid())?;
        if prepare.actor_did() != Some(owner)
            || prepare.actor_device_id() != Some(device)
            || prepare.body()["recipientDid"] != self.input.recipient_did
        {
            return Err(invalid());
        }
        match &self.legacy_origin_snapshot {
            Some(snapshot) => {
                crate::orchestrator::canonical_transport::decode_conversation_state(
                    &serde_json::to_vec(snapshot).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
                let origin =
                    super::origin::legacy_origin(snapshot, owner, &self.input.recipient_did)?
                        .ok_or_else(invalid)?;
                if prepare.body()["origin"] != origin
                    || prepare.body()["conversationId"] != snapshot["coordinates"]["conversationId"]
                {
                    return Err(invalid());
                }
            }
            None if prepare.body()["origin"]["$type"]
                != "blue.catbird.chat.defs#freshDirectOrigin" =>
            {
                return Err(invalid())
            }
            None => {}
        }
        if let Some(wrapper) = &self.cancel_wrapper {
            let cancel =
                verify_signed_request(DirectRequestKind::Cancel, wrapper, &self.actor_public_key)
                    .map_err(|_| invalid())?;
            if cancel.actor_did() != Some(owner)
                || cancel.actor_device_id() != Some(device)
                || cancel.request_id() != prepare.request_id()
                || cancel.body()["recipientDid"] != self.input.recipient_did
            {
                return Err(invalid());
            }
            use base64::Engine as _;
            let digest = cancel.body()["preparationRequestDigest"]
                .as_str()
                .ok_or_else(invalid)?;
            if base64::engine::general_purpose::STANDARD
                .decode(digest)
                .map_err(|_| invalid())?
                != prepare.request_digest()
            {
                return Err(invalid());
            }
        }
        if let Some(raw) = &self.preparation_response {
            use crate::chat_v2::transcript::direct_request::{
                resolve_direct_request_receipt_key, verify_direct_request_preparation,
            };
            use base64::Engine as _;
            let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| invalid())?;
            let key = resolve_direct_request_receipt_key(
                &self.trusted_authority_document,
                value["receiptKeyId"].as_str().ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            let snapshot = verify_direct_request_preparation(raw, &key).map_err(|_| invalid())?;
            for field in [
                "requestId",
                "firstMessageId",
                "conversationId",
                "recipientDid",
                "origin",
                "profile",
            ] {
                if snapshot[field] != prepare.body()[field] {
                    return Err(invalid());
                }
            }
            for field in ["actorDid", "actorDeviceId", "keyId", "authGeneration"] {
                if snapshot["creator"][field] != prepare.body()[field] {
                    return Err(invalid());
                }
            }
            if snapshot["preparationRequestDigest"]
                != base64::engine::general_purpose::STANDARD.encode(prepare.request_digest())
            {
                return Err(invalid());
            }
        }
        if let Some(wrapper) = &self.publication_wrapper {
            let publication =
                verify_signed_request(DirectRequestKind::Publish, wrapper, &self.actor_public_key)
                    .map_err(|_| invalid())?;
            use base64::Engine as _;
            if publication.body()["preparationRequestDigest"]
                != base64::engine::general_purpose::STANDARD.encode(prepare.request_digest())
            {
                return Err(invalid());
            }
            let snapshot: serde_json::Value =
                serde_json::from_slice(self.preparation_response.as_ref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            if publication.body()["preparationDigest"] != snapshot["preparationDigest"] {
                return Err(invalid());
            }
            let expected_seq = match &self.legacy_origin_snapshot {
                Some(state) => state["snapshotSeq"]
                    .as_u64()
                    .and_then(|s| s.checked_add(1))
                    .ok_or_else(invalid)?,
                None => 1,
            };
            if publication.body()["artifacts"]["metadataSnapshot"]["authorProof"]["originSeq"]
                .as_u64()
                != Some(expected_seq)
            {
                return Err(invalid());
            }
            for field in [
                "requestId",
                "firstMessageId",
                "conversationId",
                "recipientDid",
                "origin",
                "profile",
                "actorDid",
                "actorDeviceId",
                "keyId",
                "authGeneration",
            ] {
                if publication.body()[field] != prepare.body()[field] {
                    return Err(invalid());
                }
            }
        }
        if self.terminal_response.is_some() {
            self.evidence()?.validate_receipt(owner, device, true)?;
        }
        if self.cancellation_requested != self.cancel_wrapper.is_some()
            || (self.projection_completed
                && (self.terminal_response.is_none() || !self.publication_attempted))
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn evidence(&self) -> Result<DirectRequestTerminalAttempt> {
        Ok(DirectRequestTerminalAttempt {
            prepare_wrapper: self.prepare_wrapper.clone(),
            actor_public_key: self.actor_public_key.clone(),
            trusted_authority_document: self.trusted_authority_document.clone(),
            receipt: self.terminal_response.clone().ok_or_else(invalid)?,
            cancel_wrapper: self.cancel_wrapper.clone(),
            publication_wrapper: self.publication_wrapper.clone(),
        })
    }
    pub fn decode(raw: &[u8], owner: &str, device: &str) -> Result<Self> {
        let record: Self = serde_json::from_slice(raw).map_err(|_| invalid())?;
        record.validate(owner, device)?;
        Ok(record)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(&self.actor_did, &self.actor_device_id)?;
        serde_json::to_vec(self).map_err(|_| invalid())
    }
    pub fn request_id(&self) -> Result<String> {
        let prepare = verify_signed_request(
            DirectRequestKind::Prepare,
            &self.prepare_wrapper,
            &self.actor_public_key,
        )
        .map_err(|_| invalid())?;
        prepare.request_id().map(str::to_owned).ok_or_else(invalid)
    }
    /// A response timeout is deliberately not an editable/terminal disposition.
    /// The caller must first obtain a verified non-publication receipt and keep
    /// its old immutable operation tombstone before replacing this attempt.
    pub fn matches_input(&self, input: &DirectRequestInput) -> bool {
        self.input == *input
    }
}

/// Check support before reservation without selecting a server key ourselves.
/// The response later chooses a method that must resolve within this retained
/// authenticated document or a freshly authenticated rotation document.
pub fn validate_authority_document(document: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(document).map_err(|_| invalid())?;
    let methods = value["verificationMethod"].as_array().ok_or_else(invalid)?;
    if !methods
        .iter()
        .filter_map(|method| method["id"].as_str())
        .any(|id| {
            crate::chat_v2::transcript::direct_request::resolve_direct_request_receipt_key(
                document, id,
            )
            .is_ok()
        })
    {
        return Err(invalid());
    }
    Ok(())
}

/// Retains terminal operation evidence when the same local draft is edited.
/// This contains no bootstrap bytes that could be reassigned to another group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestTerminalAttempt {
    prepare_wrapper: Vec<u8>,
    actor_public_key: Vec<u8>,
    trusted_authority_document: Vec<u8>,
    receipt: Vec<u8>,
    cancel_wrapper: Option<Vec<u8>>,
    publication_wrapper: Option<Vec<u8>>,
}
impl DirectRequestTerminalAttempt {
    pub fn from_intent(intent: &DirectRequestIntent) -> Result<Self> {
        let attempt = intent.evidence()?;
        attempt.validate(&intent.actor_did, &intent.actor_device_id)?;
        Ok(attempt)
    }
    fn validate(&self, owner: &str, device: &str) -> Result<()> {
        self.validate_receipt(owner, device, false)
    }
    fn validate_receipt(&self, owner: &str, device: &str, allow_published: bool) -> Result<()> {
        use crate::chat_v2::transcript::direct_request::resolve_direct_request_receipt_key;
        use base64::Engine as _;
        let prepare = verify_signed_request(
            DirectRequestKind::Prepare,
            &self.prepare_wrapper,
            &self.actor_public_key,
        )
        .map_err(|_| invalid())?;
        if prepare.actor_did() != Some(owner) || prepare.actor_device_id() != Some(device) {
            return Err(invalid());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&self.receipt).map_err(|_| invalid())?;
        let method = value["body"]["keyId"].as_str().ok_or_else(invalid)?;
        let key = resolve_direct_request_receipt_key(&self.trusted_authority_document, method)
            .map_err(|_| invalid())?;
        let receipt = crate::chat_v2::transcript::direct_request::verify_received_signed_request(
            DirectRequestKind::Outcome,
            &self.receipt,
            &key,
        )
        .map_err(|_| invalid())?;
        let proof = &receipt.body()["receipt"];
        if !(allow_published
            && proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt")
            && !matches!(
                proof["$type"].as_str(),
                Some(
                    "blue.catbird.chat.defs#directRequestCancelledReceipt"
                        | "blue.catbird.chat.defs#directRequestExpiredReceipt"
                        | "blue.catbird.chat.defs#directRequestRejectedReceipt"
                        | "blue.catbird.chat.defs#directRequestExistingDirectReceipt"
                )
            )
            || proof["requestId"].as_str() != prepare.request_id()
            || proof["preparationRequestDigest"]
                != base64::engine::general_purpose::STANDARD.encode(prepare.request_digest())
        {
            return Err(invalid());
        }
        for (receipt_field, prepare_field) in [
            ("actorDid", "actorDid"),
            ("actorDeviceId", "actorDeviceId"),
            ("actorKeyId", "keyId"),
            ("authGeneration", "authGeneration"),
        ] {
            if proof[receipt_field] != prepare.body()[prepare_field] {
                return Err(invalid());
            }
        }
        if proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt"
            && proof["requestKind"] != "publish"
        {
            return Err(invalid());
        }
        let digest = match proof["requestKind"].as_str() {
            Some("prepare" | "expiry") => *prepare.request_digest(),
            Some("cancel" | "publish") => {
                let kind = if proof["requestKind"] == "cancel" {
                    DirectRequestKind::Cancel
                } else {
                    DirectRequestKind::Publish
                };
                let wrapper = if proof["requestKind"] == "cancel" {
                    &self.cancel_wrapper
                } else {
                    &self.publication_wrapper
                };
                let trigger = verify_signed_request(
                    kind,
                    wrapper.as_ref().ok_or_else(invalid)?,
                    &self.actor_public_key,
                )
                .map_err(|_| invalid())?;
                if trigger.request_id() != prepare.request_id()
                    || trigger.actor_did() != Some(owner)
                    || trigger.actor_device_id() != Some(device)
                {
                    return Err(invalid());
                }
                if trigger.body()["preparationRequestDigest"]
                    != base64::engine::general_purpose::STANDARD.encode(prepare.request_digest())
                {
                    return Err(invalid());
                }
                if proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt" {
                    if proof["requestKind"] != "publish" {
                        return Err(invalid());
                    }
                    for (receipt_field, publication_field) in [
                        ("conversationId", "conversationId"),
                        ("firstMessageId", "firstMessageId"),
                        ("coordinates", "next"),
                    ] {
                        if proof[receipt_field] != trigger.body()[publication_field] {
                            return Err(invalid());
                        }
                    }
                }
                *trigger.request_digest()
            }
            _ => return Err(invalid()),
        };
        if proof["requestDigest"] != base64::engine::general_purpose::STANDARD.encode(digest) {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn merge_trusted_documents(previous: &[u8], current: &[u8]) -> Result<Vec<u8>> {
    validate_authority_document(previous)?;
    validate_authority_document(current)?;
    let mut previous: serde_json::Value =
        serde_json::from_slice(previous).map_err(|_| invalid())?;
    let current: serde_json::Value = serde_json::from_slice(current).map_err(|_| invalid())?;
    let methods = previous["verificationMethod"]
        .as_array_mut()
        .ok_or_else(invalid)?;
    for method in current["verificationMethod"]
        .as_array()
        .ok_or_else(invalid)?
    {
        if let Some(old) = methods.iter().find(|old| old["id"] == method["id"]) {
            if old != method {
                return Err(invalid());
            }
        } else {
            methods.push(method.clone());
        }
    }
    serde_json::to_vec(&previous).map_err(|_| invalid())
}
