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
    /// Authenticated authority document retained before reservation, permitting
    /// exact receipt verification across offline restart and key rotation.
    pub trusted_authority_document: Vec<u8>,
    /// Exact bytes received from the authenticated authority. Storing them does
    /// not grant trust: every resume re-verifies signature and request bindings.
    pub preparation_response: Option<Vec<u8>>,
    pub cancel_wrapper: Option<Vec<u8>>,
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
        if self.cancellation_requested != self.cancel_wrapper.is_some()
            || (self.projection_completed
                && (self.terminal_response.is_none() || !self.publication_attempted))
        {
            return Err(invalid());
        }
        Ok(())
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
}
impl DirectRequestTerminalAttempt {
    pub fn from_intent(intent: &DirectRequestIntent) -> Result<Self> {
        let attempt = Self {
            prepare_wrapper: intent.prepare_wrapper.clone(),
            actor_public_key: intent.actor_public_key.clone(),
            trusted_authority_document: intent.trusted_authority_document.clone(),
            receipt: intent.terminal_response.clone().ok_or_else(invalid)?,
        };
        attempt.validate(&intent.actor_did, &intent.actor_device_id)?;
        Ok(attempt)
    }
    fn validate(&self, owner: &str, device: &str) -> Result<()> {
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
        let receipt = verify_signed_request(DirectRequestKind::Outcome, &self.receipt, &key)
            .map_err(|_| invalid())?;
        let proof = &receipt.body()["receipt"];
        if !matches!(
            proof["$type"].as_str(),
            Some(
                "blue.catbird.chat.defs#directRequestCancelledReceipt"
                    | "blue.catbird.chat.defs#directRequestExpiredReceipt"
                    | "blue.catbird.chat.defs#directRequestRejectedReceipt"
                    | "blue.catbird.chat.defs#directRequestExistingDirectReceipt"
            )
        ) || proof["requestId"].as_str() != prepare.request_id()
            || proof["preparationRequestDigest"]
                != base64::engine::general_purpose::STANDARD.encode(prepare.request_digest())
        {
            return Err(invalid());
        }
        Ok(())
    }
}
