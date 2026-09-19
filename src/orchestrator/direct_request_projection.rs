//! Protected request projection backed by signed publication and consent proof.
use super::super::direct_request_types::*;
use crate::chat_v2::transcript::direct_request::{
    resolve_direct_request_receipt_key, verify_signed_request, DirectRequestKind,
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
    pub sender_public_key: Vec<u8>,
    pub publication_receipt: Vec<u8>,
    pub crypto: RequestCrypto,
    pub preview: Option<RequestPreview>,
    pub acceptance_proof: Option<Vec<u8>>,
    pub recipient_public_key: Option<Vec<u8>>,
    pub pending_acceptance: Option<Vec<u8>>,
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
        let authority_key =
            resolve_direct_request_receipt_key(&self.trusted_authority_document, method)
                .map_err(|_| invalid())?;
        let receipt = verify_signed_request(
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
                let key =
                    resolve_direct_request_receipt_key(&self.trusted_authority_document, method)
                        .map_err(|_| invalid())?;
                let verified=crate::chat_v2::transcript::direct_request::verify_direct_request_acceptance_proof(proof,&key,recipient_key).map_err(|_|invalid())?;
                let accepted = &verified["entry"]["signedRequest"]["body"];
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
        Ok(DirectRequestView {
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
