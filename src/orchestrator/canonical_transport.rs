//! Internal transport for the generated clean-chat XRPC surface.
//!
//! This is intentionally a transport seam, not a second protocol
//! implementation. The platform owns OAuth/DPoP proof construction and the
//! clean-chat transcript projector. We consume those exact values, bind them
//! to the generated request, and serialize the generated DTO without routing
//! through the legacy `blue.catbird.mlsChat.*` surface.

use crate::atproto::blue_catbird::chat::{
    create_conversation::CreateConversationRequest,
    enroll_device::EnrollDeviceRequest,
    get_conversations::{GetConversations, GetConversationsRequest},
    get_entries::{GetEntries, GetEntriesRequest},
    replenish_key_packages::{ReplenishKeyPackages, ReplenishKeyPackagesRequest},
    request_leave::RequestLeaveRequest,
    send_message::SendMessageRequest,
    submit_transition::SubmitTransitionRequest,
};
use crate::atproto::jacquard_common::deps::bytes::Bytes;
use crate::atproto::jacquard_common::xrpc::XrpcEndpoint;
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;
use std::{collections::BTreeMap, str::FromStr};
use uuid::{Uuid, Version};

const REPLENISH_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REPLENISH\0";

/// The already-authenticated transport material supplied by the platform.
///
/// `authorization` and `dpop_proof` are opaque on purpose: Nest/DPoP owns
/// their construction and refresh/nonce policy. The Rust orchestrator only
/// ensures that both are present and that the signed mutation's JKT/device
/// agree with the same authenticated device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransportAuth {
    pub(crate) authorization: String,
    pub(crate) dpop_proof: String,
    pub(crate) dpop_jkt: String,
    pub(crate) device_id: String,
}

impl TransportAuth {
    fn validate(&self) -> Result<(), TransportError> {
        if self.authorization.trim().is_empty() || self.dpop_proof.trim().is_empty() {
            return Err(TransportError::MissingAuthentication);
        }
        if self.dpop_jkt.trim().is_empty() || self.device_id.trim().is_empty() {
            return Err(TransportError::MissingDeviceBinding);
        }
        Ok(())
    }
}

/// A serialized request ready for the platform's HTTP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedRequest {
    pub(crate) method: &'static str,
    pub(crate) path: String,
    pub(crate) authorization: String,
    pub(crate) dpop: String,
    pub(crate) body: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum TransportError {
    #[error("clean-chat transport authentication is missing")]
    MissingAuthentication,
    #[error("clean-chat transport device binding is missing")]
    MissingDeviceBinding,
    #[error("signed body device {body} does not match authenticated device {authenticated}")]
    DeviceBindingMismatch { body: String, authenticated: String },
    #[error("signed body DPoP JKT does not match authenticated DPoP JKT")]
    DpopBindingMismatch,
    #[error("signed body domain is not the canonical key-package replenishment domain")]
    InvalidSignatureDomain,
    #[error("canonical signing transcript is empty")]
    EmptySigningTranscript,
    #[error("generated clean-chat request serialization failed: {0}")]
    Serialization(String),
    #[error("device signing failed")]
    Signing,
    #[error("clean-chat signed mutations require an Ed25519 device key")]
    UnsupportedSigningScheme,
    #[error("clean-chat {operation:?} failed with {code} (retryable={retryable})")]
    Remote {
        operation: CanonicalOperation,
        code: String,
        retryable: bool,
    },
}

/// Map a generated clean-chat wire error without collapsing it into a legacy
/// API error. Unknown codes remain visible and non-retryable until their
/// lexicon contract is explicitly added.
pub(crate) fn map_wire_error(operation: CanonicalOperation, code: &str) -> TransportError {
    let retryable = matches!(code, "CursorExpired" | "AuthenticationGenerationConflict");
    TransportError::Remote {
        operation,
        code: code.to_owned(),
        retryable,
    }
}

/// Inputs needed to construct `blue.catbird.chat.replenishKeyPackages`.
///
/// The body fields are the sole source of truth for the signed transcript.
/// Callers cannot supply an arbitrary byte string to sign.
pub(crate) struct ReplenishKeyPackagesInput {
    pub(crate) actor_did: String,
    pub(crate) actor_device_id: String,
    pub(crate) auth_generation: i64,
    pub(crate) idempotency_key: String,
    pub(crate) key_id: String,
    pub(crate) dpop_jkt: String,
    pub(crate) signature_domain: String,
    pub(crate) key_packages: Vec<crate::atproto::blue_catbird::chat::KeyPackageArtifact<String>>,
    pub(crate) signed_at: String,
}

/// Construct and serialize one canonical key-package replenishment request.
///
/// The returned wrapper uses the generated `SignedKeyPackageReplenishment` and
/// `ReplenishKeyPackages` types, so the wire shape cannot silently drift from
/// the lexicon. No public FFI is introduced; a platform can call this from an
/// existing internal adapter once its transcript and DPoP facilities are
/// available.
pub(crate) fn replenish_key_packages(
    auth: &TransportAuth,
    signer: &SignatureKeyPair,
    input: ReplenishKeyPackagesInput,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    if input.actor_device_id != auth.device_id {
        return Err(TransportError::DeviceBindingMismatch {
            body: input.actor_device_id,
            authenticated: auth.device_id.clone(),
        });
    }
    if input.dpop_jkt != auth.dpop_jkt {
        return Err(TransportError::DpopBindingMismatch);
    }
    if input.signature_domain != REPLENISH_SIGNATURE_DOMAIN {
        return Err(TransportError::InvalidSignatureDomain);
    }
    if signer.signature_scheme() != SignatureScheme::ED25519 || signer.public().len() != 32 {
        return Err(TransportError::UnsupportedSigningScheme);
    }
    let public_key = signer.public().to_vec();
    let derived_key_id = derive_key_id(&public_key);
    if input.key_id != derived_key_id {
        return Err(TransportError::Serialization(
            "keyId does not match the Ed25519 public-key thumbprint".into(),
        ));
    }
    let signed_at = parse_datetime(input.signed_at.clone())?;
    let transcript =
        canonical_replenishment_transcript(&input, &public_key, &signed_at, &derived_key_id)?;
    let signature = signer
        .sign(&transcript)
        .map_err(|_| TransportError::Signing)?;
    let body = crate::atproto::blue_catbird::chat::KeyPackageReplenishmentBody::<String> {
        actor_device_id: input.actor_device_id,
        actor_did: crate::atproto::jacquard_common::types::string::Did::<String>::from_str(
            &input.actor_did,
        )
        .map_err(|_| TransportError::Serialization("actorDid is not a valid DID".into()))?,
        auth_generation: input.auth_generation,
        dpop_jkt: input.dpop_jkt,
        idempotency_key: input.idempotency_key,
        key_id: input.key_id,
        key_packages: input.key_packages,
        signature_domain: REPLENISH_SIGNATURE_DOMAIN.to_owned(),
        signature_public_key: Bytes::from(signer.public().to_vec()),
        signed_at,
        extra_data: None,
    };
    let signed = crate::atproto::blue_catbird::chat::SignedKeyPackageReplenishment::<String> {
        body,
        signature: Bytes::from(signature),
        extra_data: None,
    };
    let request = ReplenishKeyPackages::<String> {
        signed_request: signed,
        extra_data: None,
    };
    Ok(PreparedRequest {
        method: "POST",
        path: ReplenishKeyPackagesRequest::PATH.to_owned(),
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: Some(serialize_json(&request)?),
    })
}

pub(crate) fn derive_key_id(public_key: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

#[derive(Debug)]
enum CanonicalValue {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Array(Vec<CanonicalValue>),
    Map(BTreeMap<String, CanonicalValue>),
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

pub(crate) fn canonical_replenishment_transcript(
    input: &ReplenishKeyPackagesInput,
    public_key: &[u8],
    signed_at: &crate::atproto::blue_catbird::chat::CanonicalDatetime,
    key_id: &str,
) -> Result<Vec<u8>, TransportError> {
    let device_id = canonical_uuid_bytes(&input.actor_device_id, "actorDeviceId")?;
    let idempotency_key = canonical_uuid_bytes(&input.idempotency_key, "idempotencyKey")?;
    let auth_generation = u64::try_from(input.auth_generation)
        .map_err(|_| TransportError::Serialization("authGeneration must be non-negative".into()))?;
    let mut body = BTreeMap::new();
    body.insert(
        "$type".into(),
        CanonicalValue::Text("blue.catbird.chat.defs#keyPackageReplenishmentBody".into()),
    );
    body.insert("actorDeviceId".into(), CanonicalValue::Bytes(device_id));
    body.insert(
        "actorDid".into(),
        CanonicalValue::Text(input.actor_did.clone()),
    );
    body.insert(
        "authGeneration".into(),
        CanonicalValue::Integer(auth_generation),
    );
    body.insert(
        "dpopJkt".into(),
        CanonicalValue::Text(input.dpop_jkt.clone()),
    );
    body.insert(
        "idempotencyKey".into(),
        CanonicalValue::Bytes(idempotency_key),
    );
    body.insert("keyId".into(), CanonicalValue::Text(key_id.into()));
    let packages = input
        .key_packages
        .iter()
        .map(|package| {
            let mut value = BTreeMap::new();
            value.insert(
                "bytes".into(),
                CanonicalValue::Bytes(package.bytes.to_vec()),
            );
            value.insert(
                "contentType".into(),
                CanonicalValue::Text(package.content_type.clone()),
            );
            value.insert(
                "framing".into(),
                CanonicalValue::Text(package.framing.clone()),
            );
            value.insert(
                "keyPackageRef".into(),
                CanonicalValue::Bytes(package.key_package_ref.to_vec()),
            );
            value.insert(
                "sha256".into(),
                CanonicalValue::Bytes(package.sha256.to_vec()),
            );
            CanonicalValue::Map(value)
        })
        .collect();
    body.insert("keyPackages".into(), CanonicalValue::Array(packages));
    body.insert(
        "signatureDomain".into(),
        CanonicalValue::Text(REPLENISH_SIGNATURE_DOMAIN.into()),
    );
    body.insert(
        "signaturePublicKey".into(),
        CanonicalValue::Bytes(public_key.to_vec()),
    );
    body.insert(
        "signedAt".into(),
        CanonicalValue::Text(signed_at.to_string()),
    );
    let projection = serde_ipld_dagcbor::to_vec(&CanonicalValue::Map(body))
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut transcript = REPLENISH_SIGNATURE_DOMAIN.as_bytes().to_vec();
    transcript.extend_from_slice(&projection);
    if transcript.is_empty() {
        return Err(TransportError::EmptySigningTranscript);
    }
    Ok(transcript)
}

fn canonical_uuid_bytes(value: &str, field: &str) -> Result<Vec<u8>, TransportError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| TransportError::Serialization(format!("{field} is not a UUID")))?;
    if uuid.get_version() != Some(Version::Random) {
        return Err(TransportError::Serialization(format!(
            "{field} is not a UUIDv4"
        )));
    }
    Ok(uuid.as_bytes().to_vec())
}

fn parse_datetime(
    value: String,
) -> Result<crate::atproto::blue_catbird::chat::CanonicalDatetime, TransportError> {
    crate::atproto::blue_catbird::chat::CanonicalDatetime::from_str(&value)
        .map_err(|_| TransportError::Serialization("signedAt is not a canonical datetime".into()))
}

fn serialize_json(value: &impl Serialize) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(value).map_err(|error| TransportError::Serialization(error.to_string()))
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn read_request(
    auth: &TransportAuth,
    operation: CanonicalOperation,
    query: String,
) -> Result<PreparedRequest, TransportError> {
    auth.validate()?;
    let route = canonical_route(operation);
    Ok(PreparedRequest {
        method: "GET",
        path: format!("{}?{}", route.path, query),
        authorization: auth.authorization.clone(),
        dpop: auth.dpop_proof.clone(),
        body: None,
    })
}

/// Build the generated `getConversations` query, retaining `pageCursor` (the
/// generated field) rather than reviving the legacy `cursor` spelling.
pub(crate) fn get_conversations(
    auth: &TransportAuth,
    limit: i64,
    page_cursor: Option<&str>,
) -> Result<PreparedRequest, TransportError> {
    let request = GetConversations {
        limit,
        page_cursor: page_cursor.map(ToOwned::to_owned),
    };
    let value = serde_json::to_value(request)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut query = format!("limit={}", value["limit"]);
    if let Some(cursor) = value["pageCursor"].as_str() {
        query.push_str("&pageCursor=");
        query.push_str(&encode_query(cursor));
    }
    read_request(auth, CanonicalOperation::GetConversations, query)
}

/// Build the generated `getEntries` transport-auth query.
pub(crate) fn get_entries(
    auth: &TransportAuth,
    conversation_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<PreparedRequest, TransportError> {
    let request = GetEntries {
        after_seq,
        conversation_id: conversation_id.to_owned(),
        limit,
    };
    let value = serde_json::to_value(request)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let query = format!(
        "afterSeq={}&conversationId={}&limit={}",
        value["afterSeq"],
        encode_query(value["conversationId"].as_str().unwrap_or_default()),
        value["limit"]
    );
    read_request(auth, CanonicalOperation::GetEntries, query)
}

/// Canonical operations with a generated `blue.catbird.chat.*` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalOperation {
    GetConversations,
    CreateConversation,
    SendMessage,
    GetEntries,
    ReplenishKeyPackages,
    EnrollDevice,
    RequestLeave,
    SubmitTransition,
}

impl CanonicalOperation {
    /// Every operation in the route inventory.
    pub(crate) const ALL: &'static [Self] = &[
        Self::GetConversations,
        Self::CreateConversation,
        Self::SendMessage,
        Self::GetEntries,
        Self::ReplenishKeyPackages,
        Self::EnrollDevice,
        Self::RequestLeave,
        Self::SubmitTransition,
    ];
}

/// The generated NSID and path for one canonical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalRoute {
    pub(crate) nsid: &'static str,
    pub(crate) path: &'static str,
}

fn route(path: &'static str) -> CanonicalRoute {
    let nsid = path
        .strip_prefix("/xrpc/")
        .expect("generated XRPC endpoint paths have /xrpc/ prefix");
    CanonicalRoute { nsid, path }
}

/// Resolve an operation through the generated canonical endpoint marker.
pub(crate) fn canonical_route(operation: CanonicalOperation) -> CanonicalRoute {
    match operation {
        CanonicalOperation::GetConversations => route(GetConversationsRequest::PATH),
        CanonicalOperation::CreateConversation => route(CreateConversationRequest::PATH),
        CanonicalOperation::SendMessage => route(SendMessageRequest::PATH),
        CanonicalOperation::GetEntries => route(GetEntriesRequest::PATH),
        CanonicalOperation::ReplenishKeyPackages => route(ReplenishKeyPackagesRequest::PATH),
        CanonicalOperation::EnrollDevice => route(EnrollDeviceRequest::PATH),
        CanonicalOperation::RequestLeave => route(RequestLeaveRequest::PATH),
        CanonicalOperation::SubmitTransition => route(SubmitTransitionRequest::PATH),
    }
}

/// Resolve only a canonical generated NSID. Legacy `mlsChat` names are
/// intentionally not aliases: accepting one here would make it possible for a
/// platform adapter to silently downgrade a clean-chat request.
pub(crate) fn route_for_nsid(nsid: &str) -> Option<CanonicalRoute> {
    CanonicalOperation::ALL
        .iter()
        .copied()
        .map(canonical_route)
        .find(|route| route.nsid == nsid)
}
