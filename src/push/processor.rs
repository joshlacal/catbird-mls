//! Synchronous, zero-Tokio push notification processor (`Spec §6.2`, `G1`).
//!
//! Enforces:
//! - `G1`: Zero Tokio worker pool; `OpenMode::PushExtension` (`cache_size = -512`, `mmap_size = 0`);
//!   lazy-loads **only** the target `MlsGroup` (never all groups or all KeyPackages).
//! - `I4` (`F-02`): Every `ApplicationMessage` sender leaf and every NSE-applied Commit must match
//!   a DID-rooted authorized ATProto device signature key before persisting. Unverified controls
//!   remain for foreground sync.
//! - `I6`: All network fetches (`fetch_missing_entries`, `get_authorized_device_keys`) execute
//!   strictly **outside** `BEGIN IMMEDIATE`.
//! - `I7`: `MlsAccountDb::write_tx` reconciles `PRAGMA data_version` inside `BEGIN IMMEDIATE`.
//! - `I10`: Never refreshes OAuth; if `fetch_required`/gap needs network and cached `chat-dpop`
//!   is missing/expired (or `transport` is `None`), returns clean `"New encrypted message"` fallback.
//! - `I11`: Closes the SQLite handle completely and emits `blue.catbird.mls.nseDidCommit`.
//! - `I12`: Rejects inline ciphertext payloads exceeding `INLINE_CIPHERTEXT_MAX_BYTES` (`2200` B).
//! - `I13`: Verifies `PrivateMessageAadEnvelope` `archive_commitment` in constant time when present.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chat_v2::transcript::SignedMutationKind;
use crate::client::{
    apply_verified_roster_effects, chat_wire, verify_control_entry_receipt_with_key,
    CatbirdMlsClient,
};
use crate::error::MLSError;
use crate::keychain::KeychainAccess;
use crate::metadata::{decrypt_metadata_snapshot, derive_metadata_key_from_group};
use crate::storage::{
    ConversationRow, GroupMetadataRow, KvWriteBatch, KvWriteOverlay, MessageRow, MlsAccountDb,
    OpenMlsKvStorage, OpenMode, RusqliteKvBackend, SqlTx,
};

use super::{
    should_inline_push_ciphertext, DARWIN_NSE_DID_COMMIT_NOTIFICATION, INLINE_CIPHERTEXT_MAX_BYTES,
    NSE_DEFERRED_CONTROL_OP,
};

pub(crate) const NATIVE_ARCHIVE_RECEIPT_OP: &str = "native_archive_receipt";

/// Structured metadata-only push wake delivered via `nest` (`Spec §6.2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PushWakePayload {
    pub kind: String,
    pub conversation_id: String,
    pub generation: i64,
    pub entry_seq: i64,
    pub message_id: String,
    pub recipient_account_hash: String,
    pub fetch_required: bool,
    pub sender_did: Option<String>,
    pub inline_ciphertext: Option<Vec<u8>>,
}

/// Authorized peer device signing key published in the user's ATProto repo (`ADR-009` / `I4`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct AuthorizedPeerDeviceKey {
    pub did: String,
    pub device_id: String,
    pub signature_public_key: Vec<u8>,
}

/// Sequenced `chat.entries` item fetched during push gap catch-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct FetchedPushEntry {
    pub entry_id: String,
    pub seq: i64,
    pub epoch: i64,
    pub entry_kind: String,
    pub sender_did: String,
    pub mls_bytes: Vec<u8>,
    /// JSON-encoded actor-signed request returned by `getEntries`.
    #[serde(default)]
    pub signed_request: Option<Vec<u8>>,
    /// JSON-encoded sequencer receipt returned by `getEntries`.
    #[serde(default)]
    pub sequencer_receipt: Option<Vec<u8>>,
}

/// Encrypted `chat.metadata_snapshots` blob fetched on group metadata cache miss (`1A`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct FetchedMetadataSnapshot {
    pub epoch: i64,
    pub metadata_version: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Response bundle returned by [`PushFetchTransport::fetch_missing_entries`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PushFetchBundle {
    pub entries: Vec<FetchedPushEntry>,
    pub metadata_snapshot: Option<FetchedMetadataSnapshot>,
    pub authorized_device_keys: Vec<AuthorizedPeerDeviceKey>,
}

/// Decrypted `INSendMessageIntent` / Android FCM notification fields (`Spec §6.2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct NotificationPreview {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub sender_display_name: Option<String>,
    pub group_title: Option<String>,
    pub body: String,
    pub epoch: i64,
    pub seq: i64,
    pub from_cache: bool,
    pub fallback_generic: bool,
    pub darwin_notification_name: String,
    pub receipt_verified: bool,
    pub is_own_sibling_sender: bool,
}

/// Synchronous keystore interface for NSE / FCM (`sha256(normalized_did)`-keyed, zero OAuth refresh).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait PushKeystore: Send + Sync {
    /// Load the 32-byte raw SQLCipher DB key for `<account_did_hash>.db`.
    fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError>;

    /// Load a serialized OpenMLS signature keypair from platform Keychain/Keystore if stored externally.
    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError>;

    /// Return a non-expired cached `chat-dpop` / service-auth JWT, or `None` if missing/expired (`I10`).
    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError>;
}

/// Synchronous blocking HTTP transport for NSE / FCM catch-up (`G1` — zero Tokio runtime).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait PushFetchTransport: Send + Sync {
    /// Fetch sequenced `chat.entries` with `seq > after_seq` (and optional `metadata_snapshots`).
    fn fetch_missing_entries(
        &self,
        conversation_id: String,
        after_seq: i64,
        chat_dpop_token: String,
    ) -> Result<PushFetchBundle, MLSError>;

    /// Fetch DID-rooted authorized ATProto chat device keys for `did` (`I4` / `F-02`).
    fn get_authorized_device_keys(
        &self,
        did: String,
        chat_dpop_token: Option<String>,
    ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError>;
}

struct PushKeychainAdapter {
    keystore: Arc<dyn PushKeystore>,
}

#[async_trait::async_trait]
impl KeychainAccess for PushKeychainAdapter {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        self.keystore.load_signature_keypair(key)
    }

    async fn write(&self, _key: String, _value: Vec<u8>) -> Result<(), MLSError> {
        Ok(())
    }

    async fn delete(&self, _key: String) -> Result<(), MLSError> {
        Ok(())
    }
}

fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn resolve_push_db_path(storage_root: &Path, account_did_hash: &str) -> Result<PathBuf, MLSError> {
    if account_did_hash.len() != 64 || !account_did_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MLSError::invalid_input(
            "account_did_hash must be 64 hexadecimal characters (sha256(normalized_did))",
        ));
    }
    let normalized_hash = account_did_hash.to_ascii_lowercase();
    let filename = format!("{normalized_hash}.db");
    if storage_root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "catbird-mls")
    {
        Ok(storage_root.join(filename))
    } else {
        Ok(storage_root.join("catbird-mls").join(filename))
    }
}

pub(crate) fn root_did_from_credential_bytes(
    identity_bytes: &[u8],
) -> Result<(String, String), MLSError> {
    let identity_str = std::str::from_utf8(identity_bytes).map_err(|_| {
        MLSError::insufficient_permissions("I4/F-02: MLS leaf credential identity is not UTF-8")
    })?;
    let root_did = identity_str
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if !root_did.starts_with("did:") {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: MLS leaf credential `{identity_str}` does not start with a valid DID"
        )));
    }
    let device_id = identity_str
        .split_once('#')
        .map(|(_, dev)| dev.to_string())
        .unwrap_or_default();
    Ok((root_did, device_id))
}

pub(crate) fn extract_plaintext_body_and_verify_aad(
    decrypted_bytes: &[u8],
    aad_bytes: &[u8],
) -> Result<
    (
        String,
        String,
        Option<[u8; 32]>,
        Option<crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope>,
    ),
    MLSError,
> {
    crate::messaging::receive::extract_plaintext_body_and_verify_aad(decrypted_bytes, aad_bytes)
}

pub(crate) fn parse_canonical_message_body(
    payload_bytes: &[u8],
) -> Result<(String, String), MLSError> {
    crate::messaging::receive::parse_canonical_message_body(payload_bytes)
}

fn deserialize_cbor_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> serde::de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a CBOR byte string")
        }
        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
            Ok(bytes.to_vec())
        }
        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(bytes)
        }
    }
    deserializer.deserialize_bytes(Bytes)
}

fn authenticated_application_message_id(
    aad: &[u8],
    conversation_id: &str,
    _fixture_message_id: &str,
) -> Result<String, MLSError> {
    if let Some(cbor) = aad.strip_prefix(b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0") {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ApplicationIdentity {
            #[serde(deserialize_with = "deserialize_cbor_bytes")]
            conversation_id: Vec<u8>,
            #[serde(deserialize_with = "deserialize_cbor_bytes")]
            message_id: Vec<u8>,
        }
        let identity: ApplicationIdentity = serde_ipld_dagcbor::from_slice(cbor).map_err(|e| {
            MLSError::Cryptography(format!("invalid application identity AAD: {e}"))
        })?;
        let cid = uuid::Uuid::parse_str(conversation_id).map_err(|e| {
            MLSError::Cryptography(format!("invalid application conversation UUID: {e}"))
        })?;
        let message_id = uuid::Uuid::from_slice(&identity.message_id).map_err(|e| {
            MLSError::Cryptography(format!("invalid application message UUID: {e}"))
        })?;
        if identity.conversation_id.as_slice() != cid.as_bytes()
            || message_id.get_version_num() != 4
        {
            return Err(MLSError::Cryptography(
                "application AAD conversation/message identity mismatch".into(),
            ));
        }
        return Ok(message_id.to_string());
    }
    #[cfg(any(test, feature = "sim", feature = "test-utils"))]
    if crate::messaging::receive::PrivateMessageAadEnvelope::from_aad_bytes(aad).is_ok() {
        // Standalone MLS fixtures predate the canonical transport; never a production fallback.
        return Ok(_fixture_message_id.to_owned());
    }
    Err(MLSError::Cryptography(
        "push application is missing canonical authenticated identity".into(),
    ))
}

pub(crate) fn verify_leaf_binding_i4(
    identity_bytes: &[u8],
    signature_key: &[u8],
    owner_did: Option<&str>,
    authorized_map: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
) -> Result<(String, String), MLSError> {
    let (root_did, device_id) = root_did_from_credential_bytes(identity_bytes)?;
    let _ = owner_did;

    let Some(keys_for_did) = authorized_map.get(&root_did) else {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: no verified ATProto device keys found for sender DID `{root_did}`"
        )));
    };

    let matched = keys_for_did.iter().any(|k| {
        k.did == root_did
            && k.signature_public_key.as_slice() == signature_key
            && (device_id.is_empty() || k.device_id.is_empty() || k.device_id == device_id)
    });

    if !matched {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: unverified MLS leaf signature key for `{root_did}#{device_id}`"
        )));
    }
    Ok((root_did, device_id))
}

pub(crate) fn verify_staged_commit_i4(
    group: &MlsGroup,
    sender: &Sender,
    staged: &StagedCommit,
    owner_did: Option<&str>,
    authorized_map: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
) -> Result<(), MLSError> {
    if let Sender::Member(leaf_idx) = sender {
        let sender_member = group
            .members()
            .find(|m| m.index == *leaf_idx)
            .ok_or_else(|| {
                MLSError::insufficient_permissions("I4/F-02: Commit sender leaf missing from group")
            })?;
        verify_leaf_binding_i4(
            sender_member.credential.serialized_content(),
            &sender_member.signature_key,
            owner_did,
            authorized_map,
        )?;
    } else {
        return Err(MLSError::insufficient_permissions(
            "I4/F-02: external/non-member Commit rejected in push processor",
        ));
    }

    for queued in staged.add_proposals() {
        let ln = queued.add_proposal().key_package().leaf_node();
        verify_leaf_binding_i4(
            ln.credential().serialized_content(),
            ln.signature_key().as_slice(),
            owner_did,
            authorized_map,
        )?;
    }

    for queued in staged.update_proposals() {
        let ln = queued.update_proposal().leaf_node();
        let new_id = ln.credential().serialized_content();
        if let Sender::Member(leaf_idx) = queued.sender() {
            let old_member = group
                .members()
                .find(|m| m.index == *leaf_idx)
                .ok_or(MLSError::InvalidCommit)?;
            if old_member.credential.serialized_content() != new_id {
                return Err(MLSError::InvalidCommit);
            }
        } else {
            return Err(MLSError::InvalidCommit);
        }
        verify_leaf_binding_i4(
            new_id,
            ln.signature_key().as_slice(),
            owner_did,
            authorized_map,
        )?;
    }

    if let Some(ln) = staged.update_path_leaf_node() {
        verify_leaf_binding_i4(
            ln.credential().serialized_content(),
            ln.signature_key().as_slice(),
            owner_did,
            authorized_map,
        )?;
    }

    Ok(())
}

fn fetched_entry_kind_matches(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    let fragment = expected.rsplit('#').next().unwrap_or(expected);
    actual == fragment
        || fragment.strip_suffix("Entry") == Some(actual)
        || (expected == crate::chat_v2::wire::APPLICATION_ENTRY_KIND
            && matches!(actual, "application_message" | "applicationMessage"))
}

struct VerifiedPushCommit {
    kind: SignedMutationKind,
    body: Value,
    next: Value,
    actor_is_own: bool,
}

const FOREGROUND_SYNC_REQUIRED: &str = "NseForegroundSyncRequired";

fn foreground_sync_required() -> MLSError {
    MLSError::InvalidState(FOREGROUND_SYNC_REQUIRED.into())
}

struct VerifiedPushApplicationReceipt {
    receipt: Value,
    key: Vec<u8>,
    sender_did: String,
    sender_device_id: String,
}

fn verify_push_application_receipt(
    tx: &SqlTx<'_>,
    entry: &FetchedPushEntry,
    conversation: &ConversationRow,
) -> Result<VerifiedPushApplicationReceipt, MLSError> {
    let receipt: Value =
        serde_json::from_slice(entry.sequencer_receipt.as_deref().ok_or_else(|| {
            MLSError::Cryptography("push application missing sequencerReceipt".into())
        })?)
        .map_err(|error| {
            MLSError::Cryptography(format!("push application sequencerReceipt JSON: {error}"))
        })?;
    let kid = chat_wire::sequencer_receipt_kid(&conversation.sequencer_did, &receipt)?;
    let did_document = tx
        .get_account_meta(&format!("did_doc:{}", conversation.sequencer_did))?
        .ok_or_else(|| MLSError::Cryptography("push sequencer key is not stored locally".into()))?;
    let key = chat_wire::decode_p256_sec1_from_did_doc(
        did_document.as_bytes(),
        &conversation.sequencer_did,
        kid,
    )?;
    let verified = chat_wire::verify_pruned_application_receipt(
        &receipt,
        &key,
        &conversation.sequencer_did,
        &conversation.conversation_id,
        &conversation.group_id,
        &entry.entry_id,
        entry.seq,
    )?;
    if verified.generation != conversation.generation
        || (!entry.sender_did.is_empty() && entry.sender_did != verified.sender_did)
    {
        return Err(MLSError::Cryptography(
            "push application receipt generation or sender mismatch".into(),
        ));
    }
    Ok(VerifiedPushApplicationReceipt {
        receipt,
        key,
        sender_did: verified.sender_did,
        sender_device_id: verified.sender_device_id,
    })
}

/// The `sendCounter` of an application entry's signed request, when the request verifies under
/// the sender's MLS leaf key and names exactly this sender device, generation and epoch.
fn verified_push_send_counter(
    entry: &FetchedPushEntry,
    leaf_key: &[u8],
    sender_did: &str,
    sender_device_id: &str,
    generation: i64,
    epoch: i64,
) -> Option<u64> {
    let signed: Value = serde_json::from_slice(entry.signed_request.as_deref()?).ok()?;
    let body = chat_wire::verify_signed_mutation_body(
        &signed,
        SignedMutationKind::ApplicationSend,
        leaf_key,
    )
    .ok()?;
    let binds = body["actorDid"].as_str() == Some(sender_did)
        && body["actorDeviceId"].as_str() == Some(sender_device_id)
        && body["prior"]["generation"].as_i64() == Some(generation)
        && body["prior"]["epoch"].as_i64() == Some(epoch);
    binds.then(|| body["sendCounter"].as_u64()).flatten()
}

#[allow(clippy::too_many_arguments)]
fn verify_push_commit_control<P: OpenMlsProvider>(
    tx: &SqlTx<'_>,
    entry: &FetchedPushEntry,
    conversation: &ConversationRow,
    group: &MlsGroup,
    provider: &P,
    owner_did: Option<&str>,
    authorized_keys: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
) -> Result<VerifiedPushCommit, MLSError> {
    let signed_request: Value = serde_json::from_slice(
        entry
            .signed_request
            .as_deref()
            .ok_or_else(|| MLSError::Cryptography("push control missing signedRequest".into()))?,
    )
    .map_err(|e| MLSError::Cryptography(format!("push control signedRequest JSON: {e}")))?;
    let kind = signed_request
        .pointer("/body/$type")
        .and_then(Value::as_str)
        .and_then(SignedMutationKind::from_type_id)
        .filter(|kind| {
            matches!(
                kind,
                SignedMutationKind::CommitTransition
                    | SignedMutationKind::LeafRecoveryFulfillment
                    | SignedMutationKind::LeaveCommitFulfillment
            )
        })
        .ok_or_else(|| MLSError::Cryptography("push control is not a Commit transition".into()))?;
    let expected_kind = chat_wire::entry_kind_of(kind)
        .ok_or_else(|| MLSError::Cryptography("push control has no entry kind".into()))?;
    if !fetched_entry_kind_matches(&entry.entry_kind, expected_kind) {
        return Err(MLSError::Cryptography(
            "push control entry kind differs from its signed body".into(),
        ));
    }

    let unverified_body = &signed_request["body"];
    let actor_did = unverified_body["actorDid"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("push control missing actorDid".into()))?;
    let actor_device_id = unverified_body["actorDeviceId"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("push control missing actorDeviceId".into()))?;
    let actor_member = group
        .members()
        .find(|member| {
            root_did_from_credential_bytes(member.credential.serialized_content())
                .is_ok_and(|(did, device)| did == actor_did && device == actor_device_id)
        })
        .ok_or_else(|| {
            MLSError::insufficient_permissions(
                "I4/F-02: push control actor is not a current MLS leaf",
            )
        })?;
    verify_leaf_binding_i4(
        actor_member.credential.serialized_content(),
        &actor_member.signature_key,
        owner_did,
        authorized_keys,
    )?;
    let (body, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
        &signed_request,
        kind,
        &actor_member.signature_key,
    )?;
    let commit_bytes = body
        .pointer("/commit/bytes")
        .ok_or_else(|| MLSError::Cryptography("push Commit body missing bytes".into()))
        .and_then(chat_wire::json_bytes)?;
    if commit_bytes != entry.mls_bytes {
        return Err(MLSError::Cryptography(
            "push Commit bytes differ from signedRequest".into(),
        ));
    }

    let prior = chat_wire::canonicalize_wire_coordinate(
        &body["prior"],
        Some(&conversation.conversation_id),
    )?;
    let next = chat_wire::canonicalize_wire_coordinate(
        &body["next"],
        Some(&conversation.conversation_id),
    )?;
    let stepped_state_version = prior["stateVersion"]
        .as_i64()
        .and_then(|version| version.checked_add(1));
    if prior["generation"].as_i64() != Some(conversation.generation)
        || next["generation"].as_i64() != Some(conversation.generation)
        || next["stateVersion"].as_i64() != stepped_state_version
        || next["epoch"].as_u64() != group.epoch().as_u64().checked_add(1)
        || prior["lifecycle"].as_str() != Some("active")
        || next["lifecycle"].as_str() != Some("active")
    {
        return Err(MLSError::Cryptography(
            "push Commit does not step the local conversation coordinate".into(),
        ));
    }
    chat_wire::require_coordinate_names_group(&prior, group, provider)?;

    let receipt: Value =
        serde_json::from_slice(entry.sequencer_receipt.as_deref().ok_or_else(|| {
            MLSError::Cryptography("push control missing sequencerReceipt".into())
        })?)
        .map_err(|e| MLSError::Cryptography(format!("push control sequencerReceipt JSON: {e}")))?;
    let kid = chat_wire::sequencer_receipt_kid(&conversation.sequencer_did, &receipt)?;
    let did_document = tx
        .get_account_meta(&format!("did_doc:{}", conversation.sequencer_did))?
        .ok_or_else(|| MLSError::Cryptography("push sequencer key is not stored locally".into()))?;
    let receipt_key = chat_wire::decode_p256_sec1_from_did_doc(
        did_document.as_bytes(),
        &conversation.sequencer_did,
        kid,
    )?;
    verify_control_entry_receipt_with_key(
        &conversation.sequencer_did,
        &conversation.conversation_id,
        &entry.entry_id,
        entry.seq,
        &receipt,
        &body,
        &request_digest,
        &receipt_key,
        None,
    )?;

    let actor_is_own = group.own_leaf_node().is_some_and(|own| {
        own.credential().serialized_content() == actor_member.credential.serialized_content()
            && own.signature_key().as_slice() == actor_member.signature_key.as_slice()
    });
    Ok(VerifiedPushCommit {
        kind,
        body,
        next,
        actor_is_own,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_verified_push_commit(
    tx: &SqlTx<'_>,
    keychain: Arc<dyn KeychainAccess>,
    hooks: &crate::sim_hooks::SimClientHooks,
    conversation: &ConversationRow,
    entry: &FetchedPushEntry,
    verified: &VerifiedPushCommit,
    owner_did: Option<&str>,
    authorized_keys: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
) -> Result<(KvWriteBatch, bool, u64), MLSError> {
    let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
    let storage = OpenMlsKvStorage::with_keychain(&overlay, keychain);
    let provider = hooks.openmls_provider(storage);
    if verified.actor_is_own {
        let transition_id = verified.body["transitionId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("own push Commit missing transitionId".into()))?;
        let raw = tx
            .get_pending_op("commit_transition", transition_id)?
            .ok_or_else(|| {
                MLSError::Cryptography("own push Commit has no pending journal".into())
            })?;
        let pending: chat_wire::PendingCommitTransition = serde_json::from_str(&raw)
            .map_err(|e| MLSError::Internal(format!("parse pending push Commit: {e}")))?;
        let commit_sha256: [u8; 32] = Sha256::digest(&entry.mls_bytes).into();
        let pending_prior = chat_wire::canonicalize_wire_coordinate(
            &pending.prior,
            Some(&conversation.conversation_id),
        )?;
        let pending_next = chat_wire::canonicalize_wire_coordinate(
            &pending.next,
            Some(&conversation.conversation_id),
        )?;
        if pending.conversation_id != conversation.conversation_id
            || pending.transition_id != transition_id
            || pending.commit_sha256 != commit_sha256
            || pending_next != verified.next
        {
            return Err(MLSError::Cryptography(
                "own push Commit differs from pending journal".into(),
            ));
        }
        let current_group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&conversation.group_id),
        )
        .map_err(|e| MLSError::Internal(format!("load pending push group: {e:?}")))?
        .ok_or_else(|| MLSError::GroupNotFound {
            message: format!(
                "MlsGroup missing for conversation {}",
                conversation.conversation_id
            ),
        })?;
        chat_wire::require_coordinate_names_group(&pending_prior, &current_group, &provider)?;
        pending.kv_batch.apply(&overlay)?;
        let group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&conversation.group_id),
        )
        .map_err(|e| MLSError::Internal(format!("load applied pending push group: {e:?}")))?
        .ok_or_else(|| MLSError::GroupNotFound {
            message: format!(
                "MlsGroup missing after pending Commit for conversation {}",
                conversation.conversation_id
            ),
        })?;
        chat_wire::require_coordinate_names_group(&verified.next, &group, &provider)?;
        return Ok((pending.kv_batch, false, group.epoch().as_u64()));
    }
    let mut group = MlsGroup::load(
        provider.storage(),
        &GroupId::from_slice(&conversation.group_id),
    )
    .map_err(|e| MLSError::Internal(format!("load staged push group: {e:?}")))?
    .ok_or_else(|| MLSError::GroupNotFound {
        message: format!(
            "MlsGroup missing for conversation {}",
            conversation.conversation_id
        ),
    })?;
    let protocol_message = MlsMessageIn::tls_deserialize_exact(&entry.mls_bytes)
        .map_err(|e| MLSError::Cryptography(format!("deserialize push Commit: {e:?}")))?
        .try_into_protocol_message()
        .map_err(|e| MLSError::Cryptography(format!("push Commit protocol message: {e:?}")))?;
    if protocol_message.epoch() != group.epoch() {
        return Err(MLSError::Cryptography(
            "push Commit is not for the local MLS epoch".into(),
        ));
    }
    let processed = group
        .process_message(&provider, protocol_message)
        .map_err(|e| MLSError::Cryptography(format!("process push Commit: {e:?}")))?;
    let sender = processed.sender().clone();
    let actor_did = verified.body["actorDid"].as_str().unwrap_or_default();
    let actor_device_id = verified.body["actorDeviceId"].as_str().unwrap_or_default();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(MLSError::Cryptography(
            "push control is not the authenticated Commit kind".into(),
        ));
    };
    let Sender::Member(sender_index) = sender else {
        return Err(MLSError::insufficient_permissions(
            "I4/F-02: push Commit sender is not a member",
        ));
    };
    let sender_member = group
        .members()
        .find(|member| member.index == sender_index)
        .ok_or_else(|| {
            MLSError::insufficient_permissions("I4/F-02: push Commit sender leaf is missing")
        })?;
    let (sender_did, sender_device_id) =
        root_did_from_credential_bytes(sender_member.credential.serialized_content())?;
    if sender_did != actor_did || sender_device_id != actor_device_id {
        return Err(MLSError::Cryptography(
            "push Commit MLS sender differs from signed actor".into(),
        ));
    }
    verify_staged_commit_i4(
        &group,
        &Sender::Member(sender_index),
        &staged,
        owner_did,
        authorized_keys,
    )?;
    let removed_self = staged.self_removed();
    group
        .merge_staged_commit(&provider, *staged)
        .map_err(|e| MLSError::Cryptography(format!("merge push Commit: {e:?}")))?;
    chat_wire::require_coordinate_names_group(&verified.next, &group, &provider)?;
    Ok((overlay.into_batch(), removed_self, group.epoch().as_u64()))
}

#[cfg(target_vendor = "apple")]
fn post_darwin_nse_commit_notification() {
    use std::ffi::CString;
    extern "C" {
        fn notify_post(name: *const std::os::raw::c_char) -> u32;
    }
    if let Ok(c_name) = CString::new(DARWIN_NSE_DID_COMMIT_NOTIFICATION) {
        // SAFETY: `c_name` is a valid NUL-terminated C string for the duration of `notify_post`.
        unsafe {
            let _ = notify_post(c_name.as_ptr());
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
fn post_darwin_nse_commit_notification() {}

fn is_verified_sibling_sender(
    owner_did: Option<&str>,
    own_device_id: Option<&str>,
    account_did_hash: &str,
    verified_sender_did: &str,
    verified_device_id: &str,
) -> bool {
    if verified_sender_did.trim().is_empty() || verified_device_id.trim().is_empty() {
        return false;
    }
    let Ok(canonical_sender) = crate::client::normalize_account_did(verified_sender_did) else {
        return false;
    };
    let matches_account = if let Some(owner) = owner_did {
        crate::client::normalize_account_did(owner)
            .is_ok_and(|canonical_owner| canonical_owner == canonical_sender)
    } else {
        crate::client::account_did_hash_hex(&canonical_sender)
            .is_ok_and(|hash| hash.eq_ignore_ascii_case(account_did_hash))
    };
    if !matches_account {
        return false;
    }
    match own_device_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(own_id) => !own_id.eq_ignore_ascii_case(verified_device_id.trim()),
        None => true,
    }
}

fn build_generic_fallback_preview(
    wake: &PushWakePayload,
    group_title: Option<String>,
) -> NotificationPreview {
    NotificationPreview {
        message_id: wake.message_id.clone(),
        conversation_id: wake.conversation_id.clone(),
        sender_did: wake.sender_did.clone().unwrap_or_default(),
        sender_display_name: None,
        group_title,
        body: "New encrypted message".to_string(),
        epoch: 0,
        seq: wake.entry_seq,
        from_cache: false,
        fallback_generic: true,
        receipt_verified: false,
        darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
        is_own_sibling_sender: false,
    }
}

/// Shared synchronous push processor for iOS `NotificationServiceExtension` and Android FCM (`Spec §6.2`).
pub fn process_push_notification(
    storage_root: &Path,
    account_did_hash: &str,
    keystore: Arc<dyn PushKeystore>,
    transport: Option<Arc<dyn PushFetchTransport>>,
    wake: &PushWakePayload,
) -> Result<NotificationPreview, MLSError> {
    process_push_notification_with_hooks(
        storage_root,
        account_did_hash,
        keystore,
        transport,
        wake,
        &crate::sim_hooks::SimClientHooks::system_default(),
    )
}

/// Deterministic simulation entry point for [`process_push_notification`], routing wall-clock
/// timestamps and OpenMLS provider randomness through [`crate::sim_hooks::SimClientHooks`].
pub fn process_push_notification_with_hooks(
    storage_root: &Path,
    account_did_hash: &str,
    keystore: Arc<dyn PushKeystore>,
    transport: Option<Arc<dyn PushFetchTransport>>,
    wake: &PushWakePayload,
    hooks: &crate::sim_hooks::SimClientHooks,
) -> Result<NotificationPreview, MLSError> {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;

    if !wake.recipient_account_hash.is_empty()
        && !wake
            .recipient_account_hash
            .eq_ignore_ascii_case(account_did_hash)
    {
        return Err(MLSError::invalid_input(
            "wake.recipient_account_hash does not match target account_did_hash",
        ));
    }

    // I12: enforce 2,200-byte inline push ciphertext cap strictly before touching crypto.
    if let Some(ref ct) = wake.inline_ciphertext {
        if !should_inline_push_ciphertext(ct) {
            return Err(MLSError::invalid_input(format!(
                "I12 violation: inline push ciphertext ({} bytes) exceeds INLINE_CIPHERTEXT_MAX_BYTES ({INLINE_CIPHERTEXT_MAX_BYTES})",
                ct.len()
            )));
        }
    }
    let supplied_message_id = wake.message_id.trim();
    let legacy_missing_id = supplied_message_id
        .strip_prefix("msg-")
        .and_then(|seq| seq.parse::<i64>().ok())
        == Some(wake.entry_seq);
    let supplied_message_id =
        (!supplied_message_id.is_empty() && !legacy_missing_id).then_some(supplied_message_id);

    let db_path = resolve_push_db_path(storage_root, account_did_hash)?;
    if !db_path.exists() {
        return Ok(build_generic_fallback_preview(wake, None));
    }

    let raw_key_vec = Zeroizing::new(keystore.load_db_key(account_did_hash.to_ascii_lowercase())?);
    let db_key_32: Zeroizing<[u8; 32]> =
        Zeroizing::new(<[u8; 32]>::try_from(raw_key_vec.as_slice()).map_err(|_| {
            MLSError::invalid_input("PushKeystore::load_db_key must return exactly 32 bytes")
        })?);

    let db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::PushExtension)?;
    let keychain_adapter: Arc<dyn KeychainAccess> = Arc::new(PushKeychainAdapter {
        keystore: Arc::clone(&keystore),
    });
    db.set_keychain(Arc::clone(&keychain_adapter));

    // -------------------------------------------------------------------------
    // Phase 1: Read-only pre-flight (no write lock, lazy single-group load).
    // -------------------------------------------------------------------------
    struct PreflightState {
        cached_preview: Option<NotificationPreview>,
        convo: Option<ConversationRow>,
        cached_title: Option<String>,
        owner_did: Option<String>,
        own_device_id: Option<String>,
        authorized_keys: HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
        authorized_key_versions: HashMap<String, (String, i64)>,
        sender_display_name: Option<String>,
    }

    let preflight = db.read_tx(|tx| {
        let owner_did = tx.get_account_meta("owner_did")?;
        let own_device_id = tx.get_account_meta("device_id")?;
        let convo = tx.get_conversation(&wake.conversation_id)?;
        let cached_meta = tx.get_group_metadata(&wake.conversation_id)?;
        let cached_title = cached_meta
            .as_ref()
            .and_then(|m| m.title.clone())
            .or_else(|| convo.as_ref().and_then(|c| c.title.clone()));

        let existing_msg: Option<(String, String, String, String, i64, i64)> = tx
            .conn()
            .query_row(
                "SELECT message_id, sender_did, sender_device_id, plaintext_json, epoch, seq \
                 FROM messages WHERE conversation_id = ?1 AND seq = ?2;",
                rusqlite::params![wake.conversation_id, wake.entry_seq],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| MLSError::Internal(format!("query cached push message: {e}")))?;

        if let (Some(supplied), Some((canonical, ..))) =
            (supplied_message_id, existing_msg.as_ref())
        {
            if supplied != canonical.as_str() {
                return Err(MLSError::Cryptography(
                    "push wake messageId differs from authenticated MLS AAD".into(),
                ));
            }
        }

        if let Some((message_id, sender_did, sender_device_id, plaintext_json, epoch, seq)) =
            existing_msg
        {
            let (body, _) = parse_canonical_message_body(plaintext_json.as_bytes())?;
            let display_name: Option<String> = tx
                .conn()
                .query_row(
                    "SELECT display_name FROM participant_profiles WHERE did = ?1;",
                    [&sender_did],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| MLSError::Internal(format!("query sender profile: {e}")))?
                .flatten();
            let is_own_sibling_sender = is_verified_sibling_sender(
                owner_did.as_deref(),
                own_device_id.as_deref(),
                account_did_hash,
                &sender_did,
                &sender_device_id,
            );
            let receipt_verified =
                has_persisted_verified_receipt(tx.conn(), &wake.conversation_id, &message_id, seq)?;

            return Ok(PreflightState {
                cached_preview: Some(NotificationPreview {
                    message_id,
                    conversation_id: wake.conversation_id.clone(),
                    sender_did,
                    sender_display_name: display_name,
                    group_title: cached_title,
                    body,
                    epoch,
                    seq,
                    from_cache: true,
                    fallback_generic: false,
                    receipt_verified,
                    darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
                    is_own_sibling_sender,
                }),
                convo: None,
                cached_title: None,
                owner_did,
                own_device_id,
                authorized_keys: HashMap::new(),
                authorized_key_versions: HashMap::new(),
                sender_display_name: None,
            });
        }

        let mut authorized_keys = HashMap::new();
        let mut authorized_key_versions = HashMap::new();
        {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT key, value_json, updated_at_ms FROM account_meta \
                     WHERE key LIKE 'authorized_device_keys:%';",
                )
                .map_err(|e| MLSError::Internal(format!("prepare authorized_device_keys: {e}")))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| MLSError::Internal(format!("query authorized_device_keys: {e}")))?;
            for row in rows {
                let (k, v, updated_at_ms) = row.map_err(|e| MLSError::Internal(e.to_string()))?;
                if let Some(did) = k.strip_prefix("authorized_device_keys:") {
                    authorized_key_versions.insert(did.to_string(), (v.clone(), updated_at_ms));
                    if let Ok(parsed) = serde_json::from_str::<Vec<AuthorizedPeerDeviceKey>>(&v) {
                        authorized_keys.insert(did.to_string(), parsed);
                    }
                }
            }
        }

        let sender_display_name = if let Some(ref s_did) = wake.sender_did {
            tx.conn()
                .query_row(
                    "SELECT display_name FROM participant_profiles WHERE did = ?1;",
                    [s_did],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| MLSError::Internal(format!("query sender display_name: {e}")))?
                .flatten()
        } else {
            None
        };

        Ok(PreflightState {
            cached_preview: None,
            convo,
            cached_title,
            owner_did,
            own_device_id,
            authorized_keys,
            authorized_key_versions,
            sender_display_name,
        })
    })?;

    if let Some(cached) = preflight.cached_preview {
        let _ = db.prepare_for_background();
        return Ok(cached);
    }

    let Some(convo) = preflight.convo else {
        let _ = db.prepare_for_background();
        return Ok(build_generic_fallback_preview(wake, None));
    };

    // A wake carries no signed I13 receipt. Fetch the sequenced entry even when ciphertext was
    // inlined so the NSE cannot advance a cursor from wake/server metadata alone. When offline,
    // a contiguous inline application may still produce a verified preview, but its transaction
    // is rolled back because the wake cannot authorize a durable sequence advance.
    // -------------------------------------------------------------------------
    // Phase 2: Network fetch STRICTLY OUTSIDE any SQLite write transaction (I6, I10).
    // -------------------------------------------------------------------------
    let chat_dpop_token = if transport.is_some() {
        keystore
            .load_cached_chat_dpop_token(account_did_hash.to_ascii_lowercase())?
            .filter(|token| !token.trim().is_empty())
    } else {
        None
    };
    let network = transport.as_ref().zip(chat_dpop_token.as_ref());
    // The wake a gateway delivers names no message id, only the conversation, generation and
    // sequence. That is enough: a canonical application message carries its own id in its
    // authenticated data, which is where the preview's id comes from. An id the wake does
    // supply is still cross-checked against it below.
    let inline_preview = if !wake.fetch_required
        && fetched_entry_kind_matches(&wake.kind, crate::chat_v2::wire::APPLICATION_ENTRY_KIND)
    {
        wake.inline_ciphertext
            .as_ref()
            .map(|ciphertext| (supplied_message_id.unwrap_or_default(), ciphertext))
    } else {
        None
    };
    let mut preview_only = false;
    let inline_bundle = |message_id: &str, inline_ciphertext: &[u8]| PushFetchBundle {
        entries: vec![FetchedPushEntry {
            entry_id: message_id.to_owned(),
            seq: wake.entry_seq,
            epoch: convo.epoch,
            entry_kind: crate::chat_v2::wire::APPLICATION_ENTRY_KIND.to_owned(),
            sender_did: wake.sender_did.clone().unwrap_or_default(),
            mls_bytes: inline_ciphertext.to_vec(),
            signed_request: None,
            sequencer_receipt: None,
        }],
        metadata_snapshot: None,
        authorized_device_keys: Vec::new(),
    };
    let fetch_bundle = if let Some((net, token)) = network {
        match net.fetch_missing_entries(wake.conversation_id.clone(), convo.last_seq, token.clone())
        {
            Ok(bundle) => bundle,
            Err(error) => {
                let Some((message_id, inline_ciphertext)) = inline_preview else {
                    return Err(error);
                };
                preview_only = true;
                inline_bundle(message_id, inline_ciphertext)
            }
        }
    } else if let Some((message_id, inline_ciphertext)) = inline_preview {
        preview_only = true;
        inline_bundle(message_id, inline_ciphertext)
    } else {
        // I10: never refresh OAuth in NSE; render generic text cleanly.
        let _ = db.prepare_for_background();
        return Ok(build_generic_fallback_preview(wake, preflight.cached_title));
    };
    let mut authorized_keys = preflight.authorized_keys;
    let authorized_key_versions = preflight.authorized_key_versions;
    let mut dirty_authorized_keys = HashSet::new();
    for key in &fetch_bundle.authorized_device_keys {
        dirty_authorized_keys.insert(key.did.clone());
        authorized_keys
            .entry(key.did.clone())
            .or_default()
            .push(key.clone());
    }
    if let Some((net, token)) = network.filter(|_| !preview_only) {
        let mut candidate_dids: HashSet<String> = HashSet::new();
        if let Some(sender) = &wake.sender_did {
            candidate_dids.insert(sender.clone());
        }
        for entry in &fetch_bundle.entries {
            if !entry.sender_did.is_empty() {
                candidate_dids.insert(entry.sender_did.clone());
            }
        }
        for did in candidate_dids {
            if let std::collections::hash_map::Entry::Vacant(entry) = authorized_keys.entry(did) {
                let fetched_keys =
                    net.get_authorized_device_keys(entry.key().clone(), Some(token.clone()))?;
                if !fetched_keys.is_empty() {
                    dirty_authorized_keys.insert(entry.key().clone());
                    entry.insert(fetched_keys);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Phase 3: Atomic BEGIN IMMEDIATE write transaction (I7, I4, I13).
    // -------------------------------------------------------------------------
    let mut unsequenced_preview = None;
    let preview_res = db.write_tx(|tx| {
        let result = (|| {
        // Re-check inside BEGIN IMMEDIATE in case the foreground app already inserted this message.
        let concurrent_msg: Option<(String, String, String, String, i64, i64)> = tx
            .conn()
            .query_row(
                "SELECT conversation_id, sender_did, sender_device_id, plaintext_json, epoch, seq FROM messages \
                 WHERE message_id = ?1;",
                [&wake.message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| MLSError::Internal(format!("recheck message in write_tx: {e}")))?;

        let mut current_convo = tx
            .get_conversation(&wake.conversation_id)?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {} missing in write_tx", wake.conversation_id),
            })?;

        let mut resolved_title = tx
            .get_group_metadata(&wake.conversation_id)?
            .and_then(|m| m.title)
            .or_else(|| current_convo.title.clone());

        if let Some((
            conversation_id,
            sender_did,
            sender_device_id,
            plaintext_json,
            epoch,
            seq,
        )) = concurrent_msg
        {
            // The wake's ids are unauthenticated: a cached row answers only the exact entry.
            if conversation_id != wake.conversation_id || seq != wake.entry_seq {
                return Err(MLSError::Cryptography(
                    "push wake differs from the cached message's conversation or seq".into(),
                ));
            }
            let (body, _) = parse_canonical_message_body(plaintext_json.as_bytes())?;
            let is_own_sibling_sender = is_verified_sibling_sender(
                preflight.owner_did.as_deref(),
                preflight.own_device_id.as_deref(),
                account_did_hash,
                &sender_did,
                &sender_device_id,
            );
            let receipt_verified = has_persisted_verified_receipt(
                tx.conn(),
                &wake.conversation_id,
                &wake.message_id,
                seq,
            )?;
            return Ok(NotificationPreview {
                message_id: wake.message_id.clone(),
                conversation_id: wake.conversation_id.clone(),
                sender_did,
                sender_display_name: preflight.sender_display_name.clone(),
                group_title: resolved_title,
                body,
                epoch,
                seq,
                from_cache: true,
                fallback_generic: false,
                receipt_verified,
                darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
                is_own_sibling_sender,
            });
        }

        let now_ms = hooks.now_ms();

        // Write only fetched rows, and only if the row still matches preflight. A foreground
        // invalidation or replacement wins the race; the NSE must never resurrect its stale copy.
        for did in &dirty_authorized_keys {
            let Some(keys) = authorized_keys.get(did) else {
                continue;
            };
            let json = serde_json::to_string(keys)
                .map_err(|e| MLSError::Internal(format!("serialize authorized keys: {e}")))?;
            let key = format!("authorized_device_keys:{did}");
            match authorized_key_versions.get(did) {
                Some((expected_json, expected_updated_at_ms)) => {
                    tx.conn()
                        .execute(
                            "UPDATE account_meta SET value_json = ?1, updated_at_ms = ?2 \
                             WHERE key = ?3 AND value_json = ?4 AND updated_at_ms = ?5",
                            rusqlite::params![
                                json,
                                now_ms,
                                key,
                                expected_json,
                                expected_updated_at_ms
                            ],
                        )
                        .map_err(|e| {
                            MLSError::Internal(format!("CAS authorized device keys: {e}"))
                        })?;
                }
                None => {
                    tx.conn()
                        .execute(
                            "INSERT OR IGNORE INTO account_meta(key, value_json, updated_at_ms) \
                             VALUES(?1, ?2, ?3)",
                            rusqlite::params![key, json, now_ms],
                        )
                        .map_err(|e| {
                            MLSError::Internal(format!("insert authorized device keys: {e}"))
                        })?;
                }
            }
        }

        let storage = OpenMlsKvStorage::with_keychain(
            RusqliteKvBackend(tx.conn()),
            Arc::clone(&keychain_adapter),
        );
        let provider = hooks.openmls_provider(storage);
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&current_convo.group_id))
            .map_err(|e| MLSError::Internal(format!("MlsGroup::load failed: {e:?}")))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("MlsGroup missing for conversation {}", wake.conversation_id),
            })?;

        let mut entries_to_apply = fetch_bundle.entries;
        entries_to_apply.sort_by_key(|entry| entry.seq);
        let fetched_metadata_snapshot = fetch_bundle.metadata_snapshot;

        let mut target_decrypted: Option<(String, String, String, String, i64, i64)> = None;

        for entry in entries_to_apply {
            if entry.seq <= current_convo.last_seq {
                continue;
            }
            // Stored entries must be contiguous. A wake-only preview stores nothing (its
            // transaction is rolled back), so it may be ahead of what this device has synced:
            // otherwise only the first message since the app was last open could ever show
            // text. MLS decides whether it can be read: a later message of the same epoch
            // decrypts, one behind an unseen commit does not and falls back.
            if entry.seq != current_convo.last_seq.saturating_add(1) && !preview_only {
                return Err(foreground_sync_required());
            }
            let is_application = fetched_entry_kind_matches(
                &entry.entry_kind,
                crate::chat_v2::wire::APPLICATION_ENTRY_KIND,
            );
            let verified_application_receipt = if is_application && !preview_only {
                match verify_push_application_receipt(tx, &entry, &current_convo) {
                    Ok(receipt) => Some(receipt),
                    Err(_) => return Err(foreground_sync_required()),
                }
            } else {
                None
            };
            if !is_application {
                let verified = match verify_push_commit_control(
                    tx,
                    &entry,
                    &current_convo,
                    &group,
                    &provider,
                    preflight.owner_did.as_deref(),
                    &authorized_keys,
                ) {
                    Ok(verified) => verified,
                    Err(_) => {
                        tx.put_pending_op(
                            NSE_DEFERRED_CONTROL_OP,
                            &wake.conversation_id,
                            &entry.seq.to_string(),
                            now_ms,
                        )?;
                        break;
                    }
                };
                let (batch, removed_self, staged_epoch) = match stage_verified_push_commit(
                    tx,
                    Arc::clone(&keychain_adapter),
                    hooks,
                    &current_convo,
                    &entry,
                    &verified,
                    preflight.owner_did.as_deref(),
                    &authorized_keys,
                ) {
                    Ok(staged) => staged,
                    Err(_) => {
                        tx.put_pending_op(
                            NSE_DEFERRED_CONTROL_OP,
                            &wake.conversation_id,
                            &entry.seq.to_string(),
                            now_ms,
                        )?;
                        break;
                    }
                };
                batch.apply(&RusqliteKvBackend(tx.conn()))?;
                group = MlsGroup::load(
                    provider.storage(),
                    &GroupId::from_slice(&current_convo.group_id),
                )
                .map_err(|e| MLSError::Internal(format!("reload push Commit group: {e:?}")))?
                .ok_or_else(|| MLSError::GroupNotFound {
                    message: format!(
                        "MlsGroup missing after Commit for conversation {}",
                        wake.conversation_id
                    ),
                })?;
                if group.epoch().as_u64() != staged_epoch {
                    return Err(MLSError::Internal(
                        "staged push Commit did not persist its MLS epoch".into(),
                    ));
                }
                tx.put_account_meta(
                    &format!("conversation_coords:{}", wake.conversation_id),
                    &verified.next.to_string(),
                    now_ms,
                )?;
                apply_verified_roster_effects(
                    tx,
                    &wake.conversation_id,
                    verified.kind,
                    &verified.body,
                    now_ms,
                )?;
                tx.delete_account_meta(&chat_wire::leaf_recovery_authorization_key(
                    &wake.conversation_id,
                ))?;
                for did in chat_wire::removed_participants(verified.kind, &verified.body) {
                    tx.put_account_meta(
                        &chat_wire::invitation_closed_key(&wake.conversation_id, &did),
                        &entry.seq.to_string(),
                        now_ms,
                    )?;
                }
                if !removed_self {
                    crate::client::send_counter::advance_send_counter_epoch_chain(
                        tx,
                        &wake.conversation_id,
                        current_convo.generation,
                        current_convo.epoch,
                        staged_epoch as i64,
                        &crate::client::send_counter::group_leaf_devices(&group),
                        now_ms,
                    )?;
                }
                current_convo.epoch = staged_epoch as i64;
                current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                if verified.actor_is_own {
                    tx.delete_pending_op(
                        "commit_transition",
                        verified.body["transitionId"].as_str().unwrap_or_default(),
                    )?;
                }
                CatbirdMlsClient::prune_pending_commit_transitions(
                    tx,
                    &wake.conversation_id,
                    current_convo.generation,
                    current_convo.epoch,
                    removed_self,
                )?;
                if tx
                    .get_pending_op(NSE_DEFERRED_CONTROL_OP, &wake.conversation_id)?
                    .and_then(|seq| seq.parse::<i64>().ok())
                    .is_some_and(|seq| seq <= entry.seq)
                {
                    tx.delete_pending_op(NSE_DEFERRED_CONTROL_OP, &wake.conversation_id)?;
                }
                if removed_self {
                    break;
                }
                continue;
            }
            if entry.mls_bytes.is_empty() {
                // An `I14`-pruned entry carries nothing the NSE can verify: stop catching up
                // below it. Foreground sync verifies it under its own receipt.
                break;
            }

            let mls_in = MlsMessageIn::tls_deserialize_exact(&entry.mls_bytes).map_err(|e| {
                MLSError::InvalidInput {
                    message: format!("invalid MLS message bytes for {}: {e:?}", entry.entry_id),
                }
            })?;
            let protocol_msg = mls_in.try_into_protocol_message().map_err(|_| {
                MLSError::InvalidInput {
                    message: format!("expected ProtocolMessage for {}", entry.entry_id),
                }
            })?;

            let processed = group
                .process_message(&provider, protocol_msg)
                .map_err(|e| MLSError::Cryptography(format!("process_message failed: {e:?}")))?;
            let aad_bytes = processed.aad().to_vec();
            let msg_epoch = processed.epoch().as_u64() as i64;
            let sender = processed.sender().clone();

            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(_) => {
                    tx.put_pending_op(
                        NSE_DEFERRED_CONTROL_OP,
                        &wake.conversation_id,
                        &entry.seq.to_string(),
                        now_ms,
                    )?;
                    break;
                }
                ProcessedMessageContent::ApplicationMessage(app_msg) => {
                    let sender_member = match sender {
                        Sender::Member(leaf_idx) => group
                            .members()
                            .find(|m| m.index == leaf_idx)
                            .ok_or_else(|| {
                                MLSError::insufficient_permissions(
                                    "I4/F-02: message sender leaf missing from MLS group",
                                )
                            })?,
                        _ => {
                            return Err(MLSError::insufficient_permissions(
                                "I4/F-02: non-member ApplicationMessage sender rejected",
                            ));
                        }
                    };

                    let (verified_sender_did, verified_device_id) = verify_leaf_binding_i4(
                        sender_member.credential.serialized_content(),
                        &sender_member.signature_key,
                        preflight.owner_did.as_deref(),
                        &authorized_keys,
                    )?;

                    if !entry.sender_did.is_empty() && entry.sender_did != verified_sender_did {
                        return Err(MLSError::insufficient_permissions(format!(
                            "I4/F-02: envelope sender_did `{}` does not match verified MLS leaf DID `{verified_sender_did}`",
                            entry.sender_did
                        )));
                    }

                    let decrypted_bytes = app_msg.into_bytes();
                    let (body, plaintext_json, commitment_opt, original_sender_attestation) =
                        extract_plaintext_body_and_verify_aad(&decrypted_bytes, &aad_bytes)?;
                    let message_id = authenticated_application_message_id(
                        &aad_bytes, &wake.conversation_id, &entry.entry_id,
                    )?;
                    if entry.seq == wake.entry_seq
                        && supplied_message_id.is_some_and(|supplied| supplied != message_id)
                    {
                        return Err(MLSError::Cryptography(
                            "push wake messageId differs from authenticated MLS AAD".into(),
                        ));
                    }
                    let inner: crate::messaging::receive::PrivateMessagePlaintextEnvelope =
                        serde_json::from_slice(&decrypted_bytes).map_err(|e| {
                            MLSError::Cryptography(format!("missing authenticated push archive frame: {e}"))
                        })?;
                    let frame = std::str::from_utf8(&inner.canonical_payload_bytes)
                        .map_err(|e| MLSError::Cryptography(format!("push archive frame UTF-8: {e}")))?;
                    serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(frame)
                        .map_err(|e| MLSError::Cryptography(format!("push archive payload: {e}")))?;
                    let commitment = commitment_opt.ok_or_else(|| {
                        MLSError::Cryptography(
                            "push message has no authenticated archive commitment".into(),
                        )
                    })?;
                    let original_sender_attestation =
                        original_sender_attestation.ok_or_else(|| {
                            MLSError::Cryptography(
                                "push message has no original sender archive attestation".into(),
                            )
                        })?;
                    if original_sender_attestation.sender_did != verified_sender_did
                        || original_sender_attestation.sender_device_id != verified_device_id
                        || original_sender_attestation.sender_transport_public_key.as_slice()
                            != sender_member.signature_key.as_slice()
                    {
                        return Err(MLSError::Cryptography(
                            "push original sender attestation differs from MLS sender leaf".into(),
                        ));
                    }
                    original_sender_attestation.verify(
                        &wake.conversation_id,
                        &message_id,
                        &commitment,
                    )?;
                    if preview_only && crate::client::deletion_authority::suppress_local_frame(
                        tx, &wake.conversation_id, &verified_sender_did, &verified_device_id, entry.seq, None,
                    )? {
                        return Err(foreground_sync_required());
                    }
                    if preview_only {
                        target_decrypted = Some((
                            message_id,
                            verified_sender_did,
                            verified_device_id,
                            body,
                            msg_epoch,
                            entry.seq,
                        ));
                        continue;
                    }
                    let Some(verified_receipt) = verified_application_receipt.as_ref() else {
                        return Err(foreground_sync_required());
                    };
                    let Ok(bound_epoch) = u64::try_from(msg_epoch) else {
                        return Err(foreground_sync_required());
                    };
                    let Ok((receipt_seq, receipt_generation, _)) =
                        chat_wire::parse_and_verify_i13_sequencer_receipt(
                            &verified_receipt.receipt,
                            &verified_receipt.key,
                            &current_convo.sequencer_did,
                            &wake.conversation_id,
                            &current_convo.group_id,
                            bound_epoch,
                            &entry.entry_id,
                            &message_id,
                            &commitment,
                            Some(&original_sender_attestation),
                        )
                    else {
                        return Err(foreground_sync_required());
                    };
                    if i64::try_from(receipt_seq).ok() != Some(entry.seq)
                        || i64::try_from(receipt_generation).ok()
                            != Some(current_convo.generation)
                        || verified_receipt.sender_did != verified_sender_did
                        || verified_receipt.sender_device_id != verified_device_id
                    {
                        return Err(foreground_sync_required());
                    }
                    // Count this entry for its sender device in the transaction that applies
                    // it, so foreground completion does not count it again.
                    let own_device = preflight.owner_did.as_deref()
                        == Some(verified_sender_did.as_str())
                        && preflight.own_device_id.as_deref() == Some(verified_device_id.as_str());
                    let recorded_send_counter = if own_device {
                        None
                    } else {
                        let counter = verified_push_send_counter(
                            &entry,
                            sender_member.signature_key.as_slice(),
                            &verified_sender_did,
                            &verified_device_id,
                            current_convo.generation,
                            msg_epoch,
                        );
                        if crate::client::send_counter::record_peer_send_counter(
                            tx,
                            &wake.conversation_id,
                            current_convo.generation,
                            msg_epoch,
                            &verified_sender_did,
                            &verified_device_id,
                            counter,
                            entry.seq,
                            now_ms,
                        )
                        .is_err()
                        {
                            return Err(foreground_sync_required());
                        }
                        Some(counter.map_or_else(|| json!("unknown"), |counter| json!(counter)))
                    };
                    if crate::client::deletion_authority::suppress_local_frame(
                        tx, &wake.conversation_id, &verified_sender_did, &verified_device_id,
                        entry.seq, verified_receipt.receipt["issuedAtMs"].as_i64(),
                    )? {
                        // Foreground verifies the canonical receipt and advances the cursor.
                        return Err(foreground_sync_required());
                    }
                    // The full archive payload with the authenticated receive-time roster; the
                    // app enqueues it once the entry's I13 receipt verifies.
                    let evidence = crate::client::QueuedLabyrinthArchivePayload {
                        version: 1,
                        message_id: message_id.clone(),
                        conversation_id: wake.conversation_id.clone(),
                        group_id_hex: hex::encode(&current_convo.group_id),
                        epoch: msg_epoch,
                        expected_member_dids: group
                            .members()
                            .map(|m| {
                                root_did_from_credential_bytes(m.credential.serialized_content())
                                    .map(|(did, _)| did)
                            })
                            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
                            .into_iter()
                            .collect(),
                        seq: entry.seq,
                        sender_did: verified_sender_did.clone(),
                        sender_device_id: verified_device_id.clone(),
                        sequencer_did: current_convo.sequencer_did.clone(),
                        space_uri: current_convo.space_uri.clone(),
                        plaintext_json: plaintext_json.clone(),
                        labyrinth_frame_json: frame.to_owned(),
                        mls_ciphertext_b64: STANDARD.encode(&entry.mls_bytes),
                        frame_nonce_b64: Some(STANDARD.encode(inner.frame_nonce)),
                        sequencer_receipt_json: None,
                        original_sender_attestation_json: Some(
                            serde_json::to_string(&original_sender_attestation).map_err(
                                |error| {
                                    MLSError::Internal(format!(
                                        "serialize push original sender attestation: {error}"
                                    ))
                                },
                            )?,
                        ),
                        created_at_ms: now_ms,
                    };
                    crate::client::archive_policy::observe_frame_tighten_only(tx, &evidence)?;
                    let mut evidence = serde_json::to_value(&evidence)?;
                    // Relay receipts can have different entry IDs from the canonical receipt.
                    // The verified issue time remains available to enforce deletion during handoff.
                    evidence["nse_verified_issued_at_ms"] = verified_receipt.receipt["issuedAtMs"].clone();
                    if let Some(recorded) = recorded_send_counter {
                        evidence[chat_wire::NSE_SEND_COUNTER_RECORDED] = recorded;
                    }
                    tx.put_labyrinth_state(
                        &format!("native.message:{}:{message_id}", wake.conversation_id),
                        &serde_json::to_vec(&evidence)?, now_ms,
                    )?;
                    tx.put_labyrinth_state(
                        &format!("push.verified_receipt:{}:{message_id}", wake.conversation_id),
                        b"1",
                        now_ms,
                    )?;
                    // `entryId` is sequencer-local and federation may rebind it. The authenticated
                    // message ID is the cross-sequencer identity; foreground sync verifies the
                    // canonical sequencer's I13 receipt before archiving.
                    tx.put_pending_op(
                        NATIVE_ARCHIVE_RECEIPT_OP, &message_id,
                        &json!({
                            "conversation_id": wake.conversation_id, "seq": entry.seq,
                            "entry_id": null,
                        }).to_string(),
                        now_ms,
                    )?;

                    let is_own = preflight
                        .owner_did
                        .as_deref()
                        .is_some_and(|o| o == verified_sender_did);

                    tx.insert_message(&MessageRow {
                        message_id: message_id.clone(),
                        conversation_id: wake.conversation_id.clone(),
                        group_id: current_convo.group_id.clone(),
                        epoch: msg_epoch,
                        seq: entry.seq,
                        sender_did: verified_sender_did.clone(),
                        sender_device_id: verified_device_id.clone(),
                        plaintext_json,
                        created_at_ms: now_ms,
                        is_own,
                    })?;

                    tx.conn()
                        .execute(
                            "UPDATE messages SET archive_commitment = ?1 WHERE message_id = ?2;",
                            rusqlite::params![commitment.as_slice(), message_id],
                        )
                        .map_err(|e| {
                            MLSError::Internal(format!("persist archive_commitment: {e}"))
                        })?;

                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                    if !is_own {
                        current_convo.unread_count = current_convo.unread_count.saturating_add(1);
                    }

                    if entry.seq == wake.entry_seq
                        || supplied_message_id.is_some_and(|supplied| supplied == message_id)
                        || target_decrypted.is_none()
                    {
                        target_decrypted = Some((
                            message_id,
                            verified_sender_did,
                            verified_device_id,
                            body,
                            msg_epoch,
                            entry.seq,
                        ));
                    }
                }
                ProcessedMessageContent::ProposalMessage(_)
                | ProcessedMessageContent::ExternalJoinProposalMessage(_)
                | ProcessedMessageContent::OwnPendingCommit
                | ProcessedMessageContent::OwnPrivateMessage
                | ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                    tx.put_pending_op(
                        NSE_DEFERRED_CONTROL_OP,
                        &wake.conversation_id,
                        &entry.seq.to_string(),
                        now_ms,
                    )?;
                    break;
                }
            }
        }

        // Decrypt and cache fetched metadata_snapshots (1A) once group reaches target epoch.
        if let Some(snapshot) = fetched_metadata_snapshot.as_ref() {
            if group.epoch().as_u64() == snapshot.epoch as u64 {
                let nonce_12: [u8; 12] =
                    snapshot.nonce.as_slice().try_into().map_err(|_| {
                        MLSError::invalid_input("metadata_snapshot nonce must be 12 bytes")
                    })?;
                let meta_key = derive_metadata_key_from_group(
                    &mut group,
                    provider.crypto(),
                    provider.storage(),
                    &current_convo.group_id,
                    snapshot.epoch as u64,
                )
                .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;

                let decrypted_meta = decrypt_metadata_snapshot(
                    &meta_key,
                    &current_convo.group_id,
                    snapshot.epoch as u64,
                    snapshot.metadata_version as u64,
                    &nonce_12,
                    &snapshot.ciphertext,
                )
                .map_err(|e| MLSError::Cryptography(format!("decrypt metadata snapshot: {e}")))?;

                // A wake does not prove this snapshot was authored by a metadata transition.
                // Store it verbatim, but foreground signed-entry replay is the only authority
                // allowed to make a policy observation.
                crate::client::archive_policy::accept_snapshot(
                    tx,
                    &wake.conversation_id,
                    wake.entry_seq,
                    &decrypted_meta,
                    crate::client::archive_policy::SnapshotPolicyAuthority::ExactCarry,
                    now_ms,
                )?;

                let meta_json = serde_json::to_string(&decrypted_meta)
                    .map_err(|e| MLSError::Internal(format!("serialize GroupMetadataV1: {e}")))?;

                let title_opt = (!decrypted_meta.title.is_empty()).then(|| decrypted_meta.title.clone());
                let desc_opt =
                    (!decrypted_meta.description.is_empty()).then(|| decrypted_meta.description.clone());

                tx.upsert_group_metadata(&GroupMetadataRow {
                    conversation_id: wake.conversation_id.clone(),
                    metadata_version: snapshot.metadata_version,
                    epoch: snapshot.epoch,
                    title: title_opt.clone(),
                    description: desc_opt,
                    avatar_setter_did: decrypted_meta
                        .space_avatar
                        .as_ref()
                        .map(|a| a.setter_did.clone()),
                    avatar_blob_cid: decrypted_meta
                        .space_avatar
                        .as_ref()
                        .map(|a| a.space_blob_cid.clone()),
                    avatar_sym_key: decrypted_meta
                        .space_avatar
                        .as_ref()
                        .map(|a| a.sym_key.clone()),
                    avatar_sha256: decrypted_meta
                        .space_avatar
                        .as_ref()
                        .map(|a| a.sha256.clone()),
                    avatar_mime_type: decrypted_meta
                        .space_avatar
                        .as_ref()
                        .and_then(|a| a.mime_type.clone()),
                    metadata_json: meta_json,
                    updated_at_ms: now_ms,
                })?;

                if title_opt.is_some() {
                    current_convo.title = title_opt.clone();
                    resolved_title = title_opt;
                }
            }
        }

        current_convo.epoch = group.epoch().as_u64() as i64;
        current_convo.updated_at_ms = now_ms;
        tx.upsert_conversation(&current_convo)?;

        let Some((message_id, sender_did, sender_device_id, body, msg_epoch, msg_seq)) =
            target_decrypted
        else {
            return Ok(build_generic_fallback_preview(wake, resolved_title));
        };
        let is_own_sibling_sender = is_verified_sibling_sender(
            preflight.owner_did.as_deref(),
            preflight.own_device_id.as_deref(),
            account_did_hash,
            &sender_did,
            &sender_device_id,
        );

        Ok(NotificationPreview {
            message_id,
            conversation_id: wake.conversation_id.clone(),
            sender_did,
            sender_display_name: preflight.sender_display_name.clone(),
            group_title: resolved_title,
            body,
            epoch: msg_epoch,
            seq: msg_seq,
            from_cache: false,
            fallback_generic: false,
            receipt_verified: !preview_only,
            darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
            is_own_sibling_sender,
        })
        })();
        match (preview_only, result) {
            (true, Ok(preview)) => {
                unsequenced_preview = Some(preview);
                Err(foreground_sync_required())
            }
            (_, result) => result,
        }
    });

    // Phase 4: Always checkpoint passively and close the SQLite handle before returning (`I9`, `I11`).
    let _ = db.prepare_for_background();
    drop(db);

    let preview = match preview_res {
        Err(MLSError::InvalidState(code)) if code == FOREGROUND_SYNC_REQUIRED => {
            unsequenced_preview
                .unwrap_or_else(|| build_generic_fallback_preview(wake, preflight.cached_title))
        }
        result => result?,
    };
    if preview.receipt_verified && !preview.from_cache && !preview.fallback_generic {
        post_darwin_nse_commit_notification();
    }
    Ok(preview)
}

fn has_persisted_verified_receipt(
    conn: &rusqlite::Connection,
    conversation_id: &str,
    message_id: &str,
    seq: i64,
) -> Result<bool, MLSError> {
    let push_key = format!("push.verified_receipt:{conversation_id}:{message_id}");
    let has_push_marker: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM labyrinth_state WHERE state_key = ?1);",
            rusqlite::params![push_key],
            |row| row.get(0),
        )
        .map_err(|e| MLSError::Internal(format!("query push.verified_receipt: {e}")))?;
    if has_push_marker {
        return Ok(true);
    }

    let native_key = format!("native.message:{conversation_id}:{message_id}");
    let native_bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value_bytes FROM labyrinth_state WHERE state_key = ?1;",
            rusqlite::params![native_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| MLSError::Internal(format!("query native.message receipt: {e}")))?;
    if let Some(bytes) = native_bytes {
        if serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v["sequencer_receipt_json"].as_str().map(|s| !s.is_empty()))
            == Some(true)
        {
            return Ok(true);
        }
    }

    if seq >= 1 {
        let has_seq_rcpt: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sequencer_receipts WHERE conversation_id = ?1 AND seq = ?2);",
                rusqlite::params![conversation_id, seq],
                |row| row.get(0),
            )
            .map_err(|e| MLSError::Internal(format!("query sequencer_receipts: {e}")))?;
        if has_seq_rcpt {
            return Ok(true);
        }

        let queue_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload_bytes FROM labyrinth_queue WHERE conversation_id = ?1 AND seq = ?2 LIMIT 1;",
                rusqlite::params![conversation_id, seq],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| MLSError::Internal(format!("query labyrinth_queue receipt: {e}")))?;
        if let Some(bytes) = queue_bytes {
            if serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v["sequencer_receipt_json"].as_str().map(|s| !s.is_empty()))
                == Some(true)
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
pub(crate) mod test_exports {
    use super::*;

    pub(crate) fn fetched_entry_kind_matches_for_test(actual: &str, expected: &str) -> bool {
        super::fetched_entry_kind_matches(actual, expected)
    }

    pub(crate) fn verify_push_application_receipt_for_test(
        tx: &SqlTx<'_>,
        entry: &FetchedPushEntry,
        conversation: &ConversationRow,
    ) -> Result<(Value, Vec<u8>, String, String), MLSError> {
        let verified = super::verify_push_application_receipt(tx, entry, conversation)?;
        Ok((
            verified.receipt,
            verified.key,
            verified.sender_did,
            verified.sender_device_id,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_push_commit_control_for_test<P: OpenMlsProvider>(
        tx: &SqlTx<'_>,
        entry: &FetchedPushEntry,
        conversation: &ConversationRow,
        group: &MlsGroup,
        provider: &P,
        owner_did: Option<&str>,
        authorized_keys: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<(SignedMutationKind, Value, Value, bool), MLSError> {
        let verified = super::verify_push_commit_control(
            tx,
            entry,
            conversation,
            group,
            provider,
            owner_did,
            authorized_keys,
        )?;
        Ok((
            verified.kind,
            verified.body,
            verified.next,
            verified.actor_is_own,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_verified_push_commit_for_test(
        tx: &SqlTx<'_>,
        keychain: Arc<dyn KeychainAccess>,
        hooks: &crate::sim_hooks::SimClientHooks,
        conversation: &ConversationRow,
        entry: &FetchedPushEntry,
        kind: SignedMutationKind,
        body: Value,
        next: Value,
        actor_is_own: bool,
        owner_did: Option<&str>,
        authorized_keys: &HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<(KvWriteBatch, bool, u64), MLSError> {
        let verified = super::VerifiedPushCommit {
            kind,
            body,
            next,
            actor_is_own,
        };
        super::stage_verified_push_commit(
            tx,
            keychain,
            hooks,
            conversation,
            entry,
            &verified,
            owner_did,
            authorized_keys,
        )
    }
}
