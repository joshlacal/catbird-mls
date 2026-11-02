//! Synchronous, zero-Tokio push notification processor (`Spec §6.2`, `G1`).
//!
//! Enforces:
//! - `G1`: Zero Tokio worker pool; `OpenMode::PushExtension` (`cache_size = -512`, `mmap_size = 0`);
//!   lazy-loads **only** the target `MlsGroup` (never all groups or all KeyPackages).
//! - `I4` (`F-02`): Every `Commit` leaf addition/update and every `ApplicationMessage` sender leaf
//!   must match a DID-rooted authorized ATProto device signature key before merging or persisting.
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

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::MLSError;
use crate::keychain::KeychainAccess;
use crate::metadata::{decrypt_metadata_snapshot, derive_metadata_key_from_group};
use crate::storage::{
    ConversationRow, GroupMetadataRow, MessageRow, MlsAccountDb, OpenMlsKvStorage, OpenMode,
    RusqliteKvBackend,
};

use super::{
    should_inline_push_ciphertext, DARWIN_NSE_DID_COMMIT_NOTIFICATION, INLINE_CIPHERTEXT_MAX_BYTES,
};

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
) -> Result<(String, String, Option<[u8; 32]>), MLSError> {
    crate::messaging::receive::extract_plaintext_body_and_verify_aad(decrypted_bytes, aad_bytes)
}

pub(crate) fn parse_canonical_message_body(
    payload_bytes: &[u8],
) -> Result<(String, String), MLSError> {
    crate::messaging::receive::parse_canonical_message_body(payload_bytes)
}

fn extract_message_epoch_hint(mls_bytes: &[u8]) -> Option<u64> {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let mls_in = MlsMessageIn::tls_deserialize_exact(mls_bytes).ok()?;
    match mls_in.extract() {
        MlsMessageBodyIn::PrivateMessage(pm) => Some(pm.epoch().as_u64()),
        MlsMessageBodyIn::PublicMessage(pm) => Some(pm.epoch().as_u64()),
        _ => None,
    }
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
        darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
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
        local_group_epoch: u64,
        authorized_keys: HashMap<String, Vec<AuthorizedPeerDeviceKey>>,
        sender_display_name: Option<String>,
    }

    let preflight = db.read_tx(|tx| {
        let owner_did = tx.get_account_meta("owner_did")?;
        let convo = tx.get_conversation(&wake.conversation_id)?;
        let cached_meta = tx.get_group_metadata(&wake.conversation_id)?;
        let cached_title = cached_meta
            .as_ref()
            .and_then(|m| m.title.clone())
            .or_else(|| convo.as_ref().and_then(|c| c.title.clone()));

        let existing_msg: Option<(String, String, i64, i64)> = tx
            .conn()
            .query_row(
                "SELECT sender_did, plaintext_json, epoch, seq FROM messages WHERE message_id = ?1;",
                [&wake.message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| MLSError::Internal(format!("query cached push message: {e}")))?;

        if let Some((sender_did, plaintext_json, epoch, seq)) = existing_msg {
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

            return Ok(PreflightState {
                cached_preview: Some(NotificationPreview {
                    message_id: wake.message_id.clone(),
                    conversation_id: wake.conversation_id.clone(),
                    sender_did,
                    sender_display_name: display_name,
                    group_title: cached_title,
                    body,
                    epoch,
                    seq,
                    from_cache: true,
                    fallback_generic: false,
                    darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
                }),
                convo: None,
                cached_title: None,
                owner_did,
                local_group_epoch: 0,
                authorized_keys: HashMap::new(),
                sender_display_name: None,
            });
        }

        let mut local_group_epoch = 0u64;
        if let Some(ref c) = convo {
            let storage = OpenMlsKvStorage::with_keychain(
                RusqliteKvBackend(tx.conn()),
                Arc::clone(&keychain_adapter),
            );
            if let Some(group) = MlsGroup::load(&storage, &GroupId::from_slice(&c.group_id))
                .map_err(|e| MLSError::Internal(format!("load single target MlsGroup: {e:?}")))?
            {
                local_group_epoch = group.epoch().as_u64();
            }
        }

        let mut authorized_keys = HashMap::new();
        {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT key, value_json FROM account_meta WHERE key LIKE 'authorized_device_keys:%';",
                )
                .map_err(|e| MLSError::Internal(format!("prepare authorized_device_keys: {e}")))?;
            let rows = stmt
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                .map_err(|e| MLSError::Internal(format!("query authorized_device_keys: {e}")))?;
            for row in rows {
                let (k, v) = row.map_err(|e| MLSError::Internal(e.to_string()))?;
                if let Some(did) = k.strip_prefix("authorized_device_keys:") {
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
            local_group_epoch,
            authorized_keys,
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

    let inline_epoch_behind = wake
        .inline_ciphertext
        .as_deref()
        .and_then(extract_message_epoch_hint)
        .is_some_and(|msg_epoch| msg_epoch > preflight.local_group_epoch);

    let seq_gap = wake.entry_seq > convo.last_seq + 1;
    let needs_network_fetch =
        wake.fetch_required || wake.inline_ciphertext.is_none() || seq_gap || inline_epoch_behind;

    // -------------------------------------------------------------------------
    // Phase 2: Network fetch STRICTLY OUTSIDE any SQLite write transaction (I6, I10).
    // -------------------------------------------------------------------------
    let mut authorized_keys = preflight.authorized_keys;
    let fetch_bundle = if needs_network_fetch {
        let Some(ref net) = transport else {
            let _ = db.prepare_for_background();
            return Ok(build_generic_fallback_preview(wake, preflight.cached_title));
        };
        let Some(chat_dpop_token) = keystore
            .load_cached_chat_dpop_token(account_did_hash.to_ascii_lowercase())?
            .filter(|t| !t.trim().is_empty())
        else {
            // I10: never refresh OAuth in NSE; render generic text cleanly.
            let _ = db.prepare_for_background();
            return Ok(build_generic_fallback_preview(wake, preflight.cached_title));
        };

        let bundle = net.fetch_missing_entries(
            wake.conversation_id.clone(),
            convo.last_seq,
            chat_dpop_token.clone(),
        )?;

        for key in &bundle.authorized_device_keys {
            authorized_keys
                .entry(key.did.clone())
                .or_default()
                .push(key.clone());
        }

        let mut candidate_dids: HashSet<String> = HashSet::new();
        if let Some(ref s) = wake.sender_did {
            candidate_dids.insert(s.clone());
        }
        for entry in &bundle.entries {
            if !entry.sender_did.is_empty() {
                candidate_dids.insert(entry.sender_did.clone());
            }
        }
        for did in candidate_dids {
            if let std::collections::hash_map::Entry::Vacant(e) = authorized_keys.entry(did) {
                let fetched_keys =
                    net.get_authorized_device_keys(e.key().clone(), Some(chat_dpop_token.clone()))?;
                if !fetched_keys.is_empty() {
                    e.insert(fetched_keys);
                }
            }
        }

        Some(bundle)
    } else {
        None
    };

    // -------------------------------------------------------------------------
    // Phase 3: Atomic BEGIN IMMEDIATE write transaction (I7, I4, I13).
    // -------------------------------------------------------------------------
    let preview_res = db.write_tx(|tx| {
        // Re-check inside BEGIN IMMEDIATE in case the foreground app already inserted this message.
        let concurrent_msg: Option<(String, String, i64, i64)> = tx
            .conn()
            .query_row(
                "SELECT sender_did, plaintext_json, epoch, seq FROM messages WHERE message_id = ?1;",
                [&wake.message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
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

        if let Some((sender_did, plaintext_json, epoch, seq)) = concurrent_msg {
            let (body, _) = parse_canonical_message_body(plaintext_json.as_bytes())?;
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
                darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
            });
        }

        let now_ms = hooks.now_ms();

        // Persist any newly fetched authorized device keys in account_meta.
        if fetch_bundle.is_some() {
            for (did, keys) in &authorized_keys {
                let json = serde_json::to_string(keys)
                    .map_err(|e| MLSError::Internal(format!("serialize authorized keys: {e}")))?;
                tx.put_account_meta(&format!("authorized_device_keys:{did}"), &json, now_ms)?;
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

        let entries_to_apply: Vec<FetchedPushEntry> = if let Some(ref bundle) = fetch_bundle {
            let mut sorted = bundle.entries.clone();
            sorted.sort_by_key(|e| e.seq);
            sorted
        } else {
            let inline_bytes = wake.inline_ciphertext.clone().ok_or_else(|| {
                MLSError::invalid_input("inline push wake missing inline_ciphertext")
            })?;
            vec![FetchedPushEntry {
                entry_id: wake.message_id.clone(),
                seq: wake.entry_seq,
                epoch: group.epoch().as_u64() as i64,
                entry_kind: wake.kind.clone(),
                sender_did: wake.sender_did.clone().unwrap_or_default(),
                mls_bytes: inline_bytes,
            }]
        };

        let mut target_decrypted: Option<(String, String, i64, i64)> = None;

        for entry in entries_to_apply {
            if entry.seq <= current_convo.last_seq && entry.entry_id != wake.message_id {
                continue;
            }
            if entry.mls_bytes.is_empty() {
                // I14 pruned entry: ciphertext was deleted on `mls-ds` once all active devices
                // acknowledged it. Advance `last_seq` monotonically and continue catching up.
                current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                continue;
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
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    verify_staged_commit_i4(
                        &group,
                        &sender,
                        &staged_commit,
                        preflight.owner_did.as_deref(),
                        &authorized_keys,
                    )?;
                    group
                        .merge_staged_commit(&provider, *staged_commit)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("merge_staged_commit failed: {e:?}"))
                        })?;
                    current_convo.epoch = group.epoch().as_u64() as i64;
                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
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
                    let (body, plaintext_json, commitment_opt) =
                        extract_plaintext_body_and_verify_aad(&decrypted_bytes, &aad_bytes)?;

                    let is_own = preflight
                        .owner_did
                        .as_deref()
                        .is_some_and(|o| o == verified_sender_did);

                    tx.insert_message(&MessageRow {
                        message_id: entry.entry_id.clone(),
                        conversation_id: wake.conversation_id.clone(),
                        group_id: current_convo.group_id.clone(),
                        epoch: msg_epoch,
                        seq: entry.seq,
                        sender_did: verified_sender_did.clone(),
                        sender_device_id: verified_device_id,
                        plaintext_json,
                        created_at_ms: now_ms,
                        is_own,
                    })?;

                    if let Some(commitment) = commitment_opt {
                        tx.conn()
                            .execute(
                                "UPDATE messages SET archive_commitment = ?1 WHERE message_id = ?2;",
                                rusqlite::params![commitment.as_slice(), entry.entry_id],
                            )
                            .map_err(|e| {
                                MLSError::Internal(format!("persist archive_commitment: {e}"))
                            })?;
                    }

                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                    if !is_own {
                        current_convo.unread_count = current_convo.unread_count.saturating_add(1);
                    }

                    if entry.entry_id == wake.message_id || target_decrypted.is_none() {
                        target_decrypted = Some((verified_sender_did, body, msg_epoch, entry.seq));
                    }
                }
                ProcessedMessageContent::ProposalMessage(queued_prop) => {
                    group
                        .store_pending_proposal(provider.storage(), *queued_prop)
                        .map_err(|e| {
                            MLSError::Internal(format!("store_pending_proposal failed: {e:?}"))
                        })?;
                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                    return Err(MLSError::insufficient_permissions(
                        "I3/I4: external join proposals are forbidden",
                    ));
                }
                ProcessedMessageContent::OwnPendingCommit => {
                    group.merge_pending_commit(&provider).map_err(|e| {
                        MLSError::Cryptography(format!("merge_pending_commit failed: {e:?}"))
                    })?;
                    current_convo.epoch = group.epoch().as_u64() as i64;
                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                }
                ProcessedMessageContent::OwnPrivateMessage => {
                    current_convo.last_seq = current_convo.last_seq.max(entry.seq);
                }
                ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
                    return Err(MLSError::InvalidInput {
                        message: "unexpected UnresolvedAppDataCommit in push processor".to_string(),
                    });
                }
            }
        }

        // Decrypt and cache fetched metadata_snapshots (1A) once group reaches target epoch.
        if let Some(snapshot) = fetch_bundle.as_ref().and_then(|b| b.metadata_snapshot.as_ref()) {
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

        let Some((sender_did, body, msg_epoch, msg_seq)) = target_decrypted else {
            return Ok(build_generic_fallback_preview(wake, resolved_title));
        };

        Ok(NotificationPreview {
            message_id: wake.message_id.clone(),
            conversation_id: wake.conversation_id.clone(),
            sender_did,
            sender_display_name: preflight.sender_display_name.clone(),
            group_title: resolved_title,
            body,
            epoch: msg_epoch,
            seq: msg_seq,
            from_cache: false,
            fallback_generic: false,
            darwin_notification_name: DARWIN_NSE_DID_COMMIT_NOTIFICATION.to_string(),
        })
    });

    // Phase 4: Always checkpoint passively and close the SQLite handle before returning (`I9`, `I11`).
    let _ = db.prepare_for_background();
    drop(db);

    let preview = preview_res?;
    if !preview.from_cache && !preview.fallback_generic {
        post_darwin_nse_commit_notification();
    }
    Ok(preview)
}
