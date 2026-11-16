//! Unified `CatbirdMlsClient` SDK (`Spec §6.3`, `G2`, `D3`, `D4`, `I8`, `I9`, `I15`, `I16`).
//!
//! Single Rust SDK surface shared across iOS/macOS (`CatbirdMLSCore`), Android (`mlsffi`),
//! Tauri desktop (`catmos`), CLI (`catmos-cli`), `BIRDaemon`, and (via shared DTOs +
//! `WasmMlsClient`) browser WASM (`catbird-mls-web`).

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod archive_policy;
pub mod chat_wire;
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
mod live_plane;
#[cfg(not(target_arch = "wasm32"))]
mod live_sync;
pub mod spaces_gate;
pub mod traits;

use serde::{Deserialize, Serialize};

pub use chat_wire::{PendingGroupCreationState, PendingGroupCreationStatus};

#[cfg(not(target_arch = "wasm32"))]
pub use config::wipe_pre_cutover_local_artifacts;
pub use config::{
    account_db_path, account_did_hash_hex, normalize_account_did, CatbirdMlsClientConfig,
    PreCutoverWipeReport,
};
#[cfg(not(target_arch = "wasm32"))]
pub use spaces_gate::probe_and_check_spaces_eligibility;
pub use spaces_gate::{
    evaluate_spaces_eligibility, SpacesEligibilityInput, SpacesEligibilityStatus,
    SpacesUnavailableReason, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
pub use traits::{
    PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
};

/// Enrollment receipt returned when a device enrolls on its home `mls-ds` + Spaces (`D4`, `I15`, `I16`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct EnrollmentReceipt {
    pub account_did: String,
    pub account_did_hash: String,
    pub device_id: String,
    pub signature_public_key: Vec<u8>,
    pub direct_request_kp_bytes: Vec<u8>,
    pub recovery_kp_bytes: Vec<u8>,
    pub mailbox_space_uri: String,
    pub labyrinth_backup_enabled: bool,
}

/// Signed `blue.catbird.chat.registerPushGateway` payload minted with the enrolled Ed25519
/// device key (`CATBIRD-CHAT-PUSH-GATEWAY\0 || DAG-CBOR(...)`, `D2`, `M-F06`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct SignedPushGatewayRegistration {
    pub device_id: String,
    pub key_id: String,
    pub auth_generation: i64,
    pub gateway_url: String,
    pub app_id: String,
    pub push_key: String,
    pub enabled: bool,
    pub signed_at: String,
    pub signature_bytes: Vec<u8>,
    pub request_json: String,
}

/// A member unexpectedly dropped during a mailbox epoch rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct LabyrinthRotationExclusion {
    pub device_key_hex: Option<String>,
    pub reason: String,
    pub recovery_method: Option<String>,
}

/// Labyrinth 1.1 backup & recovery status (`D4`, `Spec §6.7`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct LabyrinthBackupStatus {
    pub backup_enabled: bool,
    pub mailbox_space_uri: String,
    pub has_recovery_code: bool,
    pub has_passkey_prf: bool,
    pub epoch_seq: u64,
    pub active_device_ids: Vec<String>,
    /// Advisory only: this restored keychain/passkey method passed its
    /// client-clock freshness window but remains valid until rotation.
    #[serde(default)]
    pub recovery_method_stale: bool,
    /// Recovery/device members unexpectedly excluded by the latest rotation.
    #[serde(default)]
    pub rotation_exclusions: Vec<LabyrinthRotationExclusion>,
    /// Epoch head durably queued for PDS + directory publication.
    #[serde(default)]
    pub pending_directory_epoch: Option<u64>,
    /// True after a publication retry failed; archive items remain queued.
    #[serde(default)]
    pub directory_publication_stalled: bool,
    /// Number of app-start/sync publication attempts observed by this device.
    #[serde(default)]
    pub directory_publication_retry_count: u64,
    /// Last retry failure, cleared once both directory publications succeed.
    #[serde(default)]
    pub directory_publication_error: Option<String>,
}

/// Enrolled-device offer for 6-digit hybrid PQ `CPace + ML-KEM-768` device pairing (`I16`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct OtcPairingOffer {
    pub six_digit_code: String,
    pub formatted_code: String,
}

/// Completed hybrid PQ `CPace + ML-KEM-768` OTC handshake transcript (`I16`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct OtcPairingCompletion {
    pub session_id: Vec<u8>,
    pub initiator_mlkem768_ek_len: u32,
    pub responder_mlkem768_ct_len: u32,
    pub new_epoch_seq: u64,
}

/// Initiator session handle returned when a new device writes an `otcSession` offer into `OwnerMailbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct OtcInitiatedSession {
    pub session_id_hex: String,
    pub expires_at_ms: i64,
    pub initiator_mlkem768_ek_len: u32,
}

/// Unified account device inventory entry combining `mls-ds` `getOwnDevices` and `OwnerMailbox` device metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct RegisteredDeviceInfo {
    pub device_id: String,
    pub device_name: Option<String>,
    pub signature_public_key: Vec<u8>,
    pub key_id: String,
    pub auth_generation: i64,
    pub status: String,
    pub created_at: String,
    pub last_active_at: Option<String>,
    pub dormant_at: Option<String>,
    pub labyrinth_device_key_hex: Option<String>,
    pub is_current_device: bool,
}

/// Per-step result of unified `revoke_device`, including atomic recovery-method rotation outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct DeviceRevocationReport {
    pub target_device_id: String,
    pub ds_revoked: bool,
    pub groups_updated: u32,
    pub labyrinth_rotated: bool,
    pub new_epoch_seq: Option<u64>,
    pub pds_record_deleted: bool,
    pub rekeyed_recovery_code: Option<String>,
    pub rekeyed_passkey_ids: Vec<Vec<u8>>,
}

/// Safety-number & 72-hour hold metadata for a peer mailbox full-chain reset (`repin_peer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PeerRepinProposalInfo {
    pub did: String,
    pub previous_seq: Option<u64>,
    pub old_safety_number: Option<String>,
    pub offered_seq: u64,
    pub offered_head_hex: String,
    pub safety_number: String,
    pub eligible_at_ms: i64,
    pub hold_remaining_ms: i64,
}

/// Outcome of `CatbirdMlsClient::leave_conversation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct LeaveConversationOutcome {
    pub left_immediately: bool,
    pub leave_request_id: Option<String>,
    pub rearchived_messages: u32,
}

/// Encrypted conversation attachment uploaded into the conversation Space (`"{spaceURI}|{repoDID}|{cid}"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct UploadedConversationAttachment {
    pub locator: String,
    pub space_uri: String,
    pub repo_did: String,
    pub cid: String,
    pub rkey: String,
    pub symmetric_key: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext_sha256: Vec<u8>,
    pub ciphertext_size: u64,
    pub mime_type: String,
}

/// Decrypted `OwnerMailbox` `readState` record (`MAX` CRDT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct MailboxReadStateRecord {
    pub conversation_id: String,
    pub read_through_seq: u64,
    pub updated_at: String,
}

/// Decrypted `OwnerMailbox` `circleOwnerState` record (`swapRecord` CAS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct CircleOwnerStateDto {
    pub circle_id: String,
    pub space_uri: String,
    pub current_key_version: u64,
    pub joined_at_version_json: String,
    pub pending_ops_json: String,
    pub updated_at: String,
    pub record_cid: Option<String>,
}

/// Durable outbox envelope persisted in `labyrinth_queue.payload_bytes` atomically inside
/// `CatbirdMlsClient::send_message`'s `write_tx` (`Spec §5 I6`, `[CB-30]`, `[CB-22]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct QueuedLabyrinthArchivePayload {
    pub version: u8,
    pub message_id: String,
    pub conversation_id: String,
    pub group_id_hex: String,
    pub epoch: i64,
    /// Authenticated MLS account roster at send time, never replaced by a flush-time roster.
    pub expected_member_dids: Vec<String>,
    pub seq: i64,
    pub sender_did: String,
    pub sender_device_id: String,
    pub sequencer_did: String,
    pub space_uri: Option<String>,
    pub plaintext_json: String,
    pub labyrinth_frame_json: String,
    pub mls_ciphertext_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_nonce_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_receipt_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_sender_attestation_json: Option<String>,
    pub created_at_ms: i64,
}

/// Canonical personal mailbox Space URI for an account (`Spec §6.4`, `D4`).
pub fn personal_mailbox_space_uri(account_did: &str) -> String {
    atproto_spaces::SpaceUri::new(account_did, "blue.catbird.labyrinth.mailbox", "self")
        .map(|u| u.to_string())
        .unwrap_or_else(|_| format!("at://{account_did}/space/blue.catbird.labyrinth.mailbox/self"))
}

/// Generate a 40-character GF(32) Labyrinth recovery code and derive its 16-byte virtual device ID (`Spec §6.7`, `D4`).
#[cfg(feature = "labyrinth")]
pub fn generate_recovery_code_vdevice(
    normalized_did: &str,
) -> Result<(String, [u8; 16]), crate::error::MLSError> {
    let code = labyrinth::recovery_code::RecoveryCode::generate()
        .map_err(|e| crate::error::MLSError::Cryptography(format!("generate RecoveryCode: {e}")))?;
    let (vdev_id, _vdev_key) = code.derive(normalized_did);
    Ok((code.format_grouped(), vdev_id))
}

/// Verify a 40-character GF(32) recovery code (up to 3-character erasure/typo correction) against `expected_vdev_id`.
#[cfg(feature = "labyrinth")]
pub fn verify_recovery_code_vdevice(
    normalized_did: &str,
    recovery_code_input: &str,
    expected_vdev_id: Option<&[u8]>,
) -> Result<[u8; 16], crate::error::MLSError> {
    let candidates = labyrinth::recovery_code::RecoveryCode::candidates(recovery_code_input)
        .map_err(|_| {
            crate::error::MLSError::invalid_input("invalid 40-character Labyrinth recovery code")
        })?;
    for candidate in candidates {
        let (cand_id, _cand_key) = candidate.derive(normalized_did);
        if match expected_vdev_id {
            Some(exp) => exp == cand_id.as_slice(),
            None => true,
        } {
            return Ok(cand_id);
        }
    }
    Err(crate::error::MLSError::insufficient_permissions(
        "recovery code does not match enrolled Labyrinth virtual device",
    ))
}

/// Generate a 6-digit One-Time Code (`OTC`) offer (`I16` hybrid `CPace + ML-KEM-768`).
#[cfg(feature = "labyrinth")]
pub fn generate_otc_offer() -> Result<OtcPairingOffer, crate::error::MLSError> {
    let code = labyrinth::otc::OneTimeCode::generate()
        .map_err(|e| crate::error::MLSError::Cryptography(format!("generate OneTimeCode: {e}")))?;
    Ok(OtcPairingOffer {
        six_digit_code: code.as_str().to_string(),
        formatted_code: code.format_grouped(),
    })
}

/// Execute the full hybrid PQ `CPace + ephemeral ML-KEM-768` handshake (`I16`) for `six_digit_code`.
#[cfg(feature = "labyrinth")]
pub fn execute_pq_otc_handshake(
    normalized_did: &str,
    six_digit_code: &str,
    expected_digits: Option<&str>,
    new_epoch_seq: u64,
) -> Result<OtcPairingCompletion, crate::error::MLSError> {
    let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
        .map_err(|_| crate::error::MLSError::invalid_input("invalid 6-digit OTC code"))?;
    let (initiator, init_msg) = labyrinth::otc::Initiator::start(&parsed, normalized_did)
        .map_err(|e| crate::error::MLSError::Cryptography(format!("OTC Initiator::start: {e}")))?;
    let ek_len = init_msg.ek_otc.len() as u32;
    let sid = init_msg.sid.to_vec();

    let responder_code = match expected_digits {
        Some(stored) => labyrinth::otc::OneTimeCode::parse(stored)
            .map_err(|e| crate::error::MLSError::Internal(format!("stored OTC invalid: {e}")))?,
        None => parsed,
    };
    let mut responder = labyrinth::otc::Responder::new(responder_code, normalized_did);
    let (resp_msg, resp_key) = responder.respond(&init_msg).map_err(|e| {
        crate::error::MLSError::Cryptography(format!("OTC Responder::respond: {e}"))
    })?;
    let ct_len = resp_msg.kem_ct.len() as u32;
    let init_key = initiator
        .finish(&resp_msg)
        .map_err(|e| crate::error::MLSError::Cryptography(format!("OTC Initiator::finish: {e}")))?;
    if init_key.as_bytes() != resp_key.as_bytes() {
        return Err(crate::error::MLSError::insufficient_permissions(
            "hybrid PQ CPace + ML-KEM-768 OTC code mismatch",
        ));
    }
    Ok(OtcPairingCompletion {
        session_id: sid,
        initiator_mlkem768_ek_len: ek_len,
        responder_mlkem768_ct_len: ct_len,
        new_epoch_seq,
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native_client {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use openmls::prelude::tls_codec::Serialize as TlsSerialize;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;
    use openmls_traits::OpenMlsProvider;
    use rusqlite::OptionalExtension as _;
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use crate::error::MLSError;
    use crate::groups::lifecycle::MemberRole;
    use crate::groups::metadata_v1::SpaceAvatarPointer;
    use crate::keychain::KeychainAccess;
    use crate::push::AuthorizedPeerDeviceKey;
    use crate::requests::c33::{
        validate_direct_request_key_package_lifetime, DIRECT_REQUEST_KP_MIN_LIFETIME_SECS,
        RECOVERY_KP_MAX_LIFETIME_SECS,
    };
    use crate::storage::{
        BackgroundCheckpointReport, ConversationRow, GroupMetadataRow, LabyrinthQueueRow,
        MessageRow, MlsAccountDb, MutationJournalRow, OpenMlsKvStorage, OpenMode, RequestRow,
        RusqliteKvBackend,
    };
    use crate::sync::reconcile::persist_entries_then_acknowledge;

    use super::{
        account_db_path, account_did_hash_hex, normalize_account_did, personal_mailbox_space_uri,
        probe_and_check_spaces_eligibility, wipe_pre_cutover_local_artifacts,
        CatbirdMlsClientConfig, CircleOwnerStateDto, DeviceRevocationReport, EnrollmentReceipt,
        LabyrinthBackupStatus, LabyrinthRotationExclusion, MailboxReadStateRecord,
        OtcInitiatedSession, OtcPairingCompletion, OtcPairingOffer, PeerRepinProposalInfo,
        PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader, PlatformHttpRequest,
        PlatformHttpResponse, PlatformKeyStore, PlatformTransport, PreCutoverWipeReport,
        QueuedLabyrinthArchivePayload, RegisteredDeviceInfo, SignedPushGatewayRegistration,
        SpacesEligibilityStatus, UploadedConversationAttachment,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    const ACK_ENTRIES_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACK-ENTRIES\0";
    const PUSH_GATEWAY_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-PUSH-GATEWAY\0";

    #[derive(Serialize)]
    struct AckTranscriptPayload<'a> {
        #[serde(rename = "keyId")]
        key_id: &'a str,
        #[serde(rename = "upToSeq")]
        up_to_seq: i64,
        #[serde(rename = "signedAt")]
        signed_at: &'a str,
        generation: i64,
        #[serde(rename = "actorDeviceId")]
        actor_device_id: String,
        #[serde(rename = "authGeneration")]
        auth_generation: i64,
        #[serde(rename = "conversationId")]
        conversation_id: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PushGatewayTranscriptPayload<'a> {
        app_id: &'a str,
        auth_generation: i64,
        device_id: String,
        enabled: bool,
        gateway_url: &'a str,
        key_id: &'a str,
        push_key: &'a str,
        signed_at: &'a str,
    }

    fn canonical_labyrinth_frame_json(plaintext_json: &str) -> String {
        if serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(plaintext_json).is_ok() {
            return plaintext_json.to_string();
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(plaintext_json) {
            if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
                if let Ok(encoded) =
                    serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(text))
                {
                    return encoded;
                }
            }
        }
        plaintext_json.to_string()
    }

    struct ClientKeychainBridge {
        keystore: Arc<dyn PlatformKeyStore>,
    }

    #[async_trait::async_trait]
    impl KeychainAccess for ClientKeychainBridge {
        async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
            self.keystore.load_signature_keypair(key)
        }

        async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
            self.keystore.store_signature_keypair(key, value)
        }

        async fn delete(&self, _key: String) -> Result<(), MLSError> {
            Ok(())
        }
    }

    /// Unified per-account MLS + Labyrinth SDK client (`Spec §6.3`).
    #[derive(uniffi::Object)]
    pub struct CatbirdMlsClient {
        pub(crate) config: CatbirdMlsClientConfig,
        pub(crate) normalized_did: String,
        account_did_hash: String,
        db_path: PathBuf,
        pub(crate) db: Arc<MlsAccountDb>,
        keystore: Arc<dyn PlatformKeyStore>,
        pub(crate) transport: Arc<dyn PlatformTransport>,
        observer: Option<Arc<dyn PlatformChangeObserver>>,
        pub(crate) hooks: crate::sim_hooks::SimClientHooks,
        #[cfg(feature = "sim")]
        pub(crate) sim_reopened: bool,
        cached_group_titles: Arc<Mutex<std::collections::HashMap<String, String>>>,
        /// Hot sender `MlsGroup` state; own MLS mutations and external `I7` commits evict it.
        cached_groups: Arc<Mutex<std::collections::HashMap<Vec<u8>, MlsGroup>>>,
        outbox_flush_lock: Mutex<()>,
        pub(super) pending_otc_offer_digits: Mutex<Option<zeroize::Zeroizing<String>>>,
        #[cfg(feature = "labyrinth")]
        pending_otc_initiator: Mutex<Option<(String, labyrinth::otc::Initiator, u32, [u8; 32])>>,
        wipe_report: PreCutoverWipeReport,
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        offline_archive_for_test: bool,
    }

    impl CatbirdMlsClient {
        /// Open `<storage_root>/catbird-mls/<sha256(normalized_did)>.db` (`OpenMode::App`),
        /// wiping pre-cutover `.sqlite`/`.lease`/`accounts.json` files (`I8`, `Spec §9 Step 5`)
        /// and enabling Labyrinth backup metadata by default (`D4`).
        pub fn open(
            config: CatbirdMlsClientConfig,
            keystore: Arc<dyn PlatformKeyStore>,
            transport: Arc<dyn PlatformTransport>,
            observer: Option<Arc<dyn PlatformChangeObserver>>,
        ) -> Result<Arc<Self>, MLSError> {
            Self::open_with_hooks(
                config,
                keystore,
                transport,
                observer,
                crate::sim_hooks::SimClientHooks::system_default(),
            )
        }

        /// Deterministic simulation constructor injecting [`crate::sim_hooks::SimClientHooks`]
        /// (`SimClock` + `SimEntropy`) while preserving `CatbirdMlsClient::open` unchanged.
        pub fn open_with_hooks(
            config: CatbirdMlsClientConfig,
            keystore: Arc<dyn PlatformKeyStore>,
            transport: Arc<dyn PlatformTransport>,
            observer: Option<Arc<dyn PlatformChangeObserver>>,
            hooks: crate::sim_hooks::SimClientHooks,
        ) -> Result<Arc<Self>, MLSError> {
            Self::open_internal(config, keystore, transport, observer, hooks, false)
        }

        /// Space-only test harness. Never available in production builds or selected by device ID.
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        pub fn open_offline_archive_for_test(
            config: CatbirdMlsClientConfig,
            keystore: Arc<dyn PlatformKeyStore>,
            transport: Arc<dyn PlatformTransport>,
            observer: Option<Arc<dyn PlatformChangeObserver>>,
        ) -> Result<Arc<Self>, MLSError> {
            Self::open_offline_archive_with_hooks_for_test(
                config,
                keystore,
                transport,
                observer,
                crate::sim_hooks::SimClientHooks::system_default(),
            )
        }

        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        pub fn open_offline_archive_with_hooks_for_test(
            config: CatbirdMlsClientConfig,
            keystore: Arc<dyn PlatformKeyStore>,
            transport: Arc<dyn PlatformTransport>,
            observer: Option<Arc<dyn PlatformChangeObserver>>,
            hooks: crate::sim_hooks::SimClientHooks,
        ) -> Result<Arc<Self>, MLSError> {
            Self::open_internal(config, keystore, transport, observer, hooks, true)
        }

        fn open_internal(
            mut config: CatbirdMlsClientConfig,
            keystore: Arc<dyn PlatformKeyStore>,
            transport: Arc<dyn PlatformTransport>,
            observer: Option<Arc<dyn PlatformChangeObserver>>,
            hooks: crate::sim_hooks::SimClientHooks,
            offline_archive_for_test: bool,
        ) -> Result<Arc<Self>, MLSError> {
            if !offline_archive_for_test {
                let device = uuid::Uuid::parse_str(config.device_id.trim())
                    .map_err(|_| MLSError::invalid_input("device_id must be a UUIDv4"))?;
                if device.get_version() != Some(uuid::Version::Random)
                    || device.get_variant() != uuid::Variant::RFC4122
                {
                    return Err(MLSError::invalid_input("device_id must be a UUIDv4"));
                }
                config.device_id = device.hyphenated().to_string();
            }
            let normalized_did = normalize_account_did(&config.account_did)?;
            let account_did_hash = account_did_hash_hex(&normalized_did)?;
            let storage_root_path = PathBuf::from(&config.storage_root);
            let wipe_report = wipe_pre_cutover_local_artifacts(&storage_root_path)?;
            let db_path = account_db_path(&storage_root_path, &normalized_did)?;

            let raw_key = Zeroizing::new(keystore.load_or_create_db_key(account_did_hash.clone())?);
            let db_key_32: Zeroizing<[u8; 32]> =
                Zeroizing::new(<[u8; 32]>::try_from(raw_key.as_slice()).map_err(|_| {
                    MLSError::invalid_input(
                        "PlatformKeyStore::load_or_create_db_key must return exactly 32 bytes",
                    )
                })?);

            let db = Arc::new(MlsAccountDb::open_native(
                &db_path,
                &db_key_32,
                OpenMode::App,
            )?);
            let keychain_bridge: Arc<dyn KeychainAccess> = Arc::new(ClientKeychainBridge {
                keystore: Arc::clone(&keystore),
            });
            db.set_keychain(keychain_bridge);
            #[cfg(feature = "sim")]
            let sim_reopened = db.read_tx(|tx| Ok(tx.get_account_meta("owner_did")?.is_some()))?;

            let cached_group_titles = Arc::new(Mutex::new(std::collections::HashMap::new()));
            let cached_groups = Arc::new(Mutex::new(std::collections::HashMap::new()));
            {
                let titles_ref = Arc::clone(&cached_group_titles);
                let groups_ref = Arc::clone(&cached_groups);
                db.register_cache_eviction_hook(Arc::new(move || {
                    if let Ok(mut guard) = titles_ref.lock() {
                        guard.clear();
                    }
                    if let Ok(mut guard) = groups_ref.lock() {
                        guard.clear();
                    }
                }));
            }

            // Initialize encrypted account_meta (`owner_did` lives inside the encrypted DB,
            // never in an unencrypted `accounts.json` per I8) and default D4 Labyrinth state.
            let mailbox_uri = personal_mailbox_space_uri(&normalized_did);
            let now_ms = hooks.now_ms();
            db.write_tx(|tx| {
                tx.put_account_meta("owner_did", &normalized_did, now_ms)?;
                tx.put_account_meta("device_id", &config.device_id, now_ms)?;
                tx.put_account_meta("home_ds_did", &config.home_ds_did, now_ms)?;
                if tx.get_labyrinth_state("status_json")?.is_none() {
                    let initial = LabyrinthBackupStatus {
                        backup_enabled: true,
                        mailbox_space_uri: mailbox_uri.clone(),
                        has_recovery_code: false,
                        has_passkey_prf: false,
                        epoch_seq: 1,
                        active_device_ids: vec![config.device_id.clone()],
                        recovery_method_stale: false,
                        rotation_exclusions: Vec::new(),
                        pending_directory_epoch: None,
                        directory_publication_stalled: false,
                        directory_publication_retry_count: 0,
                        directory_publication_error: None,
                    };
                    let bytes = serde_json::to_vec(&initial).map_err(|e| {
                        MLSError::Internal(format!("serialize initial LabyrinthBackupStatus: {e}"))
                    })?;
                    tx.put_labyrinth_state("status_json", &bytes, now_ms)?;
                }
                Ok(())
            })?;

            let client = Arc::new(Self {
                config,
                normalized_did,
                account_did_hash,
                db_path,
                db,
                keystore,
                transport,
                observer,
                hooks,
                #[cfg(feature = "sim")]
                sim_reopened,
                cached_group_titles,
                cached_groups,
                outbox_flush_lock: Mutex::new(()),
                pending_otc_offer_digits: Mutex::new(None),
                #[cfg(feature = "labyrinth")]
                pending_otc_initiator: Mutex::new(None),
                wipe_report,
                #[cfg(any(test, feature = "test-utils", feature = "sim"))]
                offline_archive_for_test,
            });
            Ok(client)
        }

        fn notify(&self, event: PlatformChangeEvent) {
            if let Some(ref obs) = self.observer {
                obs.on_change(event);
            }
        }

        pub(crate) fn notify_change(&self, event: PlatformChangeEvent) {
            self.notify(event);
        }

        pub(crate) fn cache_title_if_present(&self, conversation_id: &str, title: &Option<String>) {
            if let Some(ref t) = title {
                if let Ok(mut guard) = self.cached_group_titles.lock() {
                    guard.insert(conversation_id.to_string(), t.clone());
                }
            }
        }

        /// Execute a sender operation against the hot group after `write_tx` checked `I7`.
        /// The enclosing transaction rolls back and evicts this cache on any failure.
        pub(crate) fn with_cached_sender_group<R>(
            &self,
            group_id: &[u8],
            load: impl FnOnce() -> Result<Option<MlsGroup>, MLSError>,
            operation: impl FnOnce(&mut MlsGroup) -> Result<R, MLSError>,
        ) -> Result<Option<R>, MLSError> {
            let mut groups = self
                .cached_groups
                .lock()
                .map_err(|_| MLSError::lock_poisoned("CatbirdMlsClient.cached_groups"))?;
            if !groups.contains_key(group_id) {
                let Some(group) = load()? else {
                    return Ok(None);
                };
                groups.insert(group_id.to_vec(), group);
            }
            operation(groups.get_mut(group_id).expect("group just loaded")).map(Some)
        }

        /// Own writes do not advance SQLite `data_version`; accepted control operations
        /// and received messages invalidate the sender cache before mutating MLS storage.
        pub(crate) fn clear_cached_groups(&self) {
            if let Ok(mut groups) = self.cached_groups.lock() {
                groups.clear();
            }
        }

        pub fn account_did(&self) -> &str {
            &self.normalized_did
        }

        pub fn account_did_hash(&self) -> &str {
            &self.account_did_hash
        }

        pub fn db_path(&self) -> &std::path::Path {
            &self.db_path
        }

        pub fn db(&self) -> &Arc<MlsAccountDb> {
            &self.db
        }

        pub fn sim_hooks(&self) -> &crate::sim_hooks::SimClientHooks {
            &self.hooks
        }

        /// Returns `true` when this client's SQLite connection is currently inside any transaction
        /// (`!conn.is_autocommit()`), using safe `rusqlite::Connection::is_autocommit()`.
        pub fn is_in_transaction(&self) -> bool {
            self.db.is_in_transaction()
        }

        /// Returns `true` when this client's SQLite connection is inside a `BEGIN IMMEDIATE` write transaction (`I6`).
        pub fn is_in_write_transaction(&self) -> bool {
            self.db.is_in_write_transaction()
        }

        /// Obtain a cloneable [`crate::sim_hooks::TxAutocommitProbe`] bound to this client's database (`I6`).
        pub fn autocommit_probe(&self) -> crate::sim_hooks::TxAutocommitProbe {
            self.db.autocommit_probe()
        }

        pub fn pre_cutover_wipe_report(&self) -> &PreCutoverWipeReport {
            &self.wipe_report
        }

        /// Check `I15` Spaces capability on the user's PDS and granted OAuth scopes.
        pub fn check_spaces_eligibility(
            &self,
            granted_oauth_scopes: &[String],
        ) -> Result<SpacesEligibilityStatus, MLSError> {
            let status = probe_and_check_spaces_eligibility(
                &self.normalized_did,
                &self.config.pds_endpoint,
                granted_oauth_scopes,
                self.transport.as_ref(),
            )?;
            self.notify(PlatformChangeEvent::SpacesEligibilityChanged {
                eligible: status.eligible,
            });
            Ok(status)
        }

        /// Enroll this device (`I15` Spaces gate + `I16` `X-Wing` KeyPackages + `D4` Labyrinth default-on + live `mls-ds` & PDS publication).
        ///
        /// Idempotent: an enrolled device keeps its signer. Its MLS leaves, the Labyrinth archive
        /// session (transport key) and the `mls-ds` device row are bound to it, and `mls-ds` has no
        /// key rotation: a new signing key is a new device ID.
        pub fn enroll_device(
            &self,
            granted_oauth_scopes: &[String],
        ) -> Result<EnrollmentReceipt, MLSError> {
            let eligibility = self.check_spaces_eligibility(granted_oauth_scopes)?;
            if !eligibility.eligible {
                return Err(MLSError::insufficient_permissions(eligibility.user_message));
            }

            let now_secs = self.hooks.now_secs();
            let now_ms = self.hooks.now_ms();
            let direct_not_after = now_secs + DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 3600;
            validate_direct_request_key_package_lifetime(now_secs, direct_not_after)?;
            let recovery_not_after = now_secs + RECOVERY_KP_MAX_LIFETIME_SECS;

            let scoped_identity = format!("{}#{}", self.normalized_did, self.config.device_id);
            let mailbox_space_uri = personal_mailbox_space_uri(&self.normalized_did);

            let (signer, signer_bytes, direct_kp_bytes, recovery_kp_bytes) =
                self.db.write_tx(|tx| {
                    if tx
                        .get_account_meta("scoped_identity")?
                        .is_some_and(|identity| identity != scoped_identity)
                    {
                        return Err(MLSError::InvalidState(
                            "EnrollmentDeviceIdentityMismatch".into(),
                        ));
                    }
                    let signer = match tx.get_account_meta("enrolled_signer_json")? {
                        Some(raw) => serde_json::from_str::<SignatureKeyPair>(&raw)
                            .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?,
                        None => self
                            .hooks
                            .signature_keypair(CIPHERSUITE.signature_algorithm())?,
                    };
                    let signer_bytes = serde_json::to_vec(&signer)
                        .map_err(|e| MLSError::Internal(format!("serialize signer: {e}")))?;
                    let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                    let provider = self.hooks.openmls_provider(storage);
                    signer.store(provider.storage()).map_err(|e| {
                        MLSError::Internal(format!("store signer in openmls_kv: {e:?}"))
                    })?;

                    let cred = BasicCredential::new(scoped_identity.clone().into_bytes());
                    let cred_with_key = CredentialWithKey {
                        credential: cred.into(),
                        signature_key: signer.public().into(),
                    };

                    let direct_kp = KeyPackage::builder()
                        .key_package_lifetime(Lifetime::init(
                            now_secs.saturating_sub(60),
                            direct_not_after,
                        ))
                        .leaf_node_capabilities(
                            Capabilities::builder()
                                .ciphersuites(vec![CIPHERSUITE])
                                .build(),
                        )
                        .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                        .map_err(|e| {
                            MLSError::Cryptography(format!("build C33 KeyPackage: {e:?}"))
                        })?;

                    let recovery_kp = KeyPackage::builder()
                        .key_package_lifetime(Lifetime::init(
                            now_secs.saturating_sub(60),
                            recovery_not_after,
                        ))
                        .leaf_node_capabilities(
                            Capabilities::builder()
                                .ciphersuites(vec![CIPHERSUITE])
                                .build(),
                        )
                        .build(CIPHERSUITE, &provider, &signer, cred_with_key)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("build recovery KeyPackage: {e:?}"))
                        })?;

                    let direct_bytes = direct_kp
                        .key_package()
                        .tls_serialize_detached()
                        .map_err(|e| MLSError::Internal(format!("serialize C33 kp: {e:?}")))?;
                    let recovery_bytes = recovery_kp
                        .key_package()
                        .tls_serialize_detached()
                        .map_err(|e| MLSError::Internal(format!("serialize recovery kp: {e:?}")))?;

                    tx.put_account_meta("scoped_identity", &scoped_identity, now_ms)?;
                    tx.put_account_meta(
                        "enrolled_signer_json",
                        &String::from_utf8_lossy(&signer_bytes),
                        now_ms,
                    )?;
                    let own_auth = vec![AuthorizedPeerDeviceKey {
                        did: self.normalized_did.clone(),
                        device_id: self.config.device_id.clone(),
                        signature_public_key: signer.public().to_vec(),
                    }];
                    tx.put_account_meta(
                        &format!("authorized_device_keys:{}", self.normalized_did),
                        &serde_json::to_string(&own_auth)
                            .map_err(|e| MLSError::Internal(e.to_string()))?,
                        now_ms,
                    )?;

                    Ok((signer, signer_bytes, direct_bytes, recovery_bytes))
                })?;
            let pub_key = signer.public().to_vec();
            self.keystore.store_signature_keypair(
                format!("mls-signer:{}", self.account_did_hash),
                signer_bytes,
            )?;

            // Strictly outside `write_tx` (`I6`): publish PDS `blue.catbird.chat.device` +
            // `enrollDevice` + `publishDirectRequestKeys` + `replenishKeyPackages` when using a
            // canonical UUIDv4 device ID.
            if let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() {
                self.enroll_device_live(&canonical_dev_id, &pub_key)?;
            }

            self.notify(PlatformChangeEvent::LabyrinthStatusChanged { epoch_seq: 1 });

            Ok(EnrollmentReceipt {
                account_did: self.normalized_did.clone(),
                account_did_hash: self.account_did_hash.clone(),
                device_id: self.config.device_id.clone(),
                signature_public_key: pub_key,
                direct_request_kp_bytes: direct_kp_bytes,
                recovery_kp_bytes,
                mailbox_space_uri,
                labyrinth_backup_enabled: true,
            })
        }

        /// Suspend admissions, run non-blocking `PRAGMA wal_checkpoint(PASSIVE)`, and close
        /// the SQLite connection completely (`Spec §5 I9` — prevents iOS `0xdead10cc`).
        pub fn prepare_for_background(&self) -> Result<BackgroundCheckpointReport, MLSError> {
            let _ = self.transport.disconnect_realtime_stream();
            let report = self.db.prepare_for_background()?;
            self.notify(PlatformChangeEvent::Backgrounded);
            Ok(report)
        }

        /// Reopen `<did_hash>.db` on foreground resume and trigger `I7` cache + `sync()` reconciliation.
        pub fn resume_from_background(&self) -> Result<(), MLSError> {
            self.db.resume_from_background()?;
            let _ = self.sync();
            self.notify(PlatformChangeEvent::Resumed);
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(())
        }

        pub fn is_handle_closed(&self) -> bool {
            !self.db.is_open()
        }

        /// Handle `blue.catbird.mls.nseDidCommit` Darwin wakeup (`Spec §5 I11` + `I7`).
        pub fn handle_darwin_push_wakeup(&self) -> Result<(), MLSError> {
            if let Ok(mut guard) = self.cached_group_titles.lock() {
                guard.clear();
            }
            if let Ok(mut guard) = self.cached_groups.lock() {
                guard.clear();
            }
            let _ = self.sync();
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(())
        }

        /// Decrypts a push notification wake payload (`OpenMode::PushExtension` semantics)
        /// and immediately dispatches signed per-leaf `acknowledgeEntries` after local SQLite `COMMIT`.
        pub fn process_push_wake(
            &self,
            wake: crate::push::PushWakePayload,
        ) -> Result<crate::push::NotificationPreview, MLSError> {
            struct ClientPushKeystoreAdapter {
                keystore: Arc<dyn PlatformKeyStore>,
                has_live_session: bool,
            }
            impl crate::push::PushKeystore for ClientPushKeystoreAdapter {
                fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
                    self.keystore.load_or_create_db_key(account_did_hash)
                }
                fn load_signature_keypair(
                    &self,
                    key_id: String,
                ) -> Result<Option<Vec<u8>>, MLSError> {
                    self.keystore.load_signature_keypair(key_id)
                }
                fn load_cached_chat_dpop_token(
                    &self,
                    account_did_hash: String,
                ) -> Result<Option<String>, MLSError> {
                    if let Some(tok) = self
                        .keystore
                        .load_cached_chat_dpop_token(account_did_hash)?
                    {
                        if !tok.trim().is_empty() {
                            return Ok(Some(tok));
                        }
                    }
                    if self.has_live_session {
                        Ok(Some("client-live-signed-session".to_string()))
                    } else {
                        Ok(None)
                    }
                }
            }

            struct PrefetchedPushTransport {
                bundle: crate::push::PushFetchBundle,
                authorized_by_did:
                    std::collections::HashMap<String, Vec<crate::push::AuthorizedPeerDeviceKey>>,
            }
            impl crate::push::PushFetchTransport for PrefetchedPushTransport {
                fn fetch_missing_entries(
                    &self,
                    _conversation_id: String,
                    _after_seq: i64,
                    _chat_dpop_token: String,
                ) -> Result<crate::push::PushFetchBundle, MLSError> {
                    Ok(self.bundle.clone())
                }
                fn get_authorized_device_keys(
                    &self,
                    did: String,
                    _chat_dpop_token: Option<String>,
                ) -> Result<Vec<crate::push::AuthorizedPeerDeviceKey>, MLSError> {
                    Ok(self
                        .authorized_by_did
                        .get(&did)
                        .cloned()
                        .unwrap_or_default())
                }
            }

            let storage_root = PathBuf::from(&self.config.storage_root);
            let conv_id = wake.conversation_id.clone();

            let mut prefetched_transport: Option<Arc<dyn crate::push::PushFetchTransport>> = None;
            let hash_matches = wake.recipient_account_hash.is_empty()
                || wake
                    .recipient_account_hash
                    .eq_ignore_ascii_case(&self.account_did_hash);
            let inline_ok = wake
                .inline_ciphertext
                .as_ref()
                .is_none_or(|ct| crate::push::should_inline_push_ciphertext(ct));
            if hash_matches && inline_ok {
                if let (Ok(Some(convo)), Some(canonical_dev_id), Ok((signer, _))) = (
                    self.db.read_tx(|tx| tx.get_conversation(&conv_id)),
                    self.canonical_uuid_v4_device_id(),
                    self.load_enrolled_signer_and_auth_gen(),
                ) {
                    if self
                        .db
                        .read_tx(|tx| {
                            tx.get_account_meta(&format!("did_doc:{}", convo.sequencer_did))
                        })
                        .ok()
                        .flatten()
                        .is_none()
                    {
                        let _ = self.resolve_did_document(&convo.sequencer_did);
                    }
                    let after_seq_str = convo.last_seq.to_string();
                    if let Ok(entries_val) = self.query_signed_chat_ds(
                        "blue.catbird.chat.getEntries",
                        &[
                            ("actorDeviceId", &canonical_dev_id),
                            ("afterSeq", &after_seq_str),
                            ("conversationId", &conv_id),
                            ("limit", "100"),
                        ],
                        &canonical_dev_id,
                        &signer,
                    ) {
                        let mut entries = Vec::new();
                        let mut sender_dids = std::collections::BTreeSet::new();
                        if let Some(ref s) = wake.sender_did {
                            if !s.is_empty() {
                                sender_dids.insert(s.clone());
                            }
                        }
                        if let Some(arr) = entries_val.get("entries").and_then(|v| v.as_array()) {
                            for entry in arr {
                                let signed_req = entry.get("signedRequest");
                                let body =
                                    signed_req.and_then(|sr| sr.get("body")).unwrap_or(entry);
                                let mls_bytes = body
                                    .pointer("/applicationMessage/bytes")
                                    .or_else(|| body.pointer("/commit/bytes"))
                                    .and_then(|b| super::chat_wire::json_bytes(b).ok())
                                    .unwrap_or_default();
                                let sender_did = body
                                    .get("actorDid")
                                    .or_else(|| entry.get("senderDid"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                if !sender_did.is_empty() {
                                    sender_dids.insert(sender_did.clone());
                                }
                                entries.push(crate::push::FetchedPushEntry {
                                    entry_id: entry
                                        .get("entryId")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or_default()
                                        .to_string(),
                                    seq: entry
                                        .get("seq")
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or_default(),
                                    epoch: body
                                        .pointer("/prior/epoch")
                                        .or_else(|| entry.get("epoch"))
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or(convo.epoch),
                                    entry_kind: entry
                                        .get("$type")
                                        .or_else(|| entry.get("entryKind"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or_default()
                                        .to_string(),
                                    sender_did,
                                    mls_bytes,
                                    signed_request: signed_req
                                        .and_then(|sr| serde_json::to_vec(sr).ok()),
                                    sequencer_receipt: entry
                                        .get("sequencerReceipt")
                                        .filter(|r| r.is_object())
                                        .and_then(|r| serde_json::to_vec(r).ok()),
                                });
                            }
                        }
                        let mut authorized_by_did = std::collections::HashMap::new();
                        for did in sender_dids {
                            if let Ok(keys) = self.fetch_and_cache_authorized_pds_device_keys(&did)
                            {
                                authorized_by_did.insert(did, keys);
                            }
                        }
                        prefetched_transport = Some(Arc::new(PrefetchedPushTransport {
                            bundle: crate::push::PushFetchBundle {
                                entries,
                                metadata_snapshot: None,
                                authorized_device_keys: Vec::new(),
                            },
                            authorized_by_did,
                        }));
                    }
                }
            }

            let push_ks: Arc<dyn crate::push::PushKeystore> = Arc::new(ClientPushKeystoreAdapter {
                keystore: self.keystore.clone(),
                has_live_session: prefetched_transport.is_some(),
            });
            let preview = crate::push::process_push_notification_with_hooks(
                &storage_root,
                &self.account_did_hash,
                push_ks,
                prefetched_transport,
                &wake,
                &self.hooks,
            )?;
            if let Ok(mut guard) = self.cached_groups.lock() {
                guard.clear();
            }
            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conv_id,
            });
            Ok(preview)
        }

        /// Close `<did_hash>.db`, remove the account's SQLite files, and purge Keychain items.
        pub fn sign_out_and_wipe(&self) -> Result<(), MLSError> {
            let _ = self.transport.disconnect_realtime_stream();
            let _ = self.db.prepare_for_background();
            for suffix in ["", "-wal", "-shm"] {
                let candidate = PathBuf::from(format!("{}{}", self.db_path.display(), suffix));
                if candidate.exists() {
                    let _ = std::fs::remove_file(&candidate);
                }
            }
            self.keystore
                .delete_account_keys(self.account_did_hash.clone())?;
            Ok(())
        }

        // ---------------------------------------------------------------------
        // Paged Read Queries (strictly ordered by `seq` per I2)
        // ---------------------------------------------------------------------

        pub fn list_conversations(
            &self,
            before_updated_ms: Option<i64>,
            limit: u32,
        ) -> Result<Vec<ConversationRow>, MLSError> {
            self.db
                .read_tx(|tx| tx.list_conversations(before_updated_ms, limit as usize))
        }

        pub fn list_messages(
            &self,
            conversation_id: &str,
            before_seq: Option<i64>,
            limit: u32,
        ) -> Result<Vec<MessageRow>, MLSError> {
            self.db
                .read_tx(|tx| tx.list_messages(conversation_id, before_seq, limit as usize))
        }

        pub fn list_requests(
            &self,
            consent_filter: Option<&str>,
        ) -> Result<Vec<RequestRow>, MLSError> {
            self.db.read_tx(|tx| tx.list_requests(consent_filter))
        }

        pub fn get_group_metadata(
            &self,
            conversation_id: &str,
        ) -> Result<Option<GroupMetadataRow>, MLSError> {
            self.db.read_tx(|tx| tx.get_group_metadata(conversation_id))
        }

        /// Effective policy after sequenced controls and any stricter authenticated frame.
        /// The cached metadata JSON remains the exact decrypted snapshot, so callers should use
        /// this accessor for a toggle's state rather than reading `metadata_json` directly.
        pub fn history_backup_enabled(&self, conversation_id: &str) -> Result<bool, MLSError> {
            self.db
                .read_tx(|tx| super::archive_policy::current_enabled(tx, conversation_id))
        }

        // ---------------------------------------------------------------------
        // Group, Message, Metadata (`1A`), and Request Mutations
        // ---------------------------------------------------------------------

        /// Rejects a non-UUIDv4 conversation or device ID with `InvalidInput` before any effect.
        /// Only the explicit test harness (`open_offline_archive_for_test`) creates a local group.
        pub fn create_group(
            &self,
            conversation_id: &str,
            sequencer_did: &str,
            member_dids: Vec<String>,
            title: Option<String>,
            description: Option<String>,
        ) -> Result<ConversationRow, MLSError> {
            #[cfg(any(test, feature = "test-utils", feature = "sim"))]
            if self.offline_archive_for_test {
                return self.create_group_local_offline(
                    conversation_id,
                    sequencer_did,
                    title,
                    description,
                );
            }
            self.create_group_live(
                conversation_id,
                sequencer_did,
                member_dids,
                title,
                description,
            )
        }

        /// Test-harness group: a local MLS group with no delivery-service registration.
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        fn create_group_local_offline(
            &self,
            conversation_id: &str,
            sequencer_did: &str,
            title: Option<String>,
            description: Option<String>,
        ) -> Result<ConversationRow, MLSError> {
            use crate::groups::metadata_v1::validate_metadata_snapshot_size;
            use crate::metadata::{
                derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce,
                GroupMetadataV1,
            };
            let group_id_bytes = self.hooks.random_array::<32>().to_vec();
            let now_ms = self.hooks.now_ms();
            let now_secs = self.hooks.now_secs();
            let space_uri = Some(crate::client::live_sync::conversation_space_uri(
                sequencer_did,
                conversation_id,
                0,
            ));

            let convo = self.db.write_tx(|tx| {
                let signer_json = tx.get_account_meta("enrolled_signer_json")?;
                let signer = if let Some(raw) = signer_json {
                    serde_json::from_str::<SignatureKeyPair>(&raw)
                        .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?
                } else {
                    let s = self
                        .hooks
                        .signature_keypair(CIPHERSUITE.signature_algorithm())?;
                    let serialized = serde_json::to_string(&s)
                        .map_err(|e| MLSError::Internal(format!("serialize signer: {e}")))?;
                    tx.put_account_meta("enrolled_signer_json", &serialized, now_ms)?;
                    s
                };

                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store group signer: {e:?}")))?;

                let scoped_id = format!("{}#{}", self.normalized_did, self.config.device_id);
                let cred_with_key = CredentialWithKey {
                    credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                    signature_key: signer.public().into(),
                };
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .lifetime(Lifetime::init(
                        now_secs.saturating_sub(60),
                        now_secs + 29 * 86_400,
                    ))
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .max_past_epochs(5)
                    .sender_ratchet_configuration(
                        crate::types::GroupConfig::default().sender_ratchet_configuration(),
                    )
                    .build();

                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    cred_with_key,
                )
                .map_err(|e| MLSError::Cryptography(format!("create X-Wing group: {e:?}")))?;

                if title.is_some() || description.is_some() {
                    let meta_v1 = GroupMetadataV1 {
                        version: 1,
                        title: title.clone().unwrap_or_default(),
                        description: description.clone().unwrap_or_default(),
                        avatar_blob_locator: None,
                        avatar_content_type: None,
                        extra: Default::default(),
                        space_avatar: None,
                    };
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &group_id_bytes,
                        0,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                    let nonce = self.hooks.random_array::<12>();
                    let ct = encrypt_metadata_snapshot_with_nonce(
                        &meta_key,
                        &group_id_bytes,
                        0,
                        1,
                        &nonce,
                        &meta_v1,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("seal metadata: {e}")))?;
                    validate_metadata_snapshot_size(&ct)?;

                    tx.upsert_group_metadata(&GroupMetadataRow {
                        conversation_id: conversation_id.to_string(),
                        metadata_version: 1,
                        epoch: 0,
                        title: title.clone(),
                        description: description.clone(),
                        avatar_setter_did: None,
                        avatar_blob_cid: None,
                        avatar_sym_key: None,
                        avatar_sha256: None,
                        avatar_mime_type: None,
                        metadata_json: serde_json::to_string(&meta_v1)
                            .map_err(|e| MLSError::Internal(e.to_string()))?,
                        updated_at_ms: now_ms,
                    })?;
                }

                let row = ConversationRow {
                    conversation_id: conversation_id.to_string(),
                    group_id: group_id_bytes.clone(),
                    generation: 0,
                    epoch: 0,
                    last_seq: 1,
                    sequencer_did: sequencer_did.to_string(),
                    space_uri,
                    title: title.clone(),
                    unread_count: 0,
                    updated_at_ms: now_ms,
                };
                tx.upsert_conversation(&row)?;
                Ok(row)
            })?;

            self.cache_title_if_present(conversation_id, &convo.title);
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(convo)
        }

        /// Rejects non-UUIDv4 conversation, message or device IDs with `InvalidInput` before any
        /// effect. Only the explicit test harness (`open_offline_archive_for_test`) sends offline.
        pub fn send_message(
            &self,
            conversation_id: &str,
            message_id: &str,
            text: &str,
        ) -> Result<MessageRow, MLSError> {
            #[cfg(any(test, feature = "test-utils", feature = "sim"))]
            if self.offline_archive_for_test {
                return self.send_message_local_offline(conversation_id, message_id, text);
            }
            self.send_message_live(conversation_id, message_id, text)
        }

        /// Publish an MLS-authenticated, sequenced policy change visible to every member.
        /// The control frame itself opts out of history backup; any active group member may
        /// tighten the setting, and re-enabling is a separate signed action.
        pub fn set_history_backup_enabled(
            &self,
            conversation_id: &str,
            enabled: bool,
        ) -> Result<MessageRow, MLSError> {
            let frame = serde_json::json!({
                "version": 1,
                "messageType": "system",
                "text": if enabled {
                    "History backup turned on"
                } else {
                    "History backup turned off"
                },
                "historyBackupChange": enabled,
                "backupPolicy": 1,
                "noBackup": true,
            });
            self.send_message(
                conversation_id,
                &self.hooks.uuid_v4().to_string(),
                &frame.to_string(),
            )
        }

        /// Test-harness send: a local MLS message and a receiptless queue row that only
        /// `offline_flush_labyrinth_queue` can archive.
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        fn send_message_local_offline(
            &self,
            conversation_id: &str,
            message_id: &str,
            text: &str,
        ) -> Result<MessageRow, MLSError> {
            let (display_json, frame_json) =
                super::live_plane::canonical_labyrinth_frame_for_text(text);
            let frame_json = self.db.read_tx(|tx| {
                super::archive_policy::stamp_outgoing(tx, conversation_id, &frame_json)
            })?;
            let frame_nonce = self.hooks.random_array::<32>();
            let now_ms = self.hooks.now_ms();
            let (inner_plaintext, aad_bytes) =
                crate::messaging::receive::PrivateMessagePlaintextEnvelope::seal_with_aad(
                    frame_nonce,
                    frame_json.as_bytes().to_vec(),
                )?;

            let msg_row = self.db.write_tx(|tx| {
                let mut convo = tx.get_conversation(conversation_id)?.ok_or_else(|| {
                    MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    }
                })?;
                let signer_json =
                    tx.get_account_meta("enrolled_signer_json")?
                        .ok_or_else(|| {
                            MLSError::InvalidState("device signer not initialized".to_string())
                        })?;
                let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                    .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;

                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let mut group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        .ok_or_else(|| MLSError::GroupNotFound {
                            message: format!("MlsGroup missing for {conversation_id}"),
                        })?;

                group.set_aad(aad_bytes);
                let mls_out = group
                    .create_message(&provider, &signer, &inner_plaintext)
                    .map_err(|e| MLSError::Cryptography(format!("create_message: {e:?}")));
                group.set_aad(Vec::new());
                let mls_out = mls_out?;
                let ciphertext_bytes = mls_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize message: {e:?}")))?;

                let latest_message_seq: i64 = tx
                    .conn()
                    .query_row(
                        "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation_id = ?1",
                        [conversation_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| MLSError::Internal(format!("read offline message seq: {e}")))?;
                let next_seq = convo.last_seq.max(latest_message_seq).saturating_add(1);
                convo.last_seq = next_seq;
                convo.epoch = group.epoch().as_u64() as i64;
                convo.updated_at_ms = now_ms;
                tx.upsert_conversation(&convo)?;

                let row = MessageRow {
                    message_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    group_id: convo.group_id.clone(),
                    epoch: convo.epoch,
                    seq: next_seq,
                    sender_did: self.normalized_did.clone(),
                    sender_device_id: self.config.device_id.clone(),
                    plaintext_json: display_json.to_string(),
                    created_at_ms: now_ms,
                    is_own: true,
                };
                tx.insert_message(&row)?;

                let group_id_hex = hex::encode(&convo.group_id);
                let queued_payload = QueuedLabyrinthArchivePayload {
                    version: 1,
                    message_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    group_id_hex: group_id_hex.clone(),
                    epoch: convo.epoch,
                    expected_member_dids: group
                        .members()
                        .map(|member| {
                            let scoped =
                                String::from_utf8(member.credential.serialized_content().to_vec())
                                    .map_err(|_| {
                                        MLSError::Cryptography("invalid member identity".into())
                                    })?;
                            Ok(scoped.split('#').next().unwrap_or(&scoped).to_owned())
                        })
                        .collect::<Result<std::collections::BTreeSet<_>, MLSError>>()?
                        .into_iter()
                        .collect(),
                    seq: next_seq,
                    sender_did: self.normalized_did.clone(),
                    sender_device_id: self.config.device_id.clone(),
                    sequencer_did: convo.sequencer_did.clone(),
                    space_uri: convo.space_uri.clone(),
                    plaintext_json: display_json.to_string(),
                    labyrinth_frame_json: frame_json.to_string(),
                    mls_ciphertext_b64: BASE64_STANDARD.encode(&ciphertext_bytes),
                    frame_nonce_b64: Some(BASE64_STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    original_sender_attestation_json: None,
                    created_at_ms: now_ms,
                };
                super::archive_policy::enqueue(tx, &queued_payload)?;

                Ok(row)
            })?;

            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_string(),
            });
            Ok(msg_row)
        }

        /// Remove a member from a group conversation (`Spec §2 D3` / `M-F01`: strictly admin-only).
        /// Rejects a non-UUIDv4 conversation or device ID with `InvalidInput` before any effect.
        pub fn remove_group_member(
            &self,
            actor_role: MemberRole,
            conversation_id: &str,
            target_did: &str,
        ) -> Result<(), MLSError> {
            #[cfg(any(test, feature = "test-utils", feature = "sim"))]
            if self.offline_archive_for_test {
                return self.remove_group_member_local_offline(
                    actor_role,
                    conversation_id,
                    target_did,
                );
            }
            self.remove_group_member_live(actor_role, conversation_id, target_did)
        }

        /// Test-harness removal: records the removal locally; no Commit reaches a DS.
        #[cfg(any(test, feature = "test-utils", feature = "sim"))]
        fn remove_group_member_local_offline(
            &self,
            actor_role: MemberRole,
            conversation_id: &str,
            target_did: &str,
        ) -> Result<(), MLSError> {
            if target_did.trim().is_empty() {
                return Err(MLSError::invalid_input("target_did must not be empty"));
            }
            crate::groups::lifecycle::enforce_admin_removal_policy(
                &self.normalized_did,
                actor_role,
                &[target_did.to_string()],
            )?;
            let now_ms = self.hooks.now_ms();
            self.db.write_tx(|tx| {
                tx.get_conversation(conversation_id)?
                    .ok_or_else(|| MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    })?;
                tx.put_account_meta(
                    &format!("last_removed_member:{conversation_id}"),
                    target_did,
                    now_ms,
                )
            })?;
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(())
        }

        /// Update `1A` encrypted group metadata (`<= 16 KiB` snapshot + optional Space avatar pointer).
        pub fn update_group_metadata(
            &self,
            conversation_id: &str,
            title: String,
            description: String,
            space_avatar: Option<SpaceAvatarPointer>,
        ) -> Result<GroupMetadataRow, MLSError> {
            self.update_group_metadata_live_or_offline(
                conversation_id,
                title,
                description,
                space_avatar,
            )
        }

        pub fn accept_direct_request(&self, request_id: &str) -> Result<(), MLSError> {
            self.accept_direct_request_live_or_offline(request_id)
        }

        pub fn decline_direct_request(&self, request_id: &str) -> Result<(), MLSError> {
            self.decline_direct_request_live_or_offline(request_id)
        }

        fn load_device_ed25519_signer(
            &self,
        ) -> Result<
            (
                [u8; 32],
                Arc<dyn Fn(&[u8]) -> Result<[u8; 64], MLSError> + Send + Sync>,
            ),
            MLSError,
        > {
            let keychain_key = format!("mls-signer:{}", self.account_did_hash);
            if let Some(raw_bytes) = self.keystore.load_signature_keypair(keychain_key)? {
                if raw_bytes.len() == 32 {
                    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
                        <[u8; 32]>::try_from(raw_bytes.as_slice())
                            .map_err(|_| MLSError::Internal("invalid 32-byte seed".to_string()))?,
                    );
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    let pub_key = signing_key.verifying_key().to_bytes();
                    return Ok((
                        pub_key,
                        Arc::new(move |msg: &[u8]| {
                            use ed25519_dalek::Signer as _;
                            Ok(signing_key.sign(msg).to_bytes())
                        }),
                    ));
                }
                let signer: SignatureKeyPair = serde_json::from_slice(&raw_bytes).map_err(|e| {
                    MLSError::Internal(format!("deserialize mls-signer SignatureKeyPair: {e}"))
                })?;
                let pub_key: [u8; 32] = signer.public().try_into().map_err(|_| {
                    MLSError::Cryptography("enrolled signer public key is not 32 bytes".to_string())
                })?;
                return Ok((
                    pub_key,
                    Arc::new(move |msg: &[u8]| {
                        let sig = signer.sign(msg).map_err(|e| {
                            MLSError::Cryptography(format!("sign with SignatureKeyPair: {e:?}"))
                        })?;
                        sig.as_slice().try_into().map_err(|_| {
                            MLSError::Cryptography("Ed25519 signature is not 64 bytes".to_string())
                        })
                    }),
                ));
            }

            if let Some(signer_json) = self
                .db
                .read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?
            {
                let signer: SignatureKeyPair = serde_json::from_str(&signer_json).map_err(|e| {
                    MLSError::Internal(format!("deserialize enrolled_signer_json: {e}"))
                })?;
                let pub_key: [u8; 32] = signer.public().try_into().map_err(|_| {
                    MLSError::Cryptography("enrolled signer public key is not 32 bytes".to_string())
                })?;
                return Ok((
                    pub_key,
                    Arc::new(move |msg: &[u8]| {
                        let sig = signer.sign(msg).map_err(|e| {
                            MLSError::Cryptography(format!("sign with SignatureKeyPair: {e:?}"))
                        })?;
                        sig.as_slice().try_into().map_err(|_| {
                            MLSError::Cryptography("Ed25519 signature is not 64 bytes".to_string())
                        })
                    }),
                ));
            }

            Err(MLSError::InvalidState(
                "MLS device Ed25519 signer is not enrolled yet".to_string(),
            ))
        }

        /// Build a canonical Ed25519-signed `blue.catbird.chat.registerPushGateway` payload (`D2`, `M-F06`).
        pub fn build_signed_push_gateway_registration(
            &self,
            gateway_url: &str,
            app_id: &str,
            push_key: &str,
            enabled: bool,
        ) -> Result<SignedPushGatewayRegistration, MLSError> {
            let device_uuid =
                uuid::Uuid::parse_str(self.config.device_id.trim()).map_err(|_| {
                    MLSError::invalid_input(
                        "CatbirdMlsClientConfig.device_id must be a canonical UUIDv4",
                    )
                })?;
            if device_uuid.get_version_num() != 4 {
                return Err(MLSError::invalid_input(
                    "CatbirdMlsClientConfig.device_id must be UUID version 4",
                ));
            }
            let canonical_device_id = device_uuid.hyphenated().to_string();
            let (pub_key, sign_fn) = self.load_device_ed25519_signer()?;
            let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(pub_key));
            let auth_generation = self
                .db
                .read_tx(|tx| tx.get_account_meta("auth_generation"))?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let signed_at = self.hooks.now_rfc3339_millis();

            let transcript_payload = PushGatewayTranscriptPayload {
                app_id,
                auth_generation,
                device_id: canonical_device_id.clone(),
                enabled,
                gateway_url,
                key_id: &key_id,
                push_key,
                signed_at: &signed_at,
            };
            let cbor = serde_ipld_dagcbor::to_vec(&transcript_payload).map_err(|e| {
                MLSError::Internal(format!("encode push gateway transcript DAG-CBOR: {e}"))
            })?;
            let mut transcript =
                Vec::with_capacity(PUSH_GATEWAY_SIGNATURE_DOMAIN.len() + cbor.len());
            transcript.extend_from_slice(PUSH_GATEWAY_SIGNATURE_DOMAIN);
            transcript.extend_from_slice(&cbor);

            let sig_64 = sign_fn(&transcript)?;
            let sig_b64 = BASE64_STANDARD.encode(sig_64);
            let request_json = serde_json::to_string(&serde_json::json!({
                "deviceId": canonical_device_id,
                "keyId": key_id,
                "authGeneration": auth_generation,
                "gatewayUrl": gateway_url,
                "appId": app_id,
                "pushKey": push_key,
                "enabled": enabled,
                "signedAt": signed_at,
                "signature": { "$bytes": sig_b64 },
            }))
            .map_err(|e| MLSError::Internal(format!("serialize registerPushGateway JSON: {e}")))?;

            Ok(SignedPushGatewayRegistration {
                device_id: canonical_device_id,
                key_id,
                auth_generation,
                gateway_url: gateway_url.to_string(),
                app_id: app_id.to_string(),
                push_key: push_key.to_string(),
                enabled,
                signed_at,
                signature_bytes: sig_64.to_vec(),
                request_json,
            })
        }

        /// Commit `acked_seq` locally BEFORE dispatching signed `blue.catbird.chat.acknowledgeEntries` (`I2`, `I6`, `I14`).
        pub fn acknowledge_entries_up_to(
            &self,
            conversation_id: &str,
            up_to_seq: i64,
        ) -> Result<(), MLSError> {
            if up_to_seq < 1 {
                return Err(MLSError::invalid_input(
                    "acknowledge_entries_up_to requires up_to_seq >= 1",
                ));
            }
            let endpoint = format!(
                "{}/xrpc/blue.catbird.chat.acknowledgeEntries",
                self.config.home_ds_endpoint.trim_end_matches('/')
            );
            let device_uuid =
                uuid::Uuid::parse_str(self.config.device_id.trim()).map_err(|_| {
                    MLSError::invalid_input(
                        "CatbirdMlsClientConfig.device_id must be a canonical UUIDv4",
                    )
                })?;
            if device_uuid.get_version_num() != 4 {
                return Err(MLSError::invalid_input(
                    "CatbirdMlsClientConfig.device_id must be UUID version 4",
                ));
            }
            let conv_uuid = uuid::Uuid::parse_str(conversation_id.trim()).map_err(|_| {
                MLSError::invalid_input("conversation_id must be a canonical UUIDv4")
            })?;
            if conv_uuid.get_version_num() != 4 {
                return Err(MLSError::invalid_input(
                    "conversation_id must be UUID version 4",
                ));
            }
            let canonical_device_id = device_uuid.hyphenated().to_string();
            let canonical_conv_id = conv_uuid.hyphenated().to_string();
            let (pub_key, sign_fn) = self.load_device_ed25519_signer()?;
            let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(pub_key));

            let conv_id_db = canonical_conv_id.clone();
            let normalized_did = self.normalized_did.clone();
            let ack_meta = Arc::new(Mutex::new((0_i64, 1_i64)));
            let ack_meta_tx = Arc::clone(&ack_meta);
            let transport = Arc::clone(&self.transport);
            let hooks = self.hooks.clone();

            crate::async_runtime::block_on(persist_entries_then_acknowledge(
                &self.db,
                move |tx| {
                    let row_opt: Option<(i64, i64, i64)> = tx
                        .conn()
                        .query_row(
                            "SELECT last_seq, acked_seq, generation FROM conversations WHERE conversation_id = ?1;",
                            rusqlite::params![conv_id_db],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .optional()
                        .map_err(|e| {
                            MLSError::Internal(format!("query conversation ack bounds: {e}"))
                        })?;
                    let Some((last_seq, current_acked_seq, generation)) = row_opt else {
                        return Ok(Vec::new());
                    };

                    let mut safe_seq = up_to_seq.min(last_seq);

                    // Clamp strictly below any NSE/push entry still awaiting canonical foreground I13 receipt verification.
                    {
                        let mut stmt = tx
                            .conn()
                            .prepare(
                                "SELECT payload_json FROM pending_ops WHERE op_kind = 'native_archive_receipt';",
                            )
                            .map_err(|e| {
                                MLSError::Internal(format!("prepare pending_ops ack clamp: {e}"))
                            })?;
                        let rows = stmt
                            .query_map([], |row| row.get::<_, String>(0))
                            .map_err(|e| {
                                MLSError::Internal(format!("query pending_ops ack clamp: {e}"))
                            })?;
                        for row in rows {
                            let raw = row.map_err(|e| {
                                MLSError::Internal(format!("read pending_ops ack clamp: {e}"))
                            })?;
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                                if val["conversation_id"].as_str() == Some(conv_id_db.as_str()) {
                                    if let Some(p_seq) = val["seq"].as_i64().filter(|s| *s >= 1) {
                                        safe_seq = safe_seq.min(p_seq - 1);
                                    }
                                }
                            }
                        }
                    }

                    // Clamp strictly below any un-archived undecryptable entry gap so transient DS retention is preserved.
                    {
                        let prefix = format!("native.undecryptable:{conv_id_db}:");
                        let mut stmt = tx
                            .conn()
                            .prepare(
                                "SELECT state_key, value_bytes FROM labyrinth_state \
                                 WHERE state_key >= ?1 AND state_key < ?2;",
                            )
                            .map_err(|e| {
                                MLSError::Internal(format!(
                                    "prepare undecryptable gap ack clamp: {e}"
                                ))
                            })?;
                        let upper = format!("native.undecryptable:{conv_id_db};");
                        let rows = stmt
                            .query_map(rusqlite::params![prefix, upper], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                            })
                            .map_err(|e| {
                                MLSError::Internal(format!(
                                    "query undecryptable gap ack clamp: {e}"
                                ))
                            })?;
                        for row in rows {
                            let (_, bytes) = row.map_err(|e| {
                                MLSError::Internal(format!(
                                    "read undecryptable gap ack clamp: {e}"
                                ))
                            })?;
                            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                if let Some(gap_seq) = val["seq"].as_i64().filter(|s| *s >= 1) {
                                    safe_seq = safe_seq.min(gap_seq - 1);
                                }
                            }
                        }
                    }

                    // When an active Labyrinth Space mailbox session is established on this account,
                    // clamp to durable archived watermark (strictly below the lowest unflushed
                    // `labyrinth_queue` item for this conversation).
                    let backup_active = tx
                        .get_labyrinth_state("status_json")?
                        .and_then(|raw| serde_json::from_slice::<LabyrinthBackupStatus>(&raw).ok())
                        .is_some_and(|st| st.backup_enabled)
                        && tx
                            .get_labyrinth_state(&format!("native.session:{normalized_did}"))?
                            .is_some();
                    if backup_active {
                        let min_unflushed: Option<i64> = tx
                            .conn()
                            .query_row(
                                "SELECT MIN(seq) FROM labyrinth_queue WHERE conversation_id = ?1 AND seq >= 1;",
                                rusqlite::params![conv_id_db],
                                |row| row.get(0),
                            )
                            .map_err(|e| {
                                MLSError::Internal(format!(
                                    "query labyrinth_queue ack clamp: {e}"
                                ))
                            })?;
                        if let Some(q_seq) = min_unflushed {
                            safe_seq = safe_seq.min(q_seq - 1);
                        }
                    }

                    if safe_seq < 1 || safe_seq <= current_acked_seq {
                        return Ok(Vec::new());
                    }

                    tx.conn()
                        .execute(
                            "UPDATE conversations SET acked_seq = MAX(acked_seq, ?1) WHERE conversation_id = ?2;",
                            rusqlite::params![safe_seq, conv_id_db],
                        )
                        .map_err(|e| MLSError::Internal(format!("update acked_seq: {e}")))?;
                    let auth_gen = tx
                        .get_account_meta("auth_generation")?
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(1)
                        .max(1);
                    if let Ok(mut guard) = ack_meta_tx.lock() {
                        *guard = (generation.max(0), auth_gen);
                    }
                    Ok(vec![safe_seq])
                },
                move |seqs| async move {
                    let effective_seq = seqs.into_iter().max().unwrap_or(up_to_seq);
                    let (generation, auth_generation) = ack_meta
                        .lock()
                        .map(|g| *g)
                        .unwrap_or((1, 1));
                    let signed_at = hooks.now_rfc3339_millis();
                    let transcript_payload = AckTranscriptPayload {
                        key_id: &key_id,
                        up_to_seq: effective_seq,
                        signed_at: &signed_at,
                        generation,
                        actor_device_id: canonical_device_id.clone(),
                        auth_generation,
                        conversation_id: canonical_conv_id.clone(),
                    };
                    let cbor = serde_ipld_dagcbor::to_vec(&transcript_payload).map_err(|e| {
                        MLSError::Internal(format!("encode ack transcript DAG-CBOR: {e}"))
                    })?;
                    let mut transcript =
                        Vec::with_capacity(ACK_ENTRIES_SIGNATURE_DOMAIN.len() + cbor.len());
                    transcript.extend_from_slice(ACK_ENTRIES_SIGNATURE_DOMAIN);
                    transcript.extend_from_slice(&cbor);
                    let sig_64 = sign_fn(&transcript)?;

                    let body = serde_json::to_vec(&serde_json::json!({
                        "conversationId": canonical_conv_id,
                        "generation": generation,
                        "actorDeviceId": canonical_device_id,
                        "keyId": key_id,
                        "authGeneration": auth_generation,
                        "upToSeq": effective_seq,
                        "signedAt": signed_at,
                        "signature": { "$bytes": BASE64_STANDARD.encode(sig_64) },
                    }))
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                    let resp = transport.execute_http(PlatformHttpRequest {
                        method: "POST".to_string(),
                        url: endpoint,
                        headers: vec![PlatformHttpHeader {
                            name: "content-type".to_string(),
                            value: "application/json".to_string(),
                        }],
                        body: Some(body),
                    })?;
                    if resp.status >= 400 {
                        // Declared codes (`ConversationNotFound` after a close race) reach `sync`.
                        return Err(super::live_plane::chat_response_error(
                            "POST acknowledgeEntries",
                            &resp,
                        ));
                    }
                    Ok(())
                },
            ))
            .map(|_| ())
        }

        // ---------------------------------------------------------------------
        // Labyrinth 1.1 Backup, 40-char Recovery Code, Passkey PRF, PQ OTC, & Revocation
        // ---------------------------------------------------------------------

        pub fn labyrinth_status(&self) -> Result<LabyrinthBackupStatus, MLSError> {
            self.db.read_tx(|tx| {
                let bytes = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                serde_json::from_slice(&bytes)
                    .map_err(|e| MLSError::Internal(format!("parse LabyrinthBackupStatus: {e}")))
            })
        }

        /// Bind a WebAuthn passkey PRF 32-byte output to the Labyrinth virtual device (`Spec §6.7`).
        pub fn register_passkey_prf(
            &self,
            credential_id: Vec<u8>,
            prf_output_32: Vec<u8>,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            if credential_id.is_empty() || prf_output_32.len() != 32 {
                return Err(MLSError::invalid_input(
                    "passkey PRF requires non-empty credential_id and 32-byte PRF output",
                ));
            }
            let prf_output_32 = Zeroizing::new(prf_output_32);
            #[cfg(feature = "labyrinth")]
            self.persist_native_passkey_recovery(&credential_id, &prf_output_32)?;
            #[cfg(not(feature = "labyrinth"))]
            return Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".into(),
            ));
            let now_ms = self.hooks.now_ms();
            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_passkey_prf = true;
                st.recovery_method_stale = false;
                st.rotation_exclusions
                    .retain(|exclusion| exclusion.recovery_method.as_deref() != Some("passkey"));
                tx.put_labyrinth_state("passkey_credential_id", &credential_id, now_ms)?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )?;
                Ok(st)
            })?;
            self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
                epoch_seq: status.epoch_seq,
            });
            Ok(status)
        }

        /// Generate a 6-digit One-Time Code (`OTC`) on an enrolled device (`I16` hybrid `CPace + ML-KEM-768`).
        pub fn initiate_otc_pairing(&self) -> Result<OtcPairingOffer, MLSError> {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            #[cfg(feature = "labyrinth")]
            {
                self.ensure_native_archive_ready_for_otc_offer()?;
            }
            let code = self
                .hooks
                .with_labyrinth_rng(labyrinth::otc::OneTimeCode::generate)
                .map_err(|e| MLSError::Cryptography(format!("generate OneTimeCode: {e}")))?;
            let raw_digits = code.as_str().to_string();
            let formatted_code = code.format_grouped();
            let now_ms = self.hooks.now_ms();
            let expires_at_ms = now_ms.saturating_add(5 * 60 * 1000);
            let mut salt = [0u8; 16];
            self.hooks.fill_bytes(&mut salt);
            let mut hasher = Sha256::new();
            hasher.update(b"catbird.otc.offer.v1\0");
            hasher.update(salt);
            hasher.update(raw_digits.as_bytes());
            let code_digest_hex = hex::encode(hasher.finalize());
            let offer_state = serde_json::json!({
                "salt_hex": hex::encode(salt),
                "code_digest_hex": code_digest_hex,
                "expires_at_ms": expires_at_ms,
                "attempts": 0_u8,
            });
            self.db.write_tx(|tx| {
                let _ = tx.conn().execute(
                    "DELETE FROM labyrinth_state WHERE state_key = 'pending_otc_digits'",
                    [],
                );
                tx.put_labyrinth_state(
                    "pending_otc_offer",
                    &serde_json::to_vec(&offer_state)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )
            })?;
            *self
                .pending_otc_offer_digits
                .lock()
                .map_err(|_| MLSError::lock_poisoned("pending_otc_offer_digits"))? =
                Some(zeroize::Zeroizing::new(raw_digits.clone()));
            Ok(OtcPairingOffer {
                six_digit_code: raw_digits,
                formatted_code,
            })
        }

        /// Start a live 2-device CPace+ML-KEM-768 OTC session as the new device,
        /// publishing the initiator `otcSession` record into `OwnerMailbox`.
        pub fn start_otc_pairing(
            &self,
            six_digit_code: &str,
        ) -> Result<OtcInitiatedSession, MLSError> {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            #[cfg(feature = "labyrinth")]
            {
                self.start_live_otc_pairing(six_digit_code)
            }
            #[cfg(not(feature = "labyrinth"))]
            {
                let _ = six_digit_code;
                Err(MLSError::InvalidState(
                    "Labyrinth feature is disabled".into(),
                ))
            }
        }

        /// Respond to a live 2-device `otcSession` in `OwnerMailbox` as an enrolled device.
        /// Enforces the 5-minute TTL and 3-attempt bound on any locally initiated offer.
        pub fn respond_otc_pairing(
            &self,
            session_id_hex: &str,
            six_digit_code: Option<&str>,
        ) -> Result<(), MLSError> {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            #[cfg(feature = "labyrinth")]
            {
                self.respond_live_otc_pairing(session_id_hex, six_digit_code)
            }
            #[cfg(not(feature = "labyrinth"))]
            {
                let _ = (session_id_hex, six_digit_code);
                Err(MLSError::InvalidState(
                    "Labyrinth feature is disabled".into(),
                ))
            }
        }

        /// Complete a hybrid PQ `CPace + ephemeral ML-KEM-768` OTC handshake (`I16`)
        /// over `OwnerMailbox` (`otcSession`) and advance epoch `E -> E+1`.
        pub fn complete_otc_pairing(
            &self,
            six_digit_code: &str,
        ) -> Result<OtcPairingCompletion, MLSError> {
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
                .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;

            #[cfg(feature = "labyrinth")]
            {
                let has_pending_live = self
                    .pending_otc_initiator
                    .lock()
                    .map(|g| g.is_some())
                    .unwrap_or(false);
                if has_pending_live {
                    return self.complete_live_otc_pairing(parsed.as_str());
                }
                #[cfg(not(any(test, feature = "test-utils", feature = "sim")))]
                {
                    Err(MLSError::InvalidState(
                        "No pending live OTC initiator session; call start_otc_pairing on this device and respond_otc_pairing on an enrolled device first".into(),
                    ))
                }
                #[cfg(any(test, feature = "test-utils", feature = "sim"))]
                if !self.offline_archive_for_test {
                    return Err(MLSError::InvalidState(
                        "No pending live OTC initiator session; call start_otc_pairing on this device and respond_otc_pairing on an enrolled device first".into(),
                    ));
                }
            }

            #[cfg(not(feature = "labyrinth"))]
            {
                let _ = parsed;
                return Err(MLSError::InvalidState(
                    "Labyrinth feature is disabled".into(),
                ));
            }

            #[cfg(all(
                feature = "labyrinth",
                any(test, feature = "test-utils", feature = "sim")
            ))]
            {
                let stored = self
                    .pending_otc_offer_digits
                    .lock()
                    .map_err(|_| MLSError::lock_poisoned("pending_otc_offer_digits"))?
                    .take()
                    .ok_or_else(|| {
                        MLSError::InvalidState("No active offline test OTC offer".into())
                    })?;
                let responder_code = labyrinth::otc::OneTimeCode::parse(stored.as_str())
                    .map_err(|e| MLSError::Internal(format!("stored OTC invalid: {e}")))?;
                let (initiator, init_msg) = self
                    .hooks
                    .with_labyrinth_rng(|| {
                        labyrinth::otc::Initiator::start(&parsed, &self.normalized_did)
                    })
                    .map_err(|e| MLSError::Cryptography(format!("OTC Initiator::start: {e}")))?;
                let ek_len = init_msg.ek_otc.len() as u32;
                let sid = init_msg.sid.to_vec();
                let mut responder =
                    labyrinth::otc::Responder::new(responder_code, &self.normalized_did);
                let (resp_msg, resp_key) = self
                    .hooks
                    .with_labyrinth_rng(|| responder.respond(&init_msg))
                    .map_err(|e| MLSError::Cryptography(format!("OTC Responder::respond: {e}")))?;
                let ct_len = resp_msg.kem_ct.len() as u32;
                let init_key = initiator
                    .finish(&resp_msg)
                    .map_err(|e| MLSError::Cryptography(format!("OTC Initiator::finish: {e}")))?;
                if init_key.as_bytes() != resp_key.as_bytes() {
                    return Err(MLSError::insufficient_permissions(
                        "hybrid PQ CPace + ML-KEM-768 OTC code mismatch",
                    ));
                }
                let now_ms = self.hooks.now_ms();
                #[cfg(feature = "labyrinth")]
                let rotated_remote = self.rotate_native_archive(None)?;
                let new_epoch_seq = self.db.write_tx(|tx| {
                    let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                        MLSError::InvalidState("Labyrinth status not initialized".to_string())
                    })?;
                    let mut st: LabyrinthBackupStatus = serde_json::from_slice(&raw)
                        .map_err(|e| MLSError::Internal(e.to_string()))?;
                    #[cfg(feature = "labyrinth")]
                    {
                        st.epoch_seq = rotated_remote.new_epoch;
                        st.rotation_exclusions = rotated_remote.exclusions.clone();
                    }
                    #[cfg(not(feature = "labyrinth"))]
                    {
                        st.epoch_seq = st.epoch_seq.saturating_add(1);
                    }
                    if !st.active_device_ids.contains(&self.config.device_id) {
                        st.active_device_ids.push(self.config.device_id.clone());
                    }
                    tx.upsert_mutation_journal(&MutationJournalRow {
                        journal_id: format!("otc-epoch-{}", st.epoch_seq),
                        op_type: "epoch_rotation".to_string(),
                        epoch_seq: st.epoch_seq,
                        state_json: serde_json::json!({ "trigger": "otc_pq_pairing" }).to_string(),
                        status: "completed".to_string(),
                        created_at_ms: now_ms,
                        updated_at_ms: now_ms,
                    })?;
                    tx.put_labyrinth_state(
                        "status_json",
                        &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                        now_ms,
                    )?;
                    Ok(st.epoch_seq)
                })?;
                self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
                    epoch_seq: new_epoch_seq,
                });
                Ok(OtcPairingCompletion {
                    session_id: sid,
                    initiator_mlkem768_ek_len: ek_len,
                    responder_mlkem768_ct_len: ct_len,
                    new_epoch_seq,
                })
            }
        }

        /// Revoke a peer Labyrinth device and rotate mailbox epoch `E -> E+1`.
        pub fn revoke_labyrinth_device(
            &self,
            target_device_id: &str,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            if target_device_id.trim().is_empty() {
                return Err(MLSError::invalid_input(
                    "target_device_id must not be empty",
                ));
            }
            if self.is_handle_closed() {
                return Err(MLSError::ContextClosed);
            }
            let now_ms = self.hooks.now_ms();
            #[cfg(feature = "labyrinth")]
            let rotated_remote = self.rotate_native_archive(Some(target_device_id))?;
            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.active_device_ids.retain(|d| d != target_device_id);
                #[cfg(feature = "labyrinth")]
                {
                    st.epoch_seq = rotated_remote.new_epoch;
                    st.rotation_exclusions = rotated_remote.exclusions.clone();
                }
                #[cfg(not(feature = "labyrinth"))]
                {
                    st.epoch_seq = st.epoch_seq.saturating_add(1);
                }
                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("revoke-{target_device_id}-{}", st.epoch_seq),
                    op_type: "device_revocation".to_string(),
                    epoch_seq: st.epoch_seq,
                    state_json: serde_json::json!({ "revokedDeviceId": target_device_id })
                        .to_string(),
                    status: "completed".to_string(),
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                })?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )?;
                Ok(st)
            })?;
            self.notify(PlatformChangeEvent::LabyrinthStatusChanged {
                epoch_seq: status.epoch_seq,
            });
            Ok(status)
        }

        /// Import Space history messages into local `<did_hash>.db` (`I13`).
        /// History does not advance the live entry cursor: missing messages and MLS commits
        /// before the imported sequence must still be reconciled by `sync`.
        pub fn import_conversation_history(
            &self,
            conversation_id: &str,
            messages: Vec<MessageRow>,
        ) -> Result<u32, MLSError> {
            let count = self.db.write_tx(|tx| {
                let mut imported = 0u32;
                for msg in &messages {
                    if msg.conversation_id != conversation_id {
                        return Err(MLSError::invalid_input(
                            "history message conversation_id mismatch",
                        ));
                    }
                    if msg.message_id.trim().is_empty() || msg.seq < 0 {
                        return Err(MLSError::invalid_input(
                            "history message requires non-empty message_id and non-negative seq",
                        ));
                    }
                    normalize_account_did(&msg.sender_did)?;
                    if let Some(raw_del) = tx.get_labyrinth_state(
                        &super::chat_wire::account_deletion_key(conversation_id, &msg.sender_did),
                    )? {
                        let deleted_seq = std::str::from_utf8(&raw_del)
                            .ok()
                            .and_then(|s| s.parse::<i64>().ok())
                            .unwrap_or(i64::MAX);
                        if msg.seq <= deleted_seq {
                            continue;
                        }
                    }
                    if let Some(retained) = tx.get_labyrinth_state(&format!(
                        "native.message:{conversation_id}:{}",
                        msg.message_id
                    ))? {
                        let ev: serde_json::Value = serde_json::from_slice(&retained)
                            .map_err(|e| MLSError::Cryptography(format!("retained archive evidence: {e}")))?;
                        if ev["sender_did"].as_str().is_some_and(|s| s != msg.sender_did.as_str())
                            || ev["plaintext_json"]
                                .as_str()
                                .is_some_and(|p| p != msg.plaintext_json.as_str())
                        {
                            return Err(MLSError::Cryptography(
                                "history message contradicts retained authenticated archive evidence"
                                    .into(),
                            ));
                        }
                    }
                    let gap_key = super::chat_wire::undecryptable_evidence_key(
                        conversation_id,
                        &msg.message_id,
                    );
                    let local = tx.get_message(&msg.message_id)?;
                    let gap = local.is_some() && tx.get_labyrinth_state(&gap_key)?.is_some();
                    if local.is_some() && !gap {
                        continue;
                    }
                    tx.insert_message(msg)?;
                    if gap {
                        tx.conn()
                            .execute(
                                "DELETE FROM labyrinth_state WHERE state_key = ?1",
                                [&gap_key],
                            )
                            .map_err(|error| {
                                MLSError::Internal(format!("clear undecryptable evidence: {error}"))
                            })?;
                    }
                    imported = imported.saturating_add(1);
                }
                Ok(imported)
            })?;
            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_string(),
            });
            Ok(count)
        }

        /// Inspect durable outbox rows persisted in `labyrinth_queue` (`[CB-30]`, `I6`).
        pub fn list_pending_labyrinth_queue(
            &self,
            conversation_id: Option<&str>,
            limit: u32,
        ) -> Result<Vec<QueuedLabyrinthArchivePayload>, MLSError> {
            let rows = self
                .db
                .read_tx(|tx| tx.list_labyrinth_queue(conversation_id, limit as usize))?;
            rows.into_iter()
                .map(|r| self.decode_queue_row(&r))
                .collect()
        }

        fn decode_queue_row(
            &self,
            row: &LabyrinthQueueRow,
        ) -> Result<QueuedLabyrinthArchivePayload, MLSError> {
            serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&row.payload_bytes)
                .map_err(|e| MLSError::Cryptography(format!("invalid archive queue payload: {e}")))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn setup_recovery_code(&self) -> Result<String, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".into(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn restore_with_recovery_code(
            &self,
            _recovery_code_input: &str,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".into(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn restore_with_passkey_prf(
            &self,
            _credential_id: Vec<u8>,
            _prf_output_32: Vec<u8>,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".into(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
            Ok(0)
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn rescue_conversation_on_kick(&self, _conversation_id: &str) -> Result<u32, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn restore_conversation_from_owner_mailbox(
            &self,
            _conversation_id: &str,
        ) -> Result<u32, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn verify_and_reindex_history(&self, _conversation_id: &str) -> Result<u32, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn propose_peer_repin(
            &self,
            _peer_did: &str,
        ) -> Result<PeerRepinProposalInfo, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn repin_peer(
            &self,
            _peer_did: &str,
            _confirmed_head: Vec<u8>,
        ) -> Result<(), MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn upload_conversation_attachment(
            &self,
            _conversation_id: &str,
            _plaintext: Vec<u8>,
            _mime_type: String,
        ) -> Result<UploadedConversationAttachment, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn get_read_state(
            &self,
            _conversation_id: &str,
        ) -> Result<Option<MailboxReadStateRecord>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn advance_read_state(
            &self,
            _conversation_id: &str,
            _candidate_seq: u64,
        ) -> Result<MailboxReadStateRecord, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn list_read_states(&self) -> Result<Vec<MailboxReadStateRecord>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn get_circle_owner_state(
            &self,
            _circle_id: &str,
        ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn put_circle_owner_state(
            &self,
            _state: CircleOwnerStateDto,
            _swap_record_cid: Option<String>,
        ) -> Result<String, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn merge_circle_owner_state(
            &self,
            _update: CircleOwnerStateDto,
        ) -> Result<CircleOwnerStateDto, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn clear_circle_acl_tombstone(
            &self,
            _circle_id: &str,
            _member_did: &str,
        ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn list_circle_owner_states(&self) -> Result<Vec<CircleOwnerStateDto>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn delete_account_data(&self) -> Result<(), MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn retire_current_device(&self) -> Result<(), MLSError> {
            self.sign_out_and_wipe()
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn list_devices(&self) -> Result<Vec<RegisteredDeviceInfo>, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }

        #[cfg(not(feature = "labyrinth"))]
        pub fn revoke_device(
            &self,
            _target_device_id: &str,
        ) -> Result<DeviceRevocationReport, MLSError> {
            Err(MLSError::InvalidState(
                "Labyrinth feature is disabled".to_string(),
            ))
        }
    }

    include!("native_archive.rs");
    #[cfg(feature = "labyrinth")]
    include!("native_archive_space.rs");
    #[cfg(any(test, feature = "test-utils", feature = "sim"))]
    include!("offline_archive.rs");
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use live_sync::{apply_verified_roster_effects, verify_control_entry_receipt_with_key};
#[cfg(not(target_arch = "wasm32"))]
pub use native_client::CatbirdMlsClient;

#[cfg(all(not(target_arch = "wasm32"), feature = "labyrinth", feature = "sim"))]
pub use native_client::convert_platform_space_response_for_sim;
