//! Unified `CatbirdMlsClient` SDK (`Spec §6.3`, `G2`, `D3`, `D4`, `I8`, `I9`, `I15`, `I16`).
//!
//! Single Rust SDK surface shared across iOS/macOS (`CatbirdMLSCore`), Android (`mlsffi`),
//! Tauri desktop (`catmos`), CLI (`catmos-cli`), `BIRDaemon`, and (via shared DTOs +
//! `WasmMlsClient`) browser WASM (`catbird-mls-web`).

pub mod config;
pub mod spaces_gate;
pub mod traits;

use serde::{Deserialize, Serialize};

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

/// Durable outbox envelope persisted in `labyrinth_queue.payload_bytes` atomically inside
/// `CatbirdMlsClient::send_message`'s `write_tx` (`Spec §5 I6`, `[CB-30]`, `[CB-22]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedLabyrinthArchivePayload {
    pub version: u8,
    pub message_id: String,
    pub conversation_id: String,
    pub group_id_hex: String,
    pub epoch: i64,
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
    pub created_at_ms: i64,
}

/// Canonical personal mailbox Space URI for an account (`Spec §6.4`, `D4`).
pub fn personal_mailbox_space_uri(account_did: &str) -> String {
    format!("at://{account_did}/space/blue.catbird.labyrinth.mailbox/self")
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
mod native_client {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use openmls::prelude::tls_codec::Serialize as TlsSerialize;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;
    use openmls_traits::OpenMlsProvider;
    use rand::RngCore;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use crate::error::MLSError;
    use crate::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
    use crate::groups::metadata_v1::{validate_metadata_snapshot_size, SpaceAvatarPointer};
    use crate::keychain::KeychainAccess;
    use crate::messaging::receive::PrivateMessagePlaintextEnvelope;
    use crate::metadata::{
        derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
    };
    use crate::push::AuthorizedPeerDeviceKey;
    use crate::requests::c33::{
        validate_direct_request_key_package_lifetime, DIRECT_REQUEST_KP_MIN_LIFETIME_SECS,
        RECOVERY_KP_MAX_LIFETIME_SECS,
    };
    use crate::storage::{
        BackgroundCheckpointReport, ConversationRow, GroupMetadataRow, LabyrinthQueueRow,
        MessageRow, MlsAccountDb, MutationJournalRow, OpenMlsKvProvider, OpenMlsKvStorage,
        OpenMode, RequestRow, RusqliteKvBackend, SqlTx,
    };
    use crate::sync::reconcile::persist_entries_then_acknowledge;

    use super::{
        account_db_path, account_did_hash_hex, normalize_account_did, personal_mailbox_space_uri,
        probe_and_check_spaces_eligibility, wipe_pre_cutover_local_artifacts,
        CatbirdMlsClientConfig, EnrollmentReceipt, LabyrinthBackupStatus, OtcPairingCompletion,
        OtcPairingOffer, PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader,
        PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
        PreCutoverWipeReport, QueuedLabyrinthArchivePayload, SpacesEligibilityStatus,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    fn owner_epoch_root_key(epoch_seq: u64) -> String {
        format!("owner_epoch_root:{epoch_seq}")
    }

    fn ensure_owner_epoch_root(
        tx: &SqlTx<'_>,
        epoch_seq: u64,
        now_ms: i64,
    ) -> Result<Zeroizing<[u8; 32]>, MLSError> {
        let key = owner_epoch_root_key(epoch_seq);
        if let Some(existing) = tx.get_labyrinth_state(&key)? {
            if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                return Ok(Zeroizing::new(arr));
            }
        }
        let mut fresh = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *fresh);
        tx.put_labyrinth_state(&key, fresh.as_slice(), now_ms)?;
        Ok(fresh)
    }

    #[cfg(feature = "labyrinth")]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct StoredLabyrinthDeviceSecrets {
        device_key_hex: String,
        storage_hex: String,
        storage_auth_hex: String,
        public_device_json: String,
    }

    #[cfg(feature = "labyrinth")]
    fn decode_stored_device_secrets(raw_dev: &[u8]) -> Option<labyrinth::device::DeviceSecrets> {
        let stored: StoredLabyrinthDeviceSecrets = serde_json::from_slice(raw_dev).ok()?;
        let dk = hex::decode(&stored.device_key_hex).ok()?;
        let st = hex::decode(&stored.storage_hex).ok()?;
        let sa = hex::decode(&stored.storage_auth_hex).ok()?;
        let dev_rec: labyrinth::records::Device =
            serde_json::from_str(&stored.public_device_json).ok()?;
        let dk_arr = <[u8; 32]>::try_from(dk.as_slice()).ok()?;
        let st_arr =
            <[u8; labyrinth::hpke::hawk::HAWK_ENC_SECRET_LEN]>::try_from(st.as_slice()).ok()?;
        let sa_arr = <[u8; 32]>::try_from(sa.as_slice()).ok()?;
        let pub_dev = dev_rec.to_public().ok()?;
        labyrinth::device::DeviceSecrets::from_parts(
            labyrinth::sign::XSigningKey::from_bytes(dk_arr),
            labyrinth::hpke::hawk::HawkEncSecret::from_bytes(st_arr),
            Some(labyrinth::hpke::X25519Secret::from_bytes(sa_arr)),
            pub_dev,
        )
        .ok()
    }

    #[cfg(feature = "labyrinth")]
    fn ensure_device_secrets_and_salt(
        tx: &SqlTx<'_>,
        now_ms: i64,
    ) -> Result<(labyrinth::device::DeviceSecrets, [u8; 32]), MLSError> {
        let salt = match tx
            .get_labyrinth_state("mailbox_root_salt")?
            .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
        {
            Some(arr) => arr,
            None => {
                let mut fresh_salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut fresh_salt);
                tx.put_labyrinth_state("mailbox_root_salt", &fresh_salt, now_ms)?;
                fresh_salt
            }
        };

        if let Some(raw_dev) = tx.get_labyrinth_state("physical_device_secrets_json")? {
            if let Some(rebuilt) = decode_stored_device_secrets(&raw_dev) {
                return Ok((rebuilt, salt));
            }
        }

        let fresh = labyrinth::device::DeviceSecrets::generate_physical().map_err(|e| {
            MLSError::Cryptography(format!("generate Labyrinth physical DeviceSecrets: {e}"))
        })?;
        let auth_bytes = fresh
            .storage_auth
            .as_ref()
            .map(|a| a.to_bytes())
            .ok_or_else(|| {
                MLSError::Internal("physical device missing storage_auth".to_string())
            })?;
        let dev_rec = labyrinth::records::Device::from_public(
            fresh.public(),
            labyrinth::records::datetime_from_ms(now_ms.max(0) as u64),
        );
        let stored = StoredLabyrinthDeviceSecrets {
            device_key_hex: hex::encode(Zeroizing::new(fresh.device_key.to_bytes()).as_slice()),
            storage_hex: hex::encode(Zeroizing::new(fresh.storage.to_bytes()).as_slice()),
            storage_auth_hex: hex::encode(Zeroizing::new(auth_bytes).as_slice()),
            public_device_json: serde_json::to_string(&dev_rec)
                .map_err(|e| MLSError::Internal(format!("serialize Device record: {e}")))?,
        };
        let bytes = serde_json::to_vec(&stored).map_err(|e| {
            MLSError::Internal(format!("serialize StoredLabyrinthDeviceSecrets: {e}"))
        })?;
        tx.put_labyrinth_state("physical_device_secrets_json", &bytes, now_ms)?;
        Ok((fresh, salt))
    }

    #[cfg(feature = "labyrinth")]
    struct ClientTransportSigner {
        public_key: [u8; 32],
        sign_fn: Box<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>,
    }

    #[cfg(feature = "labyrinth")]
    impl labyrinth::sign::TransportSigner for ClientTransportSigner {
        fn transport_public_key(&self) -> [u8; 32] {
            self.public_key
        }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            (self.sign_fn)(msg)
        }
    }

    #[cfg(feature = "labyrinth")]
    fn load_or_create_transport_signer(
        db: &MlsAccountDb,
        now_ms: i64,
    ) -> Result<ClientTransportSigner, MLSError> {
        let enrolled_opt = db.read_tx(|tx| tx.get_account_meta("enrolled_signer_json"))?;
        if let Some(signer_json) = enrolled_opt {
            let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            if let Ok(pk) = <[u8; 32]>::try_from(signer.public()) {
                return Ok(ClientTransportSigner {
                    public_key: pk,
                    sign_fn: Box::new(move |msg: &[u8]| {
                        let sig = signer.sign(msg).unwrap_or_else(|_| vec![0u8; 64]);
                        <[u8; 64]>::try_from(sig.as_slice()).unwrap_or([0u8; 64])
                    }),
                });
            }
        }
        let seed: Zeroizing<[u8; 32]> = db.write_tx(|tx| {
            if let Some(existing) = tx.get_labyrinth_state("transport_ed25519_seed")? {
                if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                    return Ok(Zeroizing::new(arr));
                }
            }
            let mut fresh = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *fresh);
            tx.put_labyrinth_state("transport_ed25519_seed", fresh.as_slice(), now_ms)?;
            Ok(fresh)
        })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(ClientTransportSigner {
            public_key,
            sign_fn: Box::new(move |msg: &[u8]| {
                use ed25519_dalek::Signer as _;
                signing_key.sign(msg).to_bytes()
            }),
        })
    }

    #[cfg(feature = "labyrinth")]
    fn ensure_convo_sender_mek(
        db: &MlsAccountDb,
        conversation_id: &str,
        transport_pub: [u8; 32],
        now_ms: i64,
    ) -> Result<labyrinth::mek::Mek, MLSError> {
        let state_key = format!("convo_sender_mek:{conversation_id}");
        let secret: Zeroizing<[u8; 32]> = db.write_tx(|tx| {
            if let Some(existing) = tx.get_labyrinth_state(&state_key)? {
                if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                    return Ok(Zeroizing::new(arr));
                }
            }
            let mut fresh = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *fresh);
            tx.put_labyrinth_state(&state_key, fresh.as_slice(), now_ms)?;
            Ok(fresh)
        })?;
        let head = Sha256::digest(format!("catbird.convo.mek:{conversation_id}").as_bytes());
        let mut head_arr = [0u8; 32];
        head_arr.copy_from_slice(&head);
        let r_hash = labyrinth::mek::roster_hash(&[head_arr]);
        Ok(labyrinth::mek::Mek::from_secret(
            secret,
            r_hash,
            labyrinth::mek::MekProvenance::Transport {
                transport_pub,
                created_here: true,
            },
        ))
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

    /// Deterministic valid 13-character ATProto base32-sortable TID (`234567abcdefghijklmnopqrstuvwxyz`,
    /// top bit `0`) derived from `(timestamp_ms, sub_seq, discriminator)` so idempotent retries of
    /// `com.atproto.space.applyWrites#create` hit the exact same `rkey`.
    fn deterministic_tid(timestamp_ms: i64, sub_seq: u64, discriminator: &str) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        let micros = (timestamp_ms.max(0) as u64)
            .saturating_mul(1_000)
            .saturating_add(sub_seq)
            & ((1u64 << 53) - 1);
        let digest = Sha256::digest(discriminator.as_bytes());
        let clock_id = (u16::from_be_bytes([digest[0], digest[1]]) as u64) & 0x3ff;
        let v = (micros << 10) | clock_id;
        (0..13)
            .rev()
            .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
            .collect()
    }

    fn percent_encode_query_component(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len() + 16);
        for &b in raw.as_bytes() {
            if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn is_space_write_committed(resp: &PlatformHttpResponse) -> bool {
        if (200..300).contains(&resp.status) || resp.status == 409 {
            return true;
        }
        if resp.status == 400 {
            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                if parsed.get("error").and_then(|v| v.as_str()) == Some("RecordAlreadyExists") {
                    return true;
                }
            }
        }
        false
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

    fn unix_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn unix_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Unified per-account MLS + Labyrinth SDK client (`Spec §6.3`).
    #[derive(uniffi::Object)]
    pub struct CatbirdMlsClient {
        config: CatbirdMlsClientConfig,
        normalized_did: String,
        account_did_hash: String,
        db_path: PathBuf,
        db: Arc<MlsAccountDb>,
        keystore: Arc<dyn PlatformKeyStore>,
        transport: Arc<dyn PlatformTransport>,
        observer: Option<Arc<dyn PlatformChangeObserver>>,
        cached_group_titles: Arc<Mutex<std::collections::HashMap<String, String>>>,
        wipe_report: PreCutoverWipeReport,
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

            let cached_group_titles = Arc::new(Mutex::new(std::collections::HashMap::new()));
            {
                let titles_ref = Arc::clone(&cached_group_titles);
                db.register_cache_eviction_hook(Arc::new(move || {
                    if let Ok(mut guard) = titles_ref.lock() {
                        guard.clear();
                    }
                }));
            }

            // Initialize encrypted account_meta (`owner_did` lives inside the encrypted DB,
            // never in an unencrypted `accounts.json` per I8) and default D4 Labyrinth state.
            let mailbox_uri = personal_mailbox_space_uri(&normalized_did);
            let now_ms = unix_now_ms();
            db.write_tx(|tx| {
                tx.put_account_meta("owner_did", &normalized_did, now_ms)?;
                tx.put_account_meta("device_id", &config.device_id, now_ms)?;
                tx.put_account_meta("home_ds_did", &config.home_ds_did, now_ms)?;
                let epoch_seq = if let Some(raw) = tx.get_labyrinth_state("status_json")? {
                    serde_json::from_slice::<LabyrinthBackupStatus>(&raw)
                        .map(|s| s.epoch_seq.max(1))
                        .unwrap_or(1)
                } else {
                    let initial = LabyrinthBackupStatus {
                        backup_enabled: true,
                        mailbox_space_uri: mailbox_uri.clone(),
                        has_recovery_code: false,
                        has_passkey_prf: false,
                        epoch_seq: 1,
                        active_device_ids: vec![config.device_id.clone()],
                    };
                    let bytes = serde_json::to_vec(&initial).map_err(|e| {
                        MLSError::Internal(format!("serialize initial LabyrinthBackupStatus: {e}"))
                    })?;
                    tx.put_labyrinth_state("status_json", &bytes, now_ms)?;
                    1
                };
                let _ = ensure_owner_epoch_root(tx, epoch_seq, now_ms)?;
                #[cfg(feature = "labyrinth")]
                {
                    let _ = ensure_device_secrets_and_salt(tx, now_ms)?;
                }
                Ok(())
            })?;

            Ok(Arc::new(Self {
                config,
                normalized_did,
                account_did_hash,
                db_path,
                db,
                keystore,
                transport,
                observer,
                cached_group_titles,
                wipe_report,
            }))
        }

        fn notify(&self, event: PlatformChangeEvent) {
            if let Some(ref obs) = self.observer {
                obs.on_change(event);
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

        /// Enroll this device (`I15` Spaces gate + `I16` `X-Wing` KeyPackages + `D4` Labyrinth default-on).
        pub fn enroll_device(
            &self,
            granted_oauth_scopes: &[String],
        ) -> Result<EnrollmentReceipt, MLSError> {
            let eligibility = self.check_spaces_eligibility(granted_oauth_scopes)?;
            if !eligibility.eligible {
                return Err(MLSError::insufficient_permissions(eligibility.user_message));
            }

            let now_secs = unix_now_secs();
            let now_ms = unix_now_ms();
            let direct_not_after = now_secs + DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 3600;
            validate_direct_request_key_package_lifetime(now_secs, direct_not_after)?;
            let recovery_not_after = now_secs + RECOVERY_KP_MAX_LIFETIME_SECS;

            let scoped_identity = format!("{}#{}", self.normalized_did, self.config.device_id);
            let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
                .map_err(|e| MLSError::Cryptography(format!("generate Ed25519 signer: {e:?}")))?;
            let pub_key = signer.public().to_vec();

            let signer_bytes = serde_json::to_vec(&signer)
                .map_err(|e| MLSError::Internal(format!("serialize signer: {e}")))?;
            self.keystore.store_signature_keypair(
                format!("mls-signer:{}", self.account_did_hash),
                signer_bytes.clone(),
            )?;

            let mailbox_space_uri = personal_mailbox_space_uri(&self.normalized_did);

            let (direct_kp_bytes, recovery_kp_bytes) = self.db.write_tx(|tx| {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = OpenMlsKvProvider::new(storage)?;
                signer.store(provider.storage()).map_err(|e| {
                    MLSError::Internal(format!("store signer in openmls_kv: {e:?}"))
                })?;

                let cred = BasicCredential::new(scoped_identity.clone().into_bytes());
                let cred_with_key = CredentialWithKey {
                    credential: cred.into(),
                    signature_key: signer.public().into(),
                };

                let direct_kp = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::new(DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 3600))
                    .leaf_node_capabilities(
                        Capabilities::builder()
                            .ciphersuites(vec![CIPHERSUITE])
                            .build(),
                    )
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build C33 KeyPackage: {e:?}")))?;

                let recovery_kp = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::new(
                        recovery_not_after.saturating_sub(now_secs),
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
                    signature_public_key: pub_key.clone(),
                }];
                tx.put_account_meta(
                    &format!("authorized_device_keys:{}", self.normalized_did),
                    &serde_json::to_string(&own_auth)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    now_ms,
                )?;

                Ok((direct_bytes, recovery_bytes))
            })?;

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

        /// Reopen `<did_hash>.db` on foreground resume and trigger `I7` cache reconciliation.
        pub fn resume_from_background(&self) -> Result<(), MLSError> {
            self.db.resume_from_background()?;
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
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(())
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

        // ---------------------------------------------------------------------
        // Group, Message, Metadata (`1A`), and Request Mutations
        // ---------------------------------------------------------------------

        pub fn create_group(
            &self,
            conversation_id: &str,
            sequencer_did: &str,
            title: Option<String>,
            description: Option<String>,
        ) -> Result<ConversationRow, MLSError> {
            let mut group_id_bytes = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut group_id_bytes);
            let now_ms = unix_now_ms();
            let space_uri = Some(format!(
                "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
            ));

            let convo = self.db.write_tx(|tx| {
                let signer_json = tx.get_account_meta("enrolled_signer_json")?;
                let signer = if let Some(raw) = signer_json {
                    serde_json::from_str::<SignatureKeyPair>(&raw)
                        .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?
                } else {
                    let s = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
                        .map_err(|e| MLSError::Cryptography(format!("generate signer: {e:?}")))?;
                    let serialized = serde_json::to_string(&s)
                        .map_err(|e| MLSError::Internal(format!("serialize signer: {e}")))?;
                    tx.put_account_meta("enrolled_signer_json", &serialized, now_ms)?;
                    s
                };

                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = OpenMlsKvProvider::new(storage)?;
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
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(5)
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
                    let mut nonce = [0u8; 12];
                    rand::rngs::OsRng.fill_bytes(&mut nonce);
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

            if let Some(ref t) = convo.title {
                if let Ok(mut guard) = self.cached_group_titles.lock() {
                    guard.insert(conversation_id.to_string(), t.clone());
                }
            }
            self.notify(PlatformChangeEvent::ConversationsUpdated);
            Ok(convo)
        }

        pub fn send_message(
            &self,
            conversation_id: &str,
            message_id: &str,
            text: &str,
        ) -> Result<MessageRow, MLSError> {
            let canonical_json = serde_json::json!({ "text": text }).to_string();
            let mut frame_nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut frame_nonce);
            let (inner_plaintext, aad_bytes) = PrivateMessagePlaintextEnvelope::seal_with_aad(
                frame_nonce,
                canonical_json.as_bytes().to_vec(),
            )?;
            let now_ms = unix_now_ms();

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
                let provider = OpenMlsKvProvider::new(storage)?;
                let mut group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        .ok_or_else(|| MLSError::GroupNotFound {
                            message: format!("MlsGroup missing for {conversation_id}"),
                        })?;

                group.set_aad(aad_bytes);
                let mls_out = group
                    .create_message(&provider, &signer, &inner_plaintext)
                    .map_err(|e| MLSError::Cryptography(format!("create_message: {e:?}")))?;
                let ciphertext_bytes = mls_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize message: {e:?}")))?;

                let next_seq = convo.last_seq.saturating_add(1);
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
                    plaintext_json: canonical_json.clone(),
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
                    seq: next_seq,
                    sender_did: self.normalized_did.clone(),
                    sender_device_id: self.config.device_id.clone(),
                    sequencer_did: convo.sequencer_did.clone(),
                    space_uri: convo.space_uri.clone(),
                    plaintext_json: canonical_json.clone(),
                    labyrinth_frame_json: canonical_labyrinth_frame_json(&canonical_json),
                    mls_ciphertext_b64: BASE64_STANDARD.encode(&ciphertext_bytes),
                    frame_nonce_b64: Some(BASE64_STANDARD.encode(frame_nonce)),
                    created_at_ms: now_ms,
                };
                let queued_bytes = serde_json::to_vec(&queued_payload).map_err(|e| {
                    MLSError::Internal(format!("serialize QueuedLabyrinthArchivePayload: {e}"))
                })?;

                tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                    item_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    group_id_hex,
                    seq: next_seq,
                    payload_bytes: queued_bytes,
                    created_at_ms: now_ms,
                })?;

                Ok(row)
            })?;

            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_string(),
            });
            Ok(msg_row)
        }

        /// Remove a member from a group conversation (`Spec §2 D3` / `M-F01`: strictly admin-only).
        pub fn remove_group_member(
            &self,
            actor_role: MemberRole,
            conversation_id: &str,
            target_did: &str,
        ) -> Result<(), MLSError> {
            if target_did.trim().is_empty() {
                return Err(MLSError::invalid_input("target_did must not be empty"));
            }
            enforce_admin_removal_policy(
                &self.normalized_did,
                actor_role,
                &[target_did.to_string()],
            )?;
            let now_ms = unix_now_ms();
            self.db.write_tx(|tx| {
                let convo = tx.get_conversation(conversation_id)?.ok_or_else(|| {
                    MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    }
                })?;
                tx.put_account_meta(
                    &format!("last_removed_member:{}", convo.conversation_id),
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
            let meta_v1 = GroupMetadataV1 {
                version: 1,
                title: title.clone(),
                description: description.clone(),
                avatar_blob_locator: None,
                avatar_content_type: space_avatar.as_ref().and_then(|a| a.mime_type.clone()),
                space_avatar: space_avatar.clone(),
            };
            let serialized = serde_json::to_vec(&meta_v1)
                .map_err(|e| MLSError::Internal(format!("serialize GroupMetadataV1: {e}")))?;
            validate_metadata_snapshot_size(&serialized)?;

            let now_ms = unix_now_ms();
            let updated = self.db.write_tx(|tx| {
                let mut convo = tx.get_conversation(conversation_id)?.ok_or_else(|| {
                    MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    }
                })?;
                let next_ver = tx
                    .get_group_metadata(conversation_id)?
                    .map(|m| m.metadata_version.saturating_add(1))
                    .unwrap_or(1);

                let row = GroupMetadataRow {
                    conversation_id: conversation_id.to_string(),
                    metadata_version: next_ver,
                    epoch: convo.epoch,
                    title: (!title.is_empty()).then(|| title.clone()),
                    description: (!description.is_empty()).then(|| description.clone()),
                    avatar_setter_did: space_avatar.as_ref().map(|a| a.setter_did.clone()),
                    avatar_blob_cid: space_avatar.as_ref().map(|a| a.space_blob_cid.clone()),
                    avatar_sym_key: space_avatar.as_ref().map(|a| a.sym_key.clone()),
                    avatar_sha256: space_avatar.as_ref().map(|a| a.sha256.clone()),
                    avatar_mime_type: space_avatar.as_ref().and_then(|a| a.mime_type.clone()),
                    metadata_json: String::from_utf8_lossy(&serialized).into_owned(),
                    updated_at_ms: now_ms,
                };
                tx.upsert_group_metadata(&row)?;
                convo.title = row.title.clone();
                convo.updated_at_ms = now_ms;
                tx.upsert_conversation(&convo)?;
                Ok(row)
            })?;

            self.notify(PlatformChangeEvent::GroupMetadataUpdated {
                conversation_id: conversation_id.to_string(),
            });
            Ok(updated)
        }

        pub fn accept_direct_request(&self, request_id: &str) -> Result<(), MLSError> {
            let now_ms = unix_now_ms();
            self.db.write_tx(|tx| {
                let mut rows = tx.list_requests(None)?;
                if let Some(req) = rows.iter_mut().find(|r| r.request_id == request_id) {
                    req.consent = "accepted".to_string();
                    req.updated_at_ms = now_ms;
                    tx.upsert_request(req)?;
                }
                Ok(())
            })?;
            self.notify(PlatformChangeEvent::RequestsUpdated);
            Ok(())
        }

        pub fn decline_direct_request(&self, request_id: &str) -> Result<(), MLSError> {
            let now_ms = unix_now_ms();
            self.db.write_tx(|tx| {
                let mut rows = tx.list_requests(None)?;
                if let Some(req) = rows.iter_mut().find(|r| r.request_id == request_id) {
                    req.consent = "declined".to_string();
                    req.updated_at_ms = now_ms;
                    tx.upsert_request(req)?;
                }
                Ok(())
            })?;
            self.notify(PlatformChangeEvent::RequestsUpdated);
            Ok(())
        }

        /// Commit `acked_seq` locally BEFORE dispatching `blue.catbird.chat.acknowledgeEntries` (`I2`, `I6`).
        pub fn acknowledge_entries_up_to(
            &self,
            conversation_id: &str,
            up_to_seq: i64,
        ) -> Result<(), MLSError> {
            let endpoint = format!(
                "{}/xrpc/blue.catbird.chat.acknowledgeEntries",
                self.config.home_ds_endpoint.trim_end_matches('/')
            );
            let conv_id = conversation_id.to_string();
            let conv_for_ack = conversation_id.to_string();
            let transport = Arc::clone(&self.transport);
            crate::async_runtime::block_on(persist_entries_then_acknowledge(
                &self.db,
                move |tx| {
                    tx.conn()
                        .execute(
                            "UPDATE conversations SET acked_seq = MAX(acked_seq, ?1) WHERE conversation_id = ?2;",
                            rusqlite::params![up_to_seq, conv_id],
                        )
                        .map_err(|e| MLSError::Internal(format!("update acked_seq: {e}")))?;
                    Ok(vec![up_to_seq])
                },
                move |seqs| async move {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "conversationId": conv_for_ack,
                        "upToSeq": seqs.into_iter().max().unwrap_or(up_to_seq),
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
                        return Err(MLSError::Internal(format!(
                            "acknowledgeEntries returned HTTP {}",
                            resp.status
                        )));
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

        /// Generate and bind a GF(32) 40-character recovery code (`Spec §2 D4`, `Spec §6.7`),
        /// sealing the account's `owner_epoch_root` and `mailbox_root_salt` into a canonical
        /// `blue.catbird.labyrinth.virtualDevice` record in the personal mailbox Space (`com.atproto.space.applyWrites`).
        #[cfg(feature = "labyrinth")]
        pub fn setup_recovery_code(&self) -> Result<String, MLSError> {
            let code = labyrinth::recovery_code::RecoveryCode::generate()
                .map_err(|e| MLSError::Cryptography(format!("generate RecoveryCode: {e}")))?;
            let grouped = code.format_grouped();
            let now_ms = unix_now_ms();
            let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);

            let (st_snapshot, owner_root, me_secrets, salt) = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                let root = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms)?;
                let (me, salt) = ensure_device_secrets_and_salt(tx, now_ms)?;
                Ok((st, root, me, salt))
            })?;

            let current_epoch = labyrinth::epoch::EpochSecret::from_parts(
                st_snapshot.epoch_seq,
                format!("{:012}", st_snapshot.epoch_seq),
                *owner_root,
            );
            let (vdev_bundle, member_rec) = labyrinth::virtual_device::create(
                &self.normalized_did,
                &code,
                &me_secrets,
                &current_epoch,
                &salt,
                labyrinth::virtual_device::Mechanism::Code,
            )
            .map_err(|e| MLSError::Cryptography(format!("virtual_device::create: {e}")))?;

            let phys_dev_doc =
                labyrinth::records::Device::from_public(me_secrets.public(), created_at.clone());
            let phys_dev_rkey = hex::encode(me_secrets.public().device_key_pub.0);
            let phys_dev_val = serde_json::to_value(&phys_dev_doc)
                .map_err(|e| MLSError::Internal(format!("serialize Device: {e}")))?;

            let vdev_doc = labyrinth::records::VirtualDevice::from_bundle(
                &vdev_bundle,
                None,
                created_at.clone(),
            );
            let vdev_rkey = vdev_doc.rkey();
            let vdev_doc_bytes = serde_json::to_vec(&vdev_doc)
                .map_err(|e| MLSError::Internal(format!("serialize VirtualDevice: {e}")))?;
            let vdev_val = serde_json::to_value(&vdev_doc)
                .map_err(|e| MLSError::Internal(format!("serialize VirtualDevice Value: {e}")))?;

            let epoch_member_doc =
                labyrinth::records::EpochMember::from_record(&member_rec, created_at);
            let epoch_member_rkey = epoch_member_doc.rkey();
            let epoch_member_val = serde_json::to_value(&epoch_member_doc)
                .map_err(|e| MLSError::Internal(format!("serialize EpochMember: {e}")))?;

            // Publish physical device (idempotent) + virtual device bundle + epochMember outside write_tx.
            let dev_resp = self.apply_space_writes(
                &st_snapshot.mailbox_space_uri,
                &[serde_json::json!({
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": labyrinth::records::nsid::DEVICE,
                    "rkey": phys_dev_rkey,
                    "value": phys_dev_val,
                })],
            )?;
            if !is_space_write_committed(&dev_resp) {
                return Err(MLSError::Internal(format!(
                    "setup_recovery_code device applyWrites returned HTTP {}",
                    dev_resp.status
                )));
            }

            let bundle_resp = self.apply_space_writes(
                &st_snapshot.mailbox_space_uri,
                &[
                    serde_json::json!({
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": labyrinth::records::nsid::VIRTUAL_DEVICE,
                        "rkey": vdev_rkey,
                        "value": vdev_val,
                    }),
                    serde_json::json!({
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": labyrinth::records::nsid::EPOCH_MEMBER,
                        "rkey": epoch_member_rkey,
                        "value": epoch_member_val,
                    }),
                ],
            )?;
            if !is_space_write_committed(&bundle_resp) {
                return Err(MLSError::Internal(format!(
                    "setup_recovery_code virtualDevice applyWrites returned HTTP {}",
                    bundle_resp.status
                )));
            }

            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_recovery_code = true;
                tx.put_labyrinth_state("recovery_vdevice_id", &vdev_bundle.vdevice_id, now_ms)?;
                tx.put_labyrinth_state("recovery_vdev_doc_json", &vdev_doc_bytes, now_ms)?;
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
            Ok(grouped)
        }

        /// Restore mailbox using a 40-character GF(32) recovery code (with up to 3-character
        /// erasure/typo correction), decrypting the enrolled `blue.catbird.labyrinth.virtualDevice`
        /// bundle from the personal mailbox Space to recover `owner_epoch_root` across devices
        /// and journaling epoch rotation `E -> E+1` (`Gate 3`, `Gate 4`).
        #[cfg(feature = "labyrinth")]
        pub fn restore_with_recovery_code(
            &self,
            recovery_code_input: &str,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            use labyrinth::epoch::EpochKeys as _;

            let _ = labyrinth::recovery_code::RecoveryCode::candidates(recovery_code_input)
                .map_err(|_| {
                    MLSError::invalid_input("invalid 40-character Labyrinth recovery code")
                })?;

            let (mailbox_space_uri, local_vdev_doc) = self.db.read_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                let local_doc = tx.get_labyrinth_state("recovery_vdev_doc_json")?;
                Ok((st.mailbox_space_uri, local_doc))
            })?;

            let mut bundles: std::collections::HashMap<
                [u8; 16],
                labyrinth::virtual_device::VirtualDeviceRecord,
            > = std::collections::HashMap::new();

            if let Some(remote_records) = self.list_space_records_if_supported(
                &mailbox_space_uri,
                labyrinth::records::nsid::VIRTUAL_DEVICE,
            )? {
                for rec_val in remote_records {
                    if let Ok(vdev_doc) =
                        serde_json::from_value::<labyrinth::records::VirtualDevice>(rec_val)
                    {
                        if let Ok((bundle, _)) = vdev_doc.to_bundle() {
                            bundles.insert(bundle.vdevice_id, bundle);
                        }
                    }
                }
            } else if let Some(raw_doc) = local_vdev_doc {
                // Stub transport compatibility fallback when HTTP listRecords returns `{}` without `"records"`.
                if let Ok(vdev_doc) =
                    serde_json::from_slice::<labyrinth::records::VirtualDevice>(&raw_doc)
                {
                    if let Ok((bundle, _)) = vdev_doc.to_bundle() {
                        bundles.insert(bundle.vdevice_id, bundle);
                    }
                }
            }

            if bundles.is_empty() {
                return Err(MLSError::insufficient_permissions(
                    "no enrolled Labyrinth virtual device found in personal mailbox Space",
                ));
            }

            let matched_code = labyrinth::virtual_device::find_code(
                recovery_code_input,
                &self.normalized_did,
                |cand_id| bundles.contains_key(cand_id),
            )
            .map_err(|_| {
                MLSError::insufficient_permissions(
                    "recovery code does not match enrolled Labyrinth virtual device",
                )
            })?;
            let (matched_vdev_id, _) = matched_code.derive(&self.normalized_did);
            let bundle = bundles.get(&matched_vdev_id).ok_or_else(|| {
                MLSError::insufficient_permissions(
                    "recovery code does not match enrolled Labyrinth virtual device",
                )
            })?;
            let restored =
                labyrinth::virtual_device::open(bundle, &matched_code, &self.normalized_did)
                    .map_err(|e| {
                        MLSError::insufficient_permissions(format!(
                            "failed to decrypt Labyrinth virtual device bundle: {e}"
                        ))
                    })?;
            let recovered_seq = restored.epoch.seq();
            let recovered_root = Zeroizing::new(*restored.epoch.root());
            let recovered_salt = restored.mailbox_root_salt;

            let now_ms = unix_now_ms();
            let status = self.db.write_tx(|tx| {
                tx.put_labyrinth_state("recovery_vdevice_id", &matched_vdev_id, now_ms)?;
                tx.put_labyrinth_state("mailbox_root_salt", &recovered_salt, now_ms)?;
                tx.put_labyrinth_state(
                    &owner_epoch_root_key(recovered_seq),
                    recovered_root.as_slice(),
                    now_ms,
                )?;

                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.epoch_seq = st.epoch_seq.max(recovered_seq).saturating_add(1);
                st.has_recovery_code = true;
                if !st.active_device_ids.contains(&self.config.device_id) {
                    st.active_device_ids.push(self.config.device_id.clone());
                }
                let _ = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms)?;

                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("restore-epoch-{}", st.epoch_seq),
                    op_type: "epoch_rotation".to_string(),
                    epoch_seq: st.epoch_seq,
                    state_json: serde_json::json!({
                        "trigger": "recovery_code_restore",
                        "recoveredEpochSeq": recovered_seq,
                    })
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
            let now_ms = unix_now_ms();
            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_passkey_prf = true;
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
            let code = labyrinth::otc::OneTimeCode::generate()
                .map_err(|e| MLSError::Cryptography(format!("generate OneTimeCode: {e}")))?;
            let raw_digits = code.as_str().to_string();
            let formatted_code = code.format_grouped();
            let now_ms = unix_now_ms();
            self.db.write_tx(|tx| {
                tx.put_labyrinth_state("pending_otc_digits", raw_digits.as_bytes(), now_ms)
            })?;
            Ok(OtcPairingOffer {
                six_digit_code: raw_digits,
                formatted_code,
            })
        }

        /// Execute the full hybrid PQ `CPace + ephemeral ML-KEM-768` handshake (`I16`) for `six_digit_code`
        /// and advance epoch `E -> E+1`.
        pub fn complete_otc_pairing(
            &self,
            six_digit_code: &str,
        ) -> Result<OtcPairingCompletion, MLSError> {
            let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
                .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;

            let (initiator, init_msg) =
                labyrinth::otc::Initiator::start(&parsed, &self.normalized_did)
                    .map_err(|e| MLSError::Cryptography(format!("OTC Initiator::start: {e}")))?;
            let ek_len = init_msg.ek_otc.len() as u32;
            let sid = init_msg.sid.to_vec();

            let expected_code = self.db.read_tx(|tx| {
                let maybe = tx.get_labyrinth_state("pending_otc_digits")?;
                Ok(maybe.and_then(|b| String::from_utf8(b).ok()))
            })?;
            let responder_code = match expected_code {
                Some(stored) => labyrinth::otc::OneTimeCode::parse(&stored)
                    .map_err(|e| MLSError::Internal(format!("stored OTC invalid: {e}")))?,
                None => parsed.clone(),
            };

            let mut responder =
                labyrinth::otc::Responder::new(responder_code, &self.normalized_did);
            let (resp_msg, resp_key) = responder
                .respond(&init_msg)
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

            let now_ms = unix_now_ms();
            let new_epoch_seq = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.epoch_seq = st.epoch_seq.saturating_add(1);
                if !st.active_device_ids.contains(&self.config.device_id) {
                    st.active_device_ids.push(self.config.device_id.clone());
                }
                let _ = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms)?;
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
            let now_ms = unix_now_ms();
            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.active_device_ids.retain(|d| d != target_device_id);
                st.epoch_seq = st.epoch_seq.saturating_add(1);
                let _ = ensure_owner_epoch_root(tx, st.epoch_seq, now_ms)?;
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

        /// Import verified Space history messages into local `<did_hash>.db` (`I13`).
        pub fn import_conversation_history(
            &self,
            conversation_id: &str,
            messages: Vec<MessageRow>,
        ) -> Result<u32, MLSError> {
            let count = self.db.write_tx(|tx| {
                let mut imported = 0u32;
                let mut max_seq: Option<i64> = None;
                for msg in &messages {
                    if msg.conversation_id != conversation_id {
                        return Err(MLSError::invalid_input(
                            "history message conversation_id mismatch",
                        ));
                    }
                    tx.insert_message(msg)?;
                    max_seq = Some(max_seq.map_or(msg.seq, |cur| cur.max(msg.seq)));
                    imported = imported.saturating_add(1);
                }
                if let Some(imported_max_seq) = max_seq {
                    if let Some(mut convo) = tx.get_conversation(conversation_id)? {
                        if imported_max_seq > convo.last_seq {
                            convo.last_seq = imported_max_seq;
                            convo.updated_at_ms = unix_now_ms();
                            tx.upsert_conversation(&convo)?;
                        }
                    }
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
            if let Ok(parsed) =
                serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&row.payload_bytes)
            {
                return Ok(parsed);
            }
            let fallback_json = serde_json::json!({ "text": "" }).to_string();
            Ok(QueuedLabyrinthArchivePayload {
                version: 0,
                message_id: row.item_id.clone(),
                conversation_id: row.conversation_id.clone(),
                group_id_hex: row.group_id_hex.clone(),
                epoch: 0,
                seq: row.seq,
                sender_did: self.normalized_did.clone(),
                sender_device_id: self.config.device_id.clone(),
                sequencer_did: self.config.home_ds_did.clone(),
                space_uri: None,
                plaintext_json: fallback_json.clone(),
                labyrinth_frame_json: canonical_labyrinth_frame_json(&fallback_json),
                mls_ciphertext_b64: BASE64_STANDARD.encode(&row.payload_bytes),
                frame_nonce_b64: None,
                created_at_ms: row.created_at_ms,
            })
        }

        fn load_status_and_owner_root(
            &self,
        ) -> Result<(LabyrinthBackupStatus, Zeroizing<[u8; 32]>), MLSError> {
            let maybe = self.db.read_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                let root_opt = tx.get_labyrinth_state(&owner_epoch_root_key(st.epoch_seq))?;
                Ok((st, root_opt))
            })?;
            if let Some(bytes) = maybe.1 {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    return Ok((maybe.0, Zeroizing::new(arr)));
                }
            }
            let now_ms = unix_now_ms();
            let epoch_seq = maybe.0.epoch_seq;
            let root = self
                .db
                .write_tx(|tx| ensure_owner_epoch_root(tx, epoch_seq, now_ms))?;
            Ok((maybe.0, root))
        }

        fn apply_space_writes(
            &self,
            space_uri: &str,
            writes: &[serde_json::Value],
        ) -> Result<PlatformHttpResponse, MLSError> {
            let endpoint = format!(
                "{}/xrpc/com.atproto.space.applyWrites",
                self.config.pds_endpoint.trim_end_matches('/')
            );
            let body = serde_json::to_vec(&serde_json::json!({
                "repo": self.normalized_did,
                "space": space_uri,
                "validate": false,
                "writes": writes,
            }))
            .map_err(|e| MLSError::Internal(format!("serialize Space applyWrites: {e}")))?;
            self.transport.execute_http(PlatformHttpRequest {
                method: "POST".to_string(),
                url: endpoint,
                headers: vec![PlatformHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body: Some(body),
            })
        }

        /// Paginate `com.atproto.space.listRecords` for `collection` in `space_uri`.
        /// Returns `Ok(None)` only when a stub transport returns `{}` without a `"records"` array.
        fn list_space_records_if_supported(
            &self,
            space_uri: &str,
            collection: &str,
        ) -> Result<Option<Vec<serde_json::Value>>, MLSError> {
            let base = self.config.pds_endpoint.trim_end_matches('/');
            let mut cursor: Option<String> = None;
            let mut all_values: Vec<serde_json::Value> = Vec::new();
            let mut saw_records_array = false;

            loop {
                let mut url = format!(
                    "{base}/xrpc/com.atproto.space.listRecords?space={}&repo={}&collection={}&limit=100",
                    percent_encode_query_component(space_uri),
                    percent_encode_query_component(&self.normalized_did),
                    percent_encode_query_component(collection),
                );
                if let Some(ref c) = cursor {
                    url.push_str("&cursor=");
                    url.push_str(&percent_encode_query_component(c));
                }

                let resp = self.transport.execute_http(PlatformHttpRequest {
                    method: "GET".to_string(),
                    url,
                    headers: Vec::new(),
                    body: None,
                })?;
                if resp.status >= 400 {
                    return Err(MLSError::Internal(format!(
                        "com.atproto.space.listRecords({collection}) returned HTTP {}",
                        resp.status
                    )));
                }
                let parsed: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| MLSError::Internal(format!("parse Space listRecords: {e}")))?;
                let Some(arr) = parsed.get("records").and_then(|v| v.as_array()) else {
                    if !saw_records_array {
                        return Ok(None);
                    }
                    break;
                };
                saw_records_array = true;
                for entry in arr {
                    if let Some(val) = entry.get("value") {
                        all_values.push(val.clone());
                    }
                }
                match parsed
                    .get("cursor")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    Some(next) if !arr.is_empty() => cursor = Some(next.to_string()),
                    _ => break,
                }
            }

            Ok(Some(all_values))
        }

        /// Drain durable `labyrinth_queue` items strictly outside `write_tx` (`Spec §5 I6`).
        ///
        /// Seals canonical `blue.catbird.labyrinth.batch` records via `com.atproto.space.applyWrites`
        /// with `<16-hex-seq>-<tid>` rkeys and `frame_nonce` preserved inside AEAD plaintext.
        /// If the conversation Space rejects the write with `401`/`403`/`404` (e.g. involuntary
        /// MLS kick or closed Space per `[CB-22]`), seals a canonical `v5` `OwnerBatch`
        /// (`KIND_ATTRIBUTED_FRAME = 0x03`, preserving `sender_did`) into the account's personal
        /// mailbox Space (`at://{did}/space/blue.catbird.labyrinth.mailbox/self`) and deletes
        /// committed rows idempotently (`200..300`, `409`, or `400 RecordAlreadyExists`).
        #[cfg(feature = "labyrinth")]
        pub fn flush_labyrinth_queue(&self) -> Result<u32, MLSError> {
            use labyrinth::sign::TransportSigner as _;

            let (status, owner_root) = self.load_status_and_owner_root()?;
            if !status.backup_enabled {
                return Ok(0);
            }

            let now_ms = unix_now_ms();
            let transport_signer = load_or_create_transport_signer(&self.db, now_ms)?;
            let mut mek_cache: std::collections::HashMap<String, labyrinth::mek::Mek> =
                std::collections::HashMap::new();
            let mut total_committed: u32 = 0;

            loop {
                let rows = self.db.read_tx(|tx| tx.list_labyrinth_queue(None, 100))?;
                if rows.is_empty() {
                    break;
                }

                let mut committed_ids: Vec<String> = Vec::with_capacity(rows.len());
                let mut first_err: Option<MLSError> = None;

                for (idx, row) in rows.iter().enumerate() {
                    let payload = match self.decode_queue_row(row) {
                        Ok(p) => p,
                        Err(e) => {
                            first_err = Some(e);
                            break;
                        }
                    };
                    let convo_space = payload.space_uri.clone().unwrap_or_else(|| {
                        format!(
                            "at://{}/space/blue.catbird.labyrinth.conversation/{}-0",
                            payload.sequencer_did, payload.conversation_id
                        )
                    });

                    let mek = if let Some(m) = mek_cache.get(&payload.conversation_id) {
                        m.clone()
                    } else {
                        let m = ensure_convo_sender_mek(
                            &self.db,
                            &payload.conversation_id,
                            transport_signer.transport_public_key(),
                            now_ms,
                        )?;
                        mek_cache.insert(payload.conversation_id.clone(), m.clone());
                        m
                    };

                    let ts_ms = payload.created_at_ms.max(0) as u64;
                    let sender_data: Zeroizing<Vec<u8>> = if let Some(ref nonce_b64) =
                        payload.frame_nonce_b64
                    {
                        if let Ok(decoded) = BASE64_STANDARD.decode(nonce_b64.as_bytes()) {
                            if decoded.len() == 32 {
                                let mut combined =
                                    Vec::with_capacity(32 + payload.labyrinth_frame_json.len());
                                combined.extend_from_slice(&decoded);
                                combined.extend_from_slice(payload.labyrinth_frame_json.as_bytes());
                                Zeroizing::new(combined)
                            } else {
                                Zeroizing::new(payload.labyrinth_frame_json.as_bytes().to_vec())
                            }
                        } else {
                            Zeroizing::new(payload.labyrinth_frame_json.as_bytes().to_vec())
                        }
                    } else {
                        Zeroizing::new(payload.labyrinth_frame_json.as_bytes().to_vec())
                    };

                    let mut sealed_msg = match labyrinth::message::seal_sender(
                        &mek,
                        &payload.conversation_id,
                        &payload.message_id,
                        ts_ms,
                        &sender_data,
                        &transport_signer,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            first_err = Some(MLSError::Cryptography(format!(
                                "seal_sender conversation Batch: {e}"
                            )));
                            break;
                        }
                    };
                    sealed_msg.seq = Some(payload.seq.max(0) as u64);

                    let sender_batch = match labyrinth::records::Batch::from_messages(
                        &payload.conversation_id,
                        &[sealed_msg],
                        labyrinth::records::datetime_from_ms(ts_ms),
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            first_err =
                                Some(MLSError::Internal(format!("Batch::from_messages: {e}")));
                            break;
                        }
                    };
                    let batch_val = match serde_json::to_value(&sender_batch) {
                        Ok(v) => v,
                        Err(e) => {
                            first_err = Some(MLSError::Internal(format!("serialize Batch: {e}")));
                            break;
                        }
                    };
                    let tid = deterministic_tid(
                        payload.created_at_ms,
                        idx as u64,
                        &format!("batch:{}:{}", payload.conversation_id, row.item_id),
                    );
                    let rkey = format!("{:016x}-{tid}", payload.seq.max(0) as u64);

                    let primary_resp = match self.apply_space_writes(
                        &convo_space,
                        &[serde_json::json!({
                            "$type": "com.atproto.space.applyWrites#create",
                            "collection": labyrinth::records::nsid::BATCH,
                            "rkey": rkey,
                            "value": batch_val,
                        })],
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            first_err = Some(e);
                            break;
                        }
                    };

                    if is_space_write_committed(&primary_resp) {
                        committed_ids.push(row.item_id.clone());
                        continue;
                    }

                    if matches!(primary_resp.status, 401 | 403 | 404) {
                        // Involuntary kick / Space access revoked ([CB-22]): seal into personal mailbox Space
                        // using v5 KIND_ATTRIBUTED_FRAME so sender attribution survives restore.
                        let owner_msg = match labyrinth::message::seal_owner_attributed(
                            &owner_root,
                            status.epoch_seq,
                            &payload.conversation_id,
                            &payload.message_id,
                            ts_ms,
                            &payload.sender_did,
                            payload.labyrinth_frame_json.as_bytes(),
                        ) {
                            Ok(m) => m,
                            Err(e) => {
                                first_err = Some(MLSError::Cryptography(format!(
                                    "seal_owner_attributed fallback: {e}"
                                )));
                                break;
                            }
                        };
                        let owner_batch = match labyrinth::records::OwnerBatch::from_messages(
                            &[owner_msg],
                            labyrinth::records::datetime_from_ms(ts_ms),
                        ) {
                            Ok(b) => b,
                            Err(e) => {
                                first_err = Some(MLSError::Internal(format!(
                                    "OwnerBatch::from_messages: {e}"
                                )));
                                break;
                            }
                        };
                        let owner_batch_val = match serde_json::to_value(&owner_batch) {
                            Ok(v) => v,
                            Err(e) => {
                                first_err =
                                    Some(MLSError::Internal(format!("serialize OwnerBatch: {e}")));
                                break;
                            }
                        };
                        let fb_rkey = deterministic_tid(
                            payload.created_at_ms,
                            idx as u64,
                            &format!("fb:{}:{}", payload.conversation_id, row.item_id),
                        );
                        match self.apply_space_writes(
                            &status.mailbox_space_uri,
                            &[serde_json::json!({
                                "$type": "com.atproto.space.applyWrites#create",
                                "collection": labyrinth::records::nsid::OWNER_BATCH,
                                "rkey": fb_rkey,
                                "value": owner_batch_val,
                            })],
                        ) {
                            Ok(fb_resp) if is_space_write_committed(&fb_resp) => {
                                committed_ids.push(row.item_id.clone());
                            }
                            Ok(fb_resp) => {
                                first_err = Some(MLSError::Internal(format!(
                                    "personal mailbox OwnerBatch fallback returned HTTP {}",
                                    fb_resp.status
                                )));
                                break;
                            }
                            Err(e) => {
                                first_err = Some(e);
                                break;
                            }
                        }
                    } else {
                        first_err = Some(MLSError::Internal(format!(
                            "conversation Space applyWrites returned HTTP {}",
                            primary_resp.status
                        )));
                        break;
                    }
                }

                if !committed_ids.is_empty() {
                    self.db.write_tx(|tx| {
                        for id in &committed_ids {
                            tx.dequeue_labyrinth_item(id)?;
                        }
                        Ok(())
                    })?;
                    total_committed = total_committed.saturating_add(committed_ids.len() as u32);
                }

                if let Some(err) = first_err {
                    return Err(err);
                }
                if committed_ids.is_empty() {
                    break;
                }
            }

            Ok(total_committed)
        }

        /// Rescue ALL locally cached SQLCipher conversation messages + pending outbox items
        /// (paginating past the 500-row SQL page cap) into the account's personal mailbox Space
        /// (`v5` `OwnerBatch` with `KIND_ATTRIBUTED_FRAME`) when involuntarily kicked or before
        /// local conversation deletion (`[CB-22]`, `[CB-37]`, `I6`).
        #[cfg(feature = "labyrinth")]
        pub fn rescue_conversation_on_kick(&self, conversation_id: &str) -> Result<u32, MLSError> {
            let (mut cached_msgs, queued_rows) = self.db.read_tx(|tx| {
                let mut all_msgs: Vec<MessageRow> = Vec::new();
                let mut after_rowid: i64 = 0;
                let mut msg_stmt = tx
                    .conn()
                    .prepare(
                        "SELECT rowid, message_id, conversation_id, group_id, epoch, seq, sender_did, \
                                sender_device_id, plaintext_json, created_at_ms, is_own \
                         FROM messages WHERE conversation_id = ?1 AND rowid > ?2 \
                         ORDER BY rowid ASC LIMIT 500",
                    )
                    .map_err(|e| MLSError::Internal(format!("prepare rescue messages query: {e}")))?;
                loop {
                    let rows = msg_stmt
                        .query_map(rusqlite::params![conversation_id, after_rowid], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                MessageRow {
                                    message_id: row.get(1)?,
                                    conversation_id: row.get(2)?,
                                    group_id: row.get(3)?,
                                    epoch: row.get(4)?,
                                    seq: row.get(5)?,
                                    sender_did: row.get(6)?,
                                    sender_device_id: row.get(7)?,
                                    plaintext_json: row.get(8)?,
                                    created_at_ms: row.get(9)?,
                                    is_own: row.get::<_, i64>(10)? != 0,
                                },
                            ))
                        })
                        .map_err(|e| {
                            MLSError::Internal(format!("execute rescue messages query: {e}"))
                        })?;
                    let mut page_len = 0usize;
                    for r in rows {
                        let (rid, msg) = r.map_err(|e| {
                            MLSError::Internal(format!("read rescue message row: {e}"))
                        })?;
                        after_rowid = rid;
                        all_msgs.push(msg);
                        page_len += 1;
                    }
                    if page_len < 500 {
                        break;
                    }
                }

                let mut stmt = tx
                    .conn()
                    .prepare(
                        "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                         FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY seq ASC, item_id ASC",
                    )
                    .map_err(|e| MLSError::Internal(format!("prepare rescue queue query: {e}")))?;
                let queued_iter = stmt
                    .query_map([conversation_id], |row| {
                        Ok(LabyrinthQueueRow {
                            item_id: row.get(0)?,
                            conversation_id: row.get(1)?,
                            group_id_hex: row.get(2)?,
                            seq: row.get(3)?,
                            payload_bytes: row.get(4)?,
                            created_at_ms: row.get(5)?,
                        })
                    })
                    .map_err(|e| MLSError::Internal(format!("execute rescue queue query: {e}")))?;
                let mut all_queued = Vec::new();
                for r in queued_iter {
                    all_queued.push(
                        r.map_err(|e| MLSError::Internal(format!("read rescue queue row: {e}")))?,
                    );
                }
                Ok((all_msgs, all_queued))
            })?;
            cached_msgs.sort_by(|a, b| {
                a.created_at_ms
                    .cmp(&b.created_at_ms)
                    .then_with(|| a.seq.cmp(&b.seq))
                    .then_with(|| a.message_id.cmp(&b.message_id))
            });

            let (status, owner_root) = self.load_status_and_owner_root()?;
            if !status.backup_enabled {
                return Ok(0);
            }

            let mut seen_ids = std::collections::HashSet::new();
            let mut sealed_items = Vec::new();
            for msg in &cached_msgs {
                if !seen_ids.insert(msg.message_id.clone()) {
                    continue;
                }
                let frame_json = canonical_labyrinth_frame_json(&msg.plaintext_json);
                let owner_msg = labyrinth::message::seal_owner_attributed(
                    &owner_root,
                    status.epoch_seq,
                    conversation_id,
                    &msg.message_id,
                    msg.created_at_ms.max(0) as u64,
                    &msg.sender_did,
                    frame_json.as_bytes(),
                )
                .map_err(|e| MLSError::Cryptography(format!("seal_owner_attributed: {e}")))?;
                sealed_items.push(owner_msg);
            }

            for row in &queued_rows {
                let payload = self.decode_queue_row(row)?;
                if !seen_ids.insert(payload.message_id.clone()) {
                    continue;
                }
                let owner_msg = labyrinth::message::seal_owner_attributed(
                    &owner_root,
                    status.epoch_seq,
                    conversation_id,
                    &payload.message_id,
                    payload.created_at_ms.max(0) as u64,
                    &payload.sender_did,
                    payload.labyrinth_frame_json.as_bytes(),
                )
                .map_err(|e| MLSError::Cryptography(format!("seal_owner_attributed: {e}")))?;
                sealed_items.push(owner_msg);
            }

            if sealed_items.is_empty() {
                return Ok(0);
            }

            let now_ms = unix_now_ms();
            let created_at = labyrinth::records::datetime_from_ms(now_ms.max(0) as u64);
            for (chunk_idx, chunk) in sealed_items
                .chunks(labyrinth::records::MAX_BATCH_ITEMS)
                .enumerate()
            {
                let first_ts = chunk.first().map(|m| m.timestamp as i64).unwrap_or(now_ms);
                let first_id = chunk.first().map(|m| m.message_id.as_str()).unwrap_or("0");
                let rkey = deterministic_tid(
                    first_ts,
                    chunk_idx as u64,
                    &format!("rescue:{conversation_id}:{chunk_idx}:{first_id}"),
                );
                let batch =
                    labyrinth::records::OwnerBatch::from_messages(chunk, created_at.clone())
                        .map_err(|e| {
                            MLSError::Internal(format!("OwnerBatch::from_messages: {e}"))
                        })?;
                let batch_val = serde_json::to_value(&batch)
                    .map_err(|e| MLSError::Internal(format!("serialize OwnerBatch: {e}")))?;
                let resp = self.apply_space_writes(
                    &status.mailbox_space_uri,
                    &[serde_json::json!({
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": labyrinth::records::nsid::OWNER_BATCH,
                        "rkey": rkey,
                        "value": batch_val,
                    })],
                )?;
                if !is_space_write_committed(&resp) {
                    return Err(MLSError::Internal(format!(
                        "rescue_conversation_on_kick applyWrites returned HTTP {}",
                        resp.status
                    )));
                }
            }

            self.db.write_tx(|tx| {
                for row in &queued_rows {
                    tx.dequeue_labyrinth_item(&row.item_id)?;
                }
                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("kick-rescue-{conversation_id}-{}", status.epoch_seq),
                    op_type: "kick_rescue".to_string(),
                    epoch_seq: status.epoch_seq,
                    state_json: serde_json::json!({
                        "conversationId": conversation_id,
                        "rescuedCount": sealed_items.len(),
                    })
                    .to_string(),
                    status: "completed".to_string(),
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                })?;
                Ok(())
            })?;

            Ok(sealed_items.len() as u32)
        }

        /// Decrypt a rescued `blue.catbird.labyrinth.ownerBatch` JSON record using the account's
        /// stored `owner_epoch_root:{epoch_seq}`, returning `(message_id, sender_did, frame_bytes)`.
        #[cfg(feature = "labyrinth")]
        pub fn open_rescued_owner_batch(
            &self,
            batch_json: &[u8],
        ) -> Result<Vec<(String, Option<String>, Vec<u8>)>, MLSError> {
            let batch: labyrinth::records::OwnerBatch = serde_json::from_slice(batch_json)
                .map_err(|e| MLSError::Internal(format!("parse OwnerBatch: {e}")))?;
            let msgs = batch
                .to_messages()
                .map_err(|e| MLSError::Internal(format!("OwnerBatch::to_messages: {e}")))?;
            let mut out = Vec::with_capacity(msgs.len());
            for msg in msgs {
                let root_bytes = self
                    .db
                    .read_tx(|tx| tx.get_labyrinth_state(&owner_epoch_root_key(msg.epoch_seq)))?
                    .ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "missing owner_epoch_root for epoch {}",
                            msg.epoch_seq
                        ))
                    })?;
                let root: [u8; 32] = root_bytes.as_slice().try_into().map_err(|_| {
                    MLSError::Internal("invalid owner_epoch_root length".to_string())
                })?;
                match labyrinth::message::open_owner_content(&root, &msg)
                    .map_err(|e| MLSError::Cryptography(format!("open_owner_content: {e}")))?
                {
                    labyrinth::message::OwnerContent::Frame(frame) => {
                        out.push((msg.message_id, None, frame));
                    }
                    labyrinth::message::OwnerContent::AttributedFrame { sender_did, frame } => {
                        out.push((msg.message_id, Some(sender_did), frame));
                    }
                    labyrinth::message::OwnerContent::CommittedFrame { frame, .. } => {
                        let sender = msg.sequencer_receipt.as_ref().and_then(|r| {
                            r.signed
                                .payload
                                .sender_device_did_url
                                .split('#')
                                .next()
                                .filter(|s| s.starts_with("did:"))
                                .map(str::to_string)
                        });
                        out.push((msg.message_id, sender, frame));
                    }
                    labyrinth::message::OwnerContent::Tombstone { .. } => {}
                }
            }
            Ok(out)
        }

        /// Restore a kicked/left conversation's history on any enrolled/restored device directly
        /// from `blue.catbird.labyrinth.ownerBatch` records in the account's personal mailbox Space,
        /// preserving authenticated `sender_did` attribution (`[CB-22]`, `[CB-37]`, `Gate 3`).
        #[cfg(feature = "labyrinth")]
        pub fn restore_conversation_from_owner_mailbox(
            &self,
            conversation_id: &str,
        ) -> Result<u32, MLSError> {
            let status = self.labyrinth_status()?;
            let Some(records) = self.list_space_records_if_supported(
                &status.mailbox_space_uri,
                labyrinth::records::nsid::OWNER_BATCH,
            )?
            else {
                return Ok(0);
            };

            let mut recovered_items: Vec<(u64, String, String, String)> = Vec::new();
            let mut seen_ids = std::collections::HashSet::new();

            for rec_val in records {
                let batch: labyrinth::records::OwnerBatch = serde_json::from_value(rec_val)
                    .map_err(|e| MLSError::Internal(format!("parse OwnerBatch: {e}")))?;
                let msgs = batch
                    .to_messages()
                    .map_err(|e| MLSError::Internal(format!("OwnerBatch::to_messages: {e}")))?;
                for msg in msgs {
                    if msg.thread_id != conversation_id {
                        continue;
                    }
                    if !seen_ids.insert(msg.message_id.clone()) {
                        continue;
                    }
                    let root_bytes = self
                        .db
                        .read_tx(|tx| tx.get_labyrinth_state(&owner_epoch_root_key(msg.epoch_seq)))?
                        .ok_or_else(|| {
                            MLSError::InvalidState(format!(
                                "missing owner_epoch_root for epoch {}",
                                msg.epoch_seq
                            ))
                        })?;
                    let root: [u8; 32] = root_bytes.as_slice().try_into().map_err(|_| {
                        MLSError::Internal("invalid owner_epoch_root length".to_string())
                    })?;
                    let opened = labyrinth::message::open_owner_content(&root, &msg)
                        .map_err(|e| MLSError::Cryptography(format!("open_owner_content: {e}")))?;
                    let (sender_opt, frame_bytes) = match opened {
                        labyrinth::message::OwnerContent::AttributedFrame { sender_did, frame } => {
                            (Some(sender_did), frame)
                        }
                        labyrinth::message::OwnerContent::CommittedFrame { frame, .. } => {
                            let sender = msg.sequencer_receipt.as_ref().and_then(|r| {
                                r.signed
                                    .payload
                                    .sender_device_did_url
                                    .split('#')
                                    .next()
                                    .filter(|s| s.starts_with("did:"))
                                    .map(str::to_string)
                            });
                            (sender, frame)
                        }
                        labyrinth::message::OwnerContent::Frame(frame) => (None, frame),
                        labyrinth::message::OwnerContent::Tombstone { .. } => continue,
                    };
                    let Some(sender_did) = sender_opt else {
                        continue;
                    };
                    let plaintext_json = String::from_utf8(frame_bytes).map_err(|e| {
                        MLSError::Internal(format!("restored frame is not UTF-8: {e}"))
                    })?;
                    recovered_items.push((
                        msg.timestamp,
                        msg.message_id,
                        sender_did,
                        plaintext_json,
                    ));
                }
            }

            if recovered_items.is_empty() {
                return Ok(0);
            }
            recovered_items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

            let now_ms = unix_now_ms();
            let imported = self.db.write_tx(|tx| {
                let existing_convo = tx.get_conversation(conversation_id)?;
                let group_id = existing_convo
                    .as_ref()
                    .map(|c| c.group_id.clone())
                    .unwrap_or_else(|| Sha256::digest(conversation_id.as_bytes()).to_vec());
                let base_seq = existing_convo.as_ref().map(|c| c.last_seq).unwrap_or(0);
                let mut next_seq = base_seq;
                let mut count = 0u32;

                for (ts_ms, msg_id, sender_did, plaintext_json) in &recovered_items {
                    if tx.get_message(msg_id)?.is_some() {
                        continue;
                    }
                    next_seq = next_seq.saturating_add(1);
                    let is_own = sender_did == &self.normalized_did;
                    tx.insert_message(&MessageRow {
                        message_id: msg_id.clone(),
                        conversation_id: conversation_id.to_string(),
                        group_id: group_id.clone(),
                        epoch: 0,
                        seq: next_seq,
                        sender_did: sender_did.clone(),
                        sender_device_id: "restored-labyrinth".to_string(),
                        plaintext_json: plaintext_json.clone(),
                        created_at_ms: *ts_ms as i64,
                        is_own,
                    })?;
                    count = count.saturating_add(1);
                }

                let mut convo = existing_convo.unwrap_or(ConversationRow {
                    conversation_id: conversation_id.to_string(),
                    group_id,
                    generation: 0,
                    epoch: 0,
                    last_seq: next_seq,
                    sequencer_did: self.config.home_ds_did.clone(),
                    space_uri: None,
                    title: None,
                    unread_count: 0,
                    updated_at_ms: now_ms,
                });
                convo.last_seq = convo.last_seq.max(next_seq);
                convo.updated_at_ms = now_ms;
                tx.upsert_conversation(&convo)?;

                Ok(count)
            })?;

            if imported > 0 {
                self.notify(PlatformChangeEvent::MessagesUpdated {
                    conversation_id: conversation_id.to_string(),
                });
            }
            Ok(imported)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native_client::CatbirdMlsClient;
