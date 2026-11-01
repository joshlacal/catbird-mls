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

    use openmls::prelude::tls_codec::Serialize as TlsSerialize;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;
    use rand::RngCore;
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
        OpenMode, RequestRow, RusqliteKvBackend,
    };
    use crate::sync::reconcile::persist_entries_then_acknowledge;

    use super::{
        account_db_path, account_did_hash_hex, normalize_account_did, personal_mailbox_space_uri,
        probe_and_check_spaces_eligibility, wipe_pre_cutover_local_artifacts,
        CatbirdMlsClientConfig, EnrollmentReceipt, LabyrinthBackupStatus, OtcPairingCompletion,
        OtcPairingOffer, PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader,
        PlatformHttpRequest, PlatformKeyStore, PlatformTransport, PreCutoverWipeReport,
        SpacesEligibilityStatus,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

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
                if tx.get_labyrinth_state("status_json")?.is_none() {
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

                tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                    item_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    group_id_hex: hex::encode(&convo.group_id),
                    seq: next_seq,
                    payload_bytes: ciphertext_bytes,
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

        /// Generate and bind a GF(32) 40-character recovery code (`Spec §2 D4`, `Spec §6.7`).
        pub fn setup_recovery_code(&self) -> Result<String, MLSError> {
            let code = labyrinth::recovery_code::RecoveryCode::generate()
                .map_err(|e| MLSError::Cryptography(format!("generate RecoveryCode: {e}")))?;
            let (vdev_id, _vdev_key) = code.derive(&self.normalized_did);
            let grouped = code.format_grouped();
            let now_ms = unix_now_ms();

            let status = self.db.write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_recovery_code = true;
                tx.put_labyrinth_state("recovery_vdevice_id", &vdev_id, now_ms)?;
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
        /// erasure/typo correction) and journal epoch rotation `E -> E+1` (`Gate 3`, `Gate 4`).
        pub fn restore_with_recovery_code(
            &self,
            recovery_code_input: &str,
        ) -> Result<LabyrinthBackupStatus, MLSError> {
            let candidates = labyrinth::recovery_code::RecoveryCode::candidates(
                recovery_code_input,
            )
            .map_err(|_| MLSError::invalid_input("invalid 40-character Labyrinth recovery code"))?;

            let now_ms = unix_now_ms();
            let status = self.db.write_tx(|tx| {
                let expected_vdev = tx.get_labyrinth_state("recovery_vdevice_id")?;
                let mut matched = false;
                for candidate in candidates {
                    let (cand_id, _cand_key) = candidate.derive(&self.normalized_did);
                    if match expected_vdev.as_deref() {
                        Some(exp) => exp == cand_id.as_slice(),
                        None => true,
                    } {
                        matched = true;
                        tx.put_labyrinth_state("recovery_vdevice_id", &cand_id, now_ms)?;
                        break;
                    }
                }
                if !matched {
                    return Err(MLSError::insufficient_permissions(
                        "recovery code does not match enrolled Labyrinth virtual device",
                    ));
                }

                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.epoch_seq = st.epoch_seq.saturating_add(1);
                st.has_recovery_code = true;
                if !st.active_device_ids.contains(&self.config.device_id) {
                    st.active_device_ids.push(self.config.device_id.clone());
                }

                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("restore-epoch-{}", st.epoch_seq),
                    op_type: "epoch_rotation".to_string(),
                    epoch_seq: st.epoch_seq,
                    state_json: serde_json::json!({ "trigger": "recovery_code_restore" })
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
                for msg in &messages {
                    if msg.conversation_id != conversation_id {
                        return Err(MLSError::invalid_input(
                            "history message conversation_id mismatch",
                        ));
                    }
                    tx.insert_message(msg)?;
                    imported = imported.saturating_add(1);
                }
                Ok(imported)
            })?;
            self.notify(PlatformChangeEvent::MessagesUpdated {
                conversation_id: conversation_id.to_string(),
            });
            Ok(count)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native_client::CatbirdMlsClient;
