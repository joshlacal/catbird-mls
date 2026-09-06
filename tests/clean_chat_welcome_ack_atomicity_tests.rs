//! Exercise the database boundary before and after canonical Welcome import.
mod epoch_secret_test_support;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{welcome_ack::WelcomeDelivery, MlsCryptoContext};
use catbird_mls::{
    EpochSecretStorage, GroupConfig, KeyPackageData, KeychainAccess, MLSContext, MLSError,
};
use chrono::{SecondsFormat, TimeZone, Utc};
use openmls::prelude::{
    tls_codec::DeserializeBytes as _, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use rusqlite::types::ValueRef;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const DATABASE_KEY: &str = "welcome-atomicity-generated-test-key";
const BOB_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Default)]
struct TestKeychain(Arc<Mutex<HashMap<String, Vec<u8>>>>);

#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.0.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
}

struct RejectEpochExport(Arc<AtomicUsize>);

#[async_trait]
impl EpochSecretStorage for RejectEpochExport {
    async fn store_epoch_secret(&self, _: String, _: u64, _: Vec<u8>) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        false
    }
    async fn get_epoch_secret(&self, _: String, _: u64) -> Option<Vec<u8>> {
        None
    }
    async fn delete_epoch_secret(&self, _: String, _: u64) -> bool {
        true
    }
    async fn delete_epochs_before(&self, _: String, _: u64) -> u32 {
        0
    }
}

struct Fixture {
    bob: Arc<MLSContext>,
    keychain: TestKeychain,
    database: PathBuf,
    delivery: WelcomeDelivery,
    key_package_ref: Vec<u8>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let make_context = |path: &Path, keychain: TestKeychain| {
            let context = MLSContext::new(
                path.to_string_lossy().into_owned(),
                DATABASE_KEY.into(),
                Box::new(keychain),
            )
            .unwrap();
            epoch_secret_test_support::install(&context);
            context
        };
        let alice = make_context(&directory.path().join("alice.db"), TestKeychain::default());
        let keychain = TestKeychain::default();
        let database = directory.path().join("bob.db");
        let bob = make_context(&database, keychain.clone());
        let bob_device = uuid::Uuid::new_v4().to_string();
        let identity = format!("{BOB_DID}#{bob_device}");
        let group = alice
            .create_group(
                format!("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#{}", uuid::Uuid::new_v4()).into_bytes(),
                Some(GroupConfig::default()),
            )
            .unwrap()
            .group_id;
        let package = bob.create_key_package(identity.into_bytes()).unwrap();
        let provider = openmls_libcrux_crypto::Provider::new().unwrap();
        let MlsMessageBodyIn::KeyPackage(package_in) =
            MlsMessageIn::tls_deserialize_exact_bytes(&package.key_package_data)
                .unwrap()
                .extract()
        else {
            panic!("native KeyPackage wrapper");
        };
        let validated_package = package_in
            .validate(provider.crypto(), ProtocolVersion::default())
            .unwrap();
        let expires_at = Utc
            .timestamp_opt(validated_package.life_time().not_after() as i64, 0)
            .single()
            .unwrap()
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let added = alice
            .add_members(
                group.clone(),
                vec![KeyPackageData {
                    data: package.key_package_data,
                }],
            )
            .unwrap();
        alice.merge_pending_commit(group.clone()).unwrap();
        let cid = uuid::Uuid::new_v4().to_string();
        let delivery = WelcomeDelivery::from_value(json!({
            "welcomeId": uuid::Uuid::new_v4().to_string(), "conversationId": cid, "transitionSeq": 3,
            "coordinates": {
                "conversationId": cid, "groupId": STANDARD.encode(&group), "generation": 0,
                "stateVersion": 2, "epoch": 1, "lifecycle": "active",
                "groupContextHash": STANDARD.encode(alice.get_group_context_hash(group.clone()).unwrap()),
                "confirmationTag": STANDARD.encode(alice.get_confirmation_tag(group).unwrap()),
            },
            "status": "pending", "sha256": STANDARD.encode(Sha256::digest(&added.welcome_data)),
            "opaqueWelcome": STANDARD.encode(added.welcome_data), "recipientDid": BOB_DID,
            "recipientDeviceId": bob_device,
            "provenance": {"recoveryRequestId": uuid::Uuid::new_v4().to_string(), "keyPackageRef": STANDARD.encode(&package.hash_ref)},
            "expiresAt": expires_at,
        })).unwrap();
        Self {
            bob,
            keychain,
            database,
            delivery,
            key_package_ref: package.hash_ref,
            _directory: directory,
        }
    }

    fn reopen(&mut self) {
        self.bob.flush_and_prepare_close().unwrap();
        let reopened = MLSContext::new(
            self.database.to_string_lossy().into_owned(),
            DATABASE_KEY.into(),
            Box::new(self.keychain.clone()),
        )
        .expect("strict startup preflight must accept retained native data");
        epoch_secret_test_support::install(&reopened);
        self.bob = reopened;
    }

    fn import(&self, delivery: &WelcomeDelivery) -> Result<catbird_mls::WelcomeResult, MLSError> {
        self.bob.process_welcome_delivery(
            delivery,
            delivery.recipient_identity().into_bytes(),
            None,
        )
    }

    fn has_package(&self) -> bool {
        self.bob
            .debug_check_key_package_hash(hex::encode(&self.key_package_ref))
            .unwrap()
    }

    // Digest exact SQL cell bytes, including manifests and private MLS rows.
    // Comparing digests prevents a failed assertion from printing test keys.
    fn native_rows(&self) -> BTreeMap<String, Vec<[u8; 32]>> {
        let conn = rusqlite::Connection::open(&self.database).unwrap();
        conn.pragma_update(None, "cipher_memory_security", "OFF")
            .unwrap();
        conn.pragma_update(None, "key", DATABASE_KEY).unwrap();
        conn.pragma_update(None, "cipher_plaintext_header_size", 32)
            .unwrap();
        conn.pragma_update(
            None,
            "cipher_salt",
            format!(
                "x'{}'",
                hex::encode(&Sha256::digest(DATABASE_KEY.as_bytes())[..16])
            ),
        )
        .unwrap();
        let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'openmls_%' OR name IN ('mls_manifests','mls_key_package_bundles')) ORDER BY name")
            .unwrap().query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert!(tables.iter().any(|table| table == "openmls_key_packages"));
        tables
            .into_iter()
            .map(|table| {
                assert!(table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
                let mut query = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
                let count = query.column_count();
                let mut rows: Vec<[u8; 32]> = query
                    .query_map([], |row| {
                        let mut hash = Sha256::new();
                        for column in 0..count {
                            let (kind, bytes): (u8, Vec<u8>) = match row.get_ref(column)? {
                                ValueRef::Null => (0, Vec::new()),
                                ValueRef::Integer(value) => (1, value.to_le_bytes().to_vec()),
                                ValueRef::Real(value) => {
                                    (2, value.to_bits().to_le_bytes().to_vec())
                                }
                                ValueRef::Text(value) => (3, value.to_vec()),
                                ValueRef::Blob(value) => (4, value.to_vec()),
                            };
                            hash.update([kind]);
                            hash.update((bytes.len() as u64).to_le_bytes());
                            hash.update(bytes);
                        }
                        Ok(hash.finalize().into())
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                rows.sort_unstable();
                (table, rows)
            })
            .collect()
    }
}

#[test]
fn precommit_coordinate_rejection_preserves_exact_rows_and_reopens_before_retry() {
    let mut fixture = Fixture::new();
    let original = fixture.native_rows();
    for field in ["groupContextHash", "confirmationTag"] {
        let mut envelope = fixture.delivery.envelope.clone();
        envelope["coordinates"][field] = json!(STANDARD.encode([0xa7; 32]));
        let altered = WelcomeDelivery::from_value(envelope).unwrap();
        assert!(
            fixture.import(&altered).is_err(),
            "post-staging {field} mismatch must reject"
        );
        assert!(
            fixture.native_rows() == original,
            "{field} failure must preserve every original native SQL cell"
        );
        // Reopen before any successful import could repair inconsistent rows.
        fixture.reopen();
        assert!(
            fixture.native_rows() == original,
            "restart must preserve the rejected import's original rows"
        );
        assert!(fixture.has_package());
        assert!(fixture.bob.list_welcome_acceptances().unwrap().is_empty());
        assert!(fixture
            .bob
            .get_epoch(fixture.delivery.group_id().unwrap())
            .is_err());
    }
    fixture.import(&fixture.delivery).unwrap();
    assert!(!fixture.has_package());
    assert_eq!(
        fixture
            .bob
            .get_epoch(fixture.delivery.group_id().unwrap())
            .unwrap(),
        1
    );
    assert_eq!(fixture.bob.list_welcome_acceptances().unwrap().len(), 1);
}

#[test]
fn postcommit_epoch_export_failure_retains_receipt_and_reopens_without_reconsuming_package() {
    let mut fixture = Fixture::new();
    let exports = Arc::new(AtomicUsize::new(0));
    fixture
        .bob
        .set_epoch_secret_storage(Box::new(RejectEpochExport(exports.clone())))
        .unwrap();
    assert!(
        fixture.import(&fixture.delivery).is_err(),
        "failed host export must be reported"
    );
    assert_eq!(
        exports.load(Ordering::SeqCst),
        1,
        "fault must occur after native import reaches epoch export"
    );
    assert!(!fixture.has_package());
    assert_eq!(
        fixture
            .bob
            .get_epoch(fixture.delivery.group_id().unwrap())
            .unwrap(),
        1
    );
    let retained = fixture.bob.list_welcome_acceptances().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].delivery, fixture.delivery);
    assert!(!retained[0].projection_completed);
    assert!(retained[0].request_body.is_none());
    assert!(retained[0].terminal_response.is_none());
    let committed = fixture.native_rows();

    fixture.reopen();
    assert!(
        fixture.native_rows() == committed,
        "native restart must preserve the committed group and receipt"
    );
    assert_eq!(fixture.bob.list_welcome_acceptances().unwrap(), retained);
    assert!(!fixture.has_package());
    let mut alternate = fixture.delivery.envelope.clone();
    alternate["welcomeId"] = json!(uuid::Uuid::new_v4().to_string());
    assert!(
        fixture
            .import(&WelcomeDelivery::from_value(alternate).unwrap())
            .is_err(),
        "existing membership cannot authorize an alternate delivery"
    );
    assert!(fixture.native_rows() == committed);

    fixture
        .import(&fixture.delivery)
        .expect("exact receipt retry must resume export despite the consumed package");
    assert!(!fixture.has_package());
    assert!(
        fixture.native_rows() == committed,
        "retry must not repeat native import or replace its receipt"
    );
    assert_eq!(fixture.bob.list_welcome_acceptances().unwrap(), retained);
}
