//! Plan 06 Task 3 (`W2` / Spec §6.2, `G1`, `I4`, `I6`, `I7`, `I10`, `I11`, `I12`, `I13`):
//! Verification of `process_push_notification` (`<= 15 MB` PushExtension profile,
//! zero Tokio runtime, inline `<= 2200` B offline decrypt, 2-epoch-behind + `fetch_required`
//! catch-up with `metadata_snapshots` outside `BEGIN IMMEDIATE`, and `I4` unverified leaf rejection).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tempfile::TempDir;

use catbird_mls::client::config::account_did_hash_hex;
use catbird_mls::messaging::receive::PrivateMessagePlaintextEnvelope;
use catbird_mls::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use catbird_mls::push::{
    process_push_notification, should_inline_push_ciphertext, AuthorizedPeerDeviceKey,
    FetchedMetadataSnapshot, FetchedPushEntry, PushFetchBundle, PushFetchTransport, PushKeystore,
    PushWakePayload, INLINE_CIPHERTEXT_MAX_BYTES,
};
use catbird_mls::storage::{
    ConversationRow, GroupMetadataRow, MlsAccountDb, OpenMlsKvProvider, OpenMlsKvStorage, OpenMode,
    RusqliteKvBackend,
};
use catbird_mls::MLSError;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

fn push_coordinates<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    cid: &str,
    state_version: i64,
) -> serde_json::Value {
    let (gch, tag) =
        catbird_mls::client::chat_wire::compute_group_context_hash_and_tag(group, provider)
            .unwrap();
    serde_json::json!({
        "conversationId": cid, "generation": 0, "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode(group.group_id().as_slice()) },
        "epoch": group.epoch().as_u64(),
        "groupContextHash": { "$bytes": STANDARD.encode(gch) },
        "confirmationTag": { "$bytes": STANDARD.encode(tag) }, "lifecycle": "active",
    })
}

fn set_push_commit_aad<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    cid: &str,
    state_version: i64,
) {
    let mut prior = push_coordinates(group, provider, cid, state_version);
    let cid_bytes = STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes());
    prior["conversationId"] = serde_json::json!(cid_bytes);
    let aad = catbird_mls::orchestrator::canonical_transport::canonical_commit_aad_bytes(
        &serde_json::json!({
            "protocolVersion": "1", "conversationId": cid_bytes, "generation": 0,
            "transitionId": STANDARD.encode(uuid::Uuid::new_v4().as_bytes()), "prior": prior,
        }),
    )
    .unwrap();
    group.set_aad(aad);
}

#[cfg(target_os = "macos")]
fn current_process_thread_count() -> usize {
    #[allow(non_camel_case_types)]
    type mach_port_t = u32;
    #[allow(non_camel_case_types)]
    type thread_act_array_t = *mut mach_port_t;
    #[allow(non_camel_case_types)]
    type mach_msg_type_number_t = u32;

    extern "C" {
        fn mach_task_self() -> mach_port_t;
        fn task_threads(
            target_task: mach_port_t,
            act_list: *mut thread_act_array_t,
            act_list_cnt: *mut mach_msg_type_number_t,
        ) -> i32;
        fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> i32;
        fn vm_deallocate(target_task: mach_port_t, address: usize, size: usize) -> i32;
    }

    unsafe {
        let task = mach_task_self();
        let mut threads: thread_act_array_t = std::ptr::null_mut();
        let mut count: mach_msg_type_number_t = 0;
        let kr = task_threads(task, &mut threads, &mut count);
        assert_eq!(kr, 0, "task_threads failed with kern_return={kr}");
        if !threads.is_null() && count > 0 {
            let slice = std::slice::from_raw_parts(threads, count as usize);
            for &port in slice {
                let _ = mach_port_deallocate(task, port);
            }
            let _ = vm_deallocate(
                task,
                threads as usize,
                (count as usize) * std::mem::size_of::<mach_port_t>(),
            );
        }
        count as usize
    }
}

#[cfg(not(target_os = "macos"))]
fn current_process_thread_count() -> usize {
    1
}

/// Re-executes `exact_test_name` in a dedicated `--test-threads=1` child process when invoked by
/// multi-threaded `cargo test`, preventing sibling `libtest` worker threads from perturbing
/// `mach_task_self()` thread-count and memory-delta measurements (`G1`).
fn ensure_isolated_single_thread_process(exact_test_name: &str) -> bool {
    if std::env::var_os("CATBIRD_PUSH_SINGLE_THREAD_CHILD").is_some() {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .env("CATBIRD_PUSH_SINGLE_THREAD_CHILD", "1")
        .args([
            "--exact",
            exact_test_name,
            "--test-threads=1",
            "--nocapture",
        ])
        .status()
        .expect("spawn isolated single-thread test process");
    assert!(
        status.success(),
        "isolated single-thread probe `{exact_test_name}` failed with {status}"
    );
    true
}

struct MemoryPushKeystore {
    db_keys: Mutex<HashMap<String, [u8; 32]>>,
    sig_keys: Mutex<HashMap<String, Vec<u8>>>,
    dpop_tokens: Mutex<HashMap<String, Option<String>>>,
}

impl MemoryPushKeystore {
    fn new(account_hash: &str, db_key: [u8; 32], token: Option<String>) -> Self {
        let mut db_keys = HashMap::new();
        db_keys.insert(account_hash.to_string(), db_key);
        let mut dpop_tokens = HashMap::new();
        dpop_tokens.insert(account_hash.to_string(), token);
        Self {
            db_keys: Mutex::new(db_keys),
            sig_keys: Mutex::new(HashMap::new()),
            dpop_tokens: Mutex::new(dpop_tokens),
        }
    }
}

impl PushKeystore for MemoryPushKeystore {
    fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        self.db_keys
            .lock()
            .unwrap()
            .get(&account_did_hash)
            .map(|k| k.to_vec())
            .ok_or_else(|| MLSError::Internal(format!("missing db key for {account_did_hash}")))
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.sig_keys.lock().unwrap().get(&key_id).cloned())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(self
            .dpop_tokens
            .lock()
            .unwrap()
            .get(&account_did_hash)
            .cloned()
            .flatten())
    }
}

struct TwoPeerGroupFixture {
    temp_dir: TempDir,
    alice_hash: String,
    alice_db_path: PathBuf,
    alice_db_key: [u8; 32],
    bob_did: String,
    bob_device_id: String,
    bob_signer: SignatureKeyPair,
    bob_db: MlsAccountDb,
    conversation_id: String,
    group_id: Vec<u8>,
}

fn setup_alice_and_bob_group(authorize_bob_in_alice_db: bool) -> TwoPeerGroupFixture {
    let temp_dir = TempDir::new().expect("tempdir");
    let alice_did = "did:plc:alicepush000000000000000";
    let bob_did = "did:plc:bobpush00000000000000000";
    let alice_hash = account_did_hash_hex(alice_did).expect("alice hash");
    let alice_db_key = [0x41u8; 32];
    let bob_db_key = [0x42u8; 32];

    let alice_db_path = temp_dir
        .path()
        .join("catbird-mls")
        .join(format!("{alice_hash}.db"));
    let bob_db_path = temp_dir.path().join("bob-peer").join("bob.db");

    let conversation_id = "a1234567-89ab-4cde-8123-456789abcdef".to_string();
    let group_id_bytes = b"push-group-id-32-bytes-000000001".to_vec();

    let alice_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("alice sig");
    let bob_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("bob sig");
    let bob_pub_key = bob_signer.public().to_vec();
    let alice_pub_key = alice_signer.public().to_vec();

    // 1. Initialize Bob's DB and build Bob's X-Wing KeyPackage.
    let bob_db =
        MlsAccountDb::open_native(&bob_db_path, &bob_db_key, OpenMode::App).expect("bob db");
    let bob_kp = bob_db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(storage)?;
            bob_signer
                .store(provider.storage())
                .map_err(|e| MLSError::Internal(format!("store bob signer: {e:?}")))?;
            let cred = BasicCredential::new(format!("{bob_did}#dev-bob").into_bytes());
            let cred_with_key = CredentialWithKey {
                credential: cred.into(),
                signature_key: bob_signer.public().into(),
            };
            let bundle = KeyPackage::builder()
                .leaf_node_capabilities(
                    Capabilities::builder()
                        .ciphersuites(vec![CIPHERSUITE])
                        .build(),
                )
                .build(CIPHERSUITE, &provider, &bob_signer, cred_with_key)
                .map_err(|e| MLSError::Internal(format!("build bob kp: {e:?}")))?;
            Ok(bundle.key_package().clone())
        })
        .expect("bob kp");

    // 2. Initialize Alice's DB, create the X-Wing group, add Bob, merge Commit, and persist conversation.
    let welcome_bytes = {
        let alice_db = MlsAccountDb::open_native(&alice_db_path, &alice_db_key, OpenMode::App)
            .expect("alice db");
        let welcome_out = alice_db
            .write_tx(|tx| {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = OpenMlsKvProvider::new(storage)?;
                alice_signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store alice signer: {e:?}")))?;
                let cred = BasicCredential::new(format!("{alice_did}#dev-alice").into_bytes());
                let cred_with_key = CredentialWithKey {
                    credential: cred.into(),
                    signature_key: alice_signer.public().into(),
                };
                let join_cfg = MlsGroupJoinConfig::builder()
                    .use_ratchet_tree_extension(true)
                    .build();
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(5)
                    .build();

                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &alice_signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    cred_with_key,
                )
                .map_err(|e| MLSError::Internal(format!("create group: {e:?}")))?;
                let _ = join_cfg;

                let (_commit, welcome_out, _gi) = group
                    .add_members(&provider, &alice_signer, &[bob_kp])
                    .map_err(|e| MLSError::Internal(format!("add bob: {e:?}")))?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Internal(format!("merge add bob: {e:?}")))?;

                let epoch_now = group.epoch().as_u64() as i64;
                let now_ms = 1_700_000_000_000;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &push_coordinates(&group, &provider, &conversation_id, 7).to_string(), now_ms,
                )?;
                tx.put_account_meta("owner_did", alice_did, now_ms)?;
                let alice_keys = vec![AuthorizedPeerDeviceKey {
                    did: alice_did.to_string(),
                    device_id: "dev-alice".to_string(),
                    signature_public_key: alice_pub_key.clone(),
                }];
                tx.put_account_meta(
                    &format!("authorized_device_keys:{alice_did}"),
                    &serde_json::to_string(&alice_keys).unwrap(),
                    now_ms,
                )?;
                if authorize_bob_in_alice_db {
                    let bob_keys = vec![AuthorizedPeerDeviceKey {
                        did: bob_did.to_string(),
                        device_id: "dev-bob".to_string(),
                        signature_public_key: bob_pub_key.clone(),
                    }];
                    tx.put_account_meta(
                        &format!("authorized_device_keys:{bob_did}"),
                        &serde_json::to_string(&bob_keys).unwrap(),
                        now_ms,
                    )?;
                }

                tx.upsert_conversation(&ConversationRow {
                    conversation_id: conversation_id.clone(),
                    group_id: group_id_bytes.clone(),
                    generation: 0,
                    epoch: epoch_now,
                    last_seq: 1,
                    sequencer_did: "did:web:ds.example".to_string(),
                    space_uri: Some(
                        format!("at://did:web:ds.example/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"),
                    ),
                    title: Some("Initial Nest".to_string()),
                    unread_count: 0,
                    updated_at_ms: now_ms,
                })?;

                tx.upsert_group_metadata(&GroupMetadataRow {
                    conversation_id: conversation_id.clone(),
                    metadata_version: 1,
                    epoch: epoch_now,
                    title: Some("Initial Nest".to_string()),
                    description: Some("Initial description".to_string()),
                    avatar_setter_did: None,
                    avatar_blob_cid: None,
                    avatar_sym_key: None,
                    avatar_sha256: None,
                    avatar_mime_type: None,
                    metadata_json: r#"{"version":1,"title":"Initial Nest","description":"Initial description"}"#.to_string(),
                    updated_at_ms: now_ms,
                })?;

                welcome_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize welcome: {e:?}")))
            })
            .expect("alice group setup");
        let _ = alice_db.prepare_for_background().expect("close alice db");
        welcome_out
    };

    // 3. Join Bob from Welcome so Bob can encrypt messages and stage Commits.
    bob_db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(storage)?;
            let mls_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                .map_err(|e| MLSError::Internal(format!("parse welcome: {e:?}")))?;
            let welcome = match mls_in.extract() {
                MlsMessageBodyIn::Welcome(w) => w,
                other => {
                    return Err(MLSError::Internal(format!(
                        "expected welcome, got {other:?}"
                    )))
                }
            };
            let join_cfg = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .max_past_epochs(5)
                .build();
            let staged_join = StagedWelcome::new_from_welcome(&provider, &join_cfg, welcome, None)
                .map_err(|e| MLSError::Internal(format!("stage welcome: {e:?}")))?;
            let _group = staged_join
                .into_group(&provider)
                .map_err(|e| MLSError::Internal(format!("into_group: {e:?}")))?;
            Ok(())
        })
        .expect("bob join welcome");

    TwoPeerGroupFixture {
        temp_dir,
        alice_hash,
        alice_db_path,
        alice_db_key,
        bob_did: bob_did.to_string(),
        bob_device_id: "dev-bob".to_string(),
        bob_signer,
        bob_db,
        conversation_id,
        group_id: group_id_bytes,
    }
}

fn bob_encrypt_app_message(fixture: &TwoPeerGroupFixture, text: &str) -> Vec<u8> {
    let payload_json =
        serde_json::to_string(&catbird_mls::orchestrator::MLSMessagePayload::text(text)).unwrap();
    let (inner_plaintext, aad) =
        PrivateMessagePlaintextEnvelope::seal_with_aad([0x5Au8; 32], payload_json.into_bytes())
            .expect("seal_with_aad");

    fixture
        .bob_db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(storage)?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .map_err(|e| MLSError::Internal(format!("load bob group: {e:?}")))?
                    .expect("bob group present");
            group.set_aad(aad);
            let msg_out = group
                .create_message(&provider, &fixture.bob_signer, &inner_plaintext)
                .map_err(|e| MLSError::Internal(format!("bob create_message: {e:?}")))?;
            msg_out
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize msg: {e:?}")))
        })
        .expect("bob encrypt message")
}

#[test]
fn inline_wake_decrypts_offline_with_zero_tokio_and_enforces_2200b_cutoff() {
    if ensure_isolated_single_thread_process(
        "inline_wake_decrypts_offline_with_zero_tokio_and_enforces_2200b_cutoff",
    ) {
        return;
    }
    let fixture = setup_alice_and_bob_group(true);
    let ciphertext = bob_encrypt_app_message(&fixture, "Offline hello from Bob!");
    assert!(
        ciphertext.len() <= INLINE_CIPHERTEXT_MAX_BYTES,
        "expected inline ciphertext <= 2200 B, got {}",
        ciphertext.len()
    );
    assert!(should_inline_push_ciphertext(&ciphertext));
    assert!(!should_inline_push_ciphertext(&vec![
        0u8;
        INLINE_CIPHERTEXT_MAX_BYTES
            + 1
    ]));

    let keystore = Arc::new(MemoryPushKeystore::new(
        &fixture.alice_hash,
        fixture.alice_db_key,
        None,
    ));

    let wake = PushWakePayload {
        kind: "application_message".to_string(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 2,
        message_id: "msg-inline-002".to_string(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: false,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: Some(ciphertext),
    };

    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "test must run outside any Tokio runtime"
    );
    let threads_before = current_process_thread_count();

    let preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore.clone(),
        None,
        &wake,
    )
    .expect("offline inline push decrypt");

    let threads_after = current_process_thread_count();
    assert_eq!(
        threads_before, threads_after,
        "G1: process_push_notification must spawn zero background worker threads"
    );

    assert_eq!(preview.message_id, "msg-inline-002");
    assert_eq!(preview.sender_did, fixture.bob_did);
    assert_eq!(preview.group_title.as_deref(), Some("Initial Nest"));
    assert_eq!(preview.body, "Offline hello from Bob!");
    assert!(!preview.from_cache);
    assert!(!preview.fallback_generic);
    assert_eq!(
        preview.darwin_notification_name,
        "blue.catbird.mls.nseDidCommit"
    );

    // Duplicate delivery returns cached preview without re-decrypting.
    let cached_preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore.clone(),
        None,
        &wake,
    )
    .expect("cached inline push preview");
    assert!(cached_preview.from_cache);
    assert_eq!(cached_preview.body, "Offline hello from Bob!");

    // I12: inline ciphertext > 2200 B with fetch_required=false must be rejected.
    let oversized_wake = PushWakePayload {
        message_id: "msg-oversized-003".to_string(),
        entry_seq: 3,
        inline_ciphertext: Some(vec![0xAB; INLINE_CIPHERTEXT_MAX_BYTES + 1]),
        ..wake
    };
    let err = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore,
        None,
        &oversized_wake,
    )
    .expect_err("oversized inline wake must fail I12");
    assert!(matches!(err, MLSError::InvalidInput { .. }));
}

#[test]
fn fetch_required_and_two_epoch_behind_wake_fetches_outside_write_tx_and_decrypts_metadata() {
    if ensure_isolated_single_thread_process(
        "fetch_required_and_two_epoch_behind_wake_fetches_outside_write_tx_and_decrypts_metadata",
    ) {
        return;
    }
    let fixture = setup_alice_and_bob_group(false);
    let gap_message_id = "b2234567-89ab-4cde-8123-456789abcdef";
    let gap_entry_id = "c2234567-89ab-4cde-8123-456789abcdef";

    // Clear Alice's cached group metadata so push processor also refreshes metadata_snapshots!
    {
        let alice_db =
            MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
                .expect("reopen alice db");
        alice_db
            .write_tx(|tx| {
                tx.conn()
                    .execute("DELETE FROM group_metadata_cache;", [])
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                tx.conn()
                    .execute("UPDATE conversations SET title = NULL;", [])
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                Ok(())
            })
            .expect("clear cached metadata");
        let _ = alice_db.prepare_for_background().expect("close alice db");
    }

    // Bob performs TWO self_update Commits (advancing epoch 1 -> 2 -> 3), seals GroupMetadataV1
    // at epoch 3, and encrypts an ApplicationMessage at epoch 3 (seq 4).
    let (commit_e2_bytes, commit_e3_bytes, snapshot_e3, app_msg_e3_bytes) = fixture
        .bob_db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(storage)?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .map_err(|e| MLSError::Internal(format!("load bob group: {e:?}")))?
                    .expect("bob group");

            set_push_commit_aad(&mut group, &provider, &fixture.conversation_id, 7);
            let commit_1_bundle = group
                .self_update(
                    &provider,
                    &fixture.bob_signer,
                    LeafNodeParameters::default(),
                )
                .map_err(|e| MLSError::Internal(format!("self_update 1: {e:?}")))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|e| MLSError::Internal(format!("merge 1: {e:?}")))?;
            let c1 = commit_1_bundle
                .into_commit()
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("ser c1: {e:?}")))?;

            set_push_commit_aad(&mut group, &provider, &fixture.conversation_id, 8);
            let commit_2_bundle = group
                .self_update(
                    &provider,
                    &fixture.bob_signer,
                    LeafNodeParameters::default(),
                )
                .map_err(|e| MLSError::Internal(format!("self_update 2: {e:?}")))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|e| MLSError::Internal(format!("merge 2: {e:?}")))?;
            let c2 = commit_2_bundle
                .into_commit()
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("ser c2: {e:?}")))?;

            let target_epoch = group.epoch().as_u64();
            assert_eq!(target_epoch, 3);

            let meta_key = derive_metadata_key_from_group(
                &mut group,
                provider.crypto(),
                provider.storage(),
                &fixture.group_id,
                target_epoch,
            )
            .map_err(|e| MLSError::Internal(format!("derive meta key: {e}")))?;

            let nonce = [0x33u8; 12];
            let meta_v1 = GroupMetadataV1 {
                version: 1,
                title: "Project Peregrine".to_string(),
                description: "Updated across 2 epochs".to_string(),
                avatar_blob_locator: None,
                avatar_content_type: None,
                space_avatar: None,
            };
            let meta_ct = encrypt_metadata_snapshot_with_nonce(
                &meta_key,
                &fixture.group_id,
                target_epoch,
                2,
                &nonce,
                &meta_v1,
            )
            .map_err(|e| MLSError::Internal(format!("encrypt meta: {e}")))?;

            let payload_json = serde_json::to_string(
                &catbird_mls::orchestrator::MLSMessagePayload::text("Caught up 2 epochs in NSE!"),
            ).unwrap();
            let commitment = labyrinth_protocol::receipt::compute_archive_commitment(
                &[0x77u8; 32], payload_json.as_bytes(),
            );
            let (inner_plaintext, _) = PrivateMessagePlaintextEnvelope::seal_with_aad(
                [0x77u8; 32], payload_json.into_bytes(),
            ).expect("seal_with_aad");
            let mut prior = push_coordinates(&group, &provider, &fixture.conversation_id, 9);
            let cid_bytes = STANDARD.encode(uuid::Uuid::parse_str(&fixture.conversation_id).unwrap().as_bytes());
            prior["conversationId"] = serde_json::json!(cid_bytes);
            let aad = catbird_mls::orchestrator::canonical_transport::canonical_application_aad_bytes(
                &serde_json::json!({
                    "protocolVersion": "1", "conversationId": cid_bytes, "generation": 0,
                    "messageId": STANDARD.encode(uuid::Uuid::parse_str(gap_message_id).unwrap().as_bytes()),
                    "prior": prior, "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
                }),
            ).unwrap();
            group.set_aad(aad);
            let msg_out = group
                .create_message(&provider, &fixture.bob_signer, &inner_plaintext)
                .map_err(|e| MLSError::Internal(format!("create_message e3: {e:?}")))?;
            let msg_bytes = msg_out
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("ser msg: {e:?}")))?;

            Ok((
                c1,
                c2,
                FetchedMetadataSnapshot {
                    epoch: target_epoch as i64,
                    metadata_version: 2,
                    nonce: nonce.to_vec(),
                    ciphertext: meta_ct,
                },
                msg_bytes,
            ))
        })
        .expect("bob 2-epoch advance");

    struct VerifyingFetchTransport {
        alice_db_path: PathBuf,
        alice_db_key: [u8; 32],
        bundle: PushFetchBundle,
        bob_key: AuthorizedPeerDeviceKey,
        fetch_calls: AtomicUsize,
        wrote_concurrently_without_busy: AtomicBool,
        threads_during_fetch: AtomicUsize,
    }

    impl PushFetchTransport for VerifyingFetchTransport {
        fn fetch_missing_entries(
            &self,
            _conversation_id: String,
            after_seq: i64,
            chat_dpop_token: String,
        ) -> Result<PushFetchBundle, MLSError> {
            assert_eq!(after_seq, 1);
            assert_eq!(chat_dpop_token, "cached-chat-dpop-jwt");
            assert!(
                tokio::runtime::Handle::try_current().is_err(),
                "G1: transport must NOT be invoked inside a Tokio runtime"
            );
            self.threads_during_fetch
                .store(current_process_thread_count(), Ordering::SeqCst);
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);

            // I6 PROOF: Open a second connection to Alice's SQLite DB with busy_timeout = 0
            // and acquire BEGIN IMMEDIATE right inside the network callback! If
            // process_push_notification held a write transaction across network I/O,
            // this would fail immediately with SQLITE_BUSY.
            let probe_db = MlsAccountDb::open_native(
                &self.alice_db_path,
                &self.alice_db_key,
                OpenMode::PushExtension,
            )?;
            probe_db.write_tx(|tx| {
                tx.conn()
                    .execute_batch("PRAGMA busy_timeout = 0;")
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                tx.put_account_meta("i6_concurrent_probe", "ok", 1_700_000_000_001)?;
                Ok(())
            })?;
            let _ = probe_db.prepare_for_background()?;
            self.wrote_concurrently_without_busy
                .store(true, Ordering::SeqCst);

            Ok(self.bundle.clone())
        }

        fn get_authorized_device_keys(
            &self,
            did: String,
            _chat_dpop_token: Option<String>,
        ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
            if did == self.bob_key.did {
                Ok(vec![self.bob_key.clone()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    let bob_key = AuthorizedPeerDeviceKey {
        did: fixture.bob_did.clone(),
        device_id: fixture.bob_device_id.clone(),
        signature_public_key: fixture.bob_signer.public().to_vec(),
    };

    let transport = Arc::new(VerifyingFetchTransport {
        alice_db_path: fixture.alice_db_path.clone(),
        alice_db_key: fixture.alice_db_key,
        bundle: PushFetchBundle {
            entries: vec![
                FetchedPushEntry {
                    entry_id: "entry-commit-2".to_string(),
                    seq: 2,
                    epoch: 1,
                    entry_kind: "commit".to_string(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: commit_e2_bytes,
                },
                FetchedPushEntry {
                    entry_id: "entry-commit-3".to_string(),
                    seq: 3,
                    epoch: 2,
                    entry_kind: "commit".to_string(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: commit_e3_bytes,
                },
                FetchedPushEntry {
                    entry_id: gap_entry_id.to_string(),
                    seq: 4,
                    epoch: 3,
                    entry_kind: "application_message".to_string(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: app_msg_e3_bytes,
                },
            ],
            metadata_snapshot: Some(snapshot_e3),
            authorized_device_keys: vec![bob_key.clone()],
        },
        bob_key,
        fetch_calls: AtomicUsize::new(0),
        wrote_concurrently_without_busy: AtomicBool::new(false),
        threads_during_fetch: AtomicUsize::new(0),
    });

    // Nest/APNs omit messageId and platform adapters preserve the legacy seq sentinel. The
    // processor must derive the notification identity from authenticated MLS AAD.
    let wake = PushWakePayload {
        kind: "application_message".to_string(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 4,
        message_id: "msg-4".to_string(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: true,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: None,
    };

    // First verify I10: missing/expired cached chat-dpop token NEVER calls transport or OAuth,
    // returning clean "New encrypted message" fallback.
    let expired_keystore = Arc::new(MemoryPushKeystore::new(
        &fixture.alice_hash,
        fixture.alice_db_key,
        None,
    ));
    let fallback_preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        expired_keystore,
        Some(transport.clone()),
        &wake,
    )
    .expect("I10 clean fallback on expired token");
    assert!(fallback_preview.fallback_generic);
    assert_eq!(fallback_preview.body, "New encrypted message");
    assert_eq!(transport.fetch_calls.load(Ordering::SeqCst), 0);

    // Now provide a valid cached chat-dpop token and verify full 2-epoch catch-up + metadata!
    let valid_keystore = Arc::new(MemoryPushKeystore::new(
        &fixture.alice_hash,
        fixture.alice_db_key,
        Some("cached-chat-dpop-jwt".to_string()),
    ));
    let threads_before = current_process_thread_count();
    let preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        valid_keystore,
        Some(transport.clone()),
        &wake,
    )
    .expect("2-epoch catch-up push decrypt");
    let threads_after = current_process_thread_count();

    assert!(
        transport
            .wrote_concurrently_without_busy
            .load(Ordering::SeqCst),
        "I6: network fetch must execute outside BEGIN IMMEDIATE"
    );
    assert_eq!(threads_before, threads_after);
    assert_eq!(
        transport.threads_during_fetch.load(Ordering::SeqCst),
        threads_before,
        "G1: zero worker threads spawned during push network fetch"
    );
    assert_eq!(preview.sender_did, fixture.bob_did);
    assert_eq!(preview.group_title.as_deref(), Some("Project Peregrine"));
    assert_eq!(preview.body, "Caught up 2 epochs in NSE!");
    assert_eq!(preview.epoch, 3);
    assert_eq!(preview.seq, 4);
    assert!(!preview.fallback_generic);
    assert_eq!(preview.message_id, gap_message_id);
    let mismatched_wake = PushWakePayload {
        message_id: uuid::Uuid::new_v4().to_string(),
        ..wake.clone()
    };
    let mismatch = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        Arc::new(MemoryPushKeystore::new(
            &fixture.alice_hash,
            fixture.alice_db_key,
            Some("cached-chat-dpop-jwt".to_string()),
        )),
        Some(transport.clone()),
        &mismatched_wake,
    )
    .expect_err("supplied wake identity is only a comparator");
    assert!(
        mismatch
            .to_string()
            .contains("messageId differs from authenticated MLS AAD"),
        "{mismatch}"
    );

    let app_db =
        MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
            .unwrap();
    app_db
        .read_tx(|tx| {
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                .unwrap()
                .unwrap();
            let persisted: serde_json::Value = serde_json::from_str(
                &tx.get_account_meta(&format!("conversation_coords:{}", fixture.conversation_id))?
                    .expect("NSE persists authenticated next coordinates"),
            )
            .unwrap();
            assert_eq!(
                persisted,
                push_coordinates(&group, &provider, &fixture.conversation_id, 9)
            );
            assert!(tx.get_message(gap_message_id)?.is_some());
            assert!(
                tx.get_message(gap_entry_id)?.is_none(),
                "transport entryId is not the authenticated messageId"
            );
            let evidence: serde_json::Value = serde_json::from_slice(
                &tx.get_labyrinth_state(&format!(
                    "native.message:{}:{gap_message_id}",
                    fixture.conversation_id
                ))?
                .unwrap(),
            )
            .unwrap();
            assert!(evidence["sequencer_receipt_json"].is_null());
            assert_eq!(evidence["frame_nonce_b64"], STANDARD.encode([0x77u8; 32]));
            let pending: serde_json::Value = serde_json::from_str(
                &tx.get_pending_op("native_archive_receipt", gap_message_id)?
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(pending["entry_id"], gap_entry_id);
            Ok(())
        })
        .unwrap();
}

#[test]
fn unverified_sender_leaf_key_fails_i4_and_never_persists_message() {
    // Initialize Alice's DB WITHOUT Bob's device signature key in authorized_device_keys!
    let fixture = setup_alice_and_bob_group(false);
    let ciphertext = bob_encrypt_app_message(&fixture, "Forged/unverified device wake");

    let keystore = Arc::new(MemoryPushKeystore::new(
        &fixture.alice_hash,
        fixture.alice_db_key,
        None,
    ));

    let wake = PushWakePayload {
        kind: "application_message".to_string(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 2,
        message_id: "msg-unverified-002".to_string(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: false,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: Some(ciphertext),
    };

    let err = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore,
        None,
        &wake,
    )
    .expect_err("unverified sender leaf key must fail I4");

    assert!(
        matches!(err, MLSError::InsufficientPermissions { .. }),
        "expected InsufficientPermissions for I4 violation, got {err:?}"
    );

    // Confirm zero message rows were persisted in Alice's DB.
    let alice_db = MlsAccountDb::open_native(
        &fixture.alice_db_path,
        &fixture.alice_db_key,
        OpenMode::PushExtension,
    )
    .expect("reopen alice db");
    let msgs = alice_db
        .read_tx(|tx| tx.list_messages(&fixture.conversation_id, None, 20))
        .expect("list messages");
    assert!(msgs.is_empty(), "I4 rejection must persist zero messages");
}

#[test]
fn catbird_mls_client_enforces_i8_i9_i15_d3_d4_and_pq_otc() {
    use catbird_mls::client::{
        CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest, PlatformHttpResponse,
        PlatformKeyStore, PlatformTransport, SpacesUnavailableReason,
        REQUIRED_LABYRINTH_OAUTH_SCOPES,
    };
    use catbird_mls::groups::lifecycle::MemberRole;

    struct TestSdkKeystore {
        keys: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl PlatformKeyStore for TestSdkKeystore {
        fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
            let mut g = self.keys.lock().unwrap();
            Ok(g.entry(format!("db:{account_did_hash}"))
                .or_insert_with(|| vec![0x99u8; 32])
                .clone())
        }
        fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(self.keys.lock().unwrap().get(&key_id).cloned())
        }
        fn store_signature_keypair(
            &self,
            key_id: String,
            keypair_bytes: Vec<u8>,
        ) -> Result<(), MLSError> {
            self.keys.lock().unwrap().insert(key_id, keypair_bytes);
            Ok(())
        }
        fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
            self.keys
                .lock()
                .unwrap()
                .retain(|k, _| !k.contains(&account_did_hash));
            Ok(())
        }
        fn load_cached_chat_dpop_token(
            &self,
            account_did_hash: String,
        ) -> Result<Option<String>, MLSError> {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .get(&format!("dpop:{account_did_hash}"))
                .and_then(|b| String::from_utf8(b.clone()).ok()))
        }
        fn store_cached_chat_dpop_token(
            &self,
            account_did_hash: String,
            token: String,
            _expires_at_ms: i64,
        ) -> Result<(), MLSError> {
            self.keys
                .lock()
                .unwrap()
                .insert(format!("dpop:{account_did_hash}"), token.into_bytes());
            Ok(())
        }
    }

    struct TestSdkTransport {
        spaces_supported: AtomicBool,
    }
    impl PlatformTransport for TestSdkTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            if request.url.ends_with("/xrpc/com.atproto.space.getSpace") {
                if self.spaces_supported.load(Ordering::SeqCst) {
                    return Ok(PlatformHttpResponse {
                        status: 400,
                        headers: Vec::new(),
                        body: br#"{"error":"InvalidRequest","message":"Missing space URI"}"#
                            .to_vec(),
                    });
                } else {
                    return Ok(PlatformHttpResponse {
                        status: 404,
                        headers: Vec::new(),
                        body: br#"{"error":"XRPCNotSupported"}"#.to_vec(),
                    });
                }
            }
            Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            })
        }
        fn connect_realtime_stream(
            &self,
            _home_ds_endpoint: String,
            _cursor_seq: Option<i64>,
        ) -> Result<(), MLSError> {
            Ok(())
        }
        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let tmp = TempDir::new().expect("tempdir");
    // Seed pre-cutover artifacts (`accounts.json`, `.lease`, `.sqlite`) to verify I8 wipe on open!
    let mls_dir = tmp.path().join("catbird-mls");
    std::fs::create_dir_all(&mls_dir).unwrap();
    std::fs::write(tmp.path().join("accounts.json"), b"{}").unwrap();
    std::fs::write(mls_dir.join("legacy.sqlite"), b"old").unwrap();
    std::fs::write(mls_dir.join("writer.lease"), b"lock").unwrap();

    let keystore = Arc::new(TestSdkKeystore {
        keys: Mutex::new(HashMap::new()),
    });
    let transport = Arc::new(TestSdkTransport {
        spaces_supported: AtomicBool::new(false),
    });

    let client = CatbirdMlsClient::open_offline_archive_for_test(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().display().to_string(),
            account_did: "did:plc:sdkuser00000000000000000".to_string(),
            device_id: "dev-ios-1".to_string(),
            home_ds_did: "did:web:chat.catbird.blue".to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        keystore,
        transport.clone(),
        None,
    )
    .expect("open CatbirdMlsClient");

    assert_eq!(client.pre_cutover_wipe_report().removed_files.len(), 3);
    assert!(!tmp.path().join("accounts.json").exists());
    assert!(!mls_dir.join("writer.lease").exists());
    assert!(!mls_dir.join("legacy.sqlite").exists());

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // I15: PDS without Spaces refuses enrollment while keeping Bluesky DMs available.
    let status_no_spaces = client
        .check_spaces_eligibility(&all_scopes)
        .expect("check spaces");
    assert!(!status_no_spaces.eligible);
    assert!(status_no_spaces.bluesky_dms_available);
    assert_eq!(
        status_no_spaces.reason,
        SpacesUnavailableReason::PdsDoesNotSupportSpaces
    );
    assert!(client.enroll_device(&all_scopes).is_err());

    // Enable Spaces on PDS, verify missing scopes still fail, then full scopes succeed!
    transport.spaces_supported.store(true, Ordering::SeqCst);
    assert!(client.enroll_device(&["atproto".to_string()]).is_err());

    let receipt = client.enroll_device(&all_scopes).expect("enroll device");
    assert!(receipt.labyrinth_backup_enabled);
    assert_eq!(
        receipt.mailbox_space_uri,
        "at://did:plc:sdkuser00000000000000000/space/blue.catbird.labyrinth.mailbox/self"
    );

    // Group + message + D3 admin-only removal + Labyrinth 40-char recovery code + PQ OTC + I9 background close!
    let _convo = client
        .create_group(
            "convo-sdk-1",
            "did:web:chat.catbird.blue",
            Vec::new(),
            Some("SDK Group".to_string()),
            None,
        )
        .expect("create_group");
    let _msg = client
        .send_message("convo-sdk-1", "msg-sdk-1", "Hello unified SDK!")
        .expect("send_message");
    assert_eq!(
        client.list_messages("convo-sdk-1", None, 10).unwrap().len(),
        1
    );

    assert!(client
        .remove_group_member(
            MemberRole::Member,
            "convo-sdk-1",
            "did:plc:otherpeer000000000000000"
        )
        .is_err());
    client
        .remove_group_member(
            MemberRole::Admin,
            "convo-sdk-1",
            "did:plc:otherpeer000000000000000",
        )
        .expect("admin removal allowed");

    let recovery_code = client.setup_recovery_code().expect("setup_recovery_code");
    let restored = client
        .restore_with_recovery_code(&recovery_code)
        .expect("restore_with_recovery_code");
    assert_eq!(restored.epoch_seq, 2);

    let otc_offer = client.initiate_otc_pairing().expect("initiate_otc_pairing");
    let otc_done = client
        .complete_otc_pairing(&otc_offer.formatted_code)
        .expect("complete_otc_pairing");
    assert_eq!(otc_done.initiator_mlkem768_ek_len, 1184);
    assert_eq!(otc_done.responder_mlkem768_ct_len, 1088);
    assert_eq!(otc_done.new_epoch_seq, 3);

    let bg = client
        .prepare_for_background()
        .expect("prepare_for_background");
    assert!(bg.handle_closed);
    assert!(client.is_handle_closed());
    client
        .resume_from_background()
        .expect("resume_from_background");
    assert!(!client.is_handle_closed());
}

#[test]
fn push_catchup_skips_i14_pruned_entry_and_decrypts_live_message() {
    let fixture = setup_alice_and_bob_group(true);

    let live_msg_bytes = fixture
        .bob_db
        .write_tx(|tx| {
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(storage)?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .map_err(|e| MLSError::Internal(format!("load bob group: {e:?}")))?
                    .expect("bob group");
            let payload_json = serde_json::to_string(
                &catbird_mls::orchestrator::MLSMessagePayload::text("Message after pruned seq 2!"),
            )
            .unwrap();
            let (inner_plaintext, aad) = PrivateMessagePlaintextEnvelope::seal_with_aad(
                [0x88u8; 32],
                payload_json.into_bytes(),
            )
            .expect("seal_with_aad");
            group.set_aad(aad);
            let msg_out = group
                .create_message(&provider, &fixture.bob_signer, &inner_plaintext)
                .map_err(|e| MLSError::Internal(format!("create_message: {e:?}")))?;
            msg_out
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("ser msg: {e:?}")))
        })
        .expect("bob live msg");

    struct PrunedWindowTransport {
        bundle: PushFetchBundle,
    }
    impl PushFetchTransport for PrunedWindowTransport {
        fn fetch_missing_entries(
            &self,
            _conversation_id: String,
            after_seq: i64,
            _chat_dpop_token: String,
        ) -> Result<PushFetchBundle, MLSError> {
            assert_eq!(after_seq, 1);
            Ok(self.bundle.clone())
        }
        fn get_authorized_device_keys(
            &self,
            _did: String,
            _chat_dpop_token: Option<String>,
        ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
            Ok(Vec::new())
        }
    }

    let mut dpop_map = HashMap::new();
    dpop_map.insert(
        fixture.alice_hash.clone(),
        Some("cached-chat-dpop-jwt".to_string()),
    );
    let mut db_keys = HashMap::new();
    db_keys.insert(fixture.alice_hash.clone(), fixture.alice_db_key);
    let keystore = Arc::new(MemoryPushKeystore {
        db_keys: Mutex::new(db_keys),
        sig_keys: Mutex::new(HashMap::new()),
        dpop_tokens: Mutex::new(dpop_map),
    });

    let transport = Arc::new(PrunedWindowTransport {
        bundle: PushFetchBundle {
            entries: vec![
                FetchedPushEntry {
                    entry_id: "entry-pruned-seq-2".to_string(),
                    seq: 2,
                    epoch: 1,
                    entry_kind: "application_message".to_string(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: Vec::new(), // I14 pruned ciphertext!
                },
                FetchedPushEntry {
                    entry_id: "entry-live-seq-3".to_string(),
                    seq: 3,
                    epoch: 1,
                    entry_kind: "application_message".to_string(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: live_msg_bytes,
                },
            ],
            metadata_snapshot: None,
            authorized_device_keys: Vec::new(),
        },
    });

    let wake = PushWakePayload {
        message_id: "entry-live-seq-3".to_string(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 1,
        entry_seq: 3,
        kind: "application_message".to_string(),
        fetch_required: true,
        inline_ciphertext: None,
        sender_did: Some(fixture.bob_did.clone()),
        recipient_account_hash: fixture.alice_hash.clone(),
    };

    let preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore,
        Some(transport),
        &wake,
    )
    .expect("catch-up across I14 pruned entry must succeed");

    assert!(!preview.fallback_generic);
    assert_eq!(preview.body, "Message after pruned seq 2!");
    assert_eq!(preview.seq, 3);
}

#[test]
fn client_signs_push_gateway_registration_and_acknowledge_entries_transcripts() {
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use catbird_mls::client::{
        CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest, PlatformHttpResponse,
        PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
    };
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use sha2::{Digest as _, Sha256};

    struct CapturingKeystore {
        keys: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl PlatformKeyStore for CapturingKeystore {
        fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
            let mut g = self.keys.lock().unwrap();
            Ok(g.entry(format!("db:{account_did_hash}"))
                .or_insert_with(|| vec![0x61u8; 32])
                .clone())
        }
        fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(self.keys.lock().unwrap().get(&key_id).cloned())
        }
        fn store_signature_keypair(
            &self,
            key_id: String,
            keypair_bytes: Vec<u8>,
        ) -> Result<(), MLSError> {
            self.keys.lock().unwrap().insert(key_id, keypair_bytes);
            Ok(())
        }
        fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
            self.keys
                .lock()
                .unwrap()
                .retain(|k, _| !k.contains(&account_did_hash));
            Ok(())
        }
        fn load_cached_chat_dpop_token(
            &self,
            _account_did_hash: String,
        ) -> Result<Option<String>, MLSError> {
            Ok(None)
        }
        fn store_cached_chat_dpop_token(
            &self,
            _account_did_hash: String,
            _token: String,
            _expires_at_ms: i64,
        ) -> Result<(), MLSError> {
            Ok(())
        }
    }

    struct CapturingTransport {
        ack_bodies: Mutex<Vec<serde_json::Value>>,
        pds_records: Mutex<Vec<serde_json::Value>>,
    }
    impl PlatformTransport for CapturingTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            if request.url.ends_with("/xrpc/com.atproto.space.getSpace") {
                return Ok(PlatformHttpResponse {
                    status: 400,
                    headers: Vec::new(),
                    body: br#"{"error":"InvalidRequest"}"#.to_vec(),
                });
            }
            if request.url.contains("/xrpc/com.atproto.repo.putRecord") {
                if let Some(body) = request.body.as_deref() {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                        if v.get("collection").and_then(|c| c.as_str())
                            == Some("blue.catbird.chat.device")
                        {
                            let rkey = v.get("rkey").and_then(|r| r.as_str()).unwrap_or("dev");
                            let repo = v.get("repo").and_then(|r| r.as_str()).unwrap_or("");
                            self.pds_records.lock().unwrap().push(serde_json::json!({
                                "uri": format!("at://{repo}/blue.catbird.chat.device/{rkey}"),
                                "cid": "bafyreimock",
                                "value": v["record"],
                            }));
                        }
                    }
                }
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"uri":"at://did:plc:signedtranscriptuseraaaa/blue.catbird.chat.device/self","cid":"bafyreimock"}"#.to_vec(),
                });
            }
            if request.url.contains("/xrpc/com.atproto.repo.listRecords") {
                let records = self.pds_records.lock().unwrap().clone();
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({ "records": records })).unwrap(),
                });
            }
            if request.url.contains("/xrpc/blue.catbird.chat.enrollDevice") {
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"device":{"authGeneration":1}}"#.to_vec(),
                });
            }
            if request
                .url
                .contains("/xrpc/blue.catbird.chat.createConversation")
            {
                let v: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
                let next_coords = v["signedRequest"]["body"]["next"].clone();
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "seq": 1,
                        "state": { "coordinates": next_coords }
                    }))
                    .unwrap(),
                });
            }
            if request
                .url
                .ends_with("/xrpc/blue.catbird.chat.acknowledgeEntries")
            {
                let v: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().expect("ack body"))
                        .expect("ack json");
                self.ack_bodies.lock().unwrap().push(v);
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"acknowledgedSeq":7,"prunedCount":2}"#.to_vec(),
                });
            }
            Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"ok":true}"#.to_vec(),
            })
        }
        fn connect_realtime_stream(
            &self,
            _home_ds_endpoint: String,
            _cursor_seq: Option<i64>,
        ) -> Result<(), MLSError> {
            Ok(())
        }
        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let tmp = TempDir::new().expect("tmp");
    let device_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let conv_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let keystore = Arc::new(CapturingKeystore {
        keys: Mutex::new(HashMap::new()),
    });
    let transport = Arc::new(CapturingTransport {
        ack_bodies: Mutex::new(Vec::new()),
        pds_records: Mutex::new(Vec::new()),
    });

    let client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().display().to_string(),
            // A canonical bare DID: production `create_group` has no local-only fallback.
            account_did: "did:plc:signedtranscriptuseraaaa".to_string(),
            device_id: device_id.clone(),
            home_ds_did: "did:web:chat.catbird.blue".to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        keystore,
        transport.clone(),
        None,
    )
    .expect("open client");

    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let receipt = client.enroll_device(&scopes).expect("enroll device");
    let vk = VerifyingKey::from_bytes(receipt.signature_public_key.as_slice().try_into().unwrap())
        .unwrap();
    let expected_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&receipt.signature_public_key));
    assert_eq!(expected_key_id.len(), 43);

    // 1. Verify `build_signed_push_gateway_registration`
    let gw_reg = client
        .build_signed_push_gateway_registration(
            "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
            "blue.catbird.ios",
            "push_key_opaque_valid_length_0123456789abcdef",
            true,
        )
        .expect("build_signed_push_gateway_registration");
    assert_eq!(gw_reg.key_id, expected_key_id);
    assert_eq!(gw_reg.device_id, device_id);
    let gw_json: serde_json::Value = serde_json::from_str(&gw_reg.request_json).unwrap();
    let gw_sig_bytes = STANDARD
        .decode(gw_json["signature"]["$bytes"].as_str().unwrap())
        .unwrap();
    let gw_sig = Signature::from_slice(&gw_sig_bytes).unwrap();
    let gw_cbor = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "appId": "blue.catbird.ios",
        "authGeneration": 1,
        "deviceId": device_id,
        "enabled": true,
        "gatewayUrl": "https://api.catbird.blue/xrpc/blue.catbird.push.deliver",
        "keyId": expected_key_id,
        "pushKey": "push_key_opaque_valid_length_0123456789abcdef",
        "signedAt": gw_reg.signed_at,
    }))
    .unwrap();
    let mut gw_transcript = b"CATBIRD-CHAT-PUSH-GATEWAY\0".to_vec();
    gw_transcript.extend_from_slice(&gw_cbor);
    vk.verify(&gw_transcript, &gw_sig)
        .expect("push gateway Ed25519 signature must verify");

    // 2. Verify `acknowledge_entries_up_to`
    client
        .create_group(
            &conv_id,
            "did:web:chat.catbird.blue",
            Vec::new(),
            None,
            None,
        )
        .expect("create_group");
    client
        .acknowledge_entries_up_to(&conv_id, 7)
        .expect("acknowledge_entries_up_to");

    let acks = transport.ack_bodies.lock().unwrap();
    assert_eq!(acks.len(), 1);
    let ack = &acks[0];
    assert_eq!(ack["conversationId"], conv_id);
    assert_eq!(ack["actorDeviceId"], device_id);
    assert_eq!(ack["keyId"], expected_key_id);
    assert_eq!(ack["authGeneration"], 1);
    assert_eq!(ack["upToSeq"], 7);
    let ack_sig_bytes = STANDARD
        .decode(ack["signature"]["$bytes"].as_str().unwrap())
        .unwrap();
    let ack_sig = Signature::from_slice(&ack_sig_bytes).unwrap();
    let ack_cbor = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "keyId": expected_key_id,
        "upToSeq": 7,
        "signedAt": ack["signedAt"].as_str().unwrap(),
        "generation": ack["generation"].as_i64().unwrap(),
        "actorDeviceId": device_id,
        "authGeneration": 1,
        "conversationId": conv_id,
    }))
    .unwrap();
    let mut ack_transcript = b"CATBIRD-CHAT-ACK-ENTRIES\0".to_vec();
    ack_transcript.extend_from_slice(&ack_cbor);
    vk.verify(&ack_transcript, &ack_sig)
        .expect("acknowledgeEntries Ed25519 signature must verify");
}

#[test]
fn push_commit_rejects_authenticated_prior_for_another_conversation_atomically() {
    let fixture = setup_alice_and_bob_group(true);
    let bad_commit = fixture
        .bob_db
        .read_tx(|tx| {
            let overlay = catbird_mls::storage::KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .unwrap()
                    .unwrap();
            set_push_commit_aad(
                &mut group,
                &provider,
                "b1234567-89ab-4cde-8123-456789abcdef",
                7,
            );
            Ok(group
                .self_update(
                    &provider,
                    &fixture.bob_signer,
                    LeafNodeParameters::default(),
                )
                .unwrap()
                .into_commit()
                .tls_serialize_detached()
                .unwrap())
        })
        .unwrap();
    struct BundleTransport(PushFetchBundle);
    impl PushFetchTransport for BundleTransport {
        fn fetch_missing_entries(
            &self,
            _: String,
            _: i64,
            _: String,
        ) -> Result<PushFetchBundle, MLSError> {
            Ok(self.0.clone())
        }
        fn get_authorized_device_keys(
            &self,
            _: String,
            _: Option<String>,
        ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
            Ok(self.0.authorized_device_keys.clone())
        }
    }
    let transport = Arc::new(BundleTransport(PushFetchBundle {
        entries: vec![FetchedPushEntry {
            entry_id: "cross-conversation-commit".into(),
            seq: 2,
            epoch: 1,
            entry_kind: "commit".into(),
            sender_did: fixture.bob_did.clone(),
            mls_bytes: bad_commit,
        }],
        metadata_snapshot: None,
        authorized_device_keys: vec![AuthorizedPeerDeviceKey {
            did: fixture.bob_did.clone(),
            device_id: fixture.bob_device_id.clone(),
            signature_public_key: fixture.bob_signer.public().to_vec(),
        }],
    }));
    let wake = PushWakePayload {
        kind: "commit".into(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 2,
        message_id: "cross-conversation-commit".into(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: true,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: None,
    };
    let error = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        Arc::new(MemoryPushKeystore::new(
            &fixture.alice_hash,
            fixture.alice_db_key,
            Some("cached-token".into()),
        )),
        Some(transport),
        &wake,
    )
    .expect_err("an authorized MLS signer cannot bind another conversation's coordinates");
    assert!(
        matches!(&error, MLSError::Cryptography(message) if message.contains("local conversation prior"))
    );
    let db =
        MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
            .unwrap();
    db.read_tx(|tx| {
        let row = tx.get_conversation(&fixture.conversation_id)?.unwrap();
        assert_eq!((row.epoch, row.last_seq), (1, 1));
        let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
            .unwrap()
            .unwrap();
        assert_eq!(group.epoch().as_u64(), 1);
        let persisted: serde_json::Value = serde_json::from_str(
            &tx.get_account_meta(&format!("conversation_coords:{}", fixture.conversation_id))?
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted,
            push_coordinates(&group, &provider, &fixture.conversation_id, 7)
        );
        Ok(())
    })
    .unwrap();
}
