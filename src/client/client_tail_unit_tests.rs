//! Fast deterministic `--lib` unit tests under `client::` covering `import_conversation_history`,
//! UniFFI pending-creation wrappers, Labyrinth rotation journal recovery, account-deletion message
//! purges, SQLCipher schema validation & application-send journal transitions, Apple fullfsync
//! pragmas, and synchronous push-processor receipt/control/Darwin-notification boundaries.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer as _, OpenMlsProvider};
use p256::ecdsa::SigningKey as P256SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::*;
use crate::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use crate::client::chat_wire;
use crate::client::config::{account_did_hash_hex, CatbirdMlsClientConfig};
use crate::client::traits::{
    PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore, PlatformTransport,
};
use crate::keychain::KeychainAccess;
use crate::labyrinth::journal::{
    recover_pending_labyrinth_rotations, RotationCommitTransport, RotationJournalPayload,
    RotationJournalStage, LABYRINTH_ROTATION_OP_TYPE,
};
use crate::messaging::receive::{
    handle_account_deleted_event, OriginalSenderArchiveAttestationEnvelope,
    PrivateMessagePlaintextEnvelope,
};
use crate::mls_engine_context::MLSContext;
use crate::orchestrator::canonical_transport::{derive_key_id, CanonicalOperation};
use crate::orchestrator::{MlsCryptoContext, OwnEchoProof, ReservedApplicationSend};
use crate::push::processor::test_exports::{
    fetched_entry_kind_matches_for_test, stage_verified_push_commit_for_test,
    verify_push_application_receipt_for_test, verify_push_commit_control_for_test,
};
use crate::push::{
    process_push_notification, should_inline_push_ciphertext, AuthorizedPeerDeviceKey,
    FetchedPushEntry, PushFetchBundle, PushFetchTransport, PushKeystore, PushWakePayload,
    INLINE_CIPHERTEXT_MAX_BYTES,
};
use crate::sim_hooks::{ChaChaSimEntropy, FixedStepClock, SimClientHooks};
use crate::storage::{
    ConversationRow, GroupMetadataRow, LabyrinthQueueRow, MessageRow, MlsAccountDb,
    MutationJournalRow, OpenMlsKvProvider, OpenMlsKvStorage, OpenMode, RusqliteKvBackend,
};

const PUSH_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const BOB_DEV_1: &str = "b0b00000-0000-4000-8000-000000000001";
const BOB_DEV_2: &str = "b0b00000-0000-4000-8000-000000000002";

struct TailKeystore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl TailKeystore {
    fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl PlatformKeyStore for TailKeystore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let mut map = self.keys.lock().unwrap();
        Ok(map
            .entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x51; 32])
            .clone())
    }
    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.keys.lock().unwrap().get(&key_id).cloned())
    }
    fn store_signature_keypair(&self, key_id: String, bytes: Vec<u8>) -> Result<(), MLSError> {
        self.keys.lock().unwrap().insert(key_id, bytes);
        Ok(())
    }
    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        let mut map = self.keys.lock().unwrap();
        map.remove(&format!("db:{account_did_hash}"));
        map.remove(&format!("mls-signer:{account_did_hash}"));
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

struct InMemoryKeychain {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryKeychain {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl KeychainAccess for InMemoryKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.map.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.map.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.map.lock().unwrap().remove(&key);
        Ok(())
    }
}

struct TailTransport {
    sequencer_key: P256SigningKey,
    sequencer_multibase: String,
    create_mode: Mutex<u16>,
    state_status: Mutex<u16>,
    enrolled_device_pub: Mutex<Option<Vec<u8>>>,
}

impl TailTransport {
    fn new() -> Self {
        let sequencer_key = P256SigningKey::from_bytes((&[0x34u8; 32]).into()).unwrap();
        let point = sequencer_key.verifying_key().to_encoded_point(true);
        let mut prefixed = vec![0x80, 0x24];
        prefixed.extend_from_slice(point.as_bytes());
        let sequencer_multibase = multibase::encode(multibase::Base::Base58Btc, &prefixed);
        Self {
            sequencer_key,
            sequencer_multibase,
            create_mode: Mutex::new(503),
            state_status: Mutex::new(400),
            enrolled_device_pub: Mutex::new(None),
        }
    }
}

fn sign_i13_receipt_json(
    key: &P256SigningKey,
    sequencer_did: &str,
    kid: &str,
    conversation_id: &str,
    generation: u64,
    group_id: &[u8],
    epoch: u64,
    sender_did: &str,
    sender_device_id: &str,
    entry_id: &str,
    commitment: &[u8; 32],
    seq: u64,
) -> Value {
    let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
        sequencer_did: sequencer_did.to_string(),
        conversation_id: conversation_id.to_string(),
        group_id: group_id.to_vec(),
        epoch,
        sender_device_did_url: format!("{sender_did}#{sender_device_id}"),
        entry_id: entry_id.to_string(),
        archive_commitment: *commitment,
        seq,
        issued_at_ms: 1_700_000_000_000,
    };
    let signed =
        labyrinth_protocol::receipt::sign_sequencer_receipt(key, kid, &payload).unwrap();
    json!({
        "conversationId": conversation_id,
        "generation": generation,
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "epoch": epoch,
        "senderDid": sender_did,
        "senderDeviceId": sender_device_id,
        "entryId": entry_id,
        "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
        "seq": seq,
        "issuedAtMs": 1_700_000_000_000i64,
        "sequencerDid": sequencer_did,
        "kid": kid,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    })
}

impl PlatformTransport for TailTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if let Some(plc_did) = request.url.strip_prefix("https://plc.directory/") {
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&json!({
                    "id": plc_did,
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://swan.place",
                    }],
                }))
                .unwrap(),
            });
        }
        if request.url.ends_with("/.well-known/did.json")
            || request.url.contains("/xrpc/com.atproto.identity.resolveDid")
        {
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&json!({
                    "id": "did:web:chat.catbird.blue",
                    "verificationMethod": [{
                        "id": "did:web:chat.catbird.blue#mls-receipt-1",
                        "type": "Multikey",
                        "controller": "did:web:chat.catbird.blue",
                        "publicKeyMultibase": self.sequencer_multibase,
                    }],
                }))
                .unwrap(),
            });
        }
        if request
            .url
            .contains("/xrpc/com.atproto.repo.listRecords")
        {
            if request.url.contains("collection=blue.catbird.chat.deviceRevocation") {
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&json!({ "records": [] })).unwrap(),
                });
            }
            let records = if let Some(pk) = self.enrolled_device_pub.lock().unwrap().clone() {
                json!([{
                    "uri": "at://did:plc:tailuseraaaaaaaaaaaaaaaa/blue.catbird.chat.device/11111111-1111-4111-8111-111111111111",
                    "value": {
                        "$type": "blue.catbird.chat.device",
                        "deviceId": "11111111-1111-4111-8111-111111111111",
                        "algorithm": "Ed25519",
                        "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(pk) },
                    }
                }])
            } else {
                json!([])
            };
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&json!({ "records": records })).unwrap(),
            });
        }
        if request
            .url
            .ends_with("/xrpc/blue.catbird.chat.createConversation")
        {
            let mode = *self.create_mode.lock().unwrap();
            if mode != 200 {
                return Ok(PlatformHttpResponse {
                    status: mode,
                    headers: Vec::new(),
                    body: br#"{"error":"ServiceUnavailable"}"#.to_vec(),
                });
            }
            let req_val: Value =
                serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
            let body = &req_val["signedRequest"]["body"];
            let strict = decode_strict_json(&serde_json::to_vec(body).unwrap()).unwrap();
            let transcript = SigningTranscript::build_for(
                SignedMutationKind::Creation,
                &project_signed_body(SignedMutationKind::Creation, &strict).unwrap(),
            )
            .unwrap();
            let group_id = chat_wire::json_bytes(&body["next"]["groupId"]).unwrap();
            let cid = body["conversationId"].as_str().unwrap();
            let entry_id = body["transitionId"].as_str().unwrap();
            let receipt = sign_i13_receipt_json(
                &self.sequencer_key,
                "did:web:chat.catbird.blue",
                "did:web:chat.catbird.blue#mls-receipt-1",
                cid,
                0,
                &group_id,
                body["next"]["epoch"].as_u64().unwrap(),
                body["actorDid"].as_str().unwrap(),
                body["actorDeviceId"].as_str().unwrap(),
                entry_id,
                transcript.request_digest(),
                1,
            );
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&json!({
                    "result": {
                        "coordinates": body["next"],
                        "entry": {
                            "$type": "blue.catbird.chat.defs#creationEntry",
                            "entryId": entry_id,
                            "conversationId": cid,
                            "seq": 1,
                            "signedRequest": req_val["signedRequest"],
                            "receivedAt": body["signedAt"],
                            "sequencerReceipt": receipt,
                        }
                    }
                }))
                .unwrap(),
            });
        }
        if request
            .url
            .contains("/xrpc/blue.catbird.chat.getConversationState")
        {
            let status = *self.state_status.lock().unwrap();
            return Ok(PlatformHttpResponse {
                status,
                headers: Vec::new(),
                body: br#"{"error":"ConversationNotFound"}"#.to_vec(),
            });
        }
        Ok(PlatformHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
        })
    }

    fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }
    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

fn open_enrolled_tail_client(
    tmp: &TempDir,
    clock: Arc<FixedStepClock>,
    seed: u64,
    transport: Arc<TailTransport>,
) -> Arc<CatbirdMlsClient> {
    let dev_id = "11111111-1111-4111-8111-111111111111";
    let hooks = SimClientHooks::new(clock, Arc::new(ChaChaSimEntropy::from_seed(seed, b"tail")));
    let client = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            account_did: "did:plc:tailuseraaaaaaaaaaaaaaaa".to_string(),
            device_id: dev_id.to_string(),
            storage_root: tmp.path().display().to_string(),
            home_ds_did: "did:web:chat.catbird.blue".to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TailKeystore::new()),
        transport.clone(),
        None,
        hooks,
    )
    .unwrap();
    let signer = client
        .hooks
        .signature_keypair(PUSH_CIPHERSUITE.signature_algorithm())
        .unwrap();
    *transport.enrolled_device_pub.lock().unwrap() = Some(signer.public().to_vec());
    let signer_json = serde_json::to_string(&signer).unwrap();
    let key_id = derive_key_id(signer.public());
    let now_ms = client.hooks.now_ms();
    client
        .db
        .write_tx(|tx| {
            tx.put_account_meta("enrolled_signer_json", &signer_json, now_ms)?;
            tx.put_account_meta("enrolled_device_id", dev_id, now_ms)?;
            tx.put_account_meta("enrolled_signer_key_id", &key_id, now_ms)?;
            tx.put_account_meta("auth_generation", "1", now_ms)?;
            Ok(())
        })
        .unwrap();
    client
}

#[test]
fn import_conversation_history_skips_existing_replaces_gap_and_validates_conversation_id() {
    let tmp = TempDir::new().unwrap();
    let clock = Arc::new(FixedStepClock::new(1_700_000_000_000, 1));
    let transport = Arc::new(TailTransport::new());
    let client = open_enrolled_tail_client(&tmp, clock, 7, transport);

    let cid = "a1234567-89ab-4cde-8123-456789abcdef";
    let group_id = vec![0x22; 32];
    let mk_msg = |id: &str, seq: i64, text: &str, conv: &str| MessageRow {
        message_id: id.to_string(),
        conversation_id: conv.to_string(),
        group_id: group_id.clone(),
        epoch: 1,
        seq,
        sender_did: "did:plc:peeruserbbbbbbbbbbbbbbbb".to_string(),
        sender_device_id: BOB_DEV_1.to_string(),
        plaintext_json: format!(r#"{{"text":"{text}"}}"#),
        created_at_ms: 1_700_000_000_000 + seq,
        is_own: false,
    };

    client
        .db
        .write_tx(|tx| {
            tx.insert_message(&mk_msg("m-existing", 1, "original-real", cid))?;
            tx.insert_message(&mk_msg("m-gap", 2, "gap-placeholder", cid))?;
            let gap_key = chat_wire::undecryptable_evidence_key(cid, "m-gap");
            tx.put_labyrinth_state(&gap_key, br#"{"gap":true}"#, 1_700_000_000_000)?;
            Ok(())
        })
        .unwrap();

    // Mismatched conversation_id is rejected atomically.
    let mismatch = client.import_conversation_history(
        cid,
        vec![mk_msg("m-bad", 3, "wrong", "b1234567-89ab-4cde-8123-456789abcdef")],
    );
    assert!(mismatch.is_err());

    // Importing [existing non-gap, existing gap, brand new] imports exactly 2 (gap + new).
    let imported = client
        .import_conversation_history(
            cid,
            vec![
                mk_msg("m-existing", 1, "overwritten-attempt", cid),
                mk_msg("m-gap", 2, "recovered-from-archive", cid),
                mk_msg("m-new", 3, "fresh-archived-message", cid),
            ],
        )
        .unwrap();
    assert_eq!(imported, 2);

    client
        .db
        .read_tx(|tx| {
            let existing = tx.get_message("m-existing")?.unwrap();
            assert_eq!(existing.plaintext_json, r#"{"text":"original-real"}"#);
            let recovered = tx.get_message("m-gap")?.unwrap();
            assert_eq!(recovered.plaintext_json, r#"{"text":"recovered-from-archive"}"#);
            let gap_key = chat_wire::undecryptable_evidence_key(cid, "m-gap");
            assert!(tx.get_labyrinth_state(&gap_key)?.is_none());
            let fresh = tx.get_message("m-new")?.unwrap();
            assert_eq!(fresh.plaintext_json, r#"{"text":"fresh-archived-message"}"#);
            Ok(())
        })
        .unwrap();
}

#[test]
fn ffi_pending_group_creation_status_retry_and_cancel_wrappers_preserve_outcomes() {
    let tmp = TempDir::new().unwrap();
    let clock = Arc::new(FixedStepClock::new(1_700_000_000_000, 1));
    let transport = Arc::new(TailTransport::new());
    let client = open_enrolled_tail_client(&tmp, clock.clone(), 19, transport.clone());

    // Missing conversation: status is None, cancel returns Ok(false).
    let missing_cid = "01111111-1111-4111-8111-111111111111".to_string();
    assert!(client
        .ffi_pending_group_creation_status(missing_cid.clone())
        .unwrap()
        .is_none());
    assert!(!client
        .ffi_cancel_pending_group_creation(missing_cid)
        .unwrap());

    // 1. Trigger a 503 pending creation, verify ffi_pending_group_creation_status == Some, then
    //    switch transport to 200 and verify ffi_retry_pending_group_creation == Some(row).
    let cid_adopt = "11111111-2222-4333-8444-555555555555".to_string();
    *transport.create_mode.lock().unwrap() = 503;
    assert!(client
        .create_group(
            &cid_adopt,
            "did:web:chat.catbird.blue",
            Vec::new(),
            Some("Adopted Group".into()),
            None,
        )
        .is_err());

    let status = client
        .ffi_pending_group_creation_status(cid_adopt.clone())
        .unwrap()
        .expect("pending creation status must be Some");
    assert_eq!(status.conversation_id, cid_adopt);

    clock.advance_ms(60_000);
    *transport.create_mode.lock().unwrap() = 200;
    let adopted = client
        .ffi_retry_pending_group_creation(cid_adopt.clone())
        .unwrap()
        .expect("retry must return Some(ConversationRow) on adoption");
    assert_eq!(adopted.conversation_id, cid_adopt);

    // 2. Trigger another 503 pending creation, advance clock past attempt expiry, and verify
    //    ffi_cancel_pending_group_creation returns Ok(true).
    let cid_cancel = "22222222-3333-4444-8555-666666666666".to_string();
    *transport.create_mode.lock().unwrap() = 503;
    assert!(client
        .create_group(
            &cid_cancel,
            "did:web:chat.catbird.blue",
            Vec::new(),
            Some("Cancelled Group".into()),
            None,
        )
        .is_err());
    clock.advance_ms(24 * 60 * 60 * 1000);
    assert!(client
        .ffi_cancel_pending_group_creation(cid_cancel.clone())
        .unwrap());
    assert!(client
        .ffi_pending_group_creation_status(cid_cancel)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn recover_pending_labyrinth_rotations_rolls_forward_multiple_entries_and_returns_exact_count()
{
    struct RecordingRotationTransport {
        swaps: Mutex<Vec<(Option<String>, u64, Vec<u8>)>>,
        publishes: Mutex<Vec<(u64, [u8; 32])>>,
    }

    #[async_trait::async_trait]
    impl RotationCommitTransport for RecordingRotationTransport {
        async fn swap_mailbox_keys_cas(
            &self,
            expected_swap_cid: Option<&str>,
            next_epoch_seq: u64,
            record_cbor: &[u8],
        ) -> Result<String, MLSError> {
            self.swaps.lock().unwrap().push((
                expected_swap_cid.map(str::to_owned),
                next_epoch_seq,
                record_cbor.to_vec(),
            ));
            Ok(format!("cid-epoch-{next_epoch_seq}"))
        }

        async fn publish_epoch_head_on_ds(
            &self,
            epoch_seq: u64,
            epoch_head: &[u8; 32],
        ) -> Result<(), MLSError> {
            self.publishes
                .lock()
                .unwrap()
                .push((epoch_seq, *epoch_head));
            Ok(())
        }
    }

    let tmp = TempDir::new().unwrap();
    let db = MlsAccountDb::open_native(tmp.path().join("rot.db"), &[0x44; 32], OpenMode::App)
        .unwrap();
    let transport = RecordingRotationTransport {
        swaps: Mutex::new(Vec::new()),
        publishes: Mutex::new(Vec::new()),
    };

    assert_eq!(
        recover_pending_labyrinth_rotations(&db, &transport)
            .await
            .unwrap(),
        0
    );

    let p1 = RotationJournalPayload {
        did: "did:plc:rotuserfffffffffffffffff".into(),
        epoch_seq: 2,
        epoch_head: [0x22; 32],
        expected_swap_cid: Some("cid-1".into()),
        committed_swap_cid: None,
        mailbox_keys_cbor: vec![1, 2, 3],
        stage: RotationJournalStage::PendingMailboxSwap,
    };
    let p2 = RotationJournalPayload {
        did: "did:plc:rotuserfffffffffffffffff".into(),
        epoch_seq: 3,
        epoch_head: [0x33; 32],
        expected_swap_cid: Some("cid-2".into()),
        committed_swap_cid: Some("cid-epoch-3".into()),
        mailbox_keys_cbor: vec![4, 5, 6],
        stage: RotationJournalStage::MailboxSwapped,
    };
    db.write_tx(|tx| {
        tx.upsert_mutation_journal(&MutationJournalRow {
            journal_id: "rot-2".into(),
            op_type: LABYRINTH_ROTATION_OP_TYPE.into(),
            epoch_seq: 2,
            state_json: serde_json::to_string(&p1).unwrap(),
            status: "pending".into(),
            created_at_ms: 100,
            updated_at_ms: 100,
        })?;
        tx.upsert_mutation_journal(&MutationJournalRow {
            journal_id: "rot-3".into(),
            op_type: LABYRINTH_ROTATION_OP_TYPE.into(),
            epoch_seq: 3,
            state_json: serde_json::to_string(&p2).unwrap(),
            status: "pending".into(),
            created_at_ms: 101,
            updated_at_ms: 101,
        })?;
        Ok(())
    })
    .unwrap();

    let count = recover_pending_labyrinth_rotations(&db, &transport)
        .await
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(transport.swaps.lock().unwrap().len(), 1);
    assert_eq!(transport.publishes.lock().unwrap().len(), 2);
    assert!(db
        .read_tx(|rx| rx.list_mutation_journal_pending())
        .unwrap()
        .is_empty());
}

#[test]
fn handle_account_deleted_event_purges_exact_sender_messages_and_queue_entries() {
    let tmp = TempDir::new().unwrap();
    let db = MlsAccountDb::open_native(tmp.path().join("del.db"), &[0x45; 32], OpenMode::App)
        .unwrap();
    let cid = "a1234567-89ab-4cde-8123-456789abcdef";

    assert!(handle_account_deleted_event(&db, cid, "   ").is_err());
    assert_eq!(
        handle_account_deleted_event(&db, cid, "did:plc:goneuserdddddddddddddddd").unwrap(),
        0
    );

    db.write_tx(|tx| {
        for (id, seq, sender) in [
            ("m1", 1, "did:plc:goneuserdddddddddddddddd"),
            ("m2", 2, "did:plc:goneuserdddddddddddddddd"),
            ("m3", 3, "did:plc:keepusereeeeeeeeeeeeeeee"),
        ] {
            tx.insert_message(&MessageRow {
                message_id: id.into(),
                conversation_id: cid.into(),
                group_id: vec![0x11; 32],
                epoch: 1,
                seq,
                sender_did: sender.into(),
                sender_device_id: BOB_DEV_1.into(),
                plaintext_json: r#"{"text":"hi"}"#.into(),
                created_at_ms: 1_000 + seq,
                is_own: false,
            })?;
        }
        tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
            item_id: "q-gone".into(),
            conversation_id: cid.into(),
            group_id_hex: "11".repeat(32),
            seq: 1,
            payload_bytes: br#"{"sender_did":"did:plc:goneuserdddddddddddddddd"}"#.to_vec(),
            created_at_ms: 1_000,
        })?;
        tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
            item_id: "q-keep".into(),
            conversation_id: cid.into(),
            group_id_hex: "11".repeat(32),
            seq: 2,
            payload_bytes: br#"{"sender_did":"did:plc:keepusereeeeeeeeeeeeeeee"}"#.to_vec(),
            created_at_ms: 1_001,
        })?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        handle_account_deleted_event(&db, cid, "did:plc:goneuserdddddddddddddddd").unwrap(),
        2
    );
    db.read_tx(|tx| {
        assert!(tx.get_message("m1")?.is_none());
        assert!(tx.get_message("m2")?.is_none());
        assert!(tx.get_message("m3")?.is_some());
        let remaining = tx.list_labyrinth_queue(Some(cid), 10)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].item_id, "q-keep");
        Ok(())
    })
    .unwrap();
}

#[test]
fn mls_context_validates_schema_and_commits_discard_and_spend_application_sends() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ctx.db");
    let enc_key = "test-mls-context-passphrase".to_string();

    let ctx = MLSContext::new(
        db_path.display().to_string(),
        enc_key.clone(),
        Box::new(InMemoryKeychain::new()),
    )
    .unwrap();

    let cid = "a1234567-89ab-4cde-8123-456789abcdef".to_string();
    let reserve_op = |msg_id: &str, counter: u64, ct_tag: u8| {
        let reserved = ReservedApplicationSend {
            conversation_id: cid.clone(),
            message_id: msg_id.to_string(),
            ciphertext_sha256: [ct_tag; 32],
            body: json!({ "sendCounter": counter }),
            payload_json: r#"{"text":"reserved"}"#.to_string(),
        };
        serde_json::to_string(&reserved).unwrap()
    };

    // Seed two reserved application sends directly into the underlying account DB.
    let db_key_32: [u8; 32] = Sha256::digest(enc_key.as_bytes()).into();
    {
        let raw_db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).unwrap();
        raw_db
            .write_tx(|tx| {
                tx.put_pending_op(
                    "orchestrator_application_send",
                    "msg-discard-1",
                    &reserve_op("msg-discard-1", 5, 0xA1),
                    1_700_000_000_000,
                )?;
                tx.put_pending_op(
                    "orchestrator_application_send",
                    "msg-spend-2",
                    &reserve_op("msg-spend-2", 6, 0xA2),
                    1_700_000_000_001,
                )?;
                Ok(())
            })
            .unwrap();
        let _ = raw_db.prepare_for_background();
    }

    // 1. `<MLSContext as MlsCryptoContext>::discard_application_send(..., true)` burns counter 5
    //    and deletes `msg-discard-1`.
    <MLSContext as MlsCryptoContext>::discard_application_send(&ctx, "msg-discard-1", true)
        .unwrap();
    assert!(ctx
        .reserved_application_send(&cid, &[0xA1; 32])
        .unwrap()
        .is_none());
    {
        let raw_db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).unwrap();
        let counter = raw_db
            .read_tx(|tx| tx.get_account_meta(&chat_wire::send_counter_key(&cid)))
            .unwrap();
        assert_eq!(counter.as_deref(), Some("5"));
        let _ = raw_db.prepare_for_background();
    }

    // 2. `spend_application_send` advances counter to 6, stores `own_echo_proof`, and deletes `msg-spend-2`.
    let proof = OwnEchoProof::new(
        [0x11; 32],
        cid.clone(),
        vec![0x22; 32],
        "entry-spend-2".into(),
        1,
        [0x33; 32],
        [0xA2; 32],
    );
    ctx.spend_application_send("msg-spend-2", &proof).unwrap();
    assert!(ctx
        .reserved_application_send(&cid, &[0xA2; 32])
        .unwrap()
        .is_none());
    {
        let raw_db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).unwrap();
        raw_db
            .read_tx(|tx| {
                assert_eq!(
                    tx.get_account_meta(&chat_wire::send_counter_key(&cid))?
                        .as_deref(),
                    Some("6")
                );
                let proof_key = hex::encode(proof.canonical_entry_sha256);
                assert!(tx.get_pending_op("own_echo_proof", &proof_key)?.is_some());
                Ok(())
            })
            .unwrap();
        let _ = raw_db.prepare_for_background();
    }
    drop(ctx);

    // 3. Inject an unexpected rogue table into the SQLCipher DB and confirm `MLSContext::new`
    //    rejects the tampered schema via `validate_existing_sqlite_storage`.
    {
        let raw_db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).unwrap();
        raw_db
            .write_tx(|tx| {
                tx.conn()
                    .execute_batch("CREATE TABLE unexpected_rogue_table (id INTEGER PRIMARY KEY);")
                    .map_err(|e| MLSError::Internal(e.to_string()))
            })
            .unwrap();
        let _ = raw_db.prepare_for_background();
    }
    let reopened = MLSContext::new(
        db_path.display().to_string(),
        enc_key,
        Box::new(InMemoryKeychain::new()),
    );
    assert!(reopened.is_err());
}

#[cfg(target_vendor = "apple")]
#[test]
fn apple_fullfsync_pragmas_are_enabled_on_sqlite_connection() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let before_full: i64 = conn
        .query_row("PRAGMA fullfsync", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before_full, 0);
    crate::storage::driver_native::configure_apple_fullfsync(&conn).unwrap();
    let full: i64 = conn
        .query_row("PRAGMA fullfsync", [], |r| r.get(0))
        .unwrap();
    let ckpt: i64 = conn
        .query_row("PRAGMA checkpoint_fullfsync", [], |r| r.get(0))
        .unwrap();
    assert_eq!((full, ckpt), (1, 1));
}

#[test]
fn push_inline_cutoff_and_entry_kind_matching_boundaries() {
    assert!(should_inline_push_ciphertext(&[]));
    assert!(should_inline_push_ciphertext(&vec![
        0u8;
        INLINE_CIPHERTEXT_MAX_BYTES
    ]));
    assert!(!should_inline_push_ciphertext(&vec![
        0u8;
        INLINE_CIPHERTEXT_MAX_BYTES + 1
    ]));

    assert!(fetched_entry_kind_matches_for_test("commitEntry", "commitEntry"));
    assert!(fetched_entry_kind_matches_for_test(
        "commitEntry",
        "blue.catbird.chat.defs#commitEntry"
    ));
    assert!(fetched_entry_kind_matches_for_test(
        "commit",
        "blue.catbird.chat.defs#commitEntry"
    ));
    assert!(fetched_entry_kind_matches_for_test(
        "applicationMessage",
        crate::chat_v2::wire::APPLICATION_ENTRY_KIND
    ));
    assert!(fetched_entry_kind_matches_for_test(
        "application_message",
        crate::chat_v2::wire::APPLICATION_ENTRY_KIND
    ));
    assert!(!fetched_entry_kind_matches_for_test(
        "applicationMessage",
        "blue.catbird.chat.defs#commitEntry"
    ));
    assert!(!fetched_entry_kind_matches_for_test(
        "policy",
        crate::chat_v2::wire::APPLICATION_ENTRY_KIND
    ));
    assert!(!fetched_entry_kind_matches_for_test(
        "policyEntry",
        "blue.catbird.chat.defs#commitEntry"
    ));
}

struct PushUnitFixture {
    temp_dir: TempDir,
    alice_did: String,
    alice_hash: String,
    alice_db_path: PathBuf,
    alice_db_key: [u8; 32],
    alice_signer: SignatureKeyPair,
    bob_did: String,
    bob_signer_1: SignatureKeyPair,
    bob_signer_2: SignatureKeyPair,
    bob_ed_key_1: Ed25519SigningKey,
    bob_ed_key_2: Ed25519SigningKey,
    bob_db: MlsAccountDb,
    conversation_id: String,
    group_id: Vec<u8>,
    sequencer_signer: P256SigningKey,
}

fn push_coords<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    cid: &str,
    state_version: i64,
) -> Value {
    let (gch, tag) = chat_wire::compute_group_context_hash_and_tag(group, provider).unwrap();
    json!({
        "conversationId": cid,
        "generation": 0,
        "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode(group.group_id().as_slice()) },
        "epoch": group.epoch().as_u64(),
        "groupContextHash": { "$bytes": STANDARD.encode(gch) },
        "confirmationTag": { "$bytes": STANDARD.encode(tag) },
        "lifecycle": "active",
    })
}

fn set_commit_aad<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    cid: &str,
    transition_id: &str,
    state_version: i64,
) {
    let mut prior = push_coords(group, provider, cid, state_version);
    let cid_b64 = STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes());
    prior["conversationId"] = json!(cid_b64);
    let aad = crate::orchestrator::canonical_transport::canonical_commit_aad_bytes(&json!({
        "protocolVersion": "1",
        "conversationId": cid_b64,
        "generation": 0,
        "transitionId": STANDARD.encode(uuid::Uuid::parse_str(transition_id).unwrap().as_bytes()),
        "prior": prior,
    }))
    .unwrap();
    group.set_aad(aad);
}

fn setup_push_unit_fixture(authorize_bob_in_alice_db: bool, two_bob_devices: bool) -> PushUnitFixture {
    let temp_dir = TempDir::new().unwrap();
    let alice_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let bob_did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let alice_hash = account_did_hash_hex(&alice_did).unwrap();
    let alice_db_key = [0x41u8; 32];
    let bob_db_key = [0x42u8; 32];
    let alice_db_path = temp_dir
        .path()
        .join("catbird-mls")
        .join(format!("{alice_hash}.db"));
    let bob_db_path = temp_dir.path().join("bob").join("bob.db");
    let conversation_id = "a1234567-89ab-4cde-8123-456789abcdef".to_string();
    let group_id = b"push-unit-group-id-32-bytes-0001".to_vec();
    let sequencer_signer = P256SigningKey::from_bytes((&[0x34u8; 32]).into()).unwrap();
    let point = sequencer_signer.verifying_key().to_encoded_point(true);
    let mut prefixed = vec![0x80, 0x24];
    prefixed.extend_from_slice(point.as_bytes());
    let sequencer_multibase = multibase::encode(multibase::Base::Base58Btc, &prefixed);

    let alice_signer = SignatureKeyPair::new(PUSH_CIPHERSUITE.signature_algorithm()).unwrap();
    let bob_ed_key_1 = Ed25519SigningKey::from_bytes(&[0x61; 32]);
    let bob_ed_key_2 = Ed25519SigningKey::from_bytes(&[0x62; 32]);
    let bob_signer_1 = SignatureKeyPair::from_raw(
        PUSH_CIPHERSUITE.signature_algorithm(),
        bob_ed_key_1.to_bytes().to_vec(),
        bob_ed_key_1.verifying_key().to_bytes().to_vec(),
    );
    let bob_signer_2 = SignatureKeyPair::from_raw(
        PUSH_CIPHERSUITE.signature_algorithm(),
        bob_ed_key_2.to_bytes().to_vec(),
        bob_ed_key_2.verifying_key().to_bytes().to_vec(),
    );

    let bob_db = MlsAccountDb::open_native(&bob_db_path, &bob_db_key, OpenMode::App).unwrap();
    let mut bob_kps = Vec::new();
    bob_db
        .write_tx(|tx| {
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            bob_signer_1.store(provider.storage()).unwrap();
            let kp1 = KeyPackage::builder()
                .leaf_node_capabilities(
                    Capabilities::builder()
                        .ciphersuites(vec![PUSH_CIPHERSUITE])
                        .build(),
                )
                .build(
                    PUSH_CIPHERSUITE,
                    &provider,
                    &bob_signer_1,
                    CredentialWithKey {
                        credential: BasicCredential::new(
                            format!("{bob_did}#{BOB_DEV_1}").into_bytes(),
                        )
                        .into(),
                        signature_key: bob_signer_1.public().into(),
                    },
                )
                .unwrap();
            bob_kps.push(kp1.key_package().clone());
            if two_bob_devices {
                bob_signer_2.store(provider.storage()).unwrap();
                let kp2 = KeyPackage::builder()
                    .leaf_node_capabilities(
                        Capabilities::builder()
                            .ciphersuites(vec![PUSH_CIPHERSUITE])
                            .build(),
                    )
                    .build(
                        PUSH_CIPHERSUITE,
                        &provider,
                        &bob_signer_2,
                        CredentialWithKey {
                            credential: BasicCredential::new(
                                format!("{bob_did}#{BOB_DEV_2}").into_bytes(),
                            )
                            .into(),
                            signature_key: bob_signer_2.public().into(),
                        },
                    )
                    .unwrap();
                bob_kps.push(kp2.key_package().clone());
            }
            Ok(())
        })
        .unwrap();

    let welcome_bytes = {
        let alice_db =
            MlsAccountDb::open_native(&alice_db_path, &alice_db_key, OpenMode::App).unwrap();
        let welcome = alice_db
            .write_tx(|tx| {
                let provider =
                    OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
                alice_signer.store(provider.storage()).unwrap();
                let create_cfg = MlsGroupCreateConfig::builder()
                    .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .ciphersuite(PUSH_CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(5)
                    .build();
                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &alice_signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id),
                    CredentialWithKey {
                        credential: BasicCredential::new(
                            format!("{alice_did}#dev-alice").into_bytes(),
                        )
                        .into(),
                        signature_key: alice_signer.public().into(),
                    },
                )
                .unwrap();
                let (_, welcome_out, _) = group
                    .add_members(&provider, &alice_signer, &bob_kps)
                    .unwrap();
                group.merge_pending_commit(&provider).unwrap();

                let epoch_now = group.epoch().as_u64() as i64;
                let now_ms = 1_700_000_000_000;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &push_coords(&group, &provider, &conversation_id, 7).to_string(),
                    now_ms,
                )?;
                tx.put_account_meta("owner_did", &alice_did, now_ms)?;
                tx.put_account_meta(
                    "did_doc:did:web:ds.example",
                    &json!({
                        "id": "did:web:ds.example",
                        "verificationMethod": [{
                            "id": "did:web:ds.example#mls-receipt-1",
                            "type": "Multikey",
                            "controller": "did:web:ds.example",
                            "publicKeyMultibase": sequencer_multibase,
                        }],
                    })
                    .to_string(),
                    now_ms,
                )?;
                tx.put_account_meta(
                    &format!("authorized_device_keys:{alice_did}"),
                    &serde_json::to_string(&vec![AuthorizedPeerDeviceKey {
                        did: alice_did.clone(),
                        device_id: "dev-alice".into(),
                        signature_public_key: alice_signer.public().to_vec(),
                    }])
                    .unwrap(),
                    now_ms,
                )?;
                if authorize_bob_in_alice_db {
                    let mut keys = vec![AuthorizedPeerDeviceKey {
                        did: bob_did.clone(),
                        device_id: BOB_DEV_1.into(),
                        signature_public_key: bob_signer_1.public().to_vec(),
                    }];
                    if two_bob_devices {
                        keys.push(AuthorizedPeerDeviceKey {
                            did: bob_did.clone(),
                            device_id: BOB_DEV_2.into(),
                            signature_public_key: bob_signer_2.public().to_vec(),
                        });
                    }
                    tx.put_account_meta(
                        &format!("authorized_device_keys:{bob_did}"),
                        &serde_json::to_string(&keys).unwrap(),
                        now_ms,
                    )?;
                }
                tx.upsert_conversation(&ConversationRow {
                    conversation_id: conversation_id.clone(),
                    group_id: group_id.clone(),
                    generation: 0,
                    epoch: epoch_now,
                    last_seq: 1,
                    sequencer_did: "did:web:ds.example".into(),
                    space_uri: Some(format!(
                        "at://did:web:ds.example/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
                    )),
                    title: Some("Unit Push Group".into()),
                    unread_count: 0,
                    updated_at_ms: now_ms,
                })?;
                tx.upsert_group_metadata(&GroupMetadataRow {
                    conversation_id: conversation_id.clone(),
                    metadata_version: 1,
                    epoch: epoch_now,
                    title: Some("Unit Push Group".into()),
                    description: None,
                    avatar_setter_did: None,
                    avatar_blob_cid: None,
                    avatar_sym_key: None,
                    avatar_sha256: None,
                    avatar_mime_type: None,
                    metadata_json: r#"{"version":1,"title":"Unit Push Group","description":""}"#
                        .into(),
                    updated_at_ms: now_ms,
                })?;
                Ok(welcome_out.tls_serialize_detached().unwrap())
            })
            .unwrap();
        let _ = alice_db.prepare_for_background().unwrap();
        welcome
    };

    bob_db
        .write_tx(|tx| {
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                .unwrap()
                .extract()
            else {
                panic!("expected welcome");
            };
            let join_cfg = MlsGroupJoinConfig::builder()
                .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .max_past_epochs(5)
                .build();
            let staged =
                StagedWelcome::new_from_welcome(&provider, &join_cfg, welcome, None).unwrap();
            let _group = staged.into_group(&provider).unwrap();
            Ok(())
        })
        .unwrap();

    PushUnitFixture {
        temp_dir,
        alice_did,
        alice_hash,
        alice_db_path,
        alice_db_key,
        alice_signer,
        bob_did,
        bob_signer_1,
        bob_signer_2,
        bob_ed_key_1,
        bob_ed_key_2,
        bob_db,
        conversation_id,
        group_id,
        sequencer_signer,
    }
}

fn encrypt_bob_push_app_msg(
    fixture: &PushUnitFixture,
    message_id: &str,
    text: &str,
) -> (Vec<u8>, [u8; 32]) {
    let payload_json =
        serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(text)).unwrap();
    let frame_nonce = [0x5Au8; 32];
    let commitment = labyrinth_protocol::receipt::compute_archive_commitment(
        &frame_nonce,
        payload_json.as_bytes(),
    );
    let transcript = labyrinth_protocol::transcripts::original_sender_archive_transcript(
        &fixture.conversation_id,
        message_id,
        &commitment,
    );
    let attestation = OriginalSenderArchiveAttestationEnvelope {
        sender_did: fixture.bob_did.clone(),
        sender_device_id: BOB_DEV_1.into(),
        sender_transport_public_key: fixture.bob_signer_1.public().to_vec(),
        signature: fixture.bob_signer_1.sign(&transcript).unwrap(),
    };
    let bytes = fixture
        .bob_db
        .write_tx(|tx| {
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .unwrap()
                    .unwrap();
            let cid_b64 =
                STANDARD.encode(uuid::Uuid::parse_str(&fixture.conversation_id).unwrap().as_bytes());
            let mid_b64 = STANDARD.encode(uuid::Uuid::parse_str(message_id).unwrap().as_bytes());
            let mut prior = push_coords(&group, &provider, &fixture.conversation_id, 7);
            prior["conversationId"] = json!(cid_b64);
            let aad = crate::orchestrator::canonical_transport::canonical_application_aad_bytes(&json!({
                "protocolVersion": "1",
                "conversationId": cid_b64,
                "generation": 0,
                "messageId": mid_b64,
                "prior": prior,
                "archiveCommitment": { "$bytes": STANDARD.encode(commitment) },
                "originalSenderAttestation": attestation.to_aad_json(),
            }))
            .unwrap();
            let inner = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
                frame_nonce,
                canonical_payload_bytes: payload_json.as_bytes().to_vec(),
                original_sender_attestation: Some(attestation),
            })
            .unwrap();
            group.set_aad(aad);
            Ok(group
                .create_message(&provider, &fixture.bob_signer_1, &inner)
                .unwrap()
                .tls_serialize_detached()
                .unwrap())
        })
        .unwrap();
    (bytes, commitment)
}

#[test]
fn push_application_receipt_and_commit_control_verification_guards() {
    let fixture = setup_push_unit_fixture(true, true);
    let entry_id = "c1111111-2222-4333-8444-555555555555";
    let commitment = [0x77u8; 32];
    let receipt_json = sign_i13_receipt_json(
        &fixture.sequencer_signer,
        "did:web:ds.example",
        "did:web:ds.example#mls-receipt-1",
        &fixture.conversation_id,
        0,
        &fixture.group_id,
        1,
        &fixture.bob_did,
        BOB_DEV_1,
        entry_id,
        &commitment,
        2,
    );
    let base_entry = FetchedPushEntry {
        entry_id: entry_id.into(),
        seq: 2,
        epoch: 1,
        entry_kind: "applicationMessage".into(),
        sender_did: fixture.bob_did.clone(),
        mls_bytes: Vec::new(),
        signed_request: None,
        sequencer_receipt: Some(serde_json::to_vec(&receipt_json).unwrap()),
    };

    let alice_db =
        MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
            .unwrap();
    alice_db
        .write_tx(|tx| {
            let convo = tx.get_conversation(&fixture.conversation_id)?.unwrap();
            // Valid non-empty and empty entry.sender_did both verify.
            let (_, _, s_did, s_dev) =
                verify_push_application_receipt_for_test(tx, &base_entry, &convo)?;
            assert_eq!((s_did.as_str(), s_dev.as_str()), (fixture.bob_did.as_str(), BOB_DEV_1));
            let mut empty_sender = base_entry.clone();
            empty_sender.sender_did.clear();
            assert!(verify_push_application_receipt_for_test(tx, &empty_sender, &convo).is_ok());

            // Wrong conversation generation -> Err.
            let mut wrong_gen = convo.clone();
            wrong_gen.generation = 1;
            assert!(verify_push_application_receipt_for_test(tx, &base_entry, &wrong_gen).is_err());

            // Mismatched non-empty entry.sender_did -> Err.
            let mut wrong_sender = base_entry.clone();
            wrong_sender.sender_did = fixture.alice_did.clone();
            assert!(verify_push_application_receipt_for_test(tx, &wrong_sender, &convo).is_err());
            Ok(())
        })
        .unwrap();
    let _ = alice_db.prepare_for_background();

    // Build a real Bob#dev-1 Commit stepping epoch 1 -> 2 and stateVersion 7 -> 8.
    let transition_id = "d1111111-2222-4333-8444-555555555555";
    let (commit_bytes, prior_coord, next_coord) = fixture
        .bob_db
        .write_tx(|tx| {
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .unwrap()
                    .unwrap();
            let prior = push_coords(&group, &provider, &fixture.conversation_id, 7);
            set_commit_aad(&mut group, &provider, &fixture.conversation_id, transition_id, 7);
            let bundle = group
                .self_update(&provider, &fixture.bob_signer_1, LeafNodeParameters::default())
                .unwrap();
            group.merge_pending_commit(&provider).unwrap();
            let next = push_coords(&group, &provider, &fixture.conversation_id, 8);
            Ok((
                bundle.into_commit().tls_serialize_detached().unwrap(),
                prior,
                next,
            ))
        })
        .unwrap();

    let sign_commit_entry = |body_override: &dyn Fn(&mut Value), signer: &Ed25519SigningKey| {
        let pub_bytes = signer.verifying_key().to_bytes();
        let sig_kp = SignatureKeyPair::from_raw(
            PUSH_CIPHERSUITE.signature_algorithm(),
            signer.to_bytes().to_vec(),
            pub_bytes.to_vec(),
        );
        let convo_uuid = uuid::Uuid::parse_str(&fixture.conversation_id).unwrap();
        let cid_b64 = STANDARD.encode(convo_uuid.as_bytes());
        let mut aad_prior = prior_coord.clone();
        aad_prior["conversationId"] = json!(cid_b64);
        let commit_aad_val = json!({
            "protocolVersion": "1",
            "conversationId": cid_b64,
            "generation": 0,
            "transitionId": STANDARD.encode(uuid::Uuid::parse_str(transition_id).unwrap().as_bytes()),
            "prior": aad_prior,
        });
        let next_gch = chat_wire::json_bytes(&next_coord["groupContextHash"]).unwrap();
        let next_ctag = chat_wire::json_bytes(&next_coord["confirmationTag"]).unwrap();
        let meta_snap = chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
            &[0x42u8; 32],
            &fixture.group_id,
            &convo_uuid,
            0,
            next_coord["epoch"].as_u64().unwrap(),
            &next_gch,
            &next_ctag,
            transition_id,
            1,
            1,
            &fixture.bob_did,
            BOB_DEV_1,
            1,
            &pub_bytes,
            "Push Group",
            "",
            None,
            [0x11u8; 12],
        )
        .unwrap();
        let mut body = json!({
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": fixture.bob_did,
            "actorDeviceId": BOB_DEV_1,
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(pub_bytes)),
            "authGeneration": 1,
            "signedAt": "2026-11-15T00:00:00.000Z",
            "prior": prior_coord,
            "next": next_coord,
            "aad": commit_aad_val,
            "manifest": {
                "participantChanges": [],
                "leafChanges": [],
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
            },
            "metadataSnapshot": meta_snap,
        });
        body_override(&mut body);
        let prep = chat_wire::sign_clean_chat_mutation(
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap(),
            Some(1),
            CanonicalOperation::SubmitTransition,
            &body,
            &sig_kp,
        )
        .unwrap();
        let wire_val: Value = serde_json::from_slice(&prep.body.unwrap()).unwrap();
        let signed_req = wire_val["signedRequest"].clone();
        let (_, digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &signed_req,
            SignedMutationKind::CommitTransition,
            &pub_bytes,
        )
        .unwrap();
        let receipt = sign_i13_receipt_json(
            &fixture.sequencer_signer,
            "did:web:ds.example",
            "did:web:ds.example#mls-receipt-1",
            &fixture.conversation_id,
            body["next"]["generation"].as_u64().unwrap_or(0),
            &fixture.group_id,
            body["next"]["epoch"].as_u64().unwrap_or(2),
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap(),
            transition_id,
            &digest,
            2,
        );
        FetchedPushEntry {
            entry_id: transition_id.into(),
            seq: 2,
            epoch: 1,
            entry_kind: "commitEntry".into(),
            sender_did: fixture.bob_did.clone(),
            mls_bytes: commit_bytes.clone(),
            signed_request: Some(serde_json::to_vec(&signed_req).unwrap()),
            sequencer_receipt: Some(serde_json::to_vec(&receipt).unwrap()),
        }
    };

    let mut auth_map = HashMap::new();
    auth_map.insert(
        fixture.bob_did.clone(),
        vec![
            AuthorizedPeerDeviceKey {
                did: fixture.bob_did.clone(),
                device_id: BOB_DEV_1.into(),
                signature_public_key: fixture.bob_signer_1.public().to_vec(),
            },
            AuthorizedPeerDeviceKey {
                did: fixture.bob_did.clone(),
                device_id: BOB_DEV_2.into(),
                signature_public_key: fixture.bob_signer_2.public().to_vec(),
            },
        ],
    );
    auth_map.insert(
        fixture.alice_did.clone(),
        vec![AuthorizedPeerDeviceKey {
            did: fixture.alice_did.clone(),
            device_id: "dev-alice".into(),
            signature_public_key: fixture.alice_signer.public().to_vec(),
        }],
    );

    let alice_db =
        MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
            .unwrap();
    alice_db
        .write_tx(|tx| {
            let convo = tx.get_conversation(&fixture.conversation_id)?.unwrap();
            let provider =
                OpenMlsKvProvider::new(OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn())))?;
            let group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .unwrap()
                    .unwrap();

            // Valid Bob#dev-1 Commit control verifies with actor_is_own == false.
            let valid_entry = sign_commit_entry(&|_| {}, &fixture.bob_ed_key_1);
            let (kind, ver_body, ver_next, actor_is_own) = verify_push_commit_control_for_test(
                tx,
                &valid_entry,
                &convo,
                &group,
                &provider,
                Some(&fixture.alice_did),
                &auth_map,
            )?;
            assert_eq!(kind, SignedMutationKind::CommitTransition);
            assert!(!actor_is_own);

            // Valid peer Commit stages cleanly to epoch 2.
            let hooks = SimClientHooks::system_default();
            let (_, removed_self, new_epoch) = stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &valid_entry,
                kind,
                ver_body,
                ver_next,
                false,
                Some(&fixture.alice_did),
                &auth_map,
            )?;
            assert!(!removed_self);
            assert_eq!(new_epoch, 2);

            // Cross-device spoofing: MLS Commit signed by Bob#dev-1 leaf, but signedRequest signed
            // by Bob#dev-2 claiming actorDeviceId=BOB_DEV_2 -> passes control check (both leaves in
            // group!) and MUST fail in stage_verified_push_commit when MLS sender leaf != actorDeviceId!
            let spoofed_dev_entry = sign_commit_entry(
                &|b| {
                    b["actorDeviceId"] = json!(BOB_DEV_2);
                },
                &fixture.bob_ed_key_2,
            );
            let (skind, sbody, snext, s_own) = verify_push_commit_control_for_test(
                tx,
                &spoofed_dev_entry,
                &convo,
                &group,
                &provider,
                Some(&fixture.alice_did),
                &auth_map,
            )?;
            assert!(!s_own);
            assert!(stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &spoofed_dev_entry,
                skind,
                sbody,
                snext,
                false,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());

            // Unknown actorDeviceId not in group -> Err.
            let bad_dev = sign_commit_entry(
                &|b| {
                    b["actorDeviceId"] = json!("b0b00000-0000-4000-8000-999999999999");
                },
                &fixture.bob_ed_key_1,
            );
            assert!(verify_push_commit_control_for_test(
                tx,
                &bad_dev,
                &convo,
                &group,
                &provider,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());

            // Coordinate step invariants: prior.generation, next.generation, next.stateVersion,
            // next.epoch, prior.lifecycle, next.lifecycle.
            for mutate in [
                |b: &mut Value| b["prior"]["generation"] = json!(1),
                |b: &mut Value| b["next"]["generation"] = json!(1),
                |b: &mut Value| b["next"]["stateVersion"] = json!(9),
                |b: &mut Value| b["next"]["epoch"] = json!(3),
                |b: &mut Value| b["prior"]["lifecycle"] = json!("superseded"),
                |b: &mut Value| b["next"]["lifecycle"] = json!("superseded"),
            ] {
                let bad = sign_commit_entry(&mutate, &fixture.bob_ed_key_1);
                assert!(verify_push_commit_control_for_test(
                    tx,
                    &bad,
                    &convo,
                    &group,
                    &provider,
                    Some(&fixture.alice_did),
                    &auth_map,
                )
                .is_err());
            }
            Ok(())
        })
        .unwrap();

    // Own-pending Commit path in `stage_verified_push_commit`: stage Alice's own Commit into a
    // `KvWriteBatch` + `PendingCommitTransition` journal row and test valid + 4 mismatch guards.
    let own_tid = "e1111111-2222-4333-8444-555555555555";
    alice_db
        .write_tx(|tx| {
            let convo = tx.get_conversation(&fixture.conversation_id)?.unwrap();
            let overlay = crate::storage::KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&fixture.group_id))
                    .unwrap()
                    .unwrap();
            let prior = push_coords(&group, &provider, &fixture.conversation_id, 7);
            set_commit_aad(&mut group, &provider, &fixture.conversation_id, own_tid, 7);
            let bundle = group
                .self_update(
                    &provider,
                    &fixture.alice_signer,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            group.merge_pending_commit(&provider).unwrap();
            let next = push_coords(&group, &provider, &fixture.conversation_id, 8);
            let own_commit_bytes = bundle.into_commit().tls_serialize_detached().unwrap();
            let commit_sha256: [u8; 32] = Sha256::digest(&own_commit_bytes).into();
            let kv_batch = overlay.into_batch();

            let base_pending = chat_wire::PendingCommitTransition {
                conversation_id: fixture.conversation_id.clone(),
                transition_id: own_tid.into(),
                commit_sha256,
                prior: prior.clone(),
                next: next.clone(),
                kv_batch,
                removed_participant_did: None,
            };
            let clone_commit_pending = |p: &chat_wire::PendingCommitTransition| -> chat_wire::PendingCommitTransition {
                serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap()
            };
            let own_entry = FetchedPushEntry {
                entry_id: own_tid.into(),
                seq: 2,
                epoch: 1,
                entry_kind: "commitEntry".into(),
                sender_did: fixture.alice_did.clone(),
                mls_bytes: own_commit_bytes,
                signed_request: None,
                sequencer_receipt: None,
            };
            let canon_next =
                chat_wire::canonicalize_wire_coordinate(&next, Some(&fixture.conversation_id))?;
            let hooks = SimClientHooks::system_default();

            // Valid own pending Commit succeeds and advances to epoch 2 on overlay.
            tx.put_pending_op(
                "commit_transition",
                own_tid,
                &serde_json::to_string(&base_pending).unwrap(),
                1_700_000_000_000,
            )?;
            let (_, removed, ep) = stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &own_entry,
                SignedMutationKind::CommitTransition,
                json!({"transitionId": own_tid}),
                canon_next.clone(),
                true,
                Some(&fixture.alice_did),
                &auth_map,
            )?;
            assert!(!removed && ep == 2);

            // Mismatch 1: pending.conversation_id != conversation.conversation_id
            let mut m1 = clone_commit_pending(&base_pending);
            m1.conversation_id = "f1111111-2222-4333-8444-555555555555".into();
            tx.put_pending_op(
                "commit_transition",
                own_tid,
                &serde_json::to_string(&m1).unwrap(),
                1_700_000_000_000,
            )?;
            assert!(stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &own_entry,
                SignedMutationKind::CommitTransition,
                json!({"transitionId": own_tid}),
                canon_next.clone(),
                true,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());

            // Mismatch 2: pending.transition_id != transition_id
            let mut m2 = clone_commit_pending(&base_pending);
            m2.transition_id = "f2222222-2222-4333-8444-555555555555".into();
            tx.put_pending_op(
                "commit_transition",
                own_tid,
                &serde_json::to_string(&m2).unwrap(),
                1_700_000_000_000,
            )?;
            assert!(stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &own_entry,
                SignedMutationKind::CommitTransition,
                json!({"transitionId": own_tid}),
                canon_next.clone(),
                true,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());

            // Mismatch 3: pending.commit_sha256 != commit_sha256
            let mut m3 = clone_commit_pending(&base_pending);
            m3.commit_sha256 = [0xFF; 32];
            tx.put_pending_op(
                "commit_transition",
                own_tid,
                &serde_json::to_string(&m3).unwrap(),
                1_700_000_000_000,
            )?;
            assert!(stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &own_entry,
                SignedMutationKind::CommitTransition,
                json!({"transitionId": own_tid}),
                canon_next.clone(),
                true,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());

            // Mismatch 4: pending_next != verified.next
            let mut m4 = base_pending;
            m4.next["stateVersion"] = json!(99);
            tx.put_pending_op(
                "commit_transition",
                own_tid,
                &serde_json::to_string(&m4).unwrap(),
                1_700_000_000_000,
            )?;
            assert!(stage_verified_push_commit_for_test(
                tx,
                Arc::new(InMemoryKeychain::new()),
                &hooks,
                &convo,
                &own_entry,
                SignedMutationKind::CommitTransition,
                json!({"transitionId": own_tid}),
                canon_next,
                true,
                Some(&fixture.alice_did),
                &auth_map,
            )
            .is_err());
            Ok(())
        })
        .unwrap();
}

#[test]
fn process_push_notification_verified_fetch_offline_preview_error_propagation_and_darwin_notify() {
    struct SimplePushKeystore {
        hash: String,
        db_key: [u8; 32],
        token: Option<String>,
    }
    impl PushKeystore for SimplePushKeystore {
        fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
            assert_eq!(account_did_hash, self.hash);
            Ok(self.db_key.to_vec())
        }
        fn load_signature_keypair(&self, _: String) -> Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        fn load_cached_chat_dpop_token(&self, _: String) -> Result<Option<String>, MLSError> {
            Ok(self.token.clone())
        }
    }

    struct LivePushTransport {
        bundle: PushFetchBundle,
        bob_key: AuthorizedPeerDeviceKey,
        fail_with: Option<String>,
    }
    impl PushFetchTransport for LivePushTransport {
        fn fetch_missing_entries(
            &self,
            _: String,
            _: i64,
            _: String,
        ) -> Result<PushFetchBundle, MLSError> {
            if let Some(reason) = &self.fail_with {
                return Err(MLSError::InvalidState(reason.clone()));
            }
            Ok(self.bundle.clone())
        }
        fn get_authorized_device_keys(
            &self,
            did: String,
            _: Option<String>,
        ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
            if did == self.bob_key.did {
                Ok(vec![self.bob_key.clone()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    let fixture = setup_push_unit_fixture(false, false);
    let inline_mid = "b0b00000-0000-4000-8000-000000000010";
    let live_mid = "b0b00000-0000-4000-8000-000000000011";
    let (inline_ct, _) = encrypt_bob_push_app_msg(&fixture, inline_mid, "Inline preview text");
    let (live_ct, live_commitment) =
        encrypt_bob_push_app_msg(&fixture, live_mid, "Verified live push text");

    // Seed Bob's key ONLY after testing `get_authorized_device_keys` caching:
    // First seed Bob's key for offline inline preview, then clear it before live fetch so
    // `get_authorized_device_keys` is exercised on both Bob (non-empty) and an unknown DID (empty).
    {
        let alice_db = MlsAccountDb::open_native(
            &fixture.alice_db_path,
            &fixture.alice_db_key,
            OpenMode::App,
        )
        .unwrap();
        alice_db
            .write_tx(|tx| {
                tx.put_account_meta(
                    &format!("authorized_device_keys:{}", fixture.bob_did),
                    &serde_json::to_string(&vec![AuthorizedPeerDeviceKey {
                        did: fixture.bob_did.clone(),
                        device_id: BOB_DEV_1.into(),
                        signature_public_key: fixture.bob_signer_1.public().to_vec(),
                    }])
                    .unwrap(),
                    1_700_000_000_000,
                )
            })
            .unwrap();
        let _ = alice_db.prepare_for_background();
    }

    let keystore = Arc::new(SimplePushKeystore {
        hash: fixture.alice_hash.clone(),
        db_key: fixture.alice_db_key,
        token: Some("cached-dpop-token".into()),
    });

    #[cfg(target_vendor = "apple")]
    let check_darwin_posted = |token: i32| -> bool {
        extern "C" {
            fn notify_check(token: i32, check: *mut i32) -> u32;
        }
        let mut check: i32 = 0;
        unsafe {
            assert_eq!(notify_check(token, &mut check), 0);
        }
        check != 0
    };

    // 1. Offline inline application wake (`!fetch_required`, `transport = None`):
    //    returns decrypted preview with `receipt_verified == false`, `fallback_generic == false`,
    //    and `from_cache == false`.
    let inline_wake = PushWakePayload {
        kind: "applicationMessage".into(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 2,
        message_id: inline_mid.into(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: false,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: Some(inline_ct.clone()),
    };
    let offline_preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore.clone(),
        None,
        &inline_wake,
    )
    .unwrap();
    assert!(!offline_preview.fallback_generic);
    assert!(!offline_preview.receipt_verified);
    assert!(!offline_preview.from_cache);
    assert_eq!(offline_preview.body, "Inline preview text");

    // 2. Non-application inline wake (`kind = "commit"`, `!fetch_required`) falls back generically.
    let commit_inline_wake = PushWakePayload {
        kind: "commit".into(),
        ..inline_wake.clone()
    };
    let generic_preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore.clone(),
        None,
        &commit_inline_wake,
    )
    .unwrap();
    assert!(generic_preview.fallback_generic);

    // 3. When `network.is_some()` and `fetch_missing_entries` fails on an inline application wake,
    //    `preview_only` flips to `true` and `get_authorized_device_keys` MUST NOT be called.
    struct FailIfKeysQueried;
    impl PushFetchTransport for FailIfKeysQueried {
        fn fetch_missing_entries(&self, _: String, _: i64, _: String) -> Result<PushFetchBundle, MLSError> {
            Err(MLSError::Internal("offline".into()))
        }
        fn get_authorized_device_keys(&self, _: String, _: Option<String>) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
            Err(MLSError::Internal("must not query keys during preview_only fallback".into()))
        }
    }
    let fallback_inline = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore.clone(),
        Some(Arc::new(FailIfKeysQueried)),
        &inline_wake,
    )
    .unwrap();
    assert!(!fallback_inline.receipt_verified);
    assert_eq!(fallback_inline.body, "Inline preview text");

    // Clear Bob's cached authorized_device_keys in Alice's DB so `get_authorized_device_keys`
    // is invoked for `fixture.bob_did` (returns key -> cached) AND `"did:plc:unknownuserccccccccccccc"`
    // (returns empty -> NOT cached!).
    {
        let alice_db = MlsAccountDb::open_native(
            &fixture.alice_db_path,
            &fixture.alice_db_key,
            OpenMode::App,
        )
        .unwrap();
        alice_db
            .write_tx(|tx| {
                tx.delete_account_meta(&format!("authorized_device_keys:{}", fixture.bob_did))
            })
            .unwrap();
        let _ = alice_db.prepare_for_background();
    }

    let live_entry_id = "f3333333-4444-4555-8666-777777777777";
    let live_receipt = sign_i13_receipt_json(
        &fixture.sequencer_signer,
        "did:web:ds.example",
        "did:web:ds.example#mls-receipt-1",
        &fixture.conversation_id,
        0,
        &fixture.group_id,
        1,
        &fixture.bob_did,
        BOB_DEV_1,
        live_entry_id,
        &live_commitment,
        2,
    );
    let unknown_did = "did:plc:unknownuserccccccccccccc".to_string();
    let live_transport = Arc::new(LivePushTransport {
        bundle: PushFetchBundle {
            entries: vec![
                FetchedPushEntry {
                    entry_id: live_entry_id.into(),
                    seq: 2,
                    epoch: 1,
                    entry_kind: "applicationMessage".into(),
                    sender_did: fixture.bob_did.clone(),
                    mls_bytes: live_ct,
                    signed_request: None,
                    sequencer_receipt: Some(serde_json::to_vec(&live_receipt).unwrap()),
                },
                // Include a second entry naming `unknown_did` (with higher seq that stops/ignores
                // or pre-fetches keys before write_tx) so `get_authorized_device_keys(unknown_did)`
                // returns `vec![]` and we verify empty keys are NOT written to `account_meta`!
                FetchedPushEntry {
                    entry_id: "f4444444-4444-4555-8666-777777777777".into(),
                    seq: 2, // duplicate seq <= current_convo.last_seq after first entry advances last_seq to 2!
                    epoch: 1,
                    entry_kind: "applicationMessage".into(),
                    sender_did: unknown_did.clone(),
                    mls_bytes: Vec::new(),
                    signed_request: None,
                    sequencer_receipt: None,
                },
            ],
            metadata_snapshot: None,
            authorized_device_keys: Vec::new(),
        },
        bob_key: AuthorizedPeerDeviceKey {
            did: fixture.bob_did.clone(),
            device_id: BOB_DEV_1.into(),
            signature_public_key: fixture.bob_signer_1.public().to_vec(),
        },
        fail_with: None,
    });

    let live_wake = PushWakePayload {
        kind: "applicationMessage".into(),
        conversation_id: fixture.conversation_id.clone(),
        generation: 0,
        entry_seq: 2,
        message_id: live_mid.into(),
        recipient_account_hash: fixture.alice_hash.clone(),
        fetch_required: true,
        sender_did: Some(fixture.bob_did.clone()),
        inline_ciphertext: None,
    };
    #[cfg(target_vendor = "apple")]
    let darwin_token = {
        use std::ffi::CString;
        extern "C" {
            fn notify_register_check(
                name: *const std::os::raw::c_char,
                out_token: *mut i32,
            ) -> u32;
            fn notify_check(token: i32, check: *mut i32) -> u32;
        }
        let c_name = CString::new(crate::push::DARWIN_NSE_DID_COMMIT_NOTIFICATION).unwrap();
        let mut token: i32 = 0;
        let mut initial: i32 = 0;
        unsafe {
            assert_eq!(notify_register_check(c_name.as_ptr(), &mut token), 0);
            assert_eq!(notify_check(token, &mut initial), 0);
        }
        token
    };
    let verified_preview = process_push_notification(
        fixture.temp_dir.path(),
        &fixture.alice_hash,
        keystore,
        Some(live_transport),
        &live_wake,
    )
    .unwrap();
    assert!(!verified_preview.fallback_generic);
    assert!(verified_preview.receipt_verified);
    assert!(!verified_preview.from_cache);
    assert_eq!(verified_preview.body, "Verified live push text");
    #[cfg(target_vendor = "apple")]
    {
        let mut posted = false;
        for _ in 0..50 {
            if check_darwin_posted(darwin_token) {
                posted = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        extern "C" {
            fn notify_cancel(token: i32) -> u32;
        }
        unsafe {
            let _ = notify_cancel(darwin_token);
        }
        assert!(
            posted,
            "verified non-cached push commit must post Darwin notification"
        );
    }

    let alice_db =
        MlsAccountDb::open_native(&fixture.alice_db_path, &fixture.alice_db_key, OpenMode::App)
            .unwrap();
    alice_db
        .read_tx(|tx| {
            assert!(tx
                .get_account_meta(&format!("authorized_device_keys:{}", fixture.bob_did))?
                .is_some());
            assert!(tx
                .get_account_meta(&format!("authorized_device_keys:{unknown_did}"))?
                .is_none());
            assert!(tx.get_message(live_mid)?.is_some());
            Ok(())
        })
        .unwrap();
}
