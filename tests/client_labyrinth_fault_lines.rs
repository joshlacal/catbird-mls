//! Integration tests for `CatbirdMlsClient` durable outbox persistence (`[CB-30]`, `I6`)
//! and involuntary kick owner-mode (`v5` `KIND_ATTRIBUTED_FRAME`) fallback & history rescue (`[CB-22]`, `[CB-37]`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use catbird_mls::client::{
    personal_mailbox_space_uri, CatbirdMlsClient, CatbirdMlsClientConfig, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::storage::MessageRow;
use catbird_mls::MLSError;
use tempfile::TempDir;

#[derive(Default)]
struct TestKeystore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl PlatformKeyStore for TestKeystore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x77u8; 32])
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

struct RecordingSpaceTransport {
    convo_put_status: AtomicU16,
    mailbox_put_status: AtomicU16,
    write_requests: Mutex<Vec<serde_json::Value>>,
}

impl RecordingSpaceTransport {
    fn new() -> Self {
        Self {
            convo_put_status: AtomicU16::new(200),
            mailbox_put_status: AtomicU16::new(200),
            write_requests: Mutex::new(Vec::new()),
        }
    }
}

impl PlatformTransport for RecordingSpaceTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if request.url.ends_with("/xrpc/com.atproto.space.getSpace") {
            return Ok(PlatformHttpResponse {
                status: 400,
                headers: Vec::new(),
                body: br#"{"error":"InvalidRequest","message":"Missing space URI"}"#.to_vec(),
            });
        }
        if request.url.ends_with("/xrpc/com.atproto.space.applyWrites") {
            let val: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            let space = val["space"].as_str().unwrap_or_default().to_string();
            let status = if space.contains("/space/blue.catbird.labyrinth.mailbox/self") {
                self.mailbox_put_status.load(Ordering::SeqCst)
            } else {
                self.convo_put_status.load(Ordering::SeqCst)
            };
            if (200..300).contains(&status) || status == 409 {
                self.write_requests.lock().unwrap().push(val);
            }
            return Ok(PlatformHttpResponse {
                status,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
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

#[test]
fn catbird_mls_client_outbox_crash_durability_kick_fallback_and_attributed_history_rescue() {
    let tmp = TempDir::new().expect("tempdir");
    let alice = "did:plc:alicesdk0000000000000";
    let bob = "did:plc:bobpeer00000000000000";
    let ds_did = "did:web:chat.catbird.blue";
    let conv_id = "convo-faultline-sdk";

    let keystore = Arc::new(TestKeystore::default());
    let transport = Arc::new(RecordingSpaceTransport::new());
    let cfg = CatbirdMlsClientConfig {
        storage_root: tmp.path().display().to_string(),
        account_did: alice.to_string(),
        device_id: "dev-ios-fl".to_string(),
        home_ds_did: ds_did.to_string(),
        home_ds_endpoint: "https://chat.catbird.blue".to_string(),
        pds_endpoint: "https://swan.place".to_string(),
    };

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // 1. Open, enroll, create group, send a message, and simulate immediate process crash BEFORE flush!
    let group_id = {
        let client = CatbirdMlsClient::open(cfg.clone(), keystore.clone(), transport.clone(), None)
            .expect("open client");
        client.enroll_device(&all_scopes).expect("enroll");
        let convo = client
            .create_group(conv_id, ds_did, Some("FaultLine Group".to_string()), None)
            .expect("create_group");
        client
            .send_message(conv_id, "msg-outbox-1", "sent right before crash")
            .expect("send_message");

        // Zero Space applyWrites occurred inside send_message's write_tx (I6).
        assert!(transport.write_requests.lock().unwrap().is_empty());

        let pending = client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .expect("list_pending_labyrinth_queue");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].version, 1);
        assert_eq!(pending[0].sender_did, alice);
        assert!(
            pending[0].frame_nonce_b64.is_some(),
            "32-byte frame_nonce must be persisted inside durable outbox payload"
        );
        assert!(pending[0]
            .labyrinth_frame_json
            .contains("sent right before crash"));
        convo.group_id
    };

    // 2. Reopen after simulated crash; first verify healthy conversation Batch write, then transient 503 + kick 403!
    let client = CatbirdMlsClient::open(cfg, keystore, transport.clone(), None)
        .expect("reopen client after crash");
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .unwrap()
            .len(),
        1,
        "durable outbox row must survive process crash/reopen"
    );

    // Verify healthy conversation Space flush produces a canonical `blue.catbird.labyrinth.batch` record via applyWrites!
    let healthy_convo = "convo-healthy-batch";
    client
        .create_group(
            healthy_convo,
            ds_did,
            Some("Healthy Batch".to_string()),
            None,
        )
        .expect("create healthy group");
    client
        .send_message(healthy_convo, "msg-healthy-1", "canonical batch write")
        .expect("send healthy message");

    transport.convo_put_status.store(503, Ordering::SeqCst);
    assert!(
        client.flush_labyrinth_queue().is_err(),
        "transient 503 must surface error and retain rows"
    );
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .unwrap()
            .len(),
        1
    );

    // Kicked from conversation Space (403 Forbidden) -> flush_labyrinth_queue falls back to personal mailbox OwnerBatch!
    transport.convo_put_status.store(403, Ordering::SeqCst);
    let drained = client
        .flush_labyrinth_queue()
        .expect("flush_labyrinth_queue kick fallback");
    assert_eq!(drained, 2);
    assert!(
        client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .unwrap()
            .is_empty(),
        "outbox queue must drain cleanly after owner-mode fallback"
    );

    // Also test a 200 OK conversation write to verify canonical `Batch` schema and `<16-hex-seq>-<tid>` rkey!
    transport.convo_put_status.store(200, Ordering::SeqCst);
    client
        .send_message(healthy_convo, "msg-healthy-2", "real sender batch")
        .expect("send healthy message 2");
    assert_eq!(client.flush_labyrinth_queue().expect("flush healthy"), 1);
    let primary_req = transport
        .write_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(
        primary_req["writes"][0]["$type"].as_str().unwrap(),
        "com.atproto.space.applyWrites#create"
    );
    assert_eq!(
        primary_req["writes"][0]["collection"].as_str().unwrap(),
        "blue.catbird.labyrinth.batch"
    );
    let primary_rkey = primary_req["writes"][0]["rkey"].as_str().unwrap();
    assert_eq!(primary_rkey.len(), 16 + 1 + 13);
    let parsed_batch: labyrinth::records::Batch =
        serde_json::from_value(primary_req["writes"][0]["value"].clone())
            .expect("must parse as canonical labyrinth::records::Batch");
    assert_eq!(
        parsed_batch
            .to_messages()
            .expect("valid SealedMessage")
            .len(),
        1
    );

    let fallback_req = transport
        .write_requests
        .lock()
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(
        fallback_req["space"].as_str().unwrap(),
        personal_mailbox_space_uri(alice)
    );
    assert_eq!(
        fallback_req["writes"][0]["collection"].as_str().unwrap(),
        "blue.catbird.labyrinth.ownerBatch"
    );
    assert_eq!(
        fallback_req["writes"][0]["rkey"].as_str().unwrap().len(),
        13,
        "OwnerBatch rkey must be a canonical 13-character ATProto TID"
    );
    let batch_bytes = serde_json::to_vec(&fallback_req["writes"][0]["value"]).unwrap();
    let opened_fallback = client
        .open_rescued_owner_batch(&batch_bytes)
        .expect("decrypt fallback OwnerBatch");
    assert_eq!(opened_fallback.len(), 1);
    assert_eq!(opened_fallback[0].0, "msg-outbox-1");
    assert_eq!(opened_fallback[0].1.as_deref(), Some(alice));
    assert!(
        String::from_utf8_lossy(&opened_fallback[0].2).contains("sent right before crash"),
        "decrypted owner batch must contain canonical message payload"
    );

    // 3. Seed a peer message from Bob in local SQLCipher cache and run rescue_conversation_on_kick!
    client
        .import_conversation_history(
            conv_id,
            vec![MessageRow {
                message_id: "msg-bob-peer-0".to_string(),
                conversation_id: conv_id.to_string(),
                group_id,
                epoch: 0,
                seq: 1,
                sender_did: bob.to_string(),
                sender_device_id: "dev-bob-1".to_string(),
                plaintext_json: serde_json::json!({ "text": "peer message from Bob" }).to_string(),
                created_at_ms: 1_700_000_000_100,
                is_own: false,
            }],
        )
        .expect("import bob message");

    let rescued = client
        .rescue_conversation_on_kick(conv_id)
        .expect("rescue_conversation_on_kick");
    assert_eq!(rescued, 2);

    let rescue_req = transport
        .write_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    let rescue_bytes = serde_json::to_vec(&rescue_req["writes"][0]["value"]).unwrap();
    let opened_rescue = client
        .open_rescued_owner_batch(&rescue_bytes)
        .expect("decrypt rescued OwnerBatch");
    assert_eq!(opened_rescue.len(), 2);
    assert_eq!(opened_rescue[0].0, "msg-bob-peer-0");
    assert_eq!(
        opened_rescue[0].1.as_deref(),
        Some(bob),
        "peer message rescued into owner mailbox MUST retain Bob's sender_did"
    );
    assert!(String::from_utf8_lossy(&opened_rescue[0].2).contains("peer message from Bob"));
    assert_eq!(opened_rescue[1].0, "msg-outbox-1");
    assert_eq!(opened_rescue[1].1.as_deref(), Some(alice));
}

fn percent_decode_test_param(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct MemorySpacePlatformTransport {
    space_client: labyrinth::store::space::host::SpaceClient,
    rt: tokio::runtime::Runtime,
}

impl MemorySpacePlatformTransport {
    fn new(host: &labyrinth::store::space::host::MemorySpaceHost, did: &str) -> Self {
        Self {
            space_client: host.client(did),
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio current_thread runtime"),
        }
    }
}

impl PlatformTransport for MemorySpacePlatformTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        use labyrinth::store::space::SpaceRpc as _;

        let (path_part, query_opt) = match request.url.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (request.url.as_str(), None),
        };
        let Some((_, nsid)) = path_part.rsplit_once("/xrpc/") else {
            return Ok(PlatformHttpResponse {
                status: 404,
                headers: Vec::new(),
                body: br#"{"error":"NotFound"}"#.to_vec(),
            });
        };

        if nsid == "com.atproto.space.getSpace" && query_opt.is_none() {
            return Ok(PlatformHttpResponse {
                status: 400,
                headers: Vec::new(),
                body: br#"{"error":"InvalidRequest","message":"Missing space URI"}"#.to_vec(),
            });
        }

        let rpc_res = if request.method == "GET" {
            let mut decoded_pairs: Vec<(String, String)> = Vec::new();
            if let Some(q) = query_opt {
                for pair in q.split('&').filter(|s| !s.is_empty()) {
                    if let Some((k, v)) = pair.split_once('=') {
                        decoded_pairs
                            .push((percent_decode_test_param(k), percent_decode_test_param(v)));
                    }
                }
            }
            let borrowed: Vec<(&str, String)> = decoded_pairs
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect();
            self.rt.block_on(self.space_client.query(nsid, &borrowed))
        } else {
            let body = request.body.unwrap_or_default();
            self.rt.block_on(self.space_client.procedure(nsid, &body))
        };

        match rpc_res {
            Ok(bytes) => Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: bytes,
            }),
            Err(err) => {
                let err_json = serde_json::to_vec(&serde_json::json!({
                    "error": err.error.unwrap_or_else(|| "SpaceError".to_string()),
                    "message": err.message,
                }))
                .unwrap();
                Ok(PlatformHttpResponse {
                    status: err.status,
                    headers: Vec::new(),
                    body: err_json,
                })
            }
        }
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

#[test]
fn catbird_mls_client_memory_space_host_cross_device_recovery_and_700_row_pagination() {
    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:alicesdk0000000000000";
    let bob = "did:plc:bobpeer00000000000000";
    let ds_did = "did:web:chat.catbird.blue";
    let conv_id = "convo-700-scale";
    let convo_space = labyrinth::store::space::SpaceRef::parse(&format!(
        "at://{ds_did}/space/blue.catbird.labyrinth.conversation/{conv_id}-0"
    ))
    .unwrap();
    space_host.grant_space_member(&convo_space, alice);

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // -------------------------------------------------------------------------
    // Device 1: enroll, setup recovery code (publishes VirtualDevice to Space),
    // cache 550 messages (> 500 SQL cap), queue 150 outbox items (> 100 flush cap),
    // get kicked (403 on MemorySpaceHost), drain + rescue, then WIPE Device 1!
    // -------------------------------------------------------------------------
    let recovery_code = {
        let tmp1 = TempDir::new().expect("tempdir1");
        let keystore1 = Arc::new(TestKeystore::default());
        let transport1 = Arc::new(MemorySpacePlatformTransport::new(&space_host, alice));
        let client1 = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp1.path().display().to_string(),
                account_did: alice.to_string(),
                device_id: "dev-phone-1".to_string(),
                home_ds_did: ds_did.to_string(),
                home_ds_endpoint: "https://chat.catbird.blue".to_string(),
                pds_endpoint: "https://swan.place".to_string(),
            },
            keystore1,
            transport1,
            None,
        )
        .expect("open device 1");
        client1.enroll_device(&all_scopes).expect("enroll device 1");
        let code = client1
            .setup_recovery_code()
            .expect("setup_recovery_code on device 1");

        let convo = client1
            .create_group(conv_id, ds_did, Some("Scale Group".to_string()), None)
            .expect("create_group");

        // Import 550 cached messages (> 500 list_messages cap), alternating Bob & Alice!
        let mut seeded_msgs = Vec::with_capacity(550);
        for i in 1..=550 {
            let from_bob = i % 2 == 1;
            seeded_msgs.push(MessageRow {
                message_id: format!("cached-msg-{i:04}"),
                conversation_id: conv_id.to_string(),
                group_id: convo.group_id.clone(),
                epoch: 0,
                seq: i as i64,
                sender_did: if from_bob {
                    bob.to_string()
                } else {
                    alice.to_string()
                },
                sender_device_id: if from_bob {
                    "dev-bob-1".to_string()
                } else {
                    "dev-phone-1".to_string()
                },
                plaintext_json: serde_json::json!({ "text": format!("cached history #{i}") })
                    .to_string(),
                created_at_ms: 1_700_100_000_000 + (i as i64) * 10,
                is_own: !from_bob,
            });
        }
        assert_eq!(
            client1
                .import_conversation_history(conv_id, seeded_msgs)
                .expect("import 550 messages"),
            550
        );

        // Queue 150 outbox messages (> 100 flush_labyrinth_queue page cap)!
        for j in 1..=150 {
            client1
                .send_message(
                    conv_id,
                    &format!("queued-msg-{j:04}"),
                    &format!("queued outbox #{j}"),
                )
                .expect("send queued message");
        }
        assert_eq!(
            client1
                .list_pending_labyrinth_queue(Some(conv_id), 300)
                .unwrap()
                .len(),
            150
        );

        // Kick Alice from the conversation Space on MemorySpaceHost -> real 403 Forbidden!
        space_host.revoke_space_member(&convo_space, alice);

        let drained = client1
            .flush_labyrinth_queue()
            .expect("flush 150 queued items across multiple pages on kick");
        assert_eq!(drained, 150);
        assert!(client1
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .unwrap()
            .is_empty());

        // Rescue all 700 cached SQLCipher messages (550 imported + 150 sent) past the 500-row cap!
        let rescued = client1
            .rescue_conversation_on_kick(conv_id)
            .expect("rescue 700 messages");
        assert_eq!(rescued, 700);

        // Idempotent retry: re-running rescue_conversation_on_kick hits 400 RecordAlreadyExists on MemorySpaceHost and succeeds!
        let rescued_again = client1
            .rescue_conversation_on_kick(conv_id)
            .expect("idempotent second rescue");
        assert_eq!(rescued_again, 700);

        code
    };

    // -------------------------------------------------------------------------
    // Device 2: brand-new TempDir + brand-new TestKeystore (zero local secrets!).
    // Restore via 40-char recovery code (with 2 character typos!) from MemorySpaceHost
    // and decrypt all 700 rescued messages with exact sender_did attribution!
    // -------------------------------------------------------------------------
    let tmp2 = TempDir::new().expect("tempdir2");
    let keystore2 = Arc::new(TestKeystore::default());
    let transport2 = Arc::new(MemorySpacePlatformTransport::new(&space_host, alice));
    let client2 = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp2.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-ipad-2".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        keystore2,
        transport2,
        None,
    )
    .expect("open fresh device 2");

    // Wrong recovery code must fail closed on fresh Device 2!
    let wrong_code = labyrinth::recovery_code::RecoveryCode::generate()
        .unwrap()
        .format_grouped();
    assert!(
        client2.restore_with_recovery_code(&wrong_code).is_err(),
        "wrong recovery code must be rejected"
    );

    // Introduce 2 character substitutions (outside the '20' version/identifier prefix) into Device 1's 40-char recovery code!
    let mut typo_chars: Vec<char> = recovery_code.chars().collect();
    let mut alnum_seen = 0usize;
    let mut substituted = 0usize;
    for ch in &mut typo_chars {
        if ch.is_ascii_alphanumeric() {
            alnum_seen += 1;
            if alnum_seen > 2 {
                *ch = if *ch == 'A' { 'C' } else { 'A' };
                substituted += 1;
                if substituted == 2 {
                    break;
                }
            }
        }
    }
    let typoed_code: String = typo_chars.into_iter().collect();

    let restored_status = client2
        .restore_with_recovery_code(&typoed_code)
        .expect("restore_with_recovery_code with 2 character typos on fresh Device 2");
    assert_eq!(restored_status.epoch_seq, 2);

    let restored_count = client2
        .restore_conversation_from_owner_mailbox(conv_id)
        .expect("restore all 700 messages on Device 2");
    assert_eq!(restored_count, 700);

    // Paginate Device 2's local SQLCipher messages to verify all 700 rows and exact sender_did attribution!
    let page1 = client2.list_messages(conv_id, None, 500).unwrap();
    assert_eq!(page1.len(), 500);
    let page2 = client2
        .list_messages(conv_id, Some(page1.last().unwrap().seq), 500)
        .unwrap();
    assert_eq!(page2.len(), 200);

    let all_restored: Vec<MessageRow> = page1.into_iter().chain(page2).collect();
    let bob_msgs: Vec<&MessageRow> = all_restored
        .iter()
        .filter(|m| m.sender_did == bob)
        .collect();
    let alice_msgs: Vec<&MessageRow> = all_restored
        .iter()
        .filter(|m| m.sender_did == alice)
        .collect();
    assert_eq!(
        bob_msgs.len(),
        275,
        "all 275 peer messages from Bob must retain Bob's sender_did on fresh Device 2"
    );
    assert_eq!(
        alice_msgs.len(),
        425,
        "all 425 own messages (275 cached + 150 queued) must retain Alice's sender_did on fresh Device 2"
    );
}

#[test]
fn uniffi_exports_serialize_concurrent_flushes_and_emit_restore_events() {
    use catbird_mls::client::{PlatformChangeEvent, PlatformChangeObserver};

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<PlatformChangeEvent>>,
    }
    impl PlatformChangeObserver for RecordingObserver {
        fn on_change(&self, event: PlatformChangeEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:aliceuniffi000000000";
    let bob = "did:plc:bobuniffi00000000000";
    let ds_did = "did:web:chat.catbird.blue";
    let conv_id = "convo-uniffi-concurrent";
    let convo_space = labyrinth::store::space::SpaceRef::parse(&format!(
        "at://{ds_did}/space/blue.catbird.labyrinth.conversation/{conv_id}-0"
    ))
    .unwrap();
    space_host.grant_space_member(&convo_space, alice);

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let tmp1 = TempDir::new().expect("tempdir1");
    let keystore1 = Arc::new(TestKeystore::default());
    let transport1 = Arc::new(RecordingSpaceTransport::new());
    let client1 = CatbirdMlsClient::ffi_open(
        CatbirdMlsClientConfig {
            storage_root: tmp1.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-ffi-1".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        keystore1,
        transport1.clone(),
        None,
    )
    .expect("ffi_open");
    client1
        .ffi_enroll_device(all_scopes.clone())
        .expect("ffi_enroll_device");
    let convo = client1
        .ffi_create_group(
            conv_id.to_string(),
            ds_did.to_string(),
            Some("UniFFI Concurrent".to_string()),
            None,
        )
        .expect("ffi_create_group");

    for idx in 0..20 {
        client1
            .ffi_send_message(
                conv_id.to_string(),
                format!("msg-conc-{idx:02}"),
                format!("concurrent payload {idx}"),
            )
            .expect("ffi_send_message");
    }
    assert_eq!(
        client1
            .ffi_list_pending_labyrinth_queue(Some(conv_id.to_string()), 50)
            .expect("ffi_list_pending_labyrinth_queue")
            .len(),
        20
    );

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&client1);
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            c.ffi_flush_labyrinth_queue().expect("concurrent ffi_flush")
        }));
    }
    let total_drained: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        total_drained, 20,
        "serialized concurrent ffi_flush_labyrinth_queue calls must commit each item once"
    );
    assert_eq!(
        transport1.write_requests.lock().unwrap().len(),
        20,
        "outbox_flush_lock must prevent duplicate Space applyWrites across concurrent threads"
    );
    assert!(client1
        .ffi_list_pending_labyrinth_queue(None, 50)
        .unwrap()
        .is_empty());

    // Verify closed handle returns ContextClosed immediately on ffi_flush_labyrinth_queue.
    client1
        .ffi_prepare_for_background()
        .expect("ffi_prepare_for_background");
    assert!(matches!(
        client1.ffi_flush_labyrinth_queue(),
        Err(MLSError::ContextClosed)
    ));
    client1
        .ffi_resume_from_background()
        .expect("ffi_resume_from_background");

    // End-to-end UniFFI rescue + fresh-device restore with observer verification on MemorySpaceHost.
    let tmp_space1 = TempDir::new().expect("tmp_space1");
    let ks_space1 = Arc::new(TestKeystore::default());
    let tr_space1 = Arc::new(MemorySpacePlatformTransport::new(&space_host, alice));
    let space_client1 = CatbirdMlsClient::ffi_open(
        CatbirdMlsClientConfig {
            storage_root: tmp_space1.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-space-1".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        ks_space1,
        tr_space1,
        None,
    )
    .unwrap();
    space_client1.ffi_enroll_device(all_scopes).unwrap();
    let code = space_client1.ffi_setup_recovery_code().unwrap();
    space_client1
        .ffi_create_group(conv_id.to_string(), ds_did.to_string(), None, None)
        .unwrap();
    space_client1
        .ffi_import_conversation_history(
            conv_id.to_string(),
            vec![MessageRow {
                message_id: "peer-bob-ffi".to_string(),
                conversation_id: conv_id.to_string(),
                group_id: convo.group_id,
                epoch: 0,
                seq: 1,
                sender_did: bob.to_string(),
                sender_device_id: "dev-bob".to_string(),
                plaintext_json: r#"{"text":"bob via ffi"}"#.to_string(),
                created_at_ms: 1_700_200_000_000,
                is_own: false,
            }],
        )
        .unwrap();
    space_client1
        .ffi_send_message(
            conv_id.to_string(),
            "own-alice-ffi".to_string(),
            "alice via ffi".to_string(),
        )
        .unwrap();
    space_host.revoke_space_member(&convo_space, alice);
    assert_eq!(
        space_client1
            .ffi_rescue_conversation_on_kick(conv_id.to_string())
            .expect("ffi_rescue_conversation_on_kick"),
        2
    );

    let tmp_space2 = TempDir::new().expect("tmp_space2");
    let obs2 = Arc::new(RecordingObserver::default());
    let obs_dyn: Arc<dyn PlatformChangeObserver> = obs2.clone();
    let space_client2 = CatbirdMlsClient::ffi_open(
        CatbirdMlsClientConfig {
            storage_root: tmp_space2.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-space-2".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TestKeystore::default()),
        Arc::new(MemorySpacePlatformTransport::new(&space_host, alice)),
        Some(obs_dyn),
    )
    .unwrap();
    space_client2.ffi_restore_with_recovery_code(code).unwrap();
    obs2.events.lock().unwrap().clear();

    assert_eq!(
        space_client2
            .ffi_restore_conversation_from_owner_mailbox(conv_id.to_string())
            .expect("ffi_restore_conversation_from_owner_mailbox"),
        2
    );
    let recorded = obs2.events.lock().unwrap().clone();
    assert!(recorded.contains(&PlatformChangeEvent::ConversationsUpdated));
    assert!(recorded.contains(&PlatformChangeEvent::MessagesUpdated {
        conversation_id: conv_id.to_string(),
    }));
}

#[test]
fn flush_labyrinth_queue_partial_batch_retry_preserves_deterministic_rkeys_without_duplicates() {
    use labyrinth::store::space::SpaceRpc as _;

    struct CommitThenFailOnceTransport {
        inner: MemorySpacePlatformTransport,
        fail_next_batch_after_commit: std::sync::atomic::AtomicBool,
        fail_next_owner_batch_after_commit: std::sync::atomic::AtomicBool,
        batch_call_count: std::sync::atomic::AtomicUsize,
        owner_batch_call_count: std::sync::atomic::AtomicUsize,
    }

    impl PlatformTransport for CommitThenFailOnceTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            let mut is_second_batch = false;
            let mut is_second_owner_batch = false;
            if request.url.ends_with("/xrpc/com.atproto.space.applyWrites") {
                if let Some(ref body) = request.body {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
                        let coll = val["writes"][0]["collection"].as_str().unwrap_or_default();
                        if coll == labyrinth::records::nsid::BATCH {
                            let idx = self.batch_call_count.fetch_add(1, Ordering::SeqCst);
                            if idx == 1 {
                                is_second_batch = true;
                            }
                        } else if coll == labyrinth::records::nsid::OWNER_BATCH {
                            let idx = self.owner_batch_call_count.fetch_add(1, Ordering::SeqCst);
                            if idx == 1 {
                                is_second_owner_batch = true;
                            }
                        }
                    }
                }
            }
            let real_resp = self.inner.execute_http(request)?;
            if is_second_batch
                && self
                    .fail_next_batch_after_commit
                    .swap(false, Ordering::SeqCst)
            {
                assert_eq!(real_resp.status, 200);
                return Ok(PlatformHttpResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: br#"{"error":"BadGateway","message":"dropped response after commit"}"#
                        .to_vec(),
                });
            }
            if is_second_owner_batch
                && self
                    .fail_next_owner_batch_after_commit
                    .swap(false, Ordering::SeqCst)
            {
                assert_eq!(real_resp.status, 200);
                return Ok(PlatformHttpResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: br#"{"error":"BadGateway","message":"dropped fallback response after commit"}"#
                        .to_vec(),
                });
            }
            Ok(real_resp)
        }

        fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
            Ok(())
        }
        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:alicerkeyretry000000";
    let ds_did = "did:web:chat.catbird.blue";
    let conv_primary = "convo-rkey-primary";
    let conv_fallback = "convo-rkey-fallback";
    let primary_space_uri =
        format!("at://{ds_did}/space/blue.catbird.labyrinth.conversation/{conv_primary}-0");
    let primary_space_ref = labyrinth::store::space::SpaceRef::parse(&primary_space_uri).unwrap();
    space_host.grant_space_member(&primary_space_ref, alice);

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let tmp = TempDir::new().expect("tempdir");
    let transport = Arc::new(CommitThenFailOnceTransport {
        inner: MemorySpacePlatformTransport::new(&space_host, alice),
        fail_next_batch_after_commit: std::sync::atomic::AtomicBool::new(true),
        fail_next_owner_batch_after_commit: std::sync::atomic::AtomicBool::new(true),
        batch_call_count: std::sync::atomic::AtomicUsize::new(0),
        owner_batch_call_count: std::sync::atomic::AtomicUsize::new(0),
    });
    let client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-rkey-1".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TestKeystore::default()),
        transport.clone(),
        None,
    )
    .unwrap();
    client.enroll_device(&all_scopes).unwrap();
    client
        .create_group(conv_primary, ds_did, None, None)
        .unwrap();
    for i in 1..=3 {
        client
            .send_message(
                conv_primary,
                &format!("p-msg-{i}"),
                &format!("primary #{i}"),
            )
            .unwrap();
    }

    // 1st flush: item 1 commits & dequeues; item 2 commits on Space then returns 502; item 3 untouched.
    assert!(client.flush_labyrinth_queue().is_err());
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(conv_primary), 10)
            .unwrap()
            .len(),
        2
    );

    // 2nd flush: item 2 is now at slice index 0 instead of 1 -> must produce identical rkey (`RecordAlreadyExists`)!
    assert_eq!(client.flush_labyrinth_queue().unwrap(), 2);
    assert!(client
        .list_pending_labyrinth_queue(Some(conv_primary), 10)
        .unwrap()
        .is_empty());

    let listed_primary = transport
        .inner
        .rt
        .block_on(transport.inner.space_client.query(
            "com.atproto.space.listRecords",
            &[
                ("space", primary_space_uri),
                ("repo", alice.to_string()),
                ("collection", labyrinth::records::nsid::BATCH.to_string()),
                ("limit", "100".to_string()),
            ],
        ))
        .unwrap();
    let parsed_primary: serde_json::Value = serde_json::from_slice(&listed_primary).unwrap();
    assert_eq!(
        parsed_primary["records"].as_array().unwrap().len(),
        3,
        "partial-batch retry must deduplicate via deterministic rkey without writing a 4th duplicate Batch"
    );

    // Repeat for 403 kick OwnerBatch fallback!
    let fallback_space_uri =
        format!("at://{ds_did}/space/blue.catbird.labyrinth.conversation/{conv_fallback}-0");
    let fallback_space_ref = labyrinth::store::space::SpaceRef::parse(&fallback_space_uri).unwrap();
    space_host.grant_space_member(&fallback_space_ref, alice);
    space_host.revoke_space_member(&fallback_space_ref, alice);

    client
        .create_group(conv_fallback, ds_did, None, None)
        .unwrap();
    for i in 1..=3 {
        client
            .send_message(
                conv_fallback,
                &format!("fb-msg-{i}"),
                &format!("fallback #{i}"),
            )
            .unwrap();
    }
    // Alice was revoked from conv_fallback's Space -> MemorySpaceHost returns 403 -> OwnerBatch fallback!
    assert!(client.flush_labyrinth_queue().is_err());
    assert_eq!(
        client
            .list_pending_labyrinth_queue(Some(conv_fallback), 10)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(client.flush_labyrinth_queue().unwrap(), 2);

    let listed_fb = transport
        .inner
        .rt
        .block_on(transport.inner.space_client.query(
            "com.atproto.space.listRecords",
            &[
                ("space", personal_mailbox_space_uri(alice)),
                ("repo", alice.to_string()),
                (
                    "collection",
                    labyrinth::records::nsid::OWNER_BATCH.to_string(),
                ),
                ("limit", "100".to_string()),
            ],
        ))
        .unwrap();
    let parsed_fb: serde_json::Value = serde_json::from_slice(&listed_fb).unwrap();
    assert_eq!(
        parsed_fb["records"].as_array().unwrap().len(),
        3,
        "partial-batch OwnerBatch fallback retry must deduplicate via deterministic rkey without writing a 4th duplicate OwnerBatch"
    );
}

#[test]
fn flush_labyrinth_queue_isolates_per_conversation_503_across_120_rows() {
    struct SelectiveStallTransport {
        inner: MemorySpacePlatformTransport,
        stalled_space_substring: String,
        stall_enabled: std::sync::atomic::AtomicBool,
    }

    impl PlatformTransport for SelectiveStallTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            if self.stall_enabled.load(Ordering::SeqCst)
                && request.url.ends_with("/xrpc/com.atproto.space.applyWrites")
            {
                if let Some(ref body) = request.body {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
                        if val["space"]
                            .as_str()
                            .unwrap_or_default()
                            .contains(&self.stalled_space_substring)
                        {
                            return Ok(PlatformHttpResponse {
                                status: 503,
                                headers: Vec::new(),
                                body: br#"{"error":"ServiceUnavailable"}"#.to_vec(),
                            });
                        }
                    }
                }
            }
            self.inner.execute_http(request)
        }

        fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
            Ok(())
        }
        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:alicehol000000000000";
    let ds_did = "did:web:chat.catbird.blue";
    let convo_stalled = "convo-stalled-120";
    let convo_healthy = "convo-healthy-15";

    for cid in [convo_stalled, convo_healthy] {
        let sref = labyrinth::store::space::SpaceRef::parse(&format!(
            "at://{ds_did}/space/blue.catbird.labyrinth.conversation/{cid}-0"
        ))
        .unwrap();
        space_host.grant_space_member(&sref, alice);
    }

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let tmp = TempDir::new().expect("tempdir");
    let transport = Arc::new(SelectiveStallTransport {
        inner: MemorySpacePlatformTransport::new(&space_host, alice),
        stalled_space_substring: convo_stalled.to_string(),
        stall_enabled: std::sync::atomic::AtomicBool::new(true),
    });
    let client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-hol-1".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TestKeystore::default()),
        transport.clone(),
        None,
    )
    .unwrap();
    client.enroll_device(&all_scopes).unwrap();
    client
        .create_group(convo_stalled, ds_did, None, None)
        .unwrap();
    client
        .create_group(convo_healthy, ds_did, None, None)
        .unwrap();

    // Enqueue 120 rows (> 100 SQL page cap!) in convo_stalled FIRST, then 15 rows in convo_healthy.
    for i in 1..=120 {
        client
            .send_message(
                convo_stalled,
                &format!("stalled-{i:03}"),
                &format!("stalled #{i}"),
            )
            .unwrap();
    }
    for j in 1..=15 {
        client
            .send_message(
                convo_healthy,
                &format!("healthy-{j:03}"),
                &format!("healthy #{j}"),
            )
            .unwrap();
    }

    // Flush while convo_stalled returns 503: convo_healthy MUST still drain completely!
    assert!(
        client.flush_labyrinth_queue().is_err(),
        "stalled conversation 503 must still report error"
    );
    assert!(
        client
            .list_pending_labyrinth_queue(Some(convo_healthy), 50)
            .unwrap()
            .is_empty(),
        "healthy conversation must NOT suffer head-of-line starvation behind 120 stalled rows"
    );
    let stalled_remaining = client
        .list_pending_labyrinth_queue(Some(convo_stalled), 200)
        .unwrap();
    assert_eq!(stalled_remaining.len(), 120);
    let seqs: Vec<i64> = stalled_remaining.iter().map(|p| p.seq).collect();
    let expected_seqs: Vec<i64> = (2..=121).collect();
    assert_eq!(
        seqs, expected_seqs,
        "stalled conversation queue must preserve strict causal seq order"
    );

    // Heal 503 -> all 120 stalled rows drain cleanly across 2 pages!
    transport.stall_enabled.store(false, Ordering::SeqCst);
    assert_eq!(client.flush_labyrinth_queue().unwrap(), 120);
    assert!(client
        .list_pending_labyrinth_queue(None, 200)
        .unwrap()
        .is_empty());
}

#[test]
fn flush_labyrinth_queue_aborts_in_flight_loop_immediately_when_handle_closes() {
    struct CloseOnFirstWriteTransport {
        inner: MemorySpacePlatformTransport,
        batch_writes_seen: std::sync::atomic::AtomicUsize,
        first_write_entered_tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        resume_first_write_rx: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl PlatformTransport for CloseOnFirstWriteTransport {
        fn execute_http(
            &self,
            request: PlatformHttpRequest,
        ) -> Result<PlatformHttpResponse, MLSError> {
            let mut is_batch = false;
            if request.url.ends_with("/xrpc/com.atproto.space.applyWrites") {
                if let Some(ref body) = request.body {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
                        if val["writes"][0]["collection"].as_str()
                            == Some(labyrinth::records::nsid::BATCH)
                        {
                            is_batch = true;
                        }
                    }
                }
            }
            if is_batch {
                let n = self.batch_writes_seen.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    if let Some(tx) = self.first_write_entered_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = self.resume_first_write_rx.lock().unwrap().take() {
                        let _ = rx.recv();
                    }
                }
            }
            self.inner.execute_http(request)
        }

        fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
            Ok(())
        }
        fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
            Ok(())
        }
    }

    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:aliceclose0000000000";
    let ds_did = "did:web:chat.catbird.blue";
    let conv_id = "convo-close-mid-flush";
    let sref = labyrinth::store::space::SpaceRef::parse(&format!(
        "at://{ds_did}/space/blue.catbird.labyrinth.conversation/{conv_id}-0"
    ))
    .unwrap();
    space_host.grant_space_member(&sref, alice);

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();

    let tmp = TempDir::new().expect("tempdir");
    let transport = Arc::new(CloseOnFirstWriteTransport {
        inner: MemorySpacePlatformTransport::new(&space_host, alice),
        batch_writes_seen: std::sync::atomic::AtomicUsize::new(0),
        first_write_entered_tx: Mutex::new(Some(entered_tx)),
        resume_first_write_rx: Mutex::new(Some(resume_rx)),
    });
    let client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-close-1".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TestKeystore::default()),
        transport.clone(),
        None,
    )
    .unwrap();
    client.enroll_device(&all_scopes).unwrap();
    client.create_group(conv_id, ds_did, None, None).unwrap();
    for i in 1..=10 {
        client
            .send_message(conv_id, &format!("close-msg-{i}"), &format!("body #{i}"))
            .unwrap();
    }

    let flush_client = Arc::clone(&client);
    let flush_handle = std::thread::spawn(move || flush_client.flush_labyrinth_queue());

    // Wait until flush_labyrinth_queue is inside the 1st applyWrites HTTP call, then suspend to background!
    entered_rx.recv().unwrap();
    client
        .prepare_for_background()
        .expect("prepare_for_background while HTTP write is in flight");
    assert!(client.is_handle_closed());
    resume_tx.send(()).unwrap();

    let res = flush_handle.join().unwrap();
    assert!(
        matches!(res, Err(MLSError::ContextClosed)),
        "in-flight flush must abort with ContextClosed once handle closes, got {res:?}"
    );
    assert_eq!(
        transport.batch_writes_seen.load(Ordering::SeqCst),
        1,
        "flush loop must stop immediately after the in-flight HTTP request instead of issuing remaining 9 HTTP writes"
    );

    // Resume from background and drain remaining items cleanly with deterministic rkey deduplication!
    client.resume_from_background().unwrap();
    assert_eq!(client.flush_labyrinth_queue().unwrap(), 10);
    assert!(client
        .list_pending_labyrinth_queue(Some(conv_id), 20)
        .unwrap()
        .is_empty());
}

#[test]
fn multi_epoch_and_three_device_recovery_code_chain_recovers_all_owner_batches() {
    let space_host = labyrinth::store::space::host::MemorySpaceHost::new();
    let alice = "did:plc:alicemultiepoch00000";
    let bob = "did:plc:bobmultiepoch0000000";
    let ds_did = "did:web:chat.catbird.blue";

    let all_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // -------------------------------------------------------------------------
    // Device 1:
    // - Epoch 1: rescue `convo-ep1` (BEFORE setup_recovery_code and BEFORE OTC!)
    // - OTC pairing -> rotates Space 1 -> 2: rescue `convo-ep2`
    // - setup_recovery_code() at Epoch 2 -> generates 40-char `recovery_code`
    // - revoke_labyrinth_device -> rotates Space 2 -> 3: rescue `convo-ep3`
    // -------------------------------------------------------------------------
    let recovery_code = {
        let tmp1 = TempDir::new().expect("tmp1");
        let client1 = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp1.path().display().to_string(),
                account_did: alice.to_string(),
                device_id: "dev-chain-1".to_string(),
                home_ds_did: ds_did.to_string(),
                home_ds_endpoint: "https://chat.catbird.blue".to_string(),
                pds_endpoint: "https://swan.place".to_string(),
            },
            Arc::new(TestKeystore::default()),
            Arc::new(MemorySpacePlatformTransport::new(&space_host, alice)),
            None,
        )
        .unwrap();
        client1.enroll_device(&all_scopes).unwrap();
        assert_eq!(client1.labyrinth_status().unwrap().epoch_seq, 1);

        let c1 = client1
            .create_group("convo-ep1", ds_did, None, None)
            .unwrap();
        client1
            .import_conversation_history(
                "convo-ep1",
                vec![MessageRow {
                    message_id: "ep1-bob-msg".to_string(),
                    conversation_id: "convo-ep1".to_string(),
                    group_id: c1.group_id,
                    epoch: 0,
                    seq: 1,
                    sender_did: bob.to_string(),
                    sender_device_id: "bob-dev".to_string(),
                    plaintext_json: r#"{"text":"bob at epoch 1"}"#.to_string(),
                    created_at_ms: 1_700_300_000_001,
                    is_own: false,
                }],
            )
            .unwrap();
        assert_eq!(client1.rescue_conversation_on_kick("convo-ep1").unwrap(), 1);

        // Rotate 1 -> 2 via hybrid PQ OTC pairing!
        let offer = client1.initiate_otc_pairing().unwrap();
        let otc_done = client1.complete_otc_pairing(&offer.six_digit_code).unwrap();
        assert_eq!(otc_done.new_epoch_seq, 2);

        client1
            .create_group("convo-ep2", ds_did, None, None)
            .unwrap();
        client1
            .send_message("convo-ep2", "ep2-alice-msg", "alice at epoch 2")
            .unwrap();
        assert_eq!(client1.rescue_conversation_on_kick("convo-ep2").unwrap(), 1);

        // Setup 40-char recovery code at Epoch 2!
        let code = client1.setup_recovery_code().unwrap();

        // Rotate 2 -> 3 via device revocation AFTER setup_recovery_code!
        let rev_status = client1
            .revoke_labyrinth_device("stale-peer-device")
            .unwrap();
        assert_eq!(rev_status.epoch_seq, 3);

        client1
            .create_group("convo-ep3", ds_did, None, None)
            .unwrap();
        client1
            .send_message("convo-ep3", "ep3-alice-msg", "alice at epoch 3 post-revoke")
            .unwrap();
        assert_eq!(client1.rescue_conversation_on_kick("convo-ep3").unwrap(), 1);

        code
    };

    // -------------------------------------------------------------------------
    // Device 2 (fresh keystore + DB):
    // - Restores with `recovery_code` -> chains backward (2->1->0), forward (2->3),
    //   and publishes atomic rotation 3 -> 4!
    // - Recovers `convo-ep1`, `convo-ep2`, AND `convo-ep3`!
    // - Rescues `convo-ep4` at Epoch 4, then Device 2 is also lost!
    // -------------------------------------------------------------------------
    {
        let tmp2 = TempDir::new().expect("tmp2");
        let client2 = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: tmp2.path().display().to_string(),
                account_did: alice.to_string(),
                device_id: "dev-chain-2".to_string(),
                home_ds_did: ds_did.to_string(),
                home_ds_endpoint: "https://chat.catbird.blue".to_string(),
                pds_endpoint: "https://swan.place".to_string(),
            },
            Arc::new(TestKeystore::default()),
            Arc::new(MemorySpacePlatformTransport::new(&space_host, alice)),
            None,
        )
        .unwrap();
        let st2 = client2
            .restore_with_recovery_code(&recovery_code)
            .expect("Device 2 restore_with_recovery_code across multi-epoch history");
        assert_eq!(st2.epoch_seq, 4);

        assert_eq!(
            client2
                .restore_conversation_from_owner_mailbox("convo-ep1")
                .expect("recover epoch 1 via backward_chain"),
            1
        );
        assert_eq!(
            client2
                .restore_conversation_from_owner_mailbox("convo-ep2")
                .expect("recover epoch 2 from bundle epoch"),
            1
        );
        assert_eq!(
            client2
                .restore_conversation_from_owner_mailbox("convo-ep3")
                .expect("recover epoch 3 via forward_chain"),
            1
        );

        let ep1_msgs = client2.list_messages("convo-ep1", None, 10).unwrap();
        assert_eq!(ep1_msgs[0].sender_did, bob);
        assert!(ep1_msgs[0].plaintext_json.contains("bob at epoch 1"));

        // Rescue a new conversation at Epoch 4 on Device 2!
        client2
            .create_group("convo-ep4", ds_did, None, None)
            .unwrap();
        client2
            .send_message("convo-ep4", "ep4-dev2-msg", "sent on device 2 at epoch 4")
            .unwrap();
        assert_eq!(client2.rescue_conversation_on_kick("convo-ep4").unwrap(), 1);
    }

    // -------------------------------------------------------------------------
    // Device 3 (another fresh keystore + DB):
    // - Restores using the EXACT SAME 40-char `recovery_code` from Device 1!
    // - Chains backward (2->1->0) and forward (2->3->4, across Device 2's enrollment
    //   rotation!) and rotates 4 -> 5!
    // - Recovers ALL FOUR conversations (`convo-ep1`..`convo-ep4`)!
    // -------------------------------------------------------------------------
    let tmp3 = TempDir::new().expect("tmp3");
    let client3 = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: tmp3.path().display().to_string(),
            account_did: alice.to_string(),
            device_id: "dev-chain-3".to_string(),
            home_ds_did: ds_did.to_string(),
            home_ds_endpoint: "https://chat.catbird.blue".to_string(),
            pds_endpoint: "https://swan.place".to_string(),
        },
        Arc::new(TestKeystore::default()),
        Arc::new(MemorySpacePlatformTransport::new(&space_host, alice)),
        None,
    )
    .unwrap();
    let st3 = client3
        .restore_with_recovery_code(&recovery_code)
        .expect("Device 3 restore_with_recovery_code with original 40-char code");
    assert_eq!(st3.epoch_seq, 5);

    for cid in ["convo-ep1", "convo-ep2", "convo-ep3", "convo-ep4"] {
        assert_eq!(
            client3
                .restore_conversation_from_owner_mailbox(cid)
                .unwrap_or_else(|e| panic!("Device 3 failed to restore {cid}: {e}")),
            1
        );
    }
    let ep4_msgs = client3.list_messages("convo-ep4", None, 10).unwrap();
    assert_eq!(ep4_msgs[0].sender_did, alice);
    assert!(ep4_msgs[0]
        .plaintext_json
        .contains("sent on device 2 at epoch 4"));
}
