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
    put_requests: Mutex<Vec<serde_json::Value>>,
}

impl RecordingSpaceTransport {
    fn new() -> Self {
        Self {
            convo_put_status: AtomicU16::new(200),
            mailbox_put_status: AtomicU16::new(200),
            put_requests: Mutex::new(Vec::new()),
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
        if request.url.ends_with("/xrpc/com.atproto.space.putRecords") {
            let val: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            let space = val["space"].as_str().unwrap_or_default().to_string();
            let status = if space.contains("/space/blue.catbird.labyrinth.mailbox/self") {
                self.mailbox_put_status.load(Ordering::SeqCst)
            } else {
                self.convo_put_status.load(Ordering::SeqCst)
            };
            if (200..300).contains(&status) || status == 409 {
                self.put_requests.lock().unwrap().push(val);
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

        // Zero Space putRecords occurred inside send_message's write_tx (I6).
        assert!(transport.put_requests.lock().unwrap().is_empty());

        let pending = client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .expect("list_pending_labyrinth_queue");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].version, 1);
        assert_eq!(pending[0].sender_did, alice);
        assert!(pending[0]
            .labyrinth_frame_json
            .contains("sent right before crash"));
        convo.group_id
    };

    // 2. Reopen after simulated crash; simulate transient 503 then involuntary kick (403 Forbidden) on conversation Space!
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

    transport.convo_put_status.store(503, Ordering::SeqCst);
    assert!(
        client.flush_labyrinth_queue().is_err(),
        "transient 503 must surface error and retain row"
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
    assert_eq!(drained, 1);
    assert!(
        client
            .list_pending_labyrinth_queue(Some(conv_id), 10)
            .unwrap()
            .is_empty(),
        "outbox queue must drain cleanly after owner-mode fallback"
    );

    let fallback_req = transport
        .put_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(
        fallback_req["space"].as_str().unwrap(),
        personal_mailbox_space_uri(alice)
    );
    assert_eq!(
        fallback_req["records"][0]["collection"].as_str().unwrap(),
        "blue.catbird.labyrinth.ownerBatch"
    );
    let batch_bytes = serde_json::to_vec(&fallback_req["records"][0]["value"]).unwrap();
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
        .put_requests
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    let rescue_bytes = serde_json::to_vec(&rescue_req["records"][0]["value"]).unwrap();
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
