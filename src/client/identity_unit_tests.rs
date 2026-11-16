//! Identity hardening: strict DID resolution, declaration proofs, device directory, own-device
//! detection and leaf-recovery gating.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::client::config::CatbirdMlsClientConfig;
use crate::client::did_resolution::{
    did_doc_cache_key, did_doc_meta_key, resolve_did_document_observed,
    resolve_did_document_strict, DID_DOC_CACHE_TTL_MS, MAX_DID_DOCUMENT_BYTES,
};
use crate::client::traits::{
    PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore,
    PlatformTransport,
};
use crate::client::CatbirdMlsClient;
use crate::error::MLSError;

pub(crate) const OWN_DID: &str = "did:plc:identityownaaaaaaaaaaaaa";
pub(crate) const OWN_DEVICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(crate) const PDS_URL: &str = "https://own-pds.example.com";
pub(crate) const DS_URL: &str = "https://mlschat.example.com";
pub(crate) const DS_DID: &str = "did:web:mlschat.example.com";

pub(crate) type Handler =
    Box<dyn FnMut(&PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> + Send>;

#[derive(Default)]
pub(crate) struct IdentityMockState {
    pub requests: Vec<PlatformHttpRequest>,
    pub queued: HashMap<String, VecDeque<Result<PlatformHttpResponse, MLSError>>>,
    pub handlers: Vec<(String, Handler)>,
}

pub(crate) struct IdentityMockTransport {
    pub state: Mutex<IdentityMockState>,
}

impl IdentityMockTransport {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(IdentityMockState::default()),
        })
    }

    pub fn queue(&self, url: &str, response: Result<PlatformHttpResponse, MLSError>) {
        self.state
            .lock()
            .unwrap()
            .queued
            .entry(url.to_owned())
            .or_default()
            .push_back(response);
    }

    pub fn route(&self, needle: &str, handler: Handler) {
        self.state
            .lock()
            .unwrap()
            .handlers
            .push((needle.to_owned(), handler));
    }

    pub fn urls(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|r| r.url.clone())
            .collect()
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().requests.clear();
    }
}

impl PlatformTransport for IdentityMockTransport {
    fn execute_http(&self, req: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        let mut st = self.state.lock().unwrap();
        st.requests.push(req.clone());
        if let Some(queue) = st.queued.get_mut(&req.url) {
            if let Some(resp) = queue.pop_front() {
                return resp;
            }
        }
        for (needle, handler) in &mut st.handlers {
            if req.url.contains(needle.as_str()) {
                return handler(&req);
            }
        }
        json_response(404, &json!({ "error": "NotFound", "url": req.url }))
    }

    fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

pub(crate) struct MemKeyStore(Mutex<HashMap<String, Vec<u8>>>);

impl PlatformKeyStore for MemKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| vec![0x5a; 32])
            .clone())
    }
    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(&key_id).cloned())
    }
    fn store_signature_keypair(&self, key_id: String, bytes: Vec<u8>) -> Result<(), MLSError> {
        self.0.lock().unwrap().insert(key_id, bytes);
        Ok(())
    }
    fn delete_account_keys(&self, _account_did_hash: String) -> Result<(), MLSError> {
        Ok(())
    }
    fn load_cached_chat_dpop_token(&self, _: String) -> Result<Option<String>, MLSError> {
        Ok(None)
    }
    fn store_cached_chat_dpop_token(&self, _: String, _: String, _: i64) -> Result<(), MLSError> {
        Ok(())
    }
}

pub(crate) fn json_response(status: u16, val: &Value) -> Result<PlatformHttpResponse, MLSError> {
    Ok(PlatformHttpResponse {
        status,
        headers: vec![PlatformHttpHeader {
            name: "content-type".into(),
            value: "application/json".into(),
        }],
        body: serde_json::to_vec(val).unwrap(),
    })
}

pub(crate) fn open_client(
    transport: Arc<IdentityMockTransport>,
) -> (tempfile::TempDir, Arc<CatbirdMlsClient>) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = CatbirdMlsClientConfig {
        account_did: OWN_DID.into(),
        device_id: OWN_DEVICE.into(),
        storage_root: dir.path().to_string_lossy().into_owned(),
        home_ds_did: DS_DID.into(),
        home_ds_endpoint: DS_URL.into(),
        pds_endpoint: PDS_URL.into(),
    };
    let client = CatbirdMlsClient::open(
        cfg,
        Arc::new(MemKeyStore(Mutex::new(HashMap::new()))),
        transport,
        None,
    )
    .unwrap();
    (dir, client)
}

pub(crate) fn doc_for(did: &str, atproto_key: &str) -> Value {
    json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": atproto_key,
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://peer-pds.example.net",
        }]
    })
}

// ---------------------------------------------------------------------------------------------
// Strict resolution
// ---------------------------------------------------------------------------------------------

#[test]
fn resolver_fetches_only_plc_directory_or_the_did_web_host() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    let plc_peer = "did:plc:peerplcbbbbbbbbbbbbbbbbb";
    let web_peer = "did:web:peer.example.net";
    let path_peer = "did:web:peer.example.net:users:bob";
    transport.queue(
        &format!("https://plc.directory/{plc_peer}"),
        json_response(200, &doc_for(plc_peer, "zPlcKey")),
    );
    transport.queue(
        "https://peer.example.net/.well-known/did.json",
        json_response(200, &doc_for(web_peer, "zWebKey")),
    );
    transport.queue(
        "https://peer.example.net/users/bob/did.json",
        json_response(200, &doc_for(path_peer, "zPathKey")),
    );
    transport.queue(
        &format!("https://plc.directory/{OWN_DID}"),
        json_response(200, &doc_for(OWN_DID, "zOwnKey")),
    );

    for did in [plc_peer, web_peer, path_peer, OWN_DID] {
        assert!(client.resolve_did_document(did).unwrap().is_some(), "{did}");
    }
    assert_eq!(
        transport.urls(),
        vec![
            format!("https://plc.directory/{plc_peer}"),
            "https://peer.example.net/.well-known/did.json".to_string(),
            "https://peer.example.net/users/bob/did.json".to_string(),
            format!("https://plc.directory/{OWN_DID}"),
        ],
        "no DID, the account's own included, is ever resolved through an account PDS"
    );
    let state = transport.state.lock().unwrap();
    assert!(
        state
            .requests
            .iter()
            .all(|r| r.headers.is_empty() && r.body.is_none()),
        "resolver requests carry no credentials"
    );
}

#[test]
fn resolver_refuses_private_network_targets_before_any_request() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    for did in [
        "did:web:localhost",
        "did:web:localhost%3A3001",
        "did:web:127.0.0.1",
        "did:web:10.1.2.3",
        "did:web:169.254.169.254",
        "did:web:%5B%3A%3A1%5D",
        "did:web:intranet",
        "did:web:printer.local",
        "did:web:metadata.internal",
        "did:web:peer.example.net%3A8443",
        "did:web:peer.example.net:..:etc",
        "did:plc:short",
    ] {
        assert!(
            client.resolve_did_document(did).is_err(),
            "{did} must be refused"
        );
        assert!(
            client
                .resolve_sequencer_receipt_key(did, &format!("{did}#mls-receipt-1"))
                .is_err(),
            "{did} must never yield a receipt key"
        );
    }
    assert!(
        transport.urls().is_empty(),
        "refused DIDs must not reach the network: {:?}",
        transport.urls()
    );
}

#[test]
fn resolver_refuses_redirects_oversized_and_mismatched_documents() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    let peer = "did:web:redirect.example.net";
    let url = "https://redirect.example.net/.well-known/did.json";
    let mut redirect = json_response(302, &json!({})).unwrap();
    redirect.headers.push(PlatformHttpHeader {
        name: "location".into(),
        value: "http://169.254.169.254/latest/meta-data".into(),
    });
    transport.queue(url, Ok(redirect));
    assert!(
        client.resolve_did_document(peer).is_err(),
        "redirect refused"
    );

    let mut huge = doc_for(peer, "zKey");
    huge["padding"] = json!("x".repeat(MAX_DID_DOCUMENT_BYTES));
    transport.queue(url, json_response(200, &huge));
    assert!(
        client.resolve_did_document(peer).is_err(),
        "oversized refused"
    );

    transport.queue(
        url,
        json_response(200, &doc_for("did:web:other.example.net", "zKey")),
    );
    assert!(
        client.resolve_did_document(peer).is_err(),
        "id mismatch refused"
    );

    assert_eq!(transport.urls(), vec![url.to_string(); 3]);
    let cached = client
        .db
        .read_tx(|tx| tx.get_account_meta(&did_doc_cache_key(peer)))
        .unwrap();
    assert!(cached.is_none(), "nothing refused is cached");
}

#[test]
fn resolver_never_asks_the_account_pds_even_when_did_web_host_fails() {
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    transport.route(
        "/xrpc/com.atproto.identity.resolveDid",
        Box::new(|req| {
            let did = req
                .url
                .split("did=")
                .nth(1)
                .unwrap_or_default()
                .replace("%3A", ":");
            json_response(
                200,
                &json!({ "didDoc": doc_for(&did, "zForgedByAccountPds") }),
            )
        }),
    );
    let peer = "did:web:down.example.net";
    transport.queue(
        "https://down.example.net/.well-known/did.json",
        json_response(503, &json!({ "error": "Unavailable" })),
    );
    assert!(client.resolve_did_document(peer).is_err());
    transport.queue(
        "https://mlschat.example.com/.well-known/did.json",
        json_response(500, &json!({ "error": "x" })),
    );
    assert!(
        client.resolve_did_document(DS_DID).is_err(),
        "the home sequencer has no account-PDS or alternate-endpoint fallback"
    );
    assert!(
        transport
            .urls()
            .iter()
            .all(|u| !u.contains("com.atproto.identity.resolveDid") && !u.starts_with(PDS_URL)),
        "account PDS must never resolve DIDs: {:?}",
        transport.urls()
    );
}

// ---------------------------------------------------------------------------------------------
// Cache: provenance, age limit, atomic replacement, background reads
// ---------------------------------------------------------------------------------------------

fn failing_transport_for(url: &str) -> Arc<IdentityMockTransport> {
    let transport = IdentityMockTransport::new();
    let failing = url.to_owned();
    transport.route(
        &failing,
        Box::new(|_| Err(MLSError::Internal("network unreachable".into()))),
    );
    transport
}

#[test]
fn cache_serves_only_fresh_documents_this_resolver_fetched() {
    let url = "https://seq.example.net/.well-known/did.json";
    let did = "did:web:seq.example.net";
    let transport = failing_transport_for(url);
    let (_dir, client) = open_client(transport.clone());
    let db = &client.db;

    // A row from an earlier build has no provenance: it never stands in for the network.
    db.write_tx(|tx| {
        tx.put_account_meta(
            &did_doc_cache_key(did),
            &doc_for(did, "zLegacy").to_string(),
            1,
        )
    })
    .unwrap();
    assert!(resolve_did_document_strict(db, transport.as_ref(), 10, did).is_err());

    // A fetched document is served while it is within the age limit, and refused after it.
    let ok = IdentityMockTransport::new();
    ok.queue(url, json_response(200, &doc_for(did, "zFresh")));
    let fetched_at = 1_000_000;
    resolve_did_document_strict(db, ok.as_ref(), fetched_at, did)
        .unwrap()
        .unwrap();
    let within = resolve_did_document_strict(
        db,
        transport.as_ref(),
        fetched_at + DID_DOC_CACHE_TTL_MS,
        did,
    )
    .unwrap()
    .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&within).unwrap()["id"], did);
    assert!(
        resolve_did_document_strict(
            db,
            transport.as_ref(),
            fetched_at + DID_DOC_CACHE_TTL_MS + 1,
            did
        )
        .is_err(),
        "an expired document must fail closed"
    );
    assert!(
        resolve_did_document_strict(db, transport.as_ref(), fetched_at - 1, did).is_err(),
        "a document from the future is not fresh"
    );
}

#[test]
fn background_receipt_key_row_survives_purge_expiry_and_failed_refresh() {
    let url = "https://seq.example.net/.well-known/did.json";
    let did = "did:web:seq.example.net";
    let transport = failing_transport_for(url);
    let (_dir, client) = open_client(transport.clone());
    let db = &client.db;
    let legacy = doc_for(did, "zLegacy").to_string();
    db.write_tx(|tx| tx.put_account_meta(&did_doc_cache_key(did), &legacy, 1))
        .unwrap();

    // Foreground refuses the unproven row and the network is down: the row the push
    // processor reads must still be there, unchanged.
    assert!(client.resolve_did_document(did).is_err());
    let row = db
        .read_tx(|tx| tx.get_account_meta(&did_doc_cache_key(did)))
        .unwrap();
    assert_eq!(row.as_deref(), Some(legacy.as_str()));

    // A successful fetch replaces document and provenance together.
    let ok = IdentityMockTransport::new();
    ok.queue(url, json_response(200, &doc_for(did, "zFresh")));
    resolve_did_document_strict(db, ok.as_ref(), 5, did)
        .unwrap()
        .unwrap();
    let (row, meta) = db
        .read_tx(|tx| {
            Ok((
                tx.get_account_meta(&did_doc_cache_key(did))?,
                tx.get_account_meta(&did_doc_meta_key(did))?,
            ))
        })
        .unwrap();
    assert!(row.unwrap().contains("zFresh"));
    let meta: Value = serde_json::from_str(&meta.unwrap()).unwrap();
    assert_eq!(meta["source"], "strict-v1");
    assert_eq!(meta["fetchedAtMs"], 5);
    assert_eq!(meta["atprotoKey"], "zFresh");

    // Long after the age limit, with the network down, the foreground fails closed while the
    // background row is still the last fetched document.
    let later = 5 + DID_DOC_CACHE_TTL_MS * 10;
    assert!(resolve_did_document_strict(db, transport.as_ref(), later, did).is_err());
    let row = db
        .read_tx(|tx| tx.get_account_meta(&did_doc_cache_key(did)))
        .unwrap();
    assert!(
        row.unwrap().contains("zFresh"),
        "background read path never loses its row"
    );
}

#[test]
fn key_rotation_is_observed_against_the_last_fetched_document() {
    let url = "https://seq.example.net/.well-known/did.json";
    let did = "did:web:seq.example.net";
    let transport = IdentityMockTransport::new();
    let (_dir, client) = open_client(transport.clone());
    transport.queue(url, json_response(200, &doc_for(did, "zFirst")));
    transport.queue(url, json_response(200, &doc_for(did, "zFirst")));
    transport.queue(url, json_response(200, &doc_for(did, "zSecond")));
    let (_, first) = resolve_did_document_observed(&client.db, transport.as_ref(), 1, did).unwrap();
    assert!(
        !first.unwrap().atproto_key_changed(),
        "first sight is a baseline"
    );
    let (_, same) = resolve_did_document_observed(&client.db, transport.as_ref(), 2, did).unwrap();
    assert!(!same.unwrap().atproto_key_changed());
    let (_, rotated) =
        resolve_did_document_observed(&client.db, transport.as_ref(), 3, did).unwrap();
    let rotated = rotated.unwrap();
    assert!(rotated.atproto_key_changed());
    assert_eq!(rotated.previous_atproto_key.as_deref(), Some("zFirst"));
    assert_eq!(rotated.current_atproto_key.as_deref(), Some("zSecond"));
}
