//! Labyrinth integration tests over a mock gateway.
//!
//! [`RefGateway`] stands in for the platform gateway plus mls-ds: it checks
//! every request the way mls-ds admission does (`actorDeviceId` on queries;
//! the signed `labyrinthWriteBody` headers on procedures, verified against
//! the registered chat device key, the body digest, the NSID and the clock
//! window) and then serves it from the labyrinth crate's memory-backed
//! reference server. The tests drive [`SessionDeps`] / [`LabyrinthSession`]
//! directly, so they need no orchestrator or async runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use labyrinth::client::MessageSource;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::read_auth::{verify_read, READ_HEADER, READ_SIGNATURE_HEADER};
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{map_error, XrpcError};
use labyrinth::store::TimeRange;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::hooks::roster_members;
use super::session::SessionDeps;
use super::signer::ChatKeySigner;
use super::state::StateVault;
use super::transport::{GatewayXrpcTransport, LabyrinthGateway};
use super::write_auth::{WriteBody, WRITE_BODY_HEADER, WRITE_DOMAIN, WRITE_SIGNATURE_HEADER};
use super::LabyrinthRequest;
use crate::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use crate::orchestrator::error::OrchestratorError;
use crate::MLSError;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const THREAD: &str = "3f2b8c1e-5a4d-4e6f-9b7a-1c2d3e4f5a6b";

// ── fixtures ────────────────────────────────────────────────────────────

struct TestKey(SigningKey);

impl ChatKeySigner for TestKey {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(msg).to_bytes())
    }
}

struct FailingKey([u8; 32]);

impl ChatKeySigner for FailingKey {
    fn public_key(&self) -> [u8; 32] {
        self.0
    }
    fn sign(&self, _: &[u8]) -> Result<[u8; 64], String> {
        Err("keychain locked".into())
    }
}

#[derive(Default)]
struct MemVault(Mutex<HashMap<String, Vec<u8>>>);

impl StateVault for MemVault {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(did).cloned())
    }
    fn compare_exchange(
        &self,
        did: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        let mut m = self.0.lock().unwrap();
        if m.get(did).map(Vec::as_slice) != expected {
            return Ok(false);
        }
        m.insert(did.to_owned(), next.to_vec());
        Ok(true)
    }
    fn delete(&self, did: &str) -> Result<(), MLSError> {
        self.0.lock().unwrap().remove(did);
        Ok(())
    }
}

/// `labyrinthWriteBody` exactly as mls-ds parses it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireBody {
    operation_id: String,
    actor_device_id: String,
    endpoint_nsid: String,
    payload_sha256: String,
    signed_at: String,
}

fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// actorDeviceId → (DID, chat device key).
type DeviceRegistry = Arc<Mutex<HashMap<String, (String, [u8; 32])>>>;

/// Platform gateway + mls-ds admission over the reference server.
#[derive(Clone)]
struct RefGateway {
    server: MemoryXrpcServer,
    devices: DeviceRegistry,
    log: Arc<Mutex<Vec<LabyrinthRequest>>>,
    /// Requests to this NSID fail with no response (a dropped connection).
    fail_nsid: Arc<Mutex<Option<String>>>,
    /// Requests to this NSID are refused with 403 and this error name.
    refuse_nsid: Arc<Mutex<Option<(String, String)>>>,
}

fn reply(r: Result<Vec<u8>, XrpcError>) -> GatewayResponse {
    match r {
        Ok(body) => GatewayResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body,
        },
        Err(e) => GatewayResponse {
            status: e.status,
            content_type: Some("application/json".into()),
            body: serde_json::to_vec(&serde_json::json!({"error": e.error, "message": e.message}))
                .unwrap(),
        },
    }
}

fn refuse(status: u16, name: &str) -> GatewayResponse {
    reply(Err(XrpcError::named(status, name, "refused by RefGateway")))
}

impl RefGateway {
    fn new() -> Self {
        Self {
            server: MemoryXrpcServer::new(MemoryBackend::new()),
            devices: Arc::default(),
            log: Arc::default(),
            fail_nsid: Arc::default(),
            refuse_nsid: Arc::default(),
        }
    }

    fn net(&self) -> &MemoryBackend {
        self.server.backend()
    }

    fn add_device(&self, did: &str, device_id: &str, seed: u8) -> Arc<TestKey> {
        let key = Arc::new(TestKey(SigningKey::from_bytes(&[seed; 32])));
        let public = key.public_key();
        self.net().register_chat_device(did, public);
        self.net().add_leaf(THREAD, did, public);
        self.devices
            .lock()
            .unwrap()
            .insert(device_id.to_owned(), (did.to_owned(), public));
        key
    }

    /// Registers an orchestrator's chat device (key held by its MLS context).
    fn register(&self, did: &str, device_id: &str, key: [u8; 32]) {
        self.net().register_chat_device(did, key);
        self.devices
            .lock()
            .unwrap()
            .insert(device_id.to_owned(), (did.to_owned(), key));
    }

    fn device(&self, id: &str) -> Option<(String, [u8; 32])> {
        self.devices.lock().unwrap().get(id).cloned()
    }

    /// A query. `read` holds the request headers of a Labyrinth query,
    /// whose device-signed read claim is verified as mls-ds does; a
    /// clean-chat query (`None`) carries none.
    fn query(&self, path: &str, read: Option<&[(String, String)]>) -> GatewayResponse {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let nsid = route.strip_prefix("/xrpc/").unwrap();
        let mut params: Vec<(String, String)> = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap();
                (percent_decode(k), percent_decode(v))
            })
            .collect();
        let all = params.clone();
        let actors: Vec<String> = params
            .iter()
            .filter(|(k, _)| k == "actorDeviceId")
            .map(|(_, v)| v.clone())
            .collect();
        params.retain(|(k, _)| k != "actorDeviceId");
        let [actor] = actors.as_slice() else {
            return refuse(400, "InvalidRequest");
        };
        let Some((did, key)) = self.device(actor) else {
            return refuse(401, "NotAuthorized");
        };
        if let Some(headers) = read {
            let header = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
            };
            // mls-ds: 401 InvalidSignature when the signature fails, 400
            // InvalidRequest for a missing header or a mismatched claim.
            let (Some(h), Some(s)) = (header(READ_HEADER), header(READ_SIGNATURE_HEADER)) else {
                return refuse(400, "InvalidRequest");
            };
            let wire: Vec<(&str, String)> =
                all.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
            match verify_read(h, s, &key) {
                Err(labyrinth::Error::BadSignature) => return refuse(401, "InvalidSignature"),
                Ok(c) if c.matches(nsid, &wire, &did, actor, now) => {}
                _ => return refuse(400, "InvalidRequest"),
            }
        }
        let p: Vec<(&str, String)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        reply(self.server.transport(&did, key).query(nsid, &p))
    }

    fn procedure(&self, req: &LabyrinthRequest) -> GatewayResponse {
        let header = |name: &str| {
            req.headers
                .iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| URL_SAFE_NO_PAD.decode(v).ok())
        };
        let (Some(signed), Some(sig)) = (header(WRITE_BODY_HEADER), header(WRITE_SIGNATURE_HEADER))
        else {
            return refuse(400, "InvalidRequest");
        };
        let Ok(wire) = serde_json::from_slice::<WireBody>(&signed) else {
            return refuse(400, "InvalidRequest");
        };
        let body = req.body.clone().unwrap_or_default();
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let signed_at = chrono::DateTime::parse_from_rfc3339(&wire.signed_at).unwrap();
        let skew = (signed_at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
        if wire.endpoint_nsid != req.nsid
            || req.path != format!("/xrpc/{}", req.nsid)
            || lower_hex::<32>(&wire.payload_sha256) != Some(digest)
            || skew.abs() > 300
        {
            return refuse(400, "InvalidRequest");
        }
        let Some(op) = lower_hex::<16>(&wire.operation_id) else {
            return refuse(400, "InvalidRequest");
        };
        let Some((did, key)) = self.device(&wire.actor_device_id) else {
            return refuse(401, "NotAuthorized");
        };
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        if vk.verify(&[WRITE_DOMAIN, &signed].concat(), &sig).is_err() {
            return refuse(401, "InvalidSignature");
        }
        reply(
            self.server
                .transport(&did, key)
                .procedure(&req.nsid, &body, op),
        )
    }
}

impl LabyrinthGateway for RefGateway {
    fn submit_labyrinth(&self, req: LabyrinthRequest) -> Result<GatewayResponse, String> {
        if self.fail_nsid.lock().unwrap().as_deref() == Some(req.nsid.as_str()) {
            return Err("connection dropped".into());
        }
        self.log.lock().unwrap().push(req.clone());
        if let Some((_, name)) = self
            .refuse_nsid
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(n, _)| *n == req.nsid)
        {
            return Ok(refuse(403, name));
        }
        Ok(match req.method.as_str() {
            "GET" => self.query(&req.path, Some(&req.headers)),
            _ => self.procedure(&req),
        })
    }

    fn submit_canonical(&self, req: PreparedRequest) -> Result<GatewayResponse, String> {
        assert_eq!(req.method, "GET");
        Ok(self.query(&req.path, None))
    }
}

/// One chat device of one account, with its own vault.
struct Device {
    deps: SessionDeps,
}

impl Device {
    fn key(&self) -> [u8; 32] {
        self.deps.signer.public_key()
    }

    fn new(gw: &RefGateway, did: &str, device_id: &str, seed: u8) -> Self {
        let key = gw.add_device(did, device_id, seed);
        Self::with_signer(gw, did, device_id, key)
    }

    fn with_signer(
        gw: &RefGateway,
        did: &str,
        device_id: &str,
        signer: Arc<dyn ChatKeySigner>,
    ) -> Self {
        let transport = Arc::new(GatewayXrpcTransport::new(
            Arc::new(gw.clone()),
            signer.clone(),
            did.to_owned(),
            device_id.to_owned(),
        ));
        Self {
            deps: SessionDeps {
                did: did.to_owned(),
                transport,
                signer,
                vault: Arc::new(MemVault::default()),
                pds: None,
                space: None,
                placements: Arc::new(MemVault::default()),
            },
        }
    }
}

#[path = "queue_tests.rs"]
mod queue_tests;
#[path = "review_tests.rs"]
mod review_tests;
#[path = "space_tests.rs"]
mod space_tests;

// ── tests ───────────────────────────────────────────────────────────────

#[test]
fn write_body_is_the_exact_shape_mlsds_verifies() {
    let at = chrono::DateTime::parse_from_rfc3339("2026-10-04T12:00:00.123Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let body = WriteBody::new(
        "blue.catbird.labyrinth.createEpoch",
        b"{}",
        [0xAB; 16],
        "6f1c2b8e-3d4a-4f5b-8c6d-7e8f9a0b1c2d",
        at,
    );
    let json = String::from_utf8(body.to_json()).unwrap();
    assert_eq!(
        json,
        format!(
            "{{\"operationId\":\"{}\",\"actorDeviceId\":\"6f1c2b8e-3d4a-4f5b-8c6d-7e8f9a0b1c2d\",\
             \"endpointNsid\":\"blue.catbird.labyrinth.createEpoch\",\"payloadSha256\":\"{}\",\
             \"signedAt\":\"2026-10-04T12:00:00.123Z\"}}",
            "ab".repeat(16),
            hex::encode(Sha256::digest(b"{}"))
        )
    );
    assert_eq!(WRITE_DOMAIN, b"CATBIRD-LABYRINTH-WRITE\0");
    assert_eq!(WRITE_BODY_HEADER, "catbird-labyrinth-write");
    assert_eq!(WRITE_SIGNATURE_HEADER, "catbird-labyrinth-write-signature");
}

#[test]
fn queries_name_the_device_and_encode_parameters() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let _ = alice.deps.transport.query(
        "blue.catbird.labyrinth.getEpochHead",
        &[("did", "did:plc:a b".into())],
    );
    let req = gw.log.lock().unwrap().pop().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.nsid, "blue.catbird.labyrinth.getEpochHead");
    assert_eq!(
        req.path,
        "/xrpc/blue.catbird.labyrinth.getEpochHead?actorDeviceId=11111111-1111-4111-8111-111111111111&did=did%3Aplc%3Aa%20b"
    );
    assert!(req.body.is_none());
    // The device-signed read claim covers every wire parameter.
    let names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, [READ_HEADER, READ_SIGNATURE_HEADER]);
    let claim = verify_read(&req.headers[0].1, &req.headers[1].1, &alice.key()).unwrap();
    assert_eq!(claim.did, ALICE);
    assert_eq!(claim.device_id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(claim.nsid, "blue.catbird.labyrinth.getEpochHead");
    assert_eq!(
        claim.query,
        "actorDeviceId=11111111-1111-4111-8111-111111111111&did=did%3Aplc%3Aa%20b"
    );
    let skew = claim
        .issued_at
        .abs_diff(u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap());
    assert!(skew < 60_000);
}

#[test]
fn a_read_signed_by_another_key_is_refused() {
    let gw = RefGateway::new();
    gw.add_device(ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let impostor = Device::with_signer(
        &gw,
        ALICE,
        "11111111-1111-4111-8111-111111111111",
        Arc::new(TestKey(SigningKey::from_bytes(&[7; 32]))),
    );
    let e = impostor
        .deps
        .transport
        .query("blue.catbird.labyrinth.listDevices", &[])
        .unwrap_err();
    assert_eq!(
        (e.status, e.error.as_deref()),
        (401, Some("InvalidSignature"))
    );
    // A failing signer sends nothing.
    let locked = Device::with_signer(
        &gw,
        ALICE,
        "11111111-1111-4111-8111-111111111111",
        Arc::new(FailingKey([0; 32])),
    );
    let before = gw.log.lock().unwrap().len();
    let e = locked
        .deps
        .transport
        .query("blue.catbird.labyrinth.listDevices", &[])
        .unwrap_err();
    assert_eq!(e.status, 0);
    assert_eq!(gw.log.lock().unwrap().len(), before);
}

#[test]
fn procedures_refuse_non_labyrinth_nsids() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let e = alice
        .deps
        .transport
        .procedure("blue.catbird.chat.sendMessage", b"{}", [0; 16])
        .unwrap_err();
    assert_eq!(e.status, 0);
    assert!(gw.log.lock().unwrap().is_empty());
}

#[test]
fn error_bodies_become_named_xrpc_errors() {
    let gw = RefGateway::new();
    // Not registered: the gateway refuses with NotAuthorized.
    let ghost = Device::with_signer(
        &gw,
        ALICE,
        "99999999-9999-4999-8999-999999999999",
        Arc::new(TestKey(SigningKey::from_bytes(&[9; 32]))),
    );
    let e = ghost
        .deps
        .transport
        .query("blue.catbird.labyrinth.listDevices", &[])
        .unwrap_err();
    assert_eq!(e.status, 401);
    assert_eq!(e.error.as_deref(), Some("NotAuthorized"));
    assert!(matches!(map_error(e), labyrinth::Error::Forbidden));
}

#[test]
fn a_write_signed_by_another_key_is_refused() {
    let gw = RefGateway::new();
    gw.add_device(ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let impostor = Device::with_signer(
        &gw,
        ALICE,
        "11111111-1111-4111-8111-111111111111",
        Arc::new(TestKey(SigningKey::from_bytes(&[7; 32]))),
    );
    let e = impostor.deps.enable().map(|_| ()).unwrap_err();
    assert!(e.to_string().contains("InvalidSignature"), "{e}");
}

#[test]
fn archive_restore_load_and_revoke_over_the_gateway() {
    let gw = RefGateway::new();
    let alice1 = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let bob = Device::new(&gw, BOB, "22222222-2222-4222-8222-222222222222", 2);

    let mut a1 = alice1.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    let frame = br#"{"version":1,"messageType":"text","text":"hello from alice"}"#;
    a1.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, frame)
        .unwrap();

    // Bob reads Alice's message.
    let page = b.load_history(THREAD, TimeRange::ALL).unwrap();
    assert!(page.space_readable);
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].sender.as_deref(), Some(ALICE));
    assert_eq!(page.messages[0].frame, frame);

    // A second Alice device restores from a recovery code with typos
    // stripped of spacing, then reads the same history.
    let code = a1.create_recovery_code().unwrap();
    let alice2 = Device::new(&gw, ALICE, "33333333-3333-4333-8333-333333333333", 3);
    let mut a2 = alice2
        .deps
        .clone()
        .restore_with_recovery_code(&code)
        .unwrap();
    let page = a2.load_history(THREAD, TimeRange::ALL).unwrap();
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].message_id, "m-1");
    assert_eq!(page.messages[0].source, MessageSource::Sender);

    // The restored device revokes the first one: a new epoch opens.
    let old_key: [u8; 32] = hex::decode(a1.device_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let before = a2.load_history(THREAD, TimeRange::ALL).unwrap();
    let epoch = a2.revoke_device(old_key).unwrap();
    assert!(epoch >= 1);
    assert_eq!(before.messages.len(), 1);

    // The revoked device can no longer follow the mailbox.
    drop(a1);
    let reopened = alice1.deps.clone().open();
    assert!(reopened.is_err(), "revoked device reopened its session");

    // State survives a restart: reopening from the vault reads history.
    drop(a2);
    let mut a2 = alice2.deps.clone().open().unwrap().expect("saved session");
    assert_eq!(
        a2.load_history(THREAD, TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        1
    );

    // Bob, sending after the rotation, addresses Alice's new epoch.
    b.archive_sent(THREAD, &members, "m-2", 1_791_000_000_100, b"{}")
        .unwrap();
    assert_eq!(
        a2.load_history(THREAD, TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        2
    );
}

#[test]
fn rearchive_before_leave_copies_into_the_owner_mailbox() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let bob = Device::new(&gw, BOB, "22222222-2222-4222-8222-222222222222", 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    a.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"one")
        .unwrap();
    assert_eq!(b.rearchive_before_leave(THREAD).unwrap(), 1);
    // A second pass finds everything already archived.
    assert_eq!(b.rearchive_before_leave(THREAD).unwrap(), 0);
}

#[test]
fn enabling_twice_reopens_and_a_second_device_must_restore() {
    let gw = RefGateway::new();
    let alice1 = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let first = alice1.deps.clone().enable().unwrap().device_key_hex();
    let again = alice1.deps.clone().enable().unwrap().device_key_hex();
    assert_eq!(first, again);
    let alice2 = Device::new(&gw, ALICE, "33333333-3333-4333-8333-333333333333", 3);
    let e = alice2.deps.clone().enable().map(|_| ()).unwrap_err();
    assert!(e.to_string().contains("conflict"), "{e}");
}

#[test]
fn a_signing_failure_fails_the_operation() {
    let gw = RefGateway::new();
    let key = gw.add_device(ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let broken = Device::with_signer(
        &gw,
        ALICE,
        "11111111-1111-4111-8111-111111111111",
        Arc::new(FailingKey(key.public_key())),
    );
    let e = broken.deps.enable().map(|_| ()).unwrap_err();
    assert!(matches!(e, OrchestratorError::Credential(_)), "{e}");
}

#[test]
fn a_concurrent_state_writer_is_detected() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, "11111111-1111-4111-8111-111111111111", 1);
    let mut a = alice.deps.clone().enable().unwrap();
    // Another process rewrites the saved state behind this session.
    let saved = alice.deps.vault.load(ALICE).unwrap().unwrap();
    let mut other = saved.clone();
    other.push(0);
    assert!(alice
        .deps
        .vault
        .compare_exchange(ALICE, Some(&saved), &other)
        .unwrap());
    // Minting a MEK changes the state, so this save must notice.
    let e = a
        .archive_sent(THREAD, &[ALICE.to_owned()], "m-1", 1_791_000_000_000, b"x")
        .unwrap_err();
    assert!(matches!(e, OrchestratorError::Storage(_)), "{e}");
}

#[test]
fn roster_keeps_active_members_only() {
    let state = serde_json::json!({"state": {"participants": [
        {"userDid": "did:plc:a", "status": "active", "leafCount": 2},
        {"userDid": "did:plc:b", "status": "pending", "leafCount": 0},
        {"userDid": "did:plc:c", "status": "active", "leafCount": 0},
        {"userDid": "did:plc:d"},
    ]}});
    assert_eq!(roster_members(&state), vec!["did:plc:a", "did:plc:d"]);
}

/// The chat device key and device id of a registered harness client.
async fn chat_device<S, A, C, M>(
    o: &crate::orchestrator::MLSOrchestrator<S, A, C, M>,
    did: &str,
) -> (String, [u8; 32])
where
    S: crate::orchestrator::MLSStorageBackend + 'static,
    A: crate::orchestrator::MLSAPIClient + 'static,
    C: crate::orchestrator::CredentialStore + 'static,
    M: crate::orchestrator::MlsCryptoContext + 'static,
{
    let device_id = o.require_actor_device_id().await.unwrap();
    let key = o
        .mls_context()
        .identity_public_key(format!("{did}#{device_id}").into_bytes())
        .unwrap();
    (device_id, key.try_into().unwrap())
}

/// The orchestrator hooks end to end on the e2e harness: a send is
/// archived through `submit_labyrinth_request`, and a second device of the
/// account restores from a recovery code and imports the history into its
/// own storage.
#[tokio::test(flavor = "multi_thread")]
async fn orchestrator_archives_a_send_and_a_restored_device_imports_it() {
    use crate::orchestrator::MLSStorageBackend as _;
    use crate::recovery_e2e_harness::TestWorld;

    let gw = RefGateway::new();
    let mut world = TestWorld::new();
    let handler = gw.clone();
    world
        .api_service
        .set_labyrinth_handler(Arc::new(move |req| handler.submit_labyrinth(req)));

    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let did = alice.did.clone();
    let (device, key) = chat_device(&alice.orchestrator, &did).await;
    gw.register(&did, &device, key);

    // Before enabling, sends are not archived and history is refused.
    let convo = alice
        .orchestrator
        .create_group("history", None, None)
        .await
        .unwrap();
    let thread = convo.conversation_id.clone();
    gw.net().add_leaf(&thread, &did, key);
    alice
        .orchestrator
        .send_message(&thread, "before")
        .await
        .unwrap();
    assert!(gw.log.lock().unwrap().is_empty());
    assert!(!alice.orchestrator.labyrinth_is_enabled().await.unwrap());

    alice.orchestrator.labyrinth_enable().await.unwrap();
    // Archiving is queued off the send path; hold it until flushed.
    alice
        .orchestrator
        .labyrinth_set_archive_policy(super::QueueConfig {
            max_batch: 1000,
            max_delay: std::time::Duration::from_secs(3600),
        });
    let sent = alice
        .orchestrator
        .send_message(&thread, "remember me")
        .await
        .unwrap();
    let appends = |gw: &RefGateway| {
        gw.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.nsid == "blue.catbird.labyrinth.appendBatch")
            .count()
    };
    assert_eq!(appends(&gw), 0, "the send itself wrote no batch");
    assert_eq!(
        alice.orchestrator.labyrinth_flush_archive().await.unwrap(),
        1
    );
    assert!(gw
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.nsid == "blue.catbird.labyrinth.appendBatch"));
    let code = alice
        .orchestrator
        .labyrinth_create_recovery_code()
        .await
        .unwrap();

    // A new device of the same account.
    world.add_client_with_did("AliceTablet", &did).await;
    world.register_device("AliceTablet").await.unwrap();
    let tablet = world.client("AliceTablet");
    let (device2, key2) = chat_device(&tablet.orchestrator, &did).await;
    gw.register(&did, &device2, key2);
    tablet
        .orchestrator
        .labyrinth_restore_with_recovery_code(&code)
        .await
        .unwrap();
    let report = tablet
        .orchestrator
        .labyrinth_import_history(&thread)
        .await
        .unwrap();
    assert_eq!(report.imported, 1, "{report:?}");
    assert!(tablet.storage.message_exists(&sent.id).await.unwrap());
    let stored = tablet
        .storage
        .get_messages(&thread, 10, None)
        .await
        .unwrap();
    let m = stored.iter().find(|m| m.id == sent.id).unwrap();
    assert_eq!(m.text, "remember me");
    assert!(m.is_own);

    // Importing again stores nothing new.
    let again = tablet
        .orchestrator
        .labyrinth_import_history(&thread)
        .await
        .unwrap();
    assert_eq!((again.imported, again.already_present), (0, 1));

    // Leaving re-archives readable history into the owner mailbox first
    // ([CB-22]); the leave itself is the existing flow.
    let owner_writes = |gw: &RefGateway| {
        gw.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.nsid == "blue.catbird.labyrinth.appendOwnerBatch")
            .count()
    };
    assert_eq!(owner_writes(&gw), 0);
    let _ = world
        .client("Alice")
        .orchestrator
        .leave_conversation(&thread)
        .await;
    assert_eq!(owner_writes(&gw), 1);

    // The tablet revokes the phone's Labyrinth device.
    let phone_key = world
        .client("Alice")
        .orchestrator
        .labyrinth_enable()
        .await
        .unwrap();
    assert!(
        tablet
            .orchestrator
            .labyrinth_revoke_device(&phone_key)
            .await
            .unwrap()
            >= 1
    );
}
