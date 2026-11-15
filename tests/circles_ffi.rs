//! E2EE Circles FFI surface over real Labyrinth sessions (`src/ffi/circles_ffi.rs`).
//!
//! Each account is a `LabyrinthSession` on a shared `MemorySpaceHost`, a shared
//! `MemoryPublicRepoHost` (the `mailboxKeys` directory) and a mock of the
//! mls-ds Labyrinth directory endpoints (epoch heads + chat device keys, the
//! `[CB-18]` attestation source). The `CatbirdMlsClient` methods are thin
//! wrappers over the session-level functions exercised here.

#![cfg(feature = "labyrinth")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use catbird_mls::canonical_transport::{GatewayResponse, PreparedRequest};
use catbird_mls::ffi::circles_ffi::{
    circle_key_generate_bytes, circle_post_key_bytes, open_circle_key_for_session,
    open_circle_post_for_session, seal_circle_post_for_session, wrap_circle_key_for_session,
    CircleKeyWrapRequest, CirclePostOpenRequest, CirclePostSealRequest,
};
use catbird_mls::labyrinth::{
    ChatKeySigner, GatewayXrpcTransport, LabyrinthGateway, LabyrinthRequest, LabyrinthSession,
    SessionDeps, StateVault,
};
use catbird_mls::MLSError;
use ed25519_dalek::{Signer as _, SigningKey};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{EpochPublicDef, MailboxKeysRecord};
use labyrinth::sign::TransportSigner;
use labyrinth::store::pds::{MemoryPublicRepoHost, PdsDirectory, PublicRepoBackend};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::MailboxDirectory as _;
use serde_json::{json, Value};

const OWNER: &str = "did:plc:circleowner00000000000000";
const MEMBER: &str = "did:plc:circlemember0000000000000";
const OUTSIDER: &str = "did:plc:circleoutsider000000000000";
const SPACE: &str = "at://did:plc:circleowner00000000000000/blue.catbird.circle.encrypted/3kcircle";
const CIRCLE_ID: &str = "3kcircleid22a";
const CREATED: &str = "2026-11-07T12:00:00.000Z";

struct TestChatSigner(SigningKey);

impl ChatKeySigner for TestChatSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(msg).to_bytes())
    }
}

#[derive(Default)]
struct MemoryVault(Mutex<HashMap<String, Vec<u8>>>);

impl StateVault for MemoryVault {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        let mut map = self.0.lock().unwrap();
        if map.get(key).map(Vec::as_slice) != expected {
            return Ok(false);
        }
        map.insert(key.to_owned(), next.to_vec());
        Ok(true)
    }
    fn delete(&self, key: &str) -> Result<(), MLSError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Default)]
struct MockDs {
    heads: HashMap<String, Vec<EpochPublicDef>>,
    chat_keys: HashMap<String, Vec<[u8; 32]>>,
    /// Account-wide revocation time (`revokedAt`) per chat device key.
    revoked_at: HashMap<[u8; 32], String>,
}

struct MockGateway {
    actor: String,
    state: Arc<Mutex<MockDs>>,
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.replace("%3A", ":").replace("%2F", "/"))
    })
}

fn ok_json(body: Value) -> GatewayResponse {
    GatewayResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

#[async_trait::async_trait]
impl LabyrinthGateway for MockGateway {
    async fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String> {
        let mut st = self.state.lock().unwrap();
        match request.nsid.as_str() {
            "blue.catbird.labyrinth.publishEpochHead" => {
                let parsed: Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                        .map_err(|e| e.to_string())?;
                let epoch: EpochPublicDef =
                    serde_json::from_value(parsed["epoch"].clone()).map_err(|e| e.to_string())?;
                let list = st.heads.entry(self.actor.clone()).or_default();
                list.retain(|e| e.epoch_number != epoch.epoch_number);
                list.push(epoch);
                list.sort_by_key(|e| e.epoch_number);
                Ok(ok_json(json!({})))
            }
            "blue.catbird.labyrinth.getEpochHead" => {
                let did = query_param(&request.path, "did").unwrap_or_default();
                let seq =
                    query_param(&request.path, "epochNumber").and_then(|s| s.parse::<u64>().ok());
                let list = st.heads.get(&did).cloned().unwrap_or_default();
                let found = match seq {
                    Some(n) => list.iter().find(|e| e.epoch_number == n).cloned(),
                    None => list.last().cloned(),
                };
                match found {
                    Some(epoch) => {
                        let chain: Vec<_> = list
                            .iter()
                            .filter(|e| e.epoch_number <= epoch.epoch_number)
                            .cloned()
                            .collect();
                        let floor = chain.first().map(|e| e.epoch_number).unwrap_or(0);
                        Ok(ok_json(json!({
                            "epoch": epoch,
                            "chain": chain,
                            "floorSeq": floor,
                            "receivedAt": "2026-11-07T00:00:00Z"
                        })))
                    }
                    None => Ok(GatewayResponse {
                        status: 404,
                        content_type: Some("application/json".into()),
                        body: br#"{"error":"EpochNotFound","message":"none"}"#.to_vec(),
                    }),
                }
            }
            "blue.catbird.labyrinth.getChatDeviceKeys"
            | "blue.catbird.labyrinth.getMemberDevices" => {
                let did = query_param(&request.path, "did").unwrap_or_default();
                let device_keys = request.nsid.ends_with("getChatDeviceKeys");
                let items: Vec<_> = st
                    .chat_keys
                    .get(&did)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|k| {
                        let mut item = json!({ "signingPublicKey": { "$bytes": STANDARD_NO_PAD.encode(k) }, "joinedSeq": 0 });
                        if let (true, Some(at)) = (device_keys, st.revoked_at.get(&k)) {
                            item["revokedAt"] = json!(at);
                        }
                        item
                    })
                    .collect();
                Ok(ok_json(json!({ "items": items })))
            }
            other => Err(format!("unexpected labyrinth endpoint: {other}")),
        }
    }

    async fn submit_canonical(
        &self,
        _request: PreparedRequest,
        _headers: Vec<(String, String)>,
    ) -> Result<GatewayResponse, String> {
        Ok(GatewayResponse {
            status: 404,
            content_type: Some("application/json".into()),
            body: br#"{"error":"ConversationNotFound","message":"none"}"#.to_vec(),
        })
    }
}

struct World {
    space: MemorySpaceHost,
    pds: MemoryPublicRepoHost,
    ds: Arc<Mutex<MockDs>>,
}

impl World {
    fn new() -> Self {
        Self {
            space: MemorySpaceHost::default(),
            pds: MemoryPublicRepoHost::default(),
            ds: Arc::new(Mutex::new(MockDs::default())),
        }
    }

    async fn enroll(&self, did: &str, seed: u8) -> LabyrinthSession {
        let signer = Arc::new(TestChatSigner(SigningKey::from_bytes(&[seed; 32])));
        self.ds
            .lock()
            .unwrap()
            .chat_keys
            .entry(did.to_owned())
            .or_default()
            .push(signer.public_key());
        let gateway = Arc::new(MockGateway {
            actor: did.to_owned(),
            state: self.ds.clone(),
        });
        let deps = SessionDeps {
            did: did.to_owned(),
            transport: Arc::new(GatewayXrpcTransport::new(
                gateway,
                signer.clone(),
                did.to_owned(),
                format!("dev-{seed}"),
            )),
            signer,
            vault: Arc::new(MemoryVault::default()),
            pds: Some(Arc::new(self.pds.client(did))),
            space: Some(Arc::new(self.space.client(did))),
            placements: Arc::new(MemoryVault::default()),
            local_authority: None,
            sequencer_receipt_key: None,
            default_conversation_authority_did: None,
        };
        deps.enable().await.expect("enable labyrinth session")
    }

    /// The `mailboxKeys` record the caller would fetch from `did`'s repo.
    async fn mailbox_keys_json(&self, did: &str) -> String {
        let epoch = PdsDirectory::new(Arc::new(self.pds.client(did)) as Arc<dyn PublicRepoBackend>)
            .latest(did)
            .await
            .expect("pds latest")
            .expect("published mailboxKeys");
        serde_json::to_string(&MailboxKeysRecord::from_public(
            &epoch,
            None,
            CREATED.to_owned(),
        ))
        .unwrap()
    }

    async fn latest_epoch(&self, did: &str) -> EpochPublic {
        PdsDirectory::new(Arc::new(self.pds.client(did)) as Arc<dyn PublicRepoBackend>)
            .latest(did)
            .await
            .expect("pds latest")
            .expect("published mailboxKeys")
    }
}

fn wrap_request(members: &[&str]) -> CircleKeyWrapRequest {
    CircleKeyWrapRequest {
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        space_uri: SPACE.into(),
        reason: "created".into(),
        member_dids: members.iter().map(|d| (*d).to_owned()).collect(),
        created_at: CREATED.into(),
    }
}

fn post_uri() -> String {
    format!("at://{OWNER}/blue.catbird.circle.post/3kpost0000001")
}

fn reply_ref() -> Value {
    json!({
        "parent": { "uri": format!("at://{MEMBER}/blue.catbird.circle.post/3kparent00001"), "cid": "bafyparent" },
        "root": { "uri": format!("at://{MEMBER}/blue.catbird.circle.post/3kroot0000001"), "cid": "bafyroot" }
    })
}

fn seal_request(circle_key: &[u8], reply: Option<Value>) -> CirclePostSealRequest {
    let mut post = json!({
        "$type": "app.bsky.feed.post",
        "text": "only for the circle",
        "createdAt": CREATED,
    });
    if let Some(r) = &reply {
        post["reply"] = r.clone();
    }
    let payload = json!({ "post": post, "media": [], "created_at": CREATED });
    CirclePostSealRequest {
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        circle_key: circle_key.to_vec(),
        post_uri: post_uri(),
        author_did: OWNER.into(),
        created_at: CREATED.into(),
        payload_json: payload.to_string(),
        reply_json: reply.map(|r| r.to_string()),
        attachments_json: vec![],
    }
}

#[tokio::test]
async fn two_clients_wrap_and_open() {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;
    let mut outsider = world.enroll(OUTSIDER, 33).await;

    let key = circle_key_generate_bytes();
    assert_eq!(key.len(), 32);
    let wrapped = wrap_circle_key_for_session(
        &mut owner,
        wrap_request(&[MEMBER, "did:plc:notenrolled000000000000"]),
        key.clone(),
    )
    .await
    .expect("wrap");
    assert_eq!(wrapped.rkey, "000001");
    assert_eq!(
        wrapped.excluded_dids,
        vec!["did:plc:notenrolled000000000000".to_owned()]
    );
    assert_eq!(wrapped.excluded_reasons.len(), 1);
    let record: Value = serde_json::from_str(&wrapped.record_json).unwrap();
    assert_eq!(record["$type"], "blue.catbird.circle.key");
    assert_eq!(record["recipients"].as_array().unwrap().len(), 8);

    let opened = open_circle_key_for_session(&mut member, &wrapped.record_json, SPACE, OWNER)
        .await
        .expect("member open");
    // M3: the identity comes from the authenticated AAD.
    let ids = opened
        .as_ref()
        .map(|o| (o.circle_id.clone(), o.key_version));
    assert_eq!(ids, Some((CIRCLE_ID.to_owned(), 1)));
    assert_eq!(opened.map(|o| o.circle_key), Some(key.clone()));

    // Owner's self-wrap opens on the owner's own session.
    let self_opened = open_circle_key_for_session(&mut owner, &wrapped.record_json, SPACE, OWNER)
        .await
        .expect("owner open");
    assert_eq!(self_opened.map(|o| o.circle_key), Some(key.clone()));

    let none = open_circle_key_for_session(&mut outsider, &wrapped.record_json, SPACE, OWNER)
        .await
        .expect("outsider open");
    assert_eq!(none.map(|o| o.circle_key), None);

    // A different Space binds a different AAD: nothing opens.
    let wrong_space = open_circle_key_for_session(
        &mut member,
        &wrapped.record_json,
        &format!("at://{OWNER}/blue.catbird.circle.encrypted/3kother"),
        OWNER,
    )
    .await
    .expect("open under another space");
    assert_eq!(wrong_space.map(|o| o.circle_key), None);

    // After the owner rotates, the record's (older) sender epoch is accepted
    // only through the prev_sig chain to the owner's verified latest epoch.
    let report = owner.rotate_epoch().await.expect("owner rotate");
    assert_eq!(report.new_epoch, 1);
    assert_eq!(world.latest_epoch(OWNER).await.seq, 1);
    let after_rotation =
        open_circle_key_for_session(&mut member, &wrapped.record_json, SPACE, OWNER)
            .await
            .expect("open after owner rotation");
    assert_eq!(after_rotation.map(|o| o.circle_key), Some(key.clone()));
}

#[tokio::test]
async fn seal_open_through_ffi() {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;

    let key = circle_key_generate_bytes();
    let record_json = seal_circle_post_for_session(&mut owner, seal_request(&key, None))
        .await
        .expect("seal");
    let record: Value = serde_json::from_str(&record_json).unwrap();
    assert_eq!(record["$type"], "blue.catbird.circle.post");
    assert!(!record_json.contains("only for the circle"));

    let open = CirclePostOpenRequest {
        record_json: record_json.clone(),
        post_uri: post_uri(),
        author_did: OWNER.into(),
        circle_key: key.clone(),
        author_epoch_json: world.mailbox_keys_json(OWNER).await,
    };
    let payload_json = open_circle_post_for_session(&mut member, open)
        .await
        .expect("open");
    let payload: Value = serde_json::from_str(&payload_json).unwrap();
    assert_eq!(payload["post"]["text"], "only for the circle");

    // Post key derivation is exposed for moderation disclosure.
    let pk = circle_post_key_bytes(key.clone(), CIRCLE_ID.into(), post_uri()).unwrap();
    assert_eq!(pk.len(), 32);
    assert_ne!(pk, key);

    // Wrong author DID (the AAD binds it) and a wrong epoch both fail.
    let wrong_author = CirclePostOpenRequest {
        record_json: record_json.clone(),
        post_uri: post_uri(),
        author_did: MEMBER.into(),
        circle_key: key.clone(),
        author_epoch_json: world.mailbox_keys_json(MEMBER).await,
    };
    assert!(open_circle_post_for_session(&mut member, wrong_author)
        .await
        .is_err());

    // Too many attachments are refused before sealing.
    let mut req = seal_request(&key, None);
    req.attachments_json = (0..5).map(|i| json!({ "n": i }).to_string()).collect();
    assert!(seal_circle_post_for_session(&mut owner, req).await.is_err());
}

#[tokio::test]
async fn open_refuses_key_record_from_unverified_owner() {
    let world = World::new();
    let _owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;

    // Mint an owner epoch whose keys and attesting transport key the
    // directory never saw, and wrap a key to the member's real epoch with it.
    struct Rogue(SigningKey);
    impl TransportSigner for Rogue {
        fn transport_public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            self.0.sign(msg).to_bytes()
        }
    }
    let minted_keys = MailboxKeys::derive(&[0x5a; 32], 0);
    let minted = EpochPublic::sign(
        OWNER,
        0,
        &minted_keys,
        [0u8; 32],
        None,
        None,
        &Rogue(SigningKey::from_bytes(&[0x66; 32])),
    )
    .unwrap();
    let member_epoch = world.latest_epoch(MEMBER).await;
    let params = catbird_mls::circles::keys::CircleKeyParams {
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        space_uri: SPACE.into(),
        reason: "created".into(),
    };
    let body = catbird_mls::circles::keys::wrap_circle_key(
        &[7u8; 32],
        &params,
        OWNER,
        &minted_keys,
        &minted,
        &[
            catbird_mls::circles::keys::VerifiedRecipient {
                did: OWNER.into(),
                epoch: minted.clone(),
            },
            catbird_mls::circles::keys::VerifiedRecipient {
                did: MEMBER.into(),
                epoch: member_epoch,
            },
        ],
        CREATED,
    )
    .unwrap();
    let record_json = serde_json::to_string(
        &catbird_mls::circles::records::CircleKeyRecord::from_body(&body),
    )
    .unwrap();

    let err = open_circle_key_for_session(&mut member, &record_json, SPACE, OWNER)
        .await
        .expect_err("minted owner epoch must be refused");
    assert!(
        err.to_string().contains("untrusted sender")
            && err.to_string().contains("differs from the verified latest"),
        "unexpected error: {err}"
    );

    // A record naming someone else as sender is refused too.
    let member_space = format!("at://{MEMBER}/blue.catbird.circle.encrypted/3kcircle");
    let err = open_circle_key_for_session(&mut member, &record_json, &member_space, MEMBER)
        .await
        .expect_err("sender is not the owner");
    assert!(
        err.to_string().contains("sender is not the circle owner"),
        "{err}"
    );

    // Bounds: key version 0 is refused before any decryption.
    let mut v0: Value = serde_json::from_str(&record_json).unwrap();
    v0["keyVersion"] = json!(0);
    assert!(
        open_circle_key_for_session(&mut member, &v0.to_string(), SPACE, OWNER)
            .await
            .is_err()
    );
    // Bounds: a recipient count that is not a bucket size is refused.
    let mut odd: Value = serde_json::from_str(&record_json).unwrap();
    odd["recipients"].as_array_mut().unwrap().pop();
    let err = open_circle_key_for_session(&mut member, &odd.to_string(), SPACE, OWNER)
        .await
        .expect_err("non-bucket recipient count");
    assert!(err.to_string().contains("bucket"), "{err}");
}

#[tokio::test]
async fn post_open_refuses_rethreaded_reply() {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;

    let key = circle_key_generate_bytes();
    let record_json =
        seal_circle_post_for_session(&mut owner, seal_request(&key, Some(reply_ref())))
            .await
            .expect("seal reply");
    let epoch_json = world.mailbox_keys_json(OWNER).await;

    // The untouched reply opens.
    let open = |record_json: String| CirclePostOpenRequest {
        record_json,
        post_uri: post_uri(),
        author_did: OWNER.into(),
        circle_key: key.clone(),
        author_epoch_json: epoch_json.clone(),
    };
    open_circle_post_for_session(&mut member, open(record_json.clone()))
        .await
        .expect("open untouched reply");

    // A server that re-threads the post under another parent is caught.
    let mut moved: Value = serde_json::from_str(&record_json).unwrap();
    moved["reply"]["parent"]["uri"] = json!(format!(
        "at://{MEMBER}/blue.catbird.circle.post/3kelsewhere001"
    ));
    let err = open_circle_post_for_session(&mut member, open(moved.to_string()))
        .await
        .expect_err("re-threaded reply must be refused");
    assert!(
        err.to_string().contains("header"),
        "unexpected error: {err}"
    );

    // Stripping the reply is caught too.
    let mut stripped: Value = serde_json::from_str(&record_json).unwrap();
    stripped.as_object_mut().unwrap().remove("reply");
    assert!(
        open_circle_post_for_session(&mut member, open(stripped.to_string()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn post_open_refuses_unattested_author_epoch() {
    let world = World::new();
    let _owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;

    // A self-consistent owner epoch attested by a transport key that is not
    // one of the owner's chat devices ([CB-18]), signing a well-formed post.
    struct Rogue(SigningKey);
    impl TransportSigner for Rogue {
        fn transport_public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            self.0.sign(msg).to_bytes()
        }
    }
    let minted_keys = MailboxKeys::derive(&[0x5b; 32], 0);
    let minted = EpochPublic::sign(
        OWNER,
        0,
        &minted_keys,
        [0u8; 32],
        None,
        None,
        &Rogue(SigningKey::from_bytes(&[0x67; 32])),
    )
    .unwrap();
    let key = [9u8; 32];
    let header = catbird_mls::circles::post::CirclePostHeader {
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        post_uri: post_uri(),
        author_did: OWNER.into(),
        created_at: CREATED.into(),
    };
    let payload = catbird_mls::circles::post::CirclePostPayload {
        post: json!({ "text": "forged", "createdAt": CREATED }),
        media: vec![],
        created_at: CREATED.into(),
    };
    let sealed =
        catbird_mls::circles::post::seal_post(&payload, &header, &key, &minted_keys, minted.head)
            .unwrap();
    let record = catbird_mls::circles::records::CirclePostRecord::from_sealed(
        &sealed,
        &header,
        None,
        vec![],
    );
    let open = CirclePostOpenRequest {
        record_json: serde_json::to_string(&record).unwrap(),
        post_uri: post_uri(),
        author_did: OWNER.into(),
        circle_key: key.to_vec(),
        author_epoch_json: serde_json::to_string(&MailboxKeysRecord::from_public(
            &minted,
            None,
            CREATED.to_owned(),
        ))
        .unwrap(),
    };
    let err = open_circle_post_for_session(&mut member, open)
        .await
        .expect_err("unattested author epoch must be refused");
    assert!(err.to_string().contains("untrusted sender"), "{err}");
}

fn chat_key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

struct RogueTransport(SigningKey);
impl TransportSigner for RogueTransport {
    fn transport_public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

/// Seal a post as the owner, revoke the owner's (only) chat device at
/// `revoked_at`, then have the member open it.
async fn open_after_owner_device_revoked(revoked_at: &str) -> Result<String, String> {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;
    let key = circle_key_generate_bytes();
    let record_json = seal_circle_post_for_session(&mut owner, seal_request(&key, None))
        .await
        .expect("seal");
    let author_epoch_json = world.mailbox_keys_json(OWNER).await;
    world
        .ds
        .lock()
        .unwrap()
        .revoked_at
        .insert(chat_key(11), revoked_at.to_owned());
    let open = CirclePostOpenRequest {
        record_json,
        post_uri: post_uri(),
        author_did: OWNER.into(),
        circle_key: key,
        author_epoch_json,
    };
    open_circle_post_for_session(&mut member, open)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn post_opens_when_attesting_device_revoked_after_created_at() {
    // CREATED is 2026-11-07T12:00:00Z; the device was revoked later.
    let payload = open_after_owner_device_revoked("2026-11-08T00:00:00.000Z")
        .await
        .expect("a post written before revocation stays readable");
    assert!(payload.contains("only for the circle"));
}

#[tokio::test]
async fn post_refused_when_attesting_device_revoked_before_created_at() {
    let err = open_after_owner_device_revoked("2026-11-06T00:00:00.000Z")
        .await
        .expect_err("a post dated after the attesting device's revocation is refused");
    assert!(
        err.contains("untrusted sender") && err.contains("valid at the record's time"),
        "{err}"
    );
}

#[tokio::test]
async fn wrap_excludes_member_with_broken_chain_and_still_writes() {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;
    let mut outsider = world.enroll(OUTSIDER, 33).await;

    // First wrap pins both members at epoch 0.
    let key = circle_key_generate_bytes();
    wrap_circle_key_for_session(&mut owner, wrap_request(&[MEMBER, OUTSIDER]), key.clone())
        .await
        .expect("first wrap");

    // MEMBER rotates twice, and the directory then loses epoch 1: the pin
    // cannot be advanced to epoch 2 (missing intermediate / broken chain).
    member.rotate_epoch().await.expect("rotate 1");
    member.rotate_epoch().await.expect("rotate 2");
    world
        .ds
        .lock()
        .unwrap()
        .heads
        .get_mut(MEMBER)
        .unwrap()
        .retain(|e| e.epoch_number != 1);

    // The batched roster call aborts on this member (not a roster exclusion)...
    assert!(owner
        .resolve_roster_report(&[MEMBER, OUTSIDER])
        .await
        .is_err());

    // ...but the wrap still writes the record for the verifiable subset.
    let key2 = circle_key_generate_bytes();
    let mut req = wrap_request(&[MEMBER, OUTSIDER]);
    req.key_version = 2;
    let wrapped = wrap_circle_key_for_session(&mut owner, req, key2.clone())
        .await
        .expect("wrap tolerates a faulty member");
    assert_eq!(wrapped.excluded_dids, vec![MEMBER.to_owned()]);
    assert_eq!(wrapped.excluded_reasons.len(), 1);
    assert!(!wrapped.excluded_reasons[0].is_empty());
    assert_eq!(
        open_circle_key_for_session(&mut outsider, &wrapped.record_json, SPACE, OWNER)
            .await
            .expect("outsider-member open")
            .map(|o| o.circle_key),
        Some(key2.clone())
    );
    assert_eq!(
        open_circle_key_for_session(&mut owner, &wrapped.record_json, SPACE, OWNER)
            .await
            .expect("owner self open")
            .map(|o| o.circle_key),
        Some(key2)
    );
}

#[tokio::test]
async fn open_refuses_unchained_later_owner_epoch() {
    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;

    let key = circle_key_generate_bytes();
    let genuine = wrap_circle_key_for_session(&mut owner, wrap_request(&[MEMBER]), key.clone())
        .await
        .expect("wrap");
    // Opening pins the owner at its genuine epoch 0.
    assert_eq!(
        open_circle_key_for_session(&mut member, &genuine.record_json, SPACE, OWNER)
            .await
            .unwrap()
            .map(|o| o.circle_key),
        Some(key.clone())
    );

    // A fresh owner chain the directory never saw, at a higher seq.
    let rogue = RogueTransport(SigningKey::from_bytes(&[0x68; 32]));
    let keys0 = MailboxKeys::derive(&[0x71; 32], 0);
    let e0 = EpochPublic::sign(OWNER, 0, &keys0, [0u8; 32], None, None, &rogue).unwrap();
    let keys1 = MailboxKeys::derive(&[0x72; 32], 1);
    let e1 = EpochPublic::sign(
        OWNER,
        1,
        &keys1,
        [0u8; 32],
        Some(e0.head),
        Some(&keys0.sig_secret),
        &rogue,
    )
    .unwrap();
    let member_epoch = world.latest_epoch(MEMBER).await;
    let params = catbird_mls::circles::keys::CircleKeyParams {
        circle_id: CIRCLE_ID.into(),
        key_version: 2,
        space_uri: SPACE.into(),
        reason: "memberRemoved".into(),
    };
    let body = catbird_mls::circles::keys::wrap_circle_key(
        &[8u8; 32],
        &params,
        OWNER,
        &keys1,
        &e1,
        &[
            catbird_mls::circles::keys::VerifiedRecipient {
                did: OWNER.into(),
                epoch: e1.clone(),
            },
            catbird_mls::circles::keys::VerifiedRecipient {
                did: MEMBER.into(),
                epoch: member_epoch,
            },
        ],
        CREATED,
    )
    .unwrap();
    let forged = serde_json::to_string(&catbird_mls::circles::records::CircleKeyRecord::from_body(
        &body,
    ))
    .unwrap();
    let err = open_circle_key_for_session(&mut member, &forged, SPACE, OWNER)
        .await
        .expect_err("unchained later owner epoch must be refused");
    assert!(err.to_string().contains("untrusted sender"), "{err}");

    // The pin did not move: the genuine record still opens.
    assert_eq!(
        open_circle_key_for_session(&mut member, &genuine.record_json, SPACE, OWNER)
            .await
            .expect("genuine record after forgery")
            .map(|o| o.circle_key),
        Some(key)
    );
}

#[path = "support/circles_live_platform.rs"]
mod circles_live_platform;

const LIVE_OWNER: &str = "did:plc:ownerlivecirclesaaaaaaaa";
const LIVE_MEMBER: &str = "did:plc:memberlivecirclesbbbbbbb";

fn live_wrap_request(version: u64, members: &[&str]) -> CircleKeyWrapRequest {
    CircleKeyWrapRequest {
        circle_id: CIRCLE_ID.into(),
        key_version: version,
        space_uri: format!("at://{LIVE_OWNER}/blue.catbird.circle.encrypted/3kcircle"),
        reason: "created".into(),
        member_dids: members.iter().map(|d| (*d).to_owned()).collect(),
        created_at: CREATED.into(),
    }
}

/// C1: the production Circles session (`CatbirdMlsClient::circles_open_session`,
/// built from the native archive deps) carries the PDS backend, so its
/// directory is the strict `CompositeDirectory` and opening it publishes
/// `mailboxKeys/self` (+ the immutable per-epoch copy) to the account's PDS.
/// The chat-side archive path (`setup_recovery_code`) is unchanged: it never
/// writes `mailboxKeys`.
#[test]
fn production_circles_session_has_pds_backend_and_composite_directory() {
    use circles_live_platform::{LiveWorld, MAILBOX_KEYS};
    let tmp = tempfile::tempdir().unwrap();
    let world = LiveWorld::default();
    let scopes: Vec<String> = catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let owner = world.client(LIVE_OWNER, &tmp.path().join("owner"));
    let member = world.client(LIVE_MEMBER, &tmp.path().join("member"));
    for client in [&owner, &member] {
        client.enroll_device(&scopes).expect("enroll");
        client.setup_recovery_code().expect("labyrinth enable");
    }
    assert!(world.has_ds_head(LIVE_OWNER) && world.has_ds_head(LIVE_MEMBER));
    // Simulate a peer that has an mls-ds head but no PDS mailboxKeys record yet,
    // so we exercise CompositeDirectory's strict single-source rejection + backfill.
    world.clear_mailbox_keys(LIVE_MEMBER);

    let key = owner.circle_key_generate();
    let first = owner
        .circle_key_wrap(live_wrap_request(1, &[LIVE_MEMBER]), key.clone())
        .expect("wrap v1");

    // (b) The owner's epoch is published to the PDS (`mailboxKeys/self` + immutable copy).
    let own = world
        .mailbox_keys(LIVE_OWNER, "self")
        .expect("native session publishes mailboxKeys/self");
    assert_eq!(own["$type"], MAILBOX_KEYS);
    let seq = own["current"]["epochNumber"].as_u64().expect("epochNumber");
    assert_eq!(
        world.mailbox_keys(LIVE_OWNER, &format!("{seq:012}")),
        Some(own.clone()),
        "the immutable per-epoch copy (D11) is published too"
    );

    // (a) The member has an mls-ds head but no PDS record: the strict
    // CompositeDirectory refuses single-source evidence (an mls-ds-only
    // directory would have wrapped to the member).
    assert_eq!(first.excluded_dids, vec![LIVE_MEMBER.to_owned()]);
    assert!(
        first.excluded_reasons[0].contains("directory evidence is incomplete"),
        "{:?}",
        first.excluded_reasons
    );

    // The member's own Circles session backfills its record; after that both
    // sources agree and the wrap reaches the member.
    let space = format!("at://{LIVE_OWNER}/blue.catbird.circle.encrypted/3kcircle");
    assert_eq!(
        member
            .circle_key_open(first.record_json.clone(), space.clone(), LIVE_OWNER.into())
            .expect("member open v1")
            .map(|o| o.circle_key),
        None
    );
    assert!(world.mailbox_keys(LIVE_MEMBER, "self").is_some());
    let second = owner
        .circle_key_wrap(live_wrap_request(2, &[LIVE_MEMBER]), key.clone())
        .expect("wrap v2");
    assert!(
        second.excluded_dids.is_empty(),
        "{:?}",
        second.excluded_reasons
    );
    assert_eq!(
        member
            .circle_key_open(second.record_json, space, LIVE_OWNER.into())
            .expect("member open v2")
            .map(|o| o.circle_key),
        Some(key)
    );
}

/// Two enrolled live clients (owner, member) with Labyrinth enabled.
fn live_pair(
    world: &circles_live_platform::LiveWorld,
    root: &std::path::Path,
) -> (
    std::sync::Arc<catbird_mls::client::CatbirdMlsClient>,
    std::sync::Arc<catbird_mls::client::CatbirdMlsClient>,
) {
    let scopes: Vec<String> = catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let owner = world.client(LIVE_OWNER, &root.join("owner"));
    let member = world.client(LIVE_MEMBER, &root.join("member"));
    for client in [&owner, &member] {
        client.enroll_device(&scopes).expect("enroll");
        client.setup_recovery_code().expect("labyrinth enable");
    }
    (owner, member)
}

fn live_space() -> String {
    format!("at://{LIVE_OWNER}/blue.catbird.circle.encrypted/3kcircle")
}

/// Fix round 1 #1: on a device the transport refuses
/// `com.atproto.identity.resolveDid`; foreign PDS reads must fall back to
/// plc.directory instead of excluding every member.
#[test]
fn foreign_pds_reads_fall_back_when_transport_refuses_resolve_did() {
    let tmp = tempfile::tempdir().unwrap();
    let world = circles_live_platform::LiveWorld::default();
    world.state.lock().unwrap().refuse_resolve_did = true;
    let (owner, member) = live_pair(&world, tmp.path());
    world.clear_mailbox_keys(LIVE_MEMBER);
    let key = owner.circle_key_generate();
    let first = owner
        .circle_key_wrap(live_wrap_request(1, &[LIVE_MEMBER]), key.clone())
        .expect("wrap v1");
    // The member reads the owner's foreign PDS record to verify the sender.
    assert_eq!(
        member
            .circle_key_open(first.record_json, live_space(), LIVE_OWNER.into())
            .expect("member open v1 resolves the owner's PDS via plc.directory")
            .map(|o| o.circle_key),
        None
    );
    // The owner reads the member's foreign PDS record to wrap to it.
    let second = owner
        .circle_key_wrap(live_wrap_request(2, &[LIVE_MEMBER]), key.clone())
        .expect("wrap v2");
    assert!(
        second.excluded_dids.is_empty(),
        "{:?}",
        second.excluded_reasons
    );
    assert_eq!(
        member
            .circle_key_open(second.record_json, live_space(), LIVE_OWNER.into())
            .expect("member open v2")
            .map(|o| o.circle_key),
        Some(key)
    );
    let log = world.state.lock().unwrap().log.clone();
    assert!(
        log.iter()
            .any(|l| l.contains(circles_live_platform::PLC_URL)),
        "fallback resolver was used"
    );
}

/// Fix round 1 #4: a caller-supplied owner that is not the Space authority
/// is refused before any request (no directory fetch or pin of that DID).
#[test]
fn bogus_owner_is_refused_before_any_directory_lookup() {
    use catbird_mls::ffi::circles_ffi::CircleFfiError;
    let tmp = tempfile::tempdir().unwrap();
    let world = circles_live_platform::LiveWorld::default();
    let (owner, member) = live_pair(&world, tmp.path());
    let wrapped = owner
        .circle_key_wrap(
            live_wrap_request(1, &[LIVE_MEMBER]),
            owner.circle_key_generate(),
        )
        .expect("wrap");
    let before = world.state.lock().unwrap().log.len();
    let bogus = "did:plc:bogusownerzzzzzzzzzzzzzz";
    let err = member
        .circle_key_open(wrapped.record_json, live_space(), bogus.into())
        .expect_err("bogus owner");
    assert!(
        matches!(&err, CircleFfiError::Untrusted { reason } if reason.contains("space authority")),
        "{err:?}"
    );
    let log = world.state.lock().unwrap().log.clone();
    assert_eq!(log.len(), before, "no requests: {:?}", &log[before..]);
    assert!(!log.iter().any(|l| l.contains("bogusowner")));
}

/// Fix round 1 #2: an owner whose PDS copy is missing (the stale state after
/// a chat-side rotation, until a Circles session backfills) is Unavailable,
/// not Untrusted.
#[test]
fn owner_with_incomplete_directory_evidence_is_unavailable() {
    use catbird_mls::ffi::circles_ffi::CircleFfiError;
    let tmp = tempfile::tempdir().unwrap();
    let world = circles_live_platform::LiveWorld::default();
    let (owner, member) = live_pair(&world, tmp.path());
    let key = owner.circle_key_generate();
    let first = owner
        .circle_key_wrap(live_wrap_request(1, &[LIVE_MEMBER]), key.clone())
        .expect("wrap v1");
    member
        .circle_key_open(first.record_json, live_space(), LIVE_OWNER.into())
        .expect("member backfills");
    let second = owner
        .circle_key_wrap(live_wrap_request(2, &[LIVE_MEMBER]), key)
        .expect("wrap v2");
    world
        .state
        .lock()
        .unwrap()
        .repo
        .retain(|(repo, collection, _), _| {
            !(repo == LIVE_OWNER && collection == circles_live_platform::MAILBOX_KEYS)
        });
    let err = member
        .circle_key_open(second.record_json, live_space(), LIVE_OWNER.into())
        .expect_err("owner evidence incomplete");
    assert!(
        matches!(&err, CircleFfiError::Unavailable { reason } if reason.contains("directory evidence is incomplete")),
        "{err:?}"
    );
}

/// I1/I2: an authentic post whose decrypted payload is not valid JSON fails
/// as `Malformed` with a fixed reason; no decrypted byte reaches the error.
#[tokio::test]
async fn post_open_error_never_echoes_decrypted_plaintext() {
    use catbird_mls::circles::post::{derive_post_key, post_aad, CirclePostHeader, SealedPost};
    use catbird_mls::circles::records::CirclePostRecord;
    use catbird_mls::ffi::circles_ffi::CircleFfiError;

    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;
    let key = circle_key_generate_bytes();
    let header = CirclePostHeader {
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        post_uri: post_uri(),
        author_did: OWNER.into(),
        created_at: CREATED.into(),
    };
    let latest = owner.latest_public().unwrap();
    let mine = owner.mailbox_keys_current_and_previous().await.unwrap();
    let (_, _, author_keys) = mine.iter().find(|(s, _, _)| *s == latest.seq).unwrap();
    let post_key = derive_post_key(&key.clone().try_into().unwrap(), CIRCLE_ID, &post_uri());
    let padded = labyrinth::padding::pad(br#"{"post":{"text":"SENTINEL-PLAINTEXT-4410"},"#);
    let ciphertext = labyrinth::aead::encrypt(
        labyrinth::aead::Suite::DndkGcm,
        &post_key,
        &post_aad(&header),
        &padded,
    )
    .unwrap();
    let mut msg = b"catbird.circle.post.sig.v1:".to_vec();
    msg.extend_from_slice(&ciphertext);
    let sealed = SealedPost {
        sig: author_keys.sig_secret.sign(&msg).unwrap(),
        ciphertext,
        author_epoch_head: latest.head,
    };
    let record = CirclePostRecord::from_sealed(&sealed, &header, None, vec![]);
    let err = open_circle_post_for_session(
        &mut member,
        CirclePostOpenRequest {
            record_json: serde_json::to_string(&record).unwrap(),
            post_uri: post_uri(),
            author_did: OWNER.into(),
            circle_key: key,
            author_epoch_json: world.mailbox_keys_json(OWNER).await,
        },
    )
    .await
    .expect_err("invalid inner JSON");
    assert!(matches!(err, CircleFfiError::Malformed { .. }), "{err:?}");
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("SENTINEL"), "{shown}");
    assert!(shown.contains("payload malformed"), "{shown}");
}

/// I2: failures map onto the typed FFI variants.
#[tokio::test]
async fn ffi_errors_are_typed() {
    use catbird_mls::ffi::circles_ffi::CircleFfiError;

    let world = World::new();
    let mut owner = world.enroll(OWNER, 11).await;
    let mut member = world.enroll(MEMBER, 22).await;
    let key = circle_key_generate_bytes();

    // Record shape → Malformed.
    let err = open_circle_key_for_session(&mut member, "{\"nope\":1}", SPACE, OWNER)
        .await
        .unwrap_err();
    assert!(matches!(err, CircleFfiError::Malformed { .. }), "{err:?}");

    // A key record whose sender is not the owner → Untrusted.
    let wrapped = wrap_circle_key_for_session(&mut owner, wrap_request(&[MEMBER]), key.clone())
        .await
        .unwrap();
    let err = open_circle_key_for_session(&mut member, &wrapped.record_json, SPACE, MEMBER)
        .await
        .unwrap_err();
    assert!(matches!(err, CircleFfiError::Untrusted { .. }), "{err:?}");

    // An owner DID that is not the Space's authority → Untrusted.
    let err = open_circle_key_for_session(
        &mut member,
        &wrapped.record_json,
        &format!("at://{MEMBER}/blue.catbird.circle.encrypted/3kcircle"),
        OWNER,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CircleFfiError::Untrusted { .. }), "{err:?}");
    assert!(
        err.to_string().contains("owner is not the space authority"),
        "{err}"
    );

    // Wrong Circle key (AEAD tag) → NotOpenable.
    let record_json = seal_circle_post_for_session(&mut owner, seal_request(&key, None))
        .await
        .unwrap();
    let err = open_circle_post_for_session(
        &mut member,
        CirclePostOpenRequest {
            record_json: record_json.clone(),
            post_uri: post_uri(),
            author_did: OWNER.into(),
            circle_key: vec![9u8; 32],
            author_epoch_json: world.mailbox_keys_json(OWNER).await,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CircleFfiError::NotOpenable { .. }), "{err:?}");

    // A tampered signature → NotOpenable.
    let mut tampered: Value = serde_json::from_str(&record_json).unwrap();
    let sig = tampered["sig"]["$bytes"].as_str().unwrap().to_owned();
    let mut raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(sig.trim_end_matches('='))
        .unwrap();
    raw[0] ^= 1;
    tampered["sig"]["$bytes"] = json!(STANDARD_NO_PAD.encode(raw));
    let err = open_circle_post_for_session(
        &mut member,
        CirclePostOpenRequest {
            record_json: tampered.to_string(),
            post_uri: post_uri(),
            author_did: OWNER.into(),
            circle_key: key.clone(),
            author_epoch_json: world.mailbox_keys_json(OWNER).await,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CircleFfiError::NotOpenable { .. }), "{err:?}");
}

/// I2: a session that cannot be opened (no live device) → Unavailable.
#[test]
fn ffi_error_unavailable_without_live_session() {
    use catbird_mls::ffi::circles_ffi::CircleFfiError;
    let tmp = tempfile::tempdir().unwrap();
    let world = circles_live_platform::LiveWorld::default();
    let client = world.client(LIVE_OWNER, tmp.path());
    // Never enrolled: there is no Labyrinth session to open.
    let err = client
        .circle_key_open("{}".into(), live_space(), LIVE_OWNER.into())
        .unwrap_err();
    assert!(matches!(err, CircleFfiError::Unavailable { .. }), "{err:?}");
}
