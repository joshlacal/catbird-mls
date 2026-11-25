//! Cross-language contract for E2EE Circles: the Swift client's pinned inner
//! payload must parse here, and the Rust-produced records must round-trip
//! through the parsers/opener the Swift side drives.
//!
//! Fixtures live in `tests/fixtures/`. The `rust_*` ones are COMMITTED
//! ARTIFACTS, not reproducible bytes (random identities). They hold TEST ONLY
//! key material in `rust_cross_language_manifest_TEST_ONLY.json`; never reuse
//! any of it outside tests. Refresh deliberately with:
//! `cargo test --test circles_cross_language regenerate_cross_language_fixtures -- --ignored`
//! and commit all `rust_*` files together.
//!
//! Identifiers are in their real canonical forms (Swift's canonical-URI
//! checks reject anything else before reaching the FFI): 24-char `did:plc`
//! DIDs, 13-char TID record keys for the post and reply refs, and a Space
//! URI `at://<owner>/space/blue.catbird.circle.encrypted/<skey>`.
//!
//! LEGACY SPACE URI (2026-11-24): the committed fixtures still use the old
//! `at://<owner>/space/...` form on purpose. The Space URI is bound into the
//! Hawk AAD of every wrap in `rust_circle_key_record.json`, so it cannot be
//! string-replaced to `at:space/<owner>/...`. To move to the new form, change
//! `SPACE` and the prefix in `fixtures_use_canonical_tids_and_space_uri` to
//! `at:space/<owner>/blue.catbird.circle.encrypted/<skey>`, regenerate all
//! `rust_*` fixtures with the command above, and copy them to Catbird's
//! CatbirdTests/Fixtures/CrossLanguage.

#![cfg(feature = "labyrinth")]

use catbird_mls::circles::keys::{
    circle_key_generate, open_circle_key, wrap_circle_key, CircleKeyParams, VerifiedRecipient,
};
use catbird_mls::circles::post::{
    derive_post_key, open_post_with_post_key, seal_post, CircleMediaKey, CirclePostHeader,
    CirclePostPayload,
};
use catbird_mls::circles::records::{
    check_record_payload_consistency, header_from_record, CircleKeyRecord, CirclePostRecord,
};
use ed25519_dalek::Signer as _;
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::sign::TransportSigner;
use serde_json::{json, Value};

const SWIFT_PAYLOAD: &str = include_str!("fixtures/swift_circle_post_payload.json");
const KEY_RECORD: &str = include_str!("fixtures/rust_circle_key_record.json");
const POST_RECORD: &str = include_str!("fixtures/rust_circle_post_record.json");
const AUTHOR_KEYS: &str = include_str!("fixtures/rust_author_mailbox_keys.json");
const MANIFEST: &str = include_str!("fixtures/rust_cross_language_manifest_TEST_ONLY.json");

const CIRCLE_ID: &str = "3kcircleid22a";
// LEGACY SPACE URI: AAD-bound in the committed fixtures; see the module docs.
const SPACE: &str =
    "at://did:plc:ownerfixturecirclesaaaaa/space/blue.catbird.circle.encrypted/3l7circ2222aa";
const OWNER: &str = "did:plc:ownerfixturecirclesaaaaa";
const ALICE: &str = "did:plc:alicefixturecirclesaaaaa";
const BOB: &str = "did:plc:bobfixturecirclesaaaaaaa";
const POST_URI: &str =
    "at://did:plc:ownerfixturecirclesaaaaa/blue.catbird.circle.post/3l7post2222aa";
const CREATED: &str = "2026-11-07T12:05:00.000Z";
const TEXT: &str = "cross-language circle post";

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

#[test]
fn swift_payload_deserializes_as_circle_post_payload() {
    let payload: CirclePostPayload = serde_json::from_str(SWIFT_PAYLOAD).expect("swift payload");
    assert_eq!(payload.created_at, "2026-10-26T07:33:20.301Z");
    assert_eq!(payload.post["createdAt"], json!(payload.created_at));
    assert_eq!(payload.post["$type"], "app.bsky.feed.post");
    assert_eq!(payload.media.len(), 1);
    let m = &payload.media[0];
    assert_eq!(
        m.cid,
        "bafyreigkbxzmswvbita5b7zp6pepsz75yhpj54geciftojsbm4a3kgowde"
    );
    assert_eq!(m.key, vec![0x42; 32]);
    assert_eq!(m.iv, vec![0x24; 12]);
    assert_eq!(m.sha256, "ab".repeat(32));
    assert_eq!(m.mime_type, "image/jpeg");
    assert_eq!(m.alt.as_deref(), Some("a heron"));
    assert_eq!((m.width, m.height), (Some(1200), Some(800)));

    // The pinned fixture has no reply; the record must agree on that and on createdAt.
    assert!(payload.post.get("reply").is_none());
    let record = CirclePostRecord {
        type_: "blue.catbird.circle.post".into(),
        circle_id: CIRCLE_ID.into(),
        key_version: 1,
        created_at: payload.created_at.clone(),
        reply: None,
        ciphertext: labyrinth::records::Bytes::from_slice(&[2u8; 40]),
        sig: labyrinth::records::Bytes::from_slice(&[0u8; 64]),
        author_epoch_head: labyrinth::records::Bytes::from_slice(&[0u8; 32]),
        attachments: vec![],
    };
    check_record_payload_consistency(&record, &payload).expect("consistent");
    let mut shifted = record;
    shifted.created_at = "2026-10-26T07:33:21.301Z".into();
    assert!(check_record_payload_consistency(&shifted, &payload).is_err());
}

fn is_tid(rkey: &str) -> bool {
    const CHARS: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    rkey.len() == 13
        && rkey.bytes().all(|b| CHARS.contains(&b))
        && b"234567abcdefghij".contains(&rkey.as_bytes()[0])
}

#[test]
fn fixtures_use_canonical_tids_and_space_uri() {
    let m: Value = serde_json::from_str(MANIFEST).expect("manifest");
    let post: Value = serde_json::from_str(POST_RECORD).expect("post");
    let space = m["space_uri"].as_str().unwrap();
    let owner = m["owner_did"].as_str().unwrap();
    assert_eq!(
        space.strip_prefix(&format!(
            "at://{owner}/space/blue.catbird.circle.encrypted/"
        )),
        Some(space.rsplit('/').next().unwrap()),
        "{space}"
    );
    let mut uris = vec![m["post_uri"].as_str().unwrap().to_owned()];
    for k in ["root", "parent"] {
        uris.push(post["reply"][k]["uri"].as_str().unwrap().to_owned());
    }
    for uri in uris {
        let rkey = uri.rsplit('/').next().unwrap();
        assert!(uri.contains("/blue.catbird.circle.post/"), "{uri}");
        assert!(is_tid(rkey), "{uri} rkey is not a TID");
    }
    for k in ["owner_did", "author_did", "recipient_did"] {
        let did = m[k].as_str().unwrap();
        let id = did.strip_prefix("did:plc:").unwrap();
        assert!(
            id.len() == 24
                && id
                    .bytes()
                    .all(|b| b"234567abcdefghijklmnopqrstuvwxyz".contains(&b)),
            "{did}"
        );
    }
}

#[test]
fn rust_fixtures_round_trip() {
    let m: Value = serde_json::from_str(MANIFEST).expect("manifest");
    let s = |k: &str| {
        m[k].as_str()
            .unwrap_or_else(|| panic!("manifest {k}"))
            .to_owned()
    };

    // Key record: parse, open as the recipient.
    let key_record: CircleKeyRecord = serde_json::from_str(KEY_RECORD).expect("key record");
    assert_eq!(key_record.recipients.len(), 8);
    assert_eq!(key_record.key_version, m["key_version"].as_u64().unwrap());
    let body = key_record.to_body().expect("to_body");
    let recipient_root = hex32(&s("recipient_root_hex"));
    let seq = m["recipient_epoch_seq"].as_u64().unwrap();
    let recipient_keys = MailboxKeys::derive(&recipient_root, seq);
    let owner_head = hex32(&s("owner_epoch_head_hex"));
    let circle_key = open_circle_key(
        &body,
        &s("space_uri"),
        &s("owner_did"),
        &[owner_head],
        &[(seq, recipient_keys)],
        &[hex32(&s("recipient_epoch_head_hex"))],
    )
    .expect("open_circle_key")
    .expect("recipient entry found");
    assert_eq!(circle_key.circle_id, s("circle_id"));
    assert_eq!(circle_key.key_version, m["key_version"].as_u64().unwrap());
    let circle_key = circle_key.key;
    assert_eq!(hex::encode(circle_key), s("circle_key_hex"));
    assert_eq!(
        hex::encode(derive_post_key(
            &circle_key,
            &s("circle_id"),
            &s("post_uri")
        )),
        s("post_key_hex")
    );

    // Author keys record = what a PDS mailboxKeys/self record looks like.
    let author_rec: MailboxKeysRecord = serde_json::from_str(AUTHOR_KEYS).expect("author keys");
    let author_epoch = author_rec.to_public().expect("to_public");
    author_epoch
        .verify(&s("author_did"), None)
        .expect("author epoch verifies");

    // Post record: parse, consistency, open with the post key.
    let post_record: CirclePostRecord = serde_json::from_str(POST_RECORD).expect("post record");
    assert_eq!(post_record.created_at, s("created_at"));
    let sealed = post_record.to_sealed().expect("to_sealed");
    assert_eq!(sealed.author_epoch_head, author_epoch.head);
    let header = header_from_record(&post_record, &s("post_uri"), &s("author_did")).expect("hdr");
    let payload = open_post_with_post_key(
        &sealed,
        &header,
        &hex32(&s("post_key_hex")),
        &author_epoch.keys.sig,
    )
    .expect("open post");
    assert_eq!(payload.post["text"], json!(s("expected_text")));
    check_record_payload_consistency(&post_record, &payload).expect("consistent");
    assert!(post_record.reply.is_some(), "fixture carries a reply");
    assert_eq!(payload.media.len(), 1);
}

/// Re-pad every `{"$bytes": "..."}` value to a multiple of 4 with `=`.
fn repad(v: &mut Value) {
    match v {
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(Value::String(b)) = map.get_mut("$bytes") {
                    while b.len() % 4 != 0 {
                        b.push('=');
                    }
                    return;
                }
            }
            map.values_mut().for_each(repad);
        }
        Value::Array(a) => a.iter_mut().for_each(repad),
        _ => {}
    }
}

#[test]
fn padded_base64_in_records_is_accepted() {
    let original: CircleKeyRecord = serde_json::from_str(KEY_RECORD).expect("record");
    let mut v: Value = serde_json::from_str(KEY_RECORD).unwrap();
    repad(&mut v);
    let text = v.to_string();
    assert!(text.contains("=\""), "repadding changed at least one value");
    let padded: CircleKeyRecord = serde_json::from_str(&text).expect("padded accepted");
    assert_eq!(padded.to_body().unwrap(), original.to_body().unwrap());
}

#[test]
fn nested_type_in_sender_epoch_is_rejected() {
    let mut v: Value = serde_json::from_str(KEY_RECORD).unwrap();
    v["sender"]["senderEpoch"]["$type"] = json!("blue.catbird.labyrinth.defs#epochPublic");
    // EpochPublicDef denies unknown fields, so a re-encoder that injects a
    // `$type` there (Petrel did) breaks parsing. Swift must pass the raw
    // record bytes through to the FFI instead of re-encoding.
    let r = serde_json::from_value::<CircleKeyRecord>(v);
    assert!(r.is_err(), "nested $type must be rejected, got {r:?}");
}

// ---------------------------------------------------------------------------
// Generator (ignored): writes the rust_* fixtures.
// ---------------------------------------------------------------------------

struct TestTransport(ed25519_dalek::SigningKey);
impl TransportSigner for TestTransport {
    fn transport_public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    labyrinth::encoding::random(&mut out).expect("rng");
    out
}

struct Identity {
    root: [u8; 32],
    epoch: EpochPublic,
}

fn identity(did: &str) -> Identity {
    let root = random32();
    let keys = MailboxKeys::derive(&root, 0);
    let t = TestTransport(ed25519_dalek::SigningKey::from_bytes(&random32()));
    let epoch = EpochPublic::sign(did, 0, &keys, random32(), None, None, &t).expect("epoch");
    epoch.verify(did, None).expect("verify");
    Identity { root, epoch }
}

fn write_fixture(name: &str, v: &impl serde::Serialize) {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let mut s = serde_json::to_string_pretty(v).expect("json");
    s.push('\n');
    if std::env::var_os("CATBIRD_REGEN_FIXTURES").is_some() {
        std::fs::write(&path, s).unwrap_or_else(|e| panic!("write {path}: {e}"));
    } else {
        assert!(!s.is_empty());
    }
}

#[test]
fn regenerate_cross_language_fixtures() {
    let owner = identity(OWNER);
    let alice = identity(ALICE);
    let bob = identity(BOB);
    let recips: Vec<VerifiedRecipient> = [(OWNER, &owner), (ALICE, &alice), (BOB, &bob)]
        .iter()
        .map(|(d, i)| VerifiedRecipient {
            did: (*d).into(),
            epoch: i.epoch.clone(),
        })
        .collect();
    let key = circle_key_generate();
    let owner_keys = MailboxKeys::derive(&owner.root, 0);
    let body = wrap_circle_key(
        &key,
        &CircleKeyParams {
            circle_id: CIRCLE_ID.into(),
            key_version: 3,
            space_uri: SPACE.into(),
            reason: "created".into(),
        },
        OWNER,
        &owner_keys,
        &owner.epoch,
        &recips,
        "2026-11-07T12:00:00.000Z",
    )
    .expect("wrap");
    assert_eq!(body.recipients.len(), 8);
    write_fixture(
        "rust_circle_key_record.json",
        &CircleKeyRecord::from_body(&body),
    );

    let reply = json!({
        "root": {"uri": format!("at://{OWNER}/blue.catbird.circle.post/3l7root2222aa"), "cid": "bafyreigkbxzmswvbita5b7zp6pepsz75yhpj54geciftojsbm4a3kgowde"},
        "parent": {"uri": format!("at://{ALICE}/blue.catbird.circle.post/3l7prnt2222aa"), "cid": "bafyreigkbxzmswvbita5b7zp6pepsz75yhpj54geciftojsbm4a3kgowde"},
    });
    let payload = CirclePostPayload {
        post: json!({"$type": "app.bsky.feed.post", "text": TEXT, "createdAt": CREATED, "reply": reply}),
        media: vec![CircleMediaKey {
            cid: "bafyreigkbxzmswvbita5b7zp6pepsz75yhpj54geciftojsbm4a3kgowde".into(),
            key: vec![0x42; 32],
            iv: vec![0x24; 12],
            sha256: "ab".repeat(32),
            mime_type: "image/jpeg".into(),
            alt: Some("a heron".into()),
            width: Some(1200),
            height: Some(800),
        }],
        created_at: CREATED.into(),
    };
    let header = CirclePostHeader {
        circle_id: CIRCLE_ID.into(),
        key_version: 3,
        post_uri: POST_URI.into(),
        author_did: OWNER.into(),
        created_at: CREATED.into(),
    };
    let sealed = seal_post(&payload, &header, &key, &owner_keys, owner.epoch.head).expect("seal");
    let rec = CirclePostRecord::from_sealed(&sealed, &header, Some(reply), vec![]);
    write_fixture("rust_circle_post_record.json", &rec);
    write_fixture(
        "rust_author_mailbox_keys.json",
        &MailboxKeysRecord::from_public(&owner.epoch, None, "2026-11-07T12:00:00.000Z".into()),
    );
    write_fixture(
        "rust_cross_language_manifest_TEST_ONLY.json",
        &json!({
            "WARNING": "TEST ONLY key material. Never use outside tests. Random per generation.",
            "circle_id": CIRCLE_ID,
            "space_uri": SPACE,
            "owner_did": OWNER,
            "post_uri": POST_URI,
            "author_did": OWNER,
            "created_at": CREATED,
            "key_version": 3,
            "expected_text": TEXT,
            "recipient_did": ALICE,
            "recipient_epoch_seq": 0,
            "recipient_epoch_head_hex": hex::encode(alice.epoch.head),
            "owner_epoch_head_hex": hex::encode(owner.epoch.head),
            "circle_key_hex": hex::encode(key),
            "post_key_hex": hex::encode(derive_post_key(&key, CIRCLE_ID, POST_URI)),
            "recipient_root_hex": hex::encode(alice.root),
        }),
    );
}
