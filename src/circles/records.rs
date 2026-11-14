//! Wire forms of `blue.catbird.circle.key` and `blue.catbird.circle.post`
//! (lexicons in `PetrelCatbird/lexicons/blue/catbird/circle/`).
//!
//! Byte fields use the atproto `{"$bytes": "<base64>"}` form (emitted
//! unpadded, padded input accepted) via
//! `labyrinth::records::Bytes`, and the key record's `sender` reuses the
//! `$type`-tagged Labyrinth sender union, so Swift, Kotlin and Rust read and
//! write identical JSON.

use ::labyrinth::records::defs::EpochPublicDef;
use ::labyrinth::records::thread::{LabyrinthSenderDef, MekSenderDef};
use ::labyrinth::records::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::CircleError;
use super::keys::CircleKeyRecordBody;
use super::post::{CirclePostHeader, CirclePostPayload, SealedPost};

/// NSID of the key record.
pub const KEY_NSID: &str = "blue.catbird.circle.key";
/// NSID of the post record.
pub const POST_NSID: &str = "blue.catbird.circle.post";

fn malformed(what: impl std::fmt::Display) -> CircleError {
    CircleError::Malformed(what.to_string())
}

/// `blue.catbird.circle.key` (rkey = [`key_record_rkey`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleKeyRecord {
    #[serde(rename = "$type")]
    pub type_: String,
    pub circle_id: String,
    pub key_version: u64,
    pub sender: MekSenderDef,
    pub recipients: Vec<Bytes>,
    pub reason: String,
    pub created_at: String,
}

impl CircleKeyRecord {
    pub fn from_body(b: &CircleKeyRecordBody) -> Self {
        Self {
            type_: KEY_NSID.into(),
            circle_id: b.circle_id.clone(),
            key_version: b.key_version,
            sender: MekSenderDef::Labyrinth(LabyrinthSenderDef {
                did: b.sender_did.clone(),
                sender_epoch_head: Bytes::from_slice(&b.sender_epoch.head),
                sender_epoch: EpochPublicDef::from_public(&b.sender_epoch),
            }),
            recipients: b.recipients.iter().map(|r| Bytes::from_slice(r)).collect(),
            reason: b.reason.clone(),
            created_at: b.created_at.clone(),
        }
    }

    /// Parse into the protocol body. Does not verify the sender epoch; the
    /// caller does that against the directory (`UntrustedSender`). Rejects a
    /// wrong `$type`, a non-Labyrinth sender, a `senderEpochHead` that is not
    /// the embedded epoch's head, and unparsable epoch encodings.
    pub fn to_body(&self) -> Result<CircleKeyRecordBody, CircleError> {
        if self.type_ != KEY_NSID {
            return Err(malformed(format!("unexpected record type {}", self.type_)));
        }
        let MekSenderDef::Labyrinth(sender) = &self.sender else {
            return Err(malformed("key record sender is not a labyrinthSender"));
        };
        let head: [u8; 32] = sender
            .sender_epoch_head
            .array("senderEpochHead length")
            .map_err(malformed)?;
        let sender_epoch = sender.sender_epoch.to_public().map_err(malformed)?;
        if sender_epoch.head != head {
            return Err(malformed("senderEpochHead does not match senderEpoch"));
        }
        Ok(CircleKeyRecordBody {
            circle_id: self.circle_id.clone(),
            key_version: self.key_version,
            sender_did: sender.did.clone(),
            sender_epoch,
            recipients: self.recipients.iter().map(|r| r.0.clone()).collect(),
            reason: self.reason.clone(),
            created_at: self.created_at.clone(),
        })
    }
}

/// Record key of a key version: zero-padded to six digits.
pub fn key_record_rkey(key_version: u64) -> String {
    format!("{key_version:06}")
}

/// `blue.catbird.circle.post`. `reply` and `attachments` are visible to the
/// service and pass through untouched.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CirclePostRecord {
    #[serde(rename = "$type")]
    pub type_: String,
    pub circle_id: String,
    pub key_version: u64,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<Value>,
    pub ciphertext: Bytes,
    pub sig: Bytes,
    pub author_epoch_head: Bytes,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Value>,
}

impl CirclePostRecord {
    pub fn from_sealed(
        s: &SealedPost,
        h: &CirclePostHeader,
        reply: Option<Value>,
        attachments: Vec<Value>,
    ) -> Self {
        Self {
            type_: POST_NSID.into(),
            circle_id: h.circle_id.clone(),
            key_version: h.key_version,
            created_at: h.created_at.clone(),
            reply,
            ciphertext: Bytes::from_slice(&s.ciphertext),
            sig: Bytes::from_slice(&s.sig),
            author_epoch_head: Bytes::from_slice(&s.author_epoch_head),
            attachments,
        }
    }

    pub fn to_sealed(&self) -> Result<SealedPost, CircleError> {
        if self.type_ != POST_NSID {
            return Err(malformed(format!("unexpected record type {}", self.type_)));
        }
        Ok(SealedPost {
            ciphertext: self.ciphertext.0.clone(),
            sig: self.sig.array("sig length").map_err(malformed)?,
            author_epoch_head: self
                .author_epoch_head
                .array("authorEpochHead length")
                .map_err(malformed)?,
        })
    }
}

/// Build the AAD header for a stored post. `post_uri` and `author_did` come
/// from the repo the record was read from, not from the record. Rejects any
/// field containing `;` or `=`, which delimit the AAD and could otherwise
/// splice fields, and a `post_uri` that is not
/// `at://<author_did>/blue.catbird.circle.post/<rkey>`.
pub fn header_from_record(
    record: &CirclePostRecord,
    post_uri: &str,
    author_did: &str,
) -> Result<CirclePostHeader, CircleError> {
    for (name, value) in [
        ("circleId", record.circle_id.as_str()),
        ("postUri", post_uri),
        ("authorDid", author_did),
        ("createdAt", record.created_at.as_str()),
    ] {
        if value.contains([';', '=']) {
            return Err(malformed(format!("{name} contains a separator character")));
        }
    }
    crate::circles::post::validate_post_uri(post_uri, author_did)?;
    Ok(CirclePostHeader {
        circle_id: record.circle_id.clone(),
        key_version: record.key_version,
        post_uri: post_uri.to_owned(),
        author_did: author_did.to_owned(),
        created_at: record.created_at.clone(),
    })
}

/// The four strings that identify a reply's parent and root, or `None` if the
/// value is not a well-formed `replyRef`.
fn reply_refs(reply: &Value) -> Option<[&str; 4]> {
    let s = |a: &str, b: &str| reply.get(a)?.get(b)?.as_str();
    Some([
        s("parent", "uri")?,
        s("parent", "cid")?,
        s("root", "uri")?,
        s("root", "cid")?,
    ])
}

/// The service sees `reply` and `createdAt`; the sealed payload carries its
/// own copies. A server that re-threads a post or shifts its time must not
/// be believed. Both copies of the reply must be absent, or present and equal;
/// `createdAt` must agree across the record, the payload, and the inner post.
pub fn check_record_payload_consistency(
    record: &CirclePostRecord,
    payload: &CirclePostPayload,
) -> Result<(), CircleError> {
    match (&record.reply, payload.post.get("reply")) {
        (None, None) => {}
        (Some(r), Some(p)) => match (reply_refs(r), reply_refs(p)) {
            (Some(a), Some(b)) if a == b => {}
            _ => return Err(CircleError::HeaderMismatch),
        },
        _ => return Err(CircleError::HeaderMismatch),
    }
    if payload.created_at != record.created_at {
        return Err(CircleError::HeaderMismatch);
    }
    match payload.post.get("createdAt") {
        None => {}
        Some(Value::String(s)) if *s == payload.created_at => {}
        Some(_) => return Err(CircleError::HeaderMismatch),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circles::keys::CircleKeyRecordBody;
    use crate::circles::post::{CirclePostHeader, CirclePostPayload, SealedPost};
    use ::labyrinth::mailbox::{EpochPublic, MailboxKeys};
    use ::labyrinth::sign::TransportSigner;
    use ed25519_dalek::Signer as _;
    use serde_json::{json, Value};

    const CREATED: &str = "2026-11-07T12:05:00.000Z";
    const KEY_FIXTURE: &str = include_str!("../../tests/fixtures/circle_key_record.json");
    const POST_FIXTURE: &str = include_str!("../../tests/fixtures/circle_post_record.json");

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
        ::labyrinth::encoding::random(&mut out).expect("rng");
        out
    }

    fn epoch(did: &str) -> EpochPublic {
        let keys = MailboxKeys::derive(&random32(), 0);
        let t = TestTransport(ed25519_dalek::SigningKey::from_bytes(&random32()));
        EpochPublic::sign(did, 0, &keys, random32(), None, None, &t).expect("epoch")
    }

    fn body() -> CircleKeyRecordBody {
        CircleKeyRecordBody {
            circle_id: "3kcircleid22a".into(),
            key_version: 2,
            sender_did: "did:plc:owner".into(),
            sender_epoch: epoch("did:plc:owner"),
            recipients: (0..8u8).map(|i| vec![i; 1169]).collect(),
            reason: "memberRemoved".into(),
            created_at: "2026-11-07T12:00:00.000Z".into(),
        }
    }

    fn keys_of(v: &Value) -> Vec<String> {
        let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
        k.sort();
        k
    }

    #[test]
    fn key_record_json_matches_lexicon_fixture() {
        let fixture: Value = serde_json::from_str(KEY_FIXTURE).expect("fixture json");
        // The hand-written fixture parses under deny_unknown_fields and
        // re-serializes to exactly the same JSON.
        let parsed: CircleKeyRecord = serde_json::from_str(KEY_FIXTURE).expect("parse fixture");
        assert_eq!(serde_json::to_value(&parsed).expect("to_value"), fixture);
        let from_fixture = parsed.to_body().expect("to_body");
        assert_eq!(from_fixture.recipients.len(), 8);
        assert!(from_fixture.recipients.iter().all(|r| r.len() == 1169));
        assert_eq!(from_fixture.key_version, 2);

        // A freshly built record has the same field set and encodings.
        let record = CircleKeyRecord::from_body(&body());
        let v = serde_json::to_value(&record).expect("to_value");
        assert_eq!(keys_of(&v), keys_of(&fixture));
        assert_eq!(v["$type"], "blue.catbird.circle.key");
        assert_eq!(
            v["sender"]["$type"],
            "blue.catbird.labyrinth.mek#labyrinthSender"
        );
        assert_eq!(keys_of(&v["sender"]), keys_of(&fixture["sender"]));
        assert_eq!(
            keys_of(&v["sender"]["senderEpoch"]),
            keys_of(&fixture["sender"]["senderEpoch"])
        );
        assert_eq!(keys_of(&v["recipients"][0]), vec!["$bytes".to_string()]);
        assert!(v["recipients"][0]["$bytes"]
            .as_str()
            .is_some_and(|s| !s.contains('=')));
        // Round trip through JSON text, and back to the identical body.
        let text = serde_json::to_string(&record).expect("string");
        let back: CircleKeyRecord = serde_json::from_str(&text).expect("reparse");
        assert_eq!(back.to_body().expect("to_body"), body_eq(&record));

        // deny_unknown_fields.
        let mut extra = fixture.clone();
        extra["bogus"] = json!(1);
        assert!(serde_json::from_value::<CircleKeyRecord>(extra).is_err());
    }

    /// The body a record decodes to (for equality with the original).
    fn body_eq(r: &CircleKeyRecord) -> CircleKeyRecordBody {
        r.to_body().expect("to_body")
    }

    #[test]
    fn key_record_body_roundtrip_is_lossless() {
        let b = body();
        assert_eq!(CircleKeyRecord::from_body(&b).to_body().expect("rt"), b);
    }

    #[test]
    fn key_record_rejects_wrong_type_or_sender_variant() {
        let mut r = CircleKeyRecord::from_body(&body());
        r.type_ = "blue.catbird.circle.post".into();
        assert!(matches!(r.to_body(), Err(CircleError::Malformed(_))));

        let mut v = serde_json::to_value(CircleKeyRecord::from_body(&body())).unwrap();
        v["sender"] = json!({
            "$type": "blue.catbird.labyrinth.mek#transportSender",
            "transportPubkey": {"$bytes": "AAAA"},
            "ephemeralAuthPubkey": {"$bytes": "AAAA"},
            "sig": {"$bytes": "AAAA"},
        });
        let r: CircleKeyRecord = serde_json::from_value(v).expect("parse");
        assert!(matches!(r.to_body(), Err(CircleError::Malformed(_))));
    }

    #[test]
    fn key_record_rejects_head_mismatch() {
        let mut v = serde_json::to_value(CircleKeyRecord::from_body(&body())).unwrap();
        v["sender"]["senderEpochHead"] =
            serde_json::to_value(::labyrinth::records::Bytes::from_slice(&[9u8; 32])).unwrap();
        let r: CircleKeyRecord = serde_json::from_value(v).expect("parse");
        assert!(matches!(r.to_body(), Err(CircleError::Malformed(_))));
    }

    #[test]
    fn rkey_is_zero_padded() {
        assert_eq!(key_record_rkey(7), "000007");
        assert_eq!(key_record_rkey(123456), "123456");
        assert_eq!(key_record_rkey(1234567), "1234567");
    }

    fn header() -> CirclePostHeader {
        CirclePostHeader {
            circle_id: "3kcircleid22a".into(),
            key_version: 2,
            post_uri: "at://did:plc:author/blue.catbird.circle.post/3kpost222aa".into(),
            author_did: "did:plc:author".into(),
            created_at: CREATED.into(),
        }
    }

    fn sealed() -> SealedPost {
        SealedPost {
            ciphertext: vec![2u8; 600],
            sig: [7u8; 64],
            author_epoch_head: [8u8; 32],
        }
    }

    // `SealedPost` derives nothing (post.rs is out of scope for this task).
    fn assert_sealed_eq(a: &SealedPost, b: &SealedPost) {
        assert_eq!(a.ciphertext, b.ciphertext);
        assert_eq!(a.sig, b.sig);
        assert_eq!(a.author_epoch_head, b.author_epoch_head);
    }

    fn reply_json() -> Value {
        json!({
            "root": {"uri": "at://did:plc:o/blue.catbird.circle.post/3kroot", "cid": "bafyroot"},
            "parent": {"uri": "at://did:plc:a/blue.catbird.circle.post/3kparent", "cid": "bafyparent"},
        })
    }

    fn payload_with(reply: Option<Value>) -> CirclePostPayload {
        let mut post = json!({"$type": "app.bsky.feed.post", "text": "hi", "createdAt": CREATED});
        if let Some(r) = reply {
            post["reply"] = r;
        }
        CirclePostPayload {
            post,
            media: vec![],
            created_at: CREATED.into(),
        }
    }

    #[test]
    fn post_record_roundtrip() {
        let att = vec![json!({"$type": "blob", "mimeType": "application/octet-stream", "size": 5})];
        let rec =
            CirclePostRecord::from_sealed(&sealed(), &header(), Some(reply_json()), att.clone());
        let v = serde_json::to_value(&rec).unwrap();
        assert_eq!(v["$type"], "blue.catbird.circle.post");
        assert_eq!(
            v["authorEpochHead"]["$bytes"].as_str().map(str::len),
            Some(43)
        );
        let back: CirclePostRecord = serde_json::from_value(v).unwrap();
        assert_sealed_eq(&back.to_sealed().expect("sealed"), &sealed());
        assert_eq!(back.reply, Some(reply_json()));
        assert_eq!(back.attachments, att);
        assert_eq!(back.created_at, CREATED);

        // No reply, no attachments: both keys are omitted.
        let bare = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        let v = serde_json::to_value(&bare).unwrap();
        assert!(v.get("reply").is_none() && v.get("attachments").is_none());
        let back: CirclePostRecord = serde_json::from_value(v).unwrap();
        assert!(back.attachments.is_empty());

        // The hand-written lexicon fixture parses and re-serializes identically.
        let fixture: Value = serde_json::from_str(POST_FIXTURE).unwrap();
        let parsed: CirclePostRecord = serde_json::from_str(POST_FIXTURE).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), fixture);
        let s = parsed.to_sealed().expect("fixture sealed");
        assert_eq!(s.ciphertext.len(), 600);
    }

    #[test]
    fn post_record_rejects_bad_lengths_and_type() {
        let mut rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        rec.sig = ::labyrinth::records::Bytes::from_slice(&[0u8; 63]);
        assert!(matches!(rec.to_sealed(), Err(CircleError::Malformed(_))));
        let mut rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        rec.author_epoch_head = ::labyrinth::records::Bytes::from_slice(&[0u8; 31]);
        assert!(matches!(rec.to_sealed(), Err(CircleError::Malformed(_))));
        let mut rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        rec.type_ = "blue.catbird.circle.key".into();
        assert!(matches!(rec.to_sealed(), Err(CircleError::Malformed(_))));
    }

    #[test]
    fn consistency_passes_for_matching_record() {
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), Some(reply_json()), vec![]);
        check_record_payload_consistency(&rec, &payload_with(Some(reply_json()))).expect("ok");
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        check_record_payload_consistency(&rec, &payload_with(None)).expect("ok no reply");
    }

    #[test]
    fn consistency_rejects_rethreaded_reply() {
        let mut altered = reply_json();
        altered["parent"]["uri"] = json!("at://did:plc:evil/blue.catbird.circle.post/3kother");
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), Some(altered), vec![]);
        assert_eq!(
            check_record_payload_consistency(&rec, &payload_with(Some(reply_json()))),
            Err(CircleError::HeaderMismatch)
        );
        // Server added or removed a reply.
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), Some(reply_json()), vec![]);
        assert_eq!(
            check_record_payload_consistency(&rec, &payload_with(None)),
            Err(CircleError::HeaderMismatch)
        );
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        assert_eq!(
            check_record_payload_consistency(&rec, &payload_with(Some(reply_json()))),
            Err(CircleError::HeaderMismatch)
        );
    }

    #[test]
    fn consistency_rejects_created_at_drift() {
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        let mut p = payload_with(None);
        p.post["createdAt"] = json!("2020-01-01T00:00:00.000Z");
        assert_eq!(
            check_record_payload_consistency(&rec, &p),
            Err(CircleError::HeaderMismatch)
        );
        let mut p = payload_with(None);
        p.created_at = "2020-01-01T00:00:00.000Z".into();
        assert_eq!(
            check_record_payload_consistency(&rec, &p),
            Err(CircleError::HeaderMismatch)
        );
        let mut rec2 = rec.clone();
        rec2.created_at = "2020-01-01T00:00:00.000Z".into();
        assert_eq!(
            check_record_payload_consistency(&rec2, &payload_with(None)),
            Err(CircleError::HeaderMismatch)
        );
    }

    #[test]
    fn header_from_record_builds_header() {
        let rec = CirclePostRecord::from_sealed(&sealed(), &header(), None, vec![]);
        let h = header();
        let got = header_from_record(&rec, &h.post_uri, &h.author_did).unwrap();
        assert_eq!(
            (
                &got.circle_id,
                got.key_version,
                &got.post_uri,
                &got.author_did,
                &got.created_at
            ),
            (
                &h.circle_id,
                h.key_version,
                &h.post_uri,
                &h.author_did,
                &h.created_at
            )
        );
    }

    #[test]
    fn header_rejects_separator_chars() {
        let h = header();
        let rec = CirclePostRecord::from_sealed(&sealed(), &h, None, vec![]);
        for bad in [";", "="] {
            assert!(matches!(
                header_from_record(&rec, &format!("{}{bad}x", h.post_uri), &h.author_did),
                Err(CircleError::Malformed(_))
            ));
            assert!(matches!(
                header_from_record(&rec, &h.post_uri, &format!("did:plc:a{bad}b")),
                Err(CircleError::Malformed(_))
            ));
            let mut r = rec.clone();
            r.circle_id = format!("c{bad}d");
            assert!(matches!(
                header_from_record(&r, &h.post_uri, &h.author_did),
                Err(CircleError::Malformed(_))
            ));
            let mut r = rec.clone();
            r.created_at = format!("2026{bad}");
            assert!(matches!(
                header_from_record(&r, &h.post_uri, &h.author_did),
                Err(CircleError::Malformed(_))
            ));
        }
    }
}
