//! Circle post seal and open (spec §4.1 postKey, §4.2 `blue.catbird.circle.post`).
//!
//! Each post is encrypted under its own key, derived from the Circle key and
//! the post's URI, so one post can be disclosed for moderation without the
//! Circle key. The ciphertext is signed by the author's epoch signing key.

use ::labyrinth::aead::{decrypt_suite, encrypt, Suite};
use ::labyrinth::encoding::kdf32;
use ::labyrinth::mailbox::MailboxKeys;
use ::labyrinth::padding::{pad, unpad};
use ::labyrinth::sign::XVerifyingKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::error::CircleError;

/// Largest accepted `ciphertext` (spec §4.2: bytes ≤ 64 KiB).
pub const MAX_CIPHERTEXT: usize = 65536;

const POST_KEY_INFO: &[u8] = b"catbird.circle.post.v1:";
const POST_SIG_PREFIX: &[u8] = b"catbird.circle.post.sig.v1:";

/// The only text a payload (de)serialization failure ever carries: serde
/// errors can quote the plaintext they choked on.
pub const PAYLOAD_MALFORMED: &str = "payload malformed";

fn payload_malformed() -> CircleError {
    CircleError::Malformed(PAYLOAD_MALFORMED.into())
}

/// Collection of every encrypted Circle post.
pub const POST_COLLECTION: &str = "blue.catbird.circle.post";

/// `post_uri` must be `at://<author_did>/blue.catbird.circle.post/<rkey>`
/// with an atproto record key (1–512 of `A-Za-z0-9._:~-`, not `.`/`..`).
/// The URI is bound into the AAD and the post key, so any other form would
/// let one ciphertext be addressed by a URI that is not where it lives.
pub fn validate_post_uri(post_uri: &str, author_did: &str) -> Result<(), CircleError> {
    let bad = || {
        CircleError::Malformed(format!(
            "post uri must be at://<author did>/{POST_COLLECTION}/<rkey>"
        ))
    };
    if !author_did.starts_with("did:") {
        return Err(bad());
    }
    let rkey = post_uri
        .strip_prefix("at://")
        .and_then(|r| r.strip_prefix(author_did))
        .and_then(|r| r.strip_prefix('/'))
        .and_then(|r| r.strip_prefix(POST_COLLECTION))
        .and_then(|r| r.strip_prefix('/'))
        .ok_or_else(bad)?;
    let rkey_ok = (1..=512).contains(&rkey.len())
        && rkey != "."
        && rkey != ".."
        && rkey
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:~-".contains(&b));
    if rkey_ok {
        Ok(())
    } else {
        Err(bad())
    }
}

/// `createdAt` must be an RFC 3339 datetime (it is bound into the AAD and
/// readers parse it to check the author's device was not yet revoked).
fn validate_created_at(created_at: &str) -> Result<(), CircleError> {
    ::labyrinth::records::ms_from_datetime(created_at)
        .map(|_| ())
        .map_err(|_| CircleError::Malformed("createdAt is not an RFC 3339 datetime".into()))
}

/// Decryption key and integrity data for one encrypted media blob.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct CircleMediaKey {
    pub cid: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub sha256: String,
    pub mime_type: String,
    pub alt: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// The inner payload, serialized as JSON before padding and encryption.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct CirclePostPayload {
    /// An `app.bsky.feed.post` record minus blob refs.
    pub post: serde_json::Value,
    pub media: Vec<CircleMediaKey>,
    pub created_at: String,
}

/// The cleartext fields of a `blue.catbird.circle.post` record, bound into the AAD.
pub struct CirclePostHeader {
    pub circle_id: String,
    pub key_version: u64,
    pub post_uri: String,
    pub author_did: String,
    pub created_at: String,
}

/// The sealed fields of a `blue.catbird.circle.post` record.
pub struct SealedPost {
    /// `suite (0x02) || nonce || ct || tag`.
    pub ciphertext: Vec<u8>,
    /// Author signature over `"catbird.circle.post.sig.v1:" || ciphertext`.
    pub sig: [u8; 64],
    pub author_epoch_head: [u8; 32],
}

/// `HKDF-SHA256(circle_key, salt = circle_id, info = "catbird.circle.post.v1:" || post_uri)`.
pub fn derive_post_key(circle_key: &[u8; 32], circle_id: &str, post_uri: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(POST_KEY_INFO.len() + post_uri.len());
    info.extend_from_slice(POST_KEY_INFO);
    info.extend_from_slice(post_uri.as_bytes());
    kdf32(circle_key, Some(circle_id.as_bytes()), &info)
}

/// The post AEAD's associated data (spec §4.2).
pub fn post_aad(h: &CirclePostHeader) -> Vec<u8> {
    format!(
        "catbird.circle.post.v1:circle_id={};key_version={};uri={};author={};created_at={}",
        h.circle_id, h.key_version, h.post_uri, h.author_did, h.created_at,
    )
    .into_bytes()
}

fn sig_message(ciphertext: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(POST_SIG_PREFIX.len() + ciphertext.len());
    msg.extend_from_slice(POST_SIG_PREFIX);
    msg.extend_from_slice(ciphertext);
    msg
}

fn oversize(len: usize) -> CircleError {
    CircleError::Malformed(format!("ciphertext {len} bytes > {MAX_CIPHERTEXT}"))
}

/// Pad, encrypt under the post key, and sign as `author`.
///
/// Fails with `Malformed` if the post URI is not a Circle post in the
/// author's repo ([`validate_post_uri`]), `createdAt` is not RFC 3339, or the
/// sealed ciphertext exceeds [`MAX_CIPHERTEXT`].
/// `author_epoch_head` is copied to the result unchanged.
pub fn seal_post(
    payload: &CirclePostPayload,
    h: &CirclePostHeader,
    circle_key: &[u8; 32],
    author: &MailboxKeys,
    author_epoch_head: [u8; 32],
) -> Result<SealedPost, CircleError> {
    validate_post_uri(&h.post_uri, &h.author_did)?;
    validate_created_at(&h.created_at)?;
    let post_key = Zeroizing::new(derive_post_key(circle_key, &h.circle_id, &h.post_uri));
    let json = Zeroizing::new(serde_json::to_vec(payload).map_err(|_| payload_malformed())?);
    let padded = Zeroizing::new(pad(&json));
    let ciphertext = encrypt(Suite::DndkGcm, &post_key, &post_aad(h), &padded)
        .map_err(|e| CircleError::Crypto(e.to_string()))?;
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(oversize(ciphertext.len()));
    }
    let sig = author
        .sig_secret
        .sign(&sig_message(&ciphertext))
        .map_err(|e| CircleError::Crypto(e.to_string()))?;
    Ok(SealedPost {
        ciphertext,
        sig,
        author_epoch_head,
    })
}

/// Verify and decrypt a post with the Circle key.
///
/// Errors: `Malformed` for a post URI that fails [`validate_post_uri`], an
/// oversize ciphertext, a suite byte other than
/// DNDK-GCM, bad padding or bad JSON (always the fixed [`PAYLOAD_MALFORMED`]
/// text, never serde detail); `BadSignature` if the author signature
/// fails; `Crypto` if the AEAD tag fails, which means either the wrong key or
/// a header that differs from the one sealed (the header is in the AAD; the
/// two cases are indistinguishable); `HeaderMismatch` if the decrypted
/// payload's `created_at` differs from the header's.
pub fn open_post(
    sealed: &SealedPost,
    h: &CirclePostHeader,
    circle_key: &[u8; 32],
    author_sig: &XVerifyingKey,
) -> Result<CirclePostPayload, CircleError> {
    let post_key = Zeroizing::new(derive_post_key(circle_key, &h.circle_id, &h.post_uri));
    open_post_with_post_key(sealed, h, &post_key, author_sig)
}

/// [`open_post`] with an already-derived post key (moderation disclosure path).
pub fn open_post_with_post_key(
    sealed: &SealedPost,
    h: &CirclePostHeader,
    post_key: &[u8; 32],
    author_sig: &XVerifyingKey,
) -> Result<CirclePostPayload, CircleError> {
    validate_post_uri(&h.post_uri, &h.author_did)?;
    if sealed.ciphertext.len() > MAX_CIPHERTEXT {
        return Err(oversize(sealed.ciphertext.len()));
    }
    author_sig
        .verify(&sig_message(&sealed.ciphertext), &sealed.sig)
        .map_err(|_| CircleError::BadSignature)?;
    match sealed.ciphertext.first() {
        Some(&b) if b == Suite::DndkGcm as u8 => {}
        _ => {
            return Err(CircleError::Malformed(
                "ciphertext suite is not DNDK-GCM".into(),
            ))
        }
    }
    let padded = Zeroizing::new(
        decrypt_suite(Suite::DndkGcm, post_key, &post_aad(h), &sealed.ciphertext)
            .map_err(|e| CircleError::Crypto(e.to_string()))?,
    );
    let json = Zeroizing::new(unpad(&padded).map_err(|_| payload_malformed())?);
    let payload: CirclePostPayload =
        serde_json::from_slice(&json).map_err(|_| payload_malformed())?;
    if payload.created_at != h.created_at {
        return Err(CircleError::HeaderMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::labyrinth::aead::{encrypt, Suite};
    use ::labyrinth::mailbox::MailboxKeys;
    use ::labyrinth::padding::pad;

    const CIRCLE_ID: &str = "3kcircleid22a";
    const POST_URI: &str = "at://did:plc:author/blue.catbird.circle.post/3kpost222aa";
    const AUTHOR: &str = "did:plc:author";
    const CREATED: &str = "2026-11-07T12:00:00.000Z";

    fn random32() -> [u8; 32] {
        let mut out = [0u8; 32];
        ::labyrinth::encoding::random(&mut out).expect("rng");
        out
    }

    /// A test author: mailbox keys derived from a random epoch root.
    fn author_keys() -> MailboxKeys {
        MailboxKeys::derive(&random32(), 0)
    }

    fn header() -> CirclePostHeader {
        CirclePostHeader {
            circle_id: CIRCLE_ID.into(),
            key_version: 3,
            post_uri: POST_URI.into(),
            author_did: AUTHOR.into(),
            created_at: CREATED.into(),
        }
    }

    fn payload_with_text(text: &str) -> CirclePostPayload {
        CirclePostPayload {
            post: serde_json::json!({
                "$type": "app.bsky.feed.post",
                "text": text,
                "langs": ["en"],
                "createdAt": CREATED,
            }),
            media: vec![CircleMediaKey {
                cid: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".into(),
                key: vec![0x42; 32],
                iv: vec![0x24; 24],
                sha256: "ab".repeat(32),
                mime_type: "image/jpeg".into(),
                alt: Some("a heron".into()),
                width: Some(1200),
                height: Some(800),
            }],
            created_at: CREATED.into(),
        }
    }

    fn payload() -> CirclePostPayload {
        payload_with_text("hello circle")
    }

    /// Seal by hand with real crypto, bypassing `seal_post`, so an open-side
    /// check can be reached with a payload `seal_post` would never produce.
    fn hand_seal(
        payload: &CirclePostPayload,
        h: &CirclePostHeader,
        circle_key: &[u8; 32],
        author: &MailboxKeys,
    ) -> SealedPost {
        let post_key = derive_post_key(circle_key, &h.circle_id, &h.post_uri);
        let padded = pad(&serde_json::to_vec(payload).expect("json"));
        let ciphertext =
            encrypt(Suite::DndkGcm, &post_key, &post_aad(h), &padded).expect("encrypt");
        let mut msg = b"catbird.circle.post.sig.v1:".to_vec();
        msg.extend_from_slice(&ciphertext);
        let sig = author.sig_secret.sign(&msg).expect("sign");
        SealedPost {
            ciphertext,
            sig,
            author_epoch_head: [0x77; 32],
        }
    }

    #[test]
    fn seal_open_roundtrip_with_media() {
        let author = author_keys();
        let key = random32();
        let head = random32();
        let sealed = seal_post(&payload(), &header(), &key, &author, head).expect("seal");
        assert_eq!(sealed.author_epoch_head, head);
        assert_eq!(sealed.ciphertext[0], Suite::DndkGcm as u8);
        let opened = open_post(&sealed, &header(), &key, &author.sig_public).expect("open");
        assert_eq!(opened, payload());
        assert_eq!(opened.media.len(), 1);
        assert_eq!(opened.media[0].alt.as_deref(), Some("a heron"));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let author = author_keys();
        let key = random32();
        let mut sealed = seal_post(&payload(), &header(), &key, &author, random32()).expect("seal");
        let mid = sealed.ciphertext.len() / 2;
        sealed.ciphertext[mid] ^= 0x01;
        assert_eq!(
            open_post(&sealed, &header(), &key, &author.sig_public),
            Err(CircleError::BadSignature)
        );
    }

    #[test]
    fn open_rejects_wrong_author_key() {
        let author = author_keys();
        let other = author_keys();
        let key = random32();
        let sealed = seal_post(&payload(), &header(), &key, &author, random32()).expect("seal");
        assert_eq!(
            open_post(&sealed, &header(), &key, &other.sig_public),
            Err(CircleError::BadSignature)
        );
    }

    #[test]
    fn open_rejects_header_created_at_mismatch() {
        let author = author_keys();
        let key = random32();

        // Direction 1: sealed under header A, opened under header B that
        // differs only in `created_at`. `created_at` is in the AAD, so the
        // AEAD tag fails: `Crypto`, indistinguishable from a wrong key.
        let sealed = seal_post(&payload(), &header(), &key, &author, random32()).expect("seal");
        let mut header_b = header();
        header_b.created_at = "2026-11-07T12:00:01.000Z".into();
        assert!(matches!(
            open_post(&sealed, &header_b, &key, &author.sig_public),
            Err(CircleError::Crypto(_))
        ));

        // Direction 2: the AEAD and signature verify under the header, but
        // the inner payload's `created_at` disagrees with it.
        let mut lying = payload();
        lying.created_at = "2020-01-01T00:00:00.000Z".into();
        let sealed = hand_seal(&lying, &header(), &key, &author);
        assert_eq!(
            open_post(&sealed, &header(), &key, &author.sig_public),
            Err(CircleError::HeaderMismatch)
        );
    }

    #[test]
    fn seal_rejects_non_rfc3339_created_at() {
        for bad in [
            "yesterday",
            "2026-11-07 12:00:00",
            "2026-13-07T12:00:00Z",
            "",
        ] {
            let mut h = header();
            h.created_at = bad.into();
            let mut p = payload();
            p.created_at = bad.into();
            assert!(
                matches!(
                    seal_post(&p, &h, &random32(), &author_keys(), [0; 32]),
                    Err(CircleError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn post_uri_must_be_a_circle_post_in_the_author_repo() {
        for good in [
            POST_URI,
            "at://did:plc:author/blue.catbird.circle.post/3l2abc~x.y:z-_",
        ] {
            validate_post_uri(good, AUTHOR).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "at://did:plc:author/app.bsky.feed.post/3kpost222aa",
            "at://did:plc:other/blue.catbird.circle.post/3kpost222aa",
            "at://did:plc:authorx/blue.catbird.circle.post/3kpost222aa",
            "at://did:plc:author/blue.catbird.circle.post/",
            "at://did:plc:author/blue.catbird.circle.post/..",
            "at://did:plc:author/blue.catbird.circle.post/a/b",
            "at://did:plc:author/blue.catbird.circle.post/a b",
            "https://did:plc:author/blue.catbird.circle.post/3kpost222aa",
            "at://did:plc:author/blue.catbird.circle.post",
        ] {
            assert!(validate_post_uri(bad, AUTHOR).is_err(), "{bad}");
        }
        let author = author_keys();
        let key = random32();
        let mut h = header();
        h.post_uri = "at://did:plc:author/app.bsky.feed.post/3kpost222aa".into();
        assert!(matches!(
            seal_post(&payload(), &h, &key, &author, [0; 32]),
            Err(CircleError::Malformed(_))
        ));
        // Open refuses it too, before any crypto.
        let sealed = hand_seal(&payload(), &h, &key, &author);
        assert!(matches!(
            open_post(&sealed, &h, &key, &author.sig_public),
            Err(CircleError::Malformed(_))
        ));
    }

    #[test]
    fn open_never_echoes_decrypted_plaintext_in_errors() {
        let author = author_keys();
        let key = random32();
        let h = header();
        let post_key = derive_post_key(&key, &h.circle_id, &h.post_uri);
        let padded = pad(br#"{"post": "SENTINEL-PLAINTEXT-7731", oops"#);
        let ciphertext =
            encrypt(Suite::DndkGcm, &post_key, &post_aad(&h), &padded).expect("encrypt");
        let mut msg = POST_SIG_PREFIX.to_vec();
        msg.extend_from_slice(&ciphertext);
        let sealed = SealedPost {
            ciphertext,
            sig: author.sig_secret.sign(&msg).expect("sign"),
            author_epoch_head: random32(),
        };
        let err = open_post(&sealed, &h, &key, &author.sig_public).unwrap_err();
        assert_eq!(err, CircleError::Malformed(PAYLOAD_MALFORMED.into()));
        assert!(!format!("{err} {err:?}").contains("SENTINEL"));
    }

    #[test]
    fn open_rejects_wrong_suite_byte() {
        let author = author_keys();
        let key = random32();
        let h = header();
        // Real key, real AAD, valid signature: only the suite differs.
        let post_key = derive_post_key(&key, &h.circle_id, &h.post_uri);
        let padded = pad(&serde_json::to_vec(&payload()).expect("json"));
        let ciphertext =
            encrypt(Suite::GcmExtended, &post_key, &post_aad(&h), &padded).expect("encrypt");
        assert_eq!(ciphertext[0], Suite::GcmExtended as u8);
        let mut msg = POST_SIG_PREFIX.to_vec();
        msg.extend_from_slice(&ciphertext);
        let sealed = SealedPost {
            ciphertext,
            sig: author.sig_secret.sign(&msg).expect("sign"),
            author_epoch_head: random32(),
        };
        assert!(matches!(
            open_post(&sealed, &h, &key, &author.sig_public),
            Err(CircleError::Malformed(_))
        ));
    }

    #[test]
    fn open_rejects_wrong_circle_key() {
        let author = author_keys();
        let sealed =
            seal_post(&payload(), &header(), &random32(), &author, random32()).expect("seal");
        assert!(matches!(
            open_post(&sealed, &header(), &random32(), &author.sig_public),
            Err(CircleError::Crypto(_))
        ));
    }

    #[test]
    fn post_key_differs_per_uri() {
        let key = random32();
        let a = derive_post_key(&key, CIRCLE_ID, POST_URI);
        let b = derive_post_key(
            &key,
            CIRCLE_ID,
            "at://did:plc:author/blue.catbird.circle.post/3kpost333bb",
        );
        let c = derive_post_key(&key, "3kothercircle", POST_URI);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, key);
        assert_eq!(a, derive_post_key(&key, CIRCLE_ID, POST_URI));
    }

    #[test]
    fn open_with_post_key_matches_open_with_circle_key() {
        let author = author_keys();
        let key = random32();
        let sealed = seal_post(&payload(), &header(), &key, &author, random32()).expect("seal");
        let post_key = derive_post_key(&key, CIRCLE_ID, POST_URI);
        let via_circle = open_post(&sealed, &header(), &key, &author.sig_public).expect("open");
        let via_post = open_post_with_post_key(&sealed, &header(), &post_key, &author.sig_public)
            .expect("open with post key");
        assert_eq!(via_circle, via_post);
    }

    #[test]
    fn seal_rejects_oversize() {
        let author = author_keys();
        let key = random32();
        let big = payload_with_text(&"x".repeat(70 * 1024));
        assert!(matches!(
            seal_post(&big, &header(), &key, &author, random32()),
            Err(CircleError::Malformed(_))
        ));

        // The open side refuses an oversize ciphertext before decrypting,
        // even when the author signed it.
        let sealed = hand_seal(&big, &header(), &key, &author);
        assert!(sealed.ciphertext.len() > MAX_CIPHERTEXT);
        assert!(matches!(
            open_post(&sealed, &header(), &key, &author.sig_public),
            Err(CircleError::Malformed(_))
        ));
    }

    #[test]
    fn post_aad_golden() {
        let expected: &[u8] = b"catbird.circle.post.v1:circle_id=3k2abcdefgh2a;key_version=7;\
uri=at://did:plc:x/blue.catbird.circle.post/3kp;author=did:plc:x;\
created_at=2026-11-07T00:00:00Z";
        let h = CirclePostHeader {
            circle_id: "3k2abcdefgh2a".into(),
            key_version: 7,
            post_uri: "at://did:plc:x/blue.catbird.circle.post/3kp".into(),
            author_did: "did:plc:x".into(),
            created_at: "2026-11-07T00:00:00Z".into(),
        };
        assert_eq!(post_aad(&h), expected);
    }
}
