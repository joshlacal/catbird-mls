//! Circle key wrap and open (spec §4.1, §4.2 `blue.catbird.circle.key`, D5).
//!
//! The owner wraps a 32-byte Circle key to every member's Labyrinth mailbox
//! encryption key with Hawk HPKE, authenticated to the owner's epoch auth key.
//! The wrap list is anonymous: entries carry no DID or epoch head, are padded
//! with wraps to throwaway keys up to a size bucket, and are shuffled, so a
//! member learns neither the roster nor its size beyond the bucket. Members
//! find their entry by trial decryption.

use ::labyrinth::encoding::random;
use ::labyrinth::hpke::hawk::{hawk_decrypt, hawk_enc_keygen, hawk_encrypt};
use ::labyrinth::mailbox::{EpochPublic, MailboxKeys};
use zeroize::Zeroizing;

use super::error::CircleError;

/// Allowed `recipients.length` values; the real count rounds up to one of these.
pub const BUCKETS: [usize; 7] = [8, 16, 32, 64, 128, 256, 512];

/// Maximum number of recent `OwnerMailbox` epochs trial-decrypted when opening a Circle key.
pub const CIRCLE_KEY_TRIAL_EPOCH_WINDOW: usize = 8;

/// Smallest bucket holding `real_recipients` wraps.
pub fn bucket_size(real_recipients: usize) -> Result<usize, CircleError> {
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= real_recipients)
        .ok_or(CircleError::TooManyRecipients(real_recipients))
}

/// Per-key-version inputs to a `blue.catbird.circle.key` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleKeyParams {
    pub circle_id: String,
    pub key_version: u64,
    pub space_uri: String,
    pub reason: String,
}

/// A member's mailbox epoch the caller has already verified with
/// `epoch.verify(&did, None)` and cross-checked through the directory.
/// [`wrap_circle_key`] verifies it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecipient {
    pub did: String,
    pub epoch: EpochPublic,
}

/// The `blue.catbird.circle.key` record body before serialization.
/// `recipients` are anonymous Hawk ciphertexts, padded and shuffled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleKeyRecordBody {
    pub circle_id: String,
    pub key_version: u64,
    pub sender_did: String,
    pub sender_epoch: EpochPublic,
    pub recipients: Vec<Vec<u8>>,
    pub reason: String,
    pub created_at: String,
}

/// A Circle key opened from a `blue.catbird.circle.key` record, with the
/// identity its wrap authenticated: `circle_id` and `key_version` are exactly
/// the values in the AAD the Hawk ciphertext verified under.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedCircleKey {
    pub key: [u8; 32],
    pub circle_id: String,
    pub key_version: u64,
}

impl std::fmt::Debug for OpenedCircleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedCircleKey")
            .field("key", &"<redacted>")
            .field("circle_id", &self.circle_id)
            .field("key_version", &self.key_version)
            .finish()
    }
}

/// The DID authority of an `at://<did>/...` URI, if it has one.
fn space_authority(space_uri: &str) -> Option<&str> {
    let authority = space_uri.strip_prefix("at://")?.split('/').next()?;
    authority.starts_with("did:").then_some(authority)
}

/// The caller's owner DID is only trusted when it is the Space's authority.
/// Callers run this before any directory lookup of `owner_did`.
pub fn require_owner_is_space_authority(
    space_uri: &str,
    owner_did: &str,
) -> Result<(), CircleError> {
    if space_authority(space_uri) == Some(owner_did) {
        Ok(())
    } else {
        Err(CircleError::UntrustedSender {
            reason: "owner is not the space authority".into(),
        })
    }
}

/// A fresh random 32-byte Circle key.
///
/// Panics only if the OS CSPRNG (or the installed simulation hook) fails,
/// which leaves no safe way to continue.
pub fn circle_key_generate() -> [u8; 32] {
    let mut key = [0u8; 32];
    random(&mut key).expect("CSPRNG unavailable");
    key
}

/// The Hawk AAD binding one wrap to its Circle, key version, recipient epoch,
/// sender epoch, and Space (spec §4.2).
pub fn circle_key_aad(
    circle_id: &str,
    key_version: u64,
    recipient_head: &[u8; 32],
    sender_head: &[u8; 32],
    space_uri: &str,
) -> Vec<u8> {
    format!(
        "catbird.circle.key.v1:circle_id={circle_id};key_version={key_version};recipient_epoch={};sender_epoch={};space={space_uri}",
        hex::encode(recipient_head),
        hex::encode(sender_head),
    )
    .into_bytes()
}

fn crypto(e: ::labyrinth::Error) -> CircleError {
    CircleError::Crypto(e.to_string())
}

/// Uniform index in `0..bound` (`bound >= 1`) by rejection sampling.
fn random_index(bound: usize) -> Result<usize, CircleError> {
    let bound = bound as u64;
    // Largest multiple of `bound` that fits; values at or above it are rejected.
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let mut b = [0u8; 8];
        random(&mut b).map_err(crypto)?;
        let v = u64::from_le_bytes(b);
        if v < zone {
            return Ok((v % bound) as usize);
        }
    }
}

/// Wrap `key` to every recipient and pad the list to its bucket.
///
/// Every recipient epoch is re-verified, and duplicate DIDs or epoch heads
/// are refused (each would add a real wrap the bucket hides). The owner's own epoch must be among
/// `recipients` (self-wrap, spec §4.1) so other owner devices can recover the
/// key. Padding entries are wraps of random bytes to freshly generated Hawk
/// keys whose secrets are dropped; their AAD uses a random 32-byte stand-in
/// for the recipient head, so they are structurally identical to real wraps.
/// Real and padding entries are shuffled with a CSPRNG, so position leaks
/// nothing.
pub fn wrap_circle_key(
    key: &[u8; 32],
    params: &CircleKeyParams,
    owner_did: &str,
    owner: &MailboxKeys,
    owner_epoch: &EpochPublic,
    recipients: &[VerifiedRecipient],
    created_at: &str,
) -> Result<CircleKeyRecordBody, CircleError> {
    let bucket = bucket_size(recipients.len())?;
    for r in recipients {
        r.epoch
            .verify(&r.did, None)
            .map_err(|e| CircleError::UnverifiedRecipient {
                did: r.did.clone(),
                reason: e.to_string(),
            })?;
    }
    let mut dids = std::collections::HashSet::with_capacity(recipients.len());
    let mut heads = std::collections::HashSet::with_capacity(recipients.len());
    for r in recipients {
        if !dids.insert(r.did.as_str()) || !heads.insert(r.epoch.head) {
            return Err(CircleError::Malformed("duplicate recipient".into()));
        }
    }
    if !recipients
        .iter()
        .any(|r| r.did == owner_did && r.epoch == *owner_epoch)
    {
        return Err(CircleError::Malformed("owner not in recipients".into()));
    }
    if owner.auth_public != owner_epoch.keys.auth {
        return Err(CircleError::Malformed(
            "owner keys do not match owner epoch".into(),
        ));
    }

    let aad_for = |recipient_head: &[u8; 32]| {
        circle_key_aad(
            &params.circle_id,
            params.key_version,
            recipient_head,
            &owner_epoch.head,
            &params.space_uri,
        )
    };

    let mut entries = Vec::with_capacity(bucket);
    for r in recipients {
        let aad = aad_for(&r.epoch.head);
        let ct = hawk_encrypt(
            &r.epoch.keys.enc,
            &owner.auth_secret,
            &owner.auth_public,
            &aad,
            key,
        )
        .map_err(crypto)?;
        entries.push(ct);
    }
    for _ in recipients.len()..bucket {
        let (_dummy_secret, dummy_public) = hawk_enc_keygen().map_err(crypto)?;
        let mut head = [0u8; 32];
        random(&mut head).map_err(crypto)?;
        let filler = Zeroizing::new(circle_key_generate());
        let ct = hawk_encrypt(
            &dummy_public,
            &owner.auth_secret,
            &owner.auth_public,
            &aad_for(&head),
            filler.as_slice(),
        )
        .map_err(crypto)?;
        entries.push(ct);
    }
    // Fisher-Yates.
    for i in (1..entries.len()).rev() {
        let j = random_index(i + 1)?;
        entries.swap(i, j);
    }

    Ok(CircleKeyRecordBody {
        circle_id: params.circle_id.clone(),
        key_version: params.key_version,
        sender_did: owner_did.to_string(),
        sender_epoch: owner_epoch.clone(),
        recipients: entries,
        reason: params.reason.clone(),
        created_at: created_at.to_string(),
    })
}

/// Find and open this device's wrap by trial decryption.
///
/// The record is first bound to the real owner: `body.sender_did` must equal
/// `owner_did` and `body.sender_epoch.head` must be one of
/// `owner_verified_heads`, else [`CircleError::UntrustedSender`]. The embedded
/// epoch is only self-consistent (its head, `self_sig` and attestation all
/// come from the record), so anyone who can write the record could mint one.
/// `owner_verified_heads` MUST therefore come only from owner epochs verified
/// through the directory (`CompositeDirectory` cross-check, or pinned heads),
/// never from this record. The embedded epoch is then verified too.
///
/// `recipients` longer than 512 or not exactly a bucket size is `Malformed`
/// before any decryption is attempted (bounds trial-decryption cost).
///
/// `my_keys` are the caller's mailbox keys (current epoch first, then
/// retained older ones) and `my_heads` the epoch heads to try in the AAD;
/// every key is tried with every head against every entry. Failed decryptions
/// are expected (other members' and padding entries) and skipped. Returns
/// `Ok(None)` when no entry opens.
///
/// The scan stops at the first entry that opens, so its running time reveals
/// that entry's index to a local observer; the index is a fresh random
/// shuffle position per record, so it says nothing about the roster.
///
/// Refuses (`UntrustedSender`) unless `owner_did` is the DID authority of
/// `space_uri`: the caller's owner claim is not trusted on its own.
///
/// The returned [`OpenedCircleKey`] carries `circle_id`/`key_version` as
/// authenticated by the opened wrap's AAD; callers must use those, not the
/// record's unverified fields.
pub fn open_circle_key(
    body: &CircleKeyRecordBody,
    space_uri: &str,
    owner_did: &str,
    owner_verified_heads: &[[u8; 32]],
    my_keys: &[(u64, MailboxKeys)],
    my_heads: &[[u8; 32]],
) -> Result<Option<OpenedCircleKey>, CircleError> {
    require_owner_is_space_authority(space_uri, owner_did)?;
    if body.sender_did != owner_did {
        return Err(CircleError::UntrustedSender {
            reason: "sender is not the circle owner".into(),
        });
    }
    if !owner_verified_heads.contains(&body.sender_epoch.head) {
        return Err(CircleError::UntrustedSender {
            reason: "sender epoch head is not a directory-verified owner epoch".into(),
        });
    }
    body.sender_epoch
        .verify(&body.sender_did, None)
        .map_err(|e| CircleError::UntrustedSender {
            reason: format!("sender epoch failed verification: {e}"),
        })?;
    if !BUCKETS.contains(&body.recipients.len()) {
        return Err(CircleError::Malformed(format!(
            "recipient count {} is not a bucket size",
            body.recipients.len()
        )));
    }
    let sender_auth = &body.sender_epoch.keys.auth;
    let (circle_id, key_version) = (&body.circle_id, body.key_version);
    for (_seq, keys) in my_keys {
        for head in my_heads {
            let aad = circle_key_aad(
                circle_id,
                key_version,
                head,
                &body.sender_epoch.head,
                space_uri,
            );
            for ct in &body.recipients {
                let Ok(pt) =
                    hawk_decrypt(&keys.enc_public, &keys.enc_secret, sender_auth, &aad, ct)
                else {
                    continue;
                };
                let pt = Zeroizing::new(pt);
                let key: [u8; 32] = pt
                    .as_slice()
                    .try_into()
                    .map_err(|_| CircleError::Malformed("circle key is not 32 bytes".into()))?;
                return Ok(Some(OpenedCircleKey {
                    key,
                    circle_id: circle_id.clone(),
                    key_version,
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::labyrinth::hpke::hawk::{hawk_decrypt, hawk_encrypt};
    use ::labyrinth::mailbox::{EpochPublic, MailboxKeys};
    use ::labyrinth::sign::TransportSigner;
    use ed25519_dalek::Signer as _;

    const SPACE: &str = "at://did:plc:owner/blue.catbird.circle.encrypted/3kcircle";
    const CIRCLE_ID: &str = "3kcircleid22a";

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

    /// One epoch of a test identity: the root (so keys can be re-derived) and
    /// its signed public record.
    struct TestEpoch {
        root: [u8; 32],
        epoch: EpochPublic,
    }

    impl TestEpoch {
        fn keys(&self) -> MailboxKeys {
            MailboxKeys::derive(&self.root, self.epoch.seq)
        }
    }

    /// A signed epoch chain `0..=last_seq` for `did`, each epoch with a random root.
    fn test_chain(did: &str, last_seq: u64) -> Vec<TestEpoch> {
        let transport = TestTransport(ed25519_dalek::SigningKey::from_bytes(&random32()));
        let mut chain: Vec<TestEpoch> = Vec::new();
        for seq in 0..=last_seq {
            let root = random32();
            let keys = MailboxKeys::derive(&root, seq);
            let prev = chain.last();
            let prev_keys = prev.map(TestEpoch::keys);
            let epoch = EpochPublic::sign(
                did,
                seq,
                &keys,
                random32(),
                prev.map(|p| p.epoch.head),
                prev_keys.as_ref().map(|k| &k.sig_secret),
                &transport,
            )
            .expect("sign epoch");
            epoch
                .verify(did, prev.map(|p| &p.epoch))
                .expect("verify epoch");
            chain.push(TestEpoch { root, epoch });
        }
        chain
    }

    fn test_identity(did: &str, seq: u64) -> TestEpoch {
        test_chain(did, seq).pop().expect("non-empty chain")
    }

    fn params() -> CircleKeyParams {
        CircleKeyParams {
            circle_id: CIRCLE_ID.to_string(),
            key_version: 1,
            space_uri: SPACE.to_string(),
            reason: "created".to_string(),
        }
    }

    fn recipient(did: &str, id: &TestEpoch) -> VerifiedRecipient {
        VerifiedRecipient {
            did: did.to_string(),
            epoch: id.epoch.clone(),
        }
    }

    const OWNER: &str = "did:plc:owner";
    const MEMBERS: [&str; 3] = ["did:plc:alice", "did:plc:bob", "did:plc:carol"];

    /// Owner plus three members, wrapped. Returns (key, body, owner, members).
    fn wrap_four() -> ([u8; 32], CircleKeyRecordBody, TestEpoch, Vec<TestEpoch>) {
        let owner = test_identity(OWNER, 0);
        let members: Vec<TestEpoch> = MEMBERS.iter().map(|d| test_identity(d, 0)).collect();
        let mut recipients = vec![recipient(OWNER, &owner)];
        recipients.extend(MEMBERS.iter().zip(&members).map(|(d, m)| recipient(d, m)));
        let key = circle_key_generate();
        let body = wrap_circle_key(
            &key,
            &params(),
            OWNER,
            &owner.keys(),
            &owner.epoch,
            &recipients,
            "2026-11-07T00:00:00.000Z",
        )
        .expect("wrap");
        (key, body, owner, members)
    }

    /// Open as `id`, trusting only the real owner's directory-verified head.
    fn open_as(
        body: &CircleKeyRecordBody,
        space: &str,
        owner: &TestEpoch,
        id: &TestEpoch,
    ) -> Option<[u8; 32]> {
        try_open_as(body, space, OWNER, owner, id).expect("open does not error")
    }

    fn try_open_as(
        body: &CircleKeyRecordBody,
        space: &str,
        owner_did: &str,
        owner: &TestEpoch,
        id: &TestEpoch,
    ) -> Result<Option<[u8; 32]>, CircleError> {
        let opened = open_circle_key(
            body,
            space,
            owner_did,
            &[owner.epoch.head],
            &[(id.epoch.seq, id.keys())],
            &[id.epoch.head],
        )?;
        if let Some(o) = &opened {
            assert_eq!(
                (o.circle_id.as_str(), o.key_version),
                (body.circle_id.as_str(), body.key_version)
            );
        }
        Ok(opened.map(|o| o.key))
    }

    /// Index of `id`'s entry in `body.recipients`, by direct trial decryption.
    fn entry_index(body: &CircleKeyRecordBody, id: &TestEpoch) -> Option<usize> {
        let keys = id.keys();
        let aad = circle_key_aad(
            &body.circle_id,
            body.key_version,
            &id.epoch.head,
            &body.sender_epoch.head,
            SPACE,
        );
        body.recipients.iter().position(|ct| {
            hawk_decrypt(
                &keys.enc_public,
                &keys.enc_secret,
                &body.sender_epoch.keys.auth,
                &aad,
                ct,
            )
            .is_ok()
        })
    }

    fn wrap_with(
        owner: &TestEpoch,
        owner_keys: &MailboxKeys,
        recipients: &[VerifiedRecipient],
    ) -> Result<CircleKeyRecordBody, CircleError> {
        wrap_circle_key(
            &circle_key_generate(),
            &params(),
            OWNER,
            owner_keys,
            &owner.epoch,
            recipients,
            "2026-11-07T00:00:00.000Z",
        )
    }

    #[test]
    fn bucket_size_rounds_up_and_caps() {
        assert_eq!(bucket_size(5), Ok(8));
        assert_eq!(bucket_size(8), Ok(8));
        assert_eq!(bucket_size(9), Ok(16));
        assert_eq!(bucket_size(512), Ok(512));
        assert_eq!(bucket_size(513), Err(CircleError::TooManyRecipients(513)));
    }

    #[test]
    fn wrap_then_open_for_every_recipient() {
        let (key, body, owner, members) = wrap_four();
        assert_eq!(body.circle_id, CIRCLE_ID);
        assert_eq!(body.key_version, 1);
        assert_eq!(body.sender_did, OWNER);
        assert_eq!(body.sender_epoch, owner.epoch);
        assert_eq!(body.reason, "created");
        assert_eq!(body.created_at, "2026-11-07T00:00:00.000Z");
        assert_eq!(open_as(&body, SPACE, &owner, &owner), Some(key));
        for m in &members {
            assert_eq!(open_as(&body, SPACE, &owner, m), Some(key));
        }
    }

    #[test]
    fn open_returns_none_for_non_recipient() {
        let (_, body, owner, _) = wrap_four();
        let outsider = test_identity("did:plc:mallory", 0);
        assert_eq!(open_as(&body, SPACE, &owner, &outsider), None);
    }

    #[test]
    fn dummy_entries_do_not_break_scan() {
        let (key, body, owner, members) = wrap_four();
        assert_eq!(body.recipients.len(), 8);
        let len = body.recipients[0].len();
        assert!(
            body.recipients.iter().all(|ct| ct.len() == len),
            "entries must be uniform"
        );
        assert_eq!(open_as(&body, SPACE, &owner, &owner), Some(key));
        for m in &members {
            assert_eq!(open_as(&body, SPACE, &owner, m), Some(key));
        }
    }

    #[test]
    fn wrap_refuses_unverified_recipient() {
        let owner = test_identity(OWNER, 0);
        let alice = test_identity(MEMBERS[0], 0);
        let mut tampered = recipient(MEMBERS[0], &alice);
        tampered.epoch.self_sig[0] ^= 1;
        let err = wrap_circle_key(
            &circle_key_generate(),
            &params(),
            OWNER,
            &owner.keys(),
            &owner.epoch,
            &[recipient(OWNER, &owner), tampered],
            "2026-11-07T00:00:00.000Z",
        )
        .expect_err("tampered epoch must be refused");
        assert!(
            matches!(&err, CircleError::UnverifiedRecipient { did, .. } if did == MEMBERS[0]),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn open_refuses_owner_that_is_not_the_space_authority() {
        let (_, body, owner, members) = wrap_four();
        let foreign = "at://did:plc:mallory/blue.catbird.circle.encrypted/3kcircle";
        let err = try_open_as(&body, foreign, OWNER, &owner, &members[0]).unwrap_err();
        assert_eq!(
            err,
            CircleError::UntrustedSender {
                reason: "owner is not the space authority".into()
            }
        );
        assert!(try_open_as(&body, "not-a-uri", OWNER, &owner, &members[0]).is_err());
    }

    /// The owner check reads the Space authority through the shared strict Space URI parser:
    /// the hedged spelling names the same authority, and a URI that is not a Space URI names
    /// none.
    ///
    /// Fail-before: a hand-split `at://` prefix refused the hedged spelling and accepted any
    /// `at://<did>/...` string.
    #[test]
    fn space_authority_comes_from_the_shared_space_uri_parser() {
        for space in [
            "at://did:plc:owner/space/blue.catbird.circle.encrypted/3kcircle",
            "at:space/did:plc:owner/blue.catbird.circle.encrypted/3kcircle",
        ] {
            assert_eq!(
                require_owner_is_space_authority(space, OWNER),
                Ok(()),
                "{space}"
            );
        }
        for malformed in [
            "at://did:plc:owner",
            "at://did:plc:owner/space/blue.catbird.circle.encrypted",
            "at://did:plc:owner/space/blue.catbird.circle.encrypted/3kcircle?x=1",
            "at://did:plc:owner/notspace/blue.catbird.circle.encrypted/3kcircle",
            "at://did:plc:owner/space/not an nsid/3kcircle",
        ] {
            assert!(
                require_owner_is_space_authority(malformed, OWNER).is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn open_refuses_wrong_space_aad() {
        let (_, body, owner, members) = wrap_four();
        let other = "at://did:plc:owner/blue.catbird.circle.encrypted/3kother";
        assert_eq!(open_as(&body, other, &owner, &owner), None);
        assert_eq!(open_as(&body, other, &owner, &members[0]), None);
    }

    #[test]
    fn previous_epoch_keys_open_old_wrap() {
        let owner = test_identity(OWNER, 0);
        // Member epochs N = 1 and N + 1 = 2; the owner wraps to N.
        let chain = test_chain(MEMBERS[0], 2);
        let (old, new) = (&chain[1], &chain[2]);
        let key = circle_key_generate();
        let body = wrap_circle_key(
            &key,
            &params(),
            OWNER,
            &owner.keys(),
            &owner.epoch,
            &[recipient(OWNER, &owner), recipient(MEMBERS[0], old)],
            "2026-11-07T00:00:00.000Z",
        )
        .expect("wrap");
        // Current epoch alone cannot open it.
        assert_eq!(open_as(&body, SPACE, &owner, new), None);
        let opened = open_circle_key(
            &body,
            SPACE,
            OWNER,
            &[owner.epoch.head],
            &[(new.epoch.seq, new.keys()), (old.epoch.seq, old.keys())],
            &[new.epoch.head, old.epoch.head],
        )
        .expect("open");
        assert_eq!(opened.map(|o| o.key), Some(key));
    }

    #[test]
    fn open_refuses_minted_sender_epoch() {
        let real_owner = test_identity(OWNER, 0);
        // A second, fully self-consistent epoch for the owner DID.
        let minted = test_identity(OWNER, 0);
        minted
            .epoch
            .verify(OWNER, None)
            .expect("minted epoch self-verifies");
        let alice = test_identity(MEMBERS[0], 0);
        let body = wrap_with(
            &minted,
            &minted.keys(),
            &[recipient(OWNER, &minted), recipient(MEMBERS[0], &alice)],
        )
        .expect("wrap");
        let err = try_open_as(&body, SPACE, OWNER, &real_owner, &alice)
            .expect_err("minted sender epoch must be refused");
        assert!(
            matches!(err, CircleError::UntrustedSender { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn open_refuses_wrong_owner_did() {
        let (_, body, owner, members) = wrap_four();
        let err = try_open_as(&body, SPACE, "did:plc:other", &owner, &members[0])
            .expect_err("wrong owner DID must be refused");
        assert!(
            matches!(err, CircleError::UntrustedSender { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn open_refuses_tampered_sender_epoch() {
        let (_, mut body, owner, members) = wrap_four();
        body.sender_epoch.self_sig[0] ^= 1;
        let err = try_open_as(&body, SPACE, OWNER, &owner, &members[0])
            .expect_err("tampered sender epoch must be refused");
        assert!(
            matches!(&err, CircleError::UntrustedSender { reason } if reason.contains("verification")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn open_refuses_non_bucket_recipient_count() {
        let (_, mut body, owner, members) = wrap_four();
        body.recipients.pop();
        assert!(matches!(
            try_open_as(&body, SPACE, OWNER, &owner, &members[0]),
            Err(CircleError::Malformed(_))
        ));
        let (_, mut body, owner, members) = wrap_four();
        let filler = body.recipients[0].clone();
        body.recipients.resize(513, filler);
        assert!(matches!(
            try_open_as(&body, SPACE, OWNER, &owner, &members[0]),
            Err(CircleError::Malformed(_))
        ));
    }

    #[test]
    fn open_refuses_non_32_byte_plaintext() {
        let (_, mut body, owner, members) = wrap_four();
        let alice = &members[0];
        let idx = entry_index(&body, alice).expect("alice has an entry");
        let owner_keys = owner.keys();
        let aad = circle_key_aad(CIRCLE_ID, 1, &alice.epoch.head, &owner.epoch.head, SPACE);
        body.recipients[idx] = hawk_encrypt(
            &alice.epoch.keys.enc,
            &owner_keys.auth_secret,
            &owner_keys.auth_public,
            &aad,
            &[0x5a; 31],
        )
        .expect("seal 31 bytes");
        let err = try_open_as(&body, SPACE, OWNER, &owner, alice)
            .expect_err("31-byte plaintext must be refused");
        assert!(
            matches!(err, CircleError::Malformed(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn wrap_refuses_duplicate_recipient() {
        let owner = test_identity(OWNER, 0);
        let alice = test_identity(MEMBERS[0], 0);
        let err = wrap_with(
            &owner,
            &owner.keys(),
            &[
                recipient(OWNER, &owner),
                recipient(MEMBERS[0], &alice),
                recipient(MEMBERS[0], &alice),
            ],
        )
        .expect_err("duplicate must be refused");
        assert_eq!(err, CircleError::Malformed("duplicate recipient".into()));
    }

    #[test]
    fn wrap_refuses_owner_missing_from_recipients() {
        let owner = test_identity(OWNER, 0);
        let alice = test_identity(MEMBERS[0], 0);
        let err = wrap_with(&owner, &owner.keys(), &[recipient(MEMBERS[0], &alice)])
            .expect_err("owner must self-wrap");
        assert_eq!(
            err,
            CircleError::Malformed("owner not in recipients".into())
        );
    }

    #[test]
    fn wrap_refuses_owner_key_epoch_mismatch() {
        let owner = test_identity(OWNER, 0);
        let other = test_identity(OWNER, 0);
        let err = wrap_with(&owner, &other.keys(), &[recipient(OWNER, &owner)])
            .expect_err("owner keys must match owner epoch");
        assert_eq!(
            err,
            CircleError::Malformed("owner keys do not match owner epoch".into())
        );
    }

    #[test]
    fn wrap_too_many_recipients_via_wrap() {
        let owner = test_identity(OWNER, 0);
        let mut recipients = vec![recipient(OWNER, &owner)];
        for i in 0..512 {
            let did = format!("did:plc:member{i}");
            recipients.push(recipient(&did, &test_identity(&did, 0)));
        }
        assert_eq!(recipients.len(), 513);
        let err = wrap_with(&owner, &owner.keys(), &recipients).expect_err("513 > 512");
        assert_eq!(err, CircleError::TooManyRecipients(513));
    }

    #[test]
    fn shuffle_moves_owner_entry() {
        let owner = test_identity(OWNER, 0);
        let owner_keys = owner.keys();
        let indices: std::collections::HashSet<usize> = (0..32)
            .map(|_| {
                let body =
                    wrap_with(&owner, &owner_keys, &[recipient(OWNER, &owner)]).expect("wrap");
                assert_eq!(body.recipients.len(), 8);
                entry_index(&body, &owner).expect("owner entry opens")
            })
            .collect();
        assert!(indices.len() > 1, "owner entry never moved: {indices:?}");
    }

    #[test]
    fn circle_key_aad_golden() {
        let expected: &[u8] = b"catbird.circle.key.v1:circle_id=3k2abcdefgh2a;key_version=7;\
recipient_epoch=1111111111111111111111111111111111111111111111111111111111111111;\
sender_epoch=2222222222222222222222222222222222222222222222222222222222222222;\
space=at://did:plc:x/space/blue.catbird.circle.encrypted/abc";
        assert_eq!(
            circle_key_aad(
                "3k2abcdefgh2a",
                7,
                &[0x11; 32],
                &[0x22; 32],
                "at://did:plc:x/space/blue.catbird.circle.encrypted/abc",
            ),
            expected
        );
    }
}
