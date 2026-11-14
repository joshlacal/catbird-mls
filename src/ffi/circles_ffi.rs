//! UniFFI surface for E2EE Circles (spec `docs/superpowers/specs/2026-11-07-e2ee-circles-design.md`).
//!
//! Records cross the FFI as JSON strings and keys as `Vec<u8>`. The only
//! secret that ever crosses is the Circle key itself, which the caller owns;
//! mailbox keys stay inside the [`LabyrinthSession`].
//!
//! Trust anchors, never taken from the record being opened:
//! - a key record's sender epoch must chain to the owner's latest epoch as
//!   the directory verifies it ([`LabyrinthSession::verify_peer_epoch_chain`]);
//! - a post's author epoch must verify and be attested by one of the author's
//!   chat devices that was not yet revoked at the post's (AAD-bound)
//!   `createdAt` (`[CB-18]`/`[CB-27]`, [`LabyrinthSession::check_peer_epoch_attested`]
//!   with `VouchAt::SenderClaim`).
//!
//! The `CatbirdMlsClient` methods open a session per call and delegate to the
//! `*_for_session` functions, which tests drive directly.

use labyrinth::mailbox::EpochPublic;
use labyrinth::records::{EpochPublicDef, MailboxKeysRecord};
use labyrinth::store::VouchAt;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::circles::error::CircleError;
use crate::circles::keys::{
    self, CircleKeyParams, CircleKeyRecordBody, VerifiedRecipient, BUCKETS,
};
use crate::circles::post::{self, CirclePostHeader, CirclePostPayload};
use crate::circles::records::{
    check_record_payload_consistency, header_from_record, key_record_rkey, CircleKeyRecord,
    CirclePostRecord,
};
use crate::client::CatbirdMlsClient;
use crate::error::MLSError;
use crate::labyrinth::{LabyrinthSession, PeerEpochTrust};

/// Most plaintext `attachments` a post may carry (spec §4.2).
pub const MAX_ATTACHMENTS: usize = 4;

/// Inputs for wrapping a Circle key version to its members.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CircleKeyWrapRequest {
    pub circle_id: String,
    pub key_version: u64,
    pub space_uri: String,
    pub reason: String,
    /// Members other than the owner; the owner's self-wrap is always added.
    pub member_dids: Vec<String>,
    pub created_at: String,
}

/// A `blue.catbird.circle.key` record ready to write at `rkey`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CircleKeyWrapResult {
    pub record_json: String,
    pub rkey: String,
    /// Members left out of the record because their epoch failed
    /// verification or they have none (D15); `excluded_reasons[i]` explains
    /// `excluded_dids[i]`.
    pub excluded_dids: Vec<String>,
    pub excluded_reasons: Vec<String>,
}

/// An opened Circle key and the identity its wrap authenticated
/// (`circle_id`/`key_version` from the verified AAD, never from the record's
/// unauthenticated fields).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CircleKeyOpenResult {
    pub circle_key: Vec<u8>,
    pub circle_id: String,
    pub key_version: u64,
}

impl std::fmt::Debug for CircleKeyOpenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleKeyOpenResult")
            .field("circle_key", &"<redacted>")
            .field("circle_id", &self.circle_id)
            .field("key_version", &self.key_version)
            .finish()
    }
}

/// Inputs for sealing a `blue.catbird.circle.post` record as this account.
#[derive(Clone, uniffi::Record)]
pub struct CirclePostSealRequest {
    pub circle_id: String,
    pub key_version: u64,
    pub circle_key: Vec<u8>,
    pub post_uri: String,
    pub author_did: String,
    pub created_at: String,
    /// The inner `CirclePostPayload` JSON (`post`, `media`, `created_at`).
    pub payload_json: String,
    /// Plaintext `replyRef`; must equal the payload post's `reply`.
    pub reply_json: Option<String>,
    /// Plaintext `$type: blob` refs (at most [`MAX_ATTACHMENTS`]).
    pub attachments_json: Vec<String>,
}

/// Inputs for opening a stored `blue.catbird.circle.post` record.
///
/// Raw-bytes contract: `record_json` is the record's raw canonical JSON as
/// fetched from the PDS / AppView, passed through untouched. Re-encoding it
/// through another codec (e.g. Petrel's typed models) injects nested `$type`
/// fields and changes the bytes, which breaks the AAD/signature checks.
#[derive(Clone, uniffi::Record)]
pub struct CirclePostOpenRequest {
    pub record_json: String,
    /// The URI the record was read from (bound into the AAD).
    pub post_uri: String,
    /// The repo the record was read from (bound into the AAD).
    pub author_did: String,
    pub circle_key: Vec<u8>,
    /// The author's `mailboxKeys` record (or bare `epochPublic`) whose head
    /// is the record's `authorEpochHead`, fetched by the caller.
    pub author_epoch_json: String,
}

/// Every Circle failure, typed for the caller's UI. `reason` is short
/// diagnostic text (an error code or fixed message, never payload bytes) safe
/// to log; callers branch on the variant, not the text.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CircleFfiError {
    /// Authentic-looking input that does not open for this key: AEAD tag,
    /// signature, or wrap failure.
    #[error("not openable: {reason}")]
    NotOpenable { reason: String },
    /// The sender/author or its epoch chain failed verification
    /// (`UntrustedSender`, owner head, directory fork or rollback).
    #[error("untrusted: {reason}")]
    Untrusted { reason: String },
    /// Record, request or payload shape is invalid.
    #[error("malformed: {reason}")]
    Malformed { reason: String },
    /// I/O, directory reachability, session or lock state; may succeed later.
    #[error("unavailable: {reason}")]
    Unavailable { reason: String },
}

fn malformed(reason: impl Into<String>) -> CircleFfiError {
    CircleFfiError::Malformed {
        reason: reason.into(),
    }
}

fn unavailable(reason: impl Into<String>) -> CircleFfiError {
    CircleFfiError::Unavailable {
        reason: reason.into(),
    }
}

impl From<CircleError> for CircleFfiError {
    fn from(e: CircleError) -> Self {
        let reason = e.to_string();
        match e {
            CircleError::BadSignature | CircleError::Crypto(_) => {
                CircleFfiError::NotOpenable { reason }
            }
            CircleError::UntrustedSender { .. } | CircleError::UnverifiedRecipient { .. } => {
                CircleFfiError::Untrusted { reason }
            }
            CircleError::Malformed(_)
            | CircleError::HeaderMismatch
            | CircleError::TooManyRecipients(_) => CircleFfiError::Malformed { reason },
        }
    }
}

impl From<MLSError> for CircleFfiError {
    fn from(e: MLSError) -> Self {
        match e {
            MLSError::InvalidInput { .. } => malformed(e.to_string()),
            other => unavailable(other.to_string()),
        }
    }
}

/// Session errors arrive as `OrchestratorError`. Trust verdicts on a peer
/// (owner/author chain, attestation) are already returned typed as
/// `PeerEpochTrust::Untrusted`; what is left is classified by labyrinth's
/// fixed `Display` prefixes only ([`crate::labyrinth::is_trust_failure_text`]),
/// never by the free text of a remote/backend error. Everything else,
/// including `DirectoryIncomplete`, is `Unavailable`.
impl From<crate::orchestrator::error::OrchestratorError> for CircleFfiError {
    fn from(e: crate::orchestrator::error::OrchestratorError) -> Self {
        use crate::orchestrator::error::OrchestratorError;
        let reason = e.to_string();
        match &e {
            OrchestratorError::Api(m) if crate::labyrinth::is_trust_failure_text(m) => {
                CircleFfiError::Untrusted { reason }
            }
            _ => CircleFfiError::Unavailable { reason },
        }
    }
}

fn untrusted(reason: String) -> CircleFfiError {
    CircleError::UntrustedSender { reason }.into()
}

fn key32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, CircleFfiError> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| malformed(format!("circle key must be 32 bytes, got {}", bytes.len())))?;
    Ok(Zeroizing::new(key))
}

fn parse_json<T: serde::de::DeserializeOwned>(what: &str, json: &str) -> Result<T, CircleFfiError> {
    serde_json::from_str(json).map_err(|e| CircleError::Malformed(format!("{what}: {e}")).into())
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, CircleFfiError> {
    // A serde error could quote the (plaintext) value being serialized.
    serde_json::to_string(value).map_err(|_| malformed(crate::circles::post::PAYLOAD_MALFORMED))
}

/// A fresh random 32-byte Circle key.
pub fn circle_key_generate_bytes() -> Vec<u8> {
    keys::circle_key_generate().to_vec()
}

/// The per-post key (moderation disclosure): `HKDF(circle_key, circle_id, post_uri)`.
pub fn circle_post_key_bytes(
    circle_key: Vec<u8>,
    circle_id: String,
    post_uri: String,
) -> Result<Vec<u8>, CircleFfiError> {
    let key = key32(&circle_key)?;
    Ok(post::derive_post_key(&key, &circle_id, &post_uri).to_vec())
}

/// Members' verified epochs (owner excluded) plus this account's own.
struct ResolvedMembers {
    roster: Vec<(String, EpochPublic)>,
    own: EpochPublic,
    /// `(did, reason)` for members left out.
    excluded: Vec<(String, String)>,
}

/// [`LabyrinthSession::resolve_roster_report`] that tolerates per-member
/// directory faults (D15): when the batched call fails, this account's own
/// epoch is resolved alone (its failure aborts, since nothing could be
/// wrapped), then each member separately, and a member whose resolution
/// fails (e.g. a newer epoch that does not link to its pin, or a missing
/// intermediate epoch) is excluded with the error text.
async fn resolve_members(
    session: &mut LabyrinthSession,
    members: &[&str],
) -> Result<ResolvedMembers, CircleFfiError> {
    let me = session.did().to_owned();
    let split = |roster: Vec<(String, EpochPublic)>| {
        let mut own = None;
        let mut others = Vec::new();
        for (did, epoch) in roster {
            if did == me {
                own = Some(epoch);
            } else {
                others.push((did, epoch));
            }
        }
        (own, others)
    };
    let missing_own = || unavailable("own latest epoch missing from roster");
    if let Ok(r) = session.resolve_roster_report(members).await {
        let (own, roster) = split(r.roster);
        return Ok(ResolvedMembers {
            roster,
            own: own.ok_or_else(missing_own)?,
            excluded: r
                .excluded
                .into_iter()
                .map(|x| (x.did, x.error.to_string()))
                .collect(),
        });
    }
    let (own, _) = split(session.resolve_roster_report(&[]).await?.roster);
    let own = own.ok_or_else(missing_own)?;
    let mut out = ResolvedMembers {
        roster: Vec::new(),
        own,
        excluded: Vec::new(),
    };
    for did in members {
        match session.resolve_roster_report(&[did]).await {
            Ok(r) => {
                let (_, roster) = split(r.roster);
                out.roster.extend(roster);
                out.excluded
                    .extend(r.excluded.into_iter().map(|x| (x.did, x.error.to_string())));
            }
            Err(e) => out.excluded.push(((*did).to_owned(), e.to_string())),
        }
    }
    Ok(out)
}

/// Wrap `circle_key` to the owner (this account) and every member whose
/// latest epoch passes Labyrinth's roster checks (`[CB-18]`, `[CB-29]`).
/// Members that fail, or have no epoch, are reported, not wrapped (D15).
pub async fn wrap_circle_key_for_session(
    session: &mut LabyrinthSession,
    req: CircleKeyWrapRequest,
    circle_key: Vec<u8>,
) -> Result<CircleKeyWrapResult, CircleFfiError> {
    let key = key32(&circle_key)?;
    if req.key_version < 1 {
        return Err(malformed("key_version must be at least 1"));
    }
    let me = session.did().to_owned();
    let mut members: Vec<&str> = req
        .member_dids
        .iter()
        .map(String::as_str)
        .filter(|d| *d != me)
        .collect();
    members.sort_unstable();
    members.dedup();

    let resolved = resolve_members(session, &members).await?;
    let mut excluded_dids = Vec::new();
    let mut excluded_reasons = Vec::new();
    for (did, reason) in resolved.excluded {
        excluded_dids.push(did);
        excluded_reasons.push(reason);
    }
    for did in &members {
        let present =
            resolved.roster.iter().any(|(d, _)| d == did) || excluded_dids.iter().any(|d| d == did);
        if !present {
            excluded_dids.push((*did).to_owned());
            excluded_reasons.push("no published Labyrinth epoch".to_owned());
        }
    }

    let owner_epoch = resolved.own;
    let recipients: Vec<VerifiedRecipient> = resolved
        .roster
        .into_iter()
        .map(|(did, epoch)| VerifiedRecipient { did, epoch })
        .chain(std::iter::once(VerifiedRecipient {
            did: me.clone(),
            epoch: owner_epoch.clone(),
        }))
        .collect();

    let mine = session.mailbox_keys_current_and_previous().await?;
    let (_, _, owner_keys) = mine
        .iter()
        .find(|(seq, head, _)| *seq == owner_epoch.seq && *head == owner_epoch.head)
        .ok_or_else(|| unavailable("own mailbox keys for the latest epoch are unavailable"))?;

    let params = CircleKeyParams {
        circle_id: req.circle_id,
        key_version: req.key_version,
        space_uri: req.space_uri,
        reason: req.reason,
    };
    let body = keys::wrap_circle_key(
        &key,
        &params,
        &me,
        owner_keys,
        &owner_epoch,
        &recipients,
        &req.created_at,
    )?;
    Ok(CircleKeyWrapResult {
        record_json: to_json(&CircleKeyRecord::from_body(&body))?,
        rkey: key_record_rkey(body.key_version),
        excluded_dids,
        excluded_reasons,
    })
}

/// Open this account's wrap in a `blue.catbird.circle.key` record of the
/// Circle owned by `owner_did`. `Ok(None)` if no wrap is addressed to this
/// account's current or previous epoch. The result's `circle_id` and
/// `key_version` are the authenticated ones (M3); use them, not the record's.
///
/// Raw-bytes contract: `record_json` is the record's raw canonical JSON as
/// fetched from the PDS / AppView (`getKeys`). Do not re-encode it through
/// another codec (e.g. Petrel): that injects nested `$type` fields into the
/// sender epoch, which this parser refuses and which would break the AAD.
pub async fn open_circle_key_for_session(
    session: &mut LabyrinthSession,
    record_json: &str,
    space_uri: &str,
    owner_did: &str,
) -> Result<Option<CircleKeyOpenResult>, CircleFfiError> {
    // Before any directory fetch or pin: a caller-supplied owner that is not
    // the Space's authority must not trigger lookups of that DID.
    keys::require_owner_is_space_authority(space_uri, owner_did)?;
    let record: CircleKeyRecord = parse_json("circle key record", record_json)?;
    let body: CircleKeyRecordBody = record.to_body()?;
    if body.key_version < 1 {
        return Err(CircleError::Malformed("key_version must be at least 1".into()).into());
    }
    if !BUCKETS.contains(&body.recipients.len()) {
        return Err(CircleError::Malformed(format!(
            "recipient count {} is not a bucket size",
            body.recipients.len()
        ))
        .into());
    }
    if body.sender_did != owner_did {
        return Err(untrusted("sender is not the circle owner".into()));
    }
    match session
        .verify_peer_epoch_chain(owner_did, &body.sender_epoch)
        .await?
    {
        PeerEpochTrust::Verified => {}
        PeerEpochTrust::Untrusted(reason) => return Err(untrusted(reason)),
    }
    let owner_verified_heads = [body.sender_epoch.head];

    let mine = session
        .recent_mailbox_keys(keys::CIRCLE_KEY_TRIAL_EPOCH_WINDOW)
        .await?;
    let my_heads: Vec<[u8; 32]> = mine.iter().map(|(_, head, _)| *head).collect();
    let my_keys: Vec<_> = mine.into_iter().map(|(seq, _, k)| (seq, k)).collect();
    let opened = keys::open_circle_key(
        &body,
        space_uri,
        owner_did,
        &owner_verified_heads,
        &my_keys,
        &my_heads,
    )?;
    Ok(opened.map(|o| CircleKeyOpenResult {
        circle_key: Zeroizing::new(o.key).to_vec(),
        circle_id: o.circle_id,
        key_version: o.key_version,
    }))
}

/// Seal a post as this account under its latest epoch. Returns the
/// `blue.catbird.circle.post` record JSON.
pub async fn seal_circle_post_for_session(
    session: &mut LabyrinthSession,
    req: CirclePostSealRequest,
) -> Result<String, CircleFfiError> {
    if req.author_did != session.did() {
        return Err(malformed("author_did is not this account"));
    }
    if req.attachments_json.len() > MAX_ATTACHMENTS {
        return Err(malformed(format!(
            "{} attachments > {MAX_ATTACHMENTS}",
            req.attachments_json.len()
        )));
    }
    let key = key32(&req.circle_key)?;
    // The payload is plaintext: a serde error must not quote it.
    let payload: CirclePostPayload = serde_json::from_str(&req.payload_json)
        .map_err(|_| malformed(crate::circles::post::PAYLOAD_MALFORMED))?;
    let reply: Option<Value> = req
        .reply_json
        .as_deref()
        .map(|r| parse_json("reply", r))
        .transpose()?;
    let attachments: Vec<Value> = req
        .attachments_json
        .iter()
        .map(|a| parse_json("attachment", a))
        .collect::<Result<_, _>>()?;
    let header = CirclePostHeader {
        circle_id: req.circle_id,
        key_version: req.key_version,
        post_uri: req.post_uri,
        author_did: req.author_did,
        created_at: req.created_at,
    };

    let latest = session.latest_public()?;
    let mine = session.mailbox_keys_current_and_previous().await?;
    let (_, _, author_keys) = mine
        .iter()
        .find(|(seq, head, _)| *seq == latest.seq && *head == latest.head)
        .ok_or_else(|| unavailable("own mailbox keys for the latest epoch are unavailable"))?;

    // Build the record first so a header the AAD would bind (separators)
    // or a reply/createdAt that disagrees with the payload fails here, not
    // on every reader.
    let sealed = post::seal_post(&payload, &header, &key, author_keys, latest.head)?;
    let record = CirclePostRecord::from_sealed(&sealed, &header, reply, attachments);
    header_from_record(&record, &header.post_uri, &header.author_did)?;
    check_record_payload_consistency(&record, &payload)?;
    to_json(&record)
}

fn parse_author_epoch(json: &str) -> Result<EpochPublic, CircleFfiError> {
    let parsed = serde_json::from_str::<MailboxKeysRecord>(json)
        .map_err(|e| e.to_string())
        .and_then(|r| r.to_public().map_err(|e| e.to_string()))
        .or_else(|_| {
            serde_json::from_str::<EpochPublicDef>(json)
                .map_err(|e| e.to_string())
                .and_then(|d| d.to_public().map_err(|e| e.to_string()))
        });
    parsed.map_err(|e| CircleError::Malformed(format!("author epoch: {e}")).into())
}

/// Verify and decrypt a stored post. Returns the inner payload JSON.
///
/// Raw-bytes contract: see [`CirclePostOpenRequest`]; pass the record's raw
/// canonical JSON bytes as fetched, never a re-encoded copy.
pub async fn open_circle_post_for_session(
    session: &mut LabyrinthSession,
    req: CirclePostOpenRequest,
) -> Result<String, CircleFfiError> {
    let key = key32(&req.circle_key)?;
    let record: CirclePostRecord = parse_json("circle post record", &req.record_json)?;
    if record.attachments.len() > MAX_ATTACHMENTS {
        return Err(CircleError::Malformed(format!(
            "{} attachments > {MAX_ATTACHMENTS}",
            record.attachments.len()
        ))
        .into());
    }
    let sealed = record.to_sealed()?;
    let header = header_from_record(&record, &req.post_uri, &req.author_did)?;

    let epoch = parse_author_epoch(&req.author_epoch_json)?;
    if epoch.head != sealed.author_epoch_head {
        return Err(untrusted(
            "author epoch head does not match the record's authorEpochHead".into(),
        ));
    }
    // `createdAt` is bound into the AAD, so a server cannot shift it.
    let created_ms = labyrinth::records::ms_from_datetime(&header.created_at)
        .map_err(|e| CircleError::Malformed(format!("createdAt: {e}")))?;
    match session
        .check_peer_epoch_attested(&req.author_did, &epoch, VouchAt::SenderClaim(created_ms))
        .await?
    {
        PeerEpochTrust::Verified => {}
        PeerEpochTrust::Untrusted(reason) => return Err(untrusted(reason)),
    }

    let payload = post::open_post(&sealed, &header, &key, &epoch.keys.sig)?;
    check_record_payload_consistency(&record, &payload)?;
    to_json(&payload)
}

impl CatbirdMlsClient {
    /// [`circle_key_generate_bytes`].
    pub fn circle_key_generate(&self) -> Vec<u8> {
        circle_key_generate_bytes()
    }

    /// [`wrap_circle_key_for_session`] on this account's Labyrinth session.
    pub fn circle_key_wrap(
        &self,
        req: CircleKeyWrapRequest,
        circle_key: Vec<u8>,
    ) -> Result<CircleKeyWrapResult, CircleFfiError> {
        self.circles_run(async {
            let mut session = self.circles_open_session().await?;
            wrap_circle_key_for_session(&mut session, req, circle_key).await
        })?
    }

    /// [`open_circle_key_for_session`] on this account's Labyrinth session.
    /// `record_json` must be the raw canonical record JSON as fetched (not
    /// re-encoded through Petrel; nested `$type` breaks the AAD).
    pub fn circle_key_open(
        &self,
        record_json: String,
        space_uri: String,
        owner_did: String,
    ) -> Result<Option<CircleKeyOpenResult>, CircleFfiError> {
        // Refuse a bogus owner before opening the session (no network at all).
        keys::require_owner_is_space_authority(&space_uri, &owner_did)?;
        self.circles_run(async {
            let mut session = self.circles_open_session().await?;
            open_circle_key_for_session(&mut session, &record_json, &space_uri, &owner_did).await
        })?
    }

    /// [`seal_circle_post_for_session`] on this account's Labyrinth session.
    pub fn circle_post_seal(&self, req: CirclePostSealRequest) -> Result<String, CircleFfiError> {
        self.circles_run(async {
            let mut session = self.circles_open_session().await?;
            seal_circle_post_for_session(&mut session, req).await
        })?
    }

    /// [`open_circle_post_for_session`] on this account's Labyrinth session.
    /// `req.record_json` must be the raw canonical record JSON as fetched.
    pub fn circle_post_open(&self, req: CirclePostOpenRequest) -> Result<String, CircleFfiError> {
        self.circles_run(async {
            let mut session = self.circles_open_session().await?;
            open_circle_post_for_session(&mut session, req).await
        })?
    }

    /// [`circle_post_key_bytes`].
    pub fn circle_post_key(
        &self,
        circle_key: Vec<u8>,
        circle_id: String,
        post_uri: String,
    ) -> Result<Vec<u8>, CircleFfiError> {
        circle_post_key_bytes(circle_key, circle_id, post_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_key_rejects_short_key() {
        let err = circle_post_key_bytes(vec![1; 31], "c".into(), "u".into()).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn author_epoch_parser_rejects_garbage() {
        assert!(parse_author_epoch("{}").is_err());
        assert!(parse_author_epoch("not json").is_err());
    }

    fn ffi(e: labyrinth::Error) -> CircleFfiError {
        crate::labyrinth::map_error(e).into()
    }

    /// Every labyrinth variant: the typed and the rendered-text classifiers
    /// agree, so `map_error` text never classifies differently from the type.
    #[test]
    fn typed_and_text_trust_classification_agree() {
        use labyrinth::Error as E;
        let all = [
            E::Decrypt,
            E::BadSignature,
            E::BadPublicKey,
            E::Malformed("directory epoch gap too long"),
            E::Malformed("directory epoch under the wrong number"),
            E::Malformed("sequencer receipt authority or key_id mismatch"),
            E::Malformed("record shape"),
            E::NotEpochMember,
            E::BadRecoveryCode,
            E::DeviceTampered,
            E::Unsupported(9),
            E::Conflict,
            E::PendingWrites,
            E::Forbidden,
            E::Backend("x".into()),
            E::EpochTruncated {
                published: 3,
                reached: 2,
            },
            E::EpochRollback {
                pinned: 3,
                offered: 2,
            },
            E::DirectoryFork { pds: 3, ds: 4 },
            E::DirectoryIncomplete {
                pds_present: false,
                ds_present: true,
            },
            E::Unattested,
            E::NotFound("x"),
            E::NotRecipient,
            E::RosterMismatch,
            E::WrongEpoch,
            E::MekMismatch,
            E::Rng,
            E::EpochSquatted {
                seq: 12,
                reason: "bad link",
            },
            E::MemberTampered { seq: 4 },
            E::NotSupported("x"),
            E::ReceiptCommitmentMismatch,
        ];
        for e in all {
            let typed = crate::labyrinth::is_trust_failure(&e);
            let crate::orchestrator::error::OrchestratorError::Api(text) =
                crate::labyrinth::map_error(e.clone())
            else {
                continue; // BadRecoveryCode / signing failures map elsewhere
            };
            assert_eq!(
                crate::labyrinth::is_trust_failure_text(&text),
                typed,
                "{e:?} -> {text}"
            );
            let mapped = ffi(e.clone());
            assert_eq!(
                matches!(mapped, CircleFfiError::Untrusted { .. }),
                typed,
                "{e:?}"
            );
        }
    }

    #[test]
    fn listed_trust_cases_are_untrusted() {
        use labyrinth::Error as E;
        for e in [
            E::Malformed("directory epoch gap too long"),
            E::Malformed("directory epoch under the wrong number"),
            E::Malformed("sequencer receipt authority or key_id mismatch"),
            E::ReceiptCommitmentMismatch,
            E::DeviceTampered,
            E::Decrypt,
        ] {
            assert!(
                matches!(ffi(e.clone()), CircleFfiError::Untrusted { .. }),
                "{e:?}"
            );
        }
    }

    /// A remote 5xx whose body contains trust-sounding text stays Unavailable.
    #[test]
    fn backend_text_never_classifies_as_untrusted() {
        use labyrinth::Error as E;
        for body in [
            "mailboxKeys repo call returned HTTP 502 invalid signature",
            "invalid signature",
            "labyrinth: invalid signature",
            "peer epoch rolled back or forked: pinned epoch 1, offered 0",
            "malformed input: directory epoch gap too long",
        ] {
            let err = ffi(E::Backend(body.into()));
            assert!(
                matches!(err, CircleFfiError::Unavailable { .. }),
                "{body}: {err:?}"
            );
        }
    }

    #[test]
    fn directory_incomplete_is_unavailable() {
        let err = ffi(labyrinth::Error::DirectoryIncomplete {
            pds_present: false,
            ds_present: true,
        });
        assert!(matches!(err, CircleFfiError::Unavailable { .. }), "{err:?}");
        assert!(crate::labyrinth::is_operational_failure(
            &labyrinth::Error::DirectoryIncomplete {
                pds_present: true,
                ds_present: false
            }
        ));
    }
}
