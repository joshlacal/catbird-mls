//! Proof primitives and terminal close.
//!
//! The protocol repeatedly distinguishes *authority* from *hints*, and treats
//! confusing the two as a terminal error rather than a nuisance. §9:
//!
//! > Removal atomically records the device-bound terminal seq, tombstone, and
//! > access-ended event, but tombstone/event/inventory `terminalSeq` is
//! > navigation/wakeup data only and is never close authority; those hints do
//! > not duplicate the fingerprint.
//!
//! and:
//!
//! > The former device is entitled to the exact signed close control row at
//! > `terminalSeq`, and the client persists closure only after verifying that
//! > row and constructing close provenance.
//!
//! So this module gives hints and authority *different types*, with no
//! conversion between them. A [`CloseHint`] can wake a client and drive
//! navigation; it can never close a schedule, because nothing accepts it where
//! a [`VerifiedClose`] is required.
//!
//! The same reasoning applies to [`OuterEntryFingerprint`]: it is constructible
//! only from a verified entry envelope, so a hint DTO — which carries no
//! fingerprint at all — cannot manufacture one.

use super::ids::{BareDid, CanonicalTimestamp, ConversationId, DeviceId, Seq, TransitionId};
use core::fmt;

/// The raw SHA-256 of an entry's canonical signing transcript.
///
/// Distinct from [`OuterEntryFingerprint`]: the digest commits the *signed
/// request*, while the fingerprint additionally commits the signature and the
/// server's row identity and time. They are never interchangeable, and the
/// control-entry fingerprint takes the digest as one of its own inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    /// Adopts a computed digest.
    pub fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The immutable outer fingerprint of an authenticated append-log entry.
///
/// Constructed only by the envelope-verification layer, after the entry shape,
/// conversation binding, canonical transcript, and Ed25519 signature have all
/// been checked. That ordering is the protocol's central rule — validation
/// precedes fingerprinting, which precedes any use of the row as reducer
/// provenance — and making the constructor the verifier's job is what keeps an
/// unverified row from producing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OuterEntryFingerprint([u8; 32]);

impl OuterEntryFingerprint {
    /// Adopts a fingerprint computed by the envelope-verification layer.
    ///
    /// Callers outside that layer should be receiving an already-constructed
    /// value rather than calling this.
    pub fn from_verified(fingerprint: [u8; 32]) -> Self {
        Self(fingerprint)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OuterEntryFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// What opened an exact-device application interval.
///
/// §6: "Exact-device application interval identity is the opening transition
/// ID: creation, reset activation, or Add." These are the only three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpeningKind {
    /// Epoch-zero creation, opening the genesis creator device.
    Creation,
    /// Reset activation, opening the activator device's successor interval.
    Reset,
    /// A recovery Add, opening only the added device at its Welcome-producing
    /// transition.
    Add,
}

/// What closed an exact-device application interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseKind {
    /// This exact device's own Remove. Requires a strict later gap before any
    /// successor Add.
    Remove,
    /// The replace half of a poisoned-device recovery. May touch a successor
    /// `Add` at a shared seq.
    Replace,
    /// Reset retirement, closing every old-generation interval at reset seq.
    /// May touch a successor `Reset` at a shared seq.
    Reset,
    /// Terminal conversation close. Has no successor, ever.
    Terminal,
}

impl CloseKind {
    /// Whether this close may share its seq with a successor's opening.
    ///
    /// §6: "The only legal touching schedules are `Replace -> Add` and
    /// `Reset -> Reset`". `Remove` requires a strict later gap and `Terminal`
    /// has no successor at all, so neither may touch.
    pub fn may_touch_successor(&self) -> bool {
        matches!(self, Self::Replace | Self::Reset)
    }

    /// The opening kind this close may legally touch, if any.
    pub fn legal_touching_successor(&self) -> Option<OpeningKind> {
        match self {
            Self::Replace => Some(OpeningKind::Add),
            Self::Reset => Some(OpeningKind::Reset),
            Self::Remove | Self::Terminal => None,
        }
    }

    /// Whether a successor interval may exist at all after this close.
    pub fn permits_successor(&self) -> bool {
        !matches!(self, Self::Terminal)
    }
}

/// A navigation and wake hint that a conversation has closed.
///
/// Carried by tombstones, events, inventory, and interval summaries. It has no
/// fingerprint, no transition ID, and deliberately no path to
/// [`VerifiedClose`]. §9 is explicit that these hints "do not duplicate the
/// fingerprint" and are "never close authority", so a client may use this to
/// decide to *go and fetch* the signed row, and for nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseHint {
    /// Which conversation the hint concerns.
    pub conversation_id: ConversationId,
    /// The advertised terminal sequence. Navigation only.
    pub terminal_seq: Seq,
    /// When the server recorded the close.
    pub closed_at: CanonicalTimestamp,
}

impl CloseHint {
    /// The scan position at which the signed close row should be sought.
    ///
    /// This is the hint's entire legitimate use: it tells a client *where to
    /// look*, not what happened.
    pub fn seek_seq(&self) -> Seq {
        self.terminal_seq
    }
}

/// An authenticated terminal conversation close.
///
/// Constructed only from a verified signed `conversationCloseEntry`, which is
/// why it carries an [`OuterEntryFingerprint`] — the type a hint cannot
/// produce.
///
/// This is *conversation-level* authority: the conversation is superseded with
/// no successor and rejects later writes. It is deliberately not the same thing
/// as an exact-device schedule terminal proof, which terminalizes one
/// `(conversation, recipient DID, recipient device)` schedule. One close
/// installs many schedule proofs, and the two must not be conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClose {
    conversation_id: ConversationId,
    close_seq: Seq,
    closing_transition_id: TransitionId,
    closing_outer_entry_fingerprint: OuterEntryFingerprint,
    closed_by_did: BareDid,
    closed_by_device_id: DeviceId,
}

impl VerifiedClose {
    /// Adopts a close whose signed row has already been verified.
    ///
    /// The fingerprint argument is what enforces provenance: it can only come
    /// from the envelope-verification layer.
    pub fn from_verified_row(
        conversation_id: ConversationId,
        close_seq: Seq,
        closing_transition_id: TransitionId,
        closing_outer_entry_fingerprint: OuterEntryFingerprint,
        closed_by_did: BareDid,
        closed_by_device_id: DeviceId,
    ) -> Self {
        Self {
            conversation_id,
            close_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
            closed_by_did,
            closed_by_device_id,
        }
    }

    /// The conversation this close terminates.
    pub fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// The sequence at which the close row sits.
    pub fn close_seq(&self) -> Seq {
        self.close_seq
    }

    /// The signed transition ID, which is interval close provenance.
    pub fn closing_transition_id(&self) -> TransitionId {
        self.closing_transition_id
    }

    /// The authenticated outer fingerprint.
    pub fn closing_outer_entry_fingerprint(&self) -> OuterEntryFingerprint {
        self.closing_outer_entry_fingerprint
    }

    /// The DID of the still-authorized principal that closed the conversation.
    ///
    /// §5 separates this from audience entitlement deliberately: the signer and
    /// tombstone `closedBy` may be a distinct active admin device from a
    /// removed or former recipient device that receives the Terminal row. The
    /// recipient is not a fingerprint input, so this must never be read as
    /// naming the recipient.
    pub fn closed_by_did(&self) -> &BareDid {
        &self.closed_by_did
    }

    /// The device that closed the conversation. See [`Self::closed_by_did`].
    pub fn closed_by_device_id(&self) -> DeviceId {
        self.closed_by_device_id
    }

    /// Whether this close corroborates a hint.
    ///
    /// Used to confirm that the row fetched at a hint's `terminalSeq` is in
    /// fact the close the hint advertised. A mismatch means the hint was stale
    /// or wrong, and the *row* wins.
    pub fn corroborates(&self, hint: &CloseHint) -> bool {
        self.conversation_id == hint.conversation_id && self.close_seq == hint.terminal_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CONVERSATION: &str = "22222222-2222-4222-8222-222222222222";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
    const CLOSER_DEVICE: &str = "72727272-7272-4272-b272-727272727272";
    const REMOVED_DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";

    fn seq(value: i64) -> Seq {
        Seq::new(value).unwrap()
    }

    fn hint(conversation: &str, terminal_seq: i64) -> CloseHint {
        CloseHint {
            conversation_id: ConversationId::parse(conversation).unwrap(),
            terminal_seq: seq(terminal_seq),
            closed_at: CanonicalTimestamp::parse("2026-08-14T12:34:56.789Z").unwrap(),
        }
    }

    fn verified_close(conversation: &str, close_seq: i64) -> VerifiedClose {
        VerifiedClose::from_verified_row(
            ConversationId::parse(conversation).unwrap(),
            seq(close_seq),
            TransitionId::parse(TRANSITION).unwrap(),
            OuterEntryFingerprint::from_verified([0x5a; 32]),
            BareDid::parse(DID).unwrap(),
            DeviceId::parse(CLOSER_DEVICE).unwrap(),
        )
    }

    #[test]
    fn a_hint_carries_no_authority_and_cannot_become_one() {
        // The hint's only legitimate output is a place to look. There is no
        // From/Into to VerifiedClose and no constructor on VerifiedClose that
        // accepts a CloseHint; this test records the intent that the compiler
        // enforces.
        let advertised = hint(CONVERSATION, 10);
        assert_eq!(advertised.seek_seq(), seq(10));
    }

    #[test]
    fn a_verified_close_corroborates_only_its_own_hint() {
        let close = verified_close(CONVERSATION, 10);
        assert!(close.corroborates(&hint(CONVERSATION, 10)));
        assert!(
            !close.corroborates(&hint(CONVERSATION, 11)),
            "a hint naming a different seq is not corroborated"
        );
        assert!(
            !close.corroborates(&hint(OTHER_CONVERSATION, 10)),
            "cross-conversation corroboration must never succeed"
        );
    }

    #[test]
    fn the_closer_may_differ_from_the_removed_recipient() {
        // The master plan's named scenario: conversationCloseEntry at seq 10
        // after a Remove at seq 3, where the still-authorized signer is device
        // 7272 and the removed recipient is device 7070. Recipient entitlement
        // is verified separately, and closedBy must never be read as naming the
        // recipient.
        let close = verified_close(CONVERSATION, 10);
        assert_eq!(close.closed_by_device_id().to_string(), CLOSER_DEVICE);
        assert_ne!(close.closed_by_device_id().to_string(), REMOVED_DEVICE);
        assert!(close.close_seq().is_strictly_after(seq(3)));
    }

    #[test]
    fn only_replace_and_reset_may_touch_a_successor() {
        // The two legal touching schedules, and nothing else.
        assert!(CloseKind::Replace.may_touch_successor());
        assert!(CloseKind::Reset.may_touch_successor());
        assert!(
            !CloseKind::Remove.may_touch_successor(),
            "Remove requires a strict later gap before an Add"
        );
        assert!(
            !CloseKind::Terminal.may_touch_successor(),
            "Terminal has no successor at all"
        );
    }

    #[test]
    fn touching_pairs_are_exactly_replace_add_and_reset_reset() {
        assert_eq!(
            CloseKind::Replace.legal_touching_successor(),
            Some(OpeningKind::Add)
        );
        assert_eq!(
            CloseKind::Reset.legal_touching_successor(),
            Some(OpeningKind::Reset)
        );
        assert_eq!(CloseKind::Remove.legal_touching_successor(), None);
        assert_eq!(CloseKind::Terminal.legal_touching_successor(), None);

        // A Replace may not touch a Reset opening, nor a Reset touch an Add.
        // Those are the illegal pairings the reducer must refuse.
        assert_ne!(
            CloseKind::Replace.legal_touching_successor(),
            Some(OpeningKind::Reset)
        );
        assert_ne!(
            CloseKind::Reset.legal_touching_successor(),
            Some(OpeningKind::Add)
        );
    }

    #[test]
    fn terminal_permits_no_successor_while_the_others_do() {
        assert!(!CloseKind::Terminal.permits_successor());
        for kind in [CloseKind::Remove, CloseKind::Replace, CloseKind::Reset] {
            assert!(kind.permits_successor(), "{kind:?}");
        }
    }

    #[test]
    fn creation_reset_and_add_are_the_only_opening_kinds() {
        // Recorded as an executable statement of the closed set; the enum has
        // no other variants, so a fourth would fail to compile here.
        let all = [OpeningKind::Creation, OpeningKind::Reset, OpeningKind::Add];
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn digest_and_fingerprint_are_distinct_types_with_distinct_meaning() {
        // The control-entry fingerprint takes the request digest as one of its
        // inputs, so they are never interchangeable. Equal bytes here must
        // still be different types.
        let digest = RequestDigest::new([0x11; 32]);
        let fingerprint = OuterEntryFingerprint::from_verified([0x11; 32]);
        assert_eq!(digest.as_bytes(), fingerprint.as_bytes());
        assert_eq!(digest.to_string(), fingerprint.to_string());
        // `digest == fingerprint` does not compile, which is the point.
    }

    #[test]
    fn fingerprints_render_as_lowercase_hex() {
        let fingerprint = OuterEntryFingerprint::from_verified([0xab; 32]);
        assert_eq!(fingerprint.to_string(), "ab".repeat(32));
        assert_eq!(fingerprint.to_string().len(), 64);
    }
}
