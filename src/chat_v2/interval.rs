//! Exact-device application access intervals and their provenance.
//!
//! CHAT_PROTOCOL.md §6: an application reducer is permanently bound to one
//! immutable `conversationId` and one exact recipient `{recipientDid,
//! recipientDeviceId}`, and *every* interval in it carries that same audience.
//! Visibility is per exact `(DID, deviceId)` MLS leaf, **never** DID-aggregate,
//! so a sibling device of the same DID is a different audience entirely.
//!
//! The provenance rules are unusually strict, and each strictness exists to
//! close a specific forgery:
//!
//! - An opening records **five** fields — `{openingSeq, openingKind,
//!   openingTransitionId, openingOuterEntryFingerprint, openingContext}` — and
//!   all five are compared. The append row's `entryId` is a *separate replay
//!   identity* and can never substitute for the signed `openingTransitionId`
//!   or the fingerprint.
//! - A finite end is **all-or-none**: it requires the closing transition ID,
//!   the closing outer fingerprint, and the close kind, all three targeting
//!   this recipient. An open interval carries none of them. A partial close
//!   proof is not a weaker claim, it is an invalid one.
//! - `closeSeq > openingSeq` strictly, within an interval. Equality is legal
//!   only *across adjacent intervals*, never between one interval's own
//!   opening and close — which is what makes a creation-open plus terminal
//!   close at the same seq invalid.

use super::ids::{BareDid, ConversationId, DeviceId, Seq, TransitionId};
use super::provenance::{CloseKind, OpeningKind, OuterEntryFingerprint};
use core::fmt;

/// The exact audience a reducer and every one of its intervals is bound to.
///
/// Application visibility is per exact `(DID, deviceId)` leaf. Two devices of
/// one DID are different recipients, and a reducer must refuse a row routed to
/// the other one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipientBinding {
    conversation_id: ConversationId,
    recipient_did: BareDid,
    recipient_device_id: DeviceId,
}

impl RecipientBinding {
    /// Binds a reducer to one conversation and one exact device.
    pub fn new(
        conversation_id: ConversationId,
        recipient_did: BareDid,
        recipient_device_id: DeviceId,
    ) -> Self {
        Self {
            conversation_id,
            recipient_did,
            recipient_device_id,
        }
    }

    /// The immutable conversation.
    pub fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// The recipient DID.
    pub fn recipient_did(&self) -> &BareDid {
        &self.recipient_did
    }

    /// The exact recipient device.
    pub fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// Whether `other` names the identical conversation and exact device.
    ///
    /// A same-DID sibling device is not a match. That is the whole point of
    /// carrying the device in the binding.
    pub fn matches(&self, other: &RecipientBinding) -> bool {
        self == other
    }
}

impl fmt::Display for RecipientBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}#{}",
            self.conversation_id, self.recipient_did, self.recipient_device_id
        )
    }
}

/// The five-field provenance of an interval opening.
///
/// `context` is the opening control's exact verified successor context. It is
/// carried opaquely here as the coordinate the reducer installs as `expected`;
/// the coordinate type itself lives in [`super::coordinate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalOpening<C> {
    /// The sequence at which the interval opens.
    pub seq: Seq,
    /// Creation, reset activation, or Add.
    pub kind: OpeningKind,
    /// The signed control's `transitionId`. Never the append row's `entryId`.
    pub transition_id: TransitionId,
    /// The authenticated outer entry fingerprint.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
    /// The opening control's exact verified successor context.
    pub context: C,
}

impl<C: PartialEq> IntervalOpening<C> {
    /// Whether all five recorded fields match `other` exactly.
    ///
    /// The reducer compares all five on initial install, on non-touching
    /// reanchor, and on legal touching processing. Comparing four of them is
    /// how a forged opening gets accepted, so this is deliberately the only
    /// comparison offered.
    pub fn matches_exactly(&self, other: &IntervalOpening<C>) -> bool {
        self.seq == other.seq
            && self.kind == other.kind
            && self.transition_id == other.transition_id
            && self.outer_entry_fingerprint == other.outer_entry_fingerprint
            && self.context == other.context
    }
}

/// The all-or-none proof that an interval has a finite end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseProof {
    /// The sequence at which the interval closes, inclusive.
    pub seq: Seq,
    /// Remove, Replace, Reset, or Terminal.
    pub kind: CloseKind,
    /// The signed closing control's `transitionId`.
    pub transition_id: TransitionId,
    /// The authenticated outer entry fingerprint of the closing row.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
}

/// Why an interval or interval pair was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntervalError {
    /// A row was routed to a different conversation or device.
    RecipientMismatch {
        expected: RecipientBinding,
        found: RecipientBinding,
    },
    /// A finite end was not strictly after its own opening.
    CloseNotAfterOpening { opening_seq: Seq, close_seq: Seq },
    /// Two adjacent intervals shared a seq under a close kind that forbids it.
    IllegalTouching {
        close_kind: CloseKind,
        opening_kind: OpeningKind,
    },
    /// A touching boundary did not share the identical transition ID and
    /// fingerprint.
    TouchingProofNotShared,
    /// A non-touching successor did not leave a strict gap.
    MissingStrictGap { close_seq: Seq, opening_seq: Seq },
    /// A successor followed a close kind that permits none.
    SuccessorAfterTerminal { close_seq: Seq },
    /// A successor opened at or before its predecessor's close.
    SuccessorNotAfterPredecessor { close_seq: Seq, opening_seq: Seq },
}

impl fmt::Display for IntervalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecipientMismatch { expected, found } => {
                write!(f, "row routed to {found}, expected {expected}")
            }
            Self::CloseNotAfterOpening {
                opening_seq,
                close_seq,
            } => write!(
                f,
                "close seq {close_seq} must be strictly after its own opening {opening_seq}"
            ),
            Self::IllegalTouching {
                close_kind,
                opening_kind,
            } => write!(
                f,
                "{close_kind:?} may not touch a {opening_kind:?} opening at a shared seq"
            ),
            Self::TouchingProofNotShared => f.write_str(
                "a touching boundary must share one transition ID and outer fingerprint",
            ),
            Self::MissingStrictGap {
                close_seq,
                opening_seq,
            } => write!(
                f,
                "close {close_seq} requires a strict gap before opening {opening_seq}"
            ),
            Self::SuccessorAfterTerminal { close_seq } => {
                write!(f, "terminal close at {close_seq} admits no successor")
            }
            Self::SuccessorNotAfterPredecessor {
                close_seq,
                opening_seq,
            } => write!(
                f,
                "successor opening {opening_seq} must not precede close {close_seq}"
            ),
        }
    }
}

impl core::error::Error for IntervalError {}

/// One exact-device application access interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessInterval<C> {
    binding: RecipientBinding,
    opening: IntervalOpening<C>,
    close: Option<CloseProof>,
}

impl<C: PartialEq> AccessInterval<C> {
    /// Opens an interval with no end.
    pub fn open(binding: RecipientBinding, opening: IntervalOpening<C>) -> Self {
        Self {
            binding,
            opening,
            close: None,
        }
    }

    /// The recipient this interval is bound to.
    pub fn binding(&self) -> &RecipientBinding {
        &self.binding
    }

    /// The five-field opening provenance.
    pub fn opening(&self) -> &IntervalOpening<C> {
        &self.opening
    }

    /// The close proof, if the interval is finite.
    pub fn close(&self) -> Option<&CloseProof> {
        self.close.as_ref()
    }

    /// Whether the interval is still open.
    ///
    /// An open interval has no end *and* no close proof; the two are the same
    /// condition, because a partial close proof is never representable.
    pub fn is_open(&self) -> bool {
        self.close.is_none()
    }

    /// Applies a finite end.
    ///
    /// Requires `close.seq > opening.seq` strictly. Equality is legal only
    /// across adjacent intervals, never within one — which is precisely why an
    /// opening and a terminal close at the same seq is invalid.
    pub fn apply_close(&mut self, close: CloseProof) -> Result<(), IntervalError> {
        if !close.seq.is_strictly_after(self.opening.seq) {
            return Err(IntervalError::CloseNotAfterOpening {
                opening_seq: self.opening.seq,
                close_seq: close.seq,
            });
        }
        self.close = Some(close);
        Ok(())
    }

    /// Confirms a row's routing matches this interval's exact audience.
    pub fn require_recipient(&self, found: &RecipientBinding) -> Result<(), IntervalError> {
        if !self.binding.matches(found) {
            return Err(IntervalError::RecipientMismatch {
                expected: self.binding.clone(),
                found: found.clone(),
            });
        }
        Ok(())
    }

    /// Confirms that `successor` may legally follow this closed interval.
    ///
    /// Encodes the whole adjacency rule: `Terminal` admits no successor;
    /// `Replace -> Add` and `Reset -> Reset` may share a seq but must share one
    /// authenticated row, meaning identical transition ID and fingerprint;
    /// every other pairing needs a strict gap.
    pub fn validate_successor(
        &self,
        successor: &AccessInterval<C>,
    ) -> Result<Adjacency, IntervalError> {
        let Some(close) = &self.close else {
            // An open interval has no successor to validate against; callers
            // reach this only by mistake, and treating it as a missing gap
            // reports the right thing.
            return Err(IntervalError::MissingStrictGap {
                close_seq: self.opening.seq,
                opening_seq: successor.opening.seq,
            });
        };

        if !close.kind.permits_successor() {
            return Err(IntervalError::SuccessorAfterTerminal {
                close_seq: close.seq,
            });
        }

        let opening = &successor.opening;
        if opening.seq == close.seq {
            // A touching boundary. Only two pairings are legal, and both must
            // be one shared authenticated row rather than two rows that merely
            // agree on a number.
            if close.kind.legal_touching_successor() != Some(opening.kind) {
                return Err(IntervalError::IllegalTouching {
                    close_kind: close.kind,
                    opening_kind: opening.kind,
                });
            }
            if close.transition_id != opening.transition_id
                || close.outer_entry_fingerprint != opening.outer_entry_fingerprint
            {
                return Err(IntervalError::TouchingProofNotShared);
            }
            return Ok(Adjacency::Touching);
        }

        if !opening.seq.is_strictly_after(close.seq) {
            return Err(IntervalError::SuccessorNotAfterPredecessor {
                close_seq: close.seq,
                opening_seq: opening.seq,
            });
        }

        // A strictly later opening. `Remove` demands exactly this, and the
        // other kinds permit it.
        Ok(Adjacency::Gapped)
    }
}

/// How two adjacent intervals meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjacency {
    /// One shared authenticated row closes the prior interval and opens the
    /// successor. It is processed exactly once.
    Touching,
    /// A strict gap separates them. The gap's entries are never visible.
    Gapped,
}

/// The at-most-one immutable terminal proof for a historical exact-device
/// schedule.
///
/// §6 keeps this deliberately separate from an interval close. When the last
/// interval closed by `Remove` or `Reset`, an entitled signed `Terminal` row
/// arriving across the inaccessible gap installs **only** this proof: it does
/// not compare its `previous` against the reducer's stale expected context, does
/// not rewrite or double-close the old interval, and grants no gap history.
/// Upstream outer Terminal authority has already verified the real predecessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationScheduleTerminalProof {
    binding: RecipientBinding,
    seq: Seq,
    transition_id: TransitionId,
    outer_entry_fingerprint: OuterEntryFingerprint,
}

impl ApplicationScheduleTerminalProof {
    /// Records the terminal proof for one exact-device schedule.
    pub fn new(
        binding: RecipientBinding,
        seq: Seq,
        transition_id: TransitionId,
        outer_entry_fingerprint: OuterEntryFingerprint,
    ) -> Self {
        Self {
            binding,
            seq,
            transition_id,
            outer_entry_fingerprint,
        }
    }

    /// The exact `(conversation, recipient DID, recipient device)` this
    /// terminalizes. Lookup is bounded to zero or one row per conversation and
    /// never exposes another device's proof.
    pub fn binding(&self) -> &RecipientBinding {
        &self.binding
    }

    /// The Terminal row's sequence.
    pub fn seq(&self) -> Seq {
        self.seq
    }

    /// The signed Terminal transition ID.
    pub fn transition_id(&self) -> TransitionId {
        self.transition_id
    }

    /// The authenticated outer fingerprint of the Terminal row.
    pub fn outer_entry_fingerprint(&self) -> OuterEntryFingerprint {
        self.outer_entry_fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING_DEVICE: &str = "72727272-7272-4272-b272-727272727272";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
    const OTHER_TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

    /// A stand-in for the coordinate context; the reducer compares it by
    /// equality and nothing here depends on its shape.
    type Ctx = u32;

    fn seq(value: i64) -> Seq {
        Seq::new(value).unwrap()
    }

    fn binding(device: &str) -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(CONVERSATION).unwrap(),
            BareDid::parse(DID).unwrap(),
            DeviceId::parse(device).unwrap(),
        )
    }

    fn opening(
        at: i64,
        kind: OpeningKind,
        transition: &str,
        fingerprint: u8,
        context: Ctx,
    ) -> IntervalOpening<Ctx> {
        IntervalOpening {
            seq: seq(at),
            kind,
            transition_id: TransitionId::parse(transition).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([fingerprint; 32]),
            context,
        }
    }

    fn close(at: i64, kind: CloseKind, transition: &str, fingerprint: u8) -> CloseProof {
        CloseProof {
            seq: seq(at),
            kind,
            transition_id: TransitionId::parse(transition).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([fingerprint; 32]),
        }
    }

    fn interval(
        device: &str,
        opening: IntervalOpening<Ctx>,
        close_proof: Option<CloseProof>,
    ) -> AccessInterval<Ctx> {
        let mut built = AccessInterval::open(binding(device), opening);
        if let Some(proof) = close_proof {
            built
                .apply_close(proof)
                .expect("fixture close must be legal");
        }
        built
    }

    // ---- recipient binding ----------------------------------------------

    #[test]
    fn a_sibling_device_is_a_different_recipient() {
        // Visibility is per exact (DID, deviceId), never DID-aggregate.
        let own = binding(DEVICE);
        let sibling = binding(SIBLING_DEVICE);
        assert_eq!(own.recipient_did(), sibling.recipient_did());
        assert!(!own.matches(&sibling));

        let open = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            None,
        );
        assert!(matches!(
            open.require_recipient(&sibling).unwrap_err(),
            IntervalError::RecipientMismatch { .. }
        ));
        assert!(open.require_recipient(&own).is_ok());
    }

    // ---- opening provenance ---------------------------------------------

    #[test]
    fn an_opening_matches_only_when_all_five_fields_agree() {
        let reference = opening(5, OpeningKind::Add, TRANSITION, 0x11, 7);
        assert!(reference.matches_exactly(&opening(5, OpeningKind::Add, TRANSITION, 0x11, 7)));

        // One field wrong at a time. Each of the five must reject on its own,
        // because accepting four of five is how a forged opening gets in.
        assert!(!reference.matches_exactly(&opening(6, OpeningKind::Add, TRANSITION, 0x11, 7)));
        assert!(!reference.matches_exactly(&opening(5, OpeningKind::Reset, TRANSITION, 0x11, 7)));
        assert!(
            !reference.matches_exactly(&opening(5, OpeningKind::Add, OTHER_TRANSITION, 0x11, 7)),
            "a different signed transition ID must reject"
        );
        assert!(
            !reference.matches_exactly(&opening(5, OpeningKind::Add, TRANSITION, 0x22, 7)),
            "a different outer fingerprint must reject"
        );
        assert!(
            !reference.matches_exactly(&opening(5, OpeningKind::Add, TRANSITION, 0x11, 8)),
            "a different opening context must reject"
        );
    }

    // ---- close proof ------------------------------------------------------

    #[test]
    fn an_open_interval_carries_no_close_proof() {
        let open = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            None,
        );
        assert!(open.is_open());
        assert!(open.close().is_none());
    }

    #[test]
    fn a_close_must_be_strictly_after_its_own_opening() {
        let mut open = interval(
            DEVICE,
            opening(5, OpeningKind::Creation, TRANSITION, 0x11, 7),
            None,
        );
        assert_eq!(
            open.apply_close(close(4, CloseKind::Remove, TRANSITION, 0x22))
                .unwrap_err(),
            IntervalError::CloseNotAfterOpening {
                opening_seq: seq(5),
                close_seq: seq(4)
            }
        );
        assert!(
            open.is_open(),
            "a refused close must leave the interval open"
        );
    }

    #[test]
    fn creation_open_and_terminal_close_at_the_same_seq_is_invalid() {
        // The named `creationOpenTerminalCloseSameSeq` negative. Equality is
        // legal only ACROSS adjacent intervals, never within one.
        let mut open = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            None,
        );
        assert_eq!(
            open.apply_close(close(1, CloseKind::Terminal, TRANSITION, 0x11))
                .unwrap_err(),
            IntervalError::CloseNotAfterOpening {
                opening_seq: seq(1),
                close_seq: seq(1)
            }
        );
    }

    // ---- adjacency --------------------------------------------------------

    #[test]
    fn replace_to_add_may_touch_on_one_shared_row() {
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(9, CloseKind::Replace, OTHER_TRANSITION, 0x99)),
        );
        // The successor's opening repeats the SAME transition ID and
        // fingerprint, because it is the same authenticated row.
        let successor = interval(
            DEVICE,
            opening(9, OpeningKind::Add, OTHER_TRANSITION, 0x99, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&successor).unwrap(),
            Adjacency::Touching
        );
    }

    #[test]
    fn reset_to_reset_may_touch_on_one_shared_row() {
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(9, CloseKind::Reset, OTHER_TRANSITION, 0x99)),
        );
        let successor = interval(
            DEVICE,
            opening(9, OpeningKind::Reset, OTHER_TRANSITION, 0x99, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&successor).unwrap(),
            Adjacency::Touching
        );
    }

    #[test]
    fn a_touching_boundary_must_share_the_actual_proof() {
        // Two rows agreeing on a seq is not a shared row. Without identical
        // transition ID and fingerprint, a client could stitch an unrelated
        // opening onto a legitimate close.
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(9, CloseKind::Replace, OTHER_TRANSITION, 0x99)),
        );

        let wrong_transition = interval(
            DEVICE,
            opening(9, OpeningKind::Add, TRANSITION, 0x99, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&wrong_transition).unwrap_err(),
            IntervalError::TouchingProofNotShared
        );

        let wrong_fingerprint = interval(
            DEVICE,
            opening(9, OpeningKind::Add, OTHER_TRANSITION, 0x77, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&wrong_fingerprint).unwrap_err(),
            IntervalError::TouchingProofNotShared
        );
    }

    #[test]
    fn no_other_touching_pairing_is_legal() {
        // Replace -> Reset and Reset -> Add both share a seq and a row, and
        // both must still be refused: only two pairings exist.
        for (close_kind, opening_kind) in [
            (CloseKind::Replace, OpeningKind::Reset),
            (CloseKind::Reset, OpeningKind::Add),
            (CloseKind::Replace, OpeningKind::Creation),
        ] {
            let prior = interval(
                DEVICE,
                opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
                Some(close(9, close_kind, OTHER_TRANSITION, 0x99)),
            );
            let successor = interval(
                DEVICE,
                opening(9, opening_kind, OTHER_TRANSITION, 0x99, 8),
                None,
            );
            assert_eq!(
                prior.validate_successor(&successor).unwrap_err(),
                IntervalError::IllegalTouching {
                    close_kind,
                    opening_kind
                },
                "{close_kind:?} -> {opening_kind:?}"
            );
        }
    }

    #[test]
    fn remove_requires_a_strict_gap_and_accepts_one() {
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(3, CloseKind::Remove, OTHER_TRANSITION, 0x99)),
        );

        // Touching after a Remove is refused: Remove has no legal touching
        // successor at all.
        let touching = interval(
            DEVICE,
            opening(3, OpeningKind::Add, OTHER_TRANSITION, 0x99, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&touching).unwrap_err(),
            IntervalError::IllegalTouching {
                close_kind: CloseKind::Remove,
                opening_kind: OpeningKind::Add
            }
        );

        // A strictly later Add is the legal re-Add, and it never backfills the
        // gap between 3 and 10.
        let gapped = interval(
            DEVICE,
            opening(10, OpeningKind::Add, OTHER_TRANSITION, 0x55, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&gapped).unwrap(),
            Adjacency::Gapped
        );
    }

    #[test]
    fn terminal_admits_no_successor_at_any_distance() {
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(9, CloseKind::Terminal, OTHER_TRANSITION, 0x99)),
        );
        for successor_seq in [9, 10, 1_000] {
            let successor = interval(
                DEVICE,
                opening(successor_seq, OpeningKind::Add, OTHER_TRANSITION, 0x99, 8),
                None,
            );
            assert_eq!(
                prior.validate_successor(&successor).unwrap_err(),
                IntervalError::SuccessorAfterTerminal { close_seq: seq(9) },
                "successor at {successor_seq}"
            );
        }
    }

    #[test]
    fn a_successor_may_not_open_before_its_predecessor_closes() {
        let prior = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(9, CloseKind::Remove, OTHER_TRANSITION, 0x99)),
        );
        let overlapping = interval(
            DEVICE,
            opening(5, OpeningKind::Add, OTHER_TRANSITION, 0x55, 8),
            None,
        );
        assert_eq!(
            prior.validate_successor(&overlapping).unwrap_err(),
            IntervalError::SuccessorNotAfterPredecessor {
                close_seq: seq(9),
                opening_seq: seq(5)
            }
        );
    }

    #[test]
    fn an_open_interval_has_no_successor_to_validate() {
        let open = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            None,
        );
        let successor = interval(
            DEVICE,
            opening(5, OpeningKind::Add, OTHER_TRANSITION, 0x55, 8),
            None,
        );
        assert!(open.validate_successor(&successor).is_err());
    }

    // ---- schedule terminal proof ------------------------------------------

    #[test]
    fn a_schedule_proof_names_one_exact_device() {
        let proof = ApplicationScheduleTerminalProof::new(
            binding(DEVICE),
            seq(10),
            TransitionId::parse(TRANSITION).unwrap(),
            OuterEntryFingerprint::from_verified([0x5a; 32]),
        );
        assert!(proof.binding().matches(&binding(DEVICE)));
        assert!(
            !proof.binding().matches(&binding(SIBLING_DEVICE)),
            "a proof must never satisfy a sibling device's lookup"
        );
        assert_eq!(proof.seq(), seq(10));
    }

    #[test]
    fn a_schedule_proof_is_independent_of_interval_closure() {
        // The terminal-after-Remove case: the last interval closed at seq 3 by
        // Remove, and an entitled Terminal at seq 10 installs only the schedule
        // proof. The interval keeps its original Remove close — no rewrite, no
        // double-close, and the gap stays inaccessible.
        let closed = interval(
            DEVICE,
            opening(1, OpeningKind::Creation, TRANSITION, 0x11, 7),
            Some(close(3, CloseKind::Remove, OTHER_TRANSITION, 0x99)),
        );
        let proof = ApplicationScheduleTerminalProof::new(
            binding(DEVICE),
            seq(10),
            TransitionId::parse(TRANSITION).unwrap(),
            OuterEntryFingerprint::from_verified([0x5a; 32]),
        );

        assert_eq!(closed.close().unwrap().seq, seq(3));
        assert_eq!(closed.close().unwrap().kind, CloseKind::Remove);
        assert!(proof.seq().is_strictly_after(closed.close().unwrap().seq));
        assert_ne!(
            proof.outer_entry_fingerprint(),
            closed.close().unwrap().outer_entry_fingerprint,
            "the Terminal row is a different row from the Remove that closed the interval"
        );
    }
}
