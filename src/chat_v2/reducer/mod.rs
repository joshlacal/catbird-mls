//! The application context reducer: sequencing core.
//!
//! CHAT_PROTOCOL.md §6. A reducer is permanently bound to one immutable
//! `conversationId` and one exact recipient `{recipientDid, recipientDeviceId}`,
//! and it tracks that device's application access as a sequence of intervals
//! plus one expected context.
//!
//! This module implements the *sequencing* half:
//!
//! - the first accessible interval installs its opening context as `expected`
//!   only after the authenticated opening row matches all five recorded fields;
//! - while an interval is open, every authenticated context-changing control row
//!   requires `previous == expected` before its exact verified `next` becomes
//!   the new expected;
//! - an application entry is visible exactly when its seq lies within an
//!   interval's inclusive range;
//! - once a schedule is terminalized, nothing later is accepted.
//!
//! Interval closure, reanchor after a gap, and legal touching boundaries live
//! in [`reanchor`]. The reset-activator classification and the two Terminal
//! paths are still separate concerns and land in their own sub-slices. What is
//! built refuses them by name rather than half-implementing them, so an unbuilt
//! path cannot be mistaken for a permissive one.
//!
//! # Why sequences alone are never enough
//!
//! Every acceptance below is gated on provenance rather than on ordering. A row
//! that arrives with the right sequence but the wrong transition ID,
//! fingerprint, or context is refused, because the sequence is the one part of
//! a row an adversary can most easily arrange to look correct.

pub mod reanchor;

pub use reanchor::{ReanchorAuthority, SequentialClose, TouchingBoundary};

use super::coordinate::Coordinate;
use super::ids::Seq;
use super::interval::{
    AccessInterval, ApplicationScheduleTerminalProof, IntervalError, IntervalOpening,
    RecipientBinding,
};
use core::fmt;

/// An authenticated context-changing control row addressed to this recipient.
///
/// Construction implies the envelope layer has already verified the row's
/// shape, transcript, signature, and fingerprint; the reducer's job is only to
/// decide whether it fits this device's schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialControl {
    /// The row's append sequence.
    pub seq: Seq,
    /// The audience the row is routed to.
    pub recipient: RecipientBinding,
    /// The coordinate the row claims to build on.
    pub previous: Coordinate,
    /// The coordinate the row installs.
    pub next: Coordinate,
}

/// Why the reducer refused a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReducerError {
    /// The row was routed to a different conversation or device.
    ///
    /// Includes a same-DID sibling device: visibility is per exact
    /// `(DID, deviceId)` leaf and never DID-aggregate.
    RecipientMismatch {
        expected: RecipientBinding,
        found: RecipientBinding,
    },
    /// An opening was installed while an interval was already open.
    AlreadyOpen { opening_seq: Seq },
    /// A sequential control arrived with no interval open.
    ///
    /// After a gap, only a matching verified reanchor may reopen access; an
    /// arbitrary current head is never reanchor proof.
    NoOpenInterval { seq: Seq },
    /// A row's `previous` did not equal the expected context.
    ContextMismatch {
        seq: Seq,
        expected: Box<Coordinate>,
        found: Box<Coordinate>,
    },
    /// A row arrived after the schedule was irreversibly terminalized.
    PostTerminal { terminal_seq: Seq, row_seq: Seq },
    /// A row's seq did not advance past the interval's opening.
    NotAdvancing { expected_after: Seq, found: Seq },
    /// A reanchor arrived while an interval was still open.
    ///
    /// Reanchor reopens access after a gap. Applying one over a live interval
    /// would abandon its expected context without a close proof.
    NotAwaitingReanchor { open_since: Seq, seq: Seq },
    /// A close or touching boundary arrived with no interval open.
    NothingToClose { seq: Seq },
    /// A non-touching reanchor did not leave a strict gap after the close.
    ///
    /// Sharing a seq is a *touching* boundary and has its own entry point,
    /// because it must be processed exactly once rather than as a close
    /// followed by an independent open.
    ReanchorMustNotTouch { close_seq: Seq, opening_seq: Seq },
    /// A `Terminal` close reached the ordinary close path.
    ///
    /// Terminal must atomically install the exact schedule terminal proof. Its
    /// dedicated path is not built yet, and closing the interval here without
    /// that proof would leave the schedule un-terminalized while looking
    /// finished — so it is refused by name rather than silently mishandled.
    TerminalRequiresScheduleProof { seq: Seq },
    /// An interval-level rule was violated.
    Interval(IntervalError),
}

impl From<IntervalError> for ReducerError {
    fn from(err: IntervalError) -> Self {
        Self::Interval(err)
    }
}

impl fmt::Display for ReducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecipientMismatch { expected, found } => {
                write!(
                    f,
                    "row routed to {found}, this reducer is bound to {expected}"
                )
            }
            Self::AlreadyOpen { opening_seq } => {
                write!(f, "an interval opened at {opening_seq} is already open")
            }
            Self::NoOpenInterval { seq } => write!(
                f,
                "row at {seq} has no open interval; only a verified reanchor may reopen access"
            ),
            Self::ContextMismatch { seq, .. } => {
                write!(f, "row at {seq} does not build on the expected context")
            }
            Self::PostTerminal {
                terminal_seq,
                row_seq,
            } => write!(
                f,
                "row at {row_seq} follows an irreversible terminal at {terminal_seq}"
            ),
            Self::NotAdvancing {
                expected_after,
                found,
            } => write!(f, "row at {found} must be after {expected_after}"),
            Self::NotAwaitingReanchor { open_since, seq } => write!(
                f,
                "reanchor at {seq} refused: an interval opened at {open_since} is still live"
            ),
            Self::NothingToClose { seq } => {
                write!(f, "row at {seq} has no open interval to close")
            }
            Self::ReanchorMustNotTouch {
                close_seq,
                opening_seq,
            } => write!(
                f,
                "reanchor at {opening_seq} shares the close seq {close_seq}; \
                 a touching boundary is one shared row and has its own path"
            ),
            Self::TerminalRequiresScheduleProof { seq } => write!(
                f,
                "terminal close at {seq} must atomically install the schedule proof"
            ),
            Self::Interval(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for ReducerError {}

/// One exact-device application context reducer.
#[derive(Debug, Clone)]
pub struct ApplicationReducer {
    binding: RecipientBinding,
    intervals: Vec<AccessInterval<Coordinate>>,
    expected: Option<Coordinate>,
    terminal: Option<ApplicationScheduleTerminalProof>,
}

impl ApplicationReducer {
    /// Creates a reducer bound to one conversation and one exact device.
    pub fn new(binding: RecipientBinding) -> Self {
        Self {
            binding,
            intervals: Vec::new(),
            expected: None,
            terminal: None,
        }
    }

    /// The immutable audience this reducer is bound to.
    pub fn binding(&self) -> &RecipientBinding {
        &self.binding
    }

    /// The context the next control row must build on, if an interval is open.
    pub fn expected_context(&self) -> Option<&Coordinate> {
        self.expected.as_ref()
    }

    /// Every interval recorded so far, oldest first.
    pub fn intervals(&self) -> &[AccessInterval<Coordinate>] {
        &self.intervals
    }

    /// The schedule terminal proof, once installed.
    pub fn terminal_proof(&self) -> Option<&ApplicationScheduleTerminalProof> {
        self.terminal.as_ref()
    }

    /// Whether this schedule has been irreversibly terminalized.
    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    /// Whether an interval is currently open.
    pub fn has_open_interval(&self) -> bool {
        self.intervals.last().is_some_and(AccessInterval::is_open)
    }

    /// Installs the first accessible interval.
    ///
    /// The caller must have compared all five opening fields against the
    /// authenticated row; [`IntervalOpening::matches_exactly`] is the only
    /// comparison that does so. The opening's context becomes `expected`.
    pub fn install_initial_opening(
        &mut self,
        recipient: &RecipientBinding,
        opening: IntervalOpening<Coordinate>,
    ) -> Result<(), ReducerError> {
        self.require_not_terminal(opening.seq)?;
        self.require_recipient(recipient)?;
        if let Some(open) = self.intervals.last().filter(|i| i.is_open()) {
            return Err(ReducerError::AlreadyOpen {
                opening_seq: open.opening().seq,
            });
        }
        if !self.intervals.is_empty() {
            // A later interval after a closed one is a reanchor, which has its
            // own verification rules and its own entry point. Silently treating
            // it as an initial install would skip the Welcome/post-join
            // provenance match that a reanchor requires.
            return Err(ReducerError::NoOpenInterval { seq: opening.seq });
        }

        let context = opening.context.clone();
        self.intervals
            .push(AccessInterval::open(self.binding.clone(), opening));
        self.expected = Some(context);
        Ok(())
    }

    /// Applies an authenticated context-changing control row.
    ///
    /// Requires `previous == expected` and installs the row's exact `next`.
    pub fn apply_sequential_control(
        &mut self,
        row: &SequentialControl,
    ) -> Result<(), ReducerError> {
        self.require_not_terminal(row.seq)?;
        self.require_recipient(&row.recipient)?;

        let Some(open) = self.intervals.last().filter(|i| i.is_open()) else {
            return Err(ReducerError::NoOpenInterval { seq: row.seq });
        };
        if !row.seq.is_strictly_after(open.opening().seq) {
            return Err(ReducerError::NotAdvancing {
                expected_after: open.opening().seq,
                found: row.seq,
            });
        }

        let expected = self
            .expected
            .as_ref()
            .expect("an open interval always carries an expected context");
        if &row.previous != expected {
            return Err(ReducerError::ContextMismatch {
                seq: row.seq,
                expected: Box::new(expected.clone()),
                found: Box::new(row.previous.clone()),
            });
        }

        self.expected = Some(row.next.clone());
        Ok(())
    }

    /// Whether an application entry at `seq` is visible to this exact device.
    ///
    /// An interval's range is inclusive of its opening and, when finite, of its
    /// close. Ranges cannot overlap on an application entry: append sequences
    /// are globally unique within a conversation, and a touching boundary's
    /// shared seq belongs to the control row that both closes one interval and
    /// opens the next. So the inclusive form cannot make one application entry
    /// visible through two interval interiors.
    pub fn is_application_visible(&self, seq: Seq) -> bool {
        self.visible_interval(seq).is_some()
    }

    /// The interval through which an application entry at `seq` is visible.
    pub fn visible_interval(&self, seq: Seq) -> Option<&AccessInterval<Coordinate>> {
        self.intervals.iter().find(|interval| {
            let opening = interval.opening().seq;
            if seq < opening {
                return false;
            }
            match interval.close() {
                Some(close) => seq <= close.seq,
                None => true,
            }
        })
    }

    /// The currently open interval, if any.
    fn open_interval(&self) -> Option<&AccessInterval<Coordinate>> {
        self.intervals.last().filter(|i| i.is_open())
    }

    /// Mutable access to the interval list, for the reanchor module.
    fn intervals_mut(&mut self) -> &mut Vec<AccessInterval<Coordinate>> {
        &mut self.intervals
    }

    /// Installs a new expected context.
    fn set_expected(&mut self, context: Coordinate) {
        self.expected = Some(context);
    }

    /// Drops the expected context, as a close does.
    ///
    /// Nothing may be sequenced afterwards until a verified reanchor: there is
    /// no context to compare a `previous` against, and inventing one is exactly
    /// what an arbitrary-current-head reanchor would be.
    fn clear_expected(&mut self) {
        self.expected = None;
    }

    /// Requires a row to build on the expected context.
    fn require_expected_predecessor(
        &self,
        seq: Seq,
        previous: &Coordinate,
    ) -> Result<(), ReducerError> {
        let expected = self
            .expected
            .as_ref()
            .ok_or(ReducerError::NoOpenInterval { seq })?;
        if previous != expected {
            return Err(ReducerError::ContextMismatch {
                seq,
                expected: Box::new(expected.clone()),
                found: Box::new(previous.clone()),
            });
        }
        Ok(())
    }

    fn require_recipient(&self, found: &RecipientBinding) -> Result<(), ReducerError> {
        if !self.binding.matches(found) {
            return Err(ReducerError::RecipientMismatch {
                expected: self.binding.clone(),
                found: found.clone(),
            });
        }
        Ok(())
    }

    fn require_not_terminal(&self, row_seq: Seq) -> Result<(), ReducerError> {
        if let Some(proof) = &self.terminal {
            return Err(ReducerError::PostTerminal {
                terminal_seq: proof.seq(),
                row_seq,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::coordinate::Lifecycle;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger, TransitionId};
    use crate::chat_v2::provenance::{OpeningKind, OuterEntryFingerprint};

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CONVERSATION: &str = "22222222-2222-4222-8222-222222222222";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING: &str = "72727272-7272-4272-b272-727272727272";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";

    fn seq(value: i64) -> Seq {
        Seq::new(value).unwrap()
    }

    fn binding_for(conversation: &str, device: &str) -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(conversation).unwrap(),
            BareDid::parse(DID).unwrap(),
            DeviceId::parse(device).unwrap(),
        )
    }

    fn binding() -> RecipientBinding {
        binding_for(CONVERSATION, DEVICE)
    }

    /// A coordinate distinguished only by state version, which is all the
    /// sequencing core compares.
    fn coordinate(state_version: i64) -> Coordinate {
        Coordinate {
            conversation_id: ConversationId::parse(CONVERSATION).unwrap(),
            generation: SafeInteger::ZERO,
            state_version: SafeInteger::new(state_version).unwrap(),
            group_id: [0x01; 32],
            epoch: SafeInteger::ZERO,
            group_context_hash: [0x02; 32],
            confirmation_tag: [0x03; 32],
            lifecycle: Lifecycle::Active,
        }
    }

    fn opening(at: i64, context: Coordinate) -> IntervalOpening<Coordinate> {
        IntervalOpening {
            seq: seq(at),
            kind: OpeningKind::Creation,
            transition_id: TransitionId::parse(TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x11; 32]),
            context,
        }
    }

    fn control(at: i64, previous: Coordinate, next: Coordinate) -> SequentialControl {
        SequentialControl {
            seq: seq(at),
            recipient: binding(),
            previous,
            next,
        }
    }

    fn opened_reducer() -> ApplicationReducer {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, coordinate(0)))
            .expect("initial opening must install");
        reducer
    }

    #[test]
    fn a_new_reducer_has_no_interval_and_no_expected_context() {
        let reducer = ApplicationReducer::new(binding());
        assert!(!reducer.has_open_interval());
        assert!(reducer.expected_context().is_none());
        assert!(!reducer.is_terminal());
        assert!(reducer.intervals().is_empty());
    }

    #[test]
    fn the_initial_opening_installs_its_context_as_expected() {
        let reducer = opened_reducer();
        assert!(reducer.has_open_interval());
        assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
        assert_eq!(reducer.intervals().len(), 1);
    }

    #[test]
    fn a_sequential_control_must_build_on_the_expected_context() {
        let mut reducer = opened_reducer();
        reducer
            .apply_sequential_control(&control(2, coordinate(0), coordinate(1)))
            .expect("a row building on the expected context must apply");
        assert_eq!(reducer.expected_context(), Some(&coordinate(1)));

        // The next row must build on the newly installed context, not the old.
        reducer
            .apply_sequential_control(&control(3, coordinate(1), coordinate(2)))
            .expect("chained rows must apply");
        assert_eq!(reducer.expected_context(), Some(&coordinate(2)));
    }

    #[test]
    fn a_row_building_on_a_stale_context_is_refused() {
        let mut reducer = opened_reducer();
        reducer
            .apply_sequential_control(&control(2, coordinate(0), coordinate(1)))
            .unwrap();

        // Replaying the same predecessor: this is the fork that `previous ==
        // expected` exists to prevent.
        let err = reducer
            .apply_sequential_control(&control(3, coordinate(0), coordinate(9)))
            .unwrap_err();
        assert!(matches!(err, ReducerError::ContextMismatch { .. }));
        assert_eq!(
            reducer.expected_context(),
            Some(&coordinate(1)),
            "a refused row must not move the expected context"
        );
    }

    #[test]
    fn a_row_from_the_future_is_refused_too() {
        // Skipping ahead is as invalid as replaying: the reducer accepts only
        // the exact expected predecessor, so a client cannot silently jump a
        // context it never processed.
        let mut reducer = opened_reducer();
        let err = reducer
            .apply_sequential_control(&control(2, coordinate(5), coordinate(6)))
            .unwrap_err();
        assert!(matches!(err, ReducerError::ContextMismatch { .. }));
    }

    #[test]
    fn a_sibling_device_row_is_refused() {
        let mut reducer = opened_reducer();
        let mut row = control(2, coordinate(0), coordinate(1));
        row.recipient = binding_for(CONVERSATION, SIBLING);

        let err = reducer.apply_sequential_control(&row).unwrap_err();
        assert!(
            matches!(err, ReducerError::RecipientMismatch { .. }),
            "visibility is per exact (DID, deviceId), never DID-aggregate"
        );
        assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
    }

    #[test]
    fn a_cross_conversation_row_is_refused() {
        let mut reducer = opened_reducer();
        let mut row = control(2, coordinate(0), coordinate(1));
        row.recipient = binding_for(OTHER_CONVERSATION, DEVICE);
        assert!(matches!(
            reducer.apply_sequential_control(&row).unwrap_err(),
            ReducerError::RecipientMismatch { .. }
        ));
    }

    #[test]
    fn a_control_must_advance_past_its_own_opening() {
        // A row at the opening seq would be the opening row itself being
        // processed twice. Sequences below the opening are simply outside the
        // interval, and Seq is positive so there is nothing below 1 to test.
        let mut reducer = opened_reducer();
        let err = reducer
            .apply_sequential_control(&control(1, coordinate(0), coordinate(1)))
            .unwrap_err();
        assert_eq!(
            err,
            ReducerError::NotAdvancing {
                expected_after: seq(1),
                found: seq(1)
            }
        );

        let mut later = ApplicationReducer::new(binding());
        later
            .install_initial_opening(&binding(), opening(10, coordinate(0)))
            .unwrap();
        assert!(matches!(
            later
                .apply_sequential_control(&control(4, coordinate(0), coordinate(1)))
                .unwrap_err(),
            ReducerError::NotAdvancing { .. }
        ));
    }

    #[test]
    fn a_control_with_no_open_interval_is_refused() {
        let mut reducer = ApplicationReducer::new(binding());
        let err = reducer
            .apply_sequential_control(&control(2, coordinate(0), coordinate(1)))
            .unwrap_err();
        assert_eq!(err, ReducerError::NoOpenInterval { seq: seq(2) });
    }

    #[test]
    fn an_opening_cannot_be_installed_over_an_open_interval() {
        let mut reducer = opened_reducer();
        let err = reducer
            .install_initial_opening(&binding(), opening(5, coordinate(3)))
            .unwrap_err();
        assert_eq!(
            err,
            ReducerError::AlreadyOpen {
                opening_seq: seq(1)
            }
        );
        assert_eq!(reducer.intervals().len(), 1);
        assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
    }

    #[test]
    fn an_initial_install_refuses_a_recipient_it_is_not_bound_to() {
        let mut reducer = ApplicationReducer::new(binding());
        let err = reducer
            .install_initial_opening(
                &binding_for(CONVERSATION, SIBLING),
                opening(1, coordinate(0)),
            )
            .unwrap_err();
        assert!(matches!(err, ReducerError::RecipientMismatch { .. }));
        assert!(reducer.intervals().is_empty());
    }

    // ---- application visibility -------------------------------------------

    #[test]
    fn an_open_interval_makes_every_later_entry_visible() {
        let reducer = opened_reducer();
        assert!(reducer.is_application_visible(seq(1)));
        assert!(reducer.is_application_visible(seq(2)));
        assert!(reducer.is_application_visible(seq(1_000)));
    }

    #[test]
    fn entries_before_the_opening_are_never_visible() {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(10, coordinate(0)))
            .unwrap();
        // A device added at seq 10 receives no history backfill.
        assert!(!reducer.is_application_visible(seq(9)));
        assert!(!reducer.is_application_visible(seq(1)));
        assert!(reducer.is_application_visible(seq(10)));
    }

    #[test]
    fn a_reducer_bound_to_a_device_reports_that_device() {
        let reducer = ApplicationReducer::new(binding());
        assert!(reducer.binding().matches(&binding()));
        assert!(!reducer
            .binding()
            .matches(&binding_for(CONVERSATION, SIBLING)));
    }

    #[test]
    fn unbuilt_paths_refuse_rather_than_permit() {
        // Reanchor after a gap is a later sub-slice. Until it exists, a control
        // row with no open interval must be refused, never treated as an
        // implicit reopen — an unbuilt path must not read as a permissive one.
        let mut reducer = ApplicationReducer::new(binding());
        assert!(reducer
            .apply_sequential_control(&control(5, coordinate(0), coordinate(1)))
            .is_err());
        assert!(!reducer.has_open_interval());
        assert!(reducer.expected_context().is_none());
    }
}
