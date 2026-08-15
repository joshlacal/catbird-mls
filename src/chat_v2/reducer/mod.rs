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
//! in [`reanchor`]. The three reset-activator roles live in [`reset`], which
//! classifies rather than trusts a caller's claim about which role a device
//! held. The two Terminal modes live in [`terminal`].
//!
//! The ordinary close paths still refuse [`CloseKind::Terminal`] by name. That
//! refusal is not a placeholder for something unbuilt — it is permanent. A
//! Terminal must install the schedule proof in the same step that it closes,
//! those paths have no proof to install, and a caller arriving there with a
//! Terminal row is simply at the wrong entry point.
//!
//! # Why sequences alone are never enough
//!
//! Every acceptance below is gated on provenance rather than on ordering. A row
//! that arrives with the right sequence but the wrong transition ID,
//! fingerprint, or context is refused, because the sequence is the one part of
//! a row an adversary can most easily arrange to look correct.

pub mod reanchor;
pub mod reset;
pub mod terminal;

#[cfg(test)]
mod high_water_tests;
#[cfg(test)]
mod restore_tests;

pub use reanchor::{ReanchorAuthority, SequentialClose, TouchingBoundary};
pub use reset::{ResetActivation, ResetParticipation, ResetRole};
pub use terminal::{TerminalClose, TerminalMode};

use super::coordinate::Coordinate;
use super::ids::Seq;
use super::interval::{
    AccessInterval, ApplicationScheduleTerminalProof, IntervalError, IntervalOpening,
    RecipientBinding,
};
use super::provenance::CloseKind;
use core::fmt;

/// An authenticated context-changing control row addressed to this recipient.
///
/// The reducer's job is only to decide whether the row fits this device's
/// schedule; the envelope layer is what establishes that the row is genuine.
///
/// **That is a convention here, not a structural guarantee, and this type is
/// the one place in the family where it is *only* a convention.** Its siblings —
/// [`SequentialClose`], [`TouchingBoundary`], [`ResetActivation`],
/// [`TerminalClose`] — each carry an
/// [`OuterEntryFingerprint`](crate::chat_v2::provenance::OuterEntryFingerprint),
/// which only the envelope-verification layer can mint, so one of those cannot
/// be assembled out of nothing. This one carries no fingerprint: it is a pair of
/// coordinates and a sequence, all of which a caller can invent. Nothing here
/// detects that, and nothing in this module can — the fix, if it is ever wanted,
/// is to carry the row's fingerprint too, which is a protocol-surface decision
/// rather than a refactor.
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
    /// A row's seq did not advance past everything already consumed.
    ///
    /// `expected_after` is the schedule's high-water mark — the greatest
    /// sequence it has already applied — and not merely the current interval's
    /// opening. The two coincide until the first row lands inside an interval,
    /// which is exactly when the weaker comparison starts admitting replays.
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
    /// A `Terminal` close reached an ordinary close path.
    ///
    /// Terminal must atomically install the exact schedule terminal proof, and
    /// the ordinary paths have no proof to install. Closing here would leave the
    /// schedule un-terminalized while looking finished, so the row is refused
    /// and its caller directed to [`ApplicationReducer::apply_terminal`].
    TerminalRequiresScheduleProof { seq: Seq },
    /// A Terminal arrived across a gap after a close kind that admits no
    /// proof-only finalization.
    ///
    /// §6 names `Remove` and `Reset`. A `Replace` close always touches an `Add`
    /// successor on one shared row, so a `Replace`-closed last interval means
    /// that successor was never installed.
    TerminalAfterUnsupportedClose { close_seq: Seq, kind: CloseKind },
    /// A Terminal was applied to a schedule that never held an interval.
    ///
    /// §9 entitles a *historical* exact-device recipient schedule to fetch the
    /// Terminal control for schedule-level finalization. A device with no
    /// history is not one, and terminalizing it would record a schedule that
    /// never existed.
    TerminalWithoutSchedule { seq: Seq },
    /// A reset activation retired nothing and opened nothing on this schedule.
    ///
    /// A registered sibling or roster-only device may legitimately *see* the
    /// reset control row, but §6 gives a reset exactly three effects on an
    /// exact-device schedule and "no effect" is not one of them. Routing the row
    /// to a reducer it does not touch is a caller mistake worth naming.
    ResetAffectsNoInterval { seq: Seq },
    /// A restored schedule's expected context disagreed with its intervals.
    ///
    /// Every path in this module maintains the invariant that an interval is
    /// open exactly when an expected context is installed: an opening installs
    /// one, a close clears it, and [`ApplicationReducer::apply_sequential_control`]
    /// relies on it directly — it reaches for the expected context of an open
    /// interval and treats its absence as unreachable.
    ///
    /// Restoring durable state is the one way into this type that does not run
    /// those paths, so it is the one way the invariant could be violated. A
    /// violation would not be a wrong answer, it would be a panic in a sealed
    /// path, which is why restoring refuses it here instead.
    RestoredScheduleIncoherent {
        /// Whether the restored intervals leave one open.
        has_open_interval: bool,
        /// Whether a restored expected context was supplied.
        has_expected_context: bool,
    },
    /// Restored intervals were not in ascending order of opening sequence.
    ///
    /// The interval list is ordered oldest first, and three separate paths
    /// reason about "the current interval" as `intervals.last()`:
    /// [`ApplicationReducer::has_open_interval`], the strict-gap check in
    /// `reanchor`, and the `last_mut()` that `close_interval` applies a close
    /// proof to. In an unordered list the last element is not the latest
    /// interval, so each of those silently operates on the wrong one.
    RestoredIntervalsOutOfOrder {
        /// The opening sequence of the earlier list element.
        earlier_opening: Seq,
        /// The opening sequence of the element after it, which precedes it.
        later_opening: Seq,
    },
    /// A restored interval opened before its predecessor closed.
    ///
    /// Equality is permitted: a legal touching boundary shares one sequence
    /// between a close and the opening it also performs. Anything below the
    /// predecessor's close is an overlap, which would make one application
    /// sequence visible through two interval interiors.
    RestoredIntervalsOverlap {
        /// Where the predecessor closes.
        close_seq: Seq,
        /// Where the successor claims to open.
        opening_seq: Seq,
    },
    /// A restored interval other than the last was still open.
    ///
    /// Only the most recent interval may be open. An earlier open interval
    /// leaves [`ApplicationReducer::has_open_interval`] reporting `false` while
    /// an interval genuinely is open, which reads as a closed schedule and
    /// admits rows that should have been refused.
    RestoredNonFinalIntervalOpen {
        /// The opening sequence of the interval that was left open.
        opening_seq: Seq,
    },
    /// A restored high-water mark sat below the schedule it came with.
    ///
    /// The mark is supplied by the caller because the interval list cannot
    /// express it, but it can still be checked against a floor: every opening,
    /// close, and terminal sequence the restored schedule records was
    /// necessarily consumed. A mark below one of those is a store that lost
    /// track, and restoring it would reopen the replay window the mark closes.
    RestoredHighWaterBelowSchedule {
        /// What the caller supplied.
        high_water: Option<Seq>,
        /// The greatest sequence the restored schedule itself records.
        recorded: Seq,
    },
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
            Self::ResetAffectsNoInterval { seq } => write!(
                f,
                "reset at {seq} retires no interval and opens none on this schedule"
            ),
            Self::TerminalAfterUnsupportedClose { close_seq, kind } => write!(
                f,
                "terminal follows a {kind:?} close at {close_seq}; \
                 only Remove and Reset admit a proof-only terminal"
            ),
            Self::TerminalWithoutSchedule { seq } => write!(
                f,
                "terminal at {seq} has no historical schedule to finalize"
            ),
            Self::RestoredScheduleIncoherent {
                has_open_interval,
                has_expected_context,
            } => write!(
                f,
                "restored schedule has open_interval={has_open_interval} but \
                 expected_context={has_expected_context}; an interval is open \
                 exactly when a context is expected"
            ),
            Self::RestoredIntervalsOutOfOrder {
                earlier_opening,
                later_opening,
            } => write!(
                f,
                "restored interval opening {later_opening} follows {earlier_opening} \
                 in the list; intervals are ordered oldest first and the last one \
                 must be the latest"
            ),
            Self::RestoredIntervalsOverlap {
                close_seq,
                opening_seq,
            } => write!(
                f,
                "restored interval opens at {opening_seq}, before its predecessor \
                 closes at {close_seq}"
            ),
            Self::RestoredNonFinalIntervalOpen { opening_seq } => write!(
                f,
                "restored interval opened at {opening_seq} is still open but is not \
                 the last; only the most recent interval may be open"
            ),
            Self::RestoredHighWaterBelowSchedule {
                high_water,
                recorded,
            } => match high_water {
                Some(mark) => write!(
                    f,
                    "restored high-water mark {mark} is below sequence {recorded}, \
                     which this schedule records as already consumed"
                ),
                None => write!(
                    f,
                    "restored schedule records sequence {recorded} as consumed but \
                     came with no high-water mark"
                ),
            },
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
    /// The greatest sequence this schedule has already consumed.
    ///
    /// See [`ApplicationReducer::high_water`] for why an interval-relative
    /// comparison is not enough on its own.
    high_water: Option<Seq>,
}

impl ApplicationReducer {
    /// Creates a reducer bound to one conversation and one exact device.
    pub fn new(binding: RecipientBinding) -> Self {
        Self {
            binding,
            intervals: Vec::new(),
            expected: None,
            terminal: None,
            high_water: None,
        }
    }

    /// Restores a schedule from durable storage.
    ///
    /// The counterpart to the rule-enforcing entry points above: those decide
    /// whether a row may change a schedule, while this one reinstates a schedule
    /// those rules already accepted. It deliberately does **not** re-derive that
    /// history — replaying admission decisions against rows that are no longer
    /// held would refuse a schedule that was legitimately built.
    ///
    /// It does enforce the two invariants that later paths assume, because
    /// restoring is the only way into this type that bypasses the paths which
    /// normally maintain them:
    ///
    /// - every interval, and any terminal proof, names this reducer's exact
    ///   recipient. A schedule holding a sibling device's intervals would make
    ///   that device's history visible here, and visibility is per exact
    ///   `(DID, deviceId)`.
    /// - an interval is open exactly when an expected context is present.
    ///   Violating this does not produce a wrong answer, it panics
    ///   [`ApplicationReducer::apply_sequential_control`].
    /// - the interval list is ordered oldest first, non-overlapping, and open
    ///   only in its final position. Three separate paths treat
    ///   `intervals.last()` as "the current interval" —
    ///   [`ApplicationReducer::has_open_interval`], the strict-gap check in
    ///   `reanchor`, and the `last_mut()` that `close_interval` writes a close
    ///   proof into. If the last element is not the latest interval, each of
    ///   those operates on the wrong one and reports success.
    ///
    /// That last group exists because restore is a **second feed** into this
    /// type. The specified append-log feed cannot produce an unordered or
    /// overlapping schedule, so the reducer's own paths never had to defend
    /// against one; durable storage can hand over anything that was written, so
    /// the structural checks live here rather than being assumed upstream.
    /// - the restored high-water mark is at least the greatest sequence the
    ///   restored schedule itself records. It is a **parameter** rather than
    ///   something derived here, because the schedule cannot express it: the
    ///   sequential control rows consumed *inside* an open interval move the
    ///   mark and leave no trace in the interval list. Deriving it would
    ///   silently restore a mark below the truth and reopen the replay window
    ///   this mark exists to close, so the caller is made to state it and the
    ///   floor below is all this function can check.
    pub fn rehydrate(
        binding: RecipientBinding,
        intervals: Vec<AccessInterval<Coordinate>>,
        expected: Option<Coordinate>,
        terminal: Option<ApplicationScheduleTerminalProof>,
        high_water: Option<Seq>,
    ) -> Result<Self, ReducerError> {
        for interval in &intervals {
            if !binding.matches(interval.binding()) {
                return Err(ReducerError::RecipientMismatch {
                    expected: binding.clone(),
                    found: interval.binding().clone(),
                });
            }
        }
        if let Some(proof) = &terminal {
            if !binding.matches(proof.binding()) {
                return Err(ReducerError::RecipientMismatch {
                    expected: binding.clone(),
                    found: proof.binding().clone(),
                });
            }
        }

        // Structural checks run before the coherence check below, because that
        // one asks whether `last()` is open — a question with no meaningful
        // answer until the list is known to be ordered.
        for pair in intervals.windows(2) {
            let (earlier, later) = (&pair[0], &pair[1]);
            let earlier_opening = earlier.opening().seq;
            let later_opening = later.opening().seq;

            if later_opening < earlier_opening {
                return Err(ReducerError::RestoredIntervalsOutOfOrder {
                    earlier_opening,
                    later_opening,
                });
            }
            let Some(close) = earlier.close() else {
                return Err(ReducerError::RestoredNonFinalIntervalOpen {
                    opening_seq: earlier_opening,
                });
            };
            // Equality is legal: a touching boundary is one row that closes the
            // predecessor and opens the successor at the same sequence.
            if later_opening < close.seq {
                return Err(ReducerError::RestoredIntervalsOverlap {
                    close_seq: close.seq,
                    opening_seq: later_opening,
                });
            }
        }

        let has_open_interval = intervals.last().is_some_and(AccessInterval::is_open);
        if has_open_interval != expected.is_some() {
            return Err(ReducerError::RestoredScheduleIncoherent {
                has_open_interval,
                has_expected_context: expected.is_some(),
            });
        }

        // The floor: every sequence the restored schedule itself records was
        // consumed, so the mark cannot sit below any of them. It may legally
        // sit above all of them — that is exactly the consumed-control case the
        // interval list cannot express.
        let recorded = intervals
            .iter()
            .flat_map(|interval| {
                [
                    Some(interval.opening().seq),
                    interval.close().map(|close| close.seq),
                ]
            })
            .chain([terminal.as_ref().map(ApplicationScheduleTerminalProof::seq)])
            .flatten()
            .max();
        if let Some(recorded) = recorded {
            if high_water.is_none_or(|mark| mark < recorded) {
                return Err(ReducerError::RestoredHighWaterBelowSchedule {
                    high_water,
                    recorded,
                });
            }
        }

        Ok(Self {
            binding,
            intervals,
            expected,
            terminal,
            high_water,
        })
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

    /// The greatest sequence this schedule has already consumed.
    ///
    /// Every row this reducer accepts must sit strictly above it, and accepting
    /// one moves it. `None` means nothing has been consumed yet.
    ///
    /// The interval list cannot stand in for this. An interval records only
    /// where it opened and where it closed, so the sequential control rows
    /// consumed *within* it leave no mark — and comparing a later row against
    /// the interval's **opening** therefore accepts anything above the opening,
    /// including a sequence the schedule already moved past. That is what let a
    /// terminal at seq 2 land after a control at seq 100: irreversible proof
    /// deposited below consumed history, with the entries between them already
    /// treated as visible.
    ///
    /// A touching boundary does not violate the rule despite sharing a
    /// sequence. Sharing happens **within one row**: the boundary is one
    /// authenticated event, checked once against the mark it inherits and then
    /// recorded once. The successor interval's opening is not a second
    /// consumption.
    pub fn high_water(&self) -> Option<Seq> {
        self.high_water
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
        let opening_seq = opening.seq;
        self.intervals
            .push(AccessInterval::open(self.binding.clone(), opening));
        self.expected = Some(context);
        self.record_applied(opening_seq);
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

        if !self.has_open_interval() {
            return Err(ReducerError::NoOpenInterval { seq: row.seq });
        }
        // The high-water mark is at least this interval's opening, so this one
        // comparison is both "after the opening" and "after everything already
        // consumed inside it".
        self.require_advances_high_water(row.seq)?;

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
        self.record_applied(row.seq);
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

    /// Requires a row to sit strictly above everything already consumed.
    ///
    /// The one comparison every accepting path makes. Kept separate from the
    /// interval-relative rules because it is a *schedule* rule: it holds across
    /// closes, gaps, and reanchors, where "this interval's opening" does not
    /// exist or no longer means anything.
    fn require_advances_high_water(&self, seq: Seq) -> Result<(), ReducerError> {
        match self.high_water {
            Some(mark) if !seq.is_strictly_after(mark) => Err(ReducerError::NotAdvancing {
                expected_after: mark,
                found: seq,
            }),
            _ => Ok(()),
        }
    }

    /// Requires a close to land strictly after its own interval's opening.
    ///
    /// [`AccessInterval::apply_close`] enforces this too, but only at the point
    /// where it mutates. Asking first keeps every fallible check ahead of every
    /// state change, and keeps the specific `CloseNotAfterOpening` refusal
    /// rather than the schedule-level one for a close inside its own opening.
    fn require_close_after_opening(&self, close_seq: Seq) -> Result<(), ReducerError> {
        let Some(open) = self.open_interval() else {
            return Ok(());
        };
        let opening_seq = open.opening().seq;
        if !close_seq.is_strictly_after(opening_seq) {
            return Err(ReducerError::Interval(
                super::interval::IntervalError::CloseNotAfterOpening {
                    opening_seq,
                    close_seq,
                },
            ));
        }
        Ok(())
    }

    /// Records a row as consumed, moving the high-water mark to its sequence.
    ///
    /// Called only after a row has been accepted, and only once per row — a
    /// touching boundary is one row and calls this once, which is why sharing a
    /// sequence between its close and its opening is not a violation.
    fn record_applied(&mut self, seq: Seq) {
        debug_assert!(
            self.high_water.is_none_or(|mark| seq > mark),
            "every accepting path checks the high-water mark before applying"
        );
        self.high_water = Some(seq);
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
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x11; 32]),
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
