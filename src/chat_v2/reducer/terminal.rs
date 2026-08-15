//! The two Terminal paths.
//!
//! CHAT_PROTOCOL.md §6 gives a terminal conversation close two distinct effects
//! on an exact-device schedule, depending on whether that device still held
//! access when the close landed:
//!
//! > If that interval is open, a terminal conversation-close row also requires
//! > `previous == expected`, closes the interval, and atomically marks the
//! > recipient schedule terminal. If the last interval already closed by Remove
//! > or Reset, a later exact signed recipient/conversation-bound Terminal
//! > control instead installs a separate irreversible schedule-level terminal
//! > proof without rewriting the old interval close or granting gap history.
//! > Across that inaccessible gap, Terminal does not claim its `previous` equals
//! > the reducer's stale expected context; the upstream authenticated outer
//! > Terminal authority verifies the predecessor. After either terminal mode, no
//! > later row or reanchor is accepted.
//!
//! # Atomicity is the whole point of the first path
//!
//! A close without the proof leaves the schedule looking finished while still
//! accepting rows; a proof without the close leaves an interval open forever.
//! Either half alone is worse than neither. So
//! [`ApplicationReducer::apply_terminal`] performs every check that can fail
//! *before* it touches any state, and then applies the close and installs the
//! proof with nothing fallible between them. That is why the ordinary close
//! paths still refuse `CloseKind::Terminal` by name rather than being widened to
//! accept it: they have no proof to install, and a caller reaching for them with
//! a Terminal row is at the wrong entry point.
//!
//! # The second path must not borrow authority it does not have
//!
//! When the last interval already closed, the reducer's expected context is
//! gone, and whatever it held before is stale by an inaccessible gap. Comparing
//! the Terminal row's `previous` against it would either fail on a legitimate
//! row or, worse, invite a client to reconstruct the gap in order to make the
//! comparison succeed. The outer Terminal authority has already verified the
//! real predecessor, so this path installs the proof and touches nothing else:
//! it does not re-close, does not rewrite the existing close, and grants no
//! visibility the schedule did not already have.

use super::{ApplicationReducer, ReducerError};
use crate::chat_v2::coordinate::Coordinate;
use crate::chat_v2::ids::{Seq, TransitionId};
use crate::chat_v2::interval::{ApplicationScheduleTerminalProof, CloseProof, RecipientBinding};
use crate::chat_v2::provenance::{CloseKind, OuterEntryFingerprint};

/// An authenticated terminal conversation-close row addressed to this device.
///
/// Construction implies the envelope layer has verified the row's shape,
/// conversation binding, transcript, signature, and fingerprint, and that the
/// outer Terminal authority established the predecessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalClose {
    /// The close row's append sequence.
    pub seq: Seq,
    /// The audience the row is routed to.
    pub recipient: RecipientBinding,
    /// The coordinate the verified outer Terminal authority proved.
    ///
    /// Compared against this device's expected context **only** when an interval
    /// is still open. Across an inaccessible gap the reducer's expected context
    /// is stale, and §6 is explicit that Terminal does not claim equality with
    /// it.
    pub previous: Coordinate,
    /// The signed closing control's transition ID.
    pub transition_id: TransitionId,
    /// The authenticated outer fingerprint of the closing row.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
}

/// Which of §6's two terminal modes applied.
///
/// Returned rather than accepted: the mode follows from whether this device
/// still held access, which the reducer knows and the caller cannot override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalMode {
    /// An interval was open. It closed inclusively at the Terminal seq and the
    /// schedule proof installed in the same step.
    ClosedOpenInterval,
    /// The last interval had already closed by Remove or Reset. Only the
    /// schedule-level proof installed; the old close is untouched.
    ScheduleProofOnly,
}

impl ApplicationReducer {
    /// Applies a verified terminal conversation-close row.
    ///
    /// Both modes are irreversible: afterwards every entry point refuses,
    /// including a second Terminal and any reanchor.
    pub fn apply_terminal(
        &mut self,
        terminal: &TerminalClose,
    ) -> Result<TerminalMode, ReducerError> {
        self.require_not_terminal(terminal.seq)?;
        self.require_recipient(&terminal.recipient)?;

        match self.open_interval() {
            Some(open) => {
                let opening_seq = open.opening().seq;
                self.close_open_interval_terminally(terminal, opening_seq)
            }
            None => self.install_schedule_proof_across_the_gap(terminal),
        }
    }

    /// §6 mode one: close the live interval and terminalize, atomically.
    fn close_open_interval_terminally(
        &mut self,
        terminal: &TerminalClose,
        opening_seq: Seq,
    ) -> Result<TerminalMode, ReducerError> {
        // Every fallible check runs first, so that the close and the proof land
        // together or not at all. A creation-open plus terminal close at the
        // same seq is the named negative this rejects.
        if !terminal.seq.is_strictly_after(opening_seq) {
            return Err(ReducerError::NotAdvancing {
                expected_after: opening_seq,
                found: terminal.seq,
            });
        }
        self.require_expected_predecessor(terminal.seq, &terminal.previous)?;

        self.intervals_mut()
            .last_mut()
            .expect("an open interval was just observed")
            .apply_close(CloseProof {
                seq: terminal.seq,
                kind: CloseKind::Terminal,
                transition_id: terminal.transition_id,
                outer_entry_fingerprint: terminal.outer_entry_fingerprint,
            })
            .expect("the close seq was just checked against this interval's opening");
        self.clear_expected();
        self.install_schedule_terminal_proof(terminal);
        Ok(TerminalMode::ClosedOpenInterval)
    }

    /// §6 mode two: install only the schedule proof, across an inaccessible gap.
    fn install_schedule_proof_across_the_gap(
        &mut self,
        terminal: &TerminalClose,
    ) -> Result<TerminalMode, ReducerError> {
        let Some(last) = self.intervals().last() else {
            // A schedule that never had an interval has nothing to finalize.
            // §9 entitles a *historical* exact-device recipient schedule to
            // fetch the Terminal control for schedule-level finalization; a
            // device with no history is not one.
            return Err(ReducerError::TerminalWithoutSchedule { seq: terminal.seq });
        };
        let close = last
            .close()
            .expect("a non-open interval always carries a close proof");
        let close_seq = close.seq;

        // Exhaustive and wildcard-free. §6 names Remove and Reset, and the
        // other two are refused rather than waved through.
        match close.kind {
            CloseKind::Remove | CloseKind::Reset => {}
            CloseKind::Replace | CloseKind::Terminal => {
                // A Replace close always touches an `Add` successor on the one
                // shared row, so a Replace-closed *last* interval means that
                // successor was never installed and the schedule is malformed.
                // A Terminal-closed interval cannot be reached at all, because
                // this function is the only thing that produces one and it
                // installs the proof that `require_not_terminal` would have
                // caught above. Both are refused by name.
                return Err(ReducerError::TerminalAfterUnsupportedClose {
                    close_seq,
                    kind: close.kind,
                });
            }
        }

        if !terminal.seq.is_strictly_after(close_seq) {
            return Err(ReducerError::NotAdvancing {
                expected_after: close_seq,
                found: terminal.seq,
            });
        }

        // `terminal.previous` is deliberately not consulted. See the module
        // documentation: the outer Terminal authority verified the predecessor,
        // and the reducer's expected context is stale by an inaccessible gap.
        self.install_schedule_terminal_proof(terminal);
        Ok(TerminalMode::ScheduleProofOnly)
    }

    /// Records the at-most-one immutable schedule terminal proof.
    fn install_schedule_terminal_proof(&mut self, terminal: &TerminalClose) {
        let binding = self.binding().clone();
        self.terminal = Some(ApplicationScheduleTerminalProof::new(
            binding,
            terminal.seq,
            terminal.transition_id,
            terminal.outer_entry_fingerprint,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::coordinate::Lifecycle;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger};
    use crate::chat_v2::interval::IntervalOpening;
    use crate::chat_v2::provenance::OpeningKind;
    use crate::chat_v2::reducer::{
        ReanchorAuthority, ResetActivation, ResetParticipation, SequentialClose, SequentialControl,
        TouchingBoundary,
    };

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING: &str = "72727272-7272-4272-b272-727272727272";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
    const CLOSING_TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";
    const TERMINAL_TRANSITION: &str = "5f6e7d8c-9b0a-4132-8465-a7b8c9d0e1f2";

    fn seq(value: i64) -> Seq {
        Seq::new(value).unwrap()
    }

    fn binding_for(device: &str) -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(CONVERSATION).unwrap(),
            BareDid::parse(DID).unwrap(),
            DeviceId::parse(device).unwrap(),
        )
    }

    fn binding() -> RecipientBinding {
        binding_for(DEVICE)
    }

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

    fn opening(at: i64, kind: OpeningKind, context: Coordinate) -> IntervalOpening<Coordinate> {
        IntervalOpening {
            seq: seq(at),
            kind,
            transition_id: TransitionId::parse(TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x11; 32]),
            context,
        }
    }

    fn closing(at: i64, kind: CloseKind, previous: Coordinate) -> SequentialClose {
        SequentialClose {
            seq: seq(at),
            recipient: binding(),
            previous,
            kind,
            transition_id: TransitionId::parse(CLOSING_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
        }
    }

    fn terminal(at: i64, previous: Coordinate) -> TerminalClose {
        TerminalClose {
            seq: seq(at),
            recipient: binding(),
            previous,
            transition_id: TransitionId::parse(TERMINAL_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x5a; 32]),
        }
    }

    /// A device holding an open interval opened at seq 1 on `coordinate(0)`.
    fn open_at_one() -> ApplicationReducer {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        reducer
    }

    /// A device whose interval closed by `kind` at seq 3.
    fn closed_at_three(kind: CloseKind) -> ApplicationReducer {
        let mut reducer = open_at_one();
        reducer
            .close_interval(&closing(3, kind, coordinate(0)))
            .unwrap();
        reducer
    }

    // ---- mode one: an open interval ----------------------------------------

    #[test]
    fn a_terminal_over_an_open_interval_closes_and_terminalizes_together() {
        let mut reducer = open_at_one();
        assert_eq!(
            reducer.apply_terminal(&terminal(9, coordinate(0))).unwrap(),
            TerminalMode::ClosedOpenInterval
        );

        // Both halves, from one row. Either alone would be a defect.
        let close = reducer.intervals()[0]
            .close()
            .expect("the open interval must have closed");
        assert_eq!(close.seq, seq(9));
        assert_eq!(close.kind, CloseKind::Terminal);

        let proof = reducer
            .terminal_proof()
            .expect("the schedule proof must have installed");
        assert_eq!(proof.seq(), seq(9));
        assert_eq!(
            proof.transition_id(),
            TransitionId::parse(TERMINAL_TRANSITION).unwrap()
        );
        assert!(proof.binding().matches(&binding()));
        assert!(reducer.is_terminal());
        assert!(!reducer.has_open_interval());
        assert!(reducer.expected_context().is_none());
    }

    #[test]
    fn a_terminal_over_an_open_interval_requires_the_expected_predecessor() {
        let mut reducer = open_at_one();
        assert!(matches!(
            reducer
                .apply_terminal(&terminal(9, coordinate(7)))
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));
    }

    #[test]
    fn a_refused_terminal_leaves_neither_a_close_nor_a_proof() {
        // The atomicity requirement read backwards: a refusal must not deposit
        // half of the transition. A schedule holding a proof but no close, or a
        // close but no proof, is worse than one holding neither.
        for row in [terminal(9, coordinate(7)), terminal(1, coordinate(0))] {
            let mut reducer = open_at_one();
            assert!(reducer.apply_terminal(&row).is_err());
            assert!(reducer.has_open_interval(), "the interval must stay open");
            assert!(reducer.intervals()[0].close().is_none());
            assert!(!reducer.is_terminal());
            assert!(reducer.terminal_proof().is_none());
            assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
        }
    }

    #[test]
    fn a_creation_open_and_terminal_close_at_the_same_seq_is_invalid() {
        // The named negative. Equality is legal only across adjacent intervals,
        // never between one interval's own opening and its close.
        let mut reducer = open_at_one();
        assert_eq!(
            reducer.apply_terminal(&terminal(1, coordinate(0))),
            Err(ReducerError::NotAdvancing {
                expected_after: seq(1),
                found: seq(1)
            })
        );
        assert!(!reducer.is_terminal());
    }

    #[test]
    fn a_terminal_close_is_inclusive() {
        let mut reducer = open_at_one();
        reducer.apply_terminal(&terminal(9, coordinate(0))).unwrap();
        assert!(reducer.is_application_visible(seq(9)), "inclusive close");
        assert!(!reducer.is_application_visible(seq(10)));
    }

    // ---- mode two: across an inaccessible gap ------------------------------

    #[test]
    fn a_terminal_after_a_remove_installs_only_the_schedule_proof() {
        let mut reducer = closed_at_three(CloseKind::Remove);
        assert_eq!(
            reducer
                .apply_terminal(&terminal(10, coordinate(0)))
                .unwrap(),
            TerminalMode::ScheduleProofOnly
        );

        // The old close is untouched: same seq, same kind, same row.
        let close = reducer.intervals()[0].close().unwrap();
        assert_eq!(close.seq, seq(3));
        assert_eq!(close.kind, CloseKind::Remove);
        assert_eq!(
            close.transition_id,
            TransitionId::parse(CLOSING_TRANSITION).unwrap(),
            "the Remove that closed the interval is a different row from the Terminal"
        );
        assert_eq!(reducer.intervals().len(), 1, "no interval was added");

        let proof = reducer.terminal_proof().unwrap();
        assert_eq!(proof.seq(), seq(10));
        assert_ne!(
            proof.outer_entry_fingerprint(),
            close.outer_entry_fingerprint
        );
    }

    #[test]
    fn a_terminal_after_a_reset_retirement_also_installs_only_the_proof() {
        // The retired old leaf of a reset: closed by Reset with no successor,
        // then finalized later by the conversation's Terminal.
        let mut reducer = open_at_one();
        reducer
            .apply_reset_activation(&ResetActivation {
                seq: seq(3),
                recipient: binding(),
                transition_id: TransitionId::parse(CLOSING_TRANSITION).unwrap(),
                outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
                previous: coordinate(0),
                participation: ResetParticipation::Retired,
            })
            .unwrap();

        assert_eq!(
            reducer
                .apply_terminal(&terminal(10, coordinate(0)))
                .unwrap(),
            TerminalMode::ScheduleProofOnly
        );
        assert_eq!(
            reducer.intervals()[0].close().unwrap().kind,
            CloseKind::Reset
        );
        assert_eq!(reducer.terminal_proof().unwrap().seq(), seq(10));
    }

    #[test]
    fn a_terminal_across_a_gap_does_not_compare_its_predecessor() {
        // §6: "Across that inaccessible gap, Terminal does not claim its
        // `previous` equals the reducer's stale expected context." Requiring the
        // comparison would invite a client to reconstruct the gap in order to
        // satisfy it.
        for state_version in [0, 7, 4_000] {
            let mut reducer = closed_at_three(CloseKind::Remove);
            assert_eq!(
                reducer
                    .apply_terminal(&terminal(10, coordinate(state_version)))
                    .unwrap(),
                TerminalMode::ScheduleProofOnly,
                "predecessor state version {state_version}"
            );
        }
    }

    #[test]
    fn a_terminal_across_a_gap_grants_no_gap_history() {
        let mut reducer = closed_at_three(CloseKind::Remove);
        reducer
            .apply_terminal(&terminal(10, coordinate(0)))
            .unwrap();

        assert!(reducer.is_application_visible(seq(3)), "inclusive close");
        for hidden in [4, 5, 9, 10, 11] {
            assert!(
                !reducer.is_application_visible(seq(hidden)),
                "seq {hidden} lies beyond the close and must stay inaccessible"
            );
        }
    }

    #[test]
    fn a_terminal_across_a_gap_must_follow_the_close() {
        for at in [2, 3] {
            let mut reducer = closed_at_three(CloseKind::Remove);
            assert_eq!(
                reducer.apply_terminal(&terminal(at, coordinate(0))),
                Err(ReducerError::NotAdvancing {
                    expected_after: seq(3),
                    found: seq(at)
                }),
                "terminal at {at} against a close at 3"
            );
            assert!(!reducer.is_terminal());
        }
    }

    #[test]
    fn only_remove_and_reset_admit_a_proof_only_terminal() {
        // A Replace close always touches an `Add` successor on one shared row,
        // so a Replace-closed last interval means the successor was never
        // installed. Refused by name rather than waved through.
        let mut reducer = closed_at_three(CloseKind::Replace);
        assert_eq!(
            reducer.apply_terminal(&terminal(10, coordinate(0))),
            Err(ReducerError::TerminalAfterUnsupportedClose {
                close_seq: seq(3),
                kind: CloseKind::Replace
            })
        );
        assert!(!reducer.is_terminal());
    }

    #[test]
    fn a_schedule_that_never_had_an_interval_cannot_be_terminalized() {
        let mut reducer = ApplicationReducer::new(binding());
        assert_eq!(
            reducer.apply_terminal(&terminal(10, coordinate(0))),
            Err(ReducerError::TerminalWithoutSchedule { seq: seq(10) })
        );
        assert!(!reducer.is_terminal());
    }

    // ---- irreversibility ----------------------------------------------------

    /// Every way of reaching a terminalized reducer, so that "no later row or
    /// reanchor is accepted" is checked against the whole surface rather than
    /// the one entry point that happened to come to mind.
    fn assert_everything_refuses_after(reducer: &ApplicationReducer, terminal_seq: Seq) {
        let expect_post_terminal = |result: Result<(), ReducerError>, path: &str| {
            let err = result.expect_err(path);
            assert!(
                matches!(err, ReducerError::PostTerminal { terminal_seq: t, .. } if t == terminal_seq),
                "{path} must refuse as post-terminal, got {err:?}"
            );
        };

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe.apply_sequential_control(&SequentialControl {
                seq: seq(50),
                recipient: binding(),
                previous: coordinate(0),
                next: coordinate(1),
            }),
            "sequential control",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe.close_interval(&closing(50, CloseKind::Remove, coordinate(0))),
            "ordinary close",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe.install_initial_opening(&binding(), opening(50, OpeningKind::Add, coordinate(0))),
            "initial opening",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe.reanchor(
                &binding(),
                ReanchorAuthority::VerifiedWelcome,
                opening(50, OpeningKind::Add, coordinate(0)),
            ),
            "reanchor",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe.apply_touching_boundary(&TouchingBoundary {
                seq: seq(50),
                recipient: binding(),
                close_kind: CloseKind::Replace,
                opening_kind: OpeningKind::Add,
                transition_id: TransitionId::parse(CLOSING_TRANSITION).unwrap(),
                outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
                previous: coordinate(0),
                opening_context: coordinate(1),
            }),
            "touching boundary",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe
                .apply_reset_activation(&ResetActivation {
                    seq: seq(50),
                    recipient: binding(),
                    transition_id: TransitionId::parse(CLOSING_TRANSITION).unwrap(),
                    outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
                    previous: coordinate(0),
                    participation: ResetParticipation::Retired,
                })
                .map(|_| ()),
            "reset activation",
        );

        let mut probe = reducer.clone();
        expect_post_terminal(
            probe
                .apply_terminal(&terminal(50, coordinate(0)))
                .map(|_| ()),
            "a second terminal",
        );
    }

    #[test]
    fn nothing_is_accepted_after_the_open_interval_mode() {
        let mut reducer = open_at_one();
        reducer.apply_terminal(&terminal(9, coordinate(0))).unwrap();
        assert_everything_refuses_after(&reducer, seq(9));
    }

    #[test]
    fn nothing_is_accepted_after_the_proof_only_mode() {
        let mut reducer = closed_at_three(CloseKind::Remove);
        reducer
            .apply_terminal(&terminal(10, coordinate(0)))
            .unwrap();
        assert_everything_refuses_after(&reducer, seq(10));
    }

    #[test]
    fn the_irreversibility_sweep_can_actually_fail() {
        // A control that cannot fail is not a control. A reducer that was never
        // terminalized must make the sweep's own assertion fail, proving it is
        // reading the guard rather than passing on everything.
        let untouched = open_at_one();
        let outcome = std::panic::catch_unwind(move || {
            assert_everything_refuses_after(&untouched, seq(9));
        });
        assert!(
            outcome.is_err(),
            "the sweep must reject a reducer that was never terminalized"
        );
    }

    // ---- the converted refusal ----------------------------------------------

    #[test]
    fn the_ordinary_close_paths_still_refuse_terminal_and_this_path_accepts_it() {
        // `TerminalRequiresScheduleProof` is not deleted by this slice; it is
        // given a destination. The ordinary paths have no proof to install, so a
        // Terminal row reaching them is at the wrong entry point — and the same
        // row applied here succeeds with both halves.
        let mut wrong_path = open_at_one();
        assert_eq!(
            wrong_path
                .close_interval(&closing(9, CloseKind::Terminal, coordinate(0)))
                .unwrap_err(),
            ReducerError::TerminalRequiresScheduleProof { seq: seq(9) }
        );
        assert!(wrong_path.has_open_interval());
        assert!(!wrong_path.is_terminal());

        let mut right_path = open_at_one();
        assert_eq!(
            right_path
                .apply_terminal(&terminal(9, coordinate(0)))
                .unwrap(),
            TerminalMode::ClosedOpenInterval
        );
        assert!(right_path.is_terminal());
        assert_eq!(
            right_path.intervals()[0].close().unwrap().kind,
            CloseKind::Terminal
        );
    }

    // ---- routing -------------------------------------------------------------

    #[test]
    fn a_sibling_device_terminal_never_terminalizes_this_schedule() {
        for mut reducer in [open_at_one(), closed_at_three(CloseKind::Remove)] {
            let mut row = terminal(10, coordinate(0));
            row.recipient = binding_for(SIBLING);
            assert!(matches!(
                reducer.apply_terminal(&row).unwrap_err(),
                ReducerError::RecipientMismatch { .. }
            ));
            assert!(!reducer.is_terminal());
        }
    }

    #[test]
    fn the_schedule_proof_names_this_exact_device() {
        // A proof must never satisfy a sibling's lookup: the two schedules are
        // different audiences and terminalize independently.
        let mut reducer = open_at_one();
        reducer.apply_terminal(&terminal(9, coordinate(0))).unwrap();
        let proof = reducer.terminal_proof().unwrap();
        assert!(proof.binding().matches(&binding()));
        assert!(!proof.binding().matches(&binding_for(SIBLING)));
    }
}
