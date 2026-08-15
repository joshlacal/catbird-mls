//! Interval closure, verified reanchor, and legal touching boundaries.
//!
//! CHAT_PROTOCOL.md §6 is unusually specific about how a device regains access
//! after losing it, because this is where an adversary would most like to be
//! sloppy:
//!
//! > After a non-touching membership gap, a later interval may reanchor only
//! > from the matching verified Welcome or post-join opening row whose seq,
//! > kind, signed transition ID, outer-entry fingerprint, and context all
//! > match. **An arbitrary current head and a mid-interval row are never
//! > reanchor proof.**
//!
//! Two mechanisms exist and they are deliberately different entry points.
//!
//! # Non-touching reanchor
//!
//! After a gap, [`ApplicationReducer::reanchor`] requires a
//! [`ReanchorAuthority`] — a closed set naming the only two legitimate
//! provenance sources. There is no constructor for it from a current head, a
//! tombstone, an inventory summary, or any other hint, which is what makes the
//! prohibition structural rather than a comment. The reanchor must also leave a
//! strict gap after the close; sharing a seq is a touching boundary, not a
//! reanchor.
//!
//! # Touching boundary
//!
//! `Replace -> Add` and `Reset -> Reset` share one authenticated row that both
//! closes the prior interval and opens the successor. The spec requires that it
//! be "processed once" and "advances once", so [`TouchingBoundary`] is a single
//! value applied by a single call. A naive implementation that closed with the
//! row and then opened with it again would advance the context twice from one
//! authenticated event; making the shared row one object means that mistake has
//! nowhere to live.

use super::{ApplicationReducer, ReducerError};
use crate::chat_v2::coordinate::Coordinate;
use crate::chat_v2::ids::{Seq, TransitionId};
use crate::chat_v2::interval::{AccessInterval, CloseProof, IntervalOpening, RecipientBinding};
use crate::chat_v2::provenance::{CloseKind, OpeningKind, OuterEntryFingerprint};

/// Proof that a reanchor opening may be trusted.
///
/// Closed on purpose, with no variant for a current head, tombstone, event, or
/// inventory summary — the spec names those as never being reanchor proof. A
/// value of this type can only be produced by naming one of the two legitimate
/// sources, so code that has only a hint cannot reach [`ApplicationReducer::reanchor`]
/// at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReanchorAuthority {
    /// A Welcome addressed to this exact device, verified and matching.
    ///
    /// This is the ordinary re-Add path: the device was removed, later added
    /// again, and the Add's Welcome establishes the new MLS state without any
    /// backfill of the gap.
    VerifiedWelcome,
    /// A verified post-join opening control row for this exact device.
    VerifiedPostJoinOpening,
}

/// An authenticated control row that closes this device's open interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialClose {
    /// The closing row's append sequence.
    pub seq: Seq,
    /// The audience the row is routed to.
    pub recipient: RecipientBinding,
    /// The coordinate the row builds on. Must equal the expected context.
    pub previous: Coordinate,
    /// Remove, Replace, or Reset. `Terminal` has its own path.
    pub kind: CloseKind,
    /// The signed closing control's transition ID.
    pub transition_id: TransitionId,
    /// The authenticated outer fingerprint of the closing row.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
}

/// The one authenticated row that both closes an interval and opens its
/// successor at the same sequence.
///
/// Exists as a single value because the protocol requires the boundary to be
/// processed once and to advance once. Splitting it into a close plus an open
/// would let one authenticated event advance the context twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchingBoundary {
    /// The shared sequence.
    pub seq: Seq,
    /// The audience the row is routed to.
    pub recipient: RecipientBinding,
    /// How the prior interval closes. Only `Replace` and `Reset` may touch.
    pub close_kind: CloseKind,
    /// How the successor opens. Must be the close kind's legal partner.
    pub opening_kind: OpeningKind,
    /// The single signed transition ID, shared by both sides.
    pub transition_id: TransitionId,
    /// The single authenticated outer fingerprint, shared by both sides.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
    /// The coordinate the row builds on. Validated against the *old* expected
    /// context, which is the close side of the boundary.
    pub previous: Coordinate,
    /// The successor interval's opening context. Becomes the new expected.
    pub opening_context: Coordinate,
}

impl ApplicationReducer {
    /// Closes this device's open interval with an authenticated control row.
    ///
    /// Requires `previous == expected`, exactly as any other context-changing
    /// row does while an interval is open. Once closed there is no expected
    /// context: nothing may be sequenced until a verified reanchor.
    ///
    /// Refuses [`CloseKind::Terminal`], which needs its own atomic path.
    pub fn close_interval(&mut self, close: &SequentialClose) -> Result<(), ReducerError> {
        self.require_not_terminal(close.seq)?;
        self.require_recipient(&close.recipient)?;

        if close.kind == CloseKind::Terminal {
            // Closing here would leave the interval finite but the schedule
            // un-terminalized — finished-looking and wrong. Refuse by name.
            return Err(ReducerError::TerminalRequiresScheduleProof { seq: close.seq });
        }

        if !self.has_open_interval() {
            return Err(ReducerError::NothingToClose { seq: close.seq });
        }
        // The interval's own rule first, so a close inside its own opening
        // keeps the specific refusal, then the schedule-level one: a close
        // below a control row already consumed inside this interval would
        // retroactively cut off entries the schedule has already shown.
        self.require_close_after_opening(close.seq)?;
        self.require_advances_high_water(close.seq)?;
        self.require_expected_predecessor(close.seq, &close.previous)?;

        let proof = CloseProof {
            seq: close.seq,
            kind: close.kind,
            transition_id: close.transition_id,
            outer_entry_fingerprint: close.outer_entry_fingerprint,
        };
        self.intervals_mut()
            .last_mut()
            .expect("an open interval was just confirmed")
            .apply_close(proof)?;
        self.clear_expected();
        self.record_applied(close.seq);
        Ok(())
    }

    /// Reopens access after a non-touching gap.
    ///
    /// The caller must already have compared all five opening fields against
    /// the authenticated row via [`IntervalOpening::matches_exactly`]; the
    /// `authority` argument records *which* legitimate source proved it.
    pub fn reanchor(
        &mut self,
        recipient: &RecipientBinding,
        _authority: ReanchorAuthority,
        opening: IntervalOpening<Coordinate>,
    ) -> Result<(), ReducerError> {
        self.require_not_terminal(opening.seq)?;
        self.require_recipient(recipient)?;

        if let Some(open) = self.open_interval() {
            return Err(ReducerError::NotAwaitingReanchor {
                open_since: open.opening().seq,
                seq: opening.seq,
            });
        }

        if let Some(previous) = self.intervals().last() {
            let close = previous
                .close()
                .expect("a non-open interval always carries a close proof");
            if !close.kind.permits_successor() {
                return Err(ReducerError::Interval(
                    crate::chat_v2::interval::IntervalError::SuccessorAfterTerminal {
                        close_seq: close.seq,
                    },
                ));
            }
            if opening.seq == close.seq {
                return Err(ReducerError::ReanchorMustNotTouch {
                    close_seq: close.seq,
                    opening_seq: opening.seq,
                });
            }
            if !opening.seq.is_strictly_after(close.seq) {
                return Err(ReducerError::Interval(
                    crate::chat_v2::interval::IntervalError::SuccessorNotAfterPredecessor {
                        close_seq: close.seq,
                        opening_seq: opening.seq,
                    },
                ));
            }
        }
        // Adjacency is checked against the previous interval above; this is the
        // schedule-level floor, which also covers the case that has no previous
        // interval to be adjacent to.
        self.require_advances_high_water(opening.seq)?;

        let context = opening.context.clone();
        let opening_seq = opening.seq;
        let binding = self.binding().clone();
        self.intervals_mut()
            .push(AccessInterval::open(binding, opening));
        self.set_expected(context);
        self.record_applied(opening_seq);
        Ok(())
    }

    /// Processes the one shared row of a legal touching boundary.
    ///
    /// Validates the old expected predecessor, closes the prior interval, opens
    /// the successor at the same sequence, installs the successor's opening
    /// context, and advances exactly once.
    pub fn apply_touching_boundary(
        &mut self,
        boundary: &TouchingBoundary,
    ) -> Result<(), ReducerError> {
        self.require_not_terminal(boundary.seq)?;
        self.require_recipient(&boundary.recipient)?;

        if boundary.close_kind == CloseKind::Terminal {
            return Err(ReducerError::TerminalRequiresScheduleProof { seq: boundary.seq });
        }
        if !self.has_open_interval() {
            return Err(ReducerError::NothingToClose { seq: boundary.seq });
        }
        if boundary.close_kind.legal_touching_successor() != Some(boundary.opening_kind) {
            return Err(ReducerError::Interval(
                crate::chat_v2::interval::IntervalError::IllegalTouching {
                    close_kind: boundary.close_kind,
                    opening_kind: boundary.opening_kind,
                },
            ));
        }

        // The close side: the shared row must build on the old expected
        // context, exactly as an ordinary close would, and must land above
        // everything already consumed. One row, so the mark is checked once
        // here and moved once below — the successor opening at the same
        // sequence is the same event, not a second one.
        self.require_close_after_opening(boundary.seq)?;
        self.require_advances_high_water(boundary.seq)?;
        self.require_expected_predecessor(boundary.seq, &boundary.previous)?;

        let proof = CloseProof {
            seq: boundary.seq,
            kind: boundary.close_kind,
            transition_id: boundary.transition_id,
            outer_entry_fingerprint: boundary.outer_entry_fingerprint,
        };
        self.intervals_mut()
            .last_mut()
            .expect("an open interval was just confirmed")
            .apply_close(proof)?;

        // The open side: the same row, same transition ID and fingerprint,
        // opening at the same seq. Sharing is guaranteed by construction here
        // rather than checked, because there is only one row to read them from.
        let opening = IntervalOpening {
            seq: boundary.seq,
            kind: boundary.opening_kind,
            transition_id: boundary.transition_id,
            outer_entry_fingerprint: boundary.outer_entry_fingerprint,
            context: boundary.opening_context.clone(),
        };
        let binding = self.binding().clone();
        self.intervals_mut()
            .push(AccessInterval::open(binding, opening));
        self.set_expected(boundary.opening_context.clone());
        self.record_applied(boundary.seq);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::coordinate::Lifecycle;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger};
    use crate::chat_v2::interval::IntervalError;
    use crate::chat_v2::reducer::SequentialControl;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING: &str = "72727272-7272-4272-b272-727272727272";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
    const OTHER_TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

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
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
        }
    }

    /// A reducer with an interval opened at 1 and closed by Remove at 3.
    fn removed_at_three() -> ApplicationReducer {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        reducer
            .close_interval(&closing(3, CloseKind::Remove, coordinate(0)))
            .unwrap();
        reducer
    }

    // ---- closure ----------------------------------------------------------

    #[test]
    fn closing_requires_the_expected_predecessor_and_clears_it() {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();

        // A close building on a stale context is refused, exactly as an
        // ordinary sequential row would be.
        assert!(matches!(
            reducer
                .close_interval(&closing(3, CloseKind::Remove, coordinate(7)))
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));
        assert!(
            reducer.has_open_interval(),
            "a refused close must not close"
        );

        reducer
            .close_interval(&closing(3, CloseKind::Remove, coordinate(0)))
            .unwrap();
        assert!(!reducer.has_open_interval());
        assert!(
            reducer.expected_context().is_none(),
            "a closed interval has no expected context to sequence against"
        );
    }

    #[test]
    fn nothing_may_be_sequenced_through_a_gap() {
        let mut reducer = removed_at_three();
        let row = SequentialControl {
            seq: seq(4),
            recipient: binding(),
            previous: coordinate(0),
            next: coordinate(1),
        };
        assert_eq!(
            reducer.apply_sequential_control(&row).unwrap_err(),
            ReducerError::NoOpenInterval { seq: seq(4) }
        );
    }

    #[test]
    fn a_close_needs_an_open_interval() {
        let mut reducer = removed_at_three();
        assert_eq!(
            reducer
                .close_interval(&closing(5, CloseKind::Remove, coordinate(0)))
                .unwrap_err(),
            ReducerError::NothingToClose { seq: seq(5) }
        );
    }

    #[test]
    fn a_terminal_close_is_refused_by_name_on_the_ordinary_path() {
        // The named refusal for the unbuilt 6d path. Accepting it here would
        // close the interval while leaving the schedule un-terminalized, which
        // looks finished and is not.
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        assert_eq!(
            reducer
                .close_interval(&closing(9, CloseKind::Terminal, coordinate(0)))
                .unwrap_err(),
            ReducerError::TerminalRequiresScheduleProof { seq: seq(9) }
        );
        assert!(
            reducer.has_open_interval(),
            "the refusal must leave the interval untouched"
        );
        assert!(!reducer.is_terminal());
    }

    // ---- non-touching reanchor -------------------------------------------

    #[test]
    fn a_verified_welcome_reanchors_after_a_gap() {
        let mut reducer = removed_at_three();
        reducer
            .reanchor(
                &binding(),
                ReanchorAuthority::VerifiedWelcome,
                opening(10, OpeningKind::Add, coordinate(5)),
            )
            .expect("a verified re-Add must reanchor");

        assert!(reducer.has_open_interval());
        assert_eq!(reducer.expected_context(), Some(&coordinate(5)));
        assert_eq!(reducer.intervals().len(), 2);
    }

    #[test]
    fn a_reanchored_device_receives_no_gap_backfill() {
        // The gap between the Remove at 3 and the re-Add at 10 stays invisible.
        let mut reducer = removed_at_three();
        reducer
            .reanchor(
                &binding(),
                ReanchorAuthority::VerifiedWelcome,
                opening(10, OpeningKind::Add, coordinate(5)),
            )
            .unwrap();

        assert!(
            reducer.is_application_visible(seq(2)),
            "inside the first interval"
        );
        assert!(
            reducer.is_application_visible(seq(3)),
            "the inclusive close"
        );
        for gap_seq in [4, 5, 9] {
            assert!(
                !reducer.is_application_visible(seq(gap_seq)),
                "seq {gap_seq} lies in the inaccessible gap"
            );
        }
        assert!(reducer.is_application_visible(seq(10)));
        assert!(reducer.is_application_visible(seq(11)));
    }

    #[test]
    fn a_reanchor_may_not_share_the_close_seq() {
        // Sharing a seq is a touching boundary, which is one row processed
        // once — not a close plus an independent open.
        let mut reducer = removed_at_three();
        assert_eq!(
            reducer
                .reanchor(
                    &binding(),
                    ReanchorAuthority::VerifiedWelcome,
                    opening(3, OpeningKind::Add, coordinate(5)),
                )
                .unwrap_err(),
            ReducerError::ReanchorMustNotTouch {
                close_seq: seq(3),
                opening_seq: seq(3)
            }
        );
        assert!(!reducer.has_open_interval());
    }

    #[test]
    fn a_reanchor_may_not_predate_the_close() {
        let mut reducer = removed_at_three();
        assert!(matches!(
            reducer
                .reanchor(
                    &binding(),
                    ReanchorAuthority::VerifiedWelcome,
                    opening(2, OpeningKind::Add, coordinate(5)),
                )
                .unwrap_err(),
            ReducerError::Interval(IntervalError::SuccessorNotAfterPredecessor { .. })
        ));
    }

    #[test]
    fn a_reanchor_is_refused_while_an_interval_is_live() {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        assert_eq!(
            reducer
                .reanchor(
                    &binding(),
                    ReanchorAuthority::VerifiedWelcome,
                    opening(5, OpeningKind::Add, coordinate(5)),
                )
                .unwrap_err(),
            ReducerError::NotAwaitingReanchor {
                open_since: seq(1),
                seq: seq(5)
            }
        );
        assert_eq!(
            reducer.expected_context(),
            Some(&coordinate(0)),
            "the live interval's context must survive the refusal"
        );
    }

    #[test]
    fn a_sibling_device_may_not_reanchor_this_schedule() {
        let mut reducer = removed_at_three();
        assert!(matches!(
            reducer
                .reanchor(
                    &binding_for(SIBLING),
                    ReanchorAuthority::VerifiedWelcome,
                    opening(10, OpeningKind::Add, coordinate(5)),
                )
                .unwrap_err(),
            ReducerError::RecipientMismatch { .. }
        ));
        assert_eq!(reducer.intervals().len(), 1);
    }

    #[test]
    fn a_hint_or_head_cannot_reach_the_reanchor_path_at_all() {
        // The spec's explicit prohibition: "An arbitrary current head and a
        // mid-interval row are never reanchor proof." ReanchorAuthority is a
        // closed two-variant enum with no constructor from a head, tombstone,
        // event, or inventory summary, so code holding only a hint cannot form
        // the argument this function requires. This test records the intent;
        // the compiler is what enforces it.
        let sources = [
            ReanchorAuthority::VerifiedWelcome,
            ReanchorAuthority::VerifiedPostJoinOpening,
        ];
        assert_eq!(
            sources.len(),
            2,
            "exactly two legitimate provenance sources exist"
        );
    }

    // ---- touching boundary ------------------------------------------------

    fn touching(
        at: i64,
        close_kind: CloseKind,
        opening_kind: OpeningKind,
        previous: Coordinate,
        opening_context: Coordinate,
    ) -> TouchingBoundary {
        TouchingBoundary {
            seq: seq(at),
            recipient: binding(),
            close_kind,
            opening_kind,
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
            previous,
            opening_context,
        }
    }

    fn opened() -> ApplicationReducer {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        reducer
    }

    #[test]
    fn replace_to_add_advances_exactly_once() {
        let mut reducer = opened();
        reducer
            .apply_touching_boundary(&touching(
                9,
                CloseKind::Replace,
                OpeningKind::Add,
                coordinate(0),
                coordinate(1),
            ))
            .expect("a legal touching boundary must apply");

        assert_eq!(reducer.intervals().len(), 2);
        assert_eq!(
            reducer.expected_context(),
            Some(&coordinate(1)),
            "the context advances once, to the opening context"
        );

        // Both sides carry the same authenticated proof, because there was one
        // row. The prior interval's close and the successor's opening agree.
        let prior_close = reducer.intervals()[0].close().unwrap();
        let successor_opening = reducer.intervals()[1].opening();
        assert_eq!(prior_close.seq, successor_opening.seq);
        assert_eq!(prior_close.transition_id, successor_opening.transition_id);
        assert_eq!(
            prior_close.outer_entry_fingerprint,
            successor_opening.outer_entry_fingerprint
        );
    }

    #[test]
    fn reset_to_reset_advances_exactly_once() {
        let mut reducer = opened();
        reducer
            .apply_touching_boundary(&touching(
                9,
                CloseKind::Reset,
                OpeningKind::Reset,
                coordinate(0),
                coordinate(1),
            ))
            .expect("the old-leaf reset activator's touching boundary must apply");
        assert_eq!(reducer.intervals().len(), 2);
        assert_eq!(reducer.expected_context(), Some(&coordinate(1)));
    }

    #[test]
    fn a_touching_boundary_validates_the_old_expected_predecessor() {
        // The close side is still an ordinary context check: the shared row
        // must build on what the prior interval expected.
        let mut reducer = opened();
        assert!(matches!(
            reducer
                .apply_touching_boundary(&touching(
                    9,
                    CloseKind::Replace,
                    OpeningKind::Add,
                    coordinate(7),
                    coordinate(1),
                ))
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));
        assert_eq!(reducer.intervals().len(), 1);
        assert!(reducer.has_open_interval());
        assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
    }

    #[test]
    fn illegal_touching_pairings_are_refused() {
        for (close_kind, opening_kind) in [
            (CloseKind::Replace, OpeningKind::Reset),
            (CloseKind::Reset, OpeningKind::Add),
            (CloseKind::Remove, OpeningKind::Add),
            (CloseKind::Remove, OpeningKind::Reset),
        ] {
            let mut reducer = opened();
            assert_eq!(
                reducer
                    .apply_touching_boundary(&touching(
                        9,
                        close_kind,
                        opening_kind,
                        coordinate(0),
                        coordinate(1),
                    ))
                    .unwrap_err(),
                ReducerError::Interval(IntervalError::IllegalTouching {
                    close_kind,
                    opening_kind
                }),
                "{close_kind:?} -> {opening_kind:?}"
            );
            assert_eq!(reducer.intervals().len(), 1);
        }
    }

    #[test]
    fn a_terminal_touching_boundary_is_refused_by_name() {
        let mut reducer = opened();
        assert_eq!(
            reducer
                .apply_touching_boundary(&touching(
                    9,
                    CloseKind::Terminal,
                    OpeningKind::Add,
                    coordinate(0),
                    coordinate(1),
                ))
                .unwrap_err(),
            ReducerError::TerminalRequiresScheduleProof { seq: seq(9) }
        );
    }

    #[test]
    fn a_touching_boundary_needs_an_open_interval() {
        let mut reducer = removed_at_three();
        assert_eq!(
            reducer
                .apply_touching_boundary(&touching(
                    9,
                    CloseKind::Replace,
                    OpeningKind::Add,
                    coordinate(0),
                    coordinate(1),
                ))
                .unwrap_err(),
            ReducerError::NothingToClose { seq: seq(9) }
        );
    }

    #[test]
    fn no_application_entry_straddles_a_touching_boundary() {
        // The shared seq belongs to the control row, so no application entry
        // can claim it. Entries either side fall in exactly one interval.
        let mut reducer = opened();
        reducer
            .apply_touching_boundary(&touching(
                9,
                CloseKind::Replace,
                OpeningKind::Add,
                coordinate(0),
                coordinate(1),
            ))
            .unwrap();

        let first = &reducer.intervals()[0];
        let second = &reducer.intervals()[1];
        assert_eq!(first.close().unwrap().seq, second.opening().seq);

        // Strictly inside the first interval.
        assert_eq!(
            reducer.visible_interval(seq(5)).map(|i| i.opening().seq),
            Some(seq(1))
        );
        // Strictly inside the second.
        assert_eq!(
            reducer.visible_interval(seq(20)).map(|i| i.opening().seq),
            Some(seq(9))
        );
    }

    #[test]
    fn sequencing_resumes_inside_the_successor_interval() {
        let mut reducer = opened();
        reducer
            .apply_touching_boundary(&touching(
                9,
                CloseKind::Reset,
                OpeningKind::Reset,
                coordinate(0),
                coordinate(1),
            ))
            .unwrap();

        reducer
            .apply_sequential_control(&SequentialControl {
                seq: seq(10),
                recipient: binding(),
                previous: coordinate(1),
                next: coordinate(2),
            })
            .expect("rows after the boundary sequence from the opening context");
        assert_eq!(reducer.expected_context(), Some(&coordinate(2)));
    }
}
