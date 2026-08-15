//! Reset-activator classification.
//!
//! CHAT_PROTOCOL.md §6 gives a reset activation three distinct effects on an
//! exact-device schedule, and names all three in two sentences:
//!
//! > A registered active-admin reset activator who was not an old leaf may open
//! > its first `Reset` interval at the reset row: the outer reset verifier
//! > proves the predecessor, but that recipient had no pre-reset access.
//!
//! > An old-leaf reset activator uses touching `Reset`; every other old leaf
//! > only closes.
//!
//! §5 adds why the non-leaf case exists at all: "`activateReset` is uniformly
//! active-admin-only: an active registered device of an active admin DID may
//! activate without being an old-generation leaf."
//!
//! # The classification is derived, never asserted
//!
//! The three roles differ in exactly one respect the caller cannot be trusted
//! to report: whether *this* device held access when the reset landed. So
//! [`ResetActivation`] carries only what the verified row says — the row's
//! provenance and whether it installs this device as the successor genesis leaf
//! — and [`ApplicationReducer::apply_reset_activation`] derives the rest from
//! the reducer's own state.
//!
//! That is deliberate. The dangerous mistake here is an old leaf taking the
//! non-leaf path: the non-leaf path does not compare the row's `previous`
//! against an expected context, because a non-leaf has none. An old leaf routed
//! down it would skip the one check that stops it forking from its own history.
//! With the role derived rather than supplied, that mistake is unrepresentable
//! rather than merely refused — there is no argument a caller can pass to
//! request it.
//!
//! # Verifying the predecessor must not grant history
//!
//! The non-leaf activator's row does carry a `previous` coordinate, and the
//! outer reset verifier has already checked it. The reducer deliberately does
//! *not* re-check it and, more importantly, does not treat having seen it as
//! evidence of pre-reset access. The successor interval opens *at* the reset
//! seq, so the existing rule that entries below an opening are never visible is
//! what keeps the pre-reset history inaccessible. Both halves are pinned by
//! tests below.
//!
//! # Correction to `HANDOFF.md` §4: this is not a reanchor
//!
//! An earlier draft of the handoff said the non-leaf activator "opens its first
//! `Reset` interval at the reset row via `reanchor`". **It does not, and it
//! cannot.** [`super::reanchor::ReanchorAuthority`] is a closed two-variant enum
//! naming the only sources §6 accepts as reanchor proof — a verified Welcome and
//! a verified post-join opening — and reset activation is neither. Widening it
//! would have dissolved the prohibition that enum exists to enforce, so case 2
//! got its own private path ([`ApplicationReducer::open_activator_genesis`]) and
//! `ReanchorAuthority` was left untouched.
//!
//! No new authority marker type was introduced for reset either. The row's
//! [`OuterEntryFingerprint`] is already constructible only by the
//! envelope-verification layer, which is the same structural gate
//! `ReanchorAuthority` provides; a single-variant marker enum alongside it would
//! be invented surface excluding nothing the fingerprint does not already
//! exclude.
//!
//! # "Not an old leaf" means not a leaf *at the reset*
//!
//! A device removed at seq 3 can activate a reset at seq 20, so a non-leaf
//! activator may still carry an older closed interval. The admitting sentence is
//! §5, verbatim:
//!
//! > `activateReset` is uniformly active-admin-only: an active registered device
//! > of an active admin DID may activate without being an old-generation leaf.
//!
//! Interval history is therefore not an admission criterion. Whether the device
//! is currently active, registered, and admin is the *authority* layer's
//! question and is answered server-side; the reducer's job is only the schedule
//! constraint, which is that the new opening must clear any earlier close
//! strictly. That separation is why the refusals here are the neutral interval
//! errors rather than a reset-specific one — a bespoke error would encode
//! admission policy into the schedule layer, where it does not belong.
//!
//! This reading is pinned by
//! `a_previously_removed_activator_opens_after_a_strict_gap`.

use super::{ApplicationReducer, ReducerError, SequentialClose, TouchingBoundary};
use crate::chat_v2::coordinate::Coordinate;
use crate::chat_v2::ids::{Seq, TransitionId};
use crate::chat_v2::interval::{AccessInterval, IntervalError, IntervalOpening, RecipientBinding};
use crate::chat_v2::provenance::{CloseKind, OpeningKind, OuterEntryFingerprint};

/// What a verified reset activation row does to this exact device.
///
/// This is the part the row itself states. Whether the device was an old leaf
/// is not here, because the reducer knows it and the caller might be wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetParticipation {
    /// The row installs this exact device as the sole successor genesis leaf.
    Activator {
        /// The successor generation's opening context, which becomes expected.
        opening_context: Coordinate,
    },
    /// The row retires this device's old-generation access and opens nothing.
    ///
    /// §5: other active participants recover later through their own signed
    /// requests. A reset never re-adds them, so there is no successor here.
    Retired,
}

/// An authenticated reset activation row, as it bears on one exact device.
///
/// Construction implies the envelope layer verified the row's shape,
/// transcript, signature, and fingerprint, and that the outer reset verifier
/// established the predecessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetActivation {
    /// The reset row's append sequence. Old intervals close here inclusively,
    /// and the activator's successor opens here.
    pub seq: Seq,
    /// The audience the row is routed to.
    pub recipient: RecipientBinding,
    /// The signed reset control's transition ID.
    pub transition_id: TransitionId,
    /// The authenticated outer fingerprint of the reset row.
    pub outer_entry_fingerprint: OuterEntryFingerprint,
    /// The pre-reset coordinate the verified outer reset row builds on.
    ///
    /// Compared against this device's expected context only when it held an
    /// open interval. A device with no pre-reset access has no expected context
    /// to compare against, and the outer verifier has already proved this
    /// predecessor — so requiring the comparison there would be requiring a
    /// device to know history it is not entitled to.
    pub previous: Coordinate,
    /// What the row does to this device.
    pub participation: ResetParticipation,
}

/// Which of §6's three reset roles this device turned out to hold.
///
/// Returned rather than accepted: the reducer derives it, and reporting it back
/// lets a caller log or display what happened without being able to influence
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetRole {
    /// The activator, which held an open interval. Its old interval closes and
    /// its successor opens on the one shared row: a touching `Reset -> Reset`.
    OldLeafActivator,
    /// The activator, which held no access. It opens its first `Reset` interval
    /// at the reset row and gains no pre-reset history.
    NonLeafActivator,
    /// An old leaf that is not the activator. It closes and opens nothing.
    RetiredOldLeaf,
}

impl ApplicationReducer {
    /// Applies a verified reset activation row, classifying this device's role.
    ///
    /// The role follows from the row's `participation` and this reducer's own
    /// state, and each role routes to the mechanism §6 requires for it:
    ///
    /// | Participation | Held access | Role | Mechanism |
    /// |---|---|---|---|
    /// | `Activator` | yes | [`ResetRole::OldLeafActivator`] | touching `Reset -> Reset` |
    /// | `Activator` | no | [`ResetRole::NonLeafActivator`] | first `Reset` interval at the reset row |
    /// | `Retired` | yes | [`ResetRole::RetiredOldLeaf`] | close only |
    /// | `Retired` | no | — | refused: the row touches nothing here |
    pub fn apply_reset_activation(
        &mut self,
        reset: &ResetActivation,
    ) -> Result<ResetRole, ReducerError> {
        self.require_not_terminal(reset.seq)?;
        self.require_recipient(&reset.recipient)?;

        // Exhaustive and wildcard-free: a fourth participation would fail to
        // compile here rather than falling into whichever arm was written last.
        match (&reset.participation, self.has_open_interval()) {
            (ResetParticipation::Activator { opening_context }, true) => {
                // One shared row closes the retired interval and opens the
                // successor, advancing exactly once. `apply_touching_boundary`
                // validates the old expected context on the close side, which
                // is precisely the check the non-leaf path must not perform and
                // this one must.
                self.apply_touching_boundary(&TouchingBoundary {
                    seq: reset.seq,
                    recipient: reset.recipient.clone(),
                    close_kind: CloseKind::Reset,
                    opening_kind: OpeningKind::Reset,
                    transition_id: reset.transition_id,
                    outer_entry_fingerprint: reset.outer_entry_fingerprint,
                    previous: reset.previous.clone(),
                    opening_context: opening_context.clone(),
                })?;
                Ok(ResetRole::OldLeafActivator)
            }
            (ResetParticipation::Activator { opening_context }, false) => {
                self.open_activator_genesis(reset, opening_context)?;
                Ok(ResetRole::NonLeafActivator)
            }
            (ResetParticipation::Retired, true) => {
                self.close_interval(&SequentialClose {
                    seq: reset.seq,
                    recipient: reset.recipient.clone(),
                    previous: reset.previous.clone(),
                    kind: CloseKind::Reset,
                    transition_id: reset.transition_id,
                    outer_entry_fingerprint: reset.outer_entry_fingerprint,
                })?;
                Ok(ResetRole::RetiredOldLeaf)
            }
            (ResetParticipation::Retired, false) => {
                // A registered sibling or roster-only device may legitimately
                // *see* the reset control row (§9), but it has no interval for
                // the row to retire. Applying it to this schedule anyway is a
                // routing mistake, and reporting success would invent a fourth
                // role the spec does not have.
                Err(ReducerError::ResetAffectsNoInterval { seq: reset.seq })
            }
        }
    }

    /// Opens the non-leaf activator's first `Reset` interval at the reset row.
    ///
    /// Deliberately does not consult `reset.previous`. See the module docs.
    fn open_activator_genesis(
        &mut self,
        reset: &ResetActivation,
        opening_context: &Coordinate,
    ) -> Result<(), ReducerError> {
        // A non-leaf activator may still have an older closed interval — it was
        // not a leaf *at the reset*, which does not mean it never was one. The
        // successor must then clear that close strictly. Sharing the seq would
        // be a touching boundary, and the only touching partner of this opening
        // is a `Reset` close from this same row, which by definition is not the
        // proof that closed an earlier interval.
        if let Some(previous) = self.intervals().last() {
            let close = previous
                .close()
                .expect("a non-open interval always carries a close proof");
            if !close.kind.permits_successor() {
                return Err(ReducerError::Interval(
                    IntervalError::SuccessorAfterTerminal {
                        close_seq: close.seq,
                    },
                ));
            }
            if !reset.seq.is_strictly_after(close.seq) {
                return Err(ReducerError::Interval(
                    IntervalError::SuccessorNotAfterPredecessor {
                        close_seq: close.seq,
                        opening_seq: reset.seq,
                    },
                ));
            }
        }

        let opening = IntervalOpening {
            seq: reset.seq,
            kind: OpeningKind::Reset,
            transition_id: reset.transition_id,
            outer_entry_fingerprint: reset.outer_entry_fingerprint,
            context: opening_context.clone(),
        };
        let binding = self.binding().clone();
        self.intervals_mut()
            .push(AccessInterval::open(binding, opening));
        self.set_expected(opening_context.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_v2::coordinate::Lifecycle;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger};
    use crate::chat_v2::reducer::SequentialControl;

    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING: &str = "72727272-7272-4272-b272-727272727272";
    const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
    const RESET_TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

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

    /// A pre-reset coordinate, distinguished only by state version.
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

    /// The successor generation's coordinate: a reset increments `generation`
    /// and installs a fresh group.
    fn successor_coordinate() -> Coordinate {
        Coordinate {
            conversation_id: ConversationId::parse(CONVERSATION).unwrap(),
            generation: SafeInteger::new(1).unwrap(),
            state_version: SafeInteger::new(50).unwrap(),
            group_id: [0xaa; 32],
            epoch: SafeInteger::ZERO,
            group_context_hash: [0xbb; 32],
            confirmation_tag: [0xcc; 32],
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

    fn activation(
        at: i64,
        previous: Coordinate,
        participation: ResetParticipation,
    ) -> ResetActivation {
        ResetActivation {
            seq: seq(at),
            recipient: binding(),
            transition_id: TransitionId::parse(RESET_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x99; 32]),
            previous,
            participation,
        }
    }

    fn activator(at: i64, previous: Coordinate) -> ResetActivation {
        activation(
            at,
            previous,
            ResetParticipation::Activator {
                opening_context: successor_coordinate(),
            },
        )
    }

    fn retired(at: i64, previous: Coordinate) -> ResetActivation {
        activation(at, previous, ResetParticipation::Retired)
    }

    /// A device holding an open interval opened at seq 1 on `coordinate(0)`.
    fn old_leaf() -> ApplicationReducer {
        let mut reducer = ApplicationReducer::new(binding());
        reducer
            .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
            .unwrap();
        reducer
    }

    /// A device that never held access in this conversation.
    fn never_a_leaf() -> ApplicationReducer {
        ApplicationReducer::new(binding())
    }

    // ---- case 1: the old-leaf activator -----------------------------------

    #[test]
    fn an_old_leaf_activator_uses_a_touching_reset_and_advances_once() {
        let mut reducer = old_leaf();
        assert_eq!(
            reducer
                .apply_reset_activation(&activator(9, coordinate(0)))
                .unwrap(),
            ResetRole::OldLeafActivator
        );

        assert_eq!(reducer.intervals().len(), 2);
        assert_eq!(
            reducer.expected_context(),
            Some(&successor_coordinate()),
            "the context advances once, to the successor generation"
        );

        // One row, so both sides carry the same authenticated proof.
        let closed = reducer.intervals()[0].close().unwrap();
        let opened = reducer.intervals()[1].opening();
        assert_eq!(closed.seq, seq(9));
        assert_eq!(closed.kind, CloseKind::Reset);
        assert_eq!(opened.seq, seq(9));
        assert_eq!(opened.kind, OpeningKind::Reset);
        assert_eq!(closed.transition_id, opened.transition_id);
        assert_eq!(
            closed.outer_entry_fingerprint,
            opened.outer_entry_fingerprint
        );
    }

    #[test]
    fn an_old_leaf_activator_still_validates_its_old_expected_context() {
        // The old leaf HAD access, so it can and must check that the reset
        // builds on the context it last observed. This is exactly the check the
        // non-leaf path omits, and an old leaf never gets to omit it.
        let mut reducer = old_leaf();
        assert!(matches!(
            reducer
                .apply_reset_activation(&activator(9, coordinate(7)))
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));
        assert_eq!(reducer.intervals().len(), 1);
        assert!(reducer.has_open_interval());
        assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
    }

    #[test]
    fn an_old_leaf_activator_keeps_its_pre_reset_history() {
        // Its interval closes inclusively at the reset seq, so everything it
        // could already see stays visible. Only the non-leaf activator starts
        // blind.
        let mut reducer = old_leaf();
        reducer
            .apply_reset_activation(&activator(9, coordinate(0)))
            .unwrap();
        for visible in [1, 5, 8, 9, 10, 100] {
            assert!(
                reducer.is_application_visible(seq(visible)),
                "seq {visible} must remain visible to the old-leaf activator"
            );
        }
    }

    // ---- case 2: the non-leaf activator ------------------------------------

    #[test]
    fn a_non_leaf_activator_opens_its_first_reset_interval_at_the_reset_row() {
        let mut reducer = never_a_leaf();
        assert_eq!(
            reducer
                .apply_reset_activation(&activator(9, coordinate(0)))
                .unwrap(),
            ResetRole::NonLeafActivator
        );

        assert_eq!(reducer.intervals().len(), 1);
        assert!(reducer.has_open_interval());
        assert_eq!(reducer.expected_context(), Some(&successor_coordinate()));

        let opened = reducer.intervals()[0].opening();
        assert_eq!(opened.seq, seq(9));
        assert_eq!(
            opened.kind,
            OpeningKind::Reset,
            "the opening kind records reset activation, not creation"
        );
    }

    #[test]
    fn a_non_leaf_activator_gains_no_pre_reset_access() {
        // The named prohibition. Verifying the outer reset predecessor tells
        // this device what the conversation looked like; it must not turn that
        // into permission to read what was said.
        let mut reducer = never_a_leaf();
        reducer
            .apply_reset_activation(&activator(9, coordinate(0)))
            .unwrap();

        for hidden in [1, 2, 5, 8] {
            assert!(
                !reducer.is_application_visible(seq(hidden)),
                "seq {hidden} predates the reset and must stay inaccessible"
            );
        }
        assert!(reducer.is_application_visible(seq(9)));
        assert!(reducer.is_application_visible(seq(10)));
    }

    #[test]
    fn a_non_leaf_activator_does_not_compare_the_verified_predecessor() {
        // A device with no pre-reset access has no expected context, so there
        // is nothing to compare against and the outer verifier has already done
        // the work. Any verified predecessor applies identically.
        for state_version in [0, 7, 4_000] {
            let mut reducer = never_a_leaf();
            assert_eq!(
                reducer
                    .apply_reset_activation(&activator(9, coordinate(state_version)))
                    .unwrap(),
                ResetRole::NonLeafActivator,
                "predecessor state version {state_version}"
            );
            assert_eq!(reducer.expected_context(), Some(&successor_coordinate()));
        }
    }

    #[test]
    fn a_non_leaf_activator_sequences_from_its_new_opening_context() {
        let mut reducer = never_a_leaf();
        reducer
            .apply_reset_activation(&activator(9, coordinate(0)))
            .unwrap();

        // The pre-reset context is not a valid predecessor for anything now.
        assert!(matches!(
            reducer
                .apply_sequential_control(&SequentialControl {
                    seq: seq(10),
                    recipient: binding(),
                    previous: coordinate(0),
                    next: coordinate(1),
                })
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));

        reducer
            .apply_sequential_control(&SequentialControl {
                seq: seq(10),
                recipient: binding(),
                previous: successor_coordinate(),
                next: coordinate(60),
            })
            .expect("rows after the activation build on the successor context");
        assert_eq!(reducer.expected_context(), Some(&coordinate(60)));
    }

    #[test]
    fn a_previously_removed_activator_opens_after_a_strict_gap() {
        // "Not an old leaf" does not mean "never a leaf". A device removed at
        // seq 3 and later activating a reset at seq 20 opens a fresh interval,
        // and the gap between them stays inaccessible.
        //
        // The exact sentence this rests on is §5: "`activateReset` is uniformly
        // active-admin-only: an active registered device of an active admin DID
        // may activate without being an old-generation leaf." Interval history
        // is not an admission criterion, so a device with a closed interval is
        // admitted and constrained only by the strict-gap schedule rule.
        // Admission itself is the authority layer's question, answered
        // server-side, which is why the refusal below is a neutral interval
        // error and not a reset-specific one.
        let mut reducer = old_leaf();
        reducer
            .close_interval(&SequentialClose {
                seq: seq(3),
                recipient: binding(),
                previous: coordinate(0),
                kind: CloseKind::Remove,
                transition_id: TransitionId::parse(TRANSITION).unwrap(),
                outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x44; 32]),
            })
            .unwrap();

        assert_eq!(
            reducer
                .apply_reset_activation(&activator(20, coordinate(0)))
                .unwrap(),
            ResetRole::NonLeafActivator
        );
        assert_eq!(reducer.intervals().len(), 2);

        // The old interval keeps its own Remove close; the reset did not
        // rewrite it.
        let old_close = reducer.intervals()[0].close().unwrap();
        assert_eq!(old_close.seq, seq(3));
        assert_eq!(old_close.kind, CloseKind::Remove);

        for hidden in [4, 10, 19] {
            assert!(
                !reducer.is_application_visible(seq(hidden)),
                "seq {hidden} lies in the inaccessible gap"
            );
        }
        assert!(reducer.is_application_visible(seq(3)), "inclusive close");
        assert!(reducer.is_application_visible(seq(20)));
    }

    #[test]
    fn a_non_leaf_activation_may_not_open_at_or_before_an_earlier_close() {
        for at in [1, 3] {
            let mut reducer = old_leaf();
            reducer
                .close_interval(&SequentialClose {
                    seq: seq(3),
                    recipient: binding(),
                    previous: coordinate(0),
                    kind: CloseKind::Remove,
                    transition_id: TransitionId::parse(TRANSITION).unwrap(),
                    outer_entry_fingerprint: OuterEntryFingerprint::from_verified([0x44; 32]),
                })
                .unwrap();

            assert_eq!(
                reducer.apply_reset_activation(&activator(at, coordinate(0))),
                Err(ReducerError::Interval(
                    IntervalError::SuccessorNotAfterPredecessor {
                        close_seq: seq(3),
                        opening_seq: seq(at)
                    }
                )),
                "activation at {at} against a close at 3"
            );
            assert_eq!(reducer.intervals().len(), 1);
            assert!(reducer.expected_context().is_none());
        }
    }

    // ---- case 3: every other old leaf --------------------------------------

    #[test]
    fn every_other_old_leaf_only_closes() {
        let mut reducer = old_leaf();
        assert_eq!(
            reducer
                .apply_reset_activation(&retired(9, coordinate(0)))
                .unwrap(),
            ResetRole::RetiredOldLeaf
        );

        assert_eq!(reducer.intervals().len(), 1, "no successor opens");
        assert!(!reducer.has_open_interval());
        assert!(
            reducer.expected_context().is_none(),
            "a retired leaf has no context to sequence against"
        );

        let close = reducer.intervals()[0].close().unwrap();
        assert_eq!(close.seq, seq(9));
        assert_eq!(close.kind, CloseKind::Reset);
    }

    #[test]
    fn a_retired_old_leaf_may_not_sequence_through_the_reset() {
        let mut reducer = old_leaf();
        reducer
            .apply_reset_activation(&retired(9, coordinate(0)))
            .unwrap();
        assert_eq!(
            reducer
                .apply_sequential_control(&SequentialControl {
                    seq: seq(10),
                    recipient: binding(),
                    previous: successor_coordinate(),
                    next: coordinate(60),
                })
                .unwrap_err(),
            ReducerError::NoOpenInterval { seq: seq(10) },
            "recovery is a later signed request, not a continuation"
        );
    }

    #[test]
    fn a_retired_old_leaf_sees_nothing_after_the_reset_seq() {
        let mut reducer = old_leaf();
        reducer
            .apply_reset_activation(&retired(9, coordinate(0)))
            .unwrap();
        assert!(reducer.is_application_visible(seq(9)), "inclusive close");
        assert!(!reducer.is_application_visible(seq(10)));
        assert!(!reducer.is_application_visible(seq(1_000)));
    }

    #[test]
    fn a_retirement_validates_the_expected_context_too() {
        let mut reducer = old_leaf();
        assert!(matches!(
            reducer
                .apply_reset_activation(&retired(9, coordinate(7)))
                .unwrap_err(),
            ReducerError::ContextMismatch { .. }
        ));
        assert!(reducer.has_open_interval());
    }

    // ---- the fourth combination is not a role ------------------------------

    #[test]
    fn a_reset_that_retires_nothing_here_is_refused_by_name() {
        // A registered sibling or roster-only device may legitimately receive
        // the reset control row, but it has no interval for the row to retire.
        // Reporting success would invent a fourth role §6 does not have.
        let mut reducer = never_a_leaf();
        assert_eq!(
            reducer.apply_reset_activation(&retired(9, coordinate(0))),
            Err(ReducerError::ResetAffectsNoInterval { seq: seq(9) })
        );
        assert!(reducer.intervals().is_empty());
        assert!(reducer.expected_context().is_none());
    }

    // ---- the classification itself ------------------------------------------

    #[test]
    fn the_role_is_derived_from_reducer_state_not_from_the_caller() {
        // The identical `Activator` row classifies differently against the two
        // schedules, and the caller has no argument with which to override it.
        // That is what makes "an old leaf takes the non-leaf path"
        // unrepresentable rather than merely refused.
        let row = activator(9, coordinate(0));

        let mut held_access = old_leaf();
        assert_eq!(
            held_access.apply_reset_activation(&row).unwrap(),
            ResetRole::OldLeafActivator
        );

        let mut held_none = never_a_leaf();
        assert_eq!(
            held_none.apply_reset_activation(&row).unwrap(),
            ResetRole::NonLeafActivator
        );

        // And the two really did take different paths: only one of them closed
        // a prior interval.
        assert_eq!(held_access.intervals().len(), 2);
        assert_eq!(held_none.intervals().len(), 1);
    }

    #[test]
    fn a_sibling_device_row_never_reaches_any_reset_path() {
        // Visibility is per exact (DID, deviceId). A reset naming a sibling as
        // activator must not open an interval here, nor retire this one.
        for participation in [
            ResetParticipation::Activator {
                opening_context: successor_coordinate(),
            },
            ResetParticipation::Retired,
        ] {
            let mut reducer = old_leaf();
            let mut row = activation(9, coordinate(0), participation);
            row.recipient = binding_for(SIBLING);
            assert!(matches!(
                reducer.apply_reset_activation(&row).unwrap_err(),
                ReducerError::RecipientMismatch { .. }
            ));
            assert_eq!(reducer.intervals().len(), 1);
            assert!(reducer.has_open_interval());
            assert_eq!(reducer.expected_context(), Some(&coordinate(0)));
        }
    }

    #[test]
    fn an_activation_may_not_share_its_own_intervals_opening_seq() {
        // The old-leaf path closes and opens at the same seq across two
        // intervals, which is legal. Closing an interval at its *own* opening
        // seq is not, and that check is not weakened by routing through here.
        let mut reducer = old_leaf();
        assert_eq!(
            reducer.apply_reset_activation(&activator(1, coordinate(0))),
            Err(ReducerError::Interval(
                IntervalError::CloseNotAfterOpening {
                    opening_seq: seq(1),
                    close_seq: seq(1)
                }
            ))
        );
        assert_eq!(reducer.intervals().len(), 1);
        assert!(reducer.has_open_interval());
    }
}
