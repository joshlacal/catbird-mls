//! The schedule's seq high-water mark.
//!
//! Every reducer path used to compare an incoming row against the *interval*
//! it lands in — a control against the interval's opening, a terminal against
//! the opening or the previous close. None of them compared it against the rows
//! the schedule had already consumed, and an interval records only where it
//! opened and where it closed. So a control row applied at seq 100 left no mark
//! anywhere, and a close, terminal, or reanchor at seq 2 still looked like it
//! was "after the opening".
//!
//! The three cases below are the reproductions that showed it. Each one accepts
//! a row underneath history the schedule has already treated as consumed, and
//! the first deposits *irreversible* proof there.
//!
//! # Why one mark rather than a per-path rule
//!
//! The rule is a property of the schedule, not of any interval: it survives
//! closes, gaps, and reanchors, where "this interval's opening" either does not
//! exist or no longer means anything. A per-path comparison is also what got us
//! here — six entry points each choosing their own reference point, five of them
//! choosing one that a consumed row can slip beneath.
//!
//! # The touching boundary is not an exception
//!
//! A touching boundary shares one sequence between the close it performs and
//! the opening it performs. That is one authenticated row, checked once against
//! the mark it inherits and recorded once, so the shared sequence is a single
//! consumption rather than a second one at the same number. The last test here
//! pins that, because a high-water rule written as "strictly greater than
//! everything, including my own opening" would have broken a ratified schedule.

use super::reanchor::{SequentialClose, TouchingBoundary};
use super::reset::{ResetActivation, ResetParticipation};
use super::terminal::TerminalClose;
use super::{ApplicationReducer, ReanchorAuthority, ReducerError, SequentialControl};
use crate::chat_v2::coordinate::{Coordinate, Lifecycle};
use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger, Seq, TransitionId};
use crate::chat_v2::interval::{IntervalOpening, RecipientBinding};
use crate::chat_v2::provenance::{CloseKind, OpeningKind, OuterEntryFingerprint};

const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
const TRANSITION: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";
const OTHER_TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

fn seq(value: i64) -> Seq {
    Seq::new(value).unwrap()
}

fn binding() -> RecipientBinding {
    RecipientBinding::new(
        ConversationId::parse(CONVERSATION).unwrap(),
        BareDid::parse(DID).unwrap(),
        DeviceId::parse(DEVICE).unwrap(),
    )
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

fn closing(at: i64, kind: CloseKind, previous: Coordinate) -> SequentialClose {
    SequentialClose {
        seq: seq(at),
        recipient: binding(),
        previous,
        kind,
        transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
        outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
    }
}

fn terminal(at: i64, previous: Coordinate) -> TerminalClose {
    TerminalClose {
        seq: seq(at),
        recipient: binding(),
        previous,
        transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
        outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x5a; 32]),
    }
}

/// A schedule opened at seq 1 that has consumed a control row at `consumed`.
fn consumed_up_to(consumed: i64) -> ApplicationReducer {
    let mut reducer = ApplicationReducer::new(binding());
    reducer
        .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
        .expect("the initial opening must install");
    reducer
        .apply_sequential_control(&control(consumed, coordinate(0), coordinate(1)))
        .expect("a control row inside the interval must apply");
    reducer
}

// ---- the mark itself --------------------------------------------------------

#[test]
fn the_mark_starts_absent_and_follows_the_rows_that_are_applied() {
    let mut reducer = ApplicationReducer::new(binding());
    assert_eq!(reducer.high_water(), None, "nothing has been consumed yet");

    reducer
        .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
        .unwrap();
    assert_eq!(reducer.high_water(), Some(seq(1)));

    reducer
        .apply_sequential_control(&control(100, coordinate(0), coordinate(1)))
        .unwrap();
    assert_eq!(
        reducer.high_water(),
        Some(seq(100)),
        "a control row inside an interval moves the mark; the interval list cannot"
    );

    reducer
        .close_interval(&closing(200, CloseKind::Remove, coordinate(1)))
        .unwrap();
    assert_eq!(reducer.high_water(), Some(seq(200)));
}

#[test]
fn a_refused_row_does_not_move_the_mark() {
    // The standing rule of this tree: a rejected row that still moved state is
    // worse than one that was accepted.
    let mut reducer = consumed_up_to(100);
    assert!(reducer.apply_terminal(&terminal(2, coordinate(1))).is_err());
    assert!(reducer
        .close_interval(&closing(2, CloseKind::Remove, coordinate(1)))
        .is_err());
    assert_eq!(reducer.high_water(), Some(seq(100)));
}

// ---- the three reproductions ------------------------------------------------

#[test]
fn a_terminal_may_not_land_below_a_consumed_control_row() {
    // Reproduction one, and the worst of the three: the proof is irreversible.
    // Seq 2 sits below a control row already applied at 100, so this deposits
    // schedule-terminal proof underneath history the schedule has treated as
    // visible — and afterwards every entry point refuses, so there is no path
    // that could correct it.
    let mut reducer = consumed_up_to(100);
    assert_eq!(
        reducer.apply_terminal(&terminal(2, coordinate(1))),
        Err(ReducerError::NotAdvancing {
            expected_after: seq(100),
            found: seq(2),
        })
    );
    assert!(!reducer.is_terminal(), "nothing may have been terminalized");
    assert!(reducer.has_open_interval());
    assert!(reducer.intervals()[0].close().is_none());
}

#[test]
fn a_close_may_not_land_below_a_consumed_control_row() {
    // Reproduction two. A close at 5 after consuming 10 would retroactively cut
    // the interval off below entries it has already made visible, and the
    // inclusive range means those entries stop being visible.
    let mut reducer = consumed_up_to(10);
    assert!(
        reducer.is_application_visible(seq(8)),
        "the fixture must already show entries below the attempted close"
    );
    assert_eq!(
        reducer.close_interval(&closing(5, CloseKind::Remove, coordinate(1))),
        Err(ReducerError::NotAdvancing {
            expected_after: seq(10),
            found: seq(5),
        })
    );
    assert!(reducer.has_open_interval(), "the refusal must not close");
    assert!(reducer.is_application_visible(seq(8)));
}

#[test]
fn a_reanchor_may_not_land_below_a_consumed_control_row() {
    // Reproduction three. The gap check measures against the previous close, so
    // a reanchor above the close but below a control row consumed *before* it
    // used to pass. Here the schedule consumed 10, closed at 11, and the
    // reanchor at 6 is above neither.
    let mut reducer = consumed_up_to(10);
    reducer
        .close_interval(&closing(11, CloseKind::Remove, coordinate(1)))
        .unwrap();
    let err = reducer
        .reanchor(
            &binding(),
            ReanchorAuthority::verified_welcome(OuterEntryFingerprint::for_tests([0x11; 32])),
            opening(6, OpeningKind::Add, coordinate(5)),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            ReducerError::Interval(_) | ReducerError::NotAdvancing { .. }
        ),
        "a reanchor beneath consumed history must be refused, got {err}"
    );
    assert!(!reducer.has_open_interval());
    assert_eq!(reducer.intervals().len(), 1);
}

// ---- every accepting path is covered ----------------------------------------

#[test]
fn every_entry_point_refuses_a_row_beneath_the_mark() {
    // A sweep rather than a sample: the finding was that five of six entry
    // points each picked their own reference point, so checking one of them
    // proves nothing about the others.
    let below = 2;

    let mut reducer = consumed_up_to(100);
    assert!(reducer
        .apply_sequential_control(&control(below, coordinate(1), coordinate(2)))
        .is_err());

    let mut reducer = consumed_up_to(100);
    assert!(reducer
        .close_interval(&closing(below, CloseKind::Remove, coordinate(1)))
        .is_err());

    let mut reducer = consumed_up_to(100);
    assert!(reducer
        .apply_touching_boundary(&TouchingBoundary {
            seq: seq(below),
            recipient: binding(),
            close_kind: CloseKind::Replace,
            opening_kind: OpeningKind::Add,
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
            previous: coordinate(1),
            opening_context: coordinate(2),
        })
        .is_err());

    let mut reducer = consumed_up_to(100);
    assert!(reducer
        .apply_terminal(&terminal(below, coordinate(1)))
        .is_err());

    let mut reducer = consumed_up_to(100);
    assert!(reducer
        .apply_reset_activation(&ResetActivation {
            seq: seq(below),
            recipient: binding(),
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
            previous: coordinate(1),
            participation: ResetParticipation::Activator {
                opening_context: coordinate(2),
            },
        })
        .is_err());

    // And the non-leaf reset path, which opens with no interval to be relative
    // to at all — the case an interval-relative rule cannot express.
    let mut reducer = consumed_up_to(100);
    reducer
        .close_interval(&closing(101, CloseKind::Remove, coordinate(1)))
        .unwrap();
    assert!(reducer
        .apply_reset_activation(&ResetActivation {
            seq: seq(below),
            recipient: binding(),
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
            previous: coordinate(1),
            participation: ResetParticipation::Activator {
                opening_context: coordinate(2),
            },
        })
        .is_err());
}

#[test]
fn the_sweep_would_notice_a_path_that_stopped_checking() {
    // The positive control. Every row above is refused for being beneath the
    // mark; the identical rows above it are accepted, so the sweep is reading
    // the comparison rather than refusing everything.
    let mut reducer = consumed_up_to(100);
    reducer
        .apply_sequential_control(&control(101, coordinate(1), coordinate(2)))
        .expect("a row above the mark must apply");

    let mut reducer = consumed_up_to(100);
    reducer
        .close_interval(&closing(101, CloseKind::Remove, coordinate(1)))
        .expect("a close above the mark must apply");

    let mut reducer = consumed_up_to(100);
    reducer
        .apply_terminal(&terminal(101, coordinate(1)))
        .expect("a terminal above the mark must apply");
}

// ---- the ratified touching semantics survive --------------------------------

#[test]
fn a_touching_boundary_still_shares_one_seq_across_two_intervals() {
    // The boundary is one row: it is checked once against the mark it inherits,
    // and recorded once. Its successor interval opens at the same sequence, and
    // that shared sequence is not a second consumption — so the mark ends at
    // the boundary's own seq and the next row need only clear it.
    let mut reducer = consumed_up_to(10);
    reducer
        .apply_touching_boundary(&TouchingBoundary {
            seq: seq(11),
            recipient: binding(),
            close_kind: CloseKind::Reset,
            opening_kind: OpeningKind::Reset,
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
            previous: coordinate(1),
            opening_context: coordinate(2),
        })
        .expect("a legal touching boundary must apply");

    assert_eq!(reducer.high_water(), Some(seq(11)));
    assert_eq!(reducer.intervals()[0].close().unwrap().seq, seq(11));
    assert_eq!(reducer.intervals()[1].opening().seq, seq(11));
    reducer
        .apply_sequential_control(&control(12, coordinate(2), coordinate(3)))
        .expect("the successor interval sequences from the boundary onwards");
}

#[test]
fn a_previously_removed_activator_still_opens_after_a_strict_gap() {
    // The ratified §5 reading, re-checked under the new rule: a device removed
    // at seq 3 activates a reset at seq 20. The mark is 3 there, so the
    // schedule rule and the strict-gap rule agree and the ruling is untouched.
    let mut reducer = ApplicationReducer::new(binding());
    reducer
        .install_initial_opening(&binding(), opening(1, OpeningKind::Creation, coordinate(0)))
        .unwrap();
    reducer
        .close_interval(&closing(3, CloseKind::Remove, coordinate(0)))
        .unwrap();
    assert_eq!(reducer.high_water(), Some(seq(3)));

    reducer
        .apply_reset_activation(&ResetActivation {
            seq: seq(20),
            recipient: binding(),
            transition_id: TransitionId::parse(OTHER_TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
            previous: coordinate(0),
            participation: ResetParticipation::Activator {
                opening_context: coordinate(2),
            },
        })
        .expect("a previously removed activator opens after a strict gap");
    assert_eq!(reducer.intervals().len(), 2);
    assert_eq!(reducer.high_water(), Some(seq(20)));
}
