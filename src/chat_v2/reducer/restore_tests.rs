//! Restore-path tests for [`ApplicationReducer::rehydrate`].
//!
//! These live next to the reducer rather than beside the store, because none of
//! them needs storage: what they pin is what the reducer will accept back as its
//! own state. Three of them began life in `storage/memory_tests.rs` and were
//! moved here when the structural checks arrived, so that everything governing
//! restoration reads in one place.
//!
//! # Why restore is checked at all when the reducer's own paths are not
//!
//! Restore is a **second feed** into this type. Every other way in runs the
//! admission rules, and those rules cannot produce an unordered or overlapping
//! schedule — so the reducer's internal paths were written to trust the shape
//! and, in three places, to reason about "the current interval" as
//! `intervals.last()`:
//!
//! - [`ApplicationReducer::has_open_interval`] asks whether `last()` is open;
//! - `reanchor` measures its strict gap against `last()`'s close;
//! - `close_interval` writes its close proof into `last_mut()`.
//!
//! Durable storage hands back whatever was written. If the last element is not
//! the latest interval, all three operate on the wrong one **and report
//! success** — which is why these are refusals rather than debug assertions.

use super::reanchor::ReanchorAuthority;
use super::{ApplicationReducer, ReducerError, SequentialControl};
use crate::chat_v2::coordinate::{Coordinate, Lifecycle};
use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, SafeInteger, Seq, TransitionId};
use crate::chat_v2::interval::{AccessInterval, CloseProof, IntervalOpening, RecipientBinding};
use crate::chat_v2::provenance::{CloseKind, OpeningKind, OuterEntryFingerprint};

const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
const SIBLING_DEVICE: &str = "72727272-7272-4272-b272-727272727272";
const TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

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

fn opening(at: i64) -> IntervalOpening<Coordinate> {
    IntervalOpening {
        seq: seq(at),
        kind: OpeningKind::Creation,
        transition_id: TransitionId::parse(TRANSITION).unwrap(),
        outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x5a; 32]),
        context: coordinate(0),
    }
}

/// An interval left open at `at`.
fn open_interval(device: &str, at: i64) -> AccessInterval<Coordinate> {
    AccessInterval::open(binding(device), opening(at))
}

/// An interval opened at `from` and closed at `to`.
fn closed_interval(device: &str, from: i64, to: i64) -> AccessInterval<Coordinate> {
    let mut interval = open_interval(device, from);
    interval
        .apply_close(CloseProof {
            seq: seq(to),
            kind: CloseKind::Remove,
            transition_id: TransitionId::parse(TRANSITION).unwrap(),
            outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x99; 32]),
        })
        .expect("fixture close must be legal");
    interval
}

// ---- the checks that came with the original restore path -------------------

#[test]
fn a_fresh_schedule_restores_as_empty_rather_than_incoherent() {
    // No intervals and no context is the legitimate starting state, not a
    // violation of the open-implies-context invariant.
    let restored = ApplicationReducer::rehydrate(binding(DEVICE), Vec::new(), None, None, None)
        .expect("an empty schedule must restore");
    assert!(!restored.has_open_interval());
    assert!(restored.intervals().is_empty());
    assert_eq!(restored.expected_context(), None);
}

#[test]
fn restoring_refuses_a_schedule_holding_another_devices_intervals() {
    // Storage hands back what it was given, so restoration is where a schedule
    // stitched together from two devices must be caught. Visibility is per
    // exact (DID, deviceId).
    let err = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![open_interval(SIBLING_DEVICE, 1)],
        Some(coordinate(0)),
        None,
        Some(seq(1)),
    )
    .unwrap_err();
    assert!(
        matches!(err, ReducerError::RecipientMismatch { .. }),
        "expected a recipient refusal, got {err}"
    );
}

#[test]
fn restoring_refuses_a_context_that_disagrees_with_the_intervals() {
    // Both directions. An open interval without a context panics the sequencing
    // path; a context without an open interval would sequence rows through a
    // gap that grants no access.
    let err = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![open_interval(DEVICE, 1)],
        None,
        None,
        Some(seq(1)),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredScheduleIncoherent {
            has_open_interval: true,
            has_expected_context: false,
        }
    );

    let err =
        ApplicationReducer::rehydrate(binding(DEVICE), Vec::new(), Some(coordinate(0)), None, None)
            .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredScheduleIncoherent {
            has_open_interval: false,
            has_expected_context: true,
        }
    );
}

// ---- the structural checks -------------------------------------------------

#[test]
fn the_hazard_an_unordered_list_creates_is_real() {
    // Stated before it is refused, because the refusal is only justified by
    // what an unordered list does to the three `last()` readers. Here the last
    // element opens at 1 while the element before it opens at 10: "last" is not
    // "latest", so has_open_interval, reanchor's strict gap, and the close
    // proof written by close_interval would all address the wrong interval.
    let unordered = vec![
        closed_interval(DEVICE, 10, 20),
        closed_interval(DEVICE, 1, 5),
    ];
    assert_eq!(unordered.last().unwrap().opening().seq, seq(1));
    assert!(
        unordered.last().unwrap().opening().seq < unordered[0].opening().seq,
        "the fixture must actually be out of order for this to prove anything"
    );

    let err = ApplicationReducer::rehydrate(binding(DEVICE), unordered, None, None, Some(seq(20)))
        .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredIntervalsOutOfOrder {
            earlier_opening: seq(10),
            later_opening: seq(1),
        }
    );
}

#[test]
fn restoring_refuses_overlapping_intervals() {
    // The successor opens at 3, inside the predecessor's 1..=5 range. One
    // application sequence would be visible through two interval interiors.
    let err = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![closed_interval(DEVICE, 1, 5), closed_interval(DEVICE, 3, 9)],
        None,
        None,
        Some(seq(9)),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredIntervalsOverlap {
            close_seq: seq(5),
            opening_seq: seq(3),
        }
    );
}

#[test]
fn restoring_refuses_a_non_final_open_interval() {
    // The first interval is open and the second is not. `has_open_interval`
    // reads only `last()`, so this restores as a closed schedule while an
    // interval is genuinely open — and rows that should have been refused get
    // admitted.
    let intervals = vec![open_interval(DEVICE, 1), closed_interval(DEVICE, 5, 9)];
    assert!(
        !intervals.last().unwrap().is_open(),
        "the fixture's hazard is precisely that last() looks closed"
    );
    assert!(intervals[0].is_open());

    let err = ApplicationReducer::rehydrate(binding(DEVICE), intervals, None, None, Some(seq(9)))
        .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredNonFinalIntervalOpen {
            opening_seq: seq(1),
        }
    );
}

#[test]
fn a_touching_boundary_survives_restoration() {
    // The over-refusal guard. A legal touching boundary shares one sequence
    // between a close and the opening it also performs, so equality at the
    // boundary must restore — a strict comparison here would reject schedules
    // the protocol explicitly permits.
    let restored = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![closed_interval(DEVICE, 1, 9), open_interval(DEVICE, 9)],
        Some(coordinate(0)),
        None,
        Some(seq(9)),
    )
    .expect("a touching boundary is legal and must restore");
    assert!(restored.has_open_interval());
    assert_eq!(restored.intervals().len(), 2);
}

// ---- the restored high-water mark ------------------------------------------

#[test]
fn restoring_refuses_a_mark_below_the_schedule_it_came_with() {
    // The floor. Every opening, close, and terminal sequence the restored
    // schedule records was necessarily consumed, so a mark below one of them is
    // a store that lost track — and restoring it would reopen the replay window
    // the mark exists to close.
    let err = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![closed_interval(DEVICE, 1, 20)],
        None,
        None,
        Some(seq(19)),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredHighWaterBelowSchedule {
            high_water: Some(seq(19)),
            recorded: seq(20),
        }
    );

    // Absent is below everything, and is refused with the same name rather
    // than being silently treated as "unknown, so allow anything".
    let err = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![closed_interval(DEVICE, 1, 20)],
        None,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ReducerError::RestoredHighWaterBelowSchedule {
            high_water: None,
            recorded: seq(20),
        }
    );
}

#[test]
fn a_mark_above_the_schedule_is_the_case_the_intervals_cannot_express() {
    // This is why the mark is a parameter rather than something derived here.
    // A schedule opened at 10 that consumed a control row at 500 records only
    // the 10; deriving the mark would restore it as 10 and re-admit every
    // sequence between. So a mark above everything recorded is accepted, and
    // the restored reducer enforces it.
    let mut restored = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![open_interval(DEVICE, 10)],
        Some(coordinate(0)),
        None,
        Some(seq(500)),
    )
    .expect("a mark above the schedule is legitimate");
    assert_eq!(restored.high_water(), Some(seq(500)));

    let replay = SequentialControl {
        seq: seq(400),
        recipient: binding(DEVICE),
        previous: coordinate(0),
        next: coordinate(1),
    };
    assert_eq!(
        restored.apply_sequential_control(&replay),
        Err(ReducerError::NotAdvancing {
            expected_after: seq(500),
            found: seq(400),
        }),
        "the restored mark must be enforced, not merely stored"
    );

    let row = SequentialControl {
        seq: seq(501),
        recipient: binding(DEVICE),
        previous: coordinate(0),
        next: coordinate(1),
    };
    restored
        .apply_sequential_control(&row)
        .expect("a row above the restored mark must apply");
}

// ---- the restored reducer on the paths the checks protect ------------------

#[test]
fn a_restored_multi_interval_schedule_reanchors_against_its_latest_close() {
    // Drives the path the ordering check exists for. `reanchor` measures its
    // strict gap against `intervals.last()`, so a correctly ordered restore
    // must gap against the LATEST close (20) and not the earlier one (5).
    let mut restored = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![
            closed_interval(DEVICE, 1, 5),
            closed_interval(DEVICE, 10, 20),
        ],
        None,
        None,
        Some(seq(20)),
    )
    .expect("an ordered schedule must restore");

    // Inside the latest interval's range: refused, measured against close 20.
    let err = restored
        .reanchor(
            &binding(DEVICE),
            ReanchorAuthority::verified_welcome(OuterEntryFingerprint::for_tests([0x5a; 32])),
            opening(15),
        )
        .unwrap_err();
    assert!(
        matches!(err, ReducerError::Interval(_)),
        "a reanchor below the latest close must be refused, got {err}"
    );

    // Above it: accepted, and the schedule reopens.
    restored
        .reanchor(
            &binding(DEVICE),
            ReanchorAuthority::verified_welcome(OuterEntryFingerprint::for_tests([0x5a; 32])),
            opening(30),
        )
        .expect("a reanchor strictly after the latest close must be accepted");
    assert!(restored.has_open_interval());
    assert_eq!(restored.intervals().len(), 3);
}

#[test]
fn a_restored_open_schedule_closes_its_latest_interval() {
    // Drives the `last_mut()` path. The close proof must land on the interval
    // opened at 10, not the one already closed at 5.
    let mut restored = ApplicationReducer::rehydrate(
        binding(DEVICE),
        vec![closed_interval(DEVICE, 1, 5), open_interval(DEVICE, 10)],
        Some(coordinate(0)),
        None,
        Some(seq(10)),
    )
    .expect("an ordered schedule must restore");
    assert!(restored.has_open_interval());

    let row = SequentialControl {
        seq: seq(12),
        recipient: binding(DEVICE),
        previous: coordinate(0),
        next: coordinate(1),
    };
    restored
        .apply_sequential_control(&row)
        .expect("a restored open schedule must sequence");

    assert_eq!(
        restored.intervals()[0].close().unwrap().seq,
        seq(5),
        "the already-closed interval must be untouched"
    );
    assert!(restored.intervals()[1].is_open());
}
