//! Reference-store behaviour tests.
//!
//! Split from `memory.rs` so the implementation stays readable: the store is
//! about a hundred and sixty lines and the properties worth pinning about it are
//! several times that. Same arrangement as `content/media_tests.rs` and the
//! `transcript/` test modules.
//!
//! These exercise the trait through a real implementation rather than testing
//! the reference store for its own sake. What they pin — atomicity, the
//! compare-and-set cursor, per-DID refusal at every call site, exact-device
//! separation, and byte-identical journal rehydration — are obligations any
//! platform store must also meet.

use super::memory::MemoryStore;
use super::page::{EntryOutcome, PageCommit, PersistedEntry, RatchetCheckpoint};
use super::store::ChatV2Store;
use super::{RecordKind, StorageError, StoreScope};
use crate::chat_v2::coordinate::{Coordinate, Lifecycle};
use crate::chat_v2::cursor::AfterSeq;
use crate::chat_v2::ids::{
    BareDid, CanonicalTimestamp, ConversationId, DeviceId, EntryId, IdempotencyKey, MessageId,
    SafeInteger, Seq, TransitionId,
};
use crate::chat_v2::interval::{IntervalOpening, RecipientBinding};
use crate::chat_v2::journal::{JournalEntry, JournalState, OperationId, OperationIdentity};
use crate::chat_v2::provenance::{OpeningKind, OuterEntryFingerprint};
use crate::chat_v2::reducer::{ApplicationReducer, SequentialControl};

const OWNER: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
const STRANGER: &str = "did:plc:44ybard66vv44zksje25o7dz";
const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
const SIBLING_DEVICE: &str = "72727272-7272-4272-b272-727272727272";
const ENTRY: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";

fn did(value: &str) -> BareDid {
    BareDid::parse(value).unwrap()
}

fn binding(owner: &str, device: &str) -> RecipientBinding {
    RecipientBinding::new(
        ConversationId::parse(CONVERSATION).unwrap(),
        did(owner),
        DeviceId::parse(device).unwrap(),
    )
}

fn store() -> MemoryStore {
    MemoryStore::open(StoreScope::for_did(did(OWNER)))
}

fn frame(seq_value: i64) -> PersistedEntry {
    PersistedEntry {
        seq: Seq::new(seq_value).unwrap(),
        entry_id: EntryId::parse(ENTRY).unwrap(),
        fingerprint: OuterEntryFingerprint::for_tests([0x11; 32]),
        outcome: EntryOutcome::Frame {
            canonical_body: format!("frame-{seq_value}").into_bytes(),
        },
    }
}

fn page(device: &str, previous: i64, next: i64, entries: Vec<PersistedEntry>) -> PageCommit {
    PageCommit::new(
        binding(OWNER, device),
        AfterSeq::new(previous).unwrap(),
        AfterSeq::new(next).unwrap(),
        entries,
        Some(RatchetCheckpoint::from_crypto_layer(vec![0xaa; 8])),
    )
}

#[tokio::test]
async fn a_fresh_store_reports_absence_rather_than_a_default_position() {
    // None is not AfterSeq::START. A caller can tell "never scanned" from
    // "scanned to the beginning", which a defaulted read would erase.
    let store = store();
    assert_eq!(store.cursor(&binding(OWNER, DEVICE)).await.unwrap(), None);
    assert!(store
        .entries_after(&binding(OWNER, DEVICE), AfterSeq::START, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .ratchet_checkpoint(&binding(OWNER, DEVICE))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn a_committed_page_lands_entries_ratchet_and_cursor_together() {
    let store = store();
    store
        .commit_page(&page(DEVICE, 0, 2, vec![frame(1), frame(2)]))
        .await
        .unwrap();

    let device = binding(OWNER, DEVICE);
    assert_eq!(
        store.cursor(&device).await.unwrap(),
        Some(AfterSeq::new(2).unwrap())
    );
    assert_eq!(
        store
            .entries_after(&device, AfterSeq::START, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store.ratchet_checkpoint(&device).await.unwrap().unwrap(),
        RatchetCheckpoint::from_crypto_layer(vec![0xaa; 8])
    );
}

#[tokio::test]
async fn a_refused_commit_deposits_nothing_at_all() {
    // The atomicity claim, checked on all three halves. A commit that stored
    // its entries and then refused the cursor would leave the store holding
    // rows it would never account for.
    let store = store();
    store
        .commit_page(&page(DEVICE, 0, 5, vec![frame(5)]))
        .await
        .unwrap();

    // A second page built on a position that has since moved.
    let stale = page(DEVICE, 0, 9, vec![frame(9)]);
    let err = store.commit_page(&stale).await.unwrap_err();
    assert!(matches!(err, StorageError::CursorMismatch { .. }), "{err}");

    let device = binding(OWNER, DEVICE);
    assert_eq!(
        store.cursor(&device).await.unwrap(),
        Some(AfterSeq::new(5).unwrap()),
        "the refused commit must not have advanced the position"
    );
    let stored = store
        .entries_after(&device, AfterSeq::START, 10)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1, "the refused page's entry must not be here");
    assert_eq!(stored[0].seq, Seq::new(5).unwrap());
}

#[tokio::test]
async fn a_page_continuing_from_a_position_this_store_never_held_is_refused() {
    // Distinct from losing a race: nothing advanced this cursor, because
    // there is no cursor. A page arriving mid-stream against an empty store
    // means the store was misrouted, and it is reported as its own fault.
    let store = store();
    let err = store
        .commit_page(&page(DEVICE, 40, 41, vec![frame(41)]))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        StorageError::NotFound {
            record: RecordKind::Cursor,
            key: binding(OWNER, DEVICE).to_string(),
        }
    );
    assert_eq!(
        store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
        None,
        "the refusal must not have created the cursor it complained about"
    );
}

#[tokio::test]
async fn the_cursor_advance_is_a_compare_and_set() {
    // Sequential pages chain: each builds on the position the last one
    // installed. This is what makes a lost update impossible rather than
    // merely unlikely.
    let store = store();
    store
        .commit_page(&page(DEVICE, 0, 1, vec![frame(1)]))
        .await
        .unwrap();
    store
        .commit_page(&page(DEVICE, 1, 2, vec![frame(2)]))
        .await
        .unwrap();
    assert_eq!(
        store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
        Some(AfterSeq::new(2).unwrap())
    );

    // Replaying the first page now is refused; its effects are already in.
    let err = store
        .commit_page(&page(DEVICE, 0, 1, vec![frame(1)]))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::CursorMismatch { .. }), "{err}");
}

#[tokio::test]
async fn an_empty_page_confirms_the_position_without_moving_it() {
    let store = store();
    store
        .commit_page(&page(DEVICE, 0, 3, vec![frame(3)]))
        .await
        .unwrap();

    let position = AfterSeq::new(3).unwrap();
    let confirmation =
        PageCommit::new(binding(OWNER, DEVICE), position, position, Vec::new(), None);
    store.commit_page(&confirmation).await.unwrap();
    assert_eq!(
        store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
        Some(position)
    );
    assert_eq!(
        store
            .ratchet_checkpoint(&binding(OWNER, DEVICE))
            .await
            .unwrap()
            .unwrap()
            .len(),
        8,
        "a page carrying no ratchet state must not erase the stored one"
    );
}

#[tokio::test]
async fn sibling_devices_keep_separate_positions_and_entries() {
    // Visibility is per exact (DID, deviceId). Two devices of one principal
    // share a store, and must not share a cursor or an entry set.
    let store = store();
    store
        .commit_page(&page(DEVICE, 0, 5, vec![frame(5)]))
        .await
        .unwrap();
    store
        .commit_page(&page(SIBLING_DEVICE, 0, 1, vec![frame(1)]))
        .await
        .unwrap();

    assert_eq!(
        store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
        Some(AfterSeq::new(5).unwrap())
    );
    assert_eq!(
        store.cursor(&binding(OWNER, SIBLING_DEVICE)).await.unwrap(),
        Some(AfterSeq::new(1).unwrap())
    );

    let sibling_entries = store
        .entries_after(&binding(OWNER, SIBLING_DEVICE), AfterSeq::START, 10)
        .await
        .unwrap();
    assert_eq!(sibling_entries.len(), 1);
    assert_eq!(
        sibling_entries[0].seq,
        Seq::new(1).unwrap(),
        "one device's entries must never surface under another's binding"
    );
}

#[tokio::test]
async fn every_read_and_write_refuses_a_foreign_principal() {
    // The scope check at real call sites, not only in its own unit test.
    // A store handle routed to the wrong principal must fail on every
    // method rather than on whichever one someone remembered to guard.
    let store = store();
    let foreign = binding(STRANGER, DEVICE);

    assert!(store
        .cursor(&foreign)
        .await
        .unwrap_err()
        .is_isolation_breach());
    assert!(store
        .entries_after(&foreign, AfterSeq::START, 10)
        .await
        .unwrap_err()
        .is_isolation_breach());
    assert!(store
        .ratchet_checkpoint(&foreign)
        .await
        .unwrap_err()
        .is_isolation_breach());

    let foreign_page = PageCommit::new(
        foreign,
        AfterSeq::START,
        AfterSeq::new(1).unwrap(),
        vec![frame(1)],
        None,
    );
    assert!(store
        .commit_page(&foreign_page)
        .await
        .unwrap_err()
        .is_isolation_breach());
}

#[tokio::test]
async fn rejections_are_returned_alongside_frames() {
    // A caller that saw only frames would re-request an entry the ratchet
    // has already advanced past, and it would be refused again forever.
    let store = store();
    let rejection = PersistedEntry {
        seq: Seq::new(2).unwrap(),
        entry_id: EntryId::parse(ENTRY).unwrap(),
        fingerprint: OuterEntryFingerprint::for_tests([0x22; 32]),
        outcome: EntryOutcome::Rejection {
            detail: "semantic-invalid frame".to_owned(),
        },
    };
    store
        .commit_page(&page(DEVICE, 0, 2, vec![frame(1), rejection]))
        .await
        .unwrap();

    let stored = store
        .entries_after(&binding(OWNER, DEVICE), AfterSeq::START, 10)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored[1].outcome.is_rejection());
}

#[tokio::test]
async fn reads_are_bounded_and_exclusive_of_the_scan_position() {
    let store = store();
    store
        .commit_page(&page(
            DEVICE,
            0,
            4,
            vec![frame(1), frame(2), frame(3), frame(4)],
        ))
        .await
        .unwrap();

    let device = binding(OWNER, DEVICE);
    let from_two = store
        .entries_after(&device, AfterSeq::new(2).unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(
        from_two.iter().map(|e| e.seq.get()).collect::<Vec<_>>(),
        vec![3, 4],
        "afterSeq is exclusive; entry 2 was already delivered"
    );

    let capped = store
        .entries_after(&device, AfterSeq::START, 2)
        .await
        .unwrap();
    assert_eq!(capped.len(), 2);
    assert_eq!(capped[0].seq.get(), 1, "reads are oldest first");
}

// ---- the journal ------------------------------------------------------

const KEY: &str = "70707070-7070-4070-b070-707070707070";
const SIGNED_AT: &str = "2026-08-14T12:34:56.789Z";

fn identity(owner: &str, endpoint: &str, operation_id: OperationId) -> OperationIdentity {
    OperationIdentity {
        endpoint: endpoint.to_owned(),
        actor_did: did(owner),
        operation_id,
    }
}

fn transition_identity(owner: &str) -> OperationIdentity {
    identity(
        owner,
        "blue.catbird.chat.submitTransition",
        OperationId::IdempotencyKey(IdempotencyKey::parse(KEY).unwrap()),
    )
}

fn message_identity(owner: &str) -> OperationIdentity {
    identity(
        owner,
        "blue.catbird.chat.sendMessage",
        OperationId::MessageId(MessageId::parse(KEY).unwrap()),
    )
}

fn journalled(identity: OperationIdentity) -> JournalEntry {
    JournalEntry::prepare(
        identity,
        b"exact-canonical-body".to_vec(),
        [0xab; 32],
        [0xcd; 64],
        CanonicalTimestamp::parse(SIGNED_AT).unwrap(),
    )
}

#[tokio::test]
async fn a_journalled_mutation_round_trips_byte_for_byte() {
    // The whole reason the journal exists. §5 compares the stored transcript
    // digest and signature byte-for-byte, so a store that re-encoded a body
    // on the way in or out would produce a retry the server reads as a
    // different request — a permanent conflict on an operation that may
    // already have committed.
    let store = store();
    let original = journalled(transition_identity(OWNER));
    store.put_journal_entry(&original).await.unwrap();

    let restored = store
        .journal_entry(&transition_identity(OWNER))
        .await
        .unwrap()
        .expect("the entry must be readable");

    assert_eq!(restored.canonical_body(), original.canonical_body());
    assert_eq!(restored.request_digest(), original.request_digest());
    assert_eq!(restored.signature(), original.signature());
    assert_eq!(restored.signed_at(), original.signed_at());
    assert!(
        restored.matches_stored_bytes(original.request_digest(), original.signature()),
        "a restored entry must satisfy the server's own equality check"
    );
}

#[tokio::test]
async fn a_restored_entry_keeps_its_progress_and_never_re_signs() {
    // Restoring must not reset an in-flight operation to Prepared, and must
    // not refresh signedAt. A fresh signedAt changes the transcript, the
    // digest, and the signature, which is precisely the failure the journal
    // was written to prevent.
    let store = store();
    let mut original = journalled(transition_identity(OWNER));
    original.record_transmission().unwrap();
    original.record_transmission().unwrap();
    store.put_journal_entry(&original).await.unwrap();

    let restored = store
        .journal_entry(&transition_identity(OWNER))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.state(), &JournalState::InFlight { attempts: 2 });
    assert!(
        restored.should_submit(),
        "an ambiguous outcome is resolved by resubmitting the same bytes"
    );
    assert_eq!(
        restored.signed_at(),
        &CanonicalTimestamp::parse(SIGNED_AT).unwrap()
    );
}

#[tokio::test]
async fn rehydration_reconstructs_any_durable_state() {
    // The constructor storage needs, exercised through storage. `prepare`
    // always yields Prepared, which is right for a new mutation and wrong
    // for a restart — durable progress has to come back as it was.
    let store = store();
    let stored = JournalEntry::rehydrate(
        transition_identity(OWNER),
        b"exact-canonical-body".to_vec(),
        [0xab; 32],
        [0xcd; 64],
        CanonicalTimestamp::parse(SIGNED_AT).unwrap(),
        JournalState::InFlight { attempts: 7 },
    )
    .expect("in-flight progress is a state a real run reaches");
    store.put_journal_entry(&stored).await.unwrap();

    let restored = store
        .journal_entry(&transition_identity(OWNER))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored, stored);
    assert_eq!(restored.state(), &JournalState::InFlight { attempts: 7 });
}

#[tokio::test]
async fn outstanding_is_exactly_what_a_restart_must_resubmit() {
    let store = store();
    store
        .put_journal_entry(&journalled(transition_identity(OWNER)))
        .await
        .unwrap();
    store
        .put_journal_entry(&journalled(message_identity(OWNER)))
        .await
        .unwrap();
    assert_eq!(store.outstanding_journal_entries().await.unwrap().len(), 2);

    // A completed operation drops out; an in-flight one stays, because its
    // outcome is still unknown.
    let mut completed = journalled(transition_identity(OWNER));
    completed.record_completed().unwrap();
    store.put_journal_entry(&completed).await.unwrap();

    let mut in_flight = journalled(message_identity(OWNER));
    in_flight.record_transmission().unwrap();
    store.put_journal_entry(&in_flight).await.unwrap();

    let outstanding = store.outstanding_journal_entries().await.unwrap();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].identity(), &message_identity(OWNER));
}

#[tokio::test]
async fn the_two_operation_id_kinds_do_not_collide_in_storage() {
    // Same UUID and same DID, different endpoint and different ID kind.
    // These are distinct server-side identities; collapsing them in a
    // storage key would have one operation's bytes answer for the other's.
    let store = store();
    store
        .put_journal_entry(&journalled(transition_identity(OWNER)))
        .await
        .unwrap();
    store
        .put_journal_entry(&journalled(message_identity(OWNER)))
        .await
        .unwrap();

    assert_eq!(store.outstanding_journal_entries().await.unwrap().len(), 2);
    assert!(store
        .journal_entry(&transition_identity(OWNER))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .journal_entry(&message_identity(OWNER))
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn another_principals_journal_is_refused_on_read_and_write() {
    // The journal is keyed by the authenticated principal, so a foreign
    // identity reaching this store is the same containment breach as a
    // foreign binding.
    let store = store();
    let foreign = journalled(transition_identity(STRANGER));
    assert!(store
        .put_journal_entry(&foreign)
        .await
        .unwrap_err()
        .is_isolation_breach());
    assert!(store
        .journal_entry(&transition_identity(STRANGER))
        .await
        .unwrap_err()
        .is_isolation_breach());
}

// ---- the exact-device schedule ----------------------------------------

const TRANSITION: &str = "0e1d2c3b-4a59-4687-9876-5432100fedcb";

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
        seq: Seq::new(at).unwrap(),
        kind: OpeningKind::Creation,
        transition_id: TransitionId::parse(TRANSITION).unwrap(),
        outer_entry_fingerprint: OuterEntryFingerprint::for_tests([0x5a; 32]),
        context: coordinate(0),
    }
}

/// A reducer with one open interval, built through the rule-enforcing path.
fn open_schedule(device: &str) -> ApplicationReducer {
    let binding = binding(OWNER, device);
    let mut reducer = ApplicationReducer::new(binding.clone());
    reducer
        .install_initial_opening(&binding, opening(1))
        .expect("the fixture opening must install");
    reducer
}

#[tokio::test]
async fn a_schedule_round_trips_with_its_intervals_and_expected_context() {
    let store = store();
    let original = open_schedule(DEVICE);
    store.put_schedule(&original).await.unwrap();

    let restored = store
        .schedule(&binding(OWNER, DEVICE))
        .await
        .unwrap()
        .expect("the schedule must be readable");

    assert_eq!(restored.binding(), original.binding());
    assert_eq!(restored.intervals(), original.intervals());
    assert_eq!(restored.expected_context(), original.expected_context());
    assert_eq!(restored.terminal_proof(), original.terminal_proof());
    assert!(restored.has_open_interval());
}

#[tokio::test]
async fn a_restored_schedule_still_sequences() {
    // The point of the coherence check, made concrete. A restored reducer
    // has to be usable on the path that reaches for the expected context of
    // an open interval — the path that panics if the invariant was not kept.
    let store = store();
    store.put_schedule(&open_schedule(DEVICE)).await.unwrap();
    let mut restored = store
        .schedule(&binding(OWNER, DEVICE))
        .await
        .unwrap()
        .unwrap();

    let row = SequentialControl {
        seq: Seq::new(4).unwrap(),
        recipient: binding(OWNER, DEVICE),
        previous: coordinate(0),
        next: coordinate(1),
    };
    restored
        .apply_sequential_control(&row)
        .expect("a restored schedule must sequence exactly as the original would");
    assert_eq!(restored.expected_context(), Some(&coordinate(1)));
}

#[tokio::test]
async fn sibling_devices_keep_separate_schedules() {
    // Visibility is per exact (DID, deviceId). A key that omitted the device
    // would hand one device the other's interval history.
    let store = store();
    store.put_schedule(&open_schedule(DEVICE)).await.unwrap();
    store
        .put_schedule(&open_schedule(SIBLING_DEVICE))
        .await
        .unwrap();

    let own = store
        .schedule(&binding(OWNER, DEVICE))
        .await
        .unwrap()
        .unwrap();
    let sibling = store
        .schedule(&binding(OWNER, SIBLING_DEVICE))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(own.binding(), &binding(OWNER, DEVICE));
    assert_eq!(sibling.binding(), &binding(OWNER, SIBLING_DEVICE));
    assert!(
        !own.binding().matches(sibling.binding()),
        "two devices of one principal are different audiences"
    );
}

#[tokio::test]
async fn another_principals_schedule_is_refused_on_read_and_write() {
    let store = store();
    let foreign_binding = binding(STRANGER, DEVICE);
    let foreign = ApplicationReducer::new(foreign_binding.clone());
    assert!(store
        .put_schedule(&foreign)
        .await
        .unwrap_err()
        .is_isolation_breach());
    assert!(store
        .schedule(&foreign_binding)
        .await
        .unwrap_err()
        .is_isolation_breach());
}

#[tokio::test]
async fn an_unknown_operation_reads_as_absent_not_as_a_fault() {
    let store = store();
    assert_eq!(
        store
            .journal_entry(&transition_identity(OWNER))
            .await
            .unwrap(),
        None
    );
    assert!(store
        .outstanding_journal_entries()
        .await
        .unwrap()
        .is_empty());
}
