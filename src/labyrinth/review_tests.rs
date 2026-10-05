//! Labyrinth review 2: per-conversation flushes, member exclusion and the
//! re-pin after a peer reset, quarantine, the bounded queue, account
//! deletion that never strands the user, and redaction labels. A child of
//! `tests.rs`, sharing its fixtures and `queue_tests`' in-memory queue.

use labyrinth::store::TimeRange;

use super::super::queue::{
    enqueue, flush_queue, retry_quarantined, ArchiveQueueStore, PendingArchive, MAX_FAILURES,
    MAX_QUEUE_ROWS,
};
use super::queue_tests::{appends, copies, MemQueue};
use super::*;

const A1: &str = "11111111-1111-4111-8111-111111111111";
const B1: &str = "22222222-2222-4222-8222-222222222222";

fn row(conversation: &str, n: u32) -> PendingArchive {
    PendingArchive::new(
        ALICE,
        conversation,
        &format!("{conversation}-m{n}"),
        1_791_000_000_000 + u64::from(n),
        &n.to_be_bytes(),
    )
}

#[test]
fn a_deleted_conversation_drops_its_rows_and_never_blocks_another() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let q = MemQueue::default();
    // "gone" has no leaves: mls-ds answers ConversationNotFound.
    q.put(&row("gone", 1)).unwrap();
    q.put(&row(THREAD, 2)).unwrap();

    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.dropped, r.failed_conversations), (1, 1, 0));
    assert!(q.list(ALICE).unwrap().is_empty());
    let status = q.load_status(ALICE).unwrap();
    assert_eq!(status.dropped.len(), 1);
    assert_eq!(status.dropped[0].message_id, "gone-m1");
    assert!(status.dropped[0].reason.contains("no longer exists"));
    assert_eq!(copies(&mut b), [(format!("{THREAD}-m2"), 1)]);
}

#[test]
fn repeated_failures_quarantine_only_that_conversation() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let _bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    gw.net().add_leaf("other", ALICE, alice.key());
    let q = MemQueue::default();
    q.put(&row(THREAD, 1)).unwrap();
    // A refusal (not a dropped connection) counts towards quarantine.
    *gw.refuse_nsid.lock().unwrap() = Some((
        "blue.catbird.labyrinth.appendBatch".into(),
        "NotAuthorized".into(),
    ));
    for n in 1..=MAX_FAILURES {
        let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
        assert_eq!(r.failed_conversations, 1);
        assert_eq!(r.quarantined, usize::from(n == MAX_FAILURES));
    }
    let rows = q.list(ALICE).unwrap();
    assert!(rows[0].quarantined && rows[0].failures == MAX_FAILURES);
    assert!(rows[0].last_error.as_deref().unwrap().contains("refused"));

    // Quarantined rows are skipped; other conversations still flow.
    *gw.refuse_nsid.lock().unwrap() = None;
    q.put(&row("other", 2)).unwrap();
    let before = appends(&gw);
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.failed_conversations), (1, 0));
    assert_eq!(appends(&gw) - before, 1);
    assert_eq!(q.list(ALICE).unwrap().len(), 1);

    // An explicit retry releases it.
    assert_eq!(retry_quarantined(&q, ALICE).unwrap(), 1);
    assert_eq!(flush_queue(&mut a, &alice.deps, &q).unwrap().archived, 1);
    assert!(q.list(ALICE).unwrap().is_empty());
}

#[test]
fn a_reset_peer_is_excluded_and_reported_until_the_user_repins() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let q = MemQueue::default();
    q.put(&row(THREAD, 1)).unwrap();
    assert_eq!(flush_queue(&mut a, &alice.deps, &q).unwrap().archived, 1);

    // Bob deletes his backup and starts over: a new genesis, which
    // Alice's pin refuses ([CB-29]).
    assert!(b.purge_account().unwrap().remote_pending.is_none());
    let mut b = bob.deps.clone().enable().unwrap();
    q.put(&row(THREAD, 2)).unwrap();
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!(
        (r.archived, r.excluded_members),
        (1, 1),
        "archived without Bob"
    );
    let status = q.load_status(ALICE).unwrap();
    assert_eq!(status.needs_repin(), [BOB]);
    assert!(status.excluded_members[0].reason.contains("rolled back"));
    assert!(copies(&mut b).is_empty(), "Bob got no MEK for m2");

    // The user compares and accepts the new safety number.
    let p = a.propose_repin(BOB).unwrap();
    assert_ne!(
        p.old_safety_number.as_deref(),
        Some(p.new_safety_number.as_str())
    );
    assert!(a.repin_peer(BOB, [0; 32]).is_err(), "only the shown head");
    a.repin_peer(BOB, p.offered_head).unwrap();
    q.put(&row(THREAD, 3)).unwrap();
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.excluded_members), (1, 0));
    assert!(q.load_status(ALICE).unwrap().excluded_members.is_empty());
    assert_eq!(copies(&mut b), [(format!("{THREAD}-m3"), 1)]);
}

#[test]
fn the_queue_is_bounded_and_says_what_it_dropped() {
    let q = MemQueue::default();
    for n in 0..MAX_QUEUE_ROWS as u32 {
        assert!(enqueue(&q, &row(THREAD, n)).unwrap());
    }
    // Full: the new row is refused, and recorded.
    assert!(!enqueue(&q, &row(THREAD, 9_999)).unwrap());
    assert_eq!(q.list(ALICE).unwrap().len(), MAX_QUEUE_ROWS);
    let s = q.load_status(ALICE).unwrap();
    assert_eq!(s.dropped.len(), 1);
    assert_eq!(s.dropped[0].message_id, format!("{THREAD}-m9999"));
    assert_eq!(s.dropped[0].reason, "archive queue full");
    // A quarantined row is evicted first.
    let mut stuck = row(THREAD, 7);
    stuck.quarantined = true;
    q.put(&stuck).unwrap();
    assert!(enqueue(&q, &row(THREAD, 10_000)).unwrap());
    assert_eq!(q.list(ALICE).unwrap().len(), MAX_QUEUE_ROWS);
    let s = q.load_status(ALICE).unwrap();
    assert_eq!(s.dropped.last().unwrap().message_id, format!("{THREAD}-m7"));
}

#[test]
fn account_deletion_erases_local_state_even_when_the_server_fails() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let _b = bob.deps.clone().enable().unwrap();
    *gw.fail_nsid.lock().unwrap() = Some("blue.catbird.labyrinth.deleteAccountData".into());
    let report = a.purge_account().unwrap();
    assert!(report.remote_pending.is_some());
    assert!(
        alice.deps.vault.load(ALICE).unwrap().is_none(),
        "local state erased"
    );
    let dir = labyrinth::store::xrpc::XrpcDirectory::new(bob.deps.transport.clone());
    use labyrinth::store::MailboxDirectory as _;
    assert!(dir.latest(ALICE).unwrap().is_some(), "server still has it");
    // The retry needs no client state.
    assert!(alice.deps.delete_account_remote().is_err());
    *gw.fail_nsid.lock().unwrap() = None;
    alice.deps.delete_account_remote().unwrap();
    assert!(dir.latest(ALICE).unwrap().is_none());
}

#[test]
fn history_labels_server_redactions_by_what_proves_them() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    a.archive_sent(THREAD, &members, "a-1", 1_791_000_000_001, b"x")
        .unwrap();
    b.archive_sent(THREAD, &members, "b-1", 1_791_000_000_002, b"y")
        .unwrap();
    // The sequencer signs, but the mls-ds directory cannot report its key
    // yet: the redaction is "removed by server", never an unsend.
    gw.net()
        .set_sequencer("did:web:ds.example", Some([0x5e; 32]));
    assert!(a.purge_account().unwrap().remote_pending.is_none());
    let h = b.load_history(THREAD, TimeRange::ALL).unwrap();
    assert_eq!(h.redacted.len(), 1);
    let r = &h.redacted[0];
    assert!(
        r.removed_by_server && !r.account_deleted && !r.by_author,
        "{r:?}"
    );
}

/// The orchestrator: deleting while mls-ds refuses still erases this
/// device, reports the pending remote half, and blocks re-enabling until
/// the retry succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn the_orchestrator_deletes_offline_and_retries_the_server_half() {
    use crate::recovery_e2e_harness::TestWorld;

    let gw = RefGateway::new();
    let mut world = TestWorld::new();
    let handler = gw.clone();
    world
        .api_service
        .set_labyrinth_handler(Arc::new(move |req| handler.submit_labyrinth(req)));
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let did = alice.did.clone();
    let (device, key) = super::chat_device(&alice.orchestrator, &did).await;
    gw.register(&did, &device, key);
    let o = &alice.orchestrator;
    o.labyrinth_enable().await.unwrap();

    *gw.fail_nsid.lock().unwrap() = Some("blue.catbird.labyrinth.deleteAccountData".into());
    let report = o.labyrinth_delete_account().await.unwrap();
    assert!(report.remote_pending.is_some());
    assert!(
        !o.labyrinth_is_enabled().await.unwrap(),
        "local state erased"
    );
    let status = o.labyrinth_archive_status().await.unwrap();
    assert!(status.status.pending_remote_deletion.is_some());
    assert!(o.labyrinth_enable().await.is_err(), "refused while pending");

    *gw.fail_nsid.lock().unwrap() = None;
    assert!(o.labyrinth_retry_remote_deletion().await.unwrap());
    let status = o.labyrinth_archive_status().await.unwrap();
    assert!(status.status.pending_remote_deletion.is_none());
    o.labyrinth_enable().await.unwrap();
    assert!(o.labyrinth_is_enabled().await.unwrap());
}
