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
    let members = if conversation == "other" {
        vec![ALICE.to_owned()]
    } else {
        vec![ALICE.to_owned(), BOB.to_owned()]
    };
    PendingArchive::new(
        ALICE,
        conversation,
        &format!("{conversation}-m{n}"),
        1_791_000_000_000 + u64::from(n),
        &n.to_be_bytes(),
    )
    .with_mls_snapshot("aa11", 1, members)
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
    let ds_vk = ed25519_dalek::SigningKey::from_bytes(&[0x5e; 32])
        .verifying_key()
        .to_bytes();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let mut bob = Device::new(&gw, BOB, B1, 2);
    bob.deps.sequencer_key = Some(labyrinth::store::SequencerKey {
        did: "did:web:ds.example".into(),
        key: ds_vk,
    });
    let carol = Device::new(
        &gw,
        "did:plc:carol",
        "44444444-4444-4444-8444-444444444444",
        4,
    );
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let mut c = carol.deps.clone().enable().unwrap();
    let members = vec![ALICE.to_owned(), BOB.to_owned(), "did:plc:carol".to_owned()];
    a.archive_sent(THREAD, &members, "a-1", 1_791_000_000_001, b"x")
        .unwrap();
    b.archive_sent(THREAD, &members, "b-1", 1_791_000_000_002, b"y")
        .unwrap();
    gw.net()
        .set_sequencer("did:web:ds.example", Some([0x5e; 32]));
    assert!(a.purge_account().unwrap().remote_pending.is_none());

    // With the sequencer's verifying key configured, the DS-signed redaction
    // proves `account_deleted`, never an author unsend.
    let h = b.load_history(THREAD, TimeRange::ALL).unwrap();
    assert_eq!(h.redacted.len(), 1);
    let r = &h.redacted[0];
    assert!(
        r.account_deleted && !r.removed_by_server && !r.by_author,
        "{r:?}"
    );

    // Without a matching sequencer key, a reader never misattributes the
    // redaction as an author unsend or proven account deletion (hardened
    // `labyrinth` fails closed with `BadSignature`; pre-bump `30f259e`
    // surfaces `removed_by_server`).
    match c.load_history(THREAD, TimeRange::ALL) {
        Err(err) => assert!(
            err.to_string().to_lowercase().contains("signature"),
            "unexpected error for unverified server redaction: {err}"
        ),
        Ok(unkeyed) => {
            assert_eq!(unkeyed.redacted.len(), 1);
            let u = &unkeyed.redacted[0];
            assert!(
                u.removed_by_server && !u.account_deleted && !u.by_author,
                "{u:?}"
            );
        }
    }
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
    let recovery = o.labyrinth_create_recovery_code().await.unwrap();

    // Observe persistence at the first remote deletion boundary. A crash
    // after this callback must still leave retry intent on disk.
    let journal = o.labyrinth_queue_store();
    let journal_did = did.clone();
    let checked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = checked.clone();
    let handler = gw.clone();
    world
        .api_service
        .set_labyrinth_handler(Arc::new(move |req| {
            if req.nsid == "blue.catbird.labyrinth.deleteAccountData" {
                assert!(journal
                    .load_status(&journal_did)
                    .unwrap()
                    .pending_remote_deletion
                    .is_some());
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            handler.submit_labyrinth(req)
        }));
    *gw.fail_nsid.lock().unwrap() = Some("blue.catbird.labyrinth.deleteAccountData".into());
    let report = o.labyrinth_delete_account().await.unwrap();
    assert!(checked.load(std::sync::atomic::Ordering::SeqCst));
    assert!(report.remote_pending.is_some());
    assert!(
        !o.labyrinth_is_enabled().await.unwrap(),
        "local state erased"
    );
    let status = o.labyrinth_archive_status().await.unwrap();
    assert!(status.status.pending_remote_deletion.is_some());
    assert!(o.labyrinth_enable().await.is_err(), "refused while pending");
    let before_restore = gw.log.lock().unwrap().len();
    let error = o
        .labyrinth_restore_with_recovery_code(&recovery)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deletion is still pending"));
    assert!(
        gw.log.lock().unwrap()[before_restore..]
            .iter()
            .all(|request| request.nsid == "blue.catbird.labyrinth.deleteAccountData"),
        "pending deletion must prevent all recovery reads and enrollment writes"
    );
    assert!(!o.labyrinth_is_enabled().await.unwrap());

    *gw.fail_nsid.lock().unwrap() = None;
    assert!(o.labyrinth_retry_remote_deletion().await.unwrap());
    let status = o.labyrinth_archive_status().await.unwrap();
    assert!(status.status.pending_remote_deletion.is_none());
    o.labyrinth_enable().await.unwrap();
    assert!(o.labyrinth_is_enabled().await.unwrap());
}

/// Cancellation of the async retry cannot release lifecycle exclusion while
/// its blocking network operation is still deleting the old mailbox.
#[tokio::test(flavor = "multi_thread")]
async fn in_flight_deletion_serializes_retry_and_reenable_after_caller_cancellation() {
    use crate::recovery_e2e_harness::TestWorld;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Condvar;

    let gw = RefGateway::new();
    let mut world = TestWorld::new();
    let handler = gw.clone();
    world
        .api_service
        .set_labyrinth_handler(Arc::new(move |request| handler.submit_labyrinth(request)));
    world.add_client("Alice").await;
    world.register_device("Alice").await.unwrap();
    let alice = world.client("Alice");
    let (device, key) = super::chat_device(&alice.orchestrator, &alice.did).await;
    gw.register(&alice.did, &device, key);
    let o = &alice.orchestrator;
    o.labyrinth_enable().await.unwrap();
    *gw.fail_nsid.lock().unwrap() = Some("blue.catbird.labyrinth.deleteAccountData".into());
    assert!(o
        .labyrinth_delete_account()
        .await
        .unwrap()
        .remote_pending
        .is_some());
    *gw.fail_nsid.lock().unwrap() = None;

    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let release = ReleaseOnDrop(gate.clone());
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let entered = Arc::new(Mutex::new(Some(entered)));
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let handler = gw.clone();
    world
        .api_service
        .set_labyrinth_handler(Arc::new(move |request| {
            if request.nsid == "blue.catbird.labyrinth.deleteAccountData" {
                observed.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = entered.lock().unwrap().take() {
                    let _ = entered.send(());
                    let (lock, wake) = &*gate;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = wake.wait(released).unwrap();
                    }
                }
            }
            handler.submit_labyrinth(request)
        }));
    let mut cancelled_retry = Box::pin(o.labyrinth_retry_remote_deletion());
    tokio::select! {
        result = &mut cancelled_retry => panic!("retry finished before release: {result:?}"),
        result = waiting => result.unwrap(),
    }
    drop(cancelled_retry);
    assert!(o.labyrinth_archive().lifecycle_lock().try_lock().is_err());

    let mut retry = Box::pin(o.labyrinth_retry_remote_deletion());
    let mut enable = Box::pin(o.labyrinth_enable());
    tokio::select! {
        result = &mut retry => panic!("second retry crossed active purge: {result:?}"),
        result = &mut enable => panic!("enable crossed active purge: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(release);
    let (retried, enabled) = tokio::join!(retry, enable);
    assert!(retried.unwrap());
    enabled.unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "queued retry must re-read cleared intent"
    );
    assert!(o.labyrinth_is_enabled().await.unwrap());
}

#[test]
fn space_transient_errors_do_not_increment_failures_or_quarantine() {
    use super::super::flush::is_transient;

    for msg in [
        "space 503: ServiceUnavailable: upstream timeout",
        "space 429: RateLimitExceeded: slow down",
        "space 408: RequestTimeout: timed out",
        "space 0: connection reset by peer",
    ] {
        assert!(
            is_transient(&labyrinth::Error::Backend(msg.into())),
            "expected transient classification for {msg}"
        );
    }
    assert!(!is_transient(&labyrinth::Error::Backend(
        "space 403: Forbidden: scope missing".into()
    )));
}

#[test]
fn f01_ds_phantom_active_did_in_roster_is_rejected_without_create_mek() {
    const MALLORY: &str = "did:plc:mallory";
    const M1: &str = "44444444-4444-4444-8444-444444444444";

    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mallory = Device::new(&gw, MALLORY, M1, 4);
    let mut a = alice.deps.clone().enable().unwrap();
    let _b = bob.deps.clone().enable().unwrap();
    let mut m = mallory.deps.clone().enable().unwrap();

    // Mallory was added to mls-ds's unverified conversation state (`Device::new`
    // calls `add_leaf(THREAD, ...)`), while Alice's local OpenMLS ratchet tree
    // at send time only contained [ALICE, BOB].
    let q = MemQueue::default();
    let queued = row(THREAD, 1).with_mls_snapshot("aa11", 1, vec![ALICE.into(), BOB.into()]);
    q.put(&queued).unwrap();

    let log_before = gw.log.lock().unwrap().len();
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!(
        (r.archived, r.failed_conversations),
        (0, 1),
        "phantom active DID in mls-ds roster must fail closed"
    );
    let sent_nsids: Vec<String> = gw.log.lock().unwrap()[log_before..]
        .iter()
        .map(|req| req.nsid.clone())
        .collect();
    assert!(
        !sent_nsids
            .iter()
            .any(|n| n == "blue.catbird.labyrinth.createMek"
                || n == "blue.catbird.labyrinth.appendBatch"),
        "must not wrap MEK or append batch on phantom DS participant: {sent_nsids:?}"
    );
    let rows = q.list(ALICE).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("non-mls participant"),
        "expected non-mls participant error, got {:?}",
        rows[0].last_error
    );
    assert!(
        copies(&mut m).is_empty(),
        "Mallory must never receive a wrapped MEK"
    );
}

#[test]
fn f01_ds_omitted_participant_in_roster_is_rejected_without_create_mek() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let _b = bob.deps.clone().enable().unwrap();

    // mls-ds omits Bob's entire participant JSON entry from getConversationState.
    gw.state_overrides.lock().unwrap().insert(
        THREAD.to_owned(),
        GatewayResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: serde_json::to_vec(&serde_json::json!({
                "state": {
                    "participants": [
                        {"userDid": ALICE, "status": "active", "leafCount": 1}
                    ]
                }
            }))
            .unwrap(),
        },
    );

    let q = MemQueue::default();
    q.put(&row(THREAD, 1).with_mls_snapshot("aa11", 1, vec![ALICE.into(), BOB.into()]))
        .unwrap();

    let log_before = gw.log.lock().unwrap().len();
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!(
        (r.archived, r.failed_conversations),
        (0, 1),
        "omitted MLS participant in DS roster must fail closed"
    );
    let sent_nsids: Vec<String> = gw.log.lock().unwrap()[log_before..]
        .iter()
        .map(|req| req.nsid.clone())
        .collect();
    assert!(
        !sent_nsids
            .iter()
            .any(|n| n == "blue.catbird.labyrinth.createMek"
                || n == "blue.catbird.labyrinth.appendBatch"),
        "must not wrap MEK or append batch when DS omits participant: {sent_nsids:?}"
    );
    let rows = q.list(ALICE).unwrap();
    assert!(
        rows[0]
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("omits mls participant"),
        "expected omits mls participant error, got {:?}",
        rows[0].last_error
    );
}

#[test]
fn f01_pre_join_and_post_join_rows_never_share_mek_batch_with_new_member() {
    use super::super::session::{LocalConversationAuthority, LocalGroupSnapshot};

    const CAROL: &str = "did:plc:carol";
    const C1: &str = "55555555-5555-4555-8555-555555555555";

    struct FixedLocalAuthority(LocalGroupSnapshot);
    impl LocalConversationAuthority for FixedLocalAuthority {
        fn current_group_snapshot(
            &self,
            _conversation_id: &str,
            _queued_group_id_hex: Option<&str>,
        ) -> crate::orchestrator::error::Result<Option<LocalGroupSnapshot>> {
            Ok(Some(self.0.clone()))
        }
    }

    let gw = RefGateway::new();
    let mut alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();

    // Epoch 1 message queued before Carol joins: only [ALICE, BOB] were in MLS.
    let q = MemQueue::default();
    q.put(&row(THREAD, 1).with_mls_snapshot("aa11", 1, vec![ALICE.into(), BOB.into()]))
        .unwrap();

    // Carol joins at Epoch 2 before the background flush runs; Alice queues m2 at Epoch 2.
    let carol = Device::new(&gw, CAROL, C1, 5);
    let mut c = carol.deps.clone().enable().unwrap();
    alice.deps.local_authority = Some(Arc::new(FixedLocalAuthority(LocalGroupSnapshot {
        group_id_hex: "aa11".into(),
        epoch: 2,
        member_dids: vec![ALICE.into(), BOB.into(), CAROL.into()],
    })));
    q.put(&row(THREAD, 2).with_mls_snapshot(
        "aa11",
        2,
        vec![ALICE.into(), BOB.into(), CAROL.into()],
    ))
    .unwrap();

    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.failed_conversations), (2, 0));

    let bob_msgs: Vec<String> = copies(&mut b).into_iter().map(|(id, _)| id).collect();
    assert_eq!(
        bob_msgs,
        vec![format!("{THREAD}-m1"), format!("{THREAD}-m2")]
    );

    let carol_page = c.load_history(THREAD, TimeRange::ALL).unwrap();
    let carol_msgs: Vec<String> = carol_page
        .messages
        .into_iter()
        .map(|m| m.message_id)
        .collect();
    assert_eq!(
        carol_msgs,
        vec![format!("{THREAD}-m2")],
        "Carol must NOT receive a wrapped MEK for pre-join Epoch 1 message"
    );
}

#[test]
fn f01_conversation_not_found_with_live_local_mls_group_retains_rows() {
    use super::super::session::{LocalConversationAuthority, LocalGroupSnapshot};

    struct LiveLocalAuthority;
    impl LocalConversationAuthority for LiveLocalAuthority {
        fn current_group_snapshot(
            &self,
            _conversation_id: &str,
            _queued_group_id_hex: Option<&str>,
        ) -> crate::orchestrator::error::Result<Option<LocalGroupSnapshot>> {
            Ok(Some(LocalGroupSnapshot {
                group_id_hex: "aa11".into(),
                epoch: 1,
                member_dids: vec![ALICE.into(), BOB.into()],
            }))
        }
    }

    let gw = RefGateway::new();
    let mut alice = Device::new(&gw, ALICE, A1, 1);
    let _bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    alice.deps.local_authority = Some(Arc::new(LiveLocalAuthority));

    // mls-ds returns 404 ConversationNotFound even though local MLS still holds the group.
    gw.state_overrides.lock().unwrap().insert(
        THREAD.to_owned(),
        GatewayResponse {
            status: 404,
            content_type: Some("application/json".into()),
            body: serde_json::to_vec(&serde_json::json!({
                "error": "ConversationNotFound",
                "message": "temporary replica lag"
            }))
            .unwrap(),
        },
    );

    let q = MemQueue::default();
    q.put(&row(THREAD, 1).with_mls_snapshot("aa11", 1, vec![ALICE.into(), BOB.into()]))
        .unwrap();

    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!(
        (r.archived, r.dropped, r.failed_conversations),
        (0, 0, 1),
        "404 ConversationNotFound while local MLS group exists must NOT drop rows"
    );
    let rows = q.list(ALICE).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].failures, 0, "must be treated as transient");
    assert!(!rows[0].quarantined);
    assert!(q.load_status(ALICE).unwrap().dropped.is_empty());
}

#[test]
fn f01_legacy_row_without_expected_roster_is_quarantined_without_mek() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let _bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();

    let q = MemQueue::default();
    // Legacy row without `expected_member_dids`
    q.put(&PendingArchive::new(
        ALICE,
        THREAD,
        "legacy-m1",
        1_791_000_000_001,
        b"legacy",
    ))
    .unwrap();

    let log_before = gw.log.lock().unwrap().len();
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.quarantined), (0, 1));
    assert!(
        gw.log.lock().unwrap()[log_before..]
            .iter()
            .all(|req| req.nsid != "blue.catbird.labyrinth.createMek"
                && req.nsid != "blue.catbird.labyrinth.appendBatch"),
        "legacy row without local MLS roster must never wrap a MEK"
    );
    let rows = q.list(ALICE).unwrap();
    assert!(rows[0].quarantined);
}

#[tokio::test(flavor = "multi_thread")]
async fn f14_sign_out_clears_status_metadata_while_preserving_pending_remote_deletion() {
    use super::super::status::{DroppedArchive, MemberExclusion, PendingDeletion};
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

    // Case 1: No pending remote deletion -> sign-out wipes excluded_members, dropped, and queued rows.
    let store = o.labyrinth_queue_store();
    store
        .update_status(&did, &mut |s| {
            s.exclude(MemberExclusion {
                conversation_id: THREAD.into(),
                did: BOB.into(),
                reason: "pin mismatch".into(),
                needs_repin: true,
                at_ms: 1,
            });
            s.drop_row(DroppedArchive {
                conversation_id: THREAD.into(),
                message_id: "m-dropped".into(),
                reason: "queue full".into(),
                at_ms: 2,
            });
        })
        .unwrap();
    let mut quarantined_row = PendingArchive::new(&did, THREAD, "m-q1", 3, b"secret");
    quarantined_row.quarantined = true;
    quarantined_row.last_error = Some("sensitive failure detail".into());
    store.put(&quarantined_row).unwrap();

    assert!(o.labyrinth_sign_out().await.unwrap());
    let report = o.labyrinth_archive_status().await.unwrap();
    assert!(
        report.status.excluded_members.is_empty(),
        "sign-out must wipe excluded_members metadata"
    );
    assert!(
        report.status.dropped.is_empty(),
        "sign-out must wipe dropped archive metadata"
    );
    assert!(report.quarantined.is_empty());
    assert!(report.status.pending_remote_deletion.is_none());

    // Case 2: Pending remote deletion IS set -> sign-out preserves pending_remote_deletion while wiping reports.
    let pending_del = PendingDeletion {
        attempts: 2,
        last_error: "503 Service Unavailable".into(),
        since_ms: 100,
        mailbox_placement: Some("mls-ds".into()),
        conversation_spaces: vec![THREAD.into()],
        space_cleanup_required: true,
    };
    store
        .update_status(&did, &mut |s| {
            s.pending_remote_deletion = Some(pending_del.clone());
            s.exclude(MemberExclusion {
                conversation_id: THREAD.into(),
                did: BOB.into(),
                reason: "stale exclusion".into(),
                needs_repin: false,
                at_ms: 101,
            });
            s.drop_row(DroppedArchive {
                conversation_id: THREAD.into(),
                message_id: "m-dropped-2".into(),
                reason: "stale drop".into(),
                at_ms: 102,
            });
        })
        .unwrap();

    assert!(!o.labyrinth_sign_out().await.unwrap());
    let report_after = o.labyrinth_archive_status().await.unwrap();
    assert!(report_after.status.excluded_members.is_empty());
    assert!(report_after.status.dropped.is_empty());
    assert_eq!(
        report_after.status.pending_remote_deletion,
        Some(pending_del),
        "sign-out must preserve pending_remote_deletion retry intent"
    );
}
