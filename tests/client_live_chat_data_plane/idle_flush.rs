//! `flush_labyrinth_queue` with nothing to archive: it stays local (no request at all) between
//! bounded idle refreshes, and still runs the full pass whenever local state records work.

use super::*;
use catbird_mls::client::LabyrinthBackupStatus;
use catbird_mls::sim_hooks::{FixedStepClock, OsSimEntropy, SimClientHooks, SimClock as _};

/// The engine refreshes an idle archive session at most once per this interval.
const IDLE_REFRESH_INTERVAL_MS: i64 = 10 * 60 * 1000;
const PENDING_DEVICE_ACTIVATION_REFRESH_STATE: &str = "pending_device_activation_refresh";

struct IdleFlushFixture {
    _tmp: tempfile::TempDir,
    ds: Arc<SharedMockDs>,
    clock: Arc<FixedStepClock>,
    cid: String,
    alice: Arc<CatbirdMlsClient>,
    _bob: Arc<CatbirdMlsClient>,
}

fn clocked_client(
    tmp: &tempfile::TempDir,
    ds: &Arc<SharedMockDs>,
    clock: &Arc<FixedStepClock>,
    name: &str,
    did: &str,
) -> Arc<CatbirdMlsClient> {
    let client = CatbirdMlsClient::open_with_hooks(
        CatbirdMlsClientConfig {
            storage_root: tmp.path().join(name).to_string_lossy().into_owned(),
            account_did: did.to_string(),
            device_id: new_id(),
            home_ds_did: DS_DID.to_string(),
            home_ds_endpoint: DS_URL.to_string(),
            pds_endpoint: PDS_URL.to_string(),
        },
        Arc::new(MemKeyStore::new()),
        ds.for_account(did),
        None,
        SimClientHooks::new(clock.clone(), Arc::new(OsSimEntropy)),
    )
    .expect("open clocked client");
    client.enroll_device(&oauth_scopes()).expect("enroll");
    client
}

/// Alice and Bob share a live group. Alice's archive is initialized by her first flush (it
/// creates the mailbox Space, her device and epoch 0) and her queue is drained. Every clock,
/// the fixture's included, moves only when the test moves it.
fn idle_flush_fixture() -> IdleFlushFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let clock = Arc::new(FixedStepClock::new(
        chrono::Utc::now().timestamp_millis(),
        0,
    ));
    let ds = SharedMockDs::new_with_now_fn(Arc::new({
        let clock = clock.clone();
        move || clock.now_ms()
    }));
    let alice = clocked_client(&tmp, &ds, &clock, "idle-alice", ALICE_DID);
    let bob = clocked_client(&tmp, &ds, &clock, "idle-bob", BOB_DID);
    let cid = new_id();
    alice
        .create_group(
            &cid,
            DS_DID,
            vec![BOB_DID.to_string()],
            Some("Idle flush".into()),
            None,
        )
        .expect("create group");
    bob.sync().expect("bob accepts the invite");
    alice.sync().expect("alice adds bob");
    bob.sync().expect("bob joins");
    alice
        .send_message(&cid, &new_id(), "first archived message")
        .expect("send");
    assert_eq!(
        alice.flush_labyrinth_queue().expect("initializing flush"),
        1,
        "the first flush initializes the archive and drains the queue"
    );
    assert!(queue_is_empty(&alice));
    IdleFlushFixture {
        _tmp: tmp,
        ds,
        clock,
        cid,
        alice,
        _bob: bob,
    }
}

fn queue_is_empty(client: &CatbirdMlsClient) -> bool {
    client
        .db()
        .read_tx(|tx| tx.list_labyrinth_queue(None, 10))
        .unwrap()
        .is_empty()
}

/// Runs one flush and returns `(its result, how many requests of any kind it made)`.
fn flush_counting_requests(f: &IdleFlushFixture) -> (Result<u32, MLSError>, usize) {
    f.ds.inner.lock().unwrap().http_log.clear();
    let flushed = f.alice.flush_labyrinth_queue();
    let requests = f.ds.inner.lock().unwrap().http_log.len();
    (flushed, requests)
}

fn assert_idle_flush_is_local(f: &IdleFlushFixture, why: &str) {
    let (flushed, requests) = flush_counting_requests(f);
    assert_eq!(flushed.expect("idle flush"), 0, "{why}");
    assert_eq!(requests, 0, "an idle flush must make no request: {why}");
}

fn assert_flush_runs_the_full_pass(f: &IdleFlushFixture, why: &str) {
    let (flushed, requests) = flush_counting_requests(f);
    assert_eq!(flushed.expect("full idle pass"), 0, "{why}");
    assert!(requests > 0, "the full pass must reach the servers: {why}");
}

fn edit_status(client: &CatbirdMlsClient, edit: impl FnOnce(&mut LabyrinthBackupStatus)) {
    client
        .db()
        .write_tx(|tx| {
            let raw = tx.get_labyrinth_state("status_json")?.expect("status");
            let mut status: LabyrinthBackupStatus = serde_json::from_slice(&raw).unwrap();
            edit(&mut status);
            tx.put_labyrinth_state("status_json", &serde_json::to_vec(&status).unwrap(), 0)
        })
        .unwrap();
}

#[test]
fn idle_flush_makes_no_request_and_a_later_queued_message_still_archives() {
    let f = idle_flush_fixture();
    let before = f.alice.labyrinth_status().expect("status");
    for _ in 0..3 {
        assert_idle_flush_is_local(&f, "empty queue right after a full pass");
    }
    assert_eq!(
        f.alice.labyrinth_status().expect("status"),
        before,
        "an idle flush leaves the backup status as it was"
    );

    f.alice
        .send_message(&f.cid, &new_id(), "second archived message")
        .expect("send");
    let writes = f.ds.archive_auth.committed_space_write_count();
    let (flushed, requests) = flush_counting_requests(&f);
    assert_eq!(flushed.expect("flush a queued message"), 1);
    assert!(requests > 0);
    assert!(
        f.ds.archive_auth.committed_space_write_count() > writes,
        "the queued message is archived to its Space"
    );
    assert!(queue_is_empty(&f.alice));
    assert_idle_flush_is_local(&f, "empty queue after the second full pass");
}

#[test]
fn idle_flush_runs_the_full_pass_while_local_state_records_held_work() {
    let f = idle_flush_fixture();
    assert_idle_flush_is_local(&f, "baseline");

    // A held directory publication is retried by the very next pass.
    let epoch = f.alice.labyrinth_status().unwrap().epoch_seq;
    edit_status(&f.alice, |status| {
        status.pending_directory_epoch = Some(epoch)
    });
    assert_flush_runs_the_full_pass(&f, "held directory publication");
    assert_eq!(
        f.alice.labyrinth_status().unwrap().pending_directory_epoch,
        None,
        "the session, which holds nothing, corrects the status"
    );
    assert_idle_flush_is_local(&f, "after the held publication completed");

    // So is a publication whose last attempt failed.
    edit_status(&f.alice, |status| {
        status.directory_publication_error = Some("store refused access".into())
    });
    assert_flush_runs_the_full_pass(&f, "recorded publication failure");
    assert_eq!(
        f.alice
            .labyrinth_status()
            .unwrap()
            .directory_publication_error,
        None
    );
    assert_idle_flush_is_local(&f, "after the publication failure cleared");

    // And a device activation refresh that a completed publication left pending.
    f.alice
        .db()
        .write_tx(|tx| tx.put_labyrinth_state(PENDING_DEVICE_ACTIVATION_REFRESH_STATE, b"1", 0))
        .unwrap();
    assert_flush_runs_the_full_pass(&f, "pending device activation refresh");
    assert!(
        labyrinth_state(&f.alice, PENDING_DEVICE_ACTIVATION_REFRESH_STATE).is_none(),
        "the full pass completes the activation refresh"
    );
    assert_idle_flush_is_local(&f, "after the activation refresh completed");
}

#[test]
fn idle_flush_refreshes_the_session_once_per_interval() {
    let f = idle_flush_fixture();
    assert_idle_flush_is_local(&f, "baseline");

    f.clock.advance_ms(IDLE_REFRESH_INTERVAL_MS - 1);
    assert_idle_flush_is_local(&f, "one millisecond before the interval ends");
    f.clock.advance_ms(1);
    assert_flush_runs_the_full_pass(&f, "the interval has passed");
    assert_idle_flush_is_local(&f, "the refresh restarts the interval");

    // A clock that moved backwards proves nothing about how fresh the session is.
    f.clock.advance_ms(-1_000);
    assert_flush_runs_the_full_pass(&f, "the last refresh is in the future");
    assert_idle_flush_is_local(&f, "refreshed at the new clock");
}

#[test]
fn a_failed_pass_keeps_every_later_idle_flush_on_the_full_pass_until_one_succeeds() {
    let f = idle_flush_fixture();
    assert_idle_flush_is_local(&f, "baseline");

    // The session was refreshed a moment ago, then a pass with work to do fails.
    let id = new_id();
    f.alice
        .send_message(&f.cid, &id, "never archived")
        .expect("send");
    f.ds.archive_auth.set_write_outage(true);
    let (flushed, _) = flush_counting_requests(&f);
    assert!(flushed.is_err(), "the Space refuses the write");
    f.ds.archive_auth.set_write_outage(false);

    // The queue then empties without a pass (the author unsent the message). The failed pass
    // must not be mistaken for a fresh one.
    f.alice
        .db()
        .write_tx(|tx| tx.dequeue_labyrinth_item(&id))
        .unwrap();
    assert!(queue_is_empty(&f.alice));
    assert_flush_runs_the_full_pass(&f, "the last pass failed");
    assert_idle_flush_is_local(&f, "a pass succeeded since");
}
