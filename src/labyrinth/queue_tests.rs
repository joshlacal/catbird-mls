//! Tests for the gap closures: the background archive queue (batching,
//! crash safety), the PDS `mailboxKeys` directory, chat-device revocation
//! and erasing saved state. A child of `tests.rs`, sharing its fixtures.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use labyrinth::store::pds::PdsRecords;
use labyrinth::store::TimeRange;

use super::super::queue::{flush_queue, ArchiveQueueStore, PendingArchive, QueueConfig};
use super::super::session::LabyrinthSession;
use super::super::status::ArchiveStatus;
use super::*;
use crate::orchestrator::error::Result as OResult;

const A1: &str = "11111111-1111-4111-8111-111111111111";
const A2: &str = "33333333-3333-4333-8333-333333333333";
const B1: &str = "22222222-2222-4222-8222-222222222222";

/// An in-memory queue whose `remove` can be made to fail (a crash between
/// the server write and the local removal).
#[derive(Default)]
pub(super) struct MemQueue {
    rows: Mutex<Vec<PendingArchive>>,
    fail_remove: AtomicBool,
    status: Mutex<HashMap<String, ArchiveStatus>>,
}

impl ArchiveQueueStore for MemQueue {
    fn load_status(&self, did: &str) -> OResult<ArchiveStatus> {
        Ok(self
            .status
            .lock()
            .unwrap()
            .get(did)
            .cloned()
            .unwrap_or_default())
    }
    fn save_status(&self, did: &str, status: &ArchiveStatus) -> OResult<()> {
        self.status
            .lock()
            .unwrap()
            .insert(did.to_owned(), status.clone());
        Ok(())
    }
    fn put(&self, row: &PendingArchive) -> OResult<()> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|r| !(r.did == row.did && r.message_id == row.message_id));
        rows.push(row.clone());
        Ok(())
    }
    fn list(&self, did: &str) -> OResult<Vec<PendingArchive>> {
        let mut v: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.did == did)
            .cloned()
            .collect();
        v.sort_by_key(|r| r.timestamp_ms);
        Ok(v)
    }
    fn remove(&self, did: &str, message_id: &str) -> OResult<()> {
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(OrchestratorError::Storage("simulated crash".into()));
        }
        self.rows
            .lock()
            .unwrap()
            .retain(|r| !(r.did == did && r.message_id == message_id));
        Ok(())
    }
}

pub(super) fn appends(gw: &RefGateway) -> usize {
    gw.log
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.nsid == "blue.catbird.labyrinth.appendBatch")
        .count()
}

fn queue(q: &MemQueue, n: u8) {
    q.put(&PendingArchive::new(
        ALICE,
        THREAD,
        &format!("m-{n}"),
        1_791_000_000_000 + u64::from(n),
        &[n; 4],
    ))
    .unwrap();
}

/// Message ids Bob reads, with how many copies each.
pub(super) fn copies(b: &mut LabyrinthSession) -> Vec<(String, usize)> {
    let page = b.load_history(THREAD, TimeRange::ALL).unwrap();
    let mut out: Vec<(String, usize)> = Vec::new();
    for m in page.messages {
        assert!(!m.conflict, "duplicate copy of {}", m.message_id);
        match out.iter_mut().find(|(id, _)| *id == m.message_id) {
            Some((_, n)) => *n += 1,
            None => out.push((m.message_id, 1)),
        }
    }
    out
}

#[test]
fn one_flush_writes_one_batch_for_many_queued_messages() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let q = MemQueue::default();
    for n in 1..=3 {
        queue(&q, n);
    }
    let before = appends(&gw);
    assert_eq!(flush_queue(&mut a, &alice.deps, &q).unwrap().archived, 3);
    assert_eq!(appends(&gw) - before, 1, "three messages, one appendBatch");
    assert!(q.list(ALICE).unwrap().is_empty());
    assert_eq!(
        flush_queue(&mut a, &alice.deps, &q).unwrap().left_queue(),
        0
    );
    let ids: Vec<String> = copies(&mut b).into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, ["m-1", "m-2", "m-3"]);
}

#[test]
fn a_crash_after_the_write_does_not_archive_twice() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let q = MemQueue::default();
    queue(&q, 1);
    queue(&q, 2);

    // The batch reaches the server, then the process dies before the rows
    // leave the queue.
    q.fail_remove.store(true, Ordering::SeqCst);
    assert!(flush_queue(&mut a, &alice.deps, &q).is_err());
    assert!(q.list(ALICE).unwrap().iter().all(|r| r.inflight));
    drop(a);

    // Restart: reopen from the vault; the inflight rows are found archived.
    q.fail_remove.store(false, Ordering::SeqCst);
    let mut a = alice.deps.clone().open().unwrap().unwrap();
    let writes = appends(&gw);
    assert_eq!(flush_queue(&mut a, &alice.deps, &q).unwrap().archived, 2);
    assert_eq!(appends(&gw), writes, "nothing was archived twice");
    assert_eq!(copies(&mut b), [("m-1".into(), 1), ("m-2".into(), 1)]);
}

#[test]
fn a_crash_before_the_write_archives_on_retry() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let q = MemQueue::default();
    queue(&q, 1);
    *gw.fail_nsid.lock().unwrap() = Some("blue.catbird.labyrinth.appendBatch".into());
    let r = flush_queue(&mut a, &alice.deps, &q).unwrap();
    assert_eq!((r.archived, r.failed_conversations), (0, 1));
    // A dropped connection is transient: recorded, not counted.
    let rows = q.list(ALICE).unwrap();
    assert!(rows[0].last_error.is_some() && rows[0].failures == 0 && !rows[0].quarantined);
    drop(a);
    *gw.fail_nsid.lock().unwrap() = None;
    queue(&q, 2);
    let mut a = alice.deps.clone().open().unwrap().unwrap();
    assert_eq!(flush_queue(&mut a, &alice.deps, &q).unwrap().archived, 2);
    assert_eq!(copies(&mut b), [("m-1".into(), 1), ("m-2".into(), 1)]);
}

/// Every account's `mailboxKeys` records: (did, rkey) → bytes.
pub(super) type Repos = Arc<Mutex<HashMap<(String, String), Vec<u8>>>>;

pub(super) struct MockPds {
    pub(super) me: String,
    pub(super) repos: Repos,
}

impl PdsRecords for MockPds {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        self.repos
            .lock()
            .unwrap()
            .insert((self.me.clone(), rkey.to_owned()), record.to_vec());
        Ok(())
    }
    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .repos
            .lock()
            .unwrap()
            .get(&(did.to_owned(), rkey.to_owned()))
            .cloned())
    }
    fn delete_all_mailbox_keys(&self) -> Result<(), String> {
        self.repos.lock().unwrap().retain(|(d, _), _| *d != self.me);
        Ok(())
    }
}

pub(super) fn with_pds(mut d: Device, repos: &Repos) -> Device {
    d.deps.pds = Some(Arc::new(MockPds {
        me: d.deps.did.clone(),
        repos: repos.clone(),
    }));
    d
}

#[test]
fn epochs_are_published_to_the_pds_and_cross_checked() {
    let gw = RefGateway::new();
    let repos = Repos::default();
    // Alice enabled before PDS publication existed; reopening backfills.
    let alice = Device::new(&gw, ALICE, A1, 1);
    drop(alice.deps.clone().enable().unwrap());
    assert!(repos.lock().unwrap().is_empty());
    let alice = with_pds(alice, &repos);
    let mut a = alice.deps.clone().open().unwrap().unwrap();
    for rkey in ["self", "000000000000"] {
        assert!(repos
            .lock()
            .unwrap()
            .contains_key(&(ALICE.into(), rkey.into())));
    }
    // Bob, enabled with the PDS, publishes at genesis and reads Alice
    // through the PDS + mls-ds composite.
    let bob = with_pds(Device::new(&gw, BOB, B1, 2), &repos);
    let mut b = bob.deps.clone().enable().unwrap();
    assert!(repos
        .lock()
        .unwrap()
        .contains_key(&(BOB.into(), "self".into())));
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    b.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"hi")
        .unwrap();
    assert_eq!(
        a.load_history(THREAD, TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        1
    );

    // A PDS serving a different head for Bob is a directory fork: Alice
    // refuses to address him.
    let alice_self = repos.lock().unwrap()[&(ALICE.into(), "self".into())].clone();
    repos
        .lock()
        .unwrap()
        .insert((BOB.into(), "self".into()), alice_self);
    let fresh = Device::new(
        &gw,
        "did:plc:carol",
        "44444444-4444-4444-8444-444444444444",
        4,
    );
    let mut c = with_pds(fresh, &repos).deps.enable().unwrap();
    let e = c
        .archive_sent(THREAD, &members, "m-2", 1_791_000_000_100, b"x")
        .unwrap_err();
    assert!(e.to_string().to_lowercase().contains("labyrinth"), "{e}");
}

#[test]
fn revoking_a_chat_device_revokes_its_labyrinth_device() {
    let gw = RefGateway::new();
    let alice1 = Device::new(&gw, ALICE, A1, 1);
    let mut a1 = alice1.deps.clone().enable().unwrap();
    let code = a1.create_recovery_code().unwrap();
    let alice2 = Device::new(&gw, ALICE, A2, 3);
    let a2 = alice2
        .deps
        .clone()
        .restore_with_recovery_code(&code)
        .unwrap();
    let chat2 = alice2.deps.signer.public_key();
    drop(a2);
    // Unknown chat key: nothing to revoke.
    assert!(a1.revoke_chat_device([9; 32]).unwrap().is_empty());
    // The chat device is revoked first, then its Labyrinth device.
    gw.net().remove_chat_device(ALICE, chat2, 1);
    let epochs = a1.revoke_chat_device(chat2).unwrap();
    assert_eq!(epochs.len(), 1);
    assert!(epochs[0] >= 1);
    assert!(a1.revoke_chat_device(chat2).unwrap().is_empty());
}

#[test]
fn forgetting_and_purging_erase_the_saved_state() {
    let gw = RefGateway::new();
    let alice = Device::new(&gw, ALICE, A1, 1);
    let bob = Device::new(&gw, BOB, B1, 2);
    let mut a = alice.deps.clone().enable().unwrap();
    let mut b = bob.deps.clone().enable().unwrap();
    let members = vec![ALICE.to_owned(), BOB.to_owned()];
    a.archive_sent(THREAD, &members, "m-1", 1_791_000_000_000, b"bye")
        .unwrap();

    // Sign-out on this device: local state only.
    let mut b2 = bob.deps.clone().open().unwrap().unwrap();
    b2.forget().unwrap();
    assert!(bob.deps.vault.load(BOB).unwrap().is_none());
    assert!(bob.deps.clone().open().unwrap().is_none());

    // Account deletion: server side, and the vault.
    let report = a.purge_account().unwrap();
    assert!(report.server_side);
    assert!(alice.deps.vault.load(ALICE).unwrap().is_none());
    let h = b.load_history(THREAD, TimeRange::ALL).unwrap();
    assert!(h.messages.is_empty());
}

/// The orchestrator's worker: off the send path, batched by size, and
/// flushed by time.
#[tokio::test(flavor = "multi_thread")]
async fn the_orchestrator_archives_in_the_background() {
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
    let convo = o.create_group("history", None, None).await.unwrap();
    let thread = convo.conversation_id.clone();
    gw.net().add_leaf(&thread, &did, key);
    o.labyrinth_enable().await.unwrap();

    async fn wait_for(gw: &RefGateway, n: usize) -> bool {
        for _ in 0..100 {
            if appends(gw) >= n {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    // Size: nothing until the second message, then one batch for both.
    o.labyrinth_set_archive_policy(QueueConfig {
        max_batch: 2,
        max_delay: Duration::from_secs(3600),
    });
    o.send_message(&thread, "one").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(appends(&gw), 0);
    o.send_message(&thread, "two").await.unwrap();
    assert!(wait_for(&gw, 1).await, "size-triggered flush");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(appends(&gw), 1, "two messages, one appendBatch");

    // Time: a lone message is flushed after max_delay.
    o.labyrinth_set_archive_policy(QueueConfig {
        max_batch: 100,
        max_delay: Duration::from_millis(200),
    });
    o.send_message(&thread, "three").await.unwrap();
    assert!(wait_for(&gw, 2).await, "time-triggered flush");
    assert_eq!(o.labyrinth_flush_archive().await.unwrap(), 0);

    // Sign-out erases this device's state.
    assert!(o.labyrinth_sign_out().await.unwrap());
    assert!(!o.labyrinth_is_enabled().await.unwrap());
}
