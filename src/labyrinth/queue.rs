//! The background archive queue: sent messages are archived off the send
//! critical path, in batches, from crash-safe pending state
//! (docs/plans/2026-10-05-labyrinth-history-backup.md, D7 as amended).
//!
//! **Enqueue (send path).** The send hook writes one [`PendingArchive`]
//! row into the encrypted MLS database ([`MlsArchiveQueue`], request-value
//! namespace [`QUEUE_NAMESPACE`]) and wakes the worker. No network call
//! happens on the send path.
//!
//! **Flush (worker).** One worker per orchestrator and account waits until
//! [`QueueConfig::max_batch`] rows are pending or [`QueueConfig::max_delay`]
//! has passed since the first, then archives every pending row, one
//! conversation at a time ([`super::flush`]): rows are marked `inflight`,
//! the conversation's roster is resolved, its messages are archived and
//! written (one `appendBatch` per MEK, [CB-20]), and only then removed. One
//! conversation failing never holds back another.
//!
//! **Failures (review 2).** A roster member whose epoch fails a trust
//! check is excluded and reported, not fatal ([`super::status`]). A
//! conversation that fails for a non-transient reason counts a failure on
//! each of its rows; after [`MAX_FAILURES`] the rows are quarantined (kept,
//! skipped, reported) until the platform retries them. A conversation
//! mls-ds no longer has drops its rows with the reason recorded. The queue
//! holds at most [`MAX_QUEUE_ROWS`] rows per account: a full queue first
//! evicts quarantined rows, then refuses the new message, recording either
//! as dropped.
//!
//! **Crash safety.** A row leaves the queue only after its batch was
//! written, so a crash loses nothing. A crash *after* the write but
//! *before* the removal leaves `inflight` rows behind; the next flush looks
//! each of those up (`load_message`) and drops the ones already archived
//! by this account instead of archiving them twice. A failed flush drops
//! the in-memory session, so its unflushed outbox is discarded and the
//! rows are retried from the queue.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use super::flush::{flush_queue, FlushReport};
use super::session::SessionDeps;
use super::status::{now_ms, ArchiveStatus, DroppedArchive, STATUS_NAMESPACE};
use super::LabyrinthSlot;
use crate::orchestrator::error::{OrchestratorError, Result};
use crate::orchestrator::mls_provider::MlsCryptoContext;

/// Request-value namespace of the pending archive rows.
pub const QUEUE_NAMESPACE: &str = "labyrinthArchiveQueue";

/// One sent message waiting to be archived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingArchive {
    pub did: String,
    pub conversation_id: String,
    pub message_id: String,
    pub timestamp_ms: u64,
    /// The sent frame, base64.
    pub frame: String,
    /// Set just before a flush writes the row's batch.
    #[serde(default)]
    pub inflight: bool,
    /// Non-transient failures of this row's conversation so far.
    #[serde(default)]
    pub failures: u32,
    /// The last failure, transient or not.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Skipped by flushes after [`MAX_FAILURES`] failures, until
    /// [`retry_quarantined`].
    #[serde(default)]
    pub quarantined: bool,
}

/// Non-transient failures after which a row is quarantined.
pub const MAX_FAILURES: u32 = 5;

/// Most rows one account's queue holds.
pub const MAX_QUEUE_ROWS: usize = 1000;

impl PendingArchive {
    pub fn new(did: &str, conversation_id: &str, message_id: &str, ts: u64, frame: &[u8]) -> Self {
        Self {
            did: did.to_owned(),
            conversation_id: conversation_id.to_owned(),
            message_id: message_id.to_owned(),
            timestamp_ms: ts,
            frame: STANDARD.encode(frame),
            inflight: false,
            failures: 0,
            last_error: None,
            quarantined: false,
        }
    }

    pub(crate) fn frame_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(&self.frame)
            .map_err(|_| OrchestratorError::Storage("labyrinth: corrupt queued frame".into()))
    }
}

/// Durable storage of the pending rows (one per sent message).
pub trait ArchiveQueueStore: Send + Sync {
    fn put(&self, row: &PendingArchive) -> Result<()>;
    /// The account's rows, oldest first.
    fn list(&self, did: &str) -> Result<Vec<PendingArchive>>;
    fn remove(&self, did: &str, message_id: &str) -> Result<()>;
    /// Every row of the account (sign-out, account deletion).
    fn clear(&self, did: &str) -> Result<()> {
        for row in self.list(did)? {
            self.remove(did, &row.message_id)?;
        }
        Ok(())
    }
    /// The account's [`ArchiveStatus`] (default when none was saved).
    fn load_status(&self, did: &str) -> Result<ArchiveStatus>;
    fn save_status(&self, did: &str, status: &ArchiveStatus) -> Result<()>;
    /// Loads, changes and saves the account's status.
    fn update_status(&self, did: &str, f: &mut dyn FnMut(&mut ArchiveStatus)) -> Result<()> {
        let mut s = self.load_status(did)?;
        let before = s.clone();
        f(&mut s);
        if s != before {
            self.save_status(did, &s)?;
        }
        Ok(())
    }
}

/// Queues `row` (the send path), keeping the account's queue within
/// [`MAX_QUEUE_ROWS`]: a full queue evicts its oldest quarantined row,
/// else refuses `row`. Either is recorded as dropped. Returns whether
/// `row` was queued.
pub fn enqueue(store: &dyn ArchiveQueueStore, row: &PendingArchive) -> Result<bool> {
    let rows = store.list(&row.did)?;
    let mut dropped = None;
    if rows.len() >= MAX_QUEUE_ROWS {
        match rows.iter().find(|r| r.quarantined) {
            Some(old) => {
                store.remove(&old.did, &old.message_id)?;
                dropped = Some((old.clone(), "evicted from a full archive queue"));
            }
            None => dropped = Some((row.clone(), "archive queue full")),
        }
    }
    let queued = !dropped
        .as_ref()
        .is_some_and(|(d, _)| d.message_id == row.message_id);
    if queued {
        store.put(row)?;
    }
    if let Some((d, reason)) = dropped {
        tracing::warn!(conversation_id = %d.conversation_id, reason, "labyrinth: archive row dropped");
        store.update_status(&row.did, &mut |s| {
            s.drop_row(DroppedArchive {
                conversation_id: d.conversation_id.clone(),
                message_id: d.message_id.clone(),
                reason: reason.to_owned(),
                at_ms: now_ms(),
            })
        })?;
    }
    Ok(queued)
}

/// Clears quarantine on every row of `did` so the next flush retries
/// them. Returns how many were quarantined.
pub fn retry_quarantined(store: &dyn ArchiveQueueStore, did: &str) -> Result<usize> {
    let mut n = 0;
    for mut row in store.list(did)?.into_iter().filter(|r| r.quarantined) {
        row.quarantined = false;
        row.failures = 0;
        store.put(&row)?;
        n += 1;
    }
    Ok(n)
}

fn storage(e: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Storage(format!("labyrinth archive queue: {e}"))
}

/// [`ArchiveQueueStore`] in the encrypted MLS database.
pub struct MlsArchiveQueue<M>(pub Arc<M>);

fn row_id(did: &str, message_id: &str) -> String {
    format!("{did}|{message_id}")
}

impl<M: MlsCryptoContext + 'static> ArchiveQueueStore for MlsArchiveQueue<M> {
    fn load_status(&self, did: &str) -> Result<ArchiveStatus> {
        match self.0.read_request_value(STATUS_NAMESPACE, did)? {
            Some(v) => serde_json::from_slice(&v).map_err(storage),
            None => Ok(ArchiveStatus::default()),
        }
    }

    fn save_status(&self, did: &str, status: &ArchiveStatus) -> Result<()> {
        let next = serde_json::to_vec(status).map_err(storage)?;
        let old = self.0.read_request_value(STATUS_NAMESPACE, did)?;
        if !self
            .0
            .compare_exchange_request_value(STATUS_NAMESPACE, did, old.as_deref(), &next)?
        {
            return Err(storage("concurrent status write"));
        }
        Ok(())
    }

    fn put(&self, row: &PendingArchive) -> Result<()> {
        let id = row_id(&row.did, &row.message_id);
        let next = serde_json::to_vec(row).map_err(storage)?;
        let old = self.0.read_request_value(QUEUE_NAMESPACE, &id)?;
        if !self
            .0
            .compare_exchange_request_value(QUEUE_NAMESPACE, &id, old.as_deref(), &next)?
        {
            return Err(storage("concurrent queue write"));
        }
        Ok(())
    }

    fn list(&self, did: &str) -> Result<Vec<PendingArchive>> {
        let mut rows: Vec<PendingArchive> = self
            .0
            .list_request_values(QUEUE_NAMESPACE)?
            .iter()
            .filter_map(|v| serde_json::from_slice::<PendingArchive>(v).ok())
            .filter(|r| r.did == did)
            .collect();
        rows.sort_by_key(|r| r.timestamp_ms);
        Ok(rows)
    }

    fn remove(&self, did: &str, message_id: &str) -> Result<()> {
        self.0
            .delete_request_value(QUEUE_NAMESPACE, &row_id(did, message_id))?;
        Ok(())
    }
}

/// When the worker flushes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueConfig {
    /// Flush as soon as this many rows are pending.
    pub max_batch: usize,
    /// Otherwise flush this long after the first pending row.
    pub max_delay: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_batch: 32,
            max_delay: Duration::from_secs(2),
        }
    }
}

/// Opens the session if needed and flushes, on a blocking thread. A
/// failure drops the session so its unflushed outbox is not reused.
pub async fn flush_in_slot(
    slot: LabyrinthSlot,
    deps: SessionDeps,
    store: Arc<dyn ArchiveQueueStore>,
) -> Result<FlushReport> {
    tokio::task::spawn_blocking(move || {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let key = deps.signer.public_key();
        if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
            *guard = deps.clone().open()?;
        }
        let Some(session) = guard.as_mut() else {
            return Ok(FlushReport::default());
        };
        let out = flush_queue(session, &deps, store.as_ref());
        if out.is_err() {
            *guard = None;
        }
        out
    })
    .await
    .map_err(|e| OrchestratorError::Api(format!("labyrinth flush task failed: {e}")))?
}

/// The running worker: account DID, chat key, task.
type WorkerTask = (String, [u8; 32], JoinHandle<()>);

/// The orchestrator's archive worker state (one account at a time).
#[derive(Default)]
pub struct ArchiveWorker {
    /// Covers complete blocking remote deletion and enrollment operations.
    /// The guard lives inside the blocking task, so cancellation of its async
    /// caller cannot release it while a remote purge is still executing.
    lifecycle: Arc<Mutex<()>>,
    notify: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    config: Mutex<QueueConfig>,
    task: Mutex<Option<WorkerTask>>,
}

impl ArchiveWorker {
    pub(super) fn lifecycle_lock(&self) -> Arc<Mutex<()>> {
        self.lifecycle.clone()
    }

    pub fn set_config(&self, config: QueueConfig) {
        *self.config.lock().unwrap_or_else(|e| e.into_inner()) = config;
        self.notify.notify_one();
    }

    /// One more row is pending: wake the worker.
    pub fn enqueued(&self) {
        self.pending.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Starts the worker for `deps`' account and chat key unless it runs;
    /// a worker for another account is stopped first. `already` rows are
    /// pending from before (a previous process).
    pub fn ensure(
        &self,
        slot: LabyrinthSlot,
        deps: SessionDeps,
        store: Arc<dyn ArchiveQueueStore>,
        already: usize,
    ) {
        let mut task = self.task.lock().unwrap_or_else(|e| e.into_inner());
        let key = deps.signer.public_key();
        if let Some((did, k, h)) = task.as_ref() {
            if *did == deps.did && *k == key && !h.is_finished() {
                return;
            }
        }
        if let Some((_, _, h)) = task.take() {
            h.abort();
        }
        self.pending.store(already, Ordering::SeqCst);
        let config = *self.config.lock().unwrap_or_else(|e| e.into_inner());
        let (notify, pending) = (self.notify.clone(), self.pending.clone());
        let did = deps.did.clone();
        let handle = tokio::spawn(run(slot, deps, store, notify.clone(), pending, config));
        if already > 0 {
            notify.notify_one();
        }
        *task = Some((did, key, handle));
    }

    /// Stops the worker (shutdown, account switch, sign-out). Pending rows
    /// stay in the database.
    pub fn stop(&self) {
        if let Some((_, _, h)) = self.task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
    }

    /// Rows flushed outside the worker (an explicit flush).
    pub fn flushed(&self, n: usize) {
        let _ = self
            .pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |p| {
                Some(p.saturating_sub(n))
            });
    }
}

async fn run(
    slot: LabyrinthSlot,
    deps: SessionDeps,
    store: Arc<dyn ArchiveQueueStore>,
    notify: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    config: QueueConfig,
) {
    let mut backoff = config.max_delay;
    loop {
        if pending.load(Ordering::SeqCst) == 0 {
            notify.notified().await;
            continue;
        }
        let deadline = tokio::time::Instant::now() + config.max_delay;
        while pending.load(Ordering::SeqCst) < config.max_batch {
            tokio::select! {
                _ = notify.notified() => {}
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        match flush_in_slot(slot.clone(), deps.clone(), store.clone()).await {
            Ok(report) if report.failed_conversations == 0 => {
                let n = report.left_queue();
                let _ = pending.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |p| {
                    Some(p.saturating_sub(n))
                });
                if n == 0 {
                    // Nothing flushable (not enabled, quarantined, or rows
                    // of another flush): wait for the next enqueue.
                    pending.store(0, Ordering::SeqCst);
                }
                backoff = config.max_delay;
            }
            Ok(report) => {
                // Some conversations failed; their rows stay (or were
                // quarantined). Back off before retrying them.
                let n = report.left_queue();
                let _ = pending.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |p| {
                    Some(p.saturating_sub(n))
                });
                tracing::warn!(
                    failed = report.failed_conversations,
                    quarantined = report.quarantined,
                    "labyrinth: some conversations failed to archive; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
            Err(error) => {
                tracing::warn!(%error, "labyrinth: archive flush failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }
}
