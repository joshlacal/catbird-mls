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
//! has passed since the first, then archives every pending row: rows are
//! marked `inflight`, grouped by conversation (one roster lookup each),
//! archived, written with one `flush` (one `appendBatch` per conversation,
//! [CB-20]), and only then removed.
//!
//! **Crash safety.** A row leaves the queue only after its batch was
//! written, so a crash loses nothing. A crash *after* the write but
//! *before* the removal leaves `inflight` rows behind; the next flush looks
//! each of those up (`load_message`) and drops the ones already archived
//! by this account instead of archiving them twice. A failed flush drops
//! the in-memory session, so its unflushed outbox is discarded and the
//! rows are retried from the queue.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::hooks::roster_members;
use super::session::{LabyrinthSession, SessionDeps};
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
}

impl PendingArchive {
    pub fn new(did: &str, conversation_id: &str, message_id: &str, ts: u64, frame: &[u8]) -> Self {
        Self {
            did: did.to_owned(),
            conversation_id: conversation_id.to_owned(),
            message_id: message_id.to_owned(),
            timestamp_ms: ts,
            frame: STANDARD.encode(frame),
            inflight: false,
        }
    }

    fn frame_bytes(&self) -> Result<Vec<u8>> {
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

/// Archives every pending row of the session's account (see the module
/// docs). Returns how many rows left the queue.
pub fn flush_queue(
    session: &mut LabyrinthSession,
    deps: &SessionDeps,
    store: &dyn ArchiveQueueStore,
) -> Result<usize> {
    let did = session.did().to_owned();
    let rows = store.list(&did)?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut done = 0;
    let mut todo: BTreeMap<String, Vec<PendingArchive>> = BTreeMap::new();
    for mut row in rows {
        if row.inflight && session.has_archived(&row.conversation_id, &row.message_id)? {
            store.remove(&did, &row.message_id)?;
            done += 1;
            continue;
        }
        if !row.inflight {
            row.inflight = true;
            store.put(&row)?;
        }
        todo.entry(row.conversation_id.clone()).or_default().push(row);
    }
    let mut batches = Vec::new();
    for (conversation, rows) in &todo {
        let members = conversation_roster(deps, conversation)?;
        let items = rows
            .iter()
            .map(|r| Ok((r.message_id.clone(), r.timestamp_ms, r.frame_bytes()?)))
            .collect::<Result<Vec<_>>>()?;
        batches.push((conversation.clone(), members, items));
    }
    session.archive_many(&batches)?;
    for row in todo.values().flatten() {
        store.remove(&did, &row.message_id)?;
        done += 1;
    }
    Ok(done)
}

/// The member DIDs of `conversation` from `getConversationState`.
fn conversation_roster(deps: &SessionDeps, conversation: &str) -> Result<Vec<String>> {
    let body = deps
        .transport
        .query(
            "blue.catbird.chat.getConversationState",
            &[("conversationId", conversation.to_owned())],
        )
        .map_err(|e| super::map_error(labyrinth::store::xrpc::map_error(e)))?;
    let state: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| OrchestratorError::Api(format!("labyrinth: conversation state: {e}")))?;
    Ok(roster_members(&state))
}

/// Opens the session if needed and flushes, on a blocking thread. A
/// failure drops the session so its unflushed outbox is not reused.
pub async fn flush_in_slot(
    slot: LabyrinthSlot,
    deps: SessionDeps,
    store: Arc<dyn ArchiveQueueStore>,
) -> Result<usize> {
    tokio::task::spawn_blocking(move || {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let key = deps.signer.public_key();
        if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
            *guard = deps.clone().open()?;
        }
        let Some(session) = guard.as_mut() else {
            return Ok(0);
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

/// The orchestrator's archive worker state (one account at a time).
#[derive(Default)]
pub struct ArchiveWorker {
    notify: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    config: Mutex<QueueConfig>,
    task: Mutex<Option<(String, [u8; 32], JoinHandle<()>)>>,
}

impl ArchiveWorker {
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
            Ok(n) => {
                let _ = pending.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |p| {
                    Some(p.saturating_sub(n))
                });
                if n == 0 {
                    // Nothing flushable (not enabled, or rows of another
                    // flush): wait for the next enqueue.
                    pending.store(0, Ordering::SeqCst);
                }
                backoff = config.max_delay;
            }
            Err(error) => {
                tracing::warn!(%error, "labyrinth: archive flush failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }
}
