//! Crash-safe durable Labyrinth archive queue (`labyrinthArchiveQueue`).
//!
//! Compliant with Spec §3.2 `G1`: holds zero internal `tokio::runtime::Runtime`
//! or detached `tokio::spawn` background tasks. Sent frames are durably queued in
//! the encrypted SQLite/SQLCipher database and flushed cooperatively when batch
//! thresholds are reached or when the platform calls `labyrinth_flush_archive`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use labyrinth::store::{MaybeSend, MaybeSync};
use serde::{Deserialize, Serialize};

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
    /// Skipped by flushes after [`MAX_FAILURES`] failures, until [`retry_quarantined`].
    #[serde(default)]
    pub quarantined: bool,
    /// Hex-encoded local OpenMLS group ID at send time.
    #[serde(default)]
    pub group_id_hex: Option<String>,
    /// Local OpenMLS epoch at send time.
    #[serde(default)]
    pub mls_epoch: Option<u64>,
    /// Sorted, deduplicated root account DIDs of active local OpenMLS leaves at send time.
    #[serde(default)]
    pub expected_member_dids: Option<Vec<String>>,
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
            group_id_hex: None,
            mls_epoch: None,
            expected_member_dids: None,
        }
    }

    pub fn with_mls_snapshot(
        mut self,
        group_id_hex: impl Into<String>,
        mls_epoch: u64,
        mut expected_member_dids: Vec<String>,
    ) -> Self {
        expected_member_dids.sort();
        expected_member_dids.dedup();
        self.group_id_hex = Some(group_id_hex.into());
        self.mls_epoch = Some(mls_epoch);
        self.expected_member_dids = Some(expected_member_dids);
        self
    }

    pub(crate) fn frame_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(&self.frame)
            .map_err(|_| OrchestratorError::Storage("labyrinth: corrupt queued frame".into()))
    }
}

/// Durable storage of the pending rows (one per sent message).
pub trait ArchiveQueueStore: MaybeSend + MaybeSync {
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
    /// Clears per-conversation status metadata (`excluded_members`, `dropped`)
    /// while preserving any `pending_remote_deletion` retry intent.
    fn clear_status_preserving_deletion(&self, did: &str) -> Result<()> {
        self.update_status(did, &mut |s| {
            s.excluded_members.clear();
            s.dropped.clear();
        })
    }
}

/// Queues `row` (the send path), keeping the account's queue within [`MAX_QUEUE_ROWS`].
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
        tracing::warn!(
            conversation_id = %d.conversation_id,
            reason,
            "labyrinth: archive row dropped"
        );
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

/// Clears quarantine on every row of `did` so the next flush retries them.
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

    fn clear_status_preserving_deletion(&self, did: &str) -> Result<()> {
        let current = self.load_status(did)?;
        if let Some(pending) = current.pending_remote_deletion.clone() {
            let preserved = ArchiveStatus {
                pending_remote_deletion: Some(pending),
                excluded_members: Vec::new(),
                dropped: Vec::new(),
            };
            if preserved != current {
                self.save_status(did, &preserved)?;
            }
        } else {
            self.0.delete_request_value(STATUS_NAMESPACE, did)?;
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

/// Cooperative batch policy for the archive queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueConfig {
    /// Flush immediately once this many rows are pending.
    pub max_batch: usize,
    /// Advisory maximum delay between flushes for platform schedulers.
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

/// Opens the session if needed and flushes pending archive rows. A failure drops
/// the in-memory session so its unflushed outbox is never reused.
pub async fn flush_in_slot(
    slot: LabyrinthSlot,
    deps: SessionDeps,
    store: Arc<dyn ArchiveQueueStore>,
) -> Result<FlushReport> {
    let mut guard = slot.lock().await;
    let key = deps.signer.public_key();
    if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
        *guard = deps.clone().open().await?;
    }
    let Some(session) = guard.as_mut() else {
        return Ok(FlushReport::default());
    };
    let out = flush_queue(session, &deps, store.as_ref()).await;
    if out.is_err() {
        *guard = None;
    }
    out
}

/// Cooperative archive queue state (`G1` zero-spawn design).
#[derive(Default)]
pub struct ArchiveWorker {
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    pending: Arc<AtomicUsize>,
    config: Mutex<QueueConfig>,
}

impl ArchiveWorker {
    pub(super) fn lifecycle_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.lifecycle.clone()
    }

    pub fn set_config(&self, config: QueueConfig) {
        *self.config.lock().unwrap_or_else(|e| e.into_inner()) = config;
    }

    pub fn config(&self) -> QueueConfig {
        *self.config.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enqueued(&self) -> usize {
        self.pending.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn should_auto_flush(&self) -> bool {
        let cfg = self.config();
        self.pending.load(Ordering::SeqCst) >= cfg.max_batch.max(1)
    }

    pub fn ensure(&self, already: usize) {
        self.pending.store(already, Ordering::SeqCst);
    }

    pub fn stop(&self) {
        self.pending.store(0, Ordering::SeqCst);
    }

    pub fn flushed(&self, n: usize) {
        let mut current = self.pending.load(Ordering::SeqCst);
        while let Err(actual) = self.pending.compare_exchange_weak(
            current,
            current.saturating_sub(n),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            current = actual;
        }
    }
}
