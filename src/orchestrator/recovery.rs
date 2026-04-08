use std::collections::HashMap;
use std::time::Duration;
use web_time::Instant;

use base64::Engine;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

/// Tracks recovery state per conversation.
pub struct RecoveryTracker {
    /// Failed rejoin attempts per conversation.
    failed_rejoins: HashMap<String, (u32, Instant)>,
    /// Last successful or attempted rejoin on ANY conversation (regardless of outcome).
    /// Used to enforce a hard global minimum interval between any rejoin attempts,
    /// preventing epoch inflation spirals even when attempts succeed.
    pub(crate) last_global_rejoin_at: Option<Instant>,
    /// Maximum rejoin attempts before giving up.
    max_attempts: u32,
}

impl RecoveryTracker {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            failed_rejoins: HashMap::new(),
            last_global_rejoin_at: None,
            max_attempts,
        }
    }

    pub fn cooldown_for_attempts(&self, attempts: u32) -> Duration {
        if attempts == 0 {
            return Duration::from_secs(0);
        }
        // Spec §10: REJOIN_BACKOFF = [30s, 2m, 10m] indexed by attempt (1-based)
        let index = (attempts as usize).saturating_sub(1);
        if index < constants::REJOIN_BACKOFF.len() {
            constants::REJOIN_BACKOFF[index]
        } else {
            // Beyond defined backoff: use the last value
            *constants::REJOIN_BACKOFF.last().unwrap()
        }
    }

    /// Whether max attempts have been reached.
    pub fn is_maxed_out(&self, convo_id: &str) -> bool {
        let Some((attempts, _)) = self.failed_rejoins.get(convo_id) else {
            return false;
        };
        *attempts >= self.max_attempts
    }

    /// Remaining cooldown before the next rejoin attempt is eligible.
    pub fn cooldown_remaining(&self, convo_id: &str) -> Option<Duration> {
        let (attempts, last_attempt) = self.failed_rejoins.get(convo_id)?;
        if *attempts == 0 || *attempts >= self.max_attempts {
            return None;
        }

        let cooldown = self.cooldown_for_attempts(*attempts);
        let elapsed = last_attempt.elapsed();
        if elapsed >= cooldown {
            None
        } else {
            Some(cooldown - elapsed)
        }
    }

    /// Whether a conversation should skip rejoin (max attempts, cooldown, or min interval).
    pub fn should_skip(&self, convo_id: &str) -> bool {
        if self.is_maxed_out(convo_id) || self.cooldown_remaining(convo_id).is_some() {
            return true;
        }
        // Global minimum interval: no rejoin on ANY conversation within MIN_REJOIN_INTERVAL
        if let Some(last) = self.last_global_rejoin_at {
            if last.elapsed() < constants::MIN_REJOIN_INTERVAL {
                return true;
            }
        }
        false
    }

    /// Record a failed rejoin attempt.
    pub fn record_failure(&mut self, convo_id: &str) {
        let now = Instant::now();
        let entry = self
            .failed_rejoins
            .entry(convo_id.to_string())
            .or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        self.last_global_rejoin_at = Some(now);
    }

    /// Clear failure tracking on success.
    /// Note: does NOT clear `last_global_rejoin_at` — the minimum interval still applies
    /// to prevent rapid successive rejoins even when they succeed.
    pub fn clear(&mut self, convo_id: &str) {
        self.failed_rejoins.remove(convo_id);
        // Record the current time globally so the MIN_REJOIN_INTERVAL applies across all convos
        self.last_global_rejoin_at = Some(Instant::now());
    }
}

/// Diagnostic status of a conversation's sequencer connectivity.
#[derive(Debug, Clone)]
pub enum FailoverStatus {
    /// No failures recorded — sequencer is reachable.
    Healthy,
    /// Some failures but below the failover threshold.
    Degraded {
        consecutive_failures: u32,
        since: Instant,
    },
    /// Threshold exceeded — the caller should switch to a backup sequencer.
    FailoverRecommended {
        consecutive_failures: u32,
        since: Instant,
    },
}

/// Internal per-conversation failure tracking state.
struct FailoverState {
    consecutive_failures: u32,
    first_failure_at: Instant,
    last_failure_at: Instant,
}

/// Tracks consecutive sequencer failures per conversation to detect when
/// failover should be triggered.
///
/// This is a pure state tracker — it does not perform network calls or async
/// work. The caller is responsible for calling [`record_failure`] only for
/// connection/timeout errors (not business-logic errors like 409 Conflict).
pub struct SequencerFailoverTracker {
    failures: HashMap<String, FailoverState>,
}

impl SequencerFailoverTracker {
    pub fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    /// Record a connection/timeout failure for a conversation's sequencer.
    pub fn record_failure(&mut self, convo_id: &str) {
        let now = Instant::now();
        let state = self
            .failures
            .entry(convo_id.to_string())
            .and_modify(|s| {
                s.consecutive_failures += 1;
                s.last_failure_at = now;
            })
            .or_insert(FailoverState {
                consecutive_failures: 1,
                first_failure_at: now,
                last_failure_at: now,
            });
        tracing::debug!(
            convo_id,
            consecutive_failures = state.consecutive_failures,
            "Sequencer failure recorded"
        );
    }

    /// Record a successful sequencer interaction, clearing failure state.
    pub fn record_success(&mut self, convo_id: &str) {
        if self.failures.remove(convo_id).is_some() {
            tracing::debug!(convo_id, "Sequencer failure state cleared on success");
        }
    }

    /// Whether failover is recommended for this conversation.
    ///
    /// Returns `true` when both conditions are met:
    /// - At least [`FAILOVER_MIN_FAILURES`] consecutive failures
    /// - The first failure occurred at least [`FAILOVER_MIN_DURATION`] ago
    pub fn should_failover(&self, convo_id: &str) -> bool {
        let Some(state) = self.failures.get(convo_id) else {
            return false;
        };
        state.consecutive_failures >= constants::FAILOVER_MIN_FAILURES
            && state.first_failure_at.elapsed() >= constants::FAILOVER_MIN_DURATION
    }

    /// Reset failure tracking after a successful failover.
    pub fn clear(&mut self, convo_id: &str) {
        self.failures.remove(convo_id);
    }

    /// Get the current failover diagnostic status for a conversation.
    pub fn get_status(&self, convo_id: &str) -> Option<FailoverStatus> {
        let state = self.failures.get(convo_id)?;
        if self.should_failover(convo_id) {
            Some(FailoverStatus::FailoverRecommended {
                consecutive_failures: state.consecutive_failures,
                since: state.first_failure_at,
            })
        } else {
            Some(FailoverStatus::Degraded {
                consecutive_failures: state.consecutive_failures,
                since: state.first_failure_at,
            })
        }
    }
}

/// Tracks consecutive GroupInfo 404 responses per conversation.
/// After GROUPINFO_404_CIRCUIT_BREAKER (3) consecutive 404s, the circuit
/// trips and External Commit attempts should be skipped for that conversation.
pub struct GroupInfo404Tracker {
    counts: HashMap<String, u32>,
}

impl GroupInfo404Tracker {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn record_404(&mut self, convo_id: &str) {
        let count = self.counts.entry(convo_id.to_string()).or_insert(0);
        *count += 1;
    }

    pub fn is_tripped(&self, convo_id: &str) -> bool {
        self.counts
            .get(convo_id)
            .is_some_and(|c| *c >= constants::GROUPINFO_404_CIRCUIT_BREAKER)
    }

    pub fn clear(&mut self, convo_id: &str) {
        self.counts.remove(convo_id);
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(crate) async fn attempt_fork_readd(&self, convo_id: &str) -> Result<()> {
        let user_did = self.require_user_did().await?;
        let lock = self.rejoin_lock(convo_id).await;
        let _g = match lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                return Ok(());
            }
        };
        let ok = {
            let fds = self
                .fork_detection_states()
                .lock()
                .map_err(|_| OrchestratorError::RecoveryFailed("lock".into()))?;
            fds.get(convo_id)
                .is_some_and(|s| s.readd_attempts < constants::FORK_READD_MAX_ATTEMPTS)
        };
        if !ok {
            return Ok(());
        }
        {
            let mut fds = self
                .fork_detection_states()
                .lock()
                .map_err(|_| OrchestratorError::RecoveryFailed("lock".into()))?;
            if let Some(s) = fds.get_mut(convo_id) {
                s.readd_attempts += 1;
            }
        }
        let gid =
            hex::decode(convo_id).map_err(|_| OrchestratorError::InvalidInput("bad hex".into()))?;
        let mems: Vec<String> = {
            let st = self.group_states().lock().await;
            st.get(convo_id)
                .map(|g| g.members.clone())
                .unwrap_or_default()
        };
        if mems.is_empty() {
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed("no members".into()));
        }
        let kp_refs = match self.api_client().get_key_packages(&mems).await {
            Ok(r) => r,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
            }
        };
        let kps: Vec<Vec<u8>> = kp_refs.iter().map(|r| r.key_package_data.clone()).collect();
        let (commit, _) = match self
            .mls_context()
            .recover_fork_by_readding(gid.clone(), kps)
        {
            Ok(r) => r,
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
            }
        };
        let tag = self
            .mls_context()
            .get_confirmation_tag(gid.clone())
            .map(|t| base64::engine::general_purpose::STANDARD.encode(&t))
            .ok();
        if let Err(e) = self
            .api_client()
            .commit_group_change(convo_id, &commit, "forkReadd", tag.as_deref())
            .await
        {
            let _ = self.mls_context().clear_pending_commit(gid);
            self.escalate_fork_to_rejoin(convo_id).await;
            return Err(OrchestratorError::RecoveryFailed(format!("{e}")));
        }
        match self.mls_context().merge_pending_commit(gid.clone()) {
            Ok(ep) => {
                // Cleanup old epoch secrets after fork readd
                self.cleanup_epoch_secrets_if_needed(convo_id, ep).await;

                {
                    let mut st = self.group_states().lock().await;
                    if let Some(gs) = st.get_mut(convo_id) {
                        gs.epoch = ep;
                        let sc = gs.clone();
                        drop(st);
                        let _ = self.storage().set_group_state(&sc).await;
                    }
                }
                {
                    let mut fds = self
                        .fork_detection_states()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    fds.remove(convo_id);
                }
                self.decrypt_fail_counts().lock().await.remove(convo_id);
                self.conversation_states()
                    .lock()
                    .await
                    .insert(convo_id.to_string(), ConversationState::Active);
                if let Ok(gi) = self
                    .mls_context()
                    .export_group_info(gid, user_did.as_bytes().to_vec())
                {
                    let _ = self.api_client().publish_group_info(convo_id, &gi).await;
                }
                tracing::info!(convo_id, "Fork readd succeeded");
                Ok(())
            }
            Err(e) => {
                self.escalate_fork_to_rejoin(convo_id).await;
                Err(OrchestratorError::RecoveryFailed(format!("{e}")))
            }
        }
    }
    async fn escalate_fork_to_rejoin(&self, convo_id: &str) {
        {
            let mut fds = self
                .fork_detection_states()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            fds.remove(convo_id);
        }
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), ConversationState::NeedsRejoin);
        let _ = self.storage().mark_needs_rejoin(convo_id).await;
        tracing::info!(convo_id, "Fork escalated to NeedsRejoin");
    }

    pub(crate) async fn should_attempt_sync_rejoin(&self, convo_id: &str) -> bool {
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let lock_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::debug!(
                    convo_id,
                    "Skipping sync-triggered join/rejoin: attempt already in-flight"
                );
                return false;
            }
        };
        drop(lock_guard);

        if let Err(err) = self.enforce_rejoin_backoff(convo_id).await {
            tracing::debug!(
                convo_id,
                error = %err,
                "Skipping sync-triggered join/rejoin: recovery backoff active"
            );
            return false;
        }

        true
    }

    async fn enforce_rejoin_backoff(&self, convo_id: &str) -> Result<()> {
        let tracker = self.recovery_tracker().lock().await;
        if tracker.is_maxed_out(convo_id) {
            tracing::warn!(
                convo_id,
                max_attempts = self.config().max_rejoin_attempts,
                "Rejoin suppressed: max attempts reached, reporting recovery failure"
            );
            // Drop lock before async call
            drop(tracker);
            // Report failure to server for quorum-based auto-reset
            if let Err(e) = self
                .api_client()
                .report_recovery_failure(convo_id, "external_commit_exhausted")
                .await
            {
                tracing::warn!(
                    convo_id,
                    error = %e,
                    "Failed to report recovery failure to server"
                );
            }
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Rejoin suppressed for {convo_id}: max attempts reached"
            )));
        }

        if let Some(remaining) = tracker.cooldown_remaining(convo_id) {
            tracing::info!(
                convo_id,
                remaining_secs = remaining.as_secs(),
                "Rejoin suppressed: cooldown active"
            );
            return Err(OrchestratorError::RecoveryFailed(format!(
                "Rejoin suppressed for {convo_id}: cooldown active ({}s remaining)",
                remaining.as_secs()
            )));
        }

        // Hard minimum interval between any rejoin attempts (even successful ones)
        if let Some(last) = tracker.last_global_rejoin_at {
            let elapsed = last.elapsed();
            if elapsed < constants::MIN_REJOIN_INTERVAL {
                let remaining = constants::MIN_REJOIN_INTERVAL - elapsed;
                tracing::info!(
                    convo_id,
                    remaining_secs = remaining.as_secs(),
                    "Rejoin suppressed: minimum interval not elapsed"
                );
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Rejoin suppressed for {convo_id}: minimum interval ({}s remaining)",
                    remaining.as_secs()
                )));
            }
        }

        Ok(())
    }

    async fn clear_rejoin_failures(&self, convo_id: &str) {
        self.recovery_tracker().lock().await.clear(convo_id);
    }

    async fn record_rejoin_failure(&self, convo_id: &str) {
        self.recovery_tracker()
            .lock()
            .await
            .record_failure(convo_id);
    }

    fn local_group_epoch(&self, convo_id: &str) -> Option<u64> {
        let group_id_bytes = hex::decode(convo_id).ok()?;
        self.mls_context().get_epoch(group_id_bytes).ok()
    }

    async fn force_rejoin_unlocked(&self, convo_id: &str, user_did: &str) -> Result<()> {
        tracing::info!(convo_id, "Attempting force rejoin via External Commit");

        // Check GroupInfo 404 circuit breaker
        {
            let tracker = self.groupinfo_404_tracker().lock().await;
            if tracker.is_tripped(convo_id) {
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "GroupInfo 404 circuit breaker tripped for {convo_id}"
                )));
            }
        }

        // Fetch GroupInfo from server FIRST — only delete local state after success
        // (spec: preserve local state if fetch fails so we can still decrypt)
        let group_info = match self.api_client().get_group_info(convo_id).await {
            Ok(gi) => {
                // Success: clear 404 counter
                self.groupinfo_404_tracker().lock().await.clear(convo_id);
                gi
            }
            Err(e) => {
                // Check if this is a 404-like error
                let err_str = e.to_string().to_lowercase();
                let is_404 = err_str.contains("404")
                    || err_str.contains("not found")
                    || err_str.contains("notfound");
                if is_404 {
                    self.groupinfo_404_tracker()
                        .lock()
                        .await
                        .record_404(convo_id);
                }
                tracing::error!(error = %e, "Failed to fetch GroupInfo for rejoin");
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Failed to fetch GroupInfo: {e}"
                )));
            }
        };

        // GroupInfo fetched successfully — now delete old local group state
        if let Ok(group_id_bytes) = hex::decode(convo_id) {
            let _ = self.mls_context().delete_group(group_id_bytes);
        }

        // Create External Commit
        let identity_bytes = user_did.as_bytes().to_vec();
        let ext_commit_result = match self
            .mls_context()
            .create_external_commit(group_info, identity_bytes)
        {
            Ok(result) => result,
            Err(e) => {
                let err = OrchestratorError::RecoveryFailed(format!("External Commit failed: {e}"));
                // Remote data errors (malformed GroupInfo) are unrecoverable —
                // don't burn retries or delete local state further.
                if err.is_remote_data_error() {
                    tracing::error!(
                        convo_id,
                        error = %e,
                        "External Commit failed due to malformed remote data — marking unrecoverable"
                    );
                    // Transition to Failed state without incrementing failure counter
                    if let Err(report_err) = self
                        .api_client()
                        .report_recovery_failure(convo_id, "remote_data_error")
                        .await
                    {
                        tracing::warn!(
                            convo_id,
                            error = %report_err,
                            "Failed to report remote data recovery failure"
                        );
                    }
                    return Err(err);
                }
                tracing::error!(error = %e, "External Commit creation failed");
                return Err(err);
            }
        };

        // group_id_hex used below when updating group state

        // Get confirmation tag from the new local group state
        let tag_b64 = self
            .mls_context()
            .get_confirmation_tag(ext_commit_result.group_id.clone())
            .map(|tag| base64::engine::general_purpose::STANDARD.encode(&tag))
            .ok();

        // Send commit to server via the processExternalCommit endpoint
        // (NOT sendMessage — that endpoint validates padding/epoch/membership which don't apply)
        let ext_commit_server_result = match self
            .api_client()
            .process_external_commit(
                convo_id,
                &ext_commit_result.commit_data,
                ext_commit_result.group_info.as_deref(),
                tag_b64.as_deref(),
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                // Discard the pending external join on failure
                let _ = self
                    .mls_context()
                    .discard_pending_external_join(ext_commit_result.group_id.clone());
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "Failed to send external commit: {e}"
                )));
            }
        };

        // Best-effort receipt storage
        if let Some(ref receipt) = ext_commit_server_result.receipt {
            if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
                tracing::warn!(error = %e, convo_id, "Failed to store sequencer receipt");
            }
        }

        // Merge the external join locally
        let merged = self
            .mls_context()
            .merge_pending_commit(ext_commit_result.group_id.clone())
            .map_err(|e| {
                OrchestratorError::RecoveryFailed(format!("Failed to merge external commit: {e}"))
            })?;

        // Cleanup old epoch secrets after External Commit rejoin
        self.cleanup_epoch_secrets_if_needed(convo_id, merged).await;

        // Update group state (insert if missing, persist to storage)
        let new_group_id_hex = hex::encode(&ext_commit_result.group_id);
        {
            let mut states = self.group_states().lock().await;
            let state = states
                .entry(convo_id.to_string())
                .or_insert_with(|| GroupState {
                    group_id: new_group_id_hex.clone(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: vec![],
                });
            state.group_id = new_group_id_hex;
            state.epoch = merged;
            let state_clone = state.clone();
            drop(states);
            if let Err(e) = self.storage().set_group_state(&state_clone).await {
                tracing::warn!(error = %e, convo_id, "Failed to persist group state after force rejoin");
            }
        }

        // Clear rejoin flag
        let _ = self.storage().clear_rejoin_flag(convo_id).await;

        // Insert history boundary marker for device rejoin.
        // On iOS, Swift inserts first with the correct content key — the message_exists
        // check below prevents duplicates. On catmos/WASM, this is the only inserter.
        let marker_id = format!("hb-{}-{}", convo_id, merged);
        if !self
            .storage()
            .message_exists(&marker_id)
            .await
            .unwrap_or(true)
        {
            let payload = MLSMessagePayload::system("history_boundary.device_rejoined");
            let marker = Message {
                id: marker_id,
                conversation_id: convo_id.to_string(),
                sender_did: user_did.to_string(),
                text: "history_boundary.device_rejoined".to_string(),
                timestamp: chrono::Utc::now(),
                epoch: merged,
                sequence_number: 0,
                is_own: true,
                delivery_status: None,
                payload_json: serde_json::to_string(&payload).ok(),
            };
            if let Err(e) = self.storage().store_message(&marker).await {
                tracing::warn!(error = %e, convo_id, "Failed to store history boundary marker");
            }
        }

        // Seed lastSyncedSeq: fetch the latest message to get the current
        // server sequence number so the next sync cycle doesn't re-process
        // the entire backlog (spec: seed cursor after External Commit rejoin).
        match self
            .api_client()
            .get_messages(convo_id, None, 1, None)
            .await
        {
            Ok((_msgs, new_cursor)) => {
                if let Some(cursor_val) = new_cursor {
                    let user_did_for_cursor = user_did.to_string();
                    let sync_cursor = SyncCursor {
                        conversations_cursor: None,
                        messages_cursor: Some(cursor_val.clone()),
                    };
                    if let Err(e) = self
                        .storage()
                        .set_sync_cursor(&user_did_for_cursor, &sync_cursor)
                        .await
                    {
                        tracing::warn!(
                            error = %e,
                            convo_id,
                            "Failed to seed sync cursor after rejoin"
                        );
                    } else {
                        tracing::info!(
                            convo_id,
                            cursor = %cursor_val,
                            "Seeded sync cursor after External Commit rejoin"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    convo_id,
                    "Failed to fetch latest seq for sync cursor seeding"
                );
            }
        }

        // Publish updated GroupInfo
        let group_info = self
            .mls_context()
            .export_group_info(ext_commit_result.group_id, user_did.as_bytes().to_vec())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(convo_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to publish GroupInfo (external joins may fail)");
        }

        tracing::info!(convo_id, new_epoch = merged, "Force rejoin successful");
        Ok(())
    }

    /// Attempt to rejoin a conversation via External Commit.
    ///
    /// This is the recovery path when the local MLS state is desynced
    /// from the server (epoch mismatch, decryption failures, etc.).
    ///
    /// 1. Fetches GroupInfo from server
    /// 2. Creates an External Commit
    /// 3. Sends the commit to the server
    /// 4. Merges the pending external join
    pub async fn force_rejoin(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let _rejoin_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::info!(convo_id, "Force rejoin already in-flight, waiting");
                let _wait_guard = rejoin_lock.lock().await;
                return if self.local_group_epoch(convo_id).is_some() {
                    Ok(())
                } else {
                    Err(OrchestratorError::RecoveryFailed(format!(
                        "Concurrent force rejoin did not restore group {convo_id}"
                    )))
                };
            }
        };

        self.enforce_rejoin_backoff(convo_id).await?;

        let result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match result {
            Ok(()) => {
                self.clear_rejoin_failures(convo_id).await;
                Ok(())
            }
            Err(ref err) if err.is_rate_limited() => {
                // 429 Too Many Requests: don't burn a rejoin attempt slot.
                // Just return the error so the caller can retry later.
                tracing::warn!(
                    convo_id,
                    "Force rejoin got 429 — not counting as failed attempt"
                );
                result
            }
            Err(ref err) if err.is_remote_data_error() => {
                // Remote data errors are already handled in force_rejoin_unlocked
                // (reported to server, marked unrecoverable). Don't record as
                // normal failure — the error is on the server side.
                tracing::warn!(
                    convo_id,
                    "Force rejoin failed due to remote data error — not counting as attempt"
                );
                result
            }
            Err(_) => {
                self.record_rejoin_failure(convo_id).await;
                result
            }
        }
    }

    /// Join a conversation, trying Welcome first and falling back to External Commit.
    ///
    /// This is the correct join path for conversations where the user was added
    /// by another client. Welcome provides key continuity (can decrypt current
    /// epoch messages), while External Commit is a fallback for device-sync
    /// scenarios where the Welcome was already consumed.
    ///
    /// 1. Try fetching Welcome message from server
    /// 2. If Welcome found → process it to join the group
    /// 3. If Welcome unavailable (404/410) → fall back to External Commit
    pub async fn join_or_rejoin(&self, convo_id: &str) -> Result<u64> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
        let rejoin_lock = self.rejoin_lock(convo_id).await;
        let _rejoin_guard = match rejoin_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::info!(convo_id, "Join/rejoin already in-flight, waiting");
                let _wait_guard = rejoin_lock.lock().await;
                return self.local_group_epoch(convo_id).ok_or_else(|| {
                    OrchestratorError::RecoveryFailed(format!(
                        "Concurrent join/rejoin did not restore group {convo_id}"
                    ))
                });
            }
        };

        // Welcome should be tried unconditionally — backoff only applies to
        // External Commit fallback (spec: Welcome is the preferred join path).
        tracing::info!(
            convo_id,
            "Attempting to join group (Welcome first, External Commit fallback)"
        );

        // Step 1: Try Welcome
        match self.api_client().get_welcome(convo_id).await {
            Ok(welcome_data) => {
                tracing::info!(
                    convo_id,
                    welcome_len = welcome_data.len(),
                    "Welcome message found, joining via Welcome"
                );

                let identity_bytes = user_did.as_bytes().to_vec();
                let welcome_result = self.mls_context().process_welcome(
                    welcome_data,
                    identity_bytes,
                    Some(self.config().group_config.clone()),
                ).map_err(|e| {
                    tracing::warn!(convo_id, error = %e, "Welcome processing failed, will try External Commit");
                    e
                });

                match welcome_result {
                    Ok(result) => {
                        let epoch = self
                            .mls_context()
                            .get_epoch(result.group_id.clone())
                            .unwrap_or(0);

                        // Update group state
                        let welcome_group_id_hex = hex::encode(&result.group_id);
                        {
                            let mut states = self.group_states().lock().await;
                            let state =
                                states
                                    .entry(convo_id.to_string())
                                    .or_insert_with(|| GroupState {
                                        group_id: welcome_group_id_hex.clone(),
                                        conversation_id: convo_id.to_string(),
                                        epoch: 0,
                                        members: vec![],
                                    });
                            state.group_id = welcome_group_id_hex;
                            state.epoch = epoch;
                            let state_clone = state.clone();
                            drop(states);
                            if let Err(e) = self.storage().set_group_state(&state_clone).await {
                                tracing::warn!(error = %e, convo_id, "Failed to persist group state after Welcome join");
                            }
                        }

                        // Clear rejoin flag
                        let _ = self.storage().clear_rejoin_flag(convo_id).await;
                        self.clear_rejoin_failures(convo_id).await;

                        // Insert history boundary marker for Welcome join.
                        // On iOS, Swift inserts first — message_exists prevents duplicates.
                        let marker_id = format!("hb-{}-{}", convo_id, epoch);
                        if !self
                            .storage()
                            .message_exists(&marker_id)
                            .await
                            .unwrap_or(true)
                        {
                            let user_did_ref = &user_did;
                            let payload = MLSMessagePayload::system("history_boundary.new_member");
                            let marker = Message {
                                id: marker_id,
                                conversation_id: convo_id.to_string(),
                                sender_did: user_did_ref.clone(),
                                text: "history_boundary.new_member".to_string(),
                                timestamp: chrono::Utc::now(),
                                epoch,
                                sequence_number: 0,
                                is_own: true,
                                delivery_status: None,
                                payload_json: serde_json::to_string(&payload).ok(),
                            };
                            if let Err(e) = self.storage().store_message(&marker).await {
                                tracing::warn!(error = %e, convo_id, "Failed to store history boundary marker");
                            }
                        }

                        tracing::info!(convo_id, epoch, "Successfully joined via Welcome");
                        return Ok(epoch);
                    }
                    Err(_) => {
                        // Welcome processing failed — fall through to External Commit
                        tracing::info!(
                            convo_id,
                            "Welcome processing failed, falling back to External Commit"
                        );
                    }
                }
            }
            Err(e) => {
                // Check if this is a 404/410 (Welcome not available) vs a real error
                let is_expected = match &e {
                    OrchestratorError::ServerError { status, .. } => {
                        *status == 404 || *status == 410
                    }
                    _ => false,
                };
                if is_expected {
                    tracing::info!(
                        convo_id,
                        "No Welcome available (device-sync scenario), using External Commit"
                    );
                } else {
                    tracing::warn!(convo_id, error = %e, "Welcome fetch failed, falling back to External Commit");
                }
            }
        }

        // Step 2: Fall back to External Commit (backoff applies here, not to Welcome)
        self.enforce_rejoin_backoff(convo_id).await?;
        let rejoin_result = self.force_rejoin_unlocked(convo_id, &user_did).await;
        match rejoin_result {
            Ok(()) => {
                self.clear_rejoin_failures(convo_id).await;
                Ok(self.local_group_epoch(convo_id).unwrap_or(0))
            }
            Err(err) => {
                self.record_rejoin_failure(convo_id).await;
                Err(err)
            }
        }
    }

    /// Perform full silent recovery for a user.
    ///
    /// Nuclear option: deletes device, clears local state, re-registers,
    /// and marks all conversations for rejoin.
    pub async fn perform_silent_recovery(&self, conversation_ids: &[String]) -> Result<()> {
        let user_did = self.require_user_did().await?;

        tracing::info!(
            user_did = %user_did,
            conversations = conversation_ids.len(),
            "Starting silent recovery"
        );

        // 1. Delete current device from server
        if let Ok(devices) = self.api_client().list_devices().await {
            let device_uuid = self
                .credentials()
                .get_device_uuid(&user_did)
                .await?
                .unwrap_or_default();

            for device in &devices {
                if device.device_uuid == device_uuid {
                    let _ = self.api_client().remove_device(&device.device_id).await;
                }
            }
        }

        // 2. Clear local credentials
        self.credentials().clear_all(&user_did).await?;

        // 3. Re-register device
        let _new_mls_did = self.ensure_device_registered().await?;

        // 4. Mark conversations for rejoin
        for convo_id in conversation_ids {
            let _ = self.storage().mark_needs_rejoin(convo_id).await;
        }

        // 5. Process rejoins
        for convo_id in conversation_ids {
            if self.storage().needs_rejoin(convo_id).await.unwrap_or(false) {
                match self.join_or_rejoin(convo_id).await {
                    Ok(epoch) => {
                        tracing::info!(convo_id = %convo_id, epoch, "Rejoin successful during recovery");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            convo_id = %convo_id,
                            "Rejoin failed during recovery"
                        );
                    }
                }
            }
        }

        tracing::info!("Silent recovery complete");
        Ok(())
    }

    /// Check desync severity between local and server key packages.
    pub async fn check_desync_severity(&self) -> Result<DesyncSeverity> {
        let stats = self.api_client().get_key_package_stats().await?;

        // If no key packages on server and we think we're registered, it's severe
        if stats.available == 0 {
            let user_did = self.require_user_did().await?;
            if self.credentials().has_credentials(&user_did).await? {
                return Ok(DesyncSeverity::Severe {
                    local_count: 0,
                    server_count: 0,
                    difference: 0,
                });
            }
            return Ok(DesyncSeverity::None);
        }

        Ok(DesyncSeverity::None)
    }
}
