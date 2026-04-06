use std::collections::HashMap;
use std::time::Duration;
use web_time::Instant;

use base64::Engine;

use super::api_client::MLSAPIClient;
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
    /// Last successful or attempted rejoin per conversation (regardless of outcome).
    /// Used to enforce a hard minimum interval between any rejoin attempts,
    /// preventing epoch inflation spirals even when attempts succeed.
    last_rejoin_at: HashMap<String, Instant>,
    /// Maximum rejoin attempts before giving up.
    max_attempts: u32,
    /// Base cooldown duration for backoff.
    base_cooldown: Duration,
    /// Hard minimum interval between rejoin attempts (successful or failed).
    min_rejoin_interval: Duration,
}

impl RecoveryTracker {
    pub fn new(max_attempts: u32, base_cooldown: Duration) -> Self {
        Self {
            failed_rejoins: HashMap::new(),
            last_rejoin_at: HashMap::new(),
            max_attempts,
            base_cooldown,
            min_rejoin_interval: Duration::from_secs(30),
        }
    }

    fn cooldown_for_attempts(&self, attempts: u32) -> Duration {
        if attempts == 0 {
            return Duration::from_secs(0);
        }

        // Exponential backoff with a hard cap to avoid runaway delays.
        let exponent = attempts.saturating_sub(1).min(10);
        let multiplier = 1u64 << exponent;
        let cooldown_secs = self
            .base_cooldown
            .as_secs()
            .saturating_mul(multiplier)
            .min(Duration::from_secs(3600).as_secs());
        Duration::from_secs(cooldown_secs)
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
        // Hard minimum interval: even successful rejoins can't happen faster than this
        if let Some(last) = self.last_rejoin_at.get(convo_id) {
            if last.elapsed() < self.min_rejoin_interval {
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
        self.last_rejoin_at.insert(convo_id.to_string(), now);
    }

    /// Clear failure tracking on success.
    /// Note: does NOT clear `last_rejoin_at` — the minimum interval still applies
    /// to prevent rapid successive rejoins even when they succeed.
    pub fn clear(&mut self, convo_id: &str) {
        self.failed_rejoins.remove(convo_id);
        // Record the current time as last rejoin so the min_rejoin_interval applies
        self.last_rejoin_at
            .insert(convo_id.to_string(), Instant::now());
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

/// Minimum consecutive connection/timeout failures before failover is recommended.
const FAILOVER_MIN_FAILURES: u32 = 3;

/// Minimum wall-clock duration since the first failure before failover is recommended.
/// Prevents triggering on brief transient blips.
const FAILOVER_MIN_DURATION: Duration = Duration::from_secs(120);

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
        state.consecutive_failures >= FAILOVER_MIN_FAILURES
            && state.first_failure_at.elapsed() >= FAILOVER_MIN_DURATION
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

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
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
        if let Some(last) = tracker.last_rejoin_at.get(convo_id) {
            let elapsed = last.elapsed();
            let min_interval = Duration::from_secs(30);
            if elapsed < min_interval {
                let remaining = min_interval - elapsed;
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

        // Delete old local group state
        if let Ok(group_id_bytes) = hex::decode(convo_id) {
            let _ = self.mls_context().delete_group(group_id_bytes);
        }

        // Fetch GroupInfo from server
        let group_info = self
            .api_client()
            .get_group_info(convo_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch GroupInfo for rejoin");
                OrchestratorError::RecoveryFailed(format!("Failed to fetch GroupInfo: {e}"))
            })?;

        // Create External Commit
        let identity_bytes = user_did.as_bytes().to_vec();
        let ext_commit_result = self
            .mls_context()
            .create_external_commit(group_info, identity_bytes)
            .map_err(|e| {
                tracing::error!(error = %e, "External Commit creation failed");
                OrchestratorError::RecoveryFailed(format!("External Commit failed: {e}"))
            })?;

        let _new_group_id_hex = hex::encode(&ext_commit_result.group_id);

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

        // Update group state (insert if missing, persist to storage)
        {
            let mut states = self.group_states().lock().await;
            let state = states
                .entry(convo_id.to_string())
                .or_insert_with(|| GroupState {
                    group_id: convo_id.to_string(),
                    conversation_id: convo_id.to_string(),
                    epoch: 0,
                    members: vec![],
                });
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
            Err(err) => {
                self.record_rejoin_failure(convo_id).await;
                Err(err)
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

        self.enforce_rejoin_backoff(convo_id).await?;

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
                        {
                            let mut states = self.group_states().lock().await;
                            let state =
                                states
                                    .entry(convo_id.to_string())
                                    .or_insert_with(|| GroupState {
                                        group_id: convo_id.to_string(),
                                        conversation_id: convo_id.to_string(),
                                        epoch: 0,
                                        members: vec![],
                                    });
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

        // Step 2: Fall back to External Commit
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
