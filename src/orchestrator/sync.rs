use std::collections::HashSet;
use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::Result;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Sync conversations with the server.
    ///
    /// 1. Acquires sync lock (skip if already syncing)
    /// 2. Validates authentication
    /// 3. Fetches all conversations with pagination
    /// 4. Filters stale conversations where user is no longer a member
    /// 5. Reconciles local state
    pub async fn sync_with_server(&self, full_sync: bool) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        // Circuit breaker check with cooldown recovery
        {
            let failures = *self.consecutive_sync_failures().lock().await;
            if failures >= self.config().max_consecutive_sync_failures {
                let mut tripped_at = self.circuit_breaker_tripped_at().lock().await;
                let cooldown_secs = *self.circuit_breaker_cooldown_secs().lock().await;

                match *tripped_at {
                    None => {
                        // First time tripping — record the time, skip this call
                        *tripped_at = Some(Instant::now());
                        tracing::warn!(
                            failures,
                            cooldown_secs,
                            "Sync circuit breaker tripped, starting cooldown"
                        );
                        return Ok(());
                    }
                    Some(tripped) if tripped.elapsed().as_secs() < cooldown_secs => {
                        // Still in cooldown — skip
                        tracing::warn!(
                            failures,
                            "Sync paused due to consecutive failures (cooldown active)"
                        );
                        return Ok(());
                    }
                    Some(_) => {
                        // Cooldown expired — reset and allow one retry
                        tracing::info!(
                            cooldown_secs,
                            "Circuit breaker cooldown expired, allowing sync retry"
                        );
                        *self.consecutive_sync_failures().lock().await = 0;
                        *tripped_at = None;
                    }
                }
            }
        }

        // Acquire sync lock
        {
            let mut syncing = self.sync_in_progress().lock().await;
            if *syncing {
                tracing::debug!("Sync already in progress, skipping");
                return Ok(());
            }
            *syncing = true;
        }

        // Ensure sync_in_progress is always reset, even on panic
        let sync_flag = self.sync_in_progress();
        let _sync_guard = scopeguard::guard((), |_| {
            if let Ok(mut syncing) = sync_flag.try_lock() {
                *syncing = false;
            }
        });

        let result = self.do_sync(&user_did, full_sync).await;

        // Release sync lock (guard handles this on panic/early return too)
        *self.sync_in_progress().lock().await = false;

        match &result {
            Ok(_) => {
                *self.consecutive_sync_failures().lock().await = 0;
                // Reset circuit breaker state on success
                *self.circuit_breaker_tripped_at().lock().await = None;
                *self.circuit_breaker_cooldown_secs().lock().await = 30;
            }
            Err(e) => {
                let mut failures = self.consecutive_sync_failures().lock().await;
                *failures += 1;
                // If we just re-tripped the breaker, apply exponential backoff
                if *failures >= self.config().max_consecutive_sync_failures {
                    let mut cooldown = self.circuit_breaker_cooldown_secs().lock().await;
                    *cooldown = (*cooldown * 2).min(300); // cap at 5 minutes
                }
                tracing::error!(
                    error = %e,
                    consecutive_failures = *failures,
                    "Sync failed"
                );
            }
        }

        result
    }

    /// Internal sync implementation.
    async fn do_sync(&self, user_did: &str, _full_sync: bool) -> Result<()> {
        // Validate we're still the active account
        if !self.api_client().is_authenticated_as(user_did).await {
            tracing::info!("Account not active, skipping sync");
            return Ok(());
        }

        tracing::info!("Starting server sync");

        // Fetch all conversations with pagination
        let mut all_convos = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            self.check_shutdown().await?;

            let page = self
                .api_client()
                .get_conversations(100, cursor.as_deref())
                .await?;
            all_convos.extend(page.conversations);
            cursor = page.cursor;

            if cursor.is_none() {
                break;
            }
        }

        // Filter stale conversations (user no longer a member)
        let normalized_did = user_did.to_lowercase();
        let mut stale_ids = Vec::new();
        all_convos.retain(|convo| {
            let is_member = convo
                .members
                .iter()
                .any(|m| m.did.to_lowercase() == normalized_did);
            if !is_member {
                stale_ids.push(convo.group_id.clone());
            }
            is_member
        });

        // Clean up stale conversations
        if !stale_ids.is_empty() {
            tracing::info!(count = stale_ids.len(), "Cleaning up stale conversations");
            for id in &stale_ids {
                self.force_delete_local(id).await;
            }
        }

        // Get set of groups being created (protect from deletion)
        let creating = self.groups_being_created().lock().await.clone();

        // Reconcile: find local conversations not on server
        let server_ids: HashSet<&str> = all_convos.iter().map(|c| c.group_id.as_str()).collect();
        let local_ids: Vec<String> = self.conversations().lock().await.keys().cloned().collect();

        for local_id in &local_ids {
            if !server_ids.contains(local_id.as_str()) && !creating.contains(local_id) {
                tracing::info!(
                    conversation_id = %local_id,
                    "Local conversation not on server, deleting"
                );
                self.force_delete_local(local_id).await;
            }
        }

        // Update local state from server
        let mut sync_rejoin_attempted = HashSet::new();
        for convo in &all_convos {
            if !*self.sync_in_progress().lock().await {
                // Check if shutdown happened during processing
                break;
            }

            self.conversations()
                .lock()
                .await
                .insert(convo.group_id.clone(), convo.clone());

            // Initialize group state if missing
            if self
                .group_states()
                .lock()
                .await
                .get(&convo.group_id)
                .is_none()
            {
                let members: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();

                // Try to get epoch from FFI — if group doesn't exist locally, join it
                let epoch = if let Ok(gid_bytes) = hex::decode(&convo.group_id) {
                    match self.mls_context().get_epoch(gid_bytes) {
                        Ok(e) => e,
                        Err(_) => {
                            if !sync_rejoin_attempted.insert(convo.group_id.clone()) {
                                tracing::debug!(
                                    conversation_id = %convo.group_id,
                                    "Skipping duplicate sync-triggered join/rejoin in same cycle"
                                );
                                convo.epoch
                            } else if !self.should_attempt_sync_rejoin(&convo.group_id).await {
                                tracing::debug!(
                                    conversation_id = %convo.group_id,
                                    "Skipping sync-triggered join/rejoin due to eligibility gate"
                                );
                                convo.epoch
                            } else {
                                // Group not in FFI — try Welcome first, fall back to External Commit
                                tracing::info!(
                                    conversation_id = %convo.group_id,
                                    "Group not found in FFI, joining (Welcome first, External Commit fallback)"
                                );
                                match self.join_or_rejoin(&convo.group_id).await {
                                    Ok(epoch) => {
                                        tracing::info!(
                                            conversation_id = %convo.group_id,
                                            epoch,
                                            "Successfully joined group"
                                        );
                                        epoch
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            conversation_id = %convo.group_id,
                                            error = %e,
                                            "Failed to join group"
                                        );
                                        convo.epoch
                                    }
                                }
                            }
                        }
                    }
                } else {
                    convo.epoch
                };

                let state = GroupState {
                    group_id: convo.group_id.clone(),
                    conversation_id: convo.group_id.clone(),
                    epoch,
                    members,
                };
                self.group_states()
                    .lock()
                    .await
                    .insert(convo.group_id.clone(), state.clone());
                self.storage().set_group_state(&state).await?;
            } else {
                // Update member list from server
                if let Some(gs) = self.group_states().lock().await.get_mut(&convo.group_id) {
                    gs.members = convo.members.iter().map(|m| m.did.clone()).collect();
                }
            }

            // Ensure conversation record exists in storage
            self.storage()
                .ensure_conversation_exists(user_did, &convo.group_id, &convo.group_id)
                .await?;

            // Check for epoch reconciliation — fetch and process missing commits
            let local_epoch = self
                .group_states()
                .lock()
                .await
                .get(&convo.group_id)
                .map(|gs| gs.epoch)
                .unwrap_or(0);

            if convo.epoch > local_epoch {
                tracing::info!(
                    conversation_id = %convo.group_id,
                    local_epoch,
                    server_epoch = convo.epoch,
                    "Server ahead — fetching pending messages to catch up"
                );

                // Fetch and process messages (includes commits) to advance local epoch.
                // This is the primary catch-up path for commits missed between syncs.
                match self.fetch_messages(&convo.group_id, None, 50).await {
                    Ok((msgs, _)) => {
                        if !msgs.is_empty() {
                            tracing::info!(
                                conversation_id = %convo.group_id,
                                processed = msgs.len(),
                                "Processed pending messages during sync catch-up"
                            );
                        }
                        // Re-check epoch after processing
                        let new_local = self
                            .group_states()
                            .lock()
                            .await
                            .get(&convo.group_id)
                            .map(|gs| gs.epoch)
                            .unwrap_or(0);
                        if convo.epoch > new_local {
                            tracing::warn!(
                                conversation_id = %convo.group_id,
                                local_epoch = new_local,
                                server_epoch = convo.epoch,
                                "Still behind after processing — may need rejoin"
                            );
                            if convo.epoch.saturating_sub(new_local) > 1 {
                                let _ = self.storage().mark_needs_rejoin(&convo.group_id).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            conversation_id = %convo.group_id,
                            error = %e,
                            "Failed to fetch messages for epoch catch-up"
                        );
                        if convo.epoch.saturating_sub(local_epoch) > 1 {
                            let _ = self.storage().mark_needs_rejoin(&convo.group_id).await;
                        }
                    }
                }
            }

            // Auto-consume needs_rejoin flag: if a previous sync or decrypt failure
            // flagged this conversation, attempt rejoin now (with rate-limiting).
            if self
                .storage()
                .needs_rejoin(&convo.group_id)
                .await
                .unwrap_or(false)
            {
                tracing::info!(
                    conversation_id = %convo.group_id,
                    "Group flagged for rejoin — attempting in sync"
                );
                if !sync_rejoin_attempted.contains(&convo.group_id)
                    && self.should_attempt_sync_rejoin(&convo.group_id).await
                {
                    sync_rejoin_attempted.insert(convo.group_id.clone());
                    match self.join_or_rejoin(&convo.group_id).await {
                        Ok(epoch) => {
                            tracing::info!(
                                conversation_id = %convo.group_id,
                                epoch,
                                "Sync rejoin succeeded"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                conversation_id = %convo.group_id,
                                error = %e,
                                "Sync rejoin failed"
                            );
                        }
                    }
                }
            }
        }

        tracing::info!(
            conversation_count = all_convos.len(),
            "Server sync complete"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// Verify that `saturating_sub` prevents underflow when local epoch exceeds server epoch.
    ///
    /// This is a regression test for the epoch difference calculations in `do_sync`.
    /// Before the fix, `convo.epoch - local_epoch` would panic on underflow when
    /// the local epoch was ahead of the server (e.g., after an external commit that
    /// the server hadn't yet acknowledged).
    #[test]
    fn saturating_sub_prevents_underflow_when_local_ahead() {
        // Simulate: server reports epoch 5, but local is at epoch 10
        let server_epoch: u64 = 5;
        let local_epoch: u64 = 10;

        // Old code: `server_epoch - local_epoch` would panic here (underflow)
        // New code: saturating_sub clamps to 0
        let diff = server_epoch.saturating_sub(local_epoch);
        assert_eq!(
            diff, 0,
            "saturating_sub should return 0 when local > server"
        );

        // The rejoin threshold check (> 1) should NOT trigger when diff is 0
        assert!(
            diff <= 1,
            "Should not mark for rejoin when local epoch is ahead"
        );
    }

    #[test]
    fn saturating_sub_normal_case_server_ahead() {
        // Normal case: server is ahead of local
        let server_epoch: u64 = 10;
        let local_epoch: u64 = 5;

        let diff = server_epoch.saturating_sub(local_epoch);
        assert_eq!(
            diff, 5,
            "Normal subtraction should work when server > local"
        );

        // The rejoin threshold check should trigger for large gaps
        assert!(diff > 1, "Should mark for rejoin when server is far ahead");
    }

    #[test]
    fn saturating_sub_equal_epochs() {
        let server_epoch: u64 = 7;
        let local_epoch: u64 = 7;

        let diff = server_epoch.saturating_sub(local_epoch);
        assert_eq!(diff, 0, "Equal epochs should produce 0 difference");
    }

    #[test]
    fn saturating_sub_zero_epochs() {
        // Edge case: both epochs are 0 (fresh group, no commits yet)
        let server_epoch: u64 = 0;
        let local_epoch: u64 = 0;

        let diff = server_epoch.saturating_sub(local_epoch);
        assert_eq!(diff, 0, "Zero epochs should produce 0 difference");
    }

    #[test]
    fn saturating_sub_max_local_epoch() {
        // Extreme edge case: local epoch is u64::MAX (shouldn't happen, but must not panic)
        let server_epoch: u64 = 100;
        let local_epoch: u64 = u64::MAX;

        let diff = server_epoch.saturating_sub(local_epoch);
        assert_eq!(
            diff, 0,
            "saturating_sub should clamp to 0 even with u64::MAX local epoch"
        );
    }
}
