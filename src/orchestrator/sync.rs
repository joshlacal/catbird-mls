use std::collections::HashSet;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::Result;
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C> MLSOrchestrator<S, A, C>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
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
                        *tripped_at = Some(tokio::time::Instant::now());
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

            // Check for epoch reconciliation
            if let Some(gs) = self.group_states().lock().await.get(&convo.group_id) {
                if convo.epoch > gs.epoch {
                    tracing::warn!(
                        conversation_id = %convo.group_id,
                        local_epoch = gs.epoch,
                        server_epoch = convo.epoch,
                        "Server ahead - may need rejoin"
                    );
                    // Mark for potential rejoin if the gap is significant
                    if convo.epoch - gs.epoch > 1 {
                        let _ = self.storage().mark_needs_rejoin(&convo.group_id).await;
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
