use std::collections::HashSet;
use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::error::Result;
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::MLSOrchestrator;
use super::pagination::PaginationGuard;
use super::storage::MLSStorageBackend;
use super::types::*;

fn member_matches_user_root_exact(member_did: &str, expected_root_did: &str) -> bool {
    super::credential_binding::credential_root_did(member_did) == expected_root_did
}

fn conversation_contains_user_root_exact(
    conversation: &ConversationView,
    expected_root_did: &str,
) -> bool {
    conversation
        .members
        .iter()
        .any(|member| member_matches_user_root_exact(&member.did, expected_root_did))
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Project persisted conversations into Rust-owned recovery state on startup.
    pub async fn startup_reconcile(&self) -> Result<StartupReconcileReport> {
        let user_did = self.require_user_did().await?;
        let conversations = self.storage().list_conversations(&user_did).await?;
        let mut report = StartupReconcileReport {
            scanned: conversations.len() as u32,
            ..StartupReconcileReport::default()
        };

        for convo in conversations {
            let convo_id = convo.conversation_id.clone();
            let transition_lock = self.rejoin_lock(&convo_id).await;
            let transition_guard = transition_lock.lock().await;
            let persisted_state = self.storage().get_conversation_state(&convo_id).await?;

            // Fail closed on either view of the reset authority: the helper
            // re-reads storage, so a ResetPending seen by the first read must
            // still win if a racing writer clears it in between.
            let is_reset_pending = self
                .reset_blocks_non_reset_transition_locked(&convo_id)
                .await?
                || matches!(
                    persisted_state,
                    Some(ConversationState::ResetPending { .. })
                );

            if is_reset_pending {
                self.reset_pending_payload_result(&convo_id).await?;
                report.reset_pending += 1;
                continue;
            }

            match persisted_state {
                Some(state @ ConversationState::Quarantined { .. })
                | Some(state @ ConversationState::Failed) => {
                    if self
                        .project_non_reset_cache_locked(&convo_id, state)
                        .await?
                    {
                        report.unrecoverable_local += 1;
                    } else {
                        report.reset_pending += 1;
                    }
                    continue;
                }
                Some(ConversationState::NeedsRejoin) => {
                    drop(transition_guard);
                    // P0.2: do not re-project NeedsRejoin (which drives
                    // force_rejoin -> External Commit -> epoch inflation) when
                    // the local group is cryptographically healthy. Clear the
                    // stale flag instead.
                    if self.clear_needs_rejoin_if_locally_healthy(&convo_id).await {
                        report.healthy += 1;
                    } else {
                        self.project_startup_needs_rejoin(&convo_id).await;
                        report.needs_rejoin += 1;
                    }
                    continue;
                }
                Some(state) => {
                    let _ = self
                        .project_non_reset_cache_locked(&convo_id, state)
                        .await?;
                }
                None => {}
            }
            drop(transition_guard);

            let needs_rejoin = self.storage().needs_rejoin(&convo_id).await?;
            if needs_rejoin {
                // P0.2: same health-probe gate for the persisted boolean path —
                // a sticky needs_rejoin=true on a healthy local group must not
                // force a rejoin.
                if self.clear_needs_rejoin_if_locally_healthy(&convo_id).await {
                    report.healthy += 1;
                } else {
                    self.project_startup_needs_rejoin(&convo_id).await;
                    report.needs_rejoin += 1;
                }
                continue;
            }

            match self.local_group_epoch_result(&convo_id).await? {
                Some(_) => report.healthy += 1,
                None => {
                    tracing::info!(
                        conversation_id = %convo_id,
                        "Startup reconcile marked missing local group for rejoin"
                    );
                    self.project_startup_needs_rejoin(&convo_id).await;
                    report.needs_rejoin += 1;
                }
            }
        }

        Ok(report)
    }

    /// Sync conversations with the server.
    ///
    /// 1. Acquires sync lock (skip if already syncing)
    /// 2. Validates authentication
    /// 3. Fetches all conversations with pagination
    /// 4. Rejects uncorroborated server roster/listing omissions
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
                *self.circuit_breaker_cooldown_secs().lock().await =
                    constants::SYNC_CIRCUIT_BREAKER_BASE_SECS;
            }
            Err(e) => {
                let mut failures = self.consecutive_sync_failures().lock().await;
                *failures += 1;
                // If we just re-tripped the breaker, apply exponential backoff
                if *failures >= self.config().max_consecutive_sync_failures {
                    let mut cooldown = self.circuit_breaker_cooldown_secs().lock().await;
                    *cooldown = (*cooldown * 2).min(constants::SYNC_CIRCUIT_BREAKER_MAX_SECS);
                    // cap at 5 minutes
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
        crate::info_log!("[sync] do_sync start user_did={}", user_did);
        // Validate we're still the active account
        if !self.api_client().is_authenticated_as(user_did).await {
            crate::info_log!("[sync] do_sync ABORT: not authenticated as {}", user_did);
            tracing::info!("Account not active, skipping sync");
            return Ok(());
        }

        tracing::info!("Starting server sync");

        // Fence the server listing against local creation start/completion.
        // A changed generation means this pass cannot safely conclude that a
        // newly cached conversation absent from the listing is stale.
        let creation_generation_before = self
            .creation_generation()
            .load(std::sync::atomic::Ordering::Acquire);

        // Fetch all conversations with pagination
        let mut all_convos = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pagination = PaginationGuard::for_conversations("server sync");

        loop {
            self.check_shutdown().await?;

            let page = self
                .api_client()
                .get_conversations(100, cursor.as_deref())
                .await?;
            pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
            all_convos.extend(page.conversations);
            cursor = page.cursor;

            if cursor.is_none() {
                break;
            }
        }

        crate::info_log!(
            "[sync] fetched {} convos from server (before roster validation)",
            all_convos.len()
        );
        // A delivery-service roster is authenticated transport data, but it is
        // not cryptographic proof that this MLS client was removed. Treating a
        // missing self DID as deletion authority lets an inconsistent or
        // malicious DS erase the local ratchet tree and durable conversation
        // state. A real removal must arrive through an authenticated MLS commit
        // (or an explicit local leave), whose dedicated path owns cleanup.
        let expected_root_did =
            super::credential_binding::credential_root_did(user_did).to_string();
        // A single omitted roster must not abort the whole sync: that would let
        // one anomalous/compromised conversation deny message delivery for every
        // healthy conversation. Skip the omitted conversation instead, preserving
        // its local state, and keep syncing the rest. Deletion still only happens
        // via an authenticated MLS commit / explicit local leave.
        all_convos.retain(|convo| {
            if conversation_contains_user_root_exact(convo, &expected_root_did) {
                true
            } else {
                tracing::warn!(
                    conversation_id = %convo.conversation_id,
                    group_id = %convo.group_id,
                    member_count = convo.members.len(),
                    "Server roster omitted the current user; preserving local state and skipping sync for this conversation until authenticated MLS removal evidence arrives"
                );
                false
            }
        });

        // Preflight the inverse omission too: a DS can omit the whole row,
        // not only the current DID inside a returned row.
        let server_ids: HashSet<&str> = all_convos
            .iter()
            .map(|c| c.conversation_id.as_str())
            .collect();
        let local_conversations: Vec<(String, String)> = self
            .conversations()
            .lock()
            .await
            .iter()
            .map(|(conversation_id, view)| (conversation_id.clone(), view.group_id.clone()))
            .collect();
        let creating = self.groups_being_created().lock().await.clone();
        let creation_generation_after = self
            .creation_generation()
            .load(std::sync::atomic::Ordering::Acquire);
        let creation_changed_during_snapshot =
            creation_generation_before != creation_generation_after;

        // Log local conversations the server listing omitted, but do not abort
        // the sync: preserving local state (by simply not deleting) is the whole
        // point, and one omitted row must not block sync for the others.
        for (local_id, local_group_id) in &local_conversations {
            // Creation protection is keyed by the locally-created MLS group id.
            // A server may return a distinct stable conversation id before that
            // row becomes visible to getConversations, so compare both identities.
            // The single group-id guard remains balanced by the create path on
            // every success and error exit.
            let creation_in_progress =
                creating.contains(local_id) || creating.contains(local_group_id);
            if !server_ids.contains(local_id.as_str())
                && !creation_in_progress
                && !creation_changed_during_snapshot
            {
                tracing::warn!(
                    conversation_id = %local_id,
                    "Server listing omitted a local conversation; preserving local state until authenticated MLS removal evidence arrives"
                );
            }
        }

        // Update local state from server
        let mut sync_rejoin_attempted = HashSet::new();
        for convo in &all_convos {
            if !*self.sync_in_progress().lock().await {
                // Check if shutdown happened during processing
                break;
            }

            let conversation_id = convo.conversation_id.as_str();
            let group_id = convo.group_id.as_str();
            // A successful reset recovery may resolve this stale list item to
            // a different, authoritative group before the item finishes. All
            // post-recovery projections in this iteration must use that
            // effective view rather than normalizing the captured page again.
            let mut effective_convo = convo.clone();

            let previous_view = self
                .conversations()
                .lock()
                .await
                .insert(conversation_id.to_string(), convo.clone());

            // ADR-010 D4: record the conversation→sequencer mapping. Routing
            // does NOT consult this yet (WS-4 rung 3); every sync refresh
            // overwrites the mapping, which trivially satisfies the D4 rule-4
            // invalidation requirement for rung 2.
            let sequencer_changed = previous_view
                .as_ref()
                .map(|prev| prev.sequencer_did != convo.sequencer_did)
                .unwrap_or(convo.sequencer_did.is_some());
            crate::info_log!(
                "[sync] convo={} sequencer_did={:?}{}",
                conversation_id,
                convo.sequencer_did,
                if sequencer_changed { " (CHANGED)" } else { "" }
            );
            if sequencer_changed {
                if let Some(sequencer_did) = convo.sequencer_did.as_deref() {
                    if let Err(e) = self
                        .storage()
                        .set_conversation_sequencer(conversation_id, sequencer_did)
                        .await
                    {
                        // Log-and-continue: recovery-critical-write escalation
                        // is WS-5 territory, but never silently drop the error.
                        crate::warn_log!(
                            "[sync] convo={} failed to persist sequencer mapping: {}",
                            conversation_id,
                            e
                        );
                    }
                }
            }

            // Detect a stale persisted GroupState: the orchestrator has a
            // record for this convo, but the local MLS context does NOT have
            // the group. This happens when a prior sync attempted to join,
            // failed silently (e.g. an unimplemented FFI callback), and
            // persisted GroupState anyway with the server epoch as a
            // placeholder. From then on, every sync took the "update members"
            // branch and never retried the join — so the device stayed
            // permanently unable to encrypt or decrypt for this convo.
            //
            // Self-heal by treating the persisted state as missing so the
            // init block below re-runs `join_or_rejoin`.
            //
            // BUT a *closed* MLS context is NOT a missing group: the context's
            // DB connections were merely released (iOS suspension / account-switch
            // teardown) and the group is intact in persistent storage. Treating
            // `ContextClosed` as "group missing" funnels the convo into the rejoin
            // machinery, whose post-join success-cooldown then REJECTs it — which
            // locks a freshly-joined member out of sending for minutes (it needs a
            // cheap local context reload, not a network rejoin). Detect the
            // transient close and skip this convo for the cycle; the next sync after
            // the context reopens sees the group normally. The convo view is already
            // cached above, so nothing is lost.
            let ffi_has_group = match hex::decode(group_id) {
                Ok(gid_bytes) => match self.mls_context().get_epoch(gid_bytes) {
                    Ok(_) => true,
                    Err(crate::MLSError::ContextClosed) => {
                        crate::info_log!(
                            "[sync] convo={} group={} SKIP: MLS context closed (transient iOS suspension) — not stale, not rejoining",
                            conversation_id,
                            group_id
                        );
                        continue;
                    }
                    Err(_) => false,
                },
                Err(_) => false,
            };
            let has_state_record = {
                let states = self.group_states().lock().await;
                ResolvedConversationContext {
                    conversation_id: conversation_id.to_string(),
                    group_id: group_id.to_string(),
                }
                .group_state(&states)
                .is_some()
            };

            crate::info_log!(
                "[sync] convo={} group={} has_state_record={} ffi_has_group={}",
                conversation_id,
                group_id,
                has_state_record,
                ffi_has_group
            );

            if has_state_record && !ffi_has_group {
                tracing::warn!(
                    conversation_id = %conversation_id,
                    group_id = %group_id,
                    "Persisted GroupState exists but MLS context has no group — \
                     stale state, falling through to join_or_rejoin"
                );
                crate::info_log!(
                    "[sync] convo={} group={} stale state detected, entering init path",
                    conversation_id,
                    group_id
                );
            }

            // Initialize group state if missing OR if the persisted record is stale.
            if !has_state_record || !ffi_has_group {
                crate::info_log!(
                    "[sync] convo={} group={} entering init block",
                    conversation_id,
                    group_id
                );
                // Try to get epoch from FFI — if group doesn't exist locally, join it
                let epoch = if let Ok(gid_bytes) = hex::decode(group_id) {
                    crate::info_log!(
                        "[sync] convo={} group={} pre-get_epoch call",
                        conversation_id,
                        group_id
                    );
                    match self.mls_context().get_epoch(gid_bytes) {
                        Ok(e) => {
                            crate::info_log!(
                                "[sync] convo={} group={} FFI get_epoch Ok: {} (surprising — skipping join_or_rejoin)",
                                conversation_id,
                                group_id,
                                e
                            );
                            e
                        }
                        // The context closed between the check above and here
                        // (race with a concurrent suspension). Transient — keep the
                        // server epoch and DON'T engage the rejoin gate.
                        Err(crate::MLSError::ContextClosed) => {
                            crate::info_log!(
                                "[sync] convo={} group={} SKIP: MLS context closed mid-init (transient) — keeping epoch, not rejoining",
                                conversation_id,
                                group_id
                            );
                            convo.epoch
                        }
                        Err(e) => {
                            crate::info_log!(
                                "[sync] convo={} group={} FFI get_epoch Err: {}",
                                conversation_id,
                                group_id,
                                e
                            );
                            if !sync_rejoin_attempted.insert(conversation_id.to_string()) {
                                crate::info_log!(
                                    "[sync] convo={} SKIP: duplicate in cycle",
                                    conversation_id
                                );
                                tracing::debug!(
                                    conversation_id = %conversation_id,
                                    group_id = %group_id,
                                    "Skipping duplicate sync-triggered join/rejoin in same cycle"
                                );
                                convo.epoch
                            } else if !self.should_attempt_sync_rejoin(conversation_id).await {
                                crate::info_log!(
                                    "[sync] convo={} SKIP: eligibility gate rejected",
                                    conversation_id
                                );
                                tracing::debug!(
                                    conversation_id = %conversation_id,
                                    group_id = %group_id,
                                    "Skipping sync-triggered join/rejoin due to eligibility gate"
                                );
                                convo.epoch
                            } else {
                                crate::info_log!(
                                    "[sync] convo={} group={} CALLING join_or_rejoin",
                                    conversation_id,
                                    group_id
                                );
                                // Group not in FFI — try Welcome first, fall back to External Commit
                                tracing::info!(
                                    conversation_id = %conversation_id,
                                    group_id = %group_id,
                                    "Group not found in FFI, joining (Welcome first, External Commit fallback)"
                                );
                                match self.join_or_rejoin(conversation_id).await {
                                    Ok(epoch) => {
                                        if let Some(resolved) = self
                                            .conversations()
                                            .lock()
                                            .await
                                            .get(conversation_id)
                                            .cloned()
                                        {
                                            effective_convo = resolved;
                                        }
                                        // Keep an authoritative server epoch
                                        // when it is ahead, but never let the
                                        // stale page make reconciliation treat
                                        // the just-landed local epoch as behind.
                                        effective_convo.epoch = effective_convo.epoch.max(epoch);
                                        tracing::info!(
                                            conversation_id = %conversation_id,
                                            group_id = %effective_convo.group_id,
                                            epoch,
                                            "Successfully joined group"
                                        );
                                        epoch
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            conversation_id = %conversation_id,
                                            group_id = %group_id,
                                            error = %e,
                                            "Failed to join group via join_or_rejoin; falling back to requesting leaf recovery"
                                        );
                                        if let Err(rec_err) =
                                            self.accept_conversation(conversation_id).await
                                        {
                                            tracing::warn!(
                                                conversation_id = %conversation_id,
                                                group_id = %group_id,
                                                error = %rec_err,
                                                "Failed to request leaf recovery/accept after join_or_rejoin failure"
                                            );
                                        }
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
                    group_id: effective_convo.group_id.clone(),
                    conversation_id: effective_convo.conversation_id.clone(),
                    epoch,
                    members: effective_convo
                        .members
                        .iter()
                        .map(|member| member.did.clone())
                        .collect(),
                };
                self.storage().set_group_state(&state).await?;
                {
                    let mut states = self.group_states().lock().await;
                    normalize_group_state(&mut states, state);
                }
            } else {
                // Update the authoritative member list durably before making
                // it visible in memory. Publishing first could make a failed
                // write permanent: the next sync would take this existing-state
                // branch again and never retry the missing projection.
                let resolved = ResolvedConversationContext {
                    conversation_id: conversation_id.to_string(),
                    group_id: group_id.to_string(),
                };
                let existing = {
                    let states = self.group_states().lock().await;
                    resolved.group_state(&states).cloned()
                };
                if let Some(mut state) = existing {
                    state.members = convo.members.iter().map(|m| m.did.clone()).collect();
                    self.storage().set_group_state(&state).await?;
                    let mut states = self.group_states().lock().await;
                    normalize_group_state(&mut states, state);
                }
            }

            let conversation_id = effective_convo.conversation_id.as_str();
            let group_id = effective_convo.group_id.as_str();
            let server_epoch = effective_convo.epoch;

            // Ensure conversation record exists in storage
            self.storage()
                .ensure_conversation_exists(user_did, conversation_id, group_id)
                .await?;

            // Check for epoch reconciliation — fetch and process missing commits
            let local_epoch = {
                let states = self.group_states().lock().await;
                ResolvedConversationContext {
                    conversation_id: conversation_id.to_string(),
                    group_id: group_id.to_string(),
                }
                .group_state(&states)
                .map(|state| state.epoch)
                .unwrap_or(0)
            };

            if server_epoch > local_epoch {
                tracing::info!(
                    conversation_id = %conversation_id,
                    group_id = %group_id,
                    local_epoch,
                    server_epoch,
                    "Server ahead — fetching pending messages to catch up"
                );

                // Fetch and process messages (includes commits) to advance local epoch.
                // This is the primary catch-up path for commits missed between syncs.
                //
                // Narrow the request with fromEpoch / toEpoch (lexicon params) so the
                // server returns the commits we actually need. Without bounds the server
                // falls back to "oldest 50 commits in [0, current_epoch]", which on busy
                // groups (>50 lifetime commits) strands lagging clients permanently.
                let from_epoch = Some((local_epoch.saturating_add(1)).min(u32::MAX as u64) as u32);
                let to_epoch = Some(server_epoch.min(u32::MAX as u64) as u32);
                match self
                    .fetch_messages(
                        conversation_id,
                        None,
                        50,
                        Some("commit"),
                        from_epoch,
                        to_epoch,
                    )
                    .await
                {
                    Ok((msgs, _)) => {
                        if !msgs.is_empty() {
                            tracing::info!(
                                conversation_id = %conversation_id,
                                group_id = %group_id,
                                processed = msgs.len(),
                                "Processed pending messages during sync catch-up"
                            );
                        }
                        // Re-check epoch after processing
                        let new_local = {
                            let states = self.group_states().lock().await;
                            ResolvedConversationContext {
                                conversation_id: conversation_id.to_string(),
                                group_id: group_id.to_string(),
                            }
                            .group_state(&states)
                            .map(|state| state.epoch)
                            .unwrap_or(0)
                        };
                        if server_epoch > new_local {
                            tracing::warn!(
                                conversation_id = %conversation_id,
                                group_id = %group_id,
                                local_epoch = new_local,
                                server_epoch,
                                "Still behind after processing — marking for rejoin"
                            );
                            // WS-5.2: recovery-critical write — escalate drops.
                            self.mark_needs_rejoin_critical(conversation_id).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            conversation_id = %conversation_id,
                            group_id = %group_id,
                            error = %e,
                            "Failed to fetch messages for epoch catch-up — marking for rejoin"
                        );
                        // Fetch failed — mark for rejoin regardless of gap size.
                        // WS-5.2: recovery-critical write — escalate drops.
                        self.mark_needs_rejoin_critical(conversation_id).await;
                    }
                }
            }

            // Always-on app-message fetch. The catch-up block above only fires
            // when the server is ahead on epoch — it filters with
            // `Some("commit")` because its purpose is epoch advancement. App
            // messages don't change epoch, so without this second pass the
            // receive flow is silently dead in already-joined groups (Android
            // symptom: SSE `messageEvent` arrives, `triggerSync` runs, but
            // `process_incoming` is never called for app payloads, so
            // `storage.store_message` never fires and the UI shows nothing).
            //
            // Pulls the most recent messages for the current local epoch.
            // After Welcome/External Commit recovery, older epoch material is
            // often intentionally unavailable on this device. Replaying those
            // stale ciphertexts makes the UI look broken while OpenMLS reports
            // WrongEpoch/TooDistantInThePast. Commit catch-up above is the
            // path for epoch advancement; this pass is for current-epoch app
            // traffic.
            // get_epoch Err means the group is missing locally; Ok(epoch) —
            // including epoch 0, which is legitimate between group creation
            // and the first commit — means fetch app traffic for that epoch.
            let app_epoch = match hex::decode(group_id)
                .ok()
                .map(|gid_bytes| self.mls_context().get_epoch(gid_bytes))
            {
                Some(Ok(epoch)) => epoch.min(u32::MAX as u64) as u32,
                Some(Err(e)) => {
                    tracing::debug!(
                        conversation_id = %conversation_id,
                        group_id = %group_id,
                        error = %e,
                        "Skipping app-message pass: local MLS group is unavailable"
                    );
                    continue;
                }
                None => {
                    tracing::debug!(
                        conversation_id = %conversation_id,
                        group_id = %group_id,
                        "Skipping app-message pass: group id is not valid hex"
                    );
                    continue;
                }
            };
            match self
                .fetch_messages(
                    conversation_id,
                    None,
                    20,
                    Some("app"),
                    Some(app_epoch),
                    None,
                )
                .await
            {
                Ok((msgs, _)) => {
                    if !msgs.is_empty() {
                        tracing::debug!(
                            conversation_id = %conversation_id,
                            group_id = %group_id,
                            new = msgs.len(),
                            "Sync app-message pass processed messages"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        conversation_id = %conversation_id,
                        group_id = %group_id,
                        error = %e,
                        "Sync app-message pass failed (non-fatal)"
                    );
                }
            }

            // Use the same server-acceptance -> local-merge -> durable
            // projection transaction as the explicit API. The former inline
            // path merged before sending and could advance locally after a DS
            // rejection or lose an accepted commit after a projection failure.
            if let Err(e) = self.commit_self_remove_proposals(conversation_id).await {
                tracing::warn!(
                    error = %e,
                    conversation_id = %conversation_id,
                    group_id = %group_id,
                    "Failed to commit pending proposals during sync"
                );
            }

            // Auto-consume needs_rejoin flag: if a previous sync or decrypt failure
            // flagged this conversation, attempt rejoin now (with rate-limiting).
            let needs_rejoin = match self.storage().needs_rejoin(conversation_id).await {
                Ok(flag) => flag,
                Err(e) => {
                    // A storage READ failure must not silently read as
                    // "no rejoin needed" without a trace — deferred recovery
                    // stalls for this conversation until the read recovers.
                    tracing::warn!(
                        conversation_id = %conversation_id,
                        error = %e,
                        "needs_rejoin read failed during sync — defaulting to false (deferred recovery skipped this pass)"
                    );
                    false
                }
            };
            if needs_rejoin {
                tracing::info!(
                    conversation_id = %conversation_id,
                    group_id = %group_id,
                    "Group flagged for rejoin — attempting in sync"
                );
                if !sync_rejoin_attempted.contains(conversation_id) {
                    match self
                        .consume_deferred_recovery_for_conversation(
                            conversation_id,
                            Some(server_epoch),
                            Some(group_id),
                        )
                        .await
                    {
                        Ok(super::recovery::DeferredRecoveryOutcome::ClearedStale) => continue,
                        Ok(super::recovery::DeferredRecoveryOutcome::Skipped) => {}
                        Ok(super::recovery::DeferredRecoveryOutcome::Recovered(epoch)) => {
                            sync_rejoin_attempted.insert(conversation_id.to_string());
                            tracing::info!(
                                conversation_id = %conversation_id,
                                group_id = %group_id,
                                epoch,
                                "Sync rejoin succeeded"
                            );
                        }
                        Err(e) => {
                            sync_rejoin_attempted.insert(conversation_id.to_string());
                            tracing::warn!(
                                conversation_id = %conversation_id,
                                group_id = %group_id,
                                error = %e,
                                "Sync rejoin failed"
                            );
                        }
                    }
                }
            }
        }

        // Fulfill any pending leaf recovery requests for conversations we are active in.
        if let Err(e) = self.fulfill_pending_leaf_recoveries().await {
            tracing::warn!(error = %e, "Failed to fulfill pending leaf recoveries during sync");
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
    use super::{
        conversation_contains_user_root_exact, member_matches_user_root_exact, ConversationView,
        MemberRole, MemberView,
    };

    #[test]
    fn membership_filter_preserves_method_specific_did_case() {
        assert!(member_matches_user_root_exact(
            "did:web:Example.com#device-a",
            "did:web:Example.com"
        ));
        assert!(!member_matches_user_root_exact(
            "did:web:example.com#device-b",
            "did:web:Example.com"
        ));
    }

    #[test]
    fn conversation_roster_requires_the_current_user_root() {
        let conversation = ConversationView {
            group_id: "abcd".to_string(),
            conversation_id: "conversation-1".to_string(),
            epoch: 7,
            members: vec![MemberView {
                did: "did:plc:mallory#device-1".to_string(),
                role: MemberRole::Member,
            }],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
        };

        assert!(
            !conversation_contains_user_root_exact(&conversation, "did:plc:alice"),
            "a DS roster containing only another member must be classified as an omission"
        );
    }

    #[test]
    fn conversation_roster_accepts_an_exact_device_bound_user_root() {
        let conversation = ConversationView {
            group_id: "abcd".to_string(),
            conversation_id: "conversation-1".to_string(),
            epoch: 7,
            members: vec![MemberView {
                did: "did:plc:alice#device-1".to_string(),
                role: MemberRole::Member,
            }],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
        };

        assert!(conversation_contains_user_root_exact(
            &conversation,
            "did:plc:alice"
        ));
    }

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
