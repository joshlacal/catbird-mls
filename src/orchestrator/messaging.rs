use crate::error::MLSError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use super::api_client::MLSAPIClient;
use super::canonical_transport::CleanChatSigningContext;
use super::constants;
use super::credentials::{CleanChatSigningAuthority, CredentialStore};
use super::error::{OrchestratorError, Result};
use super::mls_provider::{MlsCryptoContext, MlsDecryptOutcome, OwnEchoProof};
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

#[derive(Debug, PartialEq, Eq)]
enum SendSyncCursorProgress {
    Complete,
    Continue(String),
}

/// Bound duplicate-proof reads so an attacker-controlled server ID cannot
/// force an unbounded conversation-history allocation on the exceptional
/// replay path. A matching row outside this recent window fails closed.
const INBOUND_DEDUP_PROOF_LOOKBACK: u32 = 1_024;

/// Validate a delivery-service cursor before following it during the bounded
/// pre-send commit catch-up loop.
///
/// A page may contain only MLS commits, so `fetch_messages` can legitimately
/// return no displayable messages while still returning a continuation cursor.
/// The cursor, not the display-message count, is therefore authoritative.
fn next_send_sync_cursor(
    current_cursor: Option<&str>,
    next_cursor: Option<String>,
    seen_cursors: &mut HashSet<String>,
) -> Result<SendSyncCursorProgress> {
    let Some(next_cursor) = next_cursor else {
        return Ok(SendSyncCursorProgress::Complete);
    };

    if next_cursor.is_empty() {
        return Err(OrchestratorError::Api(
            "delivery service returned an empty cursor during send commit catch-up".to_string(),
        ));
    }

    if current_cursor == Some(next_cursor.as_str()) || !seen_cursors.insert(next_cursor.clone()) {
        return Err(OrchestratorError::Api(
            "delivery service returned a repeated cursor during send commit catch-up".to_string(),
        ));
    }

    Ok(SendSyncCursorProgress::Continue(next_cursor))
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Prove that a globally indexed server message ID belongs to this stable
    /// conversation. `message_exists` alone is insufficient because an
    /// attacker-controlled DS can reuse an ID from another conversation.
    async fn durable_message_exists_in_conversation(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<bool> {
        if !self.storage().message_exists(message_id).await? {
            return Ok(false);
        }
        Ok(self
            .storage()
            .get_messages(conversation_id, INBOUND_DEDUP_PROOF_LOOKBACK, None)
            .await?
            .iter()
            .any(|message| message.id == message_id))
    }

    async fn catch_up_pending_commits_for_send(
        &self,
        conversation_id: &str,
        phase: &'static str,
    ) -> Result<()> {
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();

        for round in 0..constants::SEND_SYNC_MAX_ROUNDS {
            let (displayable_messages, next_cursor) = self
                .fetch_messages(
                    conversation_id,
                    cursor.as_deref(),
                    constants::SEND_SYNC_BATCH_SIZE,
                    Some("commit"),
                    None,
                    None,
                )
                .await?;

            tracing::debug!(
                conversation_id,
                phase,
                round,
                displayable_message_count = displayable_messages.len(),
                has_next_cursor = next_cursor.is_some(),
                "Processed bounded send commit catch-up page"
            );

            match next_send_sync_cursor(cursor.as_deref(), next_cursor, &mut seen_cursors)? {
                SendSyncCursorProgress::Complete => return Ok(()),
                SendSyncCursorProgress::Continue(next_cursor) => {
                    cursor = Some(next_cursor);
                }
            }
        }

        Err(OrchestratorError::Api(format!(
            "delivery service send commit catch-up exceeded the {}-page safety limit",
            constants::SEND_SYNC_MAX_ROUNDS
        )))
    }

    /// Persist an inbound epoch advance before publishing it to the in-memory
    /// cache or allowing the caller to return a delivery-service cursor.
    ///
    /// The per-conversation transition lock serializes inbound epoch writes in
    /// this module. The shared cache is deliberately left untouched until the
    /// storage write succeeds, so a failed durable write cannot masquerade as
    /// a processed page in the current process.
    async fn persist_inbound_epoch_advance(
        &self,
        resolved: &ResolvedConversationContext,
        target_epoch: u64,
    ) -> Result<()> {
        let transition_lock = self.rejoin_lock(&resolved.conversation_id).await;
        let _transition_guard = transition_lock.lock().await;

        let state_to_persist = {
            let states = self.group_states().lock().await;
            if let Some(state) = resolved.group_state(&states) {
                if target_epoch <= state.epoch {
                    None
                } else {
                    let mut advanced = state.clone();
                    advanced.epoch = target_epoch;
                    Some(advanced)
                }
            } else if let Some(stored) = self.storage().get_group_state(&resolved.group_id).await? {
                if target_epoch <= stored.epoch {
                    None
                } else {
                    let mut advanced = stored;
                    advanced.epoch = target_epoch;
                    Some(advanced)
                }
            } else {
                return Err(OrchestratorError::GroupNotFound(resolved.group_id.clone()));
            }
        };

        if let Some(state_to_persist) = state_to_persist {
            self.storage().set_group_state(&state_to_persist).await?;
            let mut states = self.group_states().lock().await;
            if let Some(state) = resolved.group_state_mut(&mut states) {
                if state_to_persist.epoch > state.epoch {
                    state.epoch = state_to_persist.epoch;
                }
            } else {
                states.insert(resolved.group_id.clone(), state_to_persist);
            }
        }
        Ok(())
    }

    /// Reconcile a `WrongEpoch` redelivery against both durable and cached
    /// epoch projections.
    ///
    /// `merge_incoming_commit` may advance the OpenMLS group before its
    /// storage flush reports failure. On redelivery, decrypt then reports
    /// `WrongEpoch` even though the matching `GroupState` write never ran. A
    /// plain duplicate skip would return the delivery-service cursor and make
    /// that partial transition permanent. When crypto is ahead, retry its
    /// durability barrier first, then write the durable projection, and only
    /// then update the cache. Any disagreement that crypto cannot safely
    /// dominate fails closed for recovery instead of being acknowledged.
    ///
    /// Returns the repaired epoch when a projection repair was required, so
    /// callers can perform post-durability secret cleanup after the transition
    /// lock is released.
    async fn reconcile_wrong_epoch_durability(
        &self,
        resolved: &ResolvedConversationContext,
        group_id_bytes: &[u8],
    ) -> Result<Option<u64>> {
        let transition_lock = self.rejoin_lock(&resolved.conversation_id).await;
        let _transition_guard = transition_lock.lock().await;

        let mut observed_epoch = self
            .mls_context()
            .get_epoch(group_id_bytes.to_vec())
            .map_err(OrchestratorError::from)?;

        // Epoch equality alone cannot prove durability: an application message
        // may already have projected the post-merge epoch after an earlier
        // crypto flush failed. Run the barrier for every WrongEpoch, and
        // stabilize across a concurrent crypto advance before publishing any
        // projection or cursor.
        let mut durable_crypto_epoch = None;
        for _ in 0..3 {
            self.mls_context()
                .ensure_storage_durable()
                .map_err(OrchestratorError::from)?;
            let after_barrier = self
                .mls_context()
                .get_epoch(group_id_bytes.to_vec())
                .map_err(OrchestratorError::from)?;
            if after_barrier == observed_epoch {
                durable_crypto_epoch = Some(after_barrier);
                break;
            }
            observed_epoch = after_barrier;
        }
        let crypto_epoch = durable_crypto_epoch.ok_or_else(|| {
            OrchestratorError::RecoveryFailed(format!(
                "MLS epoch did not stabilize across durability barriers for conversation {}",
                resolved.conversation_id
            ))
        })?;

        let persisted_state = self
            .storage()
            .get_group_state(&resolved.group_id)
            .await?
            .ok_or_else(|| OrchestratorError::GroupNotFound(resolved.group_id.clone()))?;
        let cached_state = {
            let states = self.group_states().lock().await;
            resolved
                .group_state(&states)
                .cloned()
                .unwrap_or_else(|| persisted_state.clone())
        };

        if persisted_state.group_id != resolved.group_id
            || persisted_state.conversation_id != resolved.conversation_id
        {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "persisted group projection identity mismatch for conversation {}",
                resolved.conversation_id
            )));
        }

        let cached_epoch = cached_state.epoch;
        let persisted_epoch = persisted_state.epoch;
        if crypto_epoch == cached_epoch && crypto_epoch == persisted_epoch {
            return Ok(None);
        }

        if crypto_epoch < cached_epoch || crypto_epoch < persisted_epoch {
            return Err(OrchestratorError::RecoveryFailed(format!(
                "MLS epoch projection is ahead of crypto for conversation {} (crypto={}, cached={}, persisted={})",
                resolved.conversation_id, crypto_epoch, cached_epoch, persisted_epoch
            )));
        }

        let mut repaired_state = cached_state;
        repaired_state.epoch = crypto_epoch;
        self.storage().set_group_state(&repaired_state).await?;

        let mut states = self.group_states().lock().await;
        let cached = resolved
            .group_state_mut(&mut states)
            .ok_or_else(|| OrchestratorError::GroupNotFound(resolved.group_id.clone()))?;
        cached.epoch = crypto_epoch;

        Ok(Some(crypto_epoch))
    }

    fn ready_result(
        recovery_state: ConversationRecoveryState,
        epoch: Option<u64>,
    ) -> ConversationReadyResult {
        let normalized_state =
            if recovery_state == ConversationRecoveryState::Healthy && epoch.is_none() {
                ConversationRecoveryState::GroupMissing
            } else {
                recovery_state
            };

        ConversationReadyResult {
            recovery_state: normalized_state,
            epoch,
            send_allowed: normalized_state == ConversationRecoveryState::Healthy && epoch.is_some(),
        }
    }

    /// Send a text message to a conversation.
    ///
    /// 1. Encrypts the message via MLS FFI
    /// 2. Sends ciphertext to the delivery service
    /// 3. Stores the plaintext locally
    pub async fn send_message(&self, conversation_id: &str, text: &str) -> Result<Message> {
        Box::pin(self.send_payload_message(conversation_id, MLSMessagePayload::text(text))).await
    }

    async fn reject_send_if_reset_pending(&self, conversation_id: &str) -> Result<()> {
        if let Some(pending) = self.reset_pending_payload_result(conversation_id).await? {
            return Err(OrchestratorError::ResetCompletionNotCommitted {
                convo_id: conversation_id.to_string(),
                reset_generation: pending.reset_generation,
                reason: "ResetPending authority prohibits message send".to_string(),
            });
        }
        Ok(())
    }

    pub(crate) async fn project_conversation_recovery_state(
        &self,
        conversation_id: &str,
    ) -> ConversationRecoveryState {
        match self
            .project_conversation_recovery_state_result(conversation_id)
            .await
        {
            Ok(projected) => projected,
            Err(error) => {
                tracing::warn!(
                    conversation_id,
                    error = %error,
                    "recovery-state projection failed closed"
                );
                ConversationRecoveryState::UnrecoverableLocal
            }
        }
    }

    async fn project_conversation_recovery_state_result(
        &self,
        conversation_id: &str,
    ) -> Result<ConversationRecoveryState> {
        if self
            .reset_pending_payload_result(conversation_id)
            .await?
            .is_some()
        {
            return Ok(ConversationRecoveryState::ResetPending);
        }

        let state = self
            .conversation_states()
            .lock()
            .await
            .get(conversation_id)
            .cloned();
        let projected = match state.as_ref() {
            None | Some(ConversationState::Active) => ConversationRecoveryState::Healthy,
            Some(ConversationState::Initializing) => ConversationRecoveryState::Recovering,
            Some(ConversationState::ForkDetected) => ConversationRecoveryState::EpochBehind,
            Some(ConversationState::NeedsRejoin) => ConversationRecoveryState::NeedsRejoin,
            Some(ConversationState::ResetPending { .. }) => ConversationRecoveryState::ResetPending,
            Some(ConversationState::Quarantined { .. }) | Some(ConversationState::Failed) => {
                ConversationRecoveryState::UnrecoverableLocal
            }
        };

        if projected != ConversationRecoveryState::Healthy {
            return Ok(projected);
        }

        let resolved = match self.resolve_legacy_group_identifier(conversation_id).await {
            Ok(resolved) => resolved,
            Err(_) => return Ok(ConversationRecoveryState::GroupMissing),
        };
        let Ok(group_id_bytes) = resolved.group_id_bytes() else {
            return Ok(ConversationRecoveryState::GroupMissing);
        };

        Ok(match self.mls_context().get_epoch(group_id_bytes) {
            Ok(_) => projected,
            Err(_) => ConversationRecoveryState::GroupMissing,
        })
    }

    pub async fn ensure_conversation_ready(
        &self,
        convo_id: &str,
    ) -> Result<ConversationReadyResult> {
        self.check_shutdown().await?;
        self.require_user_did().await?;

        let had_in_memory_reset_authority = matches!(
            self.conversation_states().lock().await.get(convo_id),
            Some(ConversationState::ResetPending { .. })
        );
        let projected = self
            .project_conversation_recovery_state_result(convo_id)
            .await?;
        crate::warn_log!(
            "[REJOIN-DIAG] convo={} ensure_conversation_ready ENTRY projected={:?}",
            convo_id,
            projected
        );

        if matches!(
            projected,
            ConversationRecoveryState::Recovering | ConversationRecoveryState::UnrecoverableLocal
        ) || (projected == ConversationRecoveryState::ResetPending
            && !had_in_memory_reset_authority)
        {
            crate::warn_log!(
                "[REJOIN-DIAG] convo={} ensure_conversation_ready EARLY-RETURN {:?} (Recovering/UnrecoverableLocal) — NOT calling join_or_rejoin",
                convo_id,
                projected
            );
            return Ok(Self::ready_result(projected, None));
        }

        let local_epoch = match self.local_group_epoch_result(convo_id).await {
            Ok(epoch) => {
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} ensure_conversation_ready local_group_epoch_result Ok(epoch={:?})",
                    convo_id,
                    epoch
                );
                epoch
            }
            Err(err)
                if matches!(
                    projected,
                    ConversationRecoveryState::NeedsRejoin
                        | ConversationRecoveryState::ResetPending
                        | ConversationRecoveryState::EpochBehind
                ) =>
            {
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} ensure_conversation_ready BAILING to {:?} WITHOUT join_or_rejoin — local_group_epoch_result Err: {:?}",
                    convo_id,
                    projected,
                    err
                );
                return Ok(Self::ready_result(projected, None));
            }
            Err(err) => return Err(err.into()),
        };

        if projected == ConversationRecoveryState::Healthy && local_epoch.is_some() {
            return Ok(Self::ready_result(projected, local_epoch));
        }

        // P0.1 (epoch-inflation remediation): close the force_rejoin door at the
        // authorization layer, not just at startup. A NeedsRejoin projection on a
        // group that is LOCALLY healthy (present, valid epoch, self is a current
        // member of the ratchet tree) must NOT drive join_or_rejoin -> force_rejoin
        // (delete_group + External Commit), which heals nothing and only inflates
        // the server's cosmetic group_info_epoch counter. Clear the stale flag and
        // short-circuit to Healthy. The self-membership gate inside the helper means
        // a genuinely-behind / leaf-lost member (absent from the local tree) still
        // falls through to recovery below — so this cannot strand them.
        if local_epoch.is_some()
            && projected == ConversationRecoveryState::NeedsRejoin
            && self.clear_needs_rejoin_if_locally_healthy(convo_id).await
        {
            let projected = self
                .project_conversation_recovery_state_result(convo_id)
                .await?;
            let epoch = self
                .local_group_epoch_result(convo_id)
                .await?
                .or(local_epoch);
            crate::warn_log!(
                "[REJOIN-DIAG] convo={} stale NeedsRejoin on locally-healthy group — cleared, returning {:?} (NO force_rejoin)",
                convo_id,
                projected
            );
            return Ok(Self::ready_result(projected, epoch));
        }

        match self.join_or_rejoin(convo_id).await {
            Ok(epoch) => {
                // join_or_rejoin owns the transition gate through its final
                // fail-closed Active projection. Never repeat that write after
                // the gate is released: a newer reset may already own authority.
                crate::warn_log!(
                    "[REJOIN-DIAG] convo={} rejoin succeeded — cleared NeedsRejoin -> Active (epoch={})",
                    convo_id,
                    epoch
                );
                let projected = self
                    .project_conversation_recovery_state_result(convo_id)
                    .await?;
                let epoch = self
                    .local_group_epoch_result(convo_id)
                    .await?
                    .or(Some(epoch));
                Ok(Self::ready_result(projected, epoch))
            }
            Err(OrchestratorError::NotAuthenticated) => Err(OrchestratorError::NotAuthenticated),
            Err(OrchestratorError::ShuttingDown) => Err(OrchestratorError::ShuttingDown),
            Err(_) => {
                let projected = self
                    .project_conversation_recovery_state_result(convo_id)
                    .await?;
                let epoch = match self.local_group_epoch_result(convo_id).await {
                    Ok(epoch) => epoch,
                    Err(_err)
                        if matches!(
                            projected,
                            ConversationRecoveryState::NeedsRejoin
                                | ConversationRecoveryState::ResetPending
                                | ConversationRecoveryState::EpochBehind
                        ) =>
                    {
                        None
                    }
                    Err(err) => return Err(err.into()),
                };
                Ok(Self::ready_result(projected, epoch))
            }
        }
    }

    /// Send a text message with a rich embed.
    pub async fn send_message_with_embed(
        &self,
        conversation_id: &str,
        text: &str,
        embed: MLSEmbedData,
    ) -> Result<Message> {
        self.send_payload_message(
            conversation_id,
            MLSMessagePayload::text_with_embed(text, embed),
        )
        .await
    }

    /// Send a pre-encoded MLS message payload JSON envelope.
    ///
    /// This lets platform clients keep their existing payload model as the wire
    /// compatibility boundary while Rust remains authoritative for MLS encrypt,
    /// send, retry, recovery, and local storage.
    pub async fn send_payload_json(
        &self,
        conversation_id: &str,
        payload_json: &str,
    ) -> Result<Message> {
        let payload = MLSMessagePayload::decode(payload_json.as_bytes()).map_err(|e| {
            OrchestratorError::InvalidInput(format!("Failed to decode message payload JSON: {e}"))
        })?;
        self.send_payload_message(conversation_id, payload).await
    }

    /// Send an encrypted reaction (add or remove emoji) to a message.
    ///
    /// The reaction is encrypted as an MLS application message with
    /// `messageType: "reaction"`, matching the iOS `sendEncryptedReaction` path.
    pub async fn send_reaction(
        &self,
        conversation_id: &str,
        message_id: &str,
        emoji: &str,
        action: ReactionAction,
    ) -> Result<Message> {
        self.send_payload_message(
            conversation_id,
            MLSMessagePayload::reaction(message_id, emoji, action),
        )
        .await
    }

    async fn send_payload_message(
        &self,
        conversation_id: &str,
        payload: MLSMessagePayload,
    ) -> Result<Message> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        self.reject_send_if_reset_pending(conversation_id).await?;

        tracing::debug!(conversation_id, "Sending message");

        // Layer 3: refuse send when the conversation is quarantined. Surfaces
        // a structured error to the platform so the UI can disable the composer.
        if let Some(q) = self
            .recovery_tracker()
            .lock()
            .await
            .quarantine_snapshot(conversation_id)
        {
            tracing::warn!(
                conversation_id,
                reason = q.reason.tag(),
                "send refused: conversation quarantined (Layer 3)"
            );
            return Err(OrchestratorError::ConversationQuarantined {
                convo_id: conversation_id.to_string(),
                reason: q.reason.tag().to_string(),
            });
        }

        let resolved = self
            .resolve_legacy_group_identifier(conversation_id)
            .await
            .map_err(|error| match error {
                OrchestratorError::ConversationNotFound(_) => OrchestratorError::NotJoined {
                    convo_id: conversation_id.to_string(),
                },
                other => other,
            })?;
        let group_id_bytes = resolved.group_id_bytes()?;

        let payload_bytes = payload.encode().map_err(|e| {
            OrchestratorError::InvalidInput(format!("Failed to encode message payload: {e}"))
        })?;
        let payload_json = String::from_utf8(payload_bytes.clone()).map_err(|e| {
            OrchestratorError::InvalidInput(format!("Failed to stringify message payload: {e}"))
        })?;
        let display_text = payload.display_text();

        tracing::info!(
            conversation_id,
            payload_len = payload_bytes.len(),
            "Encoded MLSMessagePayload for send"
        );
        self.catch_up_pending_commits_for_send(conversation_id, "pre_send")
            .await?;
        // Serialize only the final authorization + encryption + delivery attempt
        // against reset transitions. Network catch-up above intentionally runs
        // outside this per-conversation lock.
        let transition_lock = self.rejoin_lock(conversation_id).await;
        let transition_guard = transition_lock.lock().await;
        self.reject_send_if_reset_pending(conversation_id).await?;

        // Encrypt via MLS.
        //
        // Task #43: `send` no longer self-heals via `join_or_rejoin` when the group
        // is missing locally. Auto-External-Commits on send were a major source of
        // production epoch inflation (hot path, runs on every send failure). Instead
        // we surface `NotJoined` to the caller; the platform decides whether to
        // trigger recovery (Welcome replay, S1 reset request, UI prompt, etc.).
        let encrypt_result = match self
            .mls_context()
            .encrypt_message(group_id_bytes.clone(), payload_bytes.clone())
        {
            Ok(r) => r,
            Err(crate::MLSError::GroupNotFound { .. }) => {
                tracing::warn!(
                    conversation_id,
                    "send_payload_message: group not found locally; NOT auto-rejoining (task #43). Caller must handle."
                );
                return Err(OrchestratorError::NotJoined {
                    convo_id: conversation_id.to_string(),
                });
            }
            Err(e) => return Err(OrchestratorError::from(e)),
        };

        // Track own commit for dedup
        self.evict_stale_commits().await;
        let commit_hash = sha2::Sha256::digest(&encrypt_result.ciphertext).to_vec();
        self.own_commits()
            .lock()
            .await
            .insert(commit_hash, web_time::Instant::now());

        // Get current epoch from MLS FFI (authoritative source).
        // The in-memory group_states cache can be stale or missing after
        // session restore, so always query the FFI layer.
        let epoch = match self.mls_context().get_epoch(group_id_bytes.clone()) {
            Ok(e) => {
                tracing::info!(conversation_id, epoch = e, "FFI epoch for send_message");
                e
            }
            Err(err) => {
                tracing::warn!(conversation_id, error = %err, "FFI get_epoch failed, using cached group state");
                let states = self.group_states().lock().await;
                resolved
                    .group_state(&states)
                    .map(|state| state.epoch)
                    .unwrap_or(0)
            }
        };

        // Generate the client message ID before send so local storage and server ACK state
        // refer to the same identifier.
        let message_id = uuid::Uuid::new_v4().to_string();

        let send_result = self
            .send_message_prepared(
                &resolved.conversation_id,
                &encrypt_result.ciphertext,
                epoch,
                &message_id,
            )
            .await;
        drop(transition_guard);

        // Extract response on success, handle errors
        let send_response = match send_result {
            Ok(resp) => {
                self.failover_tracker()
                    .lock()
                    .await
                    .record_success(conversation_id);
                Some(resp)
            }
            Err(OrchestratorError::Timeout(ref _msg)) => {
                let mut tracker = self.failover_tracker().lock().await;
                tracker.record_failure(conversation_id);
                if tracker.should_failover(conversation_id) {
                    drop(tracker);
                    tracing::warn!(
                        conversation_id,
                        "Sequencer failover threshold reached, requesting failover"
                    );
                    tracing::warn!(conversation_id, "Failover requested (no-op in v2)");
                }
                return Err(send_result.unwrap_err());
            }
            Err(OrchestratorError::ServerError {
                status: 409,
                ref body,
            }) => {
                // Approach B: lightweight sync + single retry on 409 (epoch mismatch).
                // NO External Commit — only catch up on pending commits and re-encrypt.
                let remote = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["serverEpoch"].as_u64())
                    .unwrap_or(0);
                tracing::warn!(
                    conversation_id,
                    local_epoch = epoch,
                    remote_epoch = remote,
                    "Epoch mismatch (409) — attempting Approach B lightweight sync"
                );

                // Lightweight sync: fetch pending commits to advance local epoch.
                // A commit-only page intentionally returns no displayable
                // messages, so cursor progression is handled independently of
                // the returned message vector.
                if let Err(error) = self
                    .catch_up_pending_commits_for_send(conversation_id, "retry_after_409")
                    .await
                {
                    tracing::error!(
                        conversation_id,
                        error = %error,
                        "409 recovery: commit catch-up failed — flagging NEEDS_REJOIN"
                    );
                    self.mark_needs_rejoin_critical(conversation_id).await;
                    return Err(error);
                }

                // Re-encrypt with updated epoch and retry ONCE
                let retry_epoch = match self.mls_context().get_epoch(group_id_bytes.clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        self.mark_needs_rejoin_critical(conversation_id).await;
                        return Err(OrchestratorError::EpochMismatch {
                            local: epoch,
                            remote,
                        });
                    }
                };

                let retry_transition_lock = self.rejoin_lock(conversation_id).await;
                let retry_transition_guard = retry_transition_lock.lock().await;
                self.reject_send_if_reset_pending(conversation_id).await?;

                let retry_encrypt = match self
                    .mls_context()
                    .encrypt_message(group_id_bytes.clone(), payload_bytes.clone())
                {
                    Ok(r) => r,
                    Err(e) => {
                        drop(retry_transition_guard);
                        tracing::error!(
                            conversation_id,
                            error = %e,
                            "409 recovery: re-encryption failed — flagging NEEDS_REJOIN"
                        );
                        self.mark_needs_rejoin_critical(conversation_id).await;
                        return Err(OrchestratorError::from(e));
                    }
                };

                // Track the new commit for dedup
                let retry_commit_hash = sha2::Sha256::digest(&retry_encrypt.ciphertext).to_vec();
                self.own_commits()
                    .lock()
                    .await
                    .insert(retry_commit_hash, web_time::Instant::now());

                let retry_send_result = self
                    .send_message_prepared(
                        conversation_id,
                        &retry_encrypt.ciphertext,
                        retry_epoch,
                        &message_id,
                    )
                    .await;
                drop(retry_transition_guard);

                match retry_send_result {
                    Ok(resp) => {
                        self.failover_tracker()
                            .lock()
                            .await
                            .record_success(conversation_id);
                        tracing::info!(
                            conversation_id,
                            retry_epoch,
                            "409 recovery: retry succeeded after lightweight sync"
                        );
                        Some(resp)
                    }
                    Err(OrchestratorError::ServerError { status: 409, .. }) => {
                        // Second 409: flag conversation NEEDS_REJOIN, return error
                        tracing::error!(
                            conversation_id,
                            "409 recovery: second 409 after sync — flagging NEEDS_REJOIN"
                        );
                        self.mark_needs_rejoin_critical(conversation_id).await;
                        return Err(OrchestratorError::EpochMismatch {
                            local: retry_epoch,
                            remote,
                        });
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Err(_) => {
                // Other errors — don't track as sequencer failure
                return Err(send_result.unwrap_err());
            }
        };

        // Use server values when available, fall back to local
        let (msg_epoch, msg_seq) = match &send_response {
            Some(resp) => (resp.epoch, resp.seq),
            None => (epoch, 0), // timeout case — best effort
        };

        // Track as pending for dedup (in-memory fast path)
        self.pending_messages()
            .lock()
            .await
            .insert(message_id.clone());

        // Persist pending message for dedup across app restarts
        if let Err(e) = self
            .storage()
            .store_pending_message(conversation_id, &message_id)
            .await
        {
            tracing::warn!(
                error = %e,
                message_id = %message_id,
                "Failed to persist pending message for dedup"
            );
        }

        let mut message = Message {
            id: message_id,
            conversation_id: conversation_id.to_string(),
            sender_did: user_did,
            text: display_text,
            timestamp: Utc::now(),
            epoch: msg_epoch,
            sequence_number: msg_seq,
            is_own: true,
            delivery_status: None,
            payload_json: Some(payload_json),
        };

        let _ = self
            .refresh_delivery_statuses(conversation_id, std::slice::from_mut(&mut message))
            .await;

        // Store locally
        self.storage().store_message(&message).await?;

        tracing::debug!(conversation_id, "Message sent successfully");
        Ok(message)
    }

    /// Process an incoming encrypted message envelope.
    ///
    /// 1. Checks for duplicates
    /// 2. Decrypts via MLS FFI
    /// 3. Handles commit messages (epoch advances)
    /// 4. Stores the decrypted message
    pub async fn process_incoming(&self, envelope: &IncomingEnvelope) -> Result<Option<Message>> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        crate::message_limits::validate_inbound_mls_message_len(
            envelope.ciphertext.len(),
            "orchestrator incoming ciphertext",
        )?;

        // Resolve the stable conversation identity before touching deduplication or
        // self-commit replay state. Input for an unknown conversation must fail
        // closed without consuming state belonging to an authoritative context.
        let resolved = match self
            .resolve_legacy_group_identifier(&envelope.conversation_id)
            .await
        {
            Ok(resolved) => resolved,
            Err(OrchestratorError::ConversationNotFound(_)) => {
                tracing::warn!(
                    conversation_id = %envelope.conversation_id,
                    "process_incoming: no authoritative conversation-to-group mapping; refusing cursor advancement"
                );
                return Err(OrchestratorError::NotJoined {
                    convo_id: envelope.conversation_id.clone(),
                });
            }
            Err(error) => return Err(error),
        };

        // HTTP polling, push delivery, and send catch-up can all present the
        // same ordered frame concurrently. Serialize by stable conversation
        // through the final crypto/application durability barrier so one
        // pipeline cannot puncture an OpenMLS generation while another races
        // past `message_exists` and acknowledges an unpersisted envelope.
        // This is deliberately independent from `rejoin_lock`: recovery paths
        // never acquire this lock, so receive-side transition helpers can keep
        // their established lock ordering without a self-deadlock.
        let inbound_lock = self
            .inbound_processing_lock(&resolved.conversation_id)
            .await;
        let _inbound_guard = inbound_lock.lock().await;

        // A reset may have changed the stable-conversation -> group mapping
        // while this delivery waited for an earlier pipeline. Re-resolve only
        // after owning the inbound lock; decrypting against the stale group
        // would consume state outside the authoritative context.
        let resolved = match self
            .resolve_legacy_group_identifier(&envelope.conversation_id)
            .await
        {
            Ok(resolved) => resolved,
            Err(OrchestratorError::ConversationNotFound(_)) => {
                return Err(OrchestratorError::NotJoined {
                    convo_id: envelope.conversation_id.clone(),
                });
            }
            Err(error) => return Err(error),
        };
        let group_id_bytes = resolved.group_id_bytes()?;

        // Dedup check
        if let Some(ref msg_id) = envelope.server_message_id {
            if self
                .durable_message_exists_in_conversation(&resolved.conversation_id, msg_id)
                .await?
            {
                tracing::debug!(message_id = %msg_id, "Duplicate message, skipping");
                return Ok(None);
            }
        }

        // Check if this is our own commit (self-commit detection)
        let commit_hash = sha2::Sha256::digest(&envelope.ciphertext).to_vec();
        let is_own_commit = self.own_commits().lock().await.contains_key(&commit_hash);

        if is_own_commit {
            let expectation = self
                .own_commit_expectations()
                .lock()
                .await
                .get(&commit_hash)
                .cloned();
            if let Some(expectation) = expectation {
                let identity_matches = expectation.group_id == resolved.group_id;
                let proof = if identity_matches {
                    self.mls_context()
                        .ensure_storage_durable()
                        .map_err(OrchestratorError::from)
                        .and_then(|_| {
                            self.mls_context()
                                .get_epoch(group_id_bytes.clone())
                                .map_err(OrchestratorError::from)
                        })
                } else {
                    Err(OrchestratorError::RecoveryFailed(format!(
                        "self-commit expectation identity mismatch for conversation {}",
                        resolved.conversation_id
                    )))
                };

                let crypto_epoch = match proof {
                    Ok(epoch) => epoch,
                    Err(error) => {
                        self.mark_needs_rejoin_critical(&resolved.conversation_id)
                            .await;
                        return Err(error);
                    }
                };
                let durable_state = match self.storage().get_group_state(&resolved.group_id).await {
                    Ok(Some(state)) => state,
                    Ok(None) => {
                        self.mark_needs_rejoin_critical(&resolved.conversation_id)
                            .await;
                        return Err(OrchestratorError::RecoveryFailed(format!(
                            "self-commit echo arrived before durable GroupState for conversation {}",
                            resolved.conversation_id
                        )));
                    }
                    Err(error) => {
                        self.mark_needs_rejoin_critical(&resolved.conversation_id)
                            .await;
                        return Err(error);
                    }
                };
                if (durable_state.conversation_id != expectation.conversation_id
                    && durable_state.conversation_id != resolved.conversation_id)
                    || durable_state.group_id != expectation.group_id
                    || durable_state.epoch < expectation.target_epoch
                    || crypto_epoch < expectation.target_epoch
                {
                    self.mark_needs_rejoin_critical(&resolved.conversation_id)
                        .await;
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "self-commit echo arrived before durable confirmation for conversation {} (target epoch {})",
                        resolved.conversation_id, expectation.target_epoch
                    )));
                }
            }

            // Consume the hash only after any epoch-changing expectation has
            // been proven against both crypto storage and durable GroupState.
            self.remove_own_commit_tracking(&commit_hash).await;
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                "Skipping own commit"
            );
            return Ok(None);
        }

        // Decrypt via MLS FFI.
        //
        // Task #43: `process_incoming` no longer auto-External-Commits when the
        // group is missing locally. Surface NotJoined so the current page
        // cursor cannot be acknowledged before Welcome/reset recovery makes
        // the ciphertext processable. This eliminates the hot-path External
        // Commit spiral without silently skipping ordered server frames.
        let decrypt_result = match self
            .mls_context()
            .decrypt_message_outcome(group_id_bytes.clone(), envelope.ciphertext.clone())
        {
            Ok(MlsDecryptOutcome::Message(r)) => r,
            Ok(MlsDecryptOutcome::OwnPrivateMessage {
                epoch,
                aad_sha256,
                ciphertext_sha256,
            }) => {
                let has_proof = match envelope.server_message_id.as_deref() {
                    Some(server_entry_id) => self.mls_context().has_own_echo_proof(
                        &resolved.conversation_id,
                        &group_id_bytes,
                        server_entry_id,
                        epoch,
                        &aad_sha256,
                        &ciphertext_sha256,
                    )?,
                    None => false,
                };
                if has_proof {
                    tracing::debug!(
                        conversation_id = %envelope.conversation_id,
                        "Skipping durably proven own private message"
                    );
                    return Ok(None);
                } else {
                    tracing::warn!(
                        conversation_id = %envelope.conversation_id,
                        "OwnPrivateMessage without durable echo proof; refusing cursor advancement"
                    );
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "unverified own-private message outcome for conversation {}",
                        resolved.conversation_id
                    )));
                }
            }
            Ok(MlsDecryptOutcome::OwnPendingCommit) => {
                tracing::warn!(
                    conversation_id = %envelope.conversation_id,
                    "OwnPendingCommit reached decrypt outcome without prior durable confirmation; refusing cursor advancement"
                );
                return Err(OrchestratorError::RecoveryFailed(format!(
                    "unverified own pending commit outcome for conversation {}",
                    resolved.conversation_id
                )));
            }
            Err(crate::MLSError::GroupNotFound { .. }) => {
                tracing::warn!(
                    convo_id = %envelope.conversation_id,
                    "process_incoming: group not found locally; refusing cursor advancement until recovery",
                );
                return Err(OrchestratorError::NotJoined {
                    convo_id: envelope.conversation_id.clone(),
                });
            }
            Err(e) if e.is_wrong_epoch() => {
                // WrongEpoch is normally an old/replayed message, but it can
                // also be redelivery after OpenMLS mutated the group and its
                // durability flush failed before GroupState was projected. Do
                // not acknowledge until crypto, durable projection, and cache
                // are reconciled in that order.
                match self
                    .reconcile_wrong_epoch_durability(&resolved, &group_id_bytes)
                    .await
                {
                    Ok(repaired_epoch) => {
                        if let Some(repaired_epoch) = repaired_epoch {
                            tracing::info!(
                                conversation_id = %envelope.conversation_id,
                                repaired_epoch,
                                "Repaired durable epoch projection after WrongEpoch redelivery"
                            );
                            self.cleanup_epoch_secrets_if_needed(
                                &resolved.conversation_id,
                                &resolved.group_id,
                                repaired_epoch,
                            )
                            .await;
                        } else {
                            tracing::debug!(
                                conversation_id = %envelope.conversation_id,
                                "Skipping old or replayed message after verifying durable epoch projection"
                            );
                        }
                        return Ok(None);
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            conversation_id = %envelope.conversation_id,
                            "WrongEpoch durability reconciliation failed — refusing cursor advancement"
                        );
                        self.mark_needs_rejoin_critical(&envelope.conversation_id)
                            .await;
                        return Err(error);
                    }
                }
            }
            Err(e) if e.is_secret_reuse() => {
                let has_durable_evidence = match envelope.server_message_id.as_deref() {
                    Some(server_id) => {
                        self.durable_message_exists_in_conversation(
                            &resolved.conversation_id,
                            server_id,
                        )
                        .await?
                    }
                    None => false,
                };
                if has_durable_evidence {
                    tracing::debug!(
                        conversation_id = %envelope.conversation_id,
                        "Skipping already-ratcheted SecretReuse message"
                    );
                    return Ok(None);
                } else {
                    tracing::warn!(
                        conversation_id = %envelope.conversation_id,
                        "SecretReuse without durable envelope evidence; refusing cursor advancement"
                    );
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "SecretReuse without durable envelope evidence for conversation {}",
                        resolved.conversation_id
                    )));
                }
            }
            Err(e) if e.is_external_join_proposal_authorization_rejection() => {
                // This authenticated control frame was deliberately rejected
                // because no outsider authorization decision is wired. It is
                // neither a local fork nor crypto corruption: refuse cursor
                // advancement while leaving recovery counters untouched.
                tracing::warn!(
                    conversation_id = %envelope.conversation_id,
                    "Rejected unauthorized external-join proposal without attributing local divergence"
                );
                return Err(OrchestratorError::from(e));
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    conversation_id = %envelope.conversation_id,
                    "Decryption failed"
                );
                // Layer 3: classify peer-bad before falling through to fork/rejoin
                // counters. Peer-bad failures must NOT advance fork-detection or
                // NeedsRejoin counters --- those drive auto-External-Commits, which
                // is exactly the cascade we are trying to break.
                let local_epoch = self.mls_context().get_epoch(group_id_bytes.clone()).ok();
                let msg_epoch_for_class = {
                    let states = self.group_states().lock().await;
                    resolved
                        .group_state(&states)
                        .map(|state| state.epoch)
                        .unwrap_or(0)
                };
                if Self::classify_peer_bad(&e, local_epoch, msg_epoch_for_class) {
                    let msg_id = envelope.server_message_id.clone().unwrap_or_else(|| {
                        format!("unknown-{}", chrono::Utc::now().timestamp_millis())
                    });
                    let trigger = {
                        let mut tracker = self.recovery_tracker().lock().await;
                        tracker.record_peer_bad_commit(&envelope.conversation_id, &msg_id, None)
                    };
                    if let Some(reason) = trigger {
                        self.enter_quarantine(&envelope.conversation_id, reason)
                            .await;
                    }
                    return Err(OrchestratorError::from(e));
                }
                // Track consecutive decrypt failures for fork detection + divergence recovery
                let failure_count = {
                    let mut counts = self.decrypt_fail_counts().lock().await;
                    let count = counts.entry(envelope.conversation_id.clone()).or_insert(0);
                    *count += 1;
                    *count
                };
                if failure_count >= constants::DECRYPTION_FAILURE_THRESHOLD {
                    let fa = self
                        .fork_detection_states()
                        .lock()
                        .ok()
                        .and_then(|fds| fds.get(&envelope.conversation_id).cloned())
                        .is_some_and(|s| s.readd_attempts < constants::FORK_READD_MAX_ATTEMPTS);
                    if fa {
                        tracing::info!(conversation_id = %envelope.conversation_id, "Fork readd in-flight, deferring");
                    } else {
                        tracing::error!(conversation_id = %envelope.conversation_id, failures = failure_count, "Marking for rejoin");
                        if let Ok(mut fds) = self.fork_detection_states().lock() {
                            fds.remove(&envelope.conversation_id);
                        }
                        self.project_runtime_needs_rejoin(&envelope.conversation_id)
                            .await;
                        self.decrypt_fail_counts()
                            .lock()
                            .await
                            .insert(envelope.conversation_id.clone(), 0);
                    }
                } else if failure_count == constants::FORK_DETECTION_THRESHOLD {
                    let ep = self
                        .mls_context()
                        .get_epoch(group_id_bytes.clone())
                        .unwrap_or(0);
                    if self
                        .project_fork_detected_if_active(&envelope.conversation_id, ep)
                        .await
                    {
                        tracing::info!(conversation_id = %envelope.conversation_id, epoch = ep, "Fork threshold -- readd");
                        let _ = self.attempt_fork_readd(&envelope.conversation_id).await;
                        return Err(OrchestratorError::from(e));
                    }
                }
                return Err(OrchestratorError::from(e));
            }
        };

        // Reset consecutive decrypt failure counter on success
        self.decrypt_fail_counts()
            .lock()
            .await
            .remove(&envelope.conversation_id);
        {
            let was = self
                .fork_detection_states()
                .lock()
                .ok()
                .and_then(|mut fds| fds.remove(&envelope.conversation_id))
                .is_some();
            if was {
                self.project_runtime_active(&envelope.conversation_id).await;
            }
        }

        // Extract sender DID from credential
        let sender_did = String::from_utf8(decrypt_result.sender_credential.identity.clone())
            .unwrap_or_else(|_| envelope.sender_did.clone());

        // ADR-009 D4: enforce the available DID-root binding between the MLS
        // sender credential and the envelope's claimed sender DID. The
        // envelope is a routing hint, not proof. This covers application
        // messages and inbound commit frames (including External-Commit
        // joiners), since both pass through this decrypt path before the
        // empty-plaintext branch below.
        if let Err(binding_error) = self
            .verify_inbound_sender_credential(
                &envelope.conversation_id,
                &envelope.sender_did,
                &decrypt_result.sender_credential.identity,
            )
            .await
        {
            // `decrypt_message` stages incoming commits before returning the
            // sender credential. A rejected credential must not leave that
            // staged commit available for a later envelope to merge.
            if decrypt_result.content_type == crate::DecryptContentType::Commit {
                if let Err(cleanup_error) = self
                    .mls_context()
                    .discard_incoming_commit(group_id_bytes.clone(), decrypt_result.epoch)
                {
                    tracing::error!(
                        error = %cleanup_error,
                        conversation_id = %envelope.conversation_id,
                        target_epoch = decrypt_result.epoch,
                        "Credential rejection cleanup failed for staged incoming commit"
                    );
                    self.mark_needs_rejoin_critical(&envelope.conversation_id)
                        .await;
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "inbound credential rejected and staged commit cleanup failed: {cleanup_error}"
                    )));
                }
            }
            if decrypt_result.content_type == crate::DecryptContentType::Proposal {
                let Some(proposal_ref) = decrypt_result.proposal_ref.clone() else {
                    self.mark_needs_rejoin_critical(&envelope.conversation_id)
                        .await;
                    return Err(OrchestratorError::RecoveryFailed(
                        "rejected MLS proposal omitted its cleanup handle".to_string(),
                    ));
                };
                if let Err(cleanup_error) = self
                    .mls_context()
                    .discard_incoming_proposal(group_id_bytes.clone(), proposal_ref)
                {
                    self.mark_needs_rejoin_critical(&envelope.conversation_id)
                        .await;
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "inbound proposal credential rejected and staged proposal cleanup failed: {cleanup_error}"
                    )));
                }
            }
            return Err(binding_error);
        }

        // DID method-specific identifiers are case-sensitive.  Compare the
        // validated root DIDs exactly; ASCII case-folding can alias two
        // distinct identities and incorrectly classify an attacker's message
        // as our own echo.
        let is_own = super::credential_binding::credential_root_did(&sender_did)
            == super::credential_binding::credential_root_did(&user_did);

        // Proposals are authenticated control frames but do not advance the
        // epoch. The crypto layer has queued them in OpenMLS storage; require a
        // durability barrier before allowing the delivery cursor to advance.
        if matches!(
            decrypt_result.content_type,
            crate::DecryptContentType::Proposal | crate::DecryptContentType::ExternalJoinProposal
        ) {
            if decrypt_result.content_type == crate::DecryptContentType::ExternalJoinProposal {
                return Err(OrchestratorError::InvalidInput(
                    "external join proposals require an explicit authorization path".to_string(),
                ));
            }
            let Some(proposal_ref) = decrypt_result.proposal_ref.clone() else {
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(OrchestratorError::RecoveryFailed(
                    "decrypted MLS proposal omitted its authorization handle".to_string(),
                ));
            };
            self.mls_context()
                .accept_incoming_proposal(group_id_bytes.clone(), proposal_ref)
                .map_err(OrchestratorError::from)?;
            if let Err(error) = self.mls_context().ensure_storage_durable() {
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(OrchestratorError::from(error));
            }
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                epoch = decrypt_result.epoch,
                "Durably queued incoming MLS proposal"
            );
            return Ok(None);
        }

        if decrypt_result.content_type == crate::DecryptContentType::Commit {
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                epoch = decrypt_result.epoch,
                "Processed commit message (epoch staged — merging)"
            );

            // Task #58: `decrypt_message` stages the incoming commit in
            // `pending_incoming_merges` but does NOT merge it into the local
            // MLS group. The orchestrator's HTTP-sync path (this function,
            // reached from `fetch_messages` and `sync_with_server`) must
            // explicitly call `merge_incoming_commit` to advance the local
            // epoch; otherwise subsequent sends/decrypts see stale epoch and
            // trigger cascading 409/WrongEpoch errors.
            //
            // Platforms consuming WebSocket push (iOS) already perform the
            // merge themselves; this closes the gap for orchestrator-driven
            // sync (catmos Tauri, catmos-cli, catbird-mls-web, Android).
            let merged_epoch = match self
                .mls_context()
                .merge_incoming_commit(group_id_bytes.clone(), decrypt_result.epoch)
            {
                Ok(merged_epoch) => {
                    tracing::info!(
                        conversation_id = %envelope.conversation_id,
                        target_epoch = decrypt_result.epoch,
                        merged_epoch,
                        "Merged incoming staged commit"
                    );
                    merged_epoch
                }
                Err(e) => {
                    // Merge failure: the staged commit was popped from
                    // `pending_incoming_merges` by the FFI layer (see
                    // `merge_incoming_commit` in api.rs). The local MLS state
                    // is now behind the commit we just saw on the wire — mark
                    // the conversation for rejoin so the next sync cycle
                    // recovers via the deferred External Commit path.
                    //
                    // NOTE: we do NOT call `discard_incoming_commit` here —
                    // `merge_incoming_commit` already consumed the staged
                    // entry on its way to the failure, and double-discarding
                    // is a no-op anyway.
                    tracing::error!(
                        error = %e,
                        conversation_id = %envelope.conversation_id,
                        target_epoch = decrypt_result.epoch,
                        "Failed to merge incoming staged commit — marking for rejoin"
                    );
                    // WS-5.2: this flag is the sole recovery driver after a
                    // merge failure — escalate a dropped write instead of
                    // warn-and-forget.
                    self.mark_needs_rejoin_critical(&envelope.conversation_id)
                        .await;
                    // Fail this page before cached epoch advancement,
                    // persistence, secret pruning, or cursor return. The DS
                    // can redeliver after recovery has restored a mergeable
                    // state; acknowledging this envelope would create a
                    // durable gap between MLS state and the sync cursor.
                    return Err(OrchestratorError::from(e));
                }
            };

            if merged_epoch != decrypt_result.epoch {
                let error = OrchestratorError::EpochMismatch {
                    local: merged_epoch,
                    remote: decrypt_result.epoch,
                };
                tracing::error!(
                    error = %error,
                    conversation_id = %envelope.conversation_id,
                    target_epoch = decrypt_result.epoch,
                    merged_epoch,
                    "Incoming commit merged to an unexpected epoch — refusing cursor advancement"
                );
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(error);
            }

            if let Err(error) = self.mls_context().ensure_storage_durable() {
                tracing::error!(
                    error = %error,
                    conversation_id = %envelope.conversation_id,
                    merged_epoch,
                    "Failed to make merged MLS state durable — refusing cursor advancement"
                );
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(OrchestratorError::from(error));
            }

            let crypto_epoch = match self.mls_context().get_epoch(group_id_bytes.clone()) {
                Ok(epoch) => epoch,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        conversation_id = %envelope.conversation_id,
                        "Failed to verify durable MLS epoch — refusing cursor advancement"
                    );
                    self.mark_needs_rejoin_critical(&envelope.conversation_id)
                        .await;
                    return Err(OrchestratorError::from(error));
                }
            };
            if crypto_epoch != merged_epoch {
                let error = OrchestratorError::EpochMismatch {
                    local: crypto_epoch,
                    remote: merged_epoch,
                };
                tracing::error!(
                    error = %error,
                    conversation_id = %envelope.conversation_id,
                    merged_epoch,
                    crypto_epoch,
                    "Durable MLS epoch does not match merged epoch — refusing cursor advancement"
                );
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(error);
            }

            if let Err(error) = self
                .persist_inbound_epoch_advance(&resolved, crypto_epoch)
                .await
            {
                tracing::error!(
                    error = %error,
                    conversation_id = %envelope.conversation_id,
                    target_epoch = crypto_epoch,
                    "Failed to durably persist epoch after commit — refusing cursor advancement"
                );
                self.mark_needs_rejoin_critical(&envelope.conversation_id)
                    .await;
                return Err(error);
            }

            // Layer 3: only a fully durable peer commit clears the rolling
            // peer-bad observation buffer or exits quarantine.
            {
                let mut tracker = self.recovery_tracker().lock().await;
                tracker.record_healthy_peer_commit(&envelope.conversation_id);
            }
            if self
                .recovery_tracker()
                .lock()
                .await
                .is_quarantined(&envelope.conversation_id)
            {
                self.exit_quarantine(
                    &envelope.conversation_id,
                    crate::orchestrator::types::QuarantineExitReason::PeerCommitSucceeded,
                )
                .await;
            }

            // Cleanup old epoch secrets after commit advances the epoch
            self.cleanup_epoch_secrets_if_needed(
                &resolved.conversation_id,
                &resolved.group_id,
                crypto_epoch,
            )
            .await;

            // Phase F: legacy plaintext metadata refresh-after-commit removed.
            // Under the cutover, group metadata is encrypted (see metadata.rs)
            // and refreshed on the receive side via the platform-specific
            // bootstrap path (catmos `bootstrap_group_metadata`, catmos-cli
            // equivalent, iOS `MLSConversationManager+Metadata.swift`,
            // Android `MLSGroupMetadataResolver.kt`, web
            // `wasm_bootstrap_group_metadata`). The orchestrator no longer
            // peeks at MLS state for plaintext metadata after commit merge.

            return Ok(None);
        }

        debug_assert_eq!(
            decrypt_result.content_type,
            crate::DecryptContentType::Application
        );

        // Application decrypt consumes secret-tree state even when the decoded
        // payload is non-displayable. Make the crypto state and epoch
        // projection durable before any own-echo/control early return or page
        // cursor can escape this serialized receive section.
        if let Err(error) = self.mls_context().ensure_storage_durable() {
            tracing::error!(
                error = %error,
                conversation_id = %envelope.conversation_id,
                "Failed to make inbound application crypto state durable — refusing cursor advancement"
            );
            self.mark_needs_rejoin_critical(&envelope.conversation_id)
                .await;
            return Err(OrchestratorError::from(error));
        }
        if let Err(error) = self
            .persist_inbound_epoch_advance(&resolved, decrypt_result.epoch)
            .await
        {
            tracing::error!(
                error = %error,
                conversation_id = %envelope.conversation_id,
                target_epoch = decrypt_result.epoch,
                "Failed to durably persist epoch after application message — refusing cursor advancement"
            );
            self.mark_needs_rejoin_critical(&envelope.conversation_id)
                .await;
            return Err(error);
        }

        // A successfully decrypted own-device Application may still be an
        // outbox echo (for example, another local device pipeline). In-memory
        // pending state is only a hint. Skip only when the exact server ID has
        // a durable pending record, and propagate a storage failure rather than
        // acknowledging an unproven echo.
        if is_own {
            if let Some(message_id) = envelope.server_message_id.as_deref() {
                if self.storage().remove_pending_message(message_id).await? {
                    self.pending_messages().lock().await.remove(message_id);
                    tracing::debug!(
                        message_id,
                        "Received own message back from server with durable outbox evidence"
                    );
                    return Ok(None);
                }
            }
        }

        let (plaintext, payload_json) = match MLSMessagePayload::decode(&decrypt_result.plaintext) {
            Ok(payload) => {
                if !payload.is_displayable() {
                    if !(self.store_control_messages() && payload.is_known_control()) {
                        tracing::debug!(
                            conversation_id = %envelope.conversation_id,
                            epoch = decrypt_result.epoch,
                            message_type = ?payload.message_type,
                            "Ignoring non-displayable MLS payload"
                        );
                        return Ok(None);
                    }

                    tracing::debug!(
                        conversation_id = %envelope.conversation_id,
                        epoch = decrypt_result.epoch,
                        message_type = ?payload.message_type,
                        "Storing non-displayable MLS control payload"
                    );
                }

                let display_text = payload.display_text();
                tracing::debug!(
                    conversation_id = %envelope.conversation_id,
                    text_len = display_text.len(),
                    has_image = payload.image_embed().is_some(),
                    "Decoded MLSMessagePayload"
                );

                (
                    display_text,
                    String::from_utf8(decrypt_result.plaintext.clone()).ok(),
                )
            }
            Err(decode_err) => {
                // If the plaintext looks like a JSON envelope that we failed
                // to decode, it is almost certainly a newer `MLSMessagePayload`
                // variant this build doesn't understand (iOS added
                // `deliveryAck` and `recoveryRequest`; future types will
                // follow). Drop it with a warning — NEVER stringify raw JSON
                // into `Message.text`, which is what previously caused
                // Android/Tauri/WASM UIs to render raw
                // `{"messageType":"deliveryAck",...}` blobs.
                let first_non_ws = decrypt_result
                    .plaintext
                    .iter()
                    .find(|b| !b.is_ascii_whitespace())
                    .copied();
                if first_non_ws == Some(b'{') {
                    tracing::warn!(
                        conversation_id = %envelope.conversation_id,
                        epoch = decrypt_result.epoch,
                        len = decrypt_result.plaintext.len(),
                        error = %decode_err,
                        "Dropping MLS message: JSON envelope did not match MLSMessagePayload schema"
                    );
                    return Ok(None);
                }

                // UTF-8 fallback remains ONLY for genuine legacy non-JSON
                // plaintext bytes emitted by older clients.
                let text = String::from_utf8(decrypt_result.plaintext.clone()).map_err(|_| {
                    tracing::error!(
                        conversation_id = %envelope.conversation_id,
                        plaintext_len = decrypt_result.plaintext.len(),
                        "Invalid non-UTF8 MLS message payload"
                    );
                    OrchestratorError::InvalidInput("Invalid message payload".into())
                })?;

                if text.trim().is_empty() {
                    tracing::debug!(
                        conversation_id = %envelope.conversation_id,
                        epoch = decrypt_result.epoch,
                        "Ignoring empty legacy text payload"
                    );
                    return Ok(None);
                }

                (text, None)
            }
        };

        let message_id = envelope
            .server_message_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let message = Message {
            id: message_id,
            conversation_id: envelope.conversation_id.clone(),
            sender_did,
            text: plaintext,
            timestamp: envelope.timestamp,
            epoch: decrypt_result.epoch,
            sequence_number: decrypt_result.sequence_number,
            is_own,
            delivery_status: None,
            payload_json,
        };

        // Store message
        self.storage().store_message(&message).await?;

        Ok(Some(message))
    }

    pub async fn process_incoming_message(
        &self,
        envelope: &IncomingEnvelope,
    ) -> Result<MessageProcessingResult> {
        if let Some(server_epoch) = envelope.server_epoch {
            let local_epoch = self
                .local_group_epoch_result(&envelope.conversation_id)
                .await?
                .unwrap_or(0);
            if server_epoch > local_epoch {
                let from_epoch = Some((local_epoch.saturating_add(1)).min(u32::MAX as u64) as u32);
                let to_epoch = Some(server_epoch.min(u32::MAX as u64) as u32);
                let (fetched_messages, _) = self
                    .fetch_messages(
                        &envelope.conversation_id,
                        None,
                        50,
                        Some("commit"),
                        from_epoch,
                        to_epoch,
                    )
                    .await?;

                if let Some(server_message_id) = envelope.server_message_id.as_deref() {
                    if let Some(message) = fetched_messages
                        .into_iter()
                        .find(|message| message.id == server_message_id)
                    {
                        let events = vec![crate::orchestrator::EngineEvent::MessageInserted {
                            message_id: message.id.clone(),
                            convo_id: message.conversation_id.clone(),
                        }];
                        return Ok(MessageProcessingResult {
                            message: Some(message),
                            events,
                        });
                    }
                }
            }
        }

        let message = self.process_incoming(envelope).await?;
        let events = message
            .as_ref()
            .map(|message| {
                vec![crate::orchestrator::EngineEvent::MessageInserted {
                    message_id: message.id.clone(),
                    convo_id: message.conversation_id.clone(),
                }]
            })
            .unwrap_or_default();
        Ok(MessageProcessingResult { message, events })
    }

    /// Fetch and process new messages from the server for a conversation.
    ///
    /// `message_type` filters the fetch: `Some("commit")` for epoch catch-up,
    /// `None` (all) for normal message polling.
    /// `from_epoch` / `to_epoch` are inclusive bounds (spec: `blue.catbird.chat.getEntries`).
    /// Pass `None` for both when a range isn't known; the server then falls back
    /// to its default window (0..=current_epoch).
    pub async fn fetch_messages(
        &self,
        conversation_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<Message>, Option<String>)> {
        self.check_shutdown().await?;

        let (envelopes, new_cursor) = self
            .api_client()
            .get_messages(
                conversation_id,
                cursor,
                limit,
                message_type,
                from_epoch,
                to_epoch,
            )
            .await?;

        let mut messages = Vec::new();
        for envelope in &envelopes {
            match self.process_incoming(envelope).await {
                Ok(Some(msg)) => messages.push(msg),
                Ok(None) => {} // duplicate or own commit
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        conversation_id,
                        "Failed to process incoming message; refusing page cursor advancement"
                    );
                    return Err(error);
                }
            }
        }

        let changed = self
            .refresh_delivery_statuses(conversation_id, &mut messages)
            .await;
        for idx in changed {
            let msg = &messages[idx];
            if let Err(e) = self.storage().store_message(msg).await {
                tracing::warn!(
                    error = %e,
                    conversation_id,
                    message_id = %msg.id,
                    "Failed to persist refreshed delivery status"
                );
            }
        }

        Ok((messages, new_cursor))
    }

    async fn refresh_delivery_statuses(
        &self,
        conversation_id: &str,
        messages: &mut [Message],
    ) -> Vec<usize> {
        let mut changed = Vec::new();

        let own_message_ids: Vec<String> = messages
            .iter()
            .filter(|m| m.is_own)
            .map(|m| m.id.clone())
            .collect();
        if own_message_ids.is_empty() {
            return changed;
        }

        let mut status_by_id: HashMap<String, DeliveryStatus> = HashMap::new();
        for chunk in own_message_ids.chunks(50) {
            match self
                .api_client()
                .get_delivery_status(conversation_id, chunk)
                .await
            {
                Ok(statuses) => {
                    for (message_id, status) in statuses {
                        status_by_id.insert(message_id, status);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        conversation_id,
                        count = chunk.len(),
                        "Failed to refresh delivery status"
                    );
                }
            }
        }

        for (idx, message) in messages.iter_mut().enumerate() {
            let Some(status) = status_by_id.get(&message.id) else {
                continue;
            };
            if message.delivery_status.as_ref() != Some(status) {
                message.delivery_status = Some(status.clone());
                changed.push(idx);
            }
        }

        changed
    }

    pub(crate) async fn send_message_prepared(
        &self,
        conversation_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        message_id: &str,
    ) -> Result<SendMessageResponse> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use sha2::Sha256;
        let user_did = self.require_user_did().await?;
        let actor_device_id = self.require_actor_device_id().await?;
        let auth_generation = self
            .credentials()
            .get_auth_generation(&user_did)
            .await?
            .ok_or_else(|| OrchestratorError::Credential("missing auth generation".into()))?;
        if auth_generation < 1 {
            return Err(OrchestratorError::Credential(
                "auth_generation must be >= 1".into(),
            ));
        }
        let key_id = {
            let identity_bytes = format!("{user_did}#{actor_device_id}").into_bytes();
            let pk = self.mls_context().identity_public_key(identity_bytes)?;
            super::canonical_transport::derive_key_id(&pk)
        };
        let resolved = self
            .resolve_legacy_group_identifier(conversation_id)
            .await?;
        let convo_id = &resolved.conversation_id;
        let convo_uuid = uuid::Uuid::parse_str(convo_id).map_err(|e| {
            OrchestratorError::InvalidInput(format!("invalid conversation UUID: {e}"))
        })?;
        let msg_uuid = uuid::Uuid::parse_str(message_id)
            .map_err(|e| OrchestratorError::InvalidInput(format!("invalid message UUID: {e}")))?;
        let group_id_bytes = resolved.group_id_bytes()?;
        let confirmation_tag = self
            .mls_context()
            .get_confirmation_tag(group_id_bytes.clone())?;
        if confirmation_tag.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "confirmation tag must be exactly 32 bytes, got {}",
                confirmation_tag.len()
            ))));
        }
        let group_context_hash = self
            .mls_context()
            .get_group_context_hash(group_id_bytes.clone())?;
        if group_context_hash.len() != 32 {
            return Err(OrchestratorError::Mls(MLSError::Internal(format!(
                "group context hash must be exactly 32 bytes, got {}",
                group_context_hash.len()
            ))));
        }
        let state_version = {
            let convos_req = super::canonical_transport::PreparedRequest {
                operation: super::canonical_transport::CanonicalOperation::GetConversations,
                path: format!(
                    "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={}&limit=50",
                    actor_device_id
                ),
                method: "GET".to_string(),
                body: None,
            };
            let convos_val: Option<serde_json::Value> =
                if let Ok(resp) = self.api_client().submit_prepared_request(convos_req).await {
                    serde_json::from_slice(&resp.body).ok()
                } else {
                    None
                };
            convos_val
                .as_ref()
                .and_then(|v| v.get("items").and_then(|i| i.as_array()))
                .and_then(|items| {
                    items.iter().find_map(|item| {
                        let state = item.get("state").unwrap_or(item);
                        let coords = state.get("coordinates")?;
                        let cid = coords.get("conversationId").and_then(|c| c.as_str())?;
                        if cid == convo_id {
                            coords.get("stateVersion").and_then(|sv| sv.as_i64())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(1)
        };
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "aad": {
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": 0,
                "messageId": STANDARD.encode(msg_uuid.as_bytes()),
                "prior": {
                    "confirmationTag": { "$bytes": STANDARD.encode(&confirmation_tag) },
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "epoch": epoch,
                    "generation": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode(&group_context_hash) },
                    "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                    "lifecycle": "active",
                    "stateVersion": state_version
                },
                "protocolVersion": "1"
            },
            "actorDeviceId": actor_device_id,
            "actorDid": user_did,
            "applicationMessage": {
                "bytes": { "$bytes": STANDARD.encode(ciphertext) },
                "contentType": "privateMessageApplication",
                "framing": "mlsMessage",
                "sha256": { "$bytes": STANDARD.encode(Sha256::digest(ciphertext)) }
            },
            "authGeneration": auth_generation,
            "blobBindings": [],
            "keyId": key_id,
            "messageId": message_id,
            "prior": {
                "confirmationTag": { "$bytes": STANDARD.encode(&confirmation_tag) },
                "conversationId": conversation_id,
                "epoch": epoch,
                "generation": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(&group_context_hash) },
                "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
                "lifecycle": "active",
                "stateVersion": state_version
            },
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "signedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        });

        let binding = CleanChatSigningContext {
            actor_did: user_did.clone(),
            device_id: actor_device_id.clone(),
            auth_generation: Some(auth_generation),
        };
        let prepared_request = self
            .prepare_clean_chat_signed_request(
                binding,
                super::canonical_transport::CanonicalOperation::SendMessage,
                serde_json::to_vec(&body)
                    .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let submitted_bytes = prepared_request.body.as_deref().unwrap_or_default();
        let submitted_val: serde_json::Value =
            serde_json::from_slice(submitted_bytes).map_err(|e| {
                OrchestratorError::Serialization(format!("prepared_request serialization: {e}"))
            })?;
        let submitted_body = submitted_val
            .get("signedRequest")
            .and_then(|s| s.get("body"))
            .and_then(|b| b.as_object())
            .ok_or_else(|| {
                OrchestratorError::Serialization(
                    "prepared_request missing signedRequest.body".into(),
                )
            })?
            .clone();
        let accepted_request_sha256: [u8; 32] = sha2::Sha256::digest(submitted_bytes).into();

        let response = self
            .api_client()
            .submit_prepared_request(prepared_request)
            .await?;

        if response.status != 200 {
            if response.status == 409 {
                return Err(OrchestratorError::ServerError {
                    status: 409,
                    body: String::from_utf8_lossy(&response.body).to_string(),
                });
            }
            return Err(OrchestratorError::Api(format!(
                "send_message failed with status {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            )));
        }

        let resp_json: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Serialization(format!("send_message response: {e}")))?;
        let entry = if let Some(e) = resp_json.get("entry") {
            e.as_object().ok_or_else(|| {
                OrchestratorError::Serialization(
                    "send_message response entry must be an object".into(),
                )
            })?
        } else if let Some(obj) = resp_json.as_object() {
            obj
        } else {
            return Err(OrchestratorError::Serialization(
                "send_message response must be an object".into(),
            ));
        };

        let entry_id_str = entry
            .get("entryId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OrchestratorError::Serialization("send_message response missing entryId".into())
            })?;
        let parsed_entry_uuid = uuid::Uuid::parse_str(entry_id_str).map_err(|e| {
            OrchestratorError::Serialization(format!(
                "send_message entryId is not a valid UUID: {e}"
            ))
        })?;
        if parsed_entry_uuid.get_version_num() != 4 {
            return Err(OrchestratorError::Serialization(
                "send_message entryId must be UUIDv4".into(),
            ));
        }

        let seq = entry.get("seq").and_then(|v| v.as_u64()).ok_or_else(|| {
            OrchestratorError::Serialization("send_message response missing seq".into())
        })?;
        if seq == 0 {
            return Err(OrchestratorError::Serialization(
                "send_message response seq must be positive".into(),
            ));
        }

        let signed_request = entry
            .get("signedRequest")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                OrchestratorError::Serialization(
                    "send_message response missing signedRequest".into(),
                )
            })?;
        let resp_body = signed_request
            .get("body")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                OrchestratorError::Serialization(
                    "send_message response signedRequest missing body".into(),
                )
            })?;

        let resp_msg_id = resp_body
            .get("messageId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OrchestratorError::Serialization("signedRequest body missing messageId".into())
            })?;
        if resp_msg_id != message_id {
            return Err(OrchestratorError::Serialization(format!(
                "signedRequest body messageId mismatch: expected {message_id}, got {resp_msg_id}"
            )));
        }

        let resp_prior = resp_body
            .get("prior")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                OrchestratorError::Serialization("signedRequest body missing prior".into())
            })?;
        let resp_prior_convo = resp_prior
            .get("conversationId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OrchestratorError::Serialization(
                    "signedRequest prior missing conversationId".into(),
                )
            })?;
        if resp_prior_convo != conversation_id && resp_prior_convo != convo_id {
            return Err(OrchestratorError::Serialization(
                "signedRequest prior conversationId mismatch".into(),
            ));
        }
        let resp_prior_epoch = resp_prior
            .get("epoch")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                OrchestratorError::Serialization("signedRequest prior missing epoch".into())
            })?;
        if resp_prior_epoch != epoch {
            return Err(OrchestratorError::Serialization(
                "signedRequest prior epoch mismatch".into(),
            ));
        }
        let resp_prior_gen = resp_prior
            .get("generation")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                OrchestratorError::Serialization("signedRequest prior missing generation".into())
            })?;
        if resp_prior_gen != 0 {
            return Err(OrchestratorError::Serialization(
                "signedRequest prior generation mismatch".into(),
            ));
        }

        let submitted_aad = submitted_body
            .get("aad")
            .ok_or_else(|| OrchestratorError::Serialization("submitted body missing aad".into()))?;
        let resp_aad = resp_body.get("aad").ok_or_else(|| {
            OrchestratorError::Serialization("signedRequest body missing aad".into())
        })?;
        if submitted_aad != resp_aad {
            return Err(OrchestratorError::Serialization(
                "signedRequest body aad mismatch".into(),
            ));
        }

        let submitted_app_msg = submitted_body.get("applicationMessage").ok_or_else(|| {
            OrchestratorError::Serialization("submitted body missing applicationMessage".into())
        })?;
        let resp_app_msg = resp_body.get("applicationMessage").ok_or_else(|| {
            OrchestratorError::Serialization("signedRequest body missing applicationMessage".into())
        })?;
        if submitted_app_msg != resp_app_msg {
            return Err(OrchestratorError::Serialization(
                "signedRequest body applicationMessage mismatch".into(),
            ));
        }

        let aad_sha256: [u8; 32] = sha2::Sha256::digest(b"").into();
        let ciphertext_sha256: [u8; 32] = sha2::Sha256::digest(ciphertext).into();
        let proof = OwnEchoProof::new(
            accepted_request_sha256,
            resolved.conversation_id.clone(),
            group_id_bytes,
            entry_id_str.to_string(),
            epoch,
            aad_sha256,
            ciphertext_sha256,
        );
        self.mls_context().store_own_echo_proof(&proof)?;

        Ok(SendMessageResponse {
            message_id: entry_id_str.to_string(),
            seq,
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_only_page_follows_continuation_cursor() {
        let mut seen = HashSet::new();
        assert_eq!(
            next_send_sync_cursor(None, Some("page-2".to_string()), &mut seen)
                .expect("new cursor must be followed"),
            SendSyncCursorProgress::Continue("page-2".to_string())
        );
    }

    #[test]
    fn send_sync_rejects_immediately_repeated_cursor() {
        let mut seen = HashSet::from(["page-2".to_string()]);
        let error = next_send_sync_cursor(Some("page-2"), Some("page-2".to_string()), &mut seen)
            .expect_err("a stuck delivery-service cursor must fail closed");
        assert!(error.to_string().contains("repeated cursor"));
    }

    #[test]
    fn send_sync_rejects_cursor_cycle() {
        let mut seen = HashSet::from(["page-2".to_string(), "page-3".to_string()]);
        let error = next_send_sync_cursor(Some("page-3"), Some("page-2".to_string()), &mut seen)
            .expect_err("a delivery-service cursor cycle must fail closed");
        assert!(error.to_string().contains("repeated cursor"));
    }

    #[test]
    fn send_sync_rejects_empty_continuation_cursor() {
        let mut seen = HashSet::new();
        let error = next_send_sync_cursor(None, Some(String::new()), &mut seen)
            .expect_err("an empty delivery-service cursor must fail closed");
        assert!(error.to_string().contains("empty cursor"));
    }
}
