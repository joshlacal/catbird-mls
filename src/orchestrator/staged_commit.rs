//! Sender-side three-phase commit API (task #44).
//!
//! Receiver-side stage/confirm/discard already shipped in task #33
//! (`merge_incoming_commit` / `discard_incoming_commit`). This module adds the
//! symmetric sender-side surface:
//!
//! 1. `stage_commit` — constructs a pending commit via `MlsCryptoContext`,
//!    stores it in a per-orchestrator map, and returns a plan the platform
//!    can ship to the delivery service. Does NOT call the server and does
//!    NOT advance the local epoch.
//! 2. `confirm_commit` — given the handle returned by `stage_commit` (and
//!    optionally a `server_epoch` echoed back by the DS for fencing),
//!    merges the pending commit, runs `cleanup_old_epochs`, updates the
//!    in-memory group state, and removes the handle from the pending map.
//! 3. `discard_pending` — clears the pending commit via
//!    `MlsCryptoContext::clear_pending_commit`, removes the handle from the
//!    pending map, and leaves the local epoch untouched.
//!
//! Existing atomic methods (`add_members` / `remove_members` /
//! `swap_members` / `update_group_metadata`) continue to work — they are
//! refactored in `groups.rs` to thin wrappers around this API so platforms
//! can migrate incrementally.

use sha2::{Digest, Sha256};
use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::orchestrator::{MLSOrchestrator, PendingCommitMeta, StagedCommitKindSummary};
use super::storage::MLSStorageBackend;
use super::types::*;

/// Sentinel passed by wrappers (and platforms) that don't have a meaningful
/// server epoch to fence against — e.g. `api_client.remove_members` returns
/// `()` and `commit_group_change` (used by `update_group_metadata`) also
/// doesn't echo an epoch. `confirm_commit` skips the fence when
/// `server_epoch == SKIP_SERVER_EPOCH_FENCE`.
pub const SKIP_SERVER_EPOCH_FENCE: u64 = 0;

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Stage a commit without sending it to the delivery service or merging
    /// it locally. Returns a [`CommitPlan`] that the caller ships to the DS;
    /// the caller then passes the embedded handle back to
    /// [`confirm_commit`](Self::confirm_commit) on success or
    /// [`discard_pending`](Self::discard_pending) on failure.
    ///
    /// Only one pending commit may exist per group at a time (OpenMLS
    /// constraint). Staging a second commit while one is already pending
    /// returns [`OrchestratorError::InvalidInput`].
    pub async fn stage_commit(
        &self,
        conversation_id: &str,
        kind: CommitKind,
    ) -> Result<CommitPlan> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        let group_id_bytes = hex::decode(conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Guard: OpenMLS allows at most one pending commit per group. If we
        // already have one tracked, refuse to stage another until the caller
        // confirms or discards the existing one.
        {
            let pending = self.pending_staged_commits().lock().await;
            if pending.contains_key(conversation_id) {
                return Err(OrchestratorError::InvalidInput(format!(
                    "A staged commit already exists for conversation {}; confirm or discard it before staging another",
                    conversation_id
                )));
            }
        }

        let source_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;

        // Construct the pending commit via MlsCryptoContext. Each branch
        // mirrors the corresponding atomic method in `groups.rs` exactly —
        // we intentionally DO NOT call the server, merge the commit, or
        // update any in-memory state here. All of that happens in
        // `confirm_commit`.
        let (commit_bytes, welcome_bytes, kind_summary) = match kind {
            CommitKind::AddMembers {
                member_dids,
                key_packages,
            } => {
                let add_result = self
                    .mls_context()
                    .add_members(group_id_bytes.clone(), key_packages)?;
                (
                    add_result.commit_data,
                    Some(add_result.welcome_data),
                    StagedCommitKindSummary::AddMembers { member_dids },
                )
            }
            CommitKind::RemoveMembers { member_dids } => {
                let member_identities: Vec<Vec<u8>> = member_dids
                    .iter()
                    .map(|did| did.as_bytes().to_vec())
                    .collect();
                let commit_bytes = self
                    .mls_context()
                    .remove_members(group_id_bytes.clone(), member_identities)?;
                (
                    commit_bytes,
                    None,
                    StagedCommitKindSummary::RemoveMembers { member_dids },
                )
            }
            CommitKind::SwapMembers {
                remove_dids,
                add_dids,
                add_key_packages,
            } => {
                let remove_ids: Vec<Vec<u8>> =
                    remove_dids.iter().map(|d| d.as_bytes().to_vec()).collect();
                let swap_result = self.mls_context().swap_members(
                    group_id_bytes.clone(),
                    remove_ids,
                    add_key_packages,
                )?;
                // Welcome is only meaningful when new members are being
                // added; for a pure remove-and-shrink swap the Welcome will
                // still be present but empty of key package references — we
                // still forward it so the DS sees a consistent payload.
                (
                    swap_result.commit_data,
                    Some(swap_result.welcome_data),
                    StagedCommitKindSummary::SwapMembers {
                        remove_dids,
                        add_dids,
                    },
                )
            }
            CommitKind::UpdateMetadata {
                group_info_extension,
            } => {
                let commit_bytes = self
                    .mls_context()
                    .update_group_metadata(group_id_bytes.clone(), group_info_extension)?;
                (commit_bytes, None, StagedCommitKindSummary::UpdateMetadata)
            }
        };

        // Track own commit hash for self-echo dedup on the receive path.
        {
            self.evict_stale_commits().await;
            let hash = Sha256::digest(&commit_bytes);
            self.own_commits()
                .lock()
                .await
                .insert(hash.to_vec(), Instant::now());
        }

        // Export GroupInfo from the *pre-merge* group state. OpenMLS will
        // happily re-export after merge; we still publish the post-merge
        // version in `confirm_commit`, but platforms that batch operations
        // may want to ship this pre-merge blob alongside the commit.
        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes.clone(), user_did.as_bytes().to_vec())?;

        let nonce = self.next_staged_commit_nonce().await;
        let target_epoch = source_epoch.saturating_add(1);

        self.pending_staged_commits().lock().await.insert(
            conversation_id.to_string(),
            PendingCommitMeta {
                nonce,
                source_epoch,
                target_epoch,
                kind: kind_summary,
            },
        );

        tracing::debug!(
            conversation_id,
            nonce,
            source_epoch,
            target_epoch,
            "Staged commit"
        );

        Ok(CommitPlan {
            handle: StagedCommitHandle {
                group_id: conversation_id.to_string(),
                nonce,
            },
            commit_bytes,
            welcome_bytes,
            group_info,
            source_epoch,
            target_epoch,
        })
    }

    /// Confirm a previously staged commit: merge it locally, advance the
    /// epoch, run epoch-secret cleanup, update the in-memory group state,
    /// and remove the handle from the pending map.
    ///
    /// `server_epoch` is used to fence against confirm calls that reference
    /// a different epoch than the one the DS actually accepted. Pass
    /// [`SKIP_SERVER_EPOCH_FENCE`] for API paths that don't return an epoch
    /// (remove_members, commit_group_change). Non-sentinel values must match
    /// `plan.target_epoch`.
    pub async fn confirm_commit(
        &self,
        handle: StagedCommitHandle,
        server_epoch: u64,
    ) -> Result<ConfirmedCommit> {
        self.check_shutdown().await?;

        // Validate and pop the pending entry atomically to prevent a second
        // `confirm_commit` (or concurrent `discard_pending`) from operating
        // on the same handle.
        let meta = {
            let mut pending = self.pending_staged_commits().lock().await;
            match pending.get(&handle.group_id) {
                Some(existing) if existing.nonce == handle.nonce => {
                    // Match — remove it now.
                    pending.remove(&handle.group_id).expect("just matched")
                }
                Some(_) => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "Staged commit handle nonce mismatch for conversation {} (already confirmed or superseded)",
                        handle.group_id
                    )));
                }
                None => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "No staged commit found for conversation {} (already confirmed or discarded)",
                        handle.group_id
                    )));
                }
            }
        };

        // Server epoch fence. Skipped for API paths that don't echo an
        // epoch (see module doc on `SKIP_SERVER_EPOCH_FENCE`). The DS
        // always advances by +1 per accepted commit, so a non-matching echo
        // here means the server saw a different commit or skipped ours
        // entirely — we must not merge locally.
        if server_epoch != SKIP_SERVER_EPOCH_FENCE && server_epoch != meta.target_epoch {
            // Re-insert the handle so a retry (`discard_pending`) still
            // finds it. We can't merge either way, so the caller has to
            // explicitly discard.
            self.pending_staged_commits()
                .lock()
                .await
                .insert(handle.group_id.clone(), meta.clone());
            return Err(OrchestratorError::EpochMismatch {
                local: meta.target_epoch,
                remote: server_epoch,
            });
        }

        let user_did = self.require_user_did().await?;
        let group_id_bytes = hex::decode(&handle.group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Merge the pending commit. If this fails the local state is behind
        // the server — we clear the stale pending commit so future sends
        // don't hit OpenMLS's "pending commit exists" assertion, mark the
        // conversation for rejoin, and surface the error.
        let new_epoch = match self
            .mls_context()
            .merge_pending_commit(group_id_bytes.clone())
        {
            Ok(epoch) => epoch,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    conversation_id = %handle.group_id,
                    target_epoch = meta.target_epoch,
                    "CRITICAL: merge_pending_commit failed during confirm_commit"
                );
                if let Err(clear_err) = self
                    .mls_context()
                    .clear_pending_commit(group_id_bytes.clone())
                {
                    tracing::warn!(
                        error = %clear_err,
                        conversation_id = %handle.group_id,
                        "Failed to clear stale pending commit after merge failure in confirm_commit"
                    );
                }
                if let Err(storage_err) = self.storage().mark_needs_rejoin(&handle.group_id).await {
                    tracing::warn!(
                        error = %storage_err,
                        conversation_id = %handle.group_id,
                        "Failed to mark group for rejoin after confirm_commit failure"
                    );
                }
                return Err(e.into());
            }
        };

        // Epoch-secret retention (spec §10).
        self.cleanup_epoch_secrets_if_needed(&handle.group_id, new_epoch)
            .await;

        // Update in-memory group state based on which kind of commit this
        // was. Best-effort: failure to persist is logged but doesn't poison
        // the confirm (the merge already succeeded).
        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(&handle.group_id) {
                gs.epoch = new_epoch;
                match &meta.kind {
                    StagedCommitKindSummary::AddMembers { member_dids } => {
                        for did in member_dids {
                            if !gs.members.contains(did) {
                                gs.members.push(did.clone());
                            }
                        }
                    }
                    StagedCommitKindSummary::RemoveMembers { member_dids } => {
                        gs.members.retain(|m| !member_dids.contains(m));
                    }
                    StagedCommitKindSummary::SwapMembers {
                        remove_dids,
                        add_dids,
                    } => {
                        gs.members.retain(|m| !remove_dids.contains(m));
                        for did in add_dids {
                            if !gs.members.contains(did) {
                                gs.members.push(did.clone());
                            }
                        }
                    }
                    StagedCommitKindSummary::UpdateMetadata => {
                        // Membership unchanged.
                    }
                }
                let state_clone = gs.clone();
                drop(states);
                if let Err(e) = self.storage().set_group_state(&state_clone).await {
                    tracing::warn!(
                        error = %e,
                        conversation_id = %handle.group_id,
                        "Failed to persist group state after confirm_commit"
                    );
                }
            }
        }

        // Publish updated GroupInfo (best-effort).
        match self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())
        {
            Ok(group_info) => {
                if let Err(e) = self
                    .api_client()
                    .publish_group_info(&handle.group_id, &group_info)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        conversation_id = %handle.group_id,
                        "Failed to publish GroupInfo after confirm_commit"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    conversation_id = %handle.group_id,
                    "Failed to export GroupInfo after confirm_commit"
                );
            }
        }

        tracing::debug!(
            conversation_id = %handle.group_id,
            new_epoch,
            "Confirmed staged commit"
        );

        Ok(ConfirmedCommit {
            new_epoch,
            // Metadata key / reference plumbing is reserved for a future
            // trait extension; see `ConfirmedCommit` doc.
            metadata_key: None,
            metadata_reference: None,
        })
    }

    /// Discard a previously staged commit without advancing the epoch. Clears
    /// the pending commit in the MLS crypto context (so future sends don't
    /// hit OpenMLS's "pending commit exists" assertion) and removes the
    /// handle from the pending map.
    ///
    /// Calling `discard_pending` on an unknown handle returns an error so
    /// the caller notices a logic mistake; calling it twice on the same
    /// handle returns `InvalidInput` for the second call.
    pub async fn discard_pending(&self, handle: StagedCommitHandle) -> Result<()> {
        // No `check_shutdown` here: platforms may need to discard during
        // shutdown to keep MLS state clean. Discarding after shutdown is
        // safe since we're only clearing in-memory + MLS-layer state.

        let removed = {
            let mut pending = self.pending_staged_commits().lock().await;
            match pending.get(&handle.group_id) {
                Some(existing) if existing.nonce == handle.nonce => {
                    pending.remove(&handle.group_id)
                }
                Some(_) => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "Staged commit handle nonce mismatch for conversation {} (already discarded or confirmed)",
                        handle.group_id
                    )));
                }
                None => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "No staged commit found for conversation {} (already discarded or confirmed)",
                        handle.group_id
                    )));
                }
            }
        };

        // Tell MLS to forget the pending commit so future operations can
        // construct new ones. If hex-decode or the crypto layer fails we
        // still consider the discard "succeeded" from the caller's
        // perspective — the handle is gone from the pending map.
        if let Ok(group_id_bytes) = hex::decode(&handle.group_id) {
            if let Err(e) = self.mls_context().clear_pending_commit(group_id_bytes) {
                tracing::warn!(
                    error = %e,
                    conversation_id = %handle.group_id,
                    "clear_pending_commit failed during discard_pending"
                );
            }
        }

        tracing::debug!(
            conversation_id = %handle.group_id,
            nonce = handle.nonce,
            source_epoch = removed.as_ref().map(|m| m.source_epoch).unwrap_or(0),
            "Discarded staged commit"
        );

        Ok(())
    }
}
