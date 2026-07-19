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
//!    merges the pending commit, durably projects the resulting `GroupState`,
//!    then runs explicit epoch-secret cleanup and removes the handle from the
//!    pending map.
//! 3. `discard_pending` — clears the pending commit via
//!    `MlsCryptoContext::clear_pending_commit`, removes the handle from the
//!    pending map, and leaves the local epoch untouched.
//!
//! Existing atomic methods (`add_members` / `remove_members` /
//! `swap_members` / `update_group_metadata`) continue to work — they are
//! refactored in `groups.rs` to thin wrappers around this API so platforms
//! can migrate incrementally.

use sha2::{Digest, Sha256};

use super::orchestrator::OwnCommitExpectation;

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
    /// Validate staged Add/Swap packages before handing any bytes to OpenMLS.
    ///
    /// Authorized-device resolution is mandatory. Unsupported resolution,
    /// resolver infrastructure errors, and key mismatches all fail before a
    /// pending MLS commit or own-commit tracking entry is created.
    async fn enforce_staged_resolved_device_keys(
        &self,
        key_packages: &[crate::KeyPackageData],
    ) -> Result<()> {
        use super::credential_binding::{
            credential_root_did, extract_key_package_binding, DeviceKeyLookup,
        };

        for (index, key_package) in key_packages.iter().enumerate() {
            let binding = extract_key_package_binding(&key_package.data).map_err(|reason| {
                OrchestratorError::InvalidInput(format!(
                    "staged outbound key package {index} has an unverifiable credential: {reason}"
                ))
            })?;
            let root_did = credential_root_did(&binding.identity);
            match self.lookup_authorized_device_keys(root_did).await? {
                DeviceKeyLookup::Unsupported => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "staged outbound key package {index} cannot be authorized because device-key resolution is unsupported for {root_did}"
                    )));
                }
                DeviceKeyLookup::Keys(keys)
                    if keys
                        .iter()
                        .any(|key| key.as_slice() == binding.signature_key.as_slice()) => {}
                DeviceKeyLookup::Keys(_) => {
                    return Err(OrchestratorError::InvalidInput(format!(
                        "staged outbound key package {index} is not signed by an authorized device key for {root_did}"
                    )));
                }
            }
        }

        Ok(())
    }

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
        // Apply byte ceilings before credential extraction invokes a TLS
        // parser. Bind the entire caller-supplied DID batch before resolving
        // any DID so an attacker-controlled credential root cannot enter the
        // resolver cache when the delivery service substitutes a package.
        match &kind {
            CommitKind::AddMembers {
                member_dids,
                key_packages,
            } => {
                crate::message_limits::validate_outbound_key_package_data_batch(key_packages)?;
                super::credential_binding::enforce_outbound_key_package_did_bindings(
                    member_dids,
                    key_packages,
                )?;
            }
            CommitKind::SwapMembers {
                add_dids,
                add_key_packages,
                ..
            } => {
                crate::message_limits::validate_outbound_key_package_data_batch(add_key_packages)?;
                super::credential_binding::enforce_outbound_key_package_did_bindings(
                    add_dids,
                    add_key_packages,
                )?;
            }
            CommitKind::RemoveMembers { .. } | CommitKind::UpdateMetadata { .. } => {}
        }

        let resolved = self.resolve_conversation_context(conversation_id).await?;

        // Enforce the same device-key authority for every public route,
        // including legacy callers that still pass a mutable group ID.
        match &kind {
            CommitKind::AddMembers { key_packages, .. } => {
                self.enforce_staged_resolved_device_keys(key_packages)
                    .await?;
            }
            CommitKind::SwapMembers {
                add_key_packages, ..
            } => {
                self.enforce_staged_resolved_device_keys(add_key_packages)
                    .await?;
            }
            CommitKind::RemoveMembers { .. } | CommitKind::UpdateMetadata { .. } => {}
        }
        self.stage_commit_for_group(&resolved.conversation_id, &resolved.group_id, kind)
            .await
    }

    pub(crate) async fn stage_commit_for_group(
        &self,
        conversation_id: &str,
        group_id: &str,
        kind: CommitKind,
    ) -> Result<CommitPlan> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        let group_id_bytes = hex::decode(group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Guard: OpenMLS allows at most one pending commit per group. If we
        // already have one tracked, refuse to stage another until the caller
        // confirms or discards the existing one.
        {
            let pending = self.pending_staged_commits().lock().await;
            if pending.contains_key(group_id) {
                return Err(OrchestratorError::InvalidInput(format!(
                    "A staged commit already exists for conversation {}; confirm or discard it before staging another",
                    conversation_id
                )));
            }
        }

        let source_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;

        // Internal wrapper paths call `stage_commit_for_group` directly, so
        // repeat the pre-parse byte gate here rather than relying on the public
        // resolver-aware entry point above.
        match &kind {
            CommitKind::AddMembers { key_packages, .. } => {
                crate::message_limits::validate_outbound_key_package_data_batch(key_packages)?;
            }
            CommitKind::SwapMembers {
                add_key_packages, ..
            } => {
                crate::message_limits::validate_outbound_key_package_data_batch(add_key_packages)?;
            }
            CommitKind::RemoveMembers { .. } | CommitKind::UpdateMetadata { .. } => {}
        }

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
                if member_dids.is_empty() {
                    return Err(OrchestratorError::InvalidInput(
                        "AddMembers requires non-empty DID authority".to_string(),
                    ));
                }
                super::credential_binding::enforce_outbound_key_package_did_bindings(
                    &member_dids,
                    &key_packages,
                )?;
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
                super::credential_binding::enforce_outbound_key_package_did_bindings(
                    &add_dids,
                    &add_key_packages,
                )?;
                let remove_ids: Vec<Vec<u8>> =
                    remove_dids.iter().map(|d| d.as_bytes().to_vec()).collect();
                let (commit_bytes, welcome_bytes) = if add_dids.is_empty() {
                    // OpenMLS rejects swap_members with an empty add batch.
                    // Preserve the public pure-removal Swap operation by
                    // staging the equivalent removal commit instead.
                    (
                        self.mls_context()
                            .remove_members(group_id_bytes.clone(), remove_ids)?,
                        None,
                    )
                } else {
                    let swap_result = self.mls_context().swap_members(
                        group_id_bytes.clone(),
                        remove_ids,
                        add_key_packages,
                    )?;
                    (swap_result.commit_data, Some(swap_result.welcome_data))
                };
                (
                    commit_bytes,
                    welcome_bytes,
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

        // Export GroupInfo from the *pre-merge* group state. OpenMLS will
        // happily re-export after merge; we still publish the post-merge
        // version in `confirm_commit`, but platforms that batch operations
        // may want to ship this pre-merge blob alongside the commit.
        let group_info = match self
            .mls_context()
            .export_group_info(group_id_bytes.clone(), user_did.as_bytes().to_vec())
        {
            Ok(group_info) => group_info,
            Err(primary_error) => {
                if let Err(cleanup_error) = self
                    .mls_context()
                    .clear_pending_commit(group_id_bytes.clone())
                {
                    self.mark_needs_rejoin_critical(conversation_id).await;
                    return Err(OrchestratorError::RecoveryFailed(format!(
                        "recovery-critical staged GroupInfo export failure ({primary_error}); pending commit cleanup also failed for group {group_id}: {cleanup_error}"
                    )));
                }
                return Err(primary_error.into());
            }
        };

        let nonce = self.next_staged_commit_nonce().await;
        let target_epoch = source_epoch.saturating_add(1);

        // Track epoch-changing self echoes with the durable proof they must
        // satisfy. A hash match alone is insufficient: a dropped server
        // response can leave the DS ahead while local confirmation never
        // reached the stable GroupState commit point.
        let hash = Sha256::digest(&commit_bytes).to_vec();
        self.track_epoch_changing_own_commit(
            hash,
            OwnCommitExpectation {
                conversation_id: conversation_id.to_string(),
                group_id: group_id.to_string(),
                target_epoch,
            },
        )
        .await;

        self.pending_staged_commits().lock().await.insert(
            group_id.to_string(),
            PendingCommitMeta {
                conversation_id: conversation_id.to_string(),
                nonce,
                source_epoch,
                target_epoch,
                kind: kind_summary,
            },
        );

        tracing::debug!(
            conversation_id,
            group_id,
            nonce,
            source_epoch,
            target_epoch,
            "Staged commit"
        );

        Ok(CommitPlan {
            handle: StagedCommitHandle {
                group_id: group_id.to_string(),
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
    /// epoch, durably project the resulting group state, update the in-memory
    /// cache, run epoch-secret cleanup, and remove the handle from the pending
    /// map.
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

        // Complete every fallible prerequisite that does not depend on the
        // pending metadata before consuming the nonce-bearing handle. A
        // concurrent lifecycle transition or malformed group id must leave
        // the caller able to confirm or discard the same staged commit.
        let user_did = self.require_user_did().await?;
        let group_id_bytes = hex::decode(&handle.group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

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
                    conversation_id = %meta.conversation_id,
                    group_id = %handle.group_id,
                    target_epoch = meta.target_epoch,
                    "CRITICAL: merge_pending_commit failed during confirm_commit"
                );
                if let Err(clear_err) = self
                    .mls_context()
                    .clear_pending_commit(group_id_bytes.clone())
                {
                    tracing::warn!(
                        error = %clear_err,
                        conversation_id = %meta.conversation_id,
                        group_id = %handle.group_id,
                        "Failed to clear stale pending commit after merge failure in confirm_commit"
                    );
                }
                // WS-5.2: same recovery-critical pattern as the messaging
                // merge-failure path — the persisted flag is what routes this
                // conversation into deferred recovery, so escalate a dropped
                // write instead of warn-and-forget.
                self.mark_needs_rejoin_critical(&meta.conversation_id).await;
                return Err(e.into());
            }
        };
        if new_epoch != meta.target_epoch {
            tracing::error!(
                conversation_id = %meta.conversation_id,
                group_id = %handle.group_id,
                expected_epoch = meta.target_epoch,
                observed_epoch = new_epoch,
                "Confirmed commit did not land at its staged target epoch"
            );
            self.mark_needs_rejoin_critical(&meta.conversation_id).await;
            return Err(OrchestratorError::EpochMismatch {
                local: new_epoch,
                remote: meta.target_epoch,
            });
        }

        // Build the post-merge projection without publishing it to the
        // authoritative in-memory cache. The OpenMLS merge is already durable
        // at this point, but returning success while this write fails would
        // let callers observe/ack an epoch that restart recovery cannot map.
        let cached_state = {
            let states = self.group_states().lock().await;
            let resolved = ResolvedConversationContext {
                conversation_id: meta.conversation_id.clone(),
                group_id: handle.group_id.clone(),
            };
            resolved.group_state(&states).cloned()
        };
        let existing_state = match cached_state {
            Some(state) => Some(state),
            None => self.storage().get_group_state(&handle.group_id).await?,
        };
        let Some(mut state_clone) = existing_state else {
            let error = OrchestratorError::Storage(format!(
                "Missing GroupState projection after confirmed commit for conversation {} (group {})",
                meta.conversation_id, handle.group_id
            ));
            self.mark_needs_rejoin_critical(&meta.conversation_id).await;
            return Err(error);
        };
        if state_clone.group_id != handle.group_id {
            let error = OrchestratorError::Storage(format!(
                "Mismatched GroupState projection after confirmed commit for conversation {} (group {})",
                meta.conversation_id, handle.group_id
            ));
            self.mark_needs_rejoin_critical(&meta.conversation_id).await;
            return Err(error);
        }
        // A stable conversation id can legitimately diverge from the mutable
        // group id after reset. `stage_commit` already resolved and recorded
        // that stable id in `meta`; canonicalize an older group-keyed durable
        // projection before writing the post-merge state.
        state_clone.conversation_id = meta.conversation_id.clone();

        state_clone.epoch = new_epoch;
        match &meta.kind {
            StagedCommitKindSummary::AddMembers { member_dids } => {
                for did in member_dids {
                    if !state_clone.members.contains(did) {
                        state_clone.members.push(did.clone());
                    }
                }
            }
            StagedCommitKindSummary::RemoveMembers { member_dids } => {
                state_clone.members.retain(|m| !member_dids.contains(m));
            }
            StagedCommitKindSummary::SwapMembers {
                remove_dids,
                add_dids,
            } => {
                state_clone.members.retain(|m| !remove_dids.contains(m));
                for did in add_dids {
                    if !state_clone.members.contains(did) {
                        state_clone.members.push(did.clone());
                    }
                }
            }
            StagedCommitKindSummary::UpdateMetadata => {
                // Membership unchanged.
            }
        }

        if let Err(e) = self.storage().set_group_state(&state_clone).await {
            tracing::error!(
                error = %e,
                conversation_id = %meta.conversation_id,
                group_id = %handle.group_id,
                new_epoch,
                "Failed to persist group state after confirm_commit; withholding success"
            );
            self.mark_needs_rejoin_critical(&meta.conversation_id).await;
            return Err(e);
        }

        {
            let mut states = self.group_states().lock().await;
            normalize_group_state(&mut states, state_clone);
        }

        // Epoch-secret retention (spec §10) runs only after both the crypto
        // state and its stable-conversation projection are durable.
        self.cleanup_epoch_secrets_if_needed(&meta.conversation_id, &handle.group_id, new_epoch)
            .await;

        // Publish updated GroupInfo (best-effort).
        match self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())
        {
            Ok(group_info) => {
                if let Err(e) = self
                    .api_client()
                    .publish_group_info(&meta.conversation_id, &group_info)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        conversation_id = %meta.conversation_id,
                        group_id = %handle.group_id,
                        "Failed to publish GroupInfo after confirm_commit"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    conversation_id = %meta.conversation_id,
                    group_id = %handle.group_id,
                    "Failed to export GroupInfo after confirm_commit"
                );
            }
        }

        tracing::debug!(
            conversation_id = %meta.conversation_id,
            group_id = %handle.group_id,
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

        let group_id_bytes = hex::decode(&handle.group_id).map_err(|error| {
            OrchestratorError::InvalidInput(format!(
                "Invalid staged-commit group id {}: {error}",
                handle.group_id
            ))
        })?;

        let removed = {
            let mut pending = self.pending_staged_commits().lock().await;
            match pending.get(&handle.group_id) {
                Some(existing) if existing.nonce == handle.nonce => {
                    // Keep the handle authoritative until the crypto pending
                    // state is actually cleared. Returning success after a
                    // clear failure strands OpenMLS in a pending-commit state
                    // while making retry impossible.
                    self.mls_context()
                        .clear_pending_commit(group_id_bytes)
                        .map_err(OrchestratorError::from)?;
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

        tracing::debug!(
            conversation_id = %handle.group_id,
            nonce = handle.nonce,
            source_epoch = removed.as_ref().map(|m| m.source_epoch).unwrap_or(0),
            "Discarded staged commit"
        );

        Ok(())
    }

    /// Discard a wrapper-owned staged commit after the surrounding server
    /// operation failed or was an idempotent no-op. Legacy wrappers do not
    /// return the nonce-bearing handle to their caller, so swallowing a
    /// cleanup failure would make the retained pending commit inaccessible.
    /// Escalate such failures into durable recovery and return a composite
    /// error; callers may return their original error only after this succeeds.
    pub(crate) async fn discard_pending_after_failed_operation(
        &self,
        handle: StagedCommitHandle,
        operation: &str,
        primary_failure: &str,
    ) -> Result<()> {
        let conversation_id = {
            let pending = self.pending_staged_commits().lock().await;
            pending
                .get(&handle.group_id)
                .filter(|meta| meta.nonce == handle.nonce)
                .map(|meta| meta.conversation_id.clone())
        };

        if let Err(cleanup_error) = self.discard_pending(handle.clone()).await {
            if let Some(conversation_id) = conversation_id.as_deref() {
                self.mark_needs_rejoin_critical(conversation_id).await;
            }
            return Err(OrchestratorError::RecoveryFailed(format!(
                "{operation} failed ({primary_failure}); pending commit cleanup also failed for group {}: {cleanup_error}",
                handle.group_id
            )));
        }
        Ok(())
    }
}
