use sha2::{Digest, Sha256};
use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
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
    /// Create a new MLS group/conversation.
    ///
    /// 1. Creates MLS group locally via FFI
    /// 2. Creates conversation on server (with optional initial members)
    /// 3. Merges pending commit if members were added
    /// 4. Publishes GroupInfo for external joins
    pub async fn create_group(
        &self,
        name: &str,
        initial_members: Option<&[String]>,
        description: Option<&str>,
    ) -> Result<ConversationView> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!(name, member_count = ?initial_members.map(|m| m.len()), "Creating MLS group");

        // Filter out creator's DID from initial members
        let filtered_members: Option<Vec<String>> = initial_members.map(|members| {
            let self_did = user_did.to_lowercase();
            members
                .iter()
                .filter(|m| m.to_lowercase() != self_did)
                .cloned()
                .collect()
        });
        let filtered_members_ref = filtered_members.as_deref();

        // Create MLS group locally — with encrypted metadata in group context
        let identity_bytes = user_did.as_bytes().to_vec();
        let mut group_config = self.config().group_config.clone();
        if !name.is_empty() {
            group_config.group_name = Some(name.to_string());
        }
        if let Some(desc) = description {
            group_config.group_description = Some(desc.to_string());
        }
        let creation_result = self
            .mls_context()
            .create_group(identity_bytes, Some(group_config))?;
        let group_id_hex = hex::encode(&creation_result.group_id);

        tracing::info!(group_id = %group_id_hex, "Local MLS group created");

        // Protect from background sync deletion
        self.groups_being_created()
            .lock()
            .await
            .insert(group_id_hex.clone());

        // Create local conversation record
        let create_result = self
            .create_group_inner(&user_did, &group_id_hex, filtered_members_ref)
            .await;

        // On any failure, clean up the local MLS group and remove from being-created set
        if create_result.is_err() {
            tracing::warn!(group_id = %group_id_hex, "Cleaning up local MLS group after create_group failure");
            self.force_delete_local(&group_id_hex).await;
            self.groups_being_created()
                .lock()
                .await
                .remove(&group_id_hex);
            return create_result;
        }

        create_result
    }

    /// Inner implementation of create_group, separated so the outer method can
    /// handle rollback on any error path.
    async fn create_group_inner(
        &self,
        user_did: &str,
        group_id_hex: &str,
        filtered_members_ref: Option<&[String]>,
    ) -> Result<ConversationView> {
        let group_id_bytes = hex::decode(group_id_hex)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Create conversation on server (metadata is encrypted in MLS extensions, not sent as plaintext)
        let result = self
            .api_client()
            .create_conversation(group_id_hex, filtered_members_ref, None, None, None)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Server creation failed");
                e
            })?;

        let mut convo = result.conversation.clone();
        let conversation_id = &convo.conversation_id;

        self.storage()
            .ensure_conversation_exists(user_did, conversation_id, group_id_hex)
            .await?;

        self.storage()
            .update_join_info(conversation_id, user_did, JoinMethod::Creator, 0)
            .await?;

        // Cache conversation
        self.conversations()
            .lock()
            .await
            .insert(group_id_hex.to_string(), convo.clone());

        // If initial members were provided, add them via proper MLS add_members
        // This generates the commit + Welcome messages needed for them to join
        if let Some(members) = filtered_members_ref {
            if !members.is_empty() {
                tracing::info!(
                    count = members.len(),
                    "Adding initial members via MLS add_members"
                );

                // Fetch key packages for the members
                let member_dids: Vec<String> = members.to_vec();
                let key_packages = self.api_client().get_key_packages(&member_dids).await?;

                if key_packages.is_empty() {
                    tracing::error!(
                        dids = ?member_dids,
                        "No key packages found for any member — they may not have X-Wing packages registered"
                    );
                    return Err(OrchestratorError::KeyPackageExhausted);
                }

                for kp in &key_packages {
                    tracing::info!(
                        did = %kp.did,
                        cipher_suite = %kp.cipher_suite,
                        bytes = kp.key_package_data.len(),
                        "Fetched key package for member"
                    );
                }

                let kp_data: Vec<crate::KeyPackageData> = key_packages
                    .iter()
                    .map(|kp| crate::KeyPackageData {
                        data: kp.key_package_data.clone(),
                    })
                    .collect();

                let add_result = self
                    .mls_context()
                    .add_members(group_id_bytes.clone(), kp_data)
                    .map_err(|e| {
                        tracing::error!(error = %e, "MLS add_members failed — key package validation or crypto error");
                        e
                    })?;

                // Track own commit
                {
                    self.evict_stale_commits().await;
                    let hash = Sha256::digest(&add_result.commit_data);
                    self.own_commits()
                        .lock()
                        .await
                        .insert(hash.to_vec(), Instant::now());
                }

                // Send commit + Welcome to server
                let server_result = self
                    .api_client()
                    .add_members(
                        group_id_hex,
                        &member_dids,
                        &add_result.commit_data,
                        Some(&add_result.welcome_data),
                    )
                    .await?;

                if !server_result.success {
                    if let Err(e) = self
                        .mls_context()
                        .clear_pending_commit(group_id_bytes.clone())
                    {
                        tracing::warn!(error = %e, "Failed to clear pending commit after server rejection");
                    }
                    return Err(OrchestratorError::Api(
                        "Server rejected initial member addition".into(),
                    ));
                }

                // Best-effort receipt storage
                if let Some(ref receipt) = server_result.receipt {
                    if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
                        tracing::warn!(error = %e, "Failed to store sequencer receipt");
                    }
                }

                // Merge the pending commit to advance local epoch
                let merged_epoch = self
                    .mls_context()
                    .merge_pending_commit(group_id_bytes.clone())?;

                // Update convo epoch
                convo.epoch = merged_epoch;

                // Cleanup old epoch secrets after initial member add
                self.cleanup_epoch_secrets_if_needed(group_id_hex, merged_epoch)
                    .await;

                tracing::info!(
                    epoch = merged_epoch,
                    "Initial members added, epoch advanced"
                );
            }
        }

        // Get epoch from FFI (authoritative)
        let ffi_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;

        // Update group state
        let members: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();
        let state = GroupState {
            group_id: group_id_hex.to_string(),
            conversation_id: convo.conversation_id.clone(),
            epoch: ffi_epoch,
            members,
        };
        self.group_states()
            .lock()
            .await
            .insert(group_id_hex.to_string(), state.clone());
        self.storage().set_group_state(&state).await?;

        // Mark conversation as active
        self.conversation_states()
            .lock()
            .await
            .insert(group_id_hex.to_string(), ConversationState::Active);

        // Publish GroupInfo for external joins
        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.as_bytes().to_vec())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(group_id_hex, &group_info)
            .await
        {
            tracing::warn!(error = %e, "Failed to publish GroupInfo (external joins won't work)");
        }

        // Remove from being-created set
        self.groups_being_created()
            .lock()
            .await
            .remove(group_id_hex);

        tracing::info!(group_id = %group_id_hex, epoch = ffi_epoch, "Group creation complete");
        Ok(convo)
    }

    /// Join an existing group via a Welcome message.
    pub async fn join_group(&self, welcome_data: &[u8]) -> Result<ConversationView> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!("Joining group from Welcome message");

        let identity_bytes = user_did.as_bytes().to_vec();
        let welcome_result = self.mls_context().process_welcome(
            welcome_data.to_vec(),
            identity_bytes,
            Some(self.config().group_config.clone()),
        )?;
        let group_id_hex = hex::encode(&welcome_result.group_id);

        tracing::debug!(group_id = %group_id_hex, "Processed Welcome message");

        // Fetch conversation from server
        let page = self.api_client().get_conversations(100, None).await?;
        let convo = page
            .conversations
            .into_iter()
            .find(|c| c.group_id == group_id_hex)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(group_id_hex.clone()))?;

        // Cache
        self.conversations()
            .lock()
            .await
            .insert(group_id_hex.clone(), convo.clone());

        let ffi_epoch = self
            .mls_context()
            .get_epoch(welcome_result.group_id.clone())?;

        let members: Vec<String> = convo.members.iter().map(|m| m.did.clone()).collect();
        let state = GroupState {
            group_id: group_id_hex.clone(),
            conversation_id: convo.conversation_id.clone(),
            epoch: ffi_epoch,
            members,
        };
        self.group_states()
            .lock()
            .await
            .insert(group_id_hex.clone(), state.clone());
        self.storage().set_group_state(&state).await?;
        self.storage()
            .ensure_conversation_exists(&user_did, &convo.conversation_id, &group_id_hex)
            .await?;
        self.storage()
            .update_join_info(&group_id_hex, &user_did, JoinMethod::Welcome, ffi_epoch)
            .await?;

        // Insert history boundary marker for Welcome joins.
        // On iOS, Swift inserts first — message_exists prevents duplicates.
        let marker_id = format!("hb-{}-{}", group_id_hex, ffi_epoch);
        if !self
            .storage()
            .message_exists(&marker_id)
            .await
            .unwrap_or(true)
        {
            let payload = MLSMessagePayload::system("history_boundary.new_member");
            let marker = Message {
                id: marker_id,
                conversation_id: group_id_hex.clone(),
                sender_did: user_did.clone(),
                text: "history_boundary.new_member".to_string(),
                timestamp: chrono::Utc::now(),
                epoch: ffi_epoch,
                sequence_number: 0,
                is_own: true,
                delivery_status: None,
                payload_json: serde_json::to_string(&payload).ok(),
            };
            if let Err(e) = self.storage().store_message(&marker).await {
                tracing::warn!(error = %e, "Failed to store history boundary marker");
            }
        }

        Ok(convo)
    }

    /// Add members to an existing group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44. Platforms
    /// can migrate to the new API incrementally; this wrapper will remain
    /// until all clients have moved over.
    pub async fn add_members(&self, group_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;

        tracing::info!(
            group_id,
            count = member_dids.len(),
            "Adding members to group"
        );

        // Fetch key packages for the new members.
        let key_packages = self.api_client().get_key_packages(member_dids).await?;
        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        // Stage the commit via the new API.
        let plan = self
            .stage_commit(
                group_id,
                CommitKind::AddMembers {
                    member_dids: member_dids.to_vec(),
                    key_packages: kp_data,
                },
            )
            .await?;

        // Ship commit + Welcome to the DS.
        let server_result = self
            .api_client()
            .add_members(
                group_id,
                member_dids,
                &plan.commit_bytes,
                plan.welcome_bytes.as_deref(),
            )
            .await;

        match server_result {
            Ok(result) => {
                if !result.success {
                    let _ = self.discard_pending(plan.handle).await;
                    return Err(OrchestratorError::MemberSyncFailed);
                }

                // Best-effort receipt storage.
                if let Some(ref receipt) = result.receipt {
                    if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
                        tracing::warn!(error = %e, group_id, "Failed to store sequencer receipt");
                    }
                }

                // Confirm — but only if the server actually advanced the
                // epoch. Some legacy server paths accept the commit without
                // advancing (returning `new_epoch == 0` or the old epoch);
                // in that case the local pending commit must be discarded,
                // not merged.
                let current_epoch =
                    self.mls_context()
                        .get_epoch(hex::decode(group_id).map_err(|_| {
                            OrchestratorError::InvalidInput("Invalid hex group ID".into())
                        })?)?;

                if result.new_epoch > current_epoch {
                    // Pass the skip sentinel — we've already validated the
                    // server's epoch advanced, and the server's raw new_epoch
                    // isn't necessarily `source_epoch + 1` in every legacy
                    // path (e.g. if it reflects a merged-history epoch from
                    // the DS). The wrapper consciously trades fencing
                    // strictness for backward compatibility; new platform
                    // code calling `confirm_commit` directly should pass the
                    // real epoch for proper fencing.
                    self.confirm_commit(plan.handle, super::staged_commit::SKIP_SERVER_EPOCH_FENCE)
                        .await?;
                } else {
                    tracing::warn!(
                        group_id,
                        server_epoch = result.new_epoch,
                        local_epoch = current_epoch,
                        "Server accepted add_members but epoch did not advance — discarding pending commit"
                    );
                    let _ = self.discard_pending(plan.handle).await;

                    // Still update the member list in group state for
                    // backward compatibility — legacy callers rely on the
                    // members appearing even when the epoch didn't move.
                    let mut states = self.group_states().lock().await;
                    if let Some(gs) = states.get_mut(group_id) {
                        for did in member_dids {
                            if !gs.members.contains(did) {
                                gs.members.push(did.clone());
                            }
                        }
                        let state_clone = gs.clone();
                        drop(states);
                        if let Err(e) = self.storage().set_group_state(&state_clone).await {
                            tracing::warn!(error = %e, group_id, "Failed to persist group state after no-advance add_members");
                        }
                    }
                }
            }
            Err(e) => {
                let _ = self.discard_pending(plan.handle).await;
                return Err(e);
            }
        }

        tracing::info!(group_id, "Members added successfully");
        Ok(())
    }

    /// Remove members from a group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44.
    pub async fn remove_members(&self, group_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;

        tracing::info!(
            group_id,
            count = member_dids.len(),
            "Removing members from group"
        );

        let plan = self
            .stage_commit(
                group_id,
                CommitKind::RemoveMembers {
                    member_dids: member_dids.to_vec(),
                },
            )
            .await?;

        match self
            .api_client()
            .remove_members(group_id, member_dids, &plan.commit_bytes)
            .await
        {
            Ok(()) => {
                // `api_client.remove_members` returns `()` — no server
                // epoch to fence against. Pass the skip sentinel.
                self.confirm_commit(plan.handle, super::staged_commit::SKIP_SERVER_EPOCH_FENCE)
                    .await?;
                Ok(())
            }
            Err(e) => {
                let _ = self.discard_pending(plan.handle).await;
                Err(e)
            }
        }
    }

    /// Atomically swap members: remove old devices + add new in one commit.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44.
    pub async fn swap_members(
        &self,
        group_id: &str,
        remove_dids: &[String],
        add_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        tracing::info!(
            group_id,
            remove_count = remove_dids.len(),
            add_count = add_dids.len(),
            "swap_members"
        );

        let key_packages = self.api_client().get_key_packages(add_dids).await?;
        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        let plan = self
            .stage_commit(
                group_id,
                CommitKind::SwapMembers {
                    remove_dids: remove_dids.to_vec(),
                    add_dids: add_dids.to_vec(),
                    add_key_packages: kp_data,
                },
            )
            .await?;

        let server_result = self
            .api_client()
            .add_members(
                group_id,
                add_dids,
                &plan.commit_bytes,
                plan.welcome_bytes.as_deref(),
            )
            .await;

        match server_result {
            Ok(result) => {
                if !result.success {
                    let _ = self.discard_pending(plan.handle).await;
                    return Err(OrchestratorError::MemberSyncFailed);
                }
                if let Some(ref receipt) = result.receipt {
                    let _ = self.storage().store_sequencer_receipt(receipt).await;
                }
                let current_epoch =
                    self.mls_context()
                        .get_epoch(hex::decode(group_id).map_err(|_| {
                            OrchestratorError::InvalidInput("Invalid hex group ID".into())
                        })?)?;
                if result.new_epoch > current_epoch {
                    self.confirm_commit(plan.handle, super::staged_commit::SKIP_SERVER_EPOCH_FENCE)
                        .await?;
                } else {
                    let _ = self.discard_pending(plan.handle).await;
                }
                tracing::info!(group_id, "swap_members complete");
                Ok(())
            }
            Err(e) => {
                let _ = self.discard_pending(plan.handle).await;
                Err(e)
            }
        }
    }

    /// Leave a conversation.
    pub async fn leave_group(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let _user_did = self.require_user_did().await?;

        tracing::info!(convo_id, "Leaving conversation");

        // Leave on server first
        self.api_client().leave_conversation(convo_id).await?;

        // Clean up locally
        self.force_delete_local(convo_id).await;

        Ok(())
    }

    /// Delete a conversation (admin action).
    pub async fn delete_group(&self, convo_id: &str) -> Result<()> {
        self.leave_group(convo_id).await
    }

    /// Leave a group via self-remove: propose own removal, send to group, then
    /// notify the server and clean up locally.
    pub async fn leave_via_self_remove(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let _user_did = self.require_user_did().await?;

        tracing::info!(convo_id, "Leaving group via self-remove proposal");

        let group_id_bytes = hex::decode(convo_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let proposal_bytes = self.mls_context().propose_self_remove(group_id_bytes)?;

        let epoch = self
            .group_states()
            .lock()
            .await
            .get(convo_id)
            .map(|gs| gs.epoch)
            .unwrap_or(0);

        let message_id = uuid::Uuid::new_v4().to_string();
        if let Err(e) = self
            .api_client()
            .send_message_with_id(convo_id, &proposal_bytes, epoch, &message_id)
            .await
        {
            tracing::warn!(error = %e, convo_id, "Self-remove proposal send failed, falling back");
            self.api_client().leave_conversation(convo_id).await?;
            self.force_delete_local(convo_id).await;
            return Ok(());
        }

        if let Err(e) = self.api_client().leave_conversation(convo_id).await {
            tracing::warn!(error = %e, convo_id, "Server-side leave failed (non-fatal)");
        }

        self.force_delete_local(convo_id).await;
        tracing::info!(convo_id, "Left group via self-remove proposal");
        Ok(())
    }

    /// Commit pending self-remove proposals for a group.
    pub async fn commit_self_remove_proposals(&self, convo_id: &str) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!(convo_id, "Committing pending self-remove proposals");

        let group_id_bytes = hex::decode(convo_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let commit_bytes = match self
            .mls_context()
            .commit_pending_proposals(group_id_bytes.clone())
        {
            Ok(bytes) => bytes,
            Err(crate::MLSError::InvalidInput { .. }) => {
                tracing::debug!(convo_id, "No pending proposals to commit");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        {
            self.evict_stale_commits().await;
            let hash = Sha256::digest(&commit_bytes);
            self.own_commits()
                .lock()
                .await
                .insert(hash.to_vec(), Instant::now());
        }

        self.api_client()
            .commit_group_change(convo_id, &commit_bytes, "commitSelfRemove", None)
            .await?;

        let new_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(convo_id) {
                gs.epoch = new_epoch;
                let state_clone = gs.clone();
                drop(states);
                if let Err(e) = self.storage().set_group_state(&state_clone).await {
                    tracing::warn!(error = %e, convo_id, "Failed to persist group state");
                }
            }
        }

        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(convo_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to publish GroupInfo");
        }

        tracing::info!(
            convo_id,
            epoch = new_epoch,
            "Self-remove proposals committed"
        );
        Ok(())
    }

    /// Atomic encrypted metadata update (Phase A.2).
    ///
    /// Uses [`MlsCryptoContext::update_group_metadata_encrypted`] — staged
    /// commit + post-commit-epoch key derivation + ChaCha20-Poly1305
    /// encryption all in one shot — then uploads the encrypted blob via
    /// [`MLSAPIClient::put_group_metadata_blob`] and the commit via
    /// [`MLSAPIClient::commit_group_change`], finally merging the pending
    /// commit locally to advance the epoch.
    ///
    /// On any error, the pending commit is discarded so the local group
    /// state stays at the pre-update epoch.
    pub async fn update_group_metadata_encrypted(
        &self,
        conversation_id: &str,
        title: Option<&str>,
        description: Option<&str>,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
    ) -> Result<()> {
        self.check_shutdown().await?;

        let group_id_hex = self
            .group_id_hex_for_conversation(conversation_id)
            .await
            .unwrap_or_else(|| conversation_id.to_string());
        let group_id_bytes = hex::decode(&group_id_hex).map_err(|_| {
            OrchestratorError::InvalidInput("Invalid hex group ID for metadata update".into())
        })?;

        // 1. Stage commit + encrypt + assemble artifacts in one FFI call.
        let result = self.mls_context().update_group_metadata_encrypted(
            group_id_bytes.clone(),
            title.map(|s| s.to_string()),
            description.map(|s| s.to_string()),
            avatar_blob_locator.map(|s| s.to_string()),
            avatar_content_type.map(|s| s.to_string()),
        )?;

        // 2. Upload the encrypted blob first; if this fails we must discard the
        //    pending commit so the local epoch doesn't advance into a state
        //    other clients can't reach (no blob → can't decrypt metadata).
        if let Err(e) = self
            .api_client()
            .put_group_metadata_blob(
                conversation_id,
                &group_id_hex,
                &result.metadata_blob_locator,
                &result.metadata_blob_ciphertext,
                "metadata",
                result.metadata_version,
                None,
            )
            .await
        {
            let _ = self.mls_context().clear_pending_commit(group_id_bytes);
            return Err(e);
        }

        // 3. Submit the commit. Same discard logic on failure.
        if let Err(e) = self
            .api_client()
            .commit_group_change(
                conversation_id,
                &result.commit_bytes,
                "updateMetadata",
                None,
            )
            .await
        {
            let _ = self.mls_context().clear_pending_commit(group_id_bytes);
            return Err(e);
        }

        // 4. Merge locally (advances epoch and applies the new
        //    MetadataReference in AppDataDictionary).
        let merge_epoch = self
            .mls_context()
            .merge_pending_commit(group_id_bytes)?;

        tracing::info!(
            conversation_id,
            new_epoch = merge_epoch,
            metadata_version = result.metadata_version,
            blob_locator = %result.metadata_blob_locator,
            "Group metadata updated (encrypted)"
        );
        Ok(())
    }

    /// Force delete a conversation from local state only.
    pub(crate) async fn force_delete_local(&self, convo_id: &str) {
        let user_did = self.require_user_did().await.unwrap_or_default();
        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await;

        // Delete MLS group from FFI
        if let Some(group_id_bytes) = group_id_hex
            .as_deref()
            .and_then(|group_id| hex::decode(group_id).ok())
        {
            if let Err(e) = self.mls_context().delete_group(group_id_bytes) {
                tracing::warn!(error = %e, convo_id, "Failed to delete MLS group from FFI");
            }
        }

        // Delete from storage
        if let Err(e) = self
            .storage()
            .delete_conversations(&user_did, &[convo_id])
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to delete from storage");
        }
        let _ = self.storage().delete_group_state(convo_id).await;
        if let Some(group_id) = group_id_hex
            .as_deref()
            .filter(|group_id| *group_id != convo_id)
        {
            let _ = self.storage().delete_group_state(group_id).await;
        }

        // Remove from caches
        self.conversations().lock().await.remove(convo_id);
        if let Some(group_id) = group_id_hex
            .as_deref()
            .filter(|group_id| *group_id != convo_id)
        {
            self.conversations().lock().await.remove(group_id);
        }
        {
            let mut states = self.group_states().lock().await;
            states.remove(convo_id);
            if let Some(group_id) = group_id_hex
                .as_deref()
                .filter(|group_id| *group_id != convo_id)
            {
                states.remove(group_id);
            }
        }
        self.conversation_states().lock().await.remove(convo_id);
    }
}
