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
    pub async fn add_members(&self, group_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!(
            group_id,
            count = member_dids.len(),
            "Adding members to group"
        );

        // Fetch key packages for the new members
        let key_packages = self.api_client().get_key_packages(member_dids).await?;
        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        let group_id_bytes = hex::decode(group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let add_result = self
            .mls_context()
            .add_members(group_id_bytes.clone(), kp_data)?;

        // Track own commit
        {
            self.evict_stale_commits().await;
            let hash = Sha256::digest(&add_result.commit_data);
            self.own_commits()
                .lock()
                .await
                .insert(hash.to_vec(), Instant::now());
        }

        // Send to server
        let server_result = self
            .api_client()
            .add_members(
                group_id,
                member_dids,
                &add_result.commit_data,
                Some(&add_result.welcome_data),
            )
            .await?;

        if !server_result.success {
            // Clear the pending commit so the group isn't stuck
            if let Err(e) = self
                .mls_context()
                .clear_pending_commit(group_id_bytes.clone())
            {
                tracing::warn!(error = %e, group_id, "Failed to clear pending commit after server rejection");
            }
            return Err(OrchestratorError::MemberSyncFailed);
        }

        // Best-effort receipt storage
        if let Some(ref receipt) = server_result.receipt {
            if let Err(e) = self.storage().store_sequencer_receipt(receipt).await {
                tracing::warn!(error = %e, group_id, "Failed to store sequencer receipt");
            }
        }

        // Merge pending commit if server advanced epoch
        let current_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        if server_result.new_epoch > current_epoch {
            let merged_epoch = match self
                .mls_context()
                .merge_pending_commit(group_id_bytes.clone())
            {
                Ok(epoch) => epoch,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        group_id,
                        server_epoch = server_result.new_epoch,
                        local_epoch = current_epoch,
                        "CRITICAL: merge_pending_commit failed after server accepted add_members commit — local state is behind server"
                    );
                    if let Err(storage_err) = self.storage().mark_needs_rejoin(group_id).await {
                        tracing::warn!(error = %storage_err, group_id, "Failed to mark group for rejoin");
                    }
                    return Err(e.into());
                }
            };

            // Cleanup old epoch secrets after add_members epoch advance
            self.cleanup_epoch_secrets_if_needed(group_id, merged_epoch)
                .await;

            {
                let mut states = self.group_states().lock().await;
                if let Some(gs) = states.get_mut(group_id) {
                    gs.epoch = merged_epoch;
                    for did in member_dids {
                        if !gs.members.contains(did) {
                            gs.members.push(did.clone());
                        }
                    }
                    let state_clone = gs.clone();
                    drop(states);
                    if let Err(e) = self.storage().set_group_state(&state_clone).await {
                        tracing::warn!(error = %e, group_id, "Failed to persist group state after add_members");
                    }
                }
            }
        } else {
            // Server reported success but epoch didn't advance (new_epoch == 0 or == current_epoch).
            // Clear the pending commit so it doesn't leak and block future operations.
            tracing::warn!(
                group_id,
                server_epoch = server_result.new_epoch,
                local_epoch = current_epoch,
                "Server accepted add_members but epoch did not advance — clearing pending commit"
            );
            if let Err(e) = self
                .mls_context()
                .clear_pending_commit(group_id_bytes.clone())
            {
                tracing::warn!(error = %e, group_id, "Failed to clear leaked pending commit after no-advance add_members");
            }

            // Still update the member list in group state
            {
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

        // Publish updated GroupInfo
        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(group_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, group_id, "Failed to publish GroupInfo (external joins may fail)");
        }

        tracing::info!(group_id, "Members added successfully");
        Ok(())
    }

    /// Remove members from a group.
    pub async fn remove_members(&self, group_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::info!(
            group_id,
            count = member_dids.len(),
            "Removing members from group"
        );

        let group_id_bytes = hex::decode(group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // remove_members takes member identity bytes (DIDs as bytes)
        let member_identities: Vec<Vec<u8>> = member_dids
            .iter()
            .map(|did| did.as_bytes().to_vec())
            .collect();

        let commit_data = self
            .mls_context()
            .remove_members(group_id_bytes.clone(), member_identities)?;

        // Track own commit
        {
            self.evict_stale_commits().await;
            let hash = Sha256::digest(&commit_data);
            self.own_commits()
                .lock()
                .await
                .insert(hash.to_vec(), Instant::now());
        }

        // Send to server
        self.api_client()
            .remove_members(group_id, member_dids, &commit_data)
            .await?;

        // Merge pending commit — server has already advanced the epoch, so if this
        // fails the local state is behind the server and needs a rejoin.
        let merged_epoch = match self
            .mls_context()
            .merge_pending_commit(group_id_bytes.clone())
        {
            Ok(epoch) => epoch,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    group_id,
                    "CRITICAL: merge_pending_commit failed after server accepted remove_members commit — local state is behind server"
                );
                if let Err(storage_err) = self.storage().mark_needs_rejoin(group_id).await {
                    tracing::warn!(error = %storage_err, group_id, "Failed to mark group for rejoin");
                }
                return Err(e.into());
            }
        };

        // Cleanup old epoch secrets after remove_members epoch advance
        self.cleanup_epoch_secrets_if_needed(group_id, merged_epoch)
            .await;

        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(group_id) {
                gs.epoch = merged_epoch;
                gs.members.retain(|m| !member_dids.contains(m));
                let state_clone = gs.clone();
                drop(states);
                if let Err(e) = self.storage().set_group_state(&state_clone).await {
                    tracing::warn!(error = %e, group_id, "Failed to persist group state after remove_members");
                }
            }
        }

        // Publish updated GroupInfo
        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(group_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, group_id, "Failed to publish GroupInfo (external joins may fail)");
        }

        Ok(())
    }

    /// Atomically swap members: remove old devices + add new in one commit.
    pub async fn swap_members(
        &self,
        group_id: &str,
        remove_dids: &[String],
        add_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;
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
        let group_id_bytes = hex::decode(group_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;
        let remove_ids: Vec<Vec<u8>> = remove_dids.iter().map(|d| d.as_bytes().to_vec()).collect();
        let swap_result =
            self.mls_context()
                .swap_members(group_id_bytes.clone(), remove_ids, kp_data)?;

        {
            self.evict_stale_commits().await;
            let hash = Sha256::digest(&swap_result.commit_data);
            self.own_commits()
                .lock()
                .await
                .insert(hash.to_vec(), Instant::now());
        }

        let server_result = self
            .api_client()
            .add_members(
                group_id,
                add_dids,
                &swap_result.commit_data,
                Some(&swap_result.welcome_data),
            )
            .await;

        match server_result {
            Ok(result) => {
                if !result.success {
                    let _ = self
                        .mls_context()
                        .clear_pending_commit(group_id_bytes.clone());
                    return Err(OrchestratorError::MemberSyncFailed);
                }
                if let Some(ref receipt) = result.receipt {
                    let _ = self.storage().store_sequencer_receipt(receipt).await;
                }
                let current_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
                if result.new_epoch > current_epoch {
                    let merged_epoch = match self
                        .mls_context()
                        .merge_pending_commit(group_id_bytes.clone())
                    {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::error!(error = %e, group_id, "merge failed after swap_members");
                            let _ = self.storage().mark_needs_rejoin(group_id).await;
                            return Err(e.into());
                        }
                    };
                    // Cleanup old epoch secrets after swap_members epoch advance
                    self.cleanup_epoch_secrets_if_needed(group_id, merged_epoch)
                        .await;

                    {
                        let mut states = self.group_states().lock().await;
                        if let Some(gs) = states.get_mut(group_id) {
                            gs.epoch = merged_epoch;
                            gs.members.retain(|m| !remove_dids.contains(m));
                            for did in add_dids {
                                if !gs.members.contains(did) {
                                    gs.members.push(did.clone());
                                }
                            }
                            let sc = gs.clone();
                            drop(states);
                            let _ = self.storage().set_group_state(&sc).await;
                        }
                    }
                } else {
                    let _ = self
                        .mls_context()
                        .clear_pending_commit(group_id_bytes.clone());
                }
            }
            Err(e) => {
                let _ = self
                    .mls_context()
                    .clear_pending_commit(group_id_bytes.clone());
                return Err(e);
            }
        }

        let group_info = self
            .mls_context()
            .export_group_info(group_id_bytes, user_did.into_bytes())?;
        let _ = self
            .api_client()
            .publish_group_info(group_id, &group_info)
            .await;
        tracing::info!(group_id, "swap_members complete");
        Ok(())
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

    /// Update encrypted group metadata (name, description, avatar_hash).
    ///
    /// Proposes a GroupContextExtensions commit, sends it to the server,
    /// then merges the pending commit locally to advance the epoch.
    pub async fn update_group_metadata(
        &self,
        conversation_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        avatar_hash: Option<&str>,
    ) -> Result<()> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        let group_id = hex::decode(conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let metadata = crate::group_metadata::GroupMetadata {
            v: 1,
            name: name.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            avatar_hash: avatar_hash.map(|s| s.to_string()),
        };

        let metadata_json = metadata
            .to_extension_bytes()
            .map_err(|e| OrchestratorError::Serialization(format!("Metadata serialize: {}", e)))?;

        let commit_bytes = self
            .mls_context()
            .update_group_metadata(group_id.clone(), metadata_json)?;

        // Send commit to server
        // Note: confirmation_tag is None here because the pending commit hasn't been merged yet.
        // The server extracts the tag from GroupInfo in the commit.
        self.api_client()
            .commit_group_change(conversation_id, &commit_bytes, "updateMetadata", None)
            .await?;

        // Merge pending commit locally
        let merged_epoch = self.mls_context().merge_pending_commit(group_id.clone())?;

        // Cleanup old epoch secrets after metadata update epoch advance
        self.cleanup_epoch_secrets_if_needed(conversation_id, merged_epoch)
            .await;

        // Update group state cache
        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(conversation_id) {
                gs.epoch = merged_epoch;
                let state_clone = gs.clone();
                drop(states);
                if let Err(e) = self.storage().set_group_state(&state_clone).await {
                    tracing::warn!(error = %e, conversation_id, "Failed to persist group state after metadata update");
                }
            }
        }

        // Publish updated GroupInfo
        let group_info = self
            .mls_context()
            .export_group_info(group_id, user_did.into_bytes())?;
        if let Err(e) = self
            .api_client()
            .publish_group_info(conversation_id, &group_info)
            .await
        {
            tracing::warn!(error = %e, conversation_id, "Failed to publish GroupInfo after metadata update");
        }

        tracing::info!(
            conversation_id,
            epoch = merged_epoch,
            "Group metadata updated"
        );
        Ok(())
    }

    /// Read decrypted group metadata from MLS group context.
    pub fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<crate::group_metadata::GroupMetadata>> {
        let group_id = hex::decode(conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        let meta_bytes = self.mls_context().get_group_metadata(group_id)?;
        if meta_bytes.is_empty() {
            return Ok(None);
        }
        crate::group_metadata::GroupMetadata::from_extension_bytes(&meta_bytes)
            .map(Some)
            .map_err(|e| OrchestratorError::Serialization(format!("Metadata deserialize: {}", e)))
    }

    /// Force delete a conversation from local state only.
    pub(crate) async fn force_delete_local(&self, convo_id: &str) {
        let user_did = self.require_user_did().await.unwrap_or_default();

        // Delete MLS group from FFI
        if let Ok(group_id_bytes) = hex::decode(convo_id) {
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

        // Remove from caches
        self.conversations().lock().await.remove(convo_id);
        self.group_states().lock().await.remove(convo_id);
        self.conversation_states().lock().await.remove(convo_id);
    }
}
