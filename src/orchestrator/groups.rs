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
            .create_group_inner(
                &user_did,
                &group_id_hex,
                name,
                description,
                filtered_members_ref,
            )
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
        name: &str,
        description: Option<&str>,
        filtered_members_ref: Option<&[String]>,
    ) -> Result<ConversationView> {
        let group_id_bytes = hex::decode(group_id_hex)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // If initial members were provided, stage the MLS add before calling
        // createConvo. The server's createConvo path stores the Welcome and
        // treats that bootstrap add as the initial epoch-1 group material; if
        // we create first and then call commitGroupChange/addMembers, the DS
        // has already seeded the row at epoch 1 and rejects our epoch-0 commit.
        let mut initial_add_result: Option<crate::AddMembersResult> = None;
        if let Some(members) = filtered_members_ref {
            if !members.is_empty() {
                tracing::info!(
                    count = members.len(),
                    "Staging initial members for createConvo Welcome path"
                );

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

                // WS-3 stage 1 (ADR-009 D3): verify fetched key-package
                // credentials against the DIDs they were fetched for.
                // Warn-and-allow — never alters the operation.
                self.verify_fetched_key_packages(
                    &member_dids,
                    &key_packages,
                    "create_group",
                    Some(group_id_hex),
                )
                .await;

                let kp_data: Vec<crate::KeyPackageData> = key_packages
                    .iter()
                    .map(|kp| crate::KeyPackageData {
                        data: kp.key_package_data.clone(),
                    })
                    .collect();

                // If the group has a name/description, add the members AND
                // re-seal the metadata at the post-add epoch in the SAME commit,
                // so the Welcome carries a MetadataReference the joiners can use
                // and the matching blob is sealed at the epoch they land on.
                // Plain `add_members` embeds no reference, leaving joiners at
                // "Secure Chat".
                let add_result = if !name.is_empty() || description.is_some() {
                    self.mls_context()
                        .add_members_with_metadata(
                            group_id_bytes.clone(),
                            kp_data,
                            if name.is_empty() { None } else { Some(name.to_string()) },
                            description.map(|d| d.to_string()),
                        )
                        .map_err(|e| {
                            tracing::error!(error = %e, "MLS add_members_with_metadata failed — key package validation or crypto error");
                            e
                        })?
                } else {
                    self.mls_context()
                        .add_members(group_id_bytes.clone(), kp_data)
                        .map_err(|e| {
                            tracing::error!(error = %e, "MLS add_members failed — key package validation or crypto error");
                            e
                        })?
                };

                // Track own commit
                {
                    self.evict_stale_commits().await;
                    let hash = Sha256::digest(&add_result.commit_data);
                    self.own_commits()
                        .lock()
                        .await
                        .insert(hash.to_vec(), Instant::now());
                }

                initial_add_result = Some(add_result);
            }
        }

        // Create conversation on server (metadata is encrypted in MLS extensions, not sent as plaintext).
        let result = self
            .api_client()
            .create_conversation(
                group_id_hex,
                filtered_members_ref,
                None,
                initial_add_result
                    .as_ref()
                    .map(|add| add.commit_data.as_slice()),
                initial_add_result
                    .as_ref()
                    .map(|add| add.welcome_data.as_slice()),
            )
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

        if initial_add_result.is_some() {
            let merged_epoch = self
                .mls_context()
                .merge_pending_commit(group_id_bytes.clone())?;

            convo.epoch = merged_epoch;

            self.cleanup_epoch_secrets_if_needed(group_id_hex, merged_epoch)
                .await;

            tracing::info!(
                epoch = merged_epoch,
                "Initial members committed via createConvo Welcome path"
            );
        }

        // Upload the encrypted group metadata blob so OTHER members can decrypt
        // the group name/description. The initial `add_members_with_metadata`
        // commit above (1) embedded a fresh `MetadataReference` (locator +
        // version) into the group context — which the Welcome carries to every
        // joiner — and (2) re-sealed the `GroupMetadataV1` blob at the post-add
        // epoch under that same locator. Joiners land at exactly that epoch, so
        // they can derive the metadata key, fetch this blob, and decrypt it.
        //
        // No extra commit / epoch advance happens here (the reseal rode the add
        // commit), so sends keep working. `put_group_metadata_blob` requires the
        // conversation row to exist on the DS, hence we upload AFTER createConvo.
        // Non-fatal: on any failure the name stays hidden until a later update.
        if let (Some(locator), Some(ciphertext), Some(version)) = (
            initial_add_result
                .as_ref()
                .and_then(|r| r.metadata_blob_locator.clone()),
            initial_add_result
                .as_ref()
                .and_then(|r| r.metadata_blob_ciphertext.clone()),
            initial_add_result.as_ref().and_then(|r| r.metadata_version),
        ) {
            if let Err(e) = self
                .api_client()
                .put_group_metadata_blob(
                    &convo.conversation_id,
                    group_id_hex,
                    &locator,
                    &ciphertext,
                    "metadata",
                    version,
                    None,
                )
                .await
            {
                tracing::warn!(
                    error = %e,
                    group_id = %group_id_hex,
                    "Failed to upload initial group metadata blob; members won't see the group name until the next metadata update"
                );
            }
        }

        // Get epoch from FFI (authoritative; reflects the metadata commit above).
        let ffi_epoch = self.mls_context().get_epoch(group_id_bytes.clone())?;
        convo.epoch = ffi_epoch;

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

    /// Fetch + decrypt the encrypted group metadata blob for a conversation and
    /// populate the cached `ConversationView.metadata` (name / description), so
    /// every client renders the group name after joining. Newly-added members
    /// can't derive a past epoch's exporter and so never cached the plaintext;
    /// this is how they obtain it.
    ///
    /// Best-effort: any failure (no metadata set, platform hasn't wired the
    /// blob fetch, key/epoch/AAD mismatch) is logged and skipped — the join
    /// itself is never affected.
    pub(crate) async fn hydrate_conversation_metadata(&self, conversation_id: &str) {
        let group_id_hex = self
            .group_id_hex_for_conversation(conversation_id)
            .await
            .unwrap_or_else(|| conversation_id.to_string());
        let group_id_bytes = match hex::decode(&group_id_hex) {
            Ok(b) => b,
            Err(_) => return,
        };

        let info = match self
            .mls_context()
            .get_current_metadata(group_id_bytes.clone())
        {
            Ok(Some(info)) => info,
            Ok(None) => return, // no metadata set, or backend not wired
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: get_current_metadata failed");
                return;
            }
        };
        let Some(reference_json) = info.metadata_reference_json else {
            return; // group has no MetadataReference yet
        };
        let reference: crate::metadata::MetadataReference = match serde_json::from_slice(
            &reference_json,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: bad MetadataReference JSON");
                return;
            }
        };

        let blob = match self
            .api_client()
            .get_group_metadata_blob(conversation_id, &group_id_hex, &reference.blob_locator)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, "hydrate_metadata: blob fetch failed");
                return;
            }
        };

        let key: [u8; 32] = match info.metadata_key.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => {
                tracing::warn!(
                    convo = conversation_id,
                    "hydrate_metadata: metadata key wrong length"
                );
                return;
            }
        };
        let metadata = match crate::metadata::decrypt_metadata_blob(
            &key,
            &group_id_bytes,
            info.epoch,
            reference.metadata_version,
            &blob,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, convo = conversation_id, epoch = info.epoch, "hydrate_metadata: decrypt failed");
                return;
            }
        };

        if let Some(view) = self.conversations().lock().await.get_mut(&group_id_hex) {
            view.metadata = Some(ConversationMetadata {
                name: Some(metadata.title.clone()),
                description: if metadata.description.is_empty() {
                    None
                } else {
                    Some(metadata.description.clone())
                },
                avatar_url: None,
            });
        }
        tracing::info!(
            convo = conversation_id,
            epoch = info.epoch,
            "hydrate_metadata: group name decrypted"
        );
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
        let mut convo = page
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

        // Decrypt the group name/description now that we hold the joined epoch,
        // and reflect it in the returned view. Best-effort.
        self.hydrate_conversation_metadata(&convo.conversation_id)
            .await;
        if let Some(view) = self.conversations().lock().await.get(&group_id_hex) {
            convo.metadata = view.metadata.clone();
        }

        Ok(convo)
    }

    /// Add members to an existing group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44. Platforms
    /// can migrate to the new API incrementally; this wrapper will remain
    /// until all clients have moved over.
    pub async fn add_members(&self, conversation_id: &str, member_dids: &[String]) -> Result<()> {
        self.check_shutdown().await?;
        let group_id = self
            .group_id_hex_for_conversation(conversation_id)
            .await
            .unwrap_or_else(|| conversation_id.to_string());

        tracing::info!(
            conversation_id,
            group_id,
            count = member_dids.len(),
            "Adding members to group"
        );

        // Fetch key packages for the new members.
        let key_packages = self.api_client().get_key_packages(member_dids).await?;

        // WS-3 stage 1 (ADR-009 D3): warn-and-allow credential binding check.
        self.verify_fetched_key_packages(
            member_dids,
            &key_packages,
            "add_members",
            Some(&group_id),
        )
        .await;

        let kp_data: Vec<crate::KeyPackageData> = key_packages
            .iter()
            .map(|kp| crate::KeyPackageData {
                data: kp.key_package_data.clone(),
            })
            .collect();

        // Stage the commit via the new API.
        let plan = self
            .stage_commit_for_group(
                conversation_id,
                &group_id,
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
                conversation_id,
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

                // Best-effort receipt storage, with equivocation detection
                // against previously stored receipts (WS-3 stage 1, ADR-009 D8).
                if let Some(ref receipt) = result.receipt {
                    self.record_and_check_sequencer_receipt(receipt, "add_members")
                        .await;
                }

                // Confirm — but only if the server actually advanced the
                // epoch. Some legacy server paths accept the commit without
                // advancing (returning `new_epoch == 0` or the old epoch);
                // in that case the local pending commit must be discarded,
                // not merged.
                let current_epoch =
                    self.mls_context()
                        .get_epoch(hex::decode(&group_id).map_err(|_| {
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
                        group_id = %group_id,
                        server_epoch = result.new_epoch,
                        local_epoch = current_epoch,
                        "Server accepted add_members but epoch did not advance — discarding pending commit"
                    );
                    let _ = self.discard_pending(plan.handle).await;

                    // Still update the member list in group state for
                    // backward compatibility — legacy callers rely on the
                    // members appearing even when the epoch didn't move.
                    let mut states = self.group_states().lock().await;
                    if let Some(gs) = states.get_mut(&group_id) {
                        for did in member_dids {
                            if !gs.members.contains(did) {
                                gs.members.push(did.clone());
                            }
                        }
                        let state_clone = gs.clone();
                        drop(states);
                        if let Err(e) = self.storage().set_group_state(&state_clone).await {
                            tracing::warn!(error = %e, group_id = %group_id, "Failed to persist group state after no-advance add_members");
                        }
                    }
                }
            }
            Err(e) => {
                let _ = self.discard_pending(plan.handle).await;
                return Err(e);
            }
        }

        tracing::info!(conversation_id, group_id = %group_id, "Members added successfully");
        Ok(())
    }

    /// Remove members from a group.
    ///
    /// Backward-compatible wrapper around the three-phase `stage_commit` /
    /// `confirm_commit` / `discard_pending` API added in task #44.
    pub async fn remove_members(
        &self,
        conversation_id: &str,
        member_dids: &[String],
    ) -> Result<()> {
        self.check_shutdown().await?;
        let group_id = self
            .group_id_hex_for_conversation(conversation_id)
            .await
            .unwrap_or_else(|| conversation_id.to_string());

        tracing::info!(
            conversation_id,
            group_id,
            count = member_dids.len(),
            "Removing members from group"
        );

        let plan = self
            .stage_commit_for_group(
                conversation_id,
                &group_id,
                CommitKind::RemoveMembers {
                    member_dids: member_dids.to_vec(),
                },
            )
            .await?;

        match self
            .api_client()
            .remove_members(conversation_id, member_dids, &plan.commit_bytes)
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

        // WS-3 stage 1 (ADR-009 D3): warn-and-allow credential binding check.
        self.verify_fetched_key_packages(add_dids, &key_packages, "swap_members", Some(group_id))
            .await;

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
                    // Best-effort receipt storage + equivocation detection
                    // (WS-3 stage 1, ADR-009 D8); never blocks the operation.
                    self.record_and_check_sequencer_receipt(receipt, "swap_members")
                        .await;
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
        avatar_bytes: Option<&[u8]>,
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
            .merge_pending_commit(group_id_bytes.clone())?;

        // 5. Encrypt + upload the avatar blob at the SAME post-commit
        //    (epoch, metadata_version) the metadata blob was bound to, so
        //    joiners — who fetch the avatar via `avatar_blob_locator` from the
        //    decrypted metadata and decrypt it with their current-epoch key —
        //    get a matching AAD (`group_id || epoch || metadata_version`). The
        //    metadata blob references the locator; without this upload the
        //    locator points at nothing and joiners see no avatar. Best-effort:
        //    the metadata commit already merged, so a failed avatar upload
        //    leaves the group named-but-avatarless rather than breaking it.
        if let (Some(bytes), Some(locator)) = (avatar_bytes, avatar_blob_locator) {
            match self
                .mls_context()
                .get_current_metadata(group_id_bytes.clone())
            {
                Ok(Some(info)) => match <[u8; 32]>::try_from(info.metadata_key.as_slice()) {
                    Ok(key) => {
                        match crate::metadata::encrypt_avatar_blob(
                            &key,
                            &group_id_bytes,
                            info.epoch,
                            result.metadata_version,
                            bytes,
                        ) {
                            Ok(encrypted_avatar) => {
                                if let Err(e) = self
                                    .api_client()
                                    .put_group_metadata_blob(
                                        conversation_id,
                                        &group_id_hex,
                                        locator,
                                        &encrypted_avatar,
                                        "avatar",
                                        result.metadata_version,
                                        None,
                                    )
                                    .await
                                {
                                    tracing::warn!(error = %e, conversation_id, "Avatar blob upload failed; group named but avatar unavailable");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, conversation_id, "Avatar encryption failed")
                            }
                        }
                    }
                    Err(_) => tracing::warn!(
                        conversation_id,
                        "Avatar upload skipped: metadata key wrong length"
                    ),
                },
                Ok(None) => tracing::warn!(
                    conversation_id,
                    "Avatar upload skipped: no current metadata after merge"
                ),
                Err(e) => {
                    tracing::warn!(error = %e, conversation_id, "Avatar upload skipped: get_current_metadata failed")
                }
            }
        }

        tracing::info!(
            conversation_id,
            new_epoch = merge_epoch,
            metadata_version = result.metadata_version,
            blob_locator = %result.metadata_blob_locator,
            has_avatar = avatar_bytes.is_some(),
            "Group metadata updated (encrypted)"
        );
        Ok(())
    }

    /// Force delete a conversation from local state only.
    ///
    /// WS-5.3 crash-safety: the MLS-layer delete and the storage deletes are
    /// separate non-atomic steps, so a crash in between would orphan state.
    /// A pending-delete intent is persisted first and cleared only after all
    /// delete steps ran; `reconcile_pending_local_deletes` (called from
    /// `initialize`) finishes any delete a crash interrupted.
    pub(crate) async fn force_delete_local(&self, convo_id: &str) {
        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await;

        // 1. Persist the delete intent BEFORE mutating anything. Carries the
        // resolved group id so the startup sweep can drop the MLS group even
        // after the conversation row (the id mapping) is gone.
        if let Err(e) = self
            .storage()
            .mark_pending_local_delete(convo_id, group_id_hex.as_deref())
            .await
        {
            tracing::warn!(error = %e, convo_id, "Failed to persist local-delete intent (continuing; crash mid-delete may orphan state)");
        }

        // 2. Run the delete steps.
        let all_steps_ok = self
            .force_delete_local_steps(convo_id, group_id_hex.as_deref())
            .await;

        // 3. Clear the intent only after all delete steps succeeded (trait
        // contract on `clear_pending_local_delete`). A failed step keeps the
        // intent so the next startup sweep retries the idempotent delete.
        if all_steps_ok {
            if let Err(e) = self.storage().clear_pending_local_delete(convo_id).await {
                tracing::warn!(error = %e, convo_id, "Failed to clear local-delete intent (startup sweep will redo an idempotent delete)");
            }
        } else {
            tracing::warn!(
                convo_id,
                "force_delete_local: one or more delete steps failed — keeping pending-delete intent for the startup sweep"
            );
        }
    }

    /// Fault-injection helper used by rustFull E2E recovery gates.
    ///
    /// Deletes only the local OpenMLS group for a conversation and marks the
    /// conversation for rejoin. Unlike `force_delete_local`, this preserves the
    /// conversation projection so deferred Rust recovery can rediscover and
    /// repair the half-joined state.
    pub async fn debug_wipe_local_group_for_recovery(
        &self,
        convo_id: &str,
    ) -> Result<DebugWipeLocalGroupResult> {
        self.check_shutdown().await?;
        self.require_user_did().await?;

        let group_id_hex = self.group_id_hex_for_conversation(convo_id).await;
        let mut deleted_local_group = false;

        if let Some(group_id_bytes) = group_id_hex
            .as_deref()
            .and_then(|group_id| hex::decode(group_id).ok())
        {
            match self.mls_context().delete_group(group_id_bytes) {
                Ok(()) => deleted_local_group = true,
                Err(crate::MLSError::GroupNotFound { .. }) => {
                    tracing::debug!(
                        convo_id,
                        group_id = ?group_id_hex,
                        "Debug wipe found local MLS group already absent"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }

        if let Err(e) = self.storage().delete_group_state(convo_id).await {
            tracing::warn!(
                error = %e,
                convo_id,
                "Debug wipe failed to delete conversation-keyed group state"
            );
            return Err(e);
        }
        if let Some(group_id) = group_id_hex
            .as_deref()
            .filter(|group_id| *group_id != convo_id)
        {
            if let Err(e) = self.storage().delete_group_state(group_id).await {
                tracing::warn!(
                    error = %e,
                    convo_id,
                    group_id,
                    "Debug wipe failed to delete group-id-keyed group state"
                );
                return Err(e);
            }
        }

        self.storage().mark_needs_rejoin(convo_id).await?;
        self.conversation_states()
            .lock()
            .await
            .insert(convo_id.to_string(), ConversationState::NeedsRejoin);

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

        Ok(DebugWipeLocalGroupResult {
            conversation_id: convo_id.to_string(),
            group_id: group_id_hex,
            deleted_local_group,
        })
    }

    /// The idempotent delete steps shared by `force_delete_local` and the
    /// startup reconcile sweep. Every step tolerates already-deleted state.
    ///
    /// Returns `true` when every step succeeded (NotFound-class outcomes —
    /// state that is already gone — count as success for an idempotent
    /// delete). Returns `false` on any real failure so callers keep the
    /// pending-delete intent and the next startup sweep retries.
    async fn force_delete_local_steps(&self, convo_id: &str, group_id_hex: Option<&str>) -> bool {
        let user_did = self.require_user_did().await.unwrap_or_default();
        let mut all_ok = true;

        // Delete MLS group from FFI. An already-deleted group is success.
        if let Some(group_id_bytes) = group_id_hex.and_then(|group_id| hex::decode(group_id).ok()) {
            match self.mls_context().delete_group(group_id_bytes) {
                Ok(()) => {}
                Err(crate::MLSError::GroupNotFound { .. }) => {
                    tracing::debug!(convo_id, "MLS group already deleted (NotFound — ok)");
                }
                Err(e) => {
                    all_ok = false;
                    tracing::warn!(error = %e, convo_id, "Failed to delete MLS group from FFI");
                }
            }
        }

        // Delete from storage
        if let Err(e) = self
            .storage()
            .delete_conversations(&user_did, &[convo_id])
            .await
        {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to delete from storage");
        }
        if let Err(e) = self.storage().delete_group_state(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to delete group state from storage");
        }
        if let Some(group_id) = group_id_hex.filter(|group_id| *group_id != convo_id) {
            if let Err(e) = self.storage().delete_group_state(group_id).await {
                all_ok = false;
                tracing::warn!(error = %e, convo_id, group_id, "Failed to delete group state from storage");
            }
        }

        // Recovery-state cleanup: stale rows for a deleted conversation would
        // be re-imported by startup hydration and gate a re-added
        // conversation that reuses the same server conversation_id (e.g. a
        // maxed-out backoff row blocking rejoin on a fresh re-add).
        self.recovery_tracker()
            .lock()
            .await
            .forget_conversation(convo_id);
        if let Err(e) = self.storage().clear_recovery_backoff(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to clear persisted recovery backoff during local delete");
        }
        if let Err(e) = self.storage().clear_reset_pending(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to clear persisted reset-pending payload during local delete");
        }
        if let Err(e) = self.storage().clear_quarantine(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to clear persisted quarantine during local delete");
        }
        if let Err(e) = self.storage().clear_rejoin_flag(convo_id).await {
            all_ok = false;
            tracing::warn!(error = %e, convo_id, "Failed to clear rejoin flag during local delete");
        }

        // Remove from caches
        self.conversations().lock().await.remove(convo_id);
        if let Some(group_id) = group_id_hex.filter(|group_id| *group_id != convo_id) {
            self.conversations().lock().await.remove(group_id);
        }
        {
            let mut states = self.group_states().lock().await;
            states.remove(convo_id);
            if let Some(group_id) = group_id_hex.filter(|group_id| *group_id != convo_id) {
                states.remove(group_id);
            }
        }
        self.conversation_states().lock().await.remove(convo_id);

        all_ok
    }

    /// WS-5.3 startup sweep: finish local deletes that a crash interrupted
    /// between the persisted intent and completion. Called from
    /// `MLSOrchestrator::initialize`.
    pub(crate) async fn reconcile_pending_local_deletes(&self) {
        let pending = match self.storage().list_pending_local_deletes().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to list pending local deletes during startup reconcile");
                return;
            }
        };
        for intent in pending {
            tracing::info!(
                convo_id = %intent.conversation_id,
                group_id = ?intent.group_id_hex,
                "Reconciling interrupted local delete from previous run"
            );
            // Prefer the group id captured at intent time; the live mapping
            // may already be gone after a partial delete.
            let group_id_hex = match intent.group_id_hex.clone() {
                Some(gid) => Some(gid),
                None => {
                    self.group_id_hex_for_conversation(&intent.conversation_id)
                        .await
                }
            };
            let steps_ok = self
                .force_delete_local_steps(&intent.conversation_id, group_id_hex.as_deref())
                .await;
            if steps_ok {
                if let Err(e) = self
                    .storage()
                    .clear_pending_local_delete(&intent.conversation_id)
                    .await
                {
                    tracing::warn!(error = %e, convo_id = %intent.conversation_id, "Failed to clear reconciled local-delete intent");
                }
            } else {
                tracing::warn!(
                    convo_id = %intent.conversation_id,
                    "Reconcile sweep: delete steps failed — keeping intent for the next startup sweep"
                );
            }
        }
    }
}
