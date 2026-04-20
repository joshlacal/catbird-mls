use chrono::Utc;
use sha2::Digest;
use std::collections::HashMap;

use super::api_client::MLSAPIClient;
use super::constants;
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
    /// Send a text message to a conversation.
    ///
    /// 1. Encrypts the message via MLS FFI
    /// 2. Sends ciphertext to the delivery service
    /// 3. Stores the plaintext locally
    pub async fn send_message(&self, conversation_id: &str, text: &str) -> Result<Message> {
        self.send_payload_message(conversation_id, MLSMessagePayload::text(text))
            .await
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

        tracing::debug!(conversation_id, "Sending message");

        let group_id_bytes = hex::decode(conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

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
            payload_preview = %String::from_utf8_lossy(&payload_bytes[..payload_bytes.len().min(200)]),
            "Encoded MLSMessagePayload for send"
        );

        // Pre-send sync: catch up on any missed epoch-advancing commits (spec §5.1 step 1).
        // Fetch pending *commits* (not app messages) to advance the local epoch before
        // encrypting, avoiding 409 epoch mismatches on send.
        {
            let mut cursor: Option<String> = None;
            for round in 0..constants::SEND_SYNC_MAX_ROUNDS {
                match self
                    .fetch_messages(
                        conversation_id,
                        cursor.as_deref(),
                        constants::SEND_SYNC_BATCH_SIZE,
                        Some("commit"),
                        None,
                        None,
                    )
                    .await
                {
                    Ok((msgs, next_cursor)) => {
                        if !msgs.is_empty() {
                            tracing::info!(
                                conversation_id,
                                round,
                                count = msgs.len(),
                                "Pre-send sync processed pending messages"
                            );
                        }
                        if msgs.is_empty() || next_cursor.is_none() {
                            break;
                        }
                        cursor = next_cursor;
                    }
                    Err(e) => {
                        tracing::warn!(
                            conversation_id,
                            round,
                            error = %e,
                            "Pre-send sync failed, proceeding anyway"
                        );
                        break;
                    }
                }
            }
        }

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
                self.group_states()
                    .lock()
                    .await
                    .get(conversation_id)
                    .map(|gs| gs.epoch)
                    .unwrap_or(0)
            }
        };

        // Generate the client message ID before send so local storage and server ACK state
        // refer to the same identifier.
        let message_id = uuid::Uuid::new_v4().to_string();

        // Send to delivery service (with failover tracking)
        let send_result = self
            .api_client()
            .send_message_with_id(
                conversation_id,
                &encrypt_result.ciphertext,
                epoch,
                &message_id,
            )
            .await;

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
                    match self.api_client().request_failover(conversation_id).await {
                        Ok(resp) => {
                            tracing::info!(
                                conversation_id,
                                new_sequencer = %resp.new_sequencer_did,
                                "Failover succeeded, rejoining"
                            );
                            self.failover_tracker().lock().await.clear(conversation_id);
                            tracing::info!(
                                conversation_id,
                                "Failover complete — will sync on next cycle"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                conversation_id,
                                error = %e,
                                "Failover request failed"
                            );
                        }
                    }
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

                // Lightweight sync: fetch pending commits to advance local epoch
                let mut any_processed = false;
                let mut all_failed = true;
                {
                    let mut cursor: Option<String> = None;
                    for round in 0..constants::SEND_SYNC_MAX_ROUNDS {
                        match self
                            .fetch_messages(
                                conversation_id,
                                cursor.as_deref(),
                                constants::SEND_SYNC_BATCH_SIZE,
                                Some("commit"),
                                None,
                                None,
                            )
                            .await
                        {
                            Ok((msgs, next_cursor)) => {
                                if !msgs.is_empty() {
                                    any_processed = true;
                                    all_failed = false;
                                    tracing::info!(
                                        conversation_id,
                                        round,
                                        count = msgs.len(),
                                        "409 recovery: processed pending commits"
                                    );
                                } else if !any_processed {
                                    // Empty batch on first round — nothing to catch up on
                                    all_failed = false;
                                }
                                if msgs.is_empty() || next_cursor.is_none() {
                                    break;
                                }
                                cursor = next_cursor;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    conversation_id,
                                    round,
                                    error = %e,
                                    "409 recovery: sync round failed"
                                );
                                break;
                            }
                        }
                    }
                }

                if all_failed {
                    // All commit processing failed (WrongEpoch on all) — flag NEEDS_REJOIN
                    tracing::error!(
                        conversation_id,
                        "409 recovery: all commits failed to process — flagging NEEDS_REJOIN"
                    );
                    let _ = self.storage().mark_needs_rejoin(conversation_id).await;
                    return Err(OrchestratorError::EpochMismatch {
                        local: epoch,
                        remote,
                    });
                }

                // Re-encrypt with updated epoch and retry ONCE
                let retry_epoch = match self.mls_context().get_epoch(group_id_bytes.clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        let _ = self.storage().mark_needs_rejoin(conversation_id).await;
                        return Err(OrchestratorError::EpochMismatch {
                            local: epoch,
                            remote,
                        });
                    }
                };

                let retry_encrypt = match self
                    .mls_context()
                    .encrypt_message(group_id_bytes.clone(), payload_bytes.clone())
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            conversation_id,
                            error = %e,
                            "409 recovery: re-encryption failed — flagging NEEDS_REJOIN"
                        );
                        let _ = self.storage().mark_needs_rejoin(conversation_id).await;
                        return Err(OrchestratorError::from(e));
                    }
                };

                // Track the new commit for dedup
                let retry_commit_hash = sha2::Sha256::digest(&retry_encrypt.ciphertext).to_vec();
                self.own_commits()
                    .lock()
                    .await
                    .insert(retry_commit_hash, web_time::Instant::now());

                match self
                    .api_client()
                    .send_message_with_id(
                        conversation_id,
                        &retry_encrypt.ciphertext,
                        retry_epoch,
                        &message_id,
                    )
                    .await
                {
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
                        let _ = self.storage().mark_needs_rejoin(conversation_id).await;
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

        // Dedup check
        if let Some(ref msg_id) = envelope.server_message_id {
            if self.storage().message_exists(msg_id).await? {
                tracing::debug!(message_id = %msg_id, "Duplicate message, skipping");
                return Ok(None);
            }
        }

        // Check if this is our own commit (self-commit detection)
        let commit_hash = sha2::Sha256::digest(&envelope.ciphertext).to_vec();
        let is_own_commit = self
            .own_commits()
            .lock()
            .await
            .remove(&commit_hash)
            .is_some();

        if is_own_commit {
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                "Skipping own commit"
            );
            return Ok(None);
        }

        let group_id_bytes = hex::decode(&envelope.conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Decrypt via MLS FFI.
        //
        // Task #43: `process_incoming` no longer auto-External-Commits when the
        // group is missing locally. Silently skip such messages — the server will
        // re-deliver on the next normal sync, or the platform will see the
        // conversation appear via Welcome/group-reset recovery and re-fetch. This
        // eliminates the hot-path External Commit spiral.
        let decrypt_result = match self
            .mls_context()
            .decrypt_message(group_id_bytes.clone(), envelope.ciphertext.clone())
        {
            Ok(r) => r,
            Err(crate::MLSError::GroupNotFound { .. }) => {
                tracing::debug!(
                    convo_id = %envelope.conversation_id,
                    "process_incoming: group not found locally, skipping; platform will pick up via sync",
                );
                return Ok(None);
            }
            Err(e) if e.is_wrong_epoch() => {
                // WrongEpoch is the NORMAL outcome for:
                //   - commits from BEFORE our external-commit join (history we never had keys for)
                //   - replayed/duplicate commits we already applied locally
                //   - messages from epochs we've already advanced past
                // None of these indicate a fork or corrupt local state. Counting them as
                // "decrypt failures" hits DECRYPTION_FAILURE_THRESHOLD (3) on active groups,
                // which marks the convo for rejoin, which calls `force_rejoin_unlocked` —
                // that deletes the local group, external-commits to a new epoch, and breaks
                // every other device's `sendMessage` with 409s. The entire epoch-inflation
                // spiral starts with this classification. Skip silently.
                tracing::debug!(
                    conversation_id = %envelope.conversation_id,
                    "Skipping message: WrongEpoch (out-of-band epoch, not a fork)"
                );
                return Ok(None);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    conversation_id = %envelope.conversation_id,
                    "Decryption failed"
                );
                // Track consecutive decrypt failures for fork detection + divergence recovery
                {
                    let mut counts = self.decrypt_fail_counts().lock().await;
                    let count = counts.entry(envelope.conversation_id.clone()).or_insert(0);
                    *count += 1;
                    if *count >= constants::DECRYPTION_FAILURE_THRESHOLD {
                        let fa = self
                            .fork_detection_states()
                            .lock()
                            .ok()
                            .and_then(|fds| fds.get(&envelope.conversation_id).cloned())
                            .is_some_and(|s| s.readd_attempts < constants::FORK_READD_MAX_ATTEMPTS);
                        if fa {
                            tracing::info!(conversation_id = %envelope.conversation_id, "Fork readd in-flight, deferring");
                        } else {
                            tracing::error!(conversation_id = %envelope.conversation_id, failures = *count, "Marking for rejoin");
                            if let Ok(mut fds) = self.fork_detection_states().lock() {
                                fds.remove(&envelope.conversation_id);
                            }
                            self.conversation_states().lock().await.insert(
                                envelope.conversation_id.clone(),
                                ConversationState::NeedsRejoin,
                            );
                            let _ = self
                                .storage()
                                .mark_needs_rejoin(&envelope.conversation_id)
                                .await;
                            *count = 0;
                        }
                    } else if *count == constants::FORK_DETECTION_THRESHOLD {
                        let cs = self
                            .conversation_states()
                            .lock()
                            .await
                            .get(&envelope.conversation_id)
                            .cloned()
                            .unwrap_or(ConversationState::Active);
                        if cs == ConversationState::Active {
                            let ep = self
                                .mls_context()
                                .get_epoch(group_id_bytes.clone())
                                .unwrap_or(0);
                            tracing::info!(conversation_id = %envelope.conversation_id, epoch = ep, "Fork threshold -- readd");
                            self.conversation_states().lock().await.insert(
                                envelope.conversation_id.clone(),
                                ConversationState::ForkDetected,
                            );
                            if let Ok(mut fds) = self.fork_detection_states().lock() {
                                fds.insert(
                                    envelope.conversation_id.clone(),
                                    ForkDetectionState {
                                        detected_at_epoch: ep,
                                        readd_attempts: 0,
                                    },
                                );
                            }
                            let cid = envelope.conversation_id.clone();
                            drop(counts);
                            let _ = self.attempt_fork_readd(&cid).await;
                            return Err(OrchestratorError::from(e));
                        }
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
                self.conversation_states()
                    .lock()
                    .await
                    .insert(envelope.conversation_id.clone(), ConversationState::Active);
            }
        }

        // Extract sender DID from credential
        let sender_did = String::from_utf8(decrypt_result.sender_credential.identity.clone())
            .unwrap_or_else(|_| envelope.sender_did.clone());

        let is_own = sender_did.to_lowercase() == user_did.to_lowercase();

        // Check if this is an own message that we already sent
        if is_own {
            if let Some(ref msg_id) = envelope.server_message_id {
                // Fast path: in-memory pending_messages
                if self.pending_messages().lock().await.remove(msg_id) {
                    // Also clean up persistent entry
                    let _ = self.storage().remove_pending_message(msg_id).await;
                    tracing::debug!(
                        message_id = %msg_id,
                        "Received own message back from server, skipping (in-memory)"
                    );
                    return Ok(None);
                }
                // Slow path: persistent storage (survives app restart)
                if self
                    .storage()
                    .remove_pending_message(msg_id)
                    .await
                    .unwrap_or(false)
                {
                    tracing::debug!(
                        message_id = %msg_id,
                        "Received own message back from server, skipping (persistent)"
                    );
                    return Ok(None);
                }
            }
        }

        // Empty plaintext indicates a commit/control message (epoch advance) — not a user message.
        if decrypt_result.plaintext.is_empty() {
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                epoch = decrypt_result.epoch,
                "Processed commit message (epoch advanced)"
            );
            // Still update cached group state epoch
            {
                let mut states = self.group_states().lock().await;
                if let Some(gs) = states.get_mut(&envelope.conversation_id) {
                    if decrypt_result.epoch > gs.epoch {
                        gs.epoch = decrypt_result.epoch;
                        let state_clone = gs.clone();
                        drop(states);
                        if let Err(e) = self.storage().set_group_state(&state_clone).await {
                            tracing::warn!(
                                error = %e,
                                conversation_id = %envelope.conversation_id,
                                "Failed to persist epoch after commit"
                            );
                        }
                    }
                }
            }

            // Cleanup old epoch secrets after commit advances the epoch
            self.cleanup_epoch_secrets_if_needed(&envelope.conversation_id, decrypt_result.epoch)
                .await;

            // Refresh cached metadata after commit (may contain GroupContextExtensions update)
            match self.get_group_metadata(&envelope.conversation_id) {
                Ok(Some(meta)) => {
                    let mut convos = self.conversations().lock().await;
                    if let Some(convo) = convos.get_mut(&envelope.conversation_id) {
                        convo.metadata = Some(super::types::ConversationMetadata {
                            name: meta.name,
                            description: meta.description,
                            avatar_url: None,
                        });
                        tracing::debug!(
                            conversation_id = %envelope.conversation_id,
                            "Refreshed cached metadata after commit"
                        );
                    }
                }
                Ok(None) => {} // no metadata set
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        conversation_id = %envelope.conversation_id,
                        "Failed to read metadata after commit"
                    );
                }
            }

            return Ok(None);
        }

        let (plaintext, payload_json) = match MLSMessagePayload::decode(&decrypt_result.plaintext) {
            Ok(payload) => {
                if !payload.is_displayable() {
                    tracing::debug!(
                        conversation_id = %envelope.conversation_id,
                        epoch = decrypt_result.epoch,
                        message_type = ?payload.message_type,
                        "Ignoring non-displayable MLS payload"
                    );
                    return Ok(None);
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
                        plaintext_preview = %String::from_utf8_lossy(&decrypt_result.plaintext[..decrypt_result.plaintext.len().min(200)]),
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

        // Update group state epoch if it advanced (and persist)
        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(&envelope.conversation_id) {
                if decrypt_result.epoch > gs.epoch {
                    gs.epoch = decrypt_result.epoch;
                    let state_clone = gs.clone();
                    drop(states);
                    if let Err(e) = self.storage().set_group_state(&state_clone).await {
                        tracing::warn!(
                            error = %e,
                            conversation_id = %envelope.conversation_id,
                            "Failed to persist epoch after app message"
                        );
                    }
                }
            }
        }

        // Store message
        self.storage().store_message(&message).await?;

        Ok(Some(message))
    }

    /// Fetch and process new messages from the server for a conversation.
    ///
    /// `message_type` filters the fetch: `Some("commit")` for epoch catch-up,
    /// `None` (all) for normal message polling.
    /// `from_epoch` / `to_epoch` are inclusive bounds (spec: `blue.catbird.mlsChat.getMessages`).
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
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        conversation_id,
                        "Failed to process incoming message"
                    );
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
}
