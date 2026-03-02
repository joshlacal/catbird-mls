use chrono::Utc;
use sha2::Digest;
use std::collections::HashMap;

use super::api_client::MLSAPIClient;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::orchestrator::MLSOrchestrator;
use super::storage::MLSStorageBackend;
use super::types::*;

impl<S, A, C> MLSOrchestrator<S, A, C>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
{
    /// Send a text message to a conversation.
    ///
    /// 1. Encrypts the message via MLS FFI
    /// 2. Sends ciphertext to the delivery service
    /// 3. Stores the plaintext locally
    pub async fn send_message(&self, conversation_id: &str, text: &str) -> Result<Message> {
        self.check_shutdown().await?;
        let user_did = self.require_user_did().await?;

        tracing::debug!(conversation_id, "Sending message");

        let group_id_bytes = hex::decode(conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Encode as MLSMessagePayload JSON (interoperable with iOS Catbird)
        let payload = MLSMessagePayload::text(text);
        let payload_bytes = payload.encode().map_err(|e| {
            OrchestratorError::InvalidInput(format!("Failed to encode message payload: {e}"))
        })?;

        tracing::info!(
            conversation_id,
            payload_len = payload_bytes.len(),
            payload_preview = %String::from_utf8_lossy(&payload_bytes[..payload_bytes.len().min(200)]),
            "Encoded MLSMessagePayload for send"
        );

        // Pre-send sync: catch up on any missed epoch-advancing commits
        match self.fetch_messages(conversation_id, None, 50).await {
            Ok((msgs, _)) => {
                if !msgs.is_empty() {
                    tracing::info!(
                        conversation_id,
                        count = msgs.len(),
                        "Pre-send sync processed {} pending messages",
                        msgs.len()
                    );
                }
            }
            Err(e) => {
                tracing::warn!(conversation_id, error = %e, "Pre-send sync failed, proceeding anyway");
            }
        }

        // Encrypt via MLS (auto-join if group not found locally)
        let encrypt_result = match self
            .mls_context()
            .encrypt_message(group_id_bytes.clone(), payload_bytes.clone())
        {
            Ok(r) => r,
            Err(crate::MLSError::GroupNotFound { .. }) => {
                // Group exists on server but not locally — try Welcome first, External Commit fallback
                tracing::info!(
                    conversation_id,
                    "Group not found locally, joining (Welcome first)"
                );
                self.join_or_rejoin(conversation_id).await.map_err(|e| {
                    OrchestratorError::GroupNotFound(format!(
                        "Auto-join failed for {conversation_id}: {e}"
                    ))
                })?;
                // Retry encryption after joining
                self.mls_context()
                    .encrypt_message(group_id_bytes.clone(), payload_bytes)?
            }
            Err(e) => return Err(e.into()),
        };

        // Track own commit for dedup
        let commit_hash = sha2::Sha256::digest(&encrypt_result.ciphertext).to_vec();
        self.own_commits().lock().await.insert(commit_hash);

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

        match &send_result {
            Ok(()) => {
                self.failover_tracker()
                    .lock()
                    .await
                    .record_success(conversation_id);
            }
            Err(OrchestratorError::Timeout(_)) => {
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
                            let _ = self.force_rejoin(conversation_id).await;
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
            Err(_) => {
                // Business logic errors (epoch conflict, etc.) — don't track as sequencer failure
                return Err(send_result.unwrap_err());
            }
        }

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
            text: text.to_string(),
            timestamp: Utc::now(),
            epoch,
            sequence_number: 0, // Will be set by ordering module
            is_own: true,
            delivery_status: None,
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
        let is_own_commit = self.own_commits().lock().await.remove(&commit_hash);

        if is_own_commit {
            tracing::debug!(
                conversation_id = %envelope.conversation_id,
                "Skipping own commit"
            );
            return Ok(None);
        }

        let group_id_bytes = hex::decode(&envelope.conversation_id)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid hex group ID".into()))?;

        // Decrypt via MLS FFI (auto-join if group not found locally)
        let decrypt_result = match self
            .mls_context()
            .decrypt_message(group_id_bytes.clone(), envelope.ciphertext.clone())
        {
            Ok(r) => r,
            Err(crate::MLSError::GroupNotFound { .. }) => {
                tracing::info!(
                    conversation_id = %envelope.conversation_id,
                    "Group not found locally for decrypt, joining (Welcome first)"
                );
                self.join_or_rejoin(&envelope.conversation_id)
                    .await
                    .map_err(|e| {
                        OrchestratorError::GroupNotFound(format!(
                            "Auto-join failed for {}: {e}",
                            envelope.conversation_id
                        ))
                    })?;
                // Retry decryption after joining
                self.mls_context()
                    .decrypt_message(group_id_bytes.clone(), envelope.ciphertext.clone())
                    .map_err(|e| {
                        tracing::error!(
                            error = %e,
                            conversation_id = %envelope.conversation_id,
                            "Decryption failed after auto-join"
                        );
                        e
                    })?
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    conversation_id = %envelope.conversation_id,
                    "Decryption failed"
                );
                return Err(e.into());
            }
        };

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
                if self.storage().remove_pending_message(msg_id).await.unwrap_or(false) {
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
                    }
                }
            }
            return Ok(None);
        }

        // Extract display text from payload (JSON envelope or raw UTF-8 fallback)
        let plaintext = match MLSMessagePayload::extract_text(&decrypt_result.plaintext) {
            Some(text) if text.trim().is_empty() => {
                tracing::debug!(
                    conversation_id = %envelope.conversation_id,
                    epoch = decrypt_result.epoch,
                    "Ignoring empty text payload"
                );
                return Ok(None);
            }
            Some(text) => {
                tracing::debug!(
                    conversation_id = %envelope.conversation_id,
                    text_len = text.len(),
                    "Extracted text from MLSMessagePayload"
                );
                text
            }
            None => {
                tracing::error!(
                    conversation_id = %envelope.conversation_id,
                    plaintext_len = decrypt_result.plaintext.len(),
                    plaintext_preview = %String::from_utf8_lossy(&decrypt_result.plaintext[..decrypt_result.plaintext.len().min(200)]),
                    "extract_text returned None for non-empty plaintext - PAYLOAD FORMAT ERROR"
                );
                return Err(OrchestratorError::InvalidInput(
                    "Invalid message payload".into(),
                ));
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
        };

        // Update group state epoch if it advanced
        {
            let mut states = self.group_states().lock().await;
            if let Some(gs) = states.get_mut(&envelope.conversation_id) {
                if decrypt_result.epoch > gs.epoch {
                    gs.epoch = decrypt_result.epoch;
                }
            }
        }

        // Store message
        self.storage().store_message(&message).await?;

        Ok(Some(message))
    }

    /// Fetch and process new messages from the server for a conversation.
    pub async fn fetch_messages(
        &self,
        conversation_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<Message>, Option<String>)> {
        self.check_shutdown().await?;

        let (envelopes, new_cursor) = self
            .api_client()
            .get_messages(conversation_id, cursor, limit)
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
