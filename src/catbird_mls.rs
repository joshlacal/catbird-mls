// CatbirdMls — unified API surface for all platforms
//
// Combines lifecycle management (from MLSContext), high-level chat operations
// (from CatbirdClient/Orchestrator), and low-level MLS escape hatches into a
// single UniFFI-exported object. This is the ONE public API for Swift, Kotlin,
// Python, and (via naming alignment) TypeScript/WASM consumers.

use std::sync::Arc;

use crate::api::MLSContext;
use crate::client::{CatbirdClient, ChatMessage, Conversation};
use crate::orchestrator::OrchestratorConfig;
use crate::orchestrator_bridge::{
    convo_view_to_ffi, APIAdapter, CredentialAdapter, FFIConversationView, FFIDeviceInfo,
    FFIKeyPackageStats, FFIOrchestratorConfig, OrchestratorAPICallback, OrchestratorBridgeError,
    OrchestratorCredentialCallback, OrchestratorStorageCallback, StorageAdapter,
};

use crate::keychain::KeychainAccess;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════════════
// Concrete type aliases
// ═══════════════════════════════════════════════════════════════════════════

type ConcreteCatbirdClient =
    CatbirdClient<StorageAdapter, APIAdapter, CredentialAdapter, MLSContext>;

// ═══════════════════════════════════════════════════════════════════════════
// CatbirdMls — the unified API object
// ═══════════════════════════════════════════════════════════════════════════

/// Unified MLS API surface for Catbird.
///
/// `CatbirdMls` is the single entry point for all MLS operations across
/// Swift (iOS/macOS), Kotlin (Android), Python, and TypeScript/WASM.
///
/// It combines:
/// - **Lifecycle** — database management, suspension, checkpoints
/// - **Conversations** — create, list, leave
/// - **Messaging** — send, receive, fetch history
/// - **Members** — add/remove participants
/// - **Key Packages** — create, replenish, stats
/// - **Devices** — register, list, remove
/// - **Sync/Recovery** — server sync, force rejoin
/// - **MLS Escape Hatch** — direct access to epochs, encryption, commits
/// - **Debug** — group member inspection, key package diagnostics
///
/// ## Quickstart
/// ```ignore
/// let mls = CatbirdMls::new(user_did, storage_path, encryption_key, keychain,
///     storage, api_client, credentials, config)?;
/// mls.initialize()?;
/// let convos = mls.conversations()?;
/// mls.send_message(convo_id, "Hello!".into())?;
/// mls.shutdown();
/// ```
#[derive(uniffi::Object)]
pub struct CatbirdMls {
    /// Low-level MLS context for lifecycle and escape-hatch operations.
    mls_context: Arc<MLSContext>,
    /// High-level client wrapping the orchestrator.
    client: ConcreteCatbirdClient,
}

#[uniffi::export]
impl CatbirdMls {
    // ═══════════════════════════════════════════════════════════════════════
    // Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Create a new CatbirdMls instance.
    ///
    /// This creates the MLS context, orchestrator, and high-level client in one step.
    /// The instance is fully initialized and ready to use after construction:
    /// device registration and key package replenishment happen automatically.
    ///
    /// - `user_did`: The authenticated user's DID
    /// - `storage_path`: Per-user SQLite database path (e.g. `{appSupport}/mls-state/{did_hash}.db`)
    /// - `encryption_key`: SQLCipher encryption key
    /// - `keychain`: Platform keychain access callback
    /// - `storage`: Platform storage backend callback
    /// - `api_client`: Platform API client callback
    /// - `credentials`: Platform credential store callback
    /// - `config`: Orchestrator configuration
    #[uniffi::constructor]
    pub fn new(
        user_did: String,
        storage_path: String,
        encryption_key: String,
        keychain: Box<dyn KeychainAccess>,
        storage: Box<dyn OrchestratorStorageCallback>,
        api_client: Box<dyn OrchestratorAPICallback>,
        credentials: Box<dyn OrchestratorCredentialCallback>,
        config: FFIOrchestratorConfig,
    ) -> Result<Arc<Self>, OrchestratorBridgeError> {
        // Create the low-level MLS context
        let mls_context = MLSContext::new(storage_path, encryption_key, keychain)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })?;

        let orch_config = OrchestratorConfig {
            max_devices: config.max_devices,
            target_key_package_count: config.target_key_package_count,
            key_package_replenish_threshold: config.key_package_replenish_threshold,
            sync_cooldown_seconds: config.sync_cooldown_seconds,
            max_consecutive_sync_failures: config.max_consecutive_sync_failures,
            sync_pause_duration_seconds: config.sync_pause_duration_seconds,
            rejoin_cooldown_seconds: config.rejoin_cooldown_seconds,
            max_rejoin_attempts: config.max_rejoin_attempts,
            group_config: crate::GroupConfig::default(),
        };

        // Create the high-level client (internally creates orchestrator, initializes, registers device)
        let client = crate::async_runtime::block_on(CatbirdClient::create(
            user_did,
            mls_context.clone(),
            Arc::new(StorageAdapter(Arc::from(storage))),
            Arc::new(APIAdapter(Arc::from(api_client))),
            Arc::new(CredentialAdapter(Arc::from(credentials))),
            orch_config,
        ))
        .map_err(OrchestratorBridgeError::from)?;

        Ok(Arc::new(Self {
            mls_context,
            client,
        }))
    }

    /// Create a CatbirdMls from an existing MLSContext.
    ///
    /// Use this when you need to share an MLSContext (e.g., for epoch secret storage
    /// or credential validator setup before creating the unified API).
    #[uniffi::constructor]
    pub fn with_context(
        user_did: String,
        mls_context: Arc<MLSContext>,
        storage: Box<dyn OrchestratorStorageCallback>,
        api_client: Box<dyn OrchestratorAPICallback>,
        credentials: Box<dyn OrchestratorCredentialCallback>,
        config: FFIOrchestratorConfig,
    ) -> Result<Arc<Self>, OrchestratorBridgeError> {
        let orch_config = OrchestratorConfig {
            max_devices: config.max_devices,
            target_key_package_count: config.target_key_package_count,
            key_package_replenish_threshold: config.key_package_replenish_threshold,
            sync_cooldown_seconds: config.sync_cooldown_seconds,
            max_consecutive_sync_failures: config.max_consecutive_sync_failures,
            sync_pause_duration_seconds: config.sync_pause_duration_seconds,
            rejoin_cooldown_seconds: config.rejoin_cooldown_seconds,
            max_rejoin_attempts: config.max_rejoin_attempts,
            group_config: crate::GroupConfig::default(),
        };

        let client = crate::async_runtime::block_on(CatbirdClient::create(
            user_did,
            mls_context.clone(),
            Arc::new(StorageAdapter(Arc::from(storage))),
            Arc::new(APIAdapter(Arc::from(api_client))),
            Arc::new(CredentialAdapter(Arc::from(credentials))),
            orch_config,
        ))
        .map_err(OrchestratorBridgeError::from)?;

        Ok(Arc::new(Self {
            mls_context,
            client,
        }))
    }

    /// Shut down the client, releasing orchestrator resources.
    /// Does NOT close the database — call `flush_and_prepare_close()` for that.
    pub fn shutdown(&self) {
        crate::async_runtime::block_on(self.client.shutdown());
    }

    /// Flush all pending database writes and CLOSE the database connections.
    ///
    /// CRITICAL FOR 0xdead10cc PREVENTION on iOS: call this when transitioning
    /// to background/inactive state. After calling, the MLS context is closed
    /// and cannot be used for operations — create a new `CatbirdMls` if needed.
    pub fn flush_and_prepare_close(&self) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .flush_and_prepare_close()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Perform a launch-time TRUNCATE checkpoint to clear leftover WAL.
    /// Call once at app startup. Safe to call even if context was just created.
    pub fn launch_checkpoint(&self) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .launch_checkpoint()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Check if the underlying MLS context has been closed.
    pub fn is_closed(&self) -> bool {
        self.mls_context.is_closed()
    }

    /// Sync the database (flush + checkpoint).
    pub fn sync_database(&self) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .sync_database()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Get the current user's DID.
    pub fn user_did(&self) -> String {
        self.client.user_did().to_string()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the epoch secret storage backend.
    /// MUST be called during initialization before any MLS operations.
    pub fn set_epoch_secret_storage(
        &self,
        storage: Box<dyn EpochSecretStorage>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .set_epoch_secret_storage(storage)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Set the credential validator callback for client-side validation.
    pub fn set_credential_validator(
        &self,
        validator: Box<dyn CredentialValidator>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .set_credential_validator(validator)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Set the external join authorizer callback.
    pub fn set_external_join_authorizer(
        &self,
        authorizer: Box<dyn ExternalJoinAuthorizer>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .set_external_join_authorizer(authorizer)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Set the logging backend.
    pub fn set_logger(&self, logger: Box<dyn MLSLogger>) {
        self.mls_context.set_logger(logger);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Conversations (high-level, no MLS concepts exposed)
    // ═══════════════════════════════════════════════════════════════════════

    /// List all conversations for the current user.
    pub fn list_conversations(&self) -> Result<Vec<Conversation>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.conversations())
            .map_err(OrchestratorBridgeError::from)
    }

    /// Create a new conversation with optional name and initial participants.
    pub fn create_conversation(
        &self,
        name: Option<String>,
        participant_dids: Vec<String>,
    ) -> Result<Conversation, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.create_conversation(name, participant_dids))
            .map_err(OrchestratorBridgeError::from)
    }

    /// Leave a conversation.
    pub fn leave_conversation(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.leave_conversation(&conversation_id))
            .map_err(OrchestratorBridgeError::from)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Messaging (high-level)
    // ═══════════════════════════════════════════════════════════════════════

    /// Send a text message to a conversation.
    pub fn send_message(
        &self,
        conversation_id: String,
        text: String,
    ) -> Result<ChatMessage, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.send_message(&conversation_id, &text))
            .map_err(OrchestratorBridgeError::from)
    }

    /// Get message history for a conversation.
    pub fn messages(
        &self,
        conversation_id: String,
        limit: Option<i32>,
        before_sequence: Option<u64>,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.messages(
            &conversation_id,
            limit,
            before_sequence,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    /// Fetch new messages from the server for a conversation.
    pub fn fetch_new_messages(
        &self,
        conversation_id: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.fetch_new_messages(
            &conversation_id,
            cursor.as_deref(),
            limit,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    /// Update the read cursor for a conversation.
    pub fn update_cursor(
        &self,
        conversation_id: String,
        cursor: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.update_cursor(&conversation_id, &cursor))
            .map_err(OrchestratorBridgeError::from)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Members (high-level)
    // ═══════════════════════════════════════════════════════════════════════

    /// Add participants to an existing conversation.
    pub fn add_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.client
                .add_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    /// Remove participants from a conversation.
    pub fn remove_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.client
                .remove_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Key Packages
    // ═══════════════════════════════════════════════════════════════════════

    /// Create a single key package (low-level).
    pub fn create_key_package(
        &self,
        identity_bytes: Vec<u8>,
    ) -> Result<KeyPackageResult, OrchestratorBridgeError> {
        self.mls_context
            .create_key_package(identity_bytes)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Create multiple key packages in one call.
    pub fn create_key_packages_batch(
        &self,
        identity_bytes: Vec<u8>,
        count: u32,
    ) -> Result<Vec<KeyPackageResult>, OrchestratorBridgeError> {
        let mut results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let kp = self
                .mls_context
                .create_key_package(identity_bytes.clone())
                .map_err(|e| OrchestratorBridgeError::Mls {
                    message: e.to_string(),
                })?;
            results.push(kp);
        }
        Ok(results)
    }

    /// Check and replenish key packages if below threshold (orchestrator).
    pub fn replenish_key_packages_if_needed(&self) -> Result<(), OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        crate::async_runtime::block_on(orchestrator.replenish_if_needed())?;
        Ok(())
    }

    /// Get key package stats from the server (orchestrator).
    pub fn get_key_package_stats(&self) -> Result<FFIKeyPackageStats, OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        let stats = crate::async_runtime::block_on(orchestrator.get_key_package_stats())?;
        Ok(FFIKeyPackageStats {
            available: stats.available,
            total: stats.total,
        })
    }

    /// Get the count of locally available key package bundles.
    pub fn get_key_package_bundle_count(&self) -> Result<u64, OrchestratorBridgeError> {
        self.mls_context
            .get_key_package_bundle_count()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Devices (orchestrator)
    // ═══════════════════════════════════════════════════════════════════════

    /// Ensure the current device is registered with the MLS service.
    /// Returns the MLS DID for this device.
    pub fn ensure_device_registered(&self) -> Result<String, OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        let mls_did = crate::async_runtime::block_on(orchestrator.ensure_device_registered())?;
        Ok(mls_did)
    }

    /// List all registered devices.
    pub fn list_devices(&self) -> Result<Vec<FFIDeviceInfo>, OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        let devices = crate::async_runtime::block_on(orchestrator.list_devices())?;
        Ok(devices
            .into_iter()
            .map(|d| FFIDeviceInfo {
                device_id: d.device_id,
                mls_did: d.mls_did,
                device_uuid: d.device_uuid,
                created_at: d.created_at.map(|t| t.to_rfc3339()),
            })
            .collect())
    }

    /// Remove a device by ID.
    pub fn remove_device(&self, device_id: String) -> Result<(), OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        crate::async_runtime::block_on(orchestrator.remove_device(&device_id))?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Sync / Recovery
    // ═══════════════════════════════════════════════════════════════════════

    /// Sync conversations and messages with the server.
    pub fn sync(&self, full_sync: bool) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.client.sync(full_sync))
            .map_err(OrchestratorBridgeError::from)
    }

    // Task #43: `rejoin_conversation` and `force_rejoin` are no longer exposed on
    // the UniFFI surface. Client-initiated External Commits were the root cause of
    // production epoch inflation (epochs observed at 800+). Recovery moves to the
    // server via the A7 reset pyramid.

    /// Task #43: report unrecoverable local state to the server so the A7 reset
    /// pyramid can take over. Does not create External Commits.
    pub fn report_unrecoverable_local(
        &self,
        convo_id: String,
        reason: String,
    ) -> Result<(), OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        crate::async_runtime::block_on(
            orchestrator.report_unrecoverable_local(&convo_id, &reason),
        );
        Ok(())
    }

    /// Join a group via Welcome message (orchestrator).
    pub fn join_group(
        &self,
        welcome_data: Vec<u8>,
    ) -> Result<FFIConversationView, OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        let convo = crate::async_runtime::block_on(orchestrator.join_group(&welcome_data))?;
        Ok(convo_view_to_ffi(&convo))
    }

    /// Perform full silent recovery on multiple conversations.
    pub fn perform_silent_recovery(
        &self,
        conversation_ids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        let orchestrator = self.client.orchestrator();
        crate::async_runtime::block_on(orchestrator.perform_silent_recovery(&conversation_ids))?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MLS Escape Hatch — direct access to low-level MLS operations
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the current epoch for a group.
    pub fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, OrchestratorBridgeError> {
        self.mls_context
            .get_epoch(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Get the confirmation tag for a group.
    pub fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.mls_context
            .get_confirmation_tag(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Check if a group exists in local storage.
    pub fn group_exists(&self, group_id: Vec<u8>) -> bool {
        self.mls_context.group_exists(group_id)
    }

    /// Export group info for external commit.
    pub fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.mls_context
            .export_group_info(group_id, signer_identity_bytes)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Encrypt a message (raw MLS operation).
    pub fn encrypt_message_raw(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, OrchestratorBridgeError> {
        self.mls_context
            .encrypt_message(group_id, plaintext)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Decrypt a message (raw MLS operation).
    pub fn decrypt_message_raw(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, OrchestratorBridgeError> {
        self.mls_context
            .decrypt_message(group_id, ciphertext)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Process any MLS message (raw — handles commits, proposals, application messages).
    pub fn process_message_raw(
        &self,
        group_id: Vec<u8>,
        message_data: Vec<u8>,
    ) -> Result<ProcessedContent, OrchestratorBridgeError> {
        self.mls_context
            .process_message(group_id, message_data)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Create an external commit to join a group.
    pub fn create_external_commit(
        &self,
        group_info_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
    ) -> Result<ExternalCommitResult, OrchestratorBridgeError> {
        self.mls_context
            .create_external_commit(group_info_bytes, identity_bytes)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Merge a pending commit after server acknowledgment.
    pub fn merge_pending_commit(
        &self,
        group_id: Vec<u8>,
    ) -> Result<u64, OrchestratorBridgeError> {
        self.mls_context
            .merge_pending_commit(group_id)
            .map(|r| r.new_epoch)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Clear a pending commit (e.g., after server rejection).
    pub fn clear_pending_commit(
        &self,
        group_id: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .clear_pending_commit(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Discard a pending external join after server rejection.
    pub fn discard_pending_external_join(
        &self,
        group_id: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .discard_pending_external_join(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Create a self-update commit to refresh own leaf node.
    pub fn self_update(
        &self,
        group_id: Vec<u8>,
    ) -> Result<AddMembersResult, OrchestratorBridgeError> {
        self.mls_context
            .self_update(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Export the identity key pair for backup/recovery.
    pub fn export_identity_key(
        &self,
        identity: String,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.mls_context
            .export_identity_key(identity)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Import an identity key pair from backup/recovery.
    pub fn import_identity_key(
        &self,
        identity: String,
        key_data: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .import_identity_key(identity, key_data)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Sign arbitrary data with the identity key.
    pub fn sign_with_identity_key(
        &self,
        identity: String,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.mls_context
            .sign_with_identity_key(identity, data)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Validate group info format without joining.
    pub fn validate_group_info_format(&self, group_info_bytes: Vec<u8>) -> bool {
        self.mls_context
            .validate_group_info_format(group_info_bytes)
    }

    /// Process a Welcome message to join a group (low-level).
    pub fn process_welcome(
        &self,
        welcome_data: Vec<u8>,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, OrchestratorBridgeError> {
        self.mls_context
            .process_welcome(welcome_data, identity_bytes, config)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Create a group (low-level MLS operation).
    pub fn create_group_raw(
        &self,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, OrchestratorBridgeError> {
        self.mls_context
            .create_group(identity_bytes, config)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Add members to a group (low-level MLS operation).
    pub fn add_members_raw(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, OrchestratorBridgeError> {
        self.mls_context
            .add_members(group_id, key_packages)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Remove members from a group (low-level MLS operation).
    pub fn remove_members_raw(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, OrchestratorBridgeError> {
        self.mls_context
            .remove_members(group_id, member_identities)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Delete a group from local storage.
    pub fn delete_group(&self, group_id: Vec<u8>) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .delete_group(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Flush pending database writes to disk.
    pub fn flush_storage(&self) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .flush_storage()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Export epoch secret for the current epoch.
    pub fn export_epoch_secret(
        &self,
        group_id: Vec<u8>,
    ) -> Result<(), OrchestratorBridgeError> {
        self.mls_context
            .export_epoch_secret(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Get current metadata key for an already-joined group.
    /// Returns None if group not found or derivation fails.
    pub fn get_current_metadata(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Option<CurrentMetadataInfo>, OrchestratorBridgeError> {
        self.mls_context
            .get_current_metadata(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Process a commit message (low-level).
    pub fn process_commit(
        &self,
        group_id: Vec<u8>,
        commit_data: Vec<u8>,
    ) -> Result<ProcessCommitResult, OrchestratorBridgeError> {
        self.mls_context
            .process_commit(group_id, commit_data)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Debug
    // ═══════════════════════════════════════════════════════════════════════

    /// Get debug info about group members.
    pub fn debug_group_members(
        &self,
        group_id: Vec<u8>,
    ) -> Result<GroupDebugInfo, OrchestratorBridgeError> {
        self.mls_context
            .debug_group_members(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// List hashes of locally stored key package bundles.
    pub fn debug_list_key_package_hashes(&self) -> Result<Vec<String>, OrchestratorBridgeError> {
        self.mls_context
            .debug_list_key_package_hashes()
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Get debug state for a group as JSON string.
    pub fn get_group_debug_state(
        &self,
        group_id: Vec<u8>,
    ) -> Result<String, OrchestratorBridgeError> {
        self.mls_context
            .get_group_debug_state(group_id)
            .map_err(|e| OrchestratorBridgeError::Mls {
                message: e.to_string(),
            })
    }

    /// Get the underlying MLSContext (for advanced usage).
    /// Prefer using CatbirdMls methods directly.
    pub fn mls_context(&self) -> Arc<MLSContext> {
        self.mls_context.clone()
    }
}
