use base64::Engine as _;
use openmls::component::ComponentData;
use openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::messages::proposals_in::ProposalOrRefIn;
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use openmls_traits::storage::StorageProvider;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// Import StorageId to wrap public keys for storage
use openmls_basic_credential::StorageId;

use crate::error::MLSError;
use crate::mls_context::MLSContext as MLSContextInner;
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::types::*;

use crate::keychain::KeychainAccess;

// Helper function to safely truncate strings for display
fn truncate_str(s: &str, max_len: usize) -> &str {
    s.get(..max_len).unwrap_or(s)
}

/// Strip padding from ciphertext received from the server.
/// Format: [4-byte BE length][actual MLS ciphertext][zero padding...]
/// If the data doesn't appear padded, returns it unchanged (MLS handles trailing zeros).
fn strip_padding(data: &[u8]) -> Vec<u8> {
    if data.len() < 5 {
        crate::debug_log!(
            "[PADDING] strip_padding: data too small ({} bytes), returning as-is",
            data.len()
        );
        return data.to_vec();
    }
    let claimed_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // Length must be positive, fit within buffer, and the first byte after the
    // prefix must be a valid MLS wire format byte (0..=4).
    if claimed_len > 0 && claimed_len <= data.len() - 4 && matches!(data[4], 0x00..=0x04) {
        crate::debug_log!(
            "[PADDING] strip_padding: stripped padding, claimed_len={}, total={}, output={}",
            claimed_len,
            data.len(),
            claimed_len
        );
        data[4..4 + claimed_len].to_vec()
    } else {
        crate::debug_log!("[PADDING] strip_padding: no padding detected (claimed_len={}, total={}, byte4=0x{:02x}), returning as-is", claimed_len, data.len(), data.get(4).copied().unwrap_or(0xff));
        data.to_vec()
    }
}

/// Bucket sizes for traffic-analysis-resistant padding.
const BUCKET_SIZES: [usize; 5] = [512, 1024, 2048, 4096, 8192];

/// Pad ciphertext for sending to the server.
/// Format: [4-byte BE length][actual MLS ciphertext][zero padding to bucket]
/// Returns (padded_ciphertext, padded_size).
fn pad_ciphertext(ciphertext: &[u8]) -> (Vec<u8>, u32) {
    let actual_len = ciphertext.len();
    let total_needed = 4 + actual_len; // length prefix + ciphertext
    let bucket = BUCKET_SIZES
        .iter()
        .copied()
        .find(|&b| b >= total_needed)
        .unwrap_or_else(|| total_needed.div_ceil(8192) * 8192);

    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(actual_len as u32).to_be_bytes());
    padded.extend_from_slice(ciphertext);
    padded.resize(bucket, 0);
    (padded, bucket as u32)
}

fn current_metadata_reference_json(group: &MlsGroup) -> Option<Vec<u8>> {
    crate::metadata::current_metadata_reference_json(group)
}

fn compute_app_data_updates(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    committed_proposals: &[ProposalOrRefIn],
) -> Result<Option<AppDataUpdates>, MLSError> {
    let mut updater = group.app_data_dictionary_updater();
    let mut saw_app_data_update = false;

    for proposal_or_ref in committed_proposals.iter() {
        let validated = proposal_or_ref
            .clone()
            .validate(crypto, group.ciphersuite(), ProtocolVersion::default())
            .map_err(|e| MLSError::OpenMLS(format!("validate AppData proposal: {:?}", e)))?;

        let proposal: Box<Proposal> = match validated {
            ProposalOrRef::Proposal(proposal) => proposal,
            ProposalOrRef::Reference(reference) => group
                .proposal_store()
                .proposals()
                .find(|p| p.proposal_reference_ref() == &*reference)
                .map(|p| Box::new(p.proposal().clone()))
                .ok_or_else(|| MLSError::OpenMLS("AppData proposal reference missing".into()))?,
        };

        let Proposal::AppDataUpdate(app_data_update) = *proposal else {
            continue;
        };

        saw_app_data_update = true;
        match app_data_update.operation() {
            AppDataUpdateOperation::Update(data) => updater.set(ComponentData::from_parts(
                app_data_update.component_id(),
                data.clone(),
            )),
            AppDataUpdateOperation::Remove => updater.remove(&app_data_update.component_id()),
        }
    }

    Ok(if saw_app_data_update {
        updater.changes()
    } else {
        None
    })
}

fn process_protocol_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    protocol_msg: ProtocolMessage,
    context: &str,
) -> Result<ProcessedMessage, MLSError> {
    let unverified_message = group
        .unprotect_message(provider, protocol_msg)
        .map_err(|e| {
            crate::error_log!("[{}] Failed to unprotect message: {:?}", context, e);
            MLSError::OpenMLS(format!("unprotect_message failed: {:?}", e))
        })?;

    let app_data_updates =
        if let Some(committed_proposals) = unverified_message.committed_proposals() {
            compute_app_data_updates(group, provider.crypto(), committed_proposals)?
        } else {
            None
        };

    group
        .process_unverified_message_with_app_data_updates(
            provider,
            unverified_message,
            app_data_updates,
        )
        .map_err(|e| {
            crate::error_log!("[{}] Failed to process message: {:?}", context, e);
            MLSError::OpenMLS(format!("process_message failed: {:?}", e))
        })
}

/// MLS context wrapper for FFI
///
/// Uses Mutex instead of RwLock because:
/// - SQLite Connection uses RefCell (requires Send but not Sync)
/// - Swift actor provides higher-level synchronization
/// - Per-DID contexts are isolated (no shared state across accounts)
#[derive(uniffi::Object)]
pub struct MLSContext {
    /// Inner context wrapped in Option to allow taking/dropping for database close.
    /// When close_database() is called, this is set to None to drop the inner
    /// and release all SQLite file handles (critical for 0xdead10cc prevention).
    inner: Arc<Mutex<Option<MLSContextInner>>>,
    credential_validator: Arc<Mutex<Option<Arc<dyn CredentialValidator>>>>,
    external_join_authorizer: Arc<Mutex<Option<Arc<dyn ExternalJoinAuthorizer>>>>,
    /// SQLCipher interrupt handles stored OUTSIDE the inner Mutex.
    /// This allows calling sqlite3_interrupt() from any thread even when another thread
    /// holds the Mutex for an in-flight FFI operation. Critical for 0xdead10cc prevention:
    /// interrupting in-flight ops lets flush_and_prepare_close acquire the lock promptly.
    interrupt_handles: Vec<rusqlite::InterruptHandle>,
    /// Suspension flag stored OUTSIDE the Mutex for cheap atomic checks.
    /// When true, long-running operations (key package creation, write_manifest)
    /// should bail out early to release the Mutex and file locks before iOS suspends.
    is_suspended: Arc<AtomicBool>,
    /// Pending incoming `StagedCommit`s awaiting platform confirmation (task #33).
    ///
    /// When `process_message`/`decrypt_message`/`process_message_async`/`process_commit`
    /// receive a `StagedCommitMessage` from another member, the commit is **staged** here
    /// (keyed by `(group_id, target_epoch)`) instead of being auto-merged. The receiving
    /// platform is responsible for:
    ///   - calling [`merge_incoming_commit`] once it has validated the commit and is
    ///     ready to advance the local epoch, OR
    ///   - calling [`discard_incoming_commit`] to drop the staged commit without merging.
    ///
    /// This preserves RFC 9420 §14 intent: receiver state must not advance until the
    /// caller confirms. The legacy auto-merge path is still available via
    /// [`process_message_legacy_automerge`] during the cross-platform migration.
    ///
    /// **Duplicate delivery policy:** if a staged commit already exists for the same
    /// `(group_id, target_epoch)` when a new one arrives (duplicate/retransmit), the
    /// new entry **overwrites** the prior one and a warning is logged. This is
    /// idempotent: OpenMLS produces the same StagedCommit for the same wire message.
    pending_incoming_merges: Arc<Mutex<HashMap<(Vec<u8>, u64), Box<StagedCommit>>>>,
    /// Staged-but-not-yet-confirmed **outgoing** commits produced by
    /// [`MLSContext::stage_commit`] (task #62). Keyed by hex group id — MLS
    /// allows at most one pending commit per group, so a second stage call
    /// on the same group is rejected until the caller confirms or discards
    /// the existing handle.
    ///
    /// This mirrors `MLSOrchestrator::pending_staged_commits` so that
    /// platforms calling MLSContext directly (iOS MLSClient, catmos-cli)
    /// can use the same three-phase semantics without adopting the
    /// orchestrator. The two registries are **independent**: confirming a
    /// commit through one path does not affect the other's bookkeeping.
    /// This is safe because a single group is only ever driven by one of
    /// the two paths in a given client (iOS/catmos-cli use MLSContext
    /// directly; Android/Tauri/web use OrchestratorBridge).
    pending_outgoing_commits: Arc<Mutex<HashMap<String, PendingOutgoingCommitMeta>>>,
    /// Monotonic nonce for outgoing staged-commit handles.
    staged_commit_nonce: Arc<AtomicU64>,
}

/// Internal bookkeeping for an MLSContext-level staged outgoing commit.
///
/// Mirrors `crate::orchestrator::orchestrator::PendingCommitMeta` but is
/// scoped to MLSContext; we duplicate the type rather than share across the
/// FFI/orchestrator boundary so that std / tokio mutex choices and async
/// contexts don't bleed across layers (task #62).
#[derive(Debug, Clone)]
struct PendingOutgoingCommitMeta {
    /// Nonce that must match the handle passed to `confirm_commit` or
    /// `discard_pending`.
    nonce: u64,
    /// Epoch captured before the commit was constructed.
    source_epoch: u64,
    /// Epoch the group will advance to on confirm (`source_epoch + 1`).
    target_epoch: u64,
}

impl Drop for MLSContext {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(ref inner) = *guard {
                let _ = inner.flush_database();
            }
            // Take the inner to drop it and close database connections
            *guard = None;
        }
    }
}

#[uniffi::export]
impl MLSContext {
    /// Create a new context with per-DID SQLite storage
    ///
    /// Path should be unique per account, e.g., "{appSupport}/mls-state/{did_hash}.db"
    /// This stores MLS cryptographic state only - use SQLCipher separately for user content.
    ///
    /// The SQLite connection is single-threaded (uses RefCell internally).
    /// Synchronization is provided by Swift's actor system at a higher level.
    #[uniffi::constructor]
    pub fn new(
        storage_path: String,
        encryption_key: String,
        keychain: Box<dyn KeychainAccess>,
    ) -> Result<Arc<Self>, MLSError> {
        let (context, interrupt_handles) =
            MLSContextInner::new(storage_path, encryption_key, keychain)?;
        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(Some(context))),
            credential_validator: Arc::new(Mutex::new(None)),
            external_join_authorizer: Arc::new(Mutex::new(None)),
            interrupt_handles,
            is_suspended: Arc::new(AtomicBool::new(false)),
            pending_incoming_merges: Arc::new(Mutex::new(HashMap::new())),
            pending_outgoing_commits: Arc::new(Mutex::new(HashMap::new())),
            staged_commit_nonce: Arc::new(AtomicU64::new(0)),
        }))
    }

    /// Set the epoch secret storage backend
    ///
    /// This MUST be called during initialization before any MLS operations.
    /// The storage implementation should persist epoch secrets in encrypted storage (SQLCipher).
    pub fn set_epoch_secret_storage(
        &self,
        storage: Box<dyn EpochSecretStorage>,
    ) -> Result<(), MLSError> {
        crate::info_log!(
            "[MLS-FFI] set_epoch_secret_storage: Setting epoch secret storage backend"
        );

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        inner
            .epoch_secret_manager()
            .set_storage(Arc::from(storage))?;
        crate::info_log!("[MLS-FFI] set_epoch_secret_storage: Complete");

        Ok(())
    }

    /// Interrupt all in-flight SQLCipher operations on this context.
    ///
    /// Safe to call from any thread — does NOT require the inner Mutex.
    /// Causes any running sqlite3_step/sqlite3_exec to return SQLITE_INTERRUPT.
    /// The interrupted operation will release the Mutex, allowing flush_and_prepare_close
    /// to acquire it promptly.
    ///
    /// Call this BEFORE flush_and_prepare_close to avoid blocking on the Mutex
    /// while an in-flight FFI operation holds it (which causes 0xdead10cc).
    pub fn interrupt(&self) {
        crate::info_log!(
            "[MLS-FFI] interrupt: Sending sqlite3_interrupt to {} connection(s)",
            self.interrupt_handles.len()
        );
        for handle in &self.interrupt_handles {
            handle.interrupt();
        }
    }

    /// Set the suspension flag. When true, long-running operations bail out early
    /// to release the Mutex and file locks before iOS suspends the process.
    /// Safe to call from any thread — uses atomic store.
    pub fn set_suspended(&self, value: bool) {
        self.is_suspended.store(value, Ordering::Release);
    }

    /// Check if suspension has been requested. Returns MLSError::ContextClosed if so.
    fn check_suspended(&self) -> Result<(), MLSError> {
        if self.is_suspended.load(Ordering::Acquire) {
            Err(MLSError::ContextClosed)
        } else {
            Ok(())
        }
    }

    /// Flush all pending database writes and CLOSE the database connections.
    ///
    /// CRITICAL FOR 0xdead10cc PREVENTION: This method MUST be called when iOS
    /// is transitioning to background/inactive state. It:
    /// 1. Interrupts any in-flight SQLCipher operations (unblocks the Mutex)
    /// 2. Flushes all pending SQLite writes to disk
    /// 3. Performs WAL checkpoint to consolidate data
    /// 4. CLOSES all database connections by dropping the inner context
    /// 5. Releases all file handles so iOS doesn't kill the app
    ///
    /// After calling this, the context is CLOSED and cannot be used for any operations.
    /// The Swift side must create a new context if MLS operations are needed again.
    pub fn flush_and_prepare_close(&self) -> Result<(), MLSError> {
        let pid = std::process::id();
        let is_extension = std::env::current_exe()
            .map(|p| p.to_string_lossy().contains(".appex/"))
            .unwrap_or(false);
        let process_tag = if is_extension { "NSE" } else { "APP" };

        crate::info_log!(
            "[MLS-FFI/{}/pid={}] flush_and_prepare_close: Starting graceful shutdown",
            process_tag,
            pid
        );

        // Set suspension flag so in-flight operations bail out early at their next check point.
        self.is_suspended.store(true, Ordering::Release);

        // CRITICAL FIX: Interrupt first to abort any in-flight SQLCipher operations.
        // Without this, if another thread holds self.inner.lock() during a long SQLCipher
        // pread/pwrite, we'd block here until it completes — but iOS may kill us first
        // with 0xdead10cc because the file locks are still held.
        self.interrupt();

        // Try to acquire the lock. After interrupt, the in-flight op should return
        // SQLITE_INTERRUPT quickly, releasing the Mutex.
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;

        // Get the inner context (if it exists)
        if let Some(ref inner) = *guard {
            // Flush the manifest storage (WAL checkpoint - PASSIVE mode)
            let _ = inner.flush_database();
            crate::info_log!(
                "[MLS-FFI/{}/pid={}] flush_and_prepare_close: Database flushed (PASSIVE)",
                process_tag,
                pid
            );
        }

        // CRITICAL: Take and drop the inner context to CLOSE all database connections
        // This releases the SQLite file handles that cause 0xdead10cc
        let dropped = guard.take();
        if dropped.is_some() {
            crate::info_log!(
                "[MLS-FFI/{}/pid={}] flush_and_prepare_close: ✅ Inner context DROPPED - database connections CLOSED",
                process_tag,
                pid
            );
        } else {
            crate::info_log!(
                "[MLS-FFI/{}/pid={}] flush_and_prepare_close: Inner context was already closed",
                process_tag,
                pid
            );
        }

        Ok(())
    }

    /// Perform a launch-time TRUNCATE checkpoint to clear leftover WAL.
    /// Call once at app startup. Safe to call even if context was just created.
    /// Tolerates SQLITE_BUSY gracefully.
    pub fn launch_checkpoint(&self) -> Result<(), MLSError> {
        crate::info_log!("[MLS-FFI] launch_checkpoint: Starting launch TRUNCATE checkpoint");

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        inner.launch_checkpoint()
    }

    /// Check if this context has been closed.
    /// Returns true if close_database() or flush_and_prepare_close() has been called.
    pub fn is_closed(&self) -> bool {
        if let Ok(guard) = self.inner.lock() {
            guard.is_none()
        } else {
            true // Treat poisoned mutex as closed
        }
    }

    /// Set the credential validator callback for client-side validation
    ///
    /// This enables the Swift layer to validate credentials before accepting
    /// group state changes. The validator is called before merging commits.
    pub fn set_credential_validator(
        &self,
        validator: Box<dyn CredentialValidator>,
    ) -> Result<(), MLSError> {
        crate::info_log!("[MLS-FFI] set_credential_validator: Setting credential validator");

        let mut validator_lock = self
            .credential_validator
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;

        *validator_lock = Some(Arc::from(validator));
        crate::info_log!("[MLS-FFI] set_credential_validator: Complete");

        Ok(())
    }

    pub fn set_external_join_authorizer(
        &self,
        authorizer: Box<dyn ExternalJoinAuthorizer>,
    ) -> Result<(), MLSError> {
        let mut auth_lock = self
            .external_join_authorizer
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        *auth_lock = Some(Arc::from(authorizer));
        Ok(())
    }

    pub fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(signer_identity_bytes)
            .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;

        inner.export_group_info(&group_id, &identity)
    }

    pub fn create_external_commit(
        &self,
        group_info_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(identity_bytes)
            .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;

        let (commit_data, group_id, group_info) =
            inner.create_external_commit(&group_info_bytes, &identity)?;

        Ok(ExternalCommitResult {
            commit_data,
            group_id,
            group_info,
        })
    }

    pub fn create_external_commit_with_psk(
        &self,
        group_info_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
        psk_bytes: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(identity_bytes)
            .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;

        let (commit_data, group_id) =
            inner.create_external_commit_with_psk(&group_info_bytes, &identity, &psk_bytes)?;

        Ok(ExternalCommitResult {
            commit_data,
            group_id,
            group_info: None, // PSK path doesn't export GroupInfo yet
        })
    }

    /// Discard a pending external join after server rejection
    ///
    /// CRITICAL: Call this when the delivery service rejects an external commit.
    /// Failure to call this leaves orphaned cryptographic material.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier from create_external_commit result
    ///
    /// # Returns
    /// Ok(()) on success, error if group not found
    pub fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.check_suspended()?;
        crate::info_log!("[MLS-FFI] discard_pending_external_join: Starting cleanup");

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        inner.discard_pending_external_join(&group_id)?;

        crate::info_log!("[MLS-FFI] discard_pending_external_join: Complete");
        Ok(())
    }

    pub fn create_group(
        &self,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.create_group_dispatch(identity_bytes, None, config)
    }

    /// FFI/native entry point for creating a group at a predetermined `group_id`
    /// (spec §8.5 first-responder bootstrap). `group_id` is the raw bytes of
    /// the target MLS group identifier (NOT hex-encoded). All bootstrap
    /// candidates targeting the same `groupResetEvent.newGroupId` MUST land on
    /// the same MLS GroupId so the race winner's Welcome can deserialize for
    /// every recipient.
    pub fn create_group_with_id(
        &self,
        identity_bytes: Vec<u8>,
        group_id: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.create_group_dispatch(identity_bytes, Some(group_id), config)
    }

    fn create_group_dispatch(
        &self,
        identity_bytes: Vec<u8>,
        predetermined_group_id: Option<Vec<u8>>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] create_group: Starting{}",
            if predetermined_group_id.is_some() {
                " (predetermined group_id)"
            } else {
                ""
            }
        );
        crate::debug_log!("[MLS-FFI] Identity bytes: {} bytes", identity_bytes.len());

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire write lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(identity_bytes).map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Invalid UTF-8 in identity: {:?}", e);
            MLSError::invalid_input("Invalid UTF-8")
        })?;
        crate::debug_log!("[MLS-FFI] Identity: {}", identity);

        let group_config = config.unwrap_or_default();
        crate::debug_log!("[MLS-FFI] Group config - max_past_epochs: {}, out_of_order_tolerance: {}, maximum_forward_distance: {}",
            group_config.max_past_epochs, group_config.out_of_order_tolerance, group_config.maximum_forward_distance);

        let result = match predetermined_group_id {
            Some(id) => inner.create_group_with_id(&identity, id, group_config)?,
            None => inner.create_group(&identity, group_config)?,
        };
        crate::info_log!(
            "[MLS-FFI] Group created successfully, ID: {}",
            hex::encode(&result.group_id)
        );

        // 🔒 CRITICAL: Force database flush after group creation
        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ WARNING: Failed to flush database after group creation: {:?}",
                e
            );
            e
        })?;

        // Signal-style budget checkpoint: keep WAL perpetually small
        inner.maybe_truncate_checkpoint();
        crate::debug_log!("[MLS-FFI] ✅ Database flushed after group creation");

        Ok(GroupCreationResult {
            group_id: result.group_id,
            encrypted_metadata_blob: result.encrypted_metadata_blob,
            metadata_reference_json: result.metadata_reference_json,
            metadata_blob_locator: result.metadata_blob_locator,
        })
    }

    /// Async variant of create_group - offloads crypto work to avoid blocking
    pub async fn create_group_async(
        &self,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.check_suspended()?;
        let inner = self.inner.clone();
        let suspended = self.is_suspended.clone();

        tokio::task::spawn_blocking(move || {
            crate::info_log!("[MLS-FFI-ASYNC] create_group_async: Starting");

            let mut guard = inner.lock().map_err(|e| {
                crate::error_log!(
                    "[MLS-FFI-ASYNC] ERROR: Failed to acquire write lock: {:?}",
                    e
                );
                MLSError::ContextNotInitialized
            })?;
            let inner_ctx = guard.as_mut().ok_or(MLSError::ContextClosed)?;

            let identity = String::from_utf8(identity_bytes)
                .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;

            let group_config = config.unwrap_or_default();
            let result = inner_ctx.create_group(&identity, group_config)?;

            if suspended.load(Ordering::Acquire) {
                return Err(MLSError::ContextClosed);
            }
            inner_ctx.flush_database().map_err(|e| {
                crate::error_log!("[MLS-FFI-ASYNC] ⚠️ Failed to flush database: {:?}", e);
                e
            })?;

            // Signal-style budget checkpoint: keep WAL perpetually small
            inner_ctx.maybe_truncate_checkpoint();

            crate::info_log!(
                "[MLS-FFI-ASYNC] Group created successfully: {}",
                hex::encode(&result.group_id)
            );

            Ok(GroupCreationResult {
                group_id: result.group_id,
                encrypted_metadata_blob: result.encrypted_metadata_blob,
                metadata_reference_json: result.metadata_reference_json,
                metadata_blob_locator: result.metadata_blob_locator,
            })
        })
        .await
        .map_err(|e| {
            crate::error_log!("[MLS-FFI-ASYNC] ERROR: spawn_blocking join error: {:?}", e);
            MLSError::OpenMLSError
        })?
    }

    pub fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        crate::debug_log!(
            "[MLS] add_members: Processing {} key packages",
            key_packages.len()
        );
        for (i, kp) in key_packages.iter().enumerate() {
            crate::debug_log!("[MLS] KeyPackage {}: {} bytes", i, kp.data.len());
        }

        // Deserialize key packages from TLS format
        // Try both MlsMessage-wrapped format and raw KeyPackage format
        let kps: Vec<KeyPackage> = key_packages
            .iter()
            .enumerate()
            .map(|(idx, kp_data)| {
                crate::debug_log!("[MLS] Deserializing key package {}: {} bytes, first 16 bytes = {:02x?}",
                    idx, kp_data.data.len(), &kp_data.data[..kp_data.data.len().min(16)]);

                // First try: MlsMessage-wrapped format (server might send this)
                if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&kp_data.data) {
                    crate::debug_log!("[MLS] Key package {} deserialized as MlsMessage", idx);
                    match mls_msg.extract() {
                        MlsMessageBodyIn::KeyPackage(kp_in) => {
                            crate::debug_log!("[MLS] Extracted KeyPackage from MlsMessage");
                            return kp_in.validate(inner.provider_crypto(), ProtocolVersion::default())
                                .map_err(|e| {
                                    crate::error_log!("[MLS] Key package {} validation failed: {:?}", idx, e);
                                    MLSError::InvalidKeyPackage
                                });
                        }
                        other => {
                            crate::debug_log!("[MLS] MlsMessage contained unexpected type: {:?}, trying raw format",
                                std::mem::discriminant(&other));
                        }
                    }
                }

                // Second try: Raw KeyPackage format
                crate::debug_log!("[MLS] Trying raw KeyPackage deserialization for key package {}", idx);
                let (kp_in, remaining) = KeyPackageIn::tls_deserialize_bytes(&kp_data.data)
                    .map_err(|e| {
                        crate::error_log!("[MLS] Both deserialization methods failed for key package {}: {:?}", idx, e);
                        MLSError::SerializationError
                    })?;

                crate::debug_log!("[MLS] Key package {} deserialized as raw KeyPackage ({} bytes remaining)", idx, remaining.len());

                // Validate the key package
                kp_in.validate(inner.provider_crypto(), ProtocolVersion::default())
                    .map_err(|e| {
                        crate::error_log!("[MLS] Key package {} validation failed: {:?}", idx, e);
                        MLSError::InvalidKeyPackage
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if kps.is_empty() {
            return Err(MLSError::InvalidKeyPackage);
        }

        // Deduplicate key packages by signature key.
        // Multiple uploads from the same device produce different hashes but identical
        // signature keys. OpenMLS requires unique signature keys in add_members proposals.
        let original_count = kps.len();
        let kps: Vec<KeyPackage> = {
            let mut seen_sig_keys = std::collections::HashSet::new();
            let mut deduped = Vec::new();
            for kp in kps {
                let sig_key_hex = hex::encode(kp.leaf_node().signature_key().as_slice());
                let identity_str =
                    String::from_utf8_lossy(kp.leaf_node().credential().serialized_content());
                if seen_sig_keys.insert(sig_key_hex.clone()) {
                    crate::debug_log!(
                        "[MLS-FFI] KeyPackage kept: identity={}, sig_key={}...",
                        identity_str,
                        &sig_key_hex[..sig_key_hex.len().min(16)]
                    );
                    deduped.push(kp);
                } else {
                    crate::warn_log!("[MLS-FFI] Dedup: dropping key package with duplicate signature key for {} (sig: {}...)",
                        identity_str, &sig_key_hex[..sig_key_hex.len().min(16)]);
                }
            }
            deduped
        };
        if kps.len() < original_count {
            crate::info_log!("[MLS-FFI] Deduplicated key packages by signature key: {} → {} (removed {} same-device duplicates)",
                original_count, kps.len(), original_count - kps.len());
        }

        if kps.is_empty() {
            crate::error_log!("[MLS-FFI] All key packages had duplicate signature keys - no valid packages remain");
            return Err(MLSError::InvalidKeyPackage);
        }

        let gid = GroupId::from_slice(&group_id);

        // 🔍 DEBUG: Inspect key package details for Welcome secrets debugging
        crate::debug_log!("[MLS-FFI] 🔍 Key package details:");
        for (idx, kp) in kps.iter().enumerate() {
            crate::debug_log!("[MLS-FFI]   KeyPackage[{}]:", idx);
            crate::debug_log!("[MLS-FFI]     - Cipher suite: {:?}", kp.ciphersuite());
            crate::debug_log!(
                "[MLS-FFI]     - Credential identity: {} bytes",
                kp.leaf_node().credential().serialized_content().len()
            );

            // Check key package capabilities - specifically extensions
            let kp_capabilities = kp.leaf_node().capabilities();
            let kp_extensions: Vec<String> = kp_capabilities
                .extensions()
                .iter()
                .map(|e| format!("{:?}", e))
                .collect();
            crate::debug_log!(
                "[MLS-FFI]     - Supported extensions: [{}]",
                kp_extensions.join(", ")
            );
        }

        let (commit_data, welcome_data) = inner.with_group(&gid, |group, provider, signer| {
            // 🔍 DEBUG: List ALL current group members
            crate::debug_log!("[MLS-FFI] 🔍 Current group members:");
            for (idx, member) in group.members().enumerate() {
                let credential = member.credential.serialized_content();
                let identity = String::from_utf8_lossy(credential);
                crate::debug_log!("[MLS-FFI]   Member[{}]: {}", idx, identity);
                crate::debug_log!("[MLS-FFI]            Raw credential: {}", hex::encode(credential));
            }

            // 🔍 DEBUG: Show FULL credentials of incoming key packages
            crate::debug_log!("[MLS-FFI] 🔍 Incoming key packages full credentials:");
            for (idx, kp) in kps.iter().enumerate() {
                let credential = kp.leaf_node().credential().serialized_content();
                let identity = String::from_utf8_lossy(credential);
                crate::debug_log!("[MLS-FFI]   KeyPackage[{}]: {}", idx, identity);
                crate::debug_log!("[MLS-FFI]                 Raw: {}", hex::encode(credential));
            }

            // 🔍 DEBUG: Check for duplicate credentials (self-add or duplicate member)
            if let Some(own_leaf) = group.own_leaf_node() {
                let own_credential = own_leaf.credential().serialized_content();

                for (idx, kp) in kps.iter().enumerate() {
                    let kp_credential = kp.leaf_node().credential().serialized_content();

                    if own_credential == kp_credential {
                        crate::error_log!("[MLS-FFI] ❌ DUPLICATE DETECTED: KeyPackage[{}] matches group creator!", idx);
                        crate::error_log!("[MLS-FFI]    This will cause OpenMLS to create empty Welcome with 0 secrets");
                        return Err(MLSError::invalid_input("Cannot add duplicate identity to group"));
                    }

                    // Check against all existing members
                    for (member_idx, member) in group.members().enumerate() {
                        let member_credential = member.credential.serialized_content();
                        if kp_credential == member_credential {
                            crate::error_log!("[MLS-FFI] ❌ DUPLICATE DETECTED: KeyPackage[{}] matches existing Member[{}]!", idx, member_idx);
                            return Err(MLSError::invalid_input("Member already in group"));
                        }
                    }
                }
            }

            // 🔍 DEBUG: Check group's required capabilities vs key packages
            crate::debug_log!("[MLS-FFI] 🔍 Group configuration:");
            crate::debug_log!("[MLS-FFI]   - Cipher suite: {:?}", group.ciphersuite());

            // Get the group's own leaf node capabilities
            if let Some(own_leaf) = group.own_leaf_node() {
                let own_capabilities = own_leaf.capabilities();
                let group_extensions: Vec<String> = own_capabilities.extensions()
                    .iter()
                    .map(|e| format!("{:?}", e))
                    .collect();
                crate::debug_log!("[MLS-FFI]   - Own leaf extensions: [{}]", group_extensions.join(", "));

                // Check for capability mismatch
                for (idx, kp) in kps.iter().enumerate() {
                    let kp_exts = kp.leaf_node().capabilities().extensions();
                    let own_exts = own_capabilities.extensions();

                    // Check if key package supports all extensions the group's leaf supports
                    for ext in own_exts.iter() {
                        if !kp_exts.contains(ext) {
                            crate::error_log!("[MLS-FFI]   ❌ CAPABILITY MISMATCH KeyPackage[{}]: Missing extension {:?}", idx, ext);
                            crate::error_log!("[MLS-FFI]      This may cause Welcome to have no secrets!");
                        }
                    }
                }
            }
            // 🔍 DEBUG: Get member count BEFORE adding
            let member_count_before = group.members().count();
            crate::debug_log!("[MLS-FFI] 🔍 DEBUG: Member count BEFORE add_members: {}", member_count_before);
            crate::debug_log!("[MLS-FFI] 🔍 DEBUG: Adding {} key packages", kps.len());

            let planned_reference_json = crate::metadata::planned_metadata_reference_json(
                crate::metadata::current_metadata_reference(group).as_ref(),
                crate::metadata::metadata_payload_from_group(group).is_some(),
                false,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

            let mut commit_builder = group.commit_builder().propose_adds(kps.iter().cloned());
            if let Some(ref_json) = planned_reference_json.clone() {
                commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }

            let mut commit_stage = commit_builder
                .load_psks(provider.storage())
                .map_err(|e| {
                    let msg = format!("add_members load_psks failed: {:?}", e);
                    crate::error_log!("[MLS-FFI] ❌ {}", msg);
                    MLSError::AddMembersFailed { message: msg }
                })?;

            if let Some(ref_json) = planned_reference_json {
                let mut updater = commit_stage.app_data_dictionary_updater();
                updater.set(ComponentData::from_parts(
                    crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                commit_stage.with_app_data_dictionary_updates(updater.changes());
            }

            let commit_bundle = commit_stage
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|e| {
                    let msg = format!("add_members build failed: {:?}", e);
                    crate::error_log!("[MLS-FFI] ❌ {}", msg);
                    MLSError::AddMembersFailed { message: msg }
                })?
                .stage_commit(provider)
                .map_err(|e| {
                    let msg = format!("add_members stage failed: {:?}", e);
                    crate::error_log!("[MLS-FFI] ❌ {}", msg);
                    MLSError::AddMembersFailed { message: msg }
                })?;

            let (commit, welcome, _group_info) = commit_bundle.into_contents();
            let welcome = welcome.ok_or_else(|| {
                crate::error_log!("[MLS-FFI] ❌ add_members staged commit produced no Welcome");
                MLSError::AddMembersFailed {
                    message: "add_members staged commit produced no Welcome".to_string(),
                }
            })?;

            // 🔍 DEBUG: Verify member count unchanged (expected behavior - commit is staged)
            let member_count_after = group.members().count();
            crate::debug_log!("[MLS-FFI] 🔍 DEBUG: Member count AFTER add_members (staged): {}", member_count_after);
            if member_count_after == member_count_before {
                crate::debug_log!("[MLS-FFI] ✅ Commit staged correctly (members not added until merge)");
            } else {
                crate::error_log!("[MLS-FFI] ❌ UNEXPECTED: Member count changed before merge! Before: {}, After: {}",
                    member_count_before, member_count_after);
            }

            // ✅ RATCHET DESYNC FIX: DO NOT merge commit here - use send-then-merge pattern
            // The commit MUST be sent to the server and acknowledged BEFORE merging locally.
            // Merging before server acknowledgment causes epoch mismatch and SecretReuseError:
            //   1. Client merges immediately → advances to epoch 1
            //   2. Server still at epoch 0
            //   3. Messages encrypted at epoch 1 can't be decrypted by recipients at epoch 0
            // The Welcome message contains all necessary secrets even without merging.
            // Swift layer will call mergePendingCommit() AFTER server confirmation.
            crate::debug_log!("[MLS-FFI] 🔄 Commit staged (NOT merged) - Swift layer will merge after server ACK");
            crate::debug_log!("[MLS-FFI] 📊 Current epoch: {} (will advance to {} after merge)", group.epoch().as_u64(), group.epoch().as_u64() + 1);

            // Serialize the commit (MlsMessageOut)
            let commit_bytes = commit
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;

            // ✅ CRITICAL FIX: Serialize Welcome WITH MlsMessage wrapper
            // The receiver expects MlsMessageIn format, not bare Welcome
            // Both commit and welcome should be serialized as MlsMessageOut
            crate::debug_log!("[MLS-FFI] 🔄 Serializing Welcome with MlsMessage wrapper");

            let welcome_message =
                MlsMessageOut::from_welcome(welcome.clone(), ProtocolVersion::default());
            let welcome_bytes = welcome_message
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;

            crate::debug_log!("[MLS-FFI] ✅ Welcome serialized with wrapper");

            // 🔍 DEBUG: Log key package hash_refs that the Welcome references
            // These are the hashes the RECEIVER must have in their local storage
            crate::info_log!("[MLS-WELCOME-DEBUG] 🔍 Welcome created for {} recipient(s):", kps.len());
            for (idx, kp) in kps.iter().enumerate() {
                if let Ok(href) = kp.hash_ref(provider.crypto()) {
                    crate::info_log!("[MLS-WELCOME-DEBUG]   Recipient[{}] key_package hash_ref (computed) = {}",
                        idx, hex::encode(href.as_slice()));
                }
                let identity = String::from_utf8_lossy(kp.leaf_node().credential().serialized_content());
                crate::info_log!("[MLS-WELCOME-DEBUG]   Recipient[{}] identity = {}", idx, identity);
                crate::info_log!("[MLS-WELCOME-DEBUG]   Recipient[{}] cipher_suite = {:?}", idx, kp.ciphersuite());
            }

            // 🔍 DEBUG: Log the actual hash_refs stored INSIDE the Welcome message
            // (these might differ from the computed ones above if something is wrong)
            let welcome_inner = welcome_message.body();
            if let MlsMessageBodyOut::Welcome(ref w) = welcome_inner {
                crate::info_log!("[MLS-WELCOME-DEBUG] 🔍 Welcome message contains {} encrypted group secrets:", w.secrets().len());
                for (idx, egs) in w.secrets().iter().enumerate() {
                    let embedded_ref = egs.new_member();
                    crate::info_log!("[MLS-WELCOME-DEBUG]   Welcome-Secret[{}] embedded hash_ref = {}",
                        idx, hex::encode(embedded_ref.as_slice()));
                }
            }

            // 🔍 DEBUG: Inspect Welcome message structure
            crate::debug_log!("[MLS-FFI] 🔍 Welcome message diagnosis:");
            crate::debug_log!("[MLS-FFI]   - Total size: {} bytes", welcome_bytes.len());
            crate::debug_log!("[MLS-FFI]   ✅ Welcome serialized for {} new member(s)", kps.len());

            Ok((commit_bytes, welcome_bytes))
        })?;

        Ok(AddMembersResult {
            commit_data,
            welcome_data,
        })
    }

    /// Remove members from the group (cryptographically secure)
    ///
    /// Creates a commit with Remove proposals. Follows send-then-merge pattern:
    /// caller must send commit to server and call merge_pending_commit() after ACK.
    ///
    /// # Security Note
    /// This is the ONLY secure way to remove members. Server-side removal
    /// does not revoke cryptographic access until the epoch advances.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `member_identities` - Array of member credentials (DID bytes) to remove
    ///
    /// # Returns
    /// Commit data to send to server (no welcome for removals)
    ///
    /// # Errors
    /// * `InvalidInput` - No valid members found to remove
    /// * `GroupNotFound` - Group does not exist
    /// * `OpenMLSError` - OpenMLS operation failed
    pub fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] remove_members: Removing {} members from group {}",
            member_identities.len(),
            hex::encode(&group_id)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        // Log member identities being removed
        for (i, identity) in member_identities.iter().enumerate() {
            crate::debug_log!(
                "[MLS-FFI] Member[{}]: {}",
                i,
                String::from_utf8_lossy(identity)
            );
        }

        let commit_data = inner.remove_members_internal(&group_id, &member_identities)?;

        crate::info_log!(
            "[MLS-FFI] remove_members: Complete, commit size: {} bytes",
            commit_data.len()
        );

        Ok(commit_data)
    }

    /// Atomically swap members: remove old + add new in a single commit.
    pub fn swap_members(
        &self,
        group_id: Vec<u8>,
        remove_identities: Vec<Vec<u8>>,
        add_key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] swap_members: {} removals + {} adds in group {}",
            remove_identities.len(),
            add_key_packages.len(),
            hex::encode(&group_id)
        );
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let kps: Vec<KeyPackage> = add_key_packages
            .iter()
            .enumerate()
            .map(|(idx, kp_data)| {
                if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&kp_data.data) {
                    match mls_msg.extract() {
                        MlsMessageBodyIn::KeyPackage(kp_in) => {
                            return kp_in
                                .validate(inner.provider_crypto(), ProtocolVersion::default())
                                .map_err(|e| {
                                    crate::error_log!(
                                        "[MLS-FFI] swap kp {} validate: {:?}",
                                        idx,
                                        e
                                    );
                                    MLSError::InvalidKeyPackage
                                });
                        }
                        _ => {}
                    }
                }
                let (kp_in, _) =
                    KeyPackageIn::tls_deserialize_bytes(&kp_data.data).map_err(|e| {
                        crate::error_log!("[MLS-FFI] swap kp {} deser: {:?}", idx, e);
                        MLSError::SerializationError
                    })?;
                kp_in
                    .validate(inner.provider_crypto(), ProtocolVersion::default())
                    .map_err(|e| {
                        crate::error_log!("[MLS-FFI] swap kp {} validate: {:?}", idx, e);
                        MLSError::InvalidKeyPackage
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if kps.is_empty() {
            return Err(MLSError::InvalidKeyPackage);
        }

        let kps: Vec<KeyPackage> = {
            let mut seen = std::collections::HashSet::new();
            kps.into_iter()
                .filter(|kp| seen.insert(hex::encode(kp.leaf_node().signature_key().as_slice())))
                .collect()
        };
        if kps.is_empty() {
            return Err(MLSError::InvalidKeyPackage);
        }

        let gid = GroupId::from_slice(&group_id);
        let (commit_data, welcome_data) = inner.with_group(&gid, |group, provider, signer| {
            let mut indices = Vec::new();
            for identity in &remove_identities {
                for member in group.members() {
                    if member.credential.serialized_content() == identity.as_slice() {
                        indices.push(member.index);
                        break;
                    }
                }
            }
            if indices.is_empty() {
                return Err(MLSError::invalid_input("No members found to remove"));
            }

            let planned_ref = crate::metadata::planned_metadata_reference_json(
                crate::metadata::current_metadata_reference(group).as_ref(),
                crate::metadata::metadata_payload_from_group(group).is_some(),
                false,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata ref: {:?}", e)))?;

            let mut cb = group
                .commit_builder()
                .propose_removals(indices)
                .propose_adds(kps.iter().cloned());
            if let Some(ref_json) = planned_ref.clone() {
                cb = cb.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }
            let mut cs =
                cb.load_psks(provider.storage())
                    .map_err(|e| MLSError::AddMembersFailed {
                        message: format!("swap load_psks: {:?}", e),
                    })?;
            if let Some(ref_json) = planned_ref {
                let mut u = cs.app_data_dictionary_updater();
                u.set(ComponentData::from_parts(
                    crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                cs.with_app_data_dictionary_updates(u.changes());
            }
            let bundle = cs
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|e| MLSError::AddMembersFailed {
                    message: format!("swap build: {:?}", e),
                })?
                .stage_commit(provider)
                .map_err(|e| MLSError::AddMembersFailed {
                    message: format!("swap stage: {:?}", e),
                })?;
            let (commit, welcome, _) = bundle.into_contents();
            let welcome = welcome.ok_or_else(|| MLSError::AddMembersFailed {
                message: "swap: no Welcome".into(),
            })?;
            let cb = commit
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;
            let wm = MlsMessageOut::from_welcome(welcome, ProtocolVersion::default());
            let wb = wm
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;
            Ok((cb, wb))
        })?;
        Ok(AddMembersResult {
            commit_data,
            welcome_data,
        })
    }

    /// Propose adding a member (does not commit)
    ///
    /// Creates a proposal that can be committed later with commit_pending_proposals.
    /// This enables multi-admin workflows where proposals accumulate before commit.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `key_package_data` - Serialized key package of member to add
    ///
    /// # Returns
    /// ProposeResult containing proposal message to send and reference for tracking
    pub fn propose_add_member(
        &self,
        group_id: Vec<u8>,
        key_package_data: Vec<u8>,
    ) -> Result<ProposeResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] propose_add_member: Creating add proposal for group {}",
            hex::encode(&group_id)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let (msg, ref_bytes) = inner.propose_add_internal(&group_id, &key_package_data)?;

        crate::info_log!(
            "[MLS-FFI] propose_add_member: Complete, message: {} bytes, ref: {} bytes",
            msg.len(),
            ref_bytes.len()
        );

        Ok(ProposeResult {
            proposal_message: msg,
            proposal_ref: ref_bytes,
        })
    }

    /// Propose removing a member (does not commit)
    ///
    /// Creates a proposal that can be committed later with commit_pending_proposals.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `member_identity` - DID bytes of member to remove
    ///
    /// # Returns
    /// ProposeResult containing proposal message to send and reference for tracking
    ///
    /// # Errors
    /// * `MemberNotFound` - Member not in group
    pub fn propose_remove_member(
        &self,
        group_id: Vec<u8>,
        member_identity: Vec<u8>,
    ) -> Result<ProposeResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] propose_remove_member: Creating remove proposal for {}",
            String::from_utf8_lossy(&member_identity)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let (msg, ref_bytes) = inner.propose_remove_internal(&group_id, &member_identity)?;

        crate::info_log!(
            "[MLS-FFI] propose_remove_member: Complete, message: {} bytes, ref: {} bytes",
            msg.len(),
            ref_bytes.len()
        );

        Ok(ProposeResult {
            proposal_message: msg,
            proposal_ref: ref_bytes,
        })
    }

    /// Propose self-update (does not commit)
    ///
    /// Creates a proposal to update your own leaf node. Can be committed later
    /// with commit_pending_proposals, or by another group member.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    ///
    /// # Returns
    /// ProposeResult containing proposal message to send and reference for tracking
    pub fn propose_self_update(&self, group_id: Vec<u8>) -> Result<ProposeResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] propose_self_update: Creating update proposal for group {}",
            hex::encode(&group_id)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let (msg, ref_bytes) = inner.propose_self_update_internal(&group_id)?;

        crate::info_log!(
            "[MLS-FFI] propose_self_update: Complete, message: {} bytes, ref: {} bytes",
            msg.len(),
            ref_bytes.len()
        );

        Ok(ProposeResult {
            proposal_message: msg,
            proposal_ref: ref_bytes,
        })
    }

    /// Async variant of add_members - offloads crypto work to avoid blocking
    pub async fn add_members_async(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        self.check_suspended()?;
        let inner = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            crate::debug_log!(
                "[MLS-ASYNC] add_members_async: Processing {} key packages",
                key_packages.len()
            );

            let mut guard = inner.lock().map_err(|_| MLSError::ContextNotInitialized)?;
            let inner_ctx = guard.as_mut().ok_or(MLSError::ContextClosed)?;

            // Deserialize and validate key packages
            let kps: Vec<KeyPackage> = key_packages
                .iter()
                .map(|kp_data| {
                    // Try MlsMessage-wrapped format first
                    if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&kp_data.data) {
                        if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
                            return kp_in
                                .validate(inner_ctx.provider_crypto(), ProtocolVersion::default())
                                .map_err(|_| MLSError::InvalidKeyPackage);
                        }
                    }

                    // Try raw KeyPackage format
                    let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(&kp_data.data)
                        .map_err(|_| MLSError::SerializationError)?;

                    kp_in
                        .validate(inner_ctx.provider_crypto(), ProtocolVersion::default())
                        .map_err(|_| MLSError::InvalidKeyPackage)
                })
                .collect::<Result<Vec<_>, _>>()?;

            if kps.is_empty() {
                return Err(MLSError::InvalidKeyPackage);
            }

            let gid = GroupId::from_slice(&group_id);

            let (commit_data, welcome_data) =
                inner_ctx.with_group(&gid, |group, provider, signer| {
                    let planned_reference_json = crate::metadata::planned_metadata_reference_json(
                        crate::metadata::current_metadata_reference(group).as_ref(),
                        crate::metadata::metadata_payload_from_group(group).is_some(),
                        false,
                    )
                    .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

                    let mut commit_builder =
                        group.commit_builder().propose_adds(kps.iter().cloned());
                    if let Some(ref_json) = planned_reference_json.clone() {
                        commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(
                            Box::new(AppDataUpdateProposal::update(
                                crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                                ref_json,
                            )),
                        ));
                    }

                    let mut commit_stage =
                        commit_builder.load_psks(provider.storage()).map_err(|e| {
                            crate::error_log!(
                                "[MLS-ASYNC] ERROR: add_members load_psks failed: {:?}",
                                e
                            );
                            MLSError::OpenMLSError
                        })?;

                    if let Some(ref_json) = planned_reference_json {
                        let mut updater = commit_stage.app_data_dictionary_updater();
                        updater.set(ComponentData::from_parts(
                            crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                            ref_json.into(),
                        ));
                        commit_stage.with_app_data_dictionary_updates(updater.changes());
                    }

                    let commit_bundle = commit_stage
                        .build(provider.rand(), provider.crypto(), signer, |_| true)
                        .map_err(|e| {
                            crate::error_log!(
                                "[MLS-ASYNC] ERROR: add_members build failed: {:?}",
                                e
                            );
                            MLSError::OpenMLSError
                        })?
                        .stage_commit(provider)
                        .map_err(|e| {
                            crate::error_log!(
                                "[MLS-ASYNC] ERROR: add_members stage failed: {:?}",
                                e
                            );
                            MLSError::OpenMLSError
                        })?;

                    let (commit, welcome, _) = commit_bundle.into_contents();
                    let welcome = welcome.ok_or(MLSError::OpenMLSError)?;

                    let commit_bytes = commit
                        .tls_serialize_detached()
                        .map_err(|_| MLSError::SerializationError)?;

                    let welcome_message =
                        MlsMessageOut::from_welcome(welcome, ProtocolVersion::default());
                    let welcome_bytes = welcome_message
                        .tls_serialize_detached()
                        .map_err(|_| MLSError::SerializationError)?;

                    Ok((commit_bytes, welcome_bytes))
                })?;

            crate::debug_log!("[MLS-ASYNC] add_members_async completed successfully");

            Ok(AddMembersResult {
                commit_data,
                welcome_data,
            })
        })
        .await
        .map_err(|e| {
            crate::error_log!("[MLS-ASYNC] ERROR: spawn_blocking join error: {:?}", e);
            MLSError::OpenMLSError
        })?
    }

    /// Export the identity key pair for backup/recovery
    /// This allows the application to store the identity key in a separate secure location (e.g. Keychain)
    /// to survive app deletion/reinstall.
    pub fn export_identity_key(&self, identity: String) -> Result<Vec<u8>, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let signer = inner
            .get_signer_for_identity(&identity)
            .ok_or_else(|| MLSError::invalid_input("Identity not found"))?;

        // Serialize the SignatureKeyPair
        serde_json::to_vec(&signer).map_err(|_| MLSError::SerializationError)
    }

    /// Import an identity key pair from backup/recovery
    /// This restores the identity key into the current storage provider
    pub fn import_identity_key(&self, identity: String, key_data: Vec<u8>) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let signer: SignatureKeyPair =
            serde_json::from_slice(&key_data).map_err(|_| MLSError::SerializationError)?;

        // Store in provider (HybridStorage will route to Keychain)
        // We need to extract the public key to use as the key
        // Assuming SignatureKeyPair has a .public() method or similar
        // OpenMLS SignatureKeyPair usually has .public() returning SignaturePublicKey

        // Use the provider's write method
        // Wrap the public key bytes in StorageId which implements SignaturePublicKey trait
        let storage_id = StorageId::from(signer.public().to_vec());
        inner
            .provider
            .storage()
            .write_signature_key_pair(&storage_id, &signer)
            .map_err(|_| MLSError::StorageFailed)?;

        // Register the signer mapping
        let public_key = signer.public().to_vec();
        inner.register_signer(&identity, public_key)?;

        Ok(())
    }

    /// Create a self-update commit to refresh own leaf node
    /// This forces epoch advancement and is useful for preventing ratchet desync
    /// when changing senders (prevents SecretReuseError from concurrent sends in same epoch)
    ///
    /// # Arguments
    /// * `group_id` - Group identifier to update
    ///
    /// # Returns
    /// Commit data to be sent to server (no welcome needed for self-updates)
    ///
    /// # Note
    /// This uses the send-then-merge pattern - caller must merge after server ACK
    pub fn self_update(&self, group_id: Vec<u8>) -> Result<AddMembersResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] self_update: Starting for group {}",
            hex::encode(&group_id)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        let commit_data = inner.with_group(&gid, |group, provider, signer| {
            crate::debug_log!("[MLS-FFI] Creating self-update commit at epoch {}", group.epoch().as_u64());

            let planned_reference_json = crate::metadata::planned_metadata_reference_json(
                crate::metadata::current_metadata_reference(group).as_ref(),
                crate::metadata::metadata_payload_from_group(group).is_some(),
                false,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

            let mut commit_builder = group
                .commit_builder()
                .force_self_update(true);

            if let Some(ref_json) = planned_reference_json.clone() {
                commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }

            let mut commit_stage = commit_builder
                .load_psks(provider.storage())
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ❌ self_update load_psks failed: {:?}", e);
                    MLSError::OpenMLSError
                })?;

            if let Some(ref_json) = planned_reference_json {
                let mut updater = commit_stage.app_data_dictionary_updater();
                updater.set(ComponentData::from_parts(
                    crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                commit_stage.with_app_data_dictionary_updates(updater.changes());
            }

            let commit_bundle = commit_stage
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ❌ self_update build failed: {:?}", e);
                    MLSError::OpenMLSError
                })?
                .stage_commit(provider)
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ❌ self_update stage failed: {:?}", e);
                    MLSError::OpenMLSError
                })?;

            let (commit, welcome_option, _group_info) = commit_bundle.into_contents();

            // ✅ RATCHET DESYNC FIX: DO NOT merge commit here - use send-then-merge pattern
            crate::debug_log!("[MLS-FFI] ✅ Self-update commit created (NOT merged) - Swift layer will merge after server ACK");
            crate::debug_log!("[MLS-FFI] 📊 Current epoch: {} (will advance to {} after merge)", group.epoch().as_u64(), group.epoch().as_u64() + 1);

            // Serialize commit
            let commit_bytes = commit
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;

            crate::debug_log!("[MLS-FFI] ✅ Self-update commit serialized: {} bytes", commit_bytes.len());

            // Self-updates typically don't produce a welcome (no new members)
            if welcome_option.is_some() {
                crate::warn_log!("[MLS-FFI] ⚠️ Unexpected: self_update produced a Welcome message");
            }

            Ok(commit_bytes)
        })?;

        crate::info_log!(
            "[MLS-FFI] self_update: Complete, commit size: {} bytes",
            commit_data.len()
        );

        Ok(AddMembersResult {
            commit_data,
            welcome_data: Vec::new(), // Self-updates don't produce welcomes
        })
    }

    /// Delete an MLS group from storage
    /// This should be called when a conversation is deleted or the user leaves
    pub fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);
        let group_id_hex = hex::encode(&group_id);

        crate::info_log!("[MLS-FFI] delete_group: Deleting group {}", group_id_hex);

        // Remove from groups HashMap using MLSContextInner method
        if inner.delete_group(gid.as_slice()) {
            crate::info_log!("[MLS-FFI] ✅ Removed group from context: {}", group_id_hex);
            Ok(())
        } else {
            crate::warn_log!("[MLS-FFI] ⚠️ Group not found in context: {}", group_id_hex);
            Err(MLSError::group_not_found(group_id_hex))
        }
    }

    /// Propose self-removal from a group.
    ///
    /// Groups use PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, so SelfRemove proposals
    /// (always PublicMessage) are rejected. Uses leave_group() instead which
    /// creates a Remove proposal as PrivateMessage.
    pub fn propose_self_remove(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.check_suspended()?;
        let group_id_hex = hex::encode(&group_id);
        crate::info_log!(
            "[MLS-FFI] propose_self_remove: Starting for group {}",
            group_id_hex
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        let proposal_bytes = inner.with_group(&gid, |group, provider, signer| {
            let proposal_msg = group.leave_group(provider, signer).map_err(|e| {
                crate::error_log!("[MLS-FFI] propose_self_remove: leave_group failed: {:?}", e);
                MLSError::OpenMLS(format!("leave_group failed: {:?}", e))
            })?;

            let bytes = proposal_msg
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;

            crate::info_log!(
                "[MLS-FFI] propose_self_remove: Created proposal ({} bytes) at epoch {}",
                bytes.len(),
                group.epoch().as_u64()
            );

            Ok(bytes)
        })?;

        Ok(proposal_bytes)
    }

    pub fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        self.check_suspended()?;
        crate::debug_log!("[MLS-FFI] encrypt_message: Starting");
        crate::debug_log!(
            "[MLS-FFI] Group ID: {} ({} bytes)",
            hex::encode(&group_id),
            group_id.len()
        );
        crate::debug_log!("[MLS-FFI] Plaintext size: {} bytes", plaintext.len());

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire write lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);
        crate::debug_log!("[MLS-FFI] GroupId created");

        let ciphertext = inner.with_group(&gid, |group, provider, signer| {
            // Secret tree state logging BEFORE encryption
            let epoch_before = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - encrypt_message");
            crate::debug_log!("[MLS-FFI]   Group: {}", hex::encode(&group_id));
            crate::debug_log!("[MLS-FFI]   Epoch before: {}", epoch_before);
            crate::debug_log!("[MLS-FFI]   Operation type: APPLICATION_MESSAGE");
            crate::debug_log!("[MLS-FFI]   Member count: {}", group.members().count());

            // 🔥 SIGNATURE KEY FORENSICS: Log the signature key being used to sign this message
            let signer_public_key = signer.public().to_vec();
            crate::info_log!("🔑 [SIGNATURE KEY FORENSICS - Message Signing]");
            crate::info_log!("   Public Signature Key (32 bytes): {}", hex::encode(&signer_public_key));
            crate::info_log!("   ⚠️  This is the ACTUAL key being used to SIGN the outgoing message");
            crate::info_log!("   ⚠️  Receiver will verify signature using this public key");

            crate::debug_log!("[MLS-FFI] Creating encrypted message...");
            let msg = group
                .create_message(provider, signer, &plaintext)
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ERROR: Failed to create message: {:?}", e);
                    crate::error_log!("[MLS-FFI] 🔐 SECRET TREE ERROR - encryption failed at epoch {}", epoch_before);
                    MLSError::EncryptionFailed
                })?;

            // Secret tree state logging AFTER encryption
            let epoch_after = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - after encryption");
            crate::debug_log!("[MLS-FFI]   Epoch after: {}", epoch_after);
            if epoch_after != epoch_before {
                crate::warn_log!("[MLS-FFI] ⚠️ UNEXPECTED: Epoch changed during encryption! Before: {}, After: {}", epoch_before, epoch_after);
            }
            crate::debug_log!("[MLS-FFI] Message created successfully");

            crate::debug_log!("[MLS-FFI] Serializing message...");
            msg.tls_serialize_detached()
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ERROR: Failed to serialize message: {:?}", e);
                    MLSError::SerializationError
                })
        })?;

        crate::debug_log!(
            "[MLS-FFI] encrypt_message: Completed successfully, ciphertext size: {} bytes",
            ciphertext.len()
        );
        let (padded, padded_size) = pad_ciphertext(&ciphertext);
        Ok(EncryptResult {
            ciphertext: padded,
            padded_size,
        })
    }

    /// Async variant of encrypt_message - offloads crypto work to avoid blocking
    pub async fn encrypt_message_async(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        self.check_suspended()?;
        let inner = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            crate::debug_log!("[MLS-FFI] encrypt_message_async: Starting on worker thread");
            crate::debug_log!("[MLS-FFI] Group ID: {} ({} bytes)", hex::encode(&group_id), group_id.len());
            crate::debug_log!("[MLS-FFI] Plaintext size: {} bytes", plaintext.len());

            let mut guard = inner.lock()
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ERROR: Failed to acquire write lock: {:?}", e);
                    MLSError::ContextNotInitialized
                })?;
            let inner_ctx = guard.as_mut().ok_or(MLSError::ContextClosed)?;

            let gid = GroupId::from_slice(&group_id);

            let ciphertext = inner_ctx.with_group(&gid, |group, provider, signer| {
                let epoch_before = group.epoch().as_u64();
                crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - encrypt_message_async");
                crate::debug_log!("[MLS-FFI]   Group: {}", hex::encode(&group_id));
                crate::debug_log!("[MLS-FFI]   Epoch before: {}", epoch_before);
                crate::debug_log!("[MLS-FFI]   Operation type: APPLICATION_MESSAGE");
                crate::debug_log!("[MLS-FFI]   Member count: {}", group.members().count());

                let signer_public_key = signer.public().to_vec();
                crate::info_log!("🔑 [SIGNATURE KEY FORENSICS - Message Signing (async)]");
                crate::info_log!("   Public Signature Key (32 bytes): {}", hex::encode(&signer_public_key));

                let msg = group
                    .create_message(provider, signer, &plaintext)
                    .map_err(|e| {
                        crate::error_log!("[MLS-FFI] ERROR: Failed to create message: {:?}", e);
                        MLSError::EncryptionFailed
                    })?;

                let epoch_after = group.epoch().as_u64();
                if epoch_after != epoch_before {
                    crate::warn_log!("[MLS-FFI] ⚠️ UNEXPECTED: Epoch changed during encryption! Before: {}, After: {}", epoch_before, epoch_after);
                }

                msg.tls_serialize_detached()
                    .map_err(|e| {
                        crate::error_log!("[MLS-FFI] ERROR: Failed to serialize message: {:?}", e);
                        MLSError::SerializationError
                    })
            })?;

            crate::debug_log!("[MLS-FFI] encrypt_message_async: Completed successfully, ciphertext size: {} bytes", ciphertext.len());
            let (padded, padded_size) = pad_ciphertext(&ciphertext);
            Ok(EncryptResult { ciphertext: padded, padded_size })
        })
        .await
        .map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: spawn_blocking join error: {:?}", e);
            MLSError::OpenMLSError
        })?
    }

    pub fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        self.check_suspended()?;
        // 🔍 DIAGNOSTIC: Thread tracking
        let thread_id = std::thread::current().id();
        let timestamp = std::time::SystemTime::now();

        crate::debug_log!(
            "[DECRYPT] 🧵 Thread {:?} starting decrypt_message at {:?}",
            thread_id,
            timestamp
        );
        crate::debug_log!(
            "[DECRYPT] Group ID: {} ({} bytes)",
            hex::encode(&group_id),
            group_id.len()
        );
        crate::debug_log!("[DECRYPT] Ciphertext size: {} bytes", ciphertext.len());
        crate::debug_log!(
            "[DECRYPT] Ciphertext first 32 bytes: {:02x?}",
            &ciphertext[..ciphertext.len().min(32)]
        );

        // 🔍 DIAGNOSTIC: Lock acquisition tracking
        crate::debug_log!(
            "[DECRYPT] 🔒 Thread {:?} attempting to acquire lock",
            thread_id
        );
        let lock_start = std::time::SystemTime::now();

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!(
                "[DECRYPT] ❌ Thread {:?} failed to acquire lock: {:?}",
                thread_id,
                e
            );
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let lock_duration = lock_start.elapsed().unwrap_or_default();
        crate::debug_log!(
            "[DECRYPT] ✅ Thread {:?} acquired lock (waited {:?})",
            thread_id,
            lock_duration
        );

        let gid = GroupId::from_slice(&group_id);

        // Capture epoch manager for staged commit auto-merge
        let epoch_manager = inner.epoch_secret_manager().clone();

        // Strip padding envelope before MLS deserialization
        let ciphertext = strip_padding(&ciphertext);

        // Deserialize to peek at message epoch for diagnostics (outside with_group)
        let (mls_msg, remaining) =
            MlsMessageIn::tls_deserialize_bytes(&ciphertext).map_err(|e| {
                crate::error_log!("[DECRYPT] ❌ Failed to deserialize MlsMessage: {:?}", e);
                MLSError::SerializationError
            })?;
        crate::debug_log!(
            "[DECRYPT] MlsMessage deserialized ({} bytes remaining)",
            remaining.len()
        );

        let protocol_msg: ProtocolMessage = mls_msg.try_into().map_err(|e| {
            crate::error_log!("[DECRYPT] ❌ Failed to convert to ProtocolMessage: {:?}", e);
            MLSError::DecryptionFailed
        })?;

        let message_epoch = protocol_msg.epoch().as_u64();

        // 🔍 DIAGNOSTIC: Replay detection check (using per-context storage)
        // Note: We can't extract generation without processing, so we track by epoch only for now
        {
            let group_history = inner
                .processed_messages
                .entry(group_id.clone())
                .or_insert_with(Vec::new);

            // Check if we've seen this exact epoch recently (simple replay detection)
            let recent_epochs: Vec<u64> = group_history.iter().map(|(e, _)| *e).collect();
            // Get current epoch from group for comparison
            let current_epoch = inner
                .groups
                .get(&group_id)
                .map(|gs| gs.group.epoch().as_u64())
                .unwrap_or(0);

            if recent_epochs.contains(&message_epoch) && message_epoch < current_epoch {
                crate::error_log!(
                    "[DECRYPT] 🔴 REPLAY SUSPECTED: Message from epoch {} was already processed!",
                    message_epoch
                );
                crate::error_log!("[DECRYPT]   Current epoch: {}", current_epoch);
                crate::error_log!("[DECRYPT]   Recent processed epochs: {:?}", recent_epochs);
            }

            crate::debug_log!(
                "[DECRYPT] Recently processed epochs for this group: {:?}",
                recent_epochs
            );
        }

        let (plaintext, epoch, sender_credential, staged_commit_opt): (Vec<u8>, u64, CredentialData, Option<Box<StagedCommit>>) = inner.with_group(&gid, |group, provider, _signer| {
            // 🔍 DIAGNOSTIC: Get current epoch and estimated generation BEFORE processing
            let current_epoch = group.epoch().as_u64();
            crate::info_log!("[DECRYPT] 📊 PRE-PROCESSING STATE:");
            crate::info_log!("[DECRYPT]   Group: {}", hex::encode(&group_id));
            crate::info_log!("[DECRYPT]   Current epoch: {}", current_epoch);
            crate::info_log!("[DECRYPT]   Thread: {:?}", thread_id);

            // 🔍 DIAGNOSTIC: Message metadata
            crate::info_log!("[DECRYPT] 📨 MESSAGE METADATA:");
            crate::info_log!("[DECRYPT]   Message epoch: {}", message_epoch);
            crate::info_log!("[DECRYPT]   Message wire format: {:?}", protocol_msg.wire_format());

            // 🔍 DIAGNOSTIC: Epoch mismatch check
            if message_epoch != current_epoch {
                crate::warn_log!("[DECRYPT] ⚠️ EPOCH MISMATCH DETECTED!");
                crate::warn_log!("[DECRYPT]   Message epoch: {}, Group epoch: {}", message_epoch, current_epoch);
                if message_epoch < current_epoch {
                    crate::warn_log!("[DECRYPT]   Message is from PAST epoch (likely replayed or delayed)");
                } else {
                    crate::warn_log!("[DECRYPT]   Message is from FUTURE epoch (group out of sync)");
                }
            }

            crate::debug_log!("[DECRYPT] 🔄 Calling OpenMLS process_message...");
            let process_start = std::time::SystemTime::now();

            let processed =
                process_protocol_message(group, provider, protocol_msg, "DECRYPT").map_err(|e| {
                    crate::error_log!("[DECRYPT] ❌ OpenMLS process_message FAILED!");
                    crate::error_log!("[DECRYPT]   Error: {:?}", e);
                    crate::error_log!("[DECRYPT]   Message epoch: {}", message_epoch);
                    crate::error_log!("[DECRYPT]   Group epoch: {}", current_epoch);

                    let error_str = format!("{:?}", e);
                    if error_str.contains("SecretReuse") {
                        crate::error_log!("[DECRYPT] 🔴 SECRET REUSE ERROR DETECTED!");
                        crate::error_log!("[DECRYPT]   This indicates either:");
                        crate::error_log!("[DECRYPT]   1. Message replay (same message processed twice)");
                        crate::error_log!("[DECRYPT]   2. Concurrent access (multiple threads racing)");
                        crate::error_log!("[DECRYPT]   3. Storage corruption (secret tree not persisted correctly)");
                    }

                    MLSError::DecryptionFailed
                })?;

            let process_duration = process_start.elapsed().unwrap_or_default();
            crate::debug_log!("[DECRYPT] ✅ OpenMLS process_message succeeded (took {:?})", process_duration);

            // 🔍 DIAGNOSTIC: Post-processing state
            let epoch_after = group.epoch().as_u64();
            crate::info_log!("[DECRYPT] 📊 POST-PROCESSING STATE:");
            crate::info_log!("[DECRYPT]   Epoch after: {}", epoch_after);
            if epoch_after != current_epoch {
                crate::warn_log!("[DECRYPT]   ⚠️ Epoch CHANGED during processing! {} -> {}", current_epoch, epoch_after);
            }

            // Extract sender credential BEFORE consuming the processed message
            let sender_cred = processed.credential().clone();
            let sender_credential = CredentialData {
                credential_type: format!("{:?}", sender_cred.credential_type()),
                identity: sender_cred.serialized_content().to_vec(),
            };
            crate::debug_log!("[DECRYPT] Sender credential extracted: {} bytes", sender_credential.identity.len());

            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app_msg) => {
                    let bytes = app_msg.into_bytes();
                    crate::debug_log!("[DECRYPT] ApplicationMessage processed: {} bytes", bytes.len());
                    if !bytes.is_empty() {
                        crate::debug_log!("[DECRYPT] Plaintext preview: {:?}", String::from_utf8_lossy(&bytes[..bytes.len().min(200)]));
                    }
                    Ok((bytes, message_epoch, sender_credential, None))
                },
                ProcessedMessageContent::ProposalMessage(prop) => {
                    crate::debug_log!("[DECRYPT] ProposalMessage received: {:?}", std::any::type_name_of_val(&prop));
                    Ok((vec![], message_epoch, sender_credential, None))
                },
                ProcessedMessageContent::ExternalJoinProposalMessage(ext) => {
                    crate::debug_log!("[DECRYPT] ExternalJoinProposalMessage received: {:?}", std::any::type_name_of_val(&ext));
                    Ok((vec![], message_epoch, sender_credential, None))
                },
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    // Task #33: stage the incoming commit instead of auto-merging.
                    // Platform must explicitly call `merge_incoming_commit(group_id, target_epoch)`
                    // to advance the epoch (or `discard_incoming_commit` to abandon).
                    let target_epoch = staged.group_context().epoch().as_u64();
                    crate::info_log!(
                        "[DECRYPT] StagedCommitMessage received - STAGING for explicit merge (target epoch {})",
                        target_epoch
                    );

                    // Export current epoch secret now (forward-secrecy window includes pre-merge epoch)
                    if let Err(e) = crate::async_runtime::block_on(
                        epoch_manager.export_current_epoch_secret(group, provider)
                    ) {
                        crate::warn_log!("[DECRYPT] ⚠️ Failed to export epoch secret before staging: {:?}", e);
                    }

                    // Return the staged commit in the 4th tuple slot; the caller (decrypt_message)
                    // will stash it in `pending_incoming_merges` keyed by (group_id, target_epoch).
                    Ok((vec![], target_epoch, sender_credential, Some(staged)))
                },
            }
        })?;

        // Task #33: if an incoming StagedCommit was produced, stash it for explicit confirmation.
        // Overwrites any prior pending entry for the same (group_id, epoch) — OpenMLS produces
        // deterministic StagedCommits for the same wire message, so overwrite is idempotent.
        if let Some(staged) = staged_commit_opt {
            let mut pending = self.pending_incoming_merges.lock().map_err(|_| {
                crate::error_log!("[DECRYPT] ❌ pending_incoming_merges mutex poisoned");
                MLSError::ContextNotInitialized
            })?;
            let key = (group_id.clone(), epoch);
            if pending.insert(key, staged).is_some() {
                crate::warn_log!(
                    "[DECRYPT] ⚠️ Overwrote existing pending staged commit for group {} epoch {} (duplicate delivery)",
                    hex::encode(&group_id),
                    epoch
                );
            }
        }

        let total_duration = timestamp.elapsed().unwrap_or_default();
        crate::debug_log!(
            "[DECRYPT] 🧵 Thread {:?} completed decrypt_message in {:?}",
            thread_id,
            total_duration
        );
        crate::debug_log!("[DECRYPT] ✅ Plaintext size: {} bytes", plaintext.len());

        // 🔍 DIAGNOSTIC: Record this successful processing (using per-context storage)
        // Note: We still don't have generation here, but we record the epoch
        {
            let group_history = inner
                .processed_messages
                .entry(group_id.clone())
                .or_insert_with(Vec::new);

            // Keep only last 100 messages per group to avoid unbounded growth
            if group_history.len() >= 100 {
                group_history.remove(0);
            }

            // Record (epoch, generation=0) since we don't track generation separately
            group_history.push((message_epoch, 0));
            crate::debug_log!(
                "[DECRYPT] Recorded message processing: epoch {}",
                message_epoch
            );
        }

        // Increment and get sequence number for this group (using per-context storage)
        let sequence_number = {
            let counter = inner.sequence_counters.entry(group_id.clone()).or_insert(0);
            *counter += 1;
            *counter
        };

        crate::debug_log!(
            "[DECRYPT] Message metadata - epoch: {}, sequence_number: {}",
            epoch,
            sequence_number
        );

        Ok(DecryptResult {
            plaintext,
            epoch,
            sequence_number,
            sender_credential,
        })
    }

    /// Async variant of decrypt_message - offloads crypto work to avoid blocking
    pub async fn decrypt_message_async(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        self.check_suspended()?;
        let inner = self.inner.clone();
        // Task #33: also carry the pending-merges map so we can stash incoming StagedCommits
        // from the worker thread.
        let pending_incoming_merges = self.pending_incoming_merges.clone();

        tokio::task::spawn_blocking(move || {
            let thread_id = std::thread::current().id();
            let timestamp = std::time::SystemTime::now();

            crate::debug_log!(
                "[DECRYPT-ASYNC] 🧵 Thread {:?} starting decrypt_message_async",
                thread_id
            );
            crate::debug_log!(
                "[DECRYPT-ASYNC] Group ID: {} ({} bytes)",
                hex::encode(&group_id),
                group_id.len()
            );
            crate::debug_log!(
                "[DECRYPT-ASYNC] Ciphertext size: {} bytes",
                ciphertext.len()
            );

            let mut guard = inner.lock().map_err(|e| {
                crate::error_log!(
                    "[DECRYPT-ASYNC] ❌ Thread {:?} failed to acquire lock: {:?}",
                    thread_id,
                    e
                );
                MLSError::ContextNotInitialized
            })?;
            let inner_ctx = guard.as_mut().ok_or(MLSError::ContextClosed)?;

            let gid = GroupId::from_slice(&group_id);

            let (plaintext, epoch, sender_credential, staged_commit_opt): (
                Vec<u8>,
                u64,
                CredentialData,
                Option<Box<StagedCommit>>,
            ) = inner_ctx.with_group(&gid, |group, provider, _signer| {
                    let current_epoch = group.epoch().as_u64();
                    crate::info_log!("[DECRYPT-ASYNC] 📊 PRE-PROCESSING STATE:");
                    crate::info_log!("[DECRYPT-ASYNC]   Group: {}", hex::encode(&group_id));
                    crate::info_log!("[DECRYPT-ASYNC]   Current epoch: {}", current_epoch);

                    let ciphertext = strip_padding(&ciphertext);

                    let (mls_msg, _) =
                        MlsMessageIn::tls_deserialize_bytes(&ciphertext).map_err(|e| {
                            crate::error_log!("[DECRYPT-ASYNC] ❌ Failed to deserialize: {:?}", e);
                            MLSError::SerializationError
                        })?;

                    let protocol_msg: ProtocolMessage = mls_msg.try_into().map_err(|e| {
                        crate::error_log!("[DECRYPT-ASYNC] ❌ Failed to convert: {:?}", e);
                        MLSError::DecryptionFailed
                    })?;

                    let message_epoch = protocol_msg.epoch().as_u64();

                    if message_epoch != current_epoch {
                        crate::warn_log!(
                            "[DECRYPT-ASYNC] ⚠️ EPOCH MISMATCH: {} vs {}",
                            message_epoch,
                            current_epoch
                        );
                    }

                    let processed =
                        process_protocol_message(group, provider, protocol_msg, "DECRYPT-ASYNC")
                            .map_err(|e| {
                                crate::error_log!(
                                    "[DECRYPT-ASYNC] ❌ OpenMLS process_message FAILED: {:?}",
                                    e
                                );
                                MLSError::DecryptionFailed
                            })?;

                    crate::debug_log!("[DECRYPT-ASYNC] ✅ Message processed successfully");

                    // Extract sender credential BEFORE consuming the processed message
                    let sender_cred = processed.credential().clone();
                    let sender_credential = CredentialData {
                        credential_type: format!("{:?}", sender_cred.credential_type()),
                        identity: sender_cred.serialized_content().to_vec(),
                    };

                    match processed.into_content() {
                        ProcessedMessageContent::ApplicationMessage(app_msg) => {
                            Ok((app_msg.into_bytes(), message_epoch, sender_credential, None))
                        }
                        ProcessedMessageContent::ProposalMessage(_)
                        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                            Ok((vec![], message_epoch, sender_credential, None))
                        }
                        ProcessedMessageContent::StagedCommitMessage(staged) => {
                            // Task #33: stage incoming commits for caller-driven merge.
                            // Prior behavior silently dropped the StagedCommit; now we return it
                            // and the caller stashes it in `pending_incoming_merges`.
                            let target_epoch = staged.group_context().epoch().as_u64();
                            crate::info_log!(
                                "[DECRYPT-ASYNC] StagedCommitMessage received - STAGING for explicit merge (target epoch {})",
                                target_epoch
                            );
                            Ok((vec![], target_epoch, sender_credential, Some(staged)))
                        }
                    }
                })?;

            // Increment and get sequence number for this group (using per-context storage).
            // Do this while we still hold `inner_ctx`.
            let sequence_number = {
                let counter = inner_ctx
                    .sequence_counters
                    .entry(group_id.clone())
                    .or_insert(0);
                *counter += 1;
                *counter
            };

            // Release the inner lock before touching `pending_incoming_merges` — avoid
            // holding two locks at once.
            drop(guard);

            // Task #33: stash incoming StagedCommit for explicit platform confirmation.
            if let Some(staged) = staged_commit_opt {
                let mut pending = pending_incoming_merges.lock().map_err(|_| {
                    crate::error_log!("[DECRYPT-ASYNC] ❌ pending_incoming_merges mutex poisoned");
                    MLSError::ContextNotInitialized
                })?;
                let key = (group_id.clone(), epoch);
                if pending.insert(key, staged).is_some() {
                    crate::warn_log!(
                        "[DECRYPT-ASYNC] ⚠️ Overwrote existing pending staged commit for group {} epoch {} (duplicate delivery)",
                        hex::encode(&group_id),
                        epoch
                    );
                }
            }

            let total_duration = timestamp.elapsed().unwrap_or_default();
            crate::debug_log!("[DECRYPT-ASYNC] Completed in {:?}", total_duration);

            Ok(DecryptResult {
                plaintext,
                epoch,
                sequence_number,
                sender_credential,
            })
        })
        .await
        .map_err(|e| {
            crate::error_log!("[DECRYPT-ASYNC] ERROR: spawn_blocking join error: {:?}", e);
            MLSError::OpenMLSError
        })?
    }

    pub fn process_message(
        &self,
        group_id: Vec<u8>,
        message_data: Vec<u8>,
    ) -> Result<ProcessedContent, MLSError> {
        self.check_suspended()?;
        crate::debug_log!("[MLS-FFI] process_message: Starting");
        crate::debug_log!(
            "[MLS-FFI] Group ID: {} ({} bytes)",
            hex::encode(&group_id),
            group_id.len()
        );
        crate::debug_log!("[MLS-FFI] Message data size: {} bytes", message_data.len());
        crate::debug_log!(
            "[MLS-FFI] Message data first 32 bytes: {:02x?}",
            &message_data[..message_data.len().min(32)]
        );

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire write lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);
        crate::debug_log!("[MLS-FFI] GroupId created: {}", hex::encode(gid.as_slice()));

        // Capture epoch manager for use inside the closure (for staged commit auto-merge)
        let epoch_manager = inner.epoch_secret_manager().clone();

        // Capture authorizer
        let _external_join_authorizer = self
            .external_join_authorizer
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?
            .clone();

        let result: Result<(ProcessedContent, Option<Box<StagedCommit>>), MLSError> = inner.with_group(&gid, |group, provider, _signer| {
            crate::debug_log!("[MLS-FFI] Inside with_group closure for process_message");

            // Strip padding envelope before MLS deserialization
            let message_data = strip_padding(&message_data);

            // Secret tree state logging BEFORE processing
            let epoch_before = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - process_message");
            crate::debug_log!("[MLS-FFI]   Group: {}", hex::encode(&group_id));
            crate::debug_log!("[MLS-FFI]   Epoch before: {}", epoch_before);
            crate::debug_log!("[MLS-FFI]   Group ciphersuite: {:?}", group.ciphersuite());
            crate::debug_log!("[MLS-FFI]   Group members count: {}", group.members().count());

            crate::debug_log!("[MLS-FFI] Deserializing MlsMessage...");
            let (mls_msg, remaining) = MlsMessageIn::tls_deserialize_bytes(&message_data)
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ERROR: Failed to deserialize MlsMessage: {:?}", e);
                    MLSError::SerializationError
                })?;
            crate::debug_log!("[MLS-FFI] MlsMessage deserialized ({} bytes remaining)", remaining.len());

            crate::debug_log!("[MLS-FFI] Converting to ProtocolMessage...");
            let protocol_msg: ProtocolMessage = mls_msg.try_into()
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] ERROR: Failed to convert to ProtocolMessage: {:?}", e);
                    MLSError::DecryptionFailed
                })?;
            crate::debug_log!("[MLS-FFI] ProtocolMessage created");
            let message_epoch = protocol_msg.epoch();
            let current_epoch = group.epoch();
            crate::debug_log!("[MLS-FFI]   Message epoch: {}", message_epoch.as_u64());
            crate::debug_log!("[MLS-FFI]   Current epoch: {}", current_epoch.as_u64());
            crate::debug_log!("[MLS-FFI]   Protocol message content type: {:?}", std::any::type_name_of_val(&protocol_msg));

            // Check for epoch mismatch BEFORE attempting to decrypt
            if message_epoch != current_epoch {
                // 🔍 FIX #1: Enhanced epoch transition detection
                // Distinguish between "future epoch" (might be a commit we need) vs "past epoch" (unrecoverable)
                let msg_epoch = message_epoch.as_u64();
                let cur_epoch = current_epoch.as_u64();

                if msg_epoch == cur_epoch + 1 {
                    // This could be an epoch-advancing Commit message we need to process
                    crate::warn_log!("[MLS-FFI] 📥 POTENTIAL EPOCH TRANSITION MESSAGE DETECTED!");
                    crate::warn_log!("[MLS-FFI]   Message epoch: {} (current: {})", msg_epoch, cur_epoch);
                    crate::warn_log!("[MLS-FFI]   ⚠️  This message MAY transition epoch {} → {}", cur_epoch, msg_epoch);
                    crate::warn_log!("[MLS-FFI]   ⚠️  If this is a Commit from another member, it MUST be processed to stay in sync");
                    crate::warn_log!("[MLS-FFI]   ⚠️  Attempting to process anyway - OpenMLS will handle if it's a valid Commit");
                    // Let it through - OpenMLS can process Commits that advance the epoch
                } else if msg_epoch > cur_epoch + 1 {
                    // Message is from too far in the future - we missed commits
                    crate::error_log!("[MLS-FFI] 🚨 EPOCH GAP DETECTED - MISSED COMMITS!");
                    crate::error_log!("[MLS-FFI]   Message epoch: {} (current: {})", msg_epoch, cur_epoch);
                    crate::error_log!("[MLS-FFI]   Missing {} epochs worth of commits", msg_epoch - cur_epoch);
                    crate::error_log!("[MLS-FFI]   Client needs to sync commits from server before processing");
                    return Err(MLSError::invalid_input(format!(
                        "Cannot decrypt message from epoch {} - group is at epoch {} (missing {} commits - sync required)",
                        msg_epoch, cur_epoch, msg_epoch - cur_epoch
                    )));
                } else {
                    // Message is from the past - forward secrecy prevents decryption
                    crate::warn_log!("[MLS-FFI] ⚠️ OLD EPOCH MESSAGE - Forward secrecy prevents decryption");
                    crate::debug_log!("[MLS-FFI]   Message epoch: {} (current: {})", msg_epoch, cur_epoch);
                    crate::debug_log!("[MLS-FFI]   Epoch keys were deleted after advancing past epoch {}", msg_epoch);
                    crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - epoch mismatch rejection");
                    return Err(MLSError::invalid_input(format!(
                        "Cannot decrypt message from epoch {} - group is at epoch {} (forward secrecy prevents decrypting old epochs)",
                        msg_epoch, cur_epoch
                    )));
                }
            }

            crate::debug_log!("[MLS-FFI] Calling OpenMLS process_message...");
            let processed = process_protocol_message(group, provider, protocol_msg, "MLS-FFI")
                .map_err(|e| {
                    let error_details = format!("{:?}", e);
                    crate::error_log!("[MLS-FFI] ERROR: OpenMLS process_message failed!");
                    crate::error_log!("[MLS-FFI] ERROR: Error details: {}", error_details);
                    crate::error_log!("[MLS-FFI] ERROR: Current epoch: {:?}", group.epoch());
                    crate::error_log!("[MLS-FFI] 🔐 SECRET TREE ERROR - decryption failed");
                    MLSError::OpenMLS(format!("process_message failed: {}", error_details))
                })?;

            // Secret tree state logging AFTER processing
            let epoch_after = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - after process_message");
            crate::debug_log!("[MLS-FFI]   Epoch after: {}", epoch_after);
            if epoch_after != epoch_before {
                crate::debug_log!("[MLS-FFI]   Epoch changed from {} to {} during process", epoch_before, epoch_after);
            }
            crate::debug_log!("[MLS-FFI] OpenMLS process_message succeeded!");

            crate::debug_log!("[MLS-FFI] Processing message content type...");

            // Extract sender credential BEFORE consuming the processed message
            let sender_credential = processed.credential();
            let sender = CredentialData {
                credential_type: format!("{:?}", sender_credential.credential_type()),
                identity: sender_credential.serialized_content().to_vec(),
            };
            crate::debug_log!("[MLS-FFI] Sender extracted: {} bytes identity", sender.identity.len());

            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app_msg) => {
                    let plaintext = app_msg.into_bytes();
                    crate::debug_log!("[MLS-FFI] ApplicationMessage processed: {} bytes", plaintext.len());

                    Ok((ProcessedContent::ApplicationMessage {
                        plaintext,
                        sender,
                    }, None))
                },
                ProcessedMessageContent::ProposalMessage(proposal_msg) => {
                    crate::debug_log!("[MLS-FFI] ProposalMessage received, processing...");
                    let proposal = proposal_msg.proposal();

                    // Compute proposal reference by hashing the proposal
                    // Since proposal_reference() is pub(crate), we compute our own identifier
                    let proposal_bytes = proposal
                        .tls_serialize_detached()
                        .map_err(|e| {
                            crate::error_log!("[MLS-FFI] ERROR: Failed to serialize proposal: {:?}", e);
                            MLSError::SerializationError
                        })?;

                    let proposal_ref_bytes = provider.crypto()
                        .hash(group.ciphersuite().hash_algorithm(), &proposal_bytes)
                        .map_err(|e| {
                            crate::error_log!("[MLS-FFI] ERROR: Failed to hash proposal: {:?}", e);
                            MLSError::OpenMLSError
                        })?;

                    crate::debug_log!("[MLS-FFI] Proposal ref computed: {}", hex::encode(&proposal_ref_bytes));

                    let proposal_info = match proposal {
                        Proposal::Add(add_proposal) => {
                            crate::debug_log!("[MLS-FFI] Add proposal detected");
                            let key_package = add_proposal.key_package();
                            let credential = key_package.leaf_node().credential();

                            let credential_info = CredentialData {
                                credential_type: format!("{:?}", credential.credential_type()),
                                identity: credential.serialized_content().to_vec(),
                            };

                            ProposalInfo::Add {
                                info: AddProposalInfo {
                                    credential: credential_info,
                                    key_package_ref: key_package.hash_ref(provider.crypto())
                                        .map_err(|_| MLSError::OpenMLSError)?
                                        .as_slice()
                                        .to_vec(),
                                }
                            }
                        },
                        Proposal::Remove(remove_proposal) => {
                            crate::debug_log!("[MLS-FFI] Remove proposal detected, index: {}", remove_proposal.removed().u32());
                            ProposalInfo::Remove {
                                info: RemoveProposalInfo {
                                    removed_index: remove_proposal.removed().u32(),
                                }
                            }
                        },
                        Proposal::Update(update_proposal) => {
                            crate::debug_log!("[MLS-FFI] Update proposal detected");
                            let leaf_node = update_proposal.leaf_node();
                            let credential = leaf_node.credential();

                            let credential_info = CredentialData {
                                credential_type: format!("{:?}", credential.credential_type()),
                                identity: credential.serialized_content().to_vec(),
                            };

                            let leaf_index = group.own_leaf_index().u32();
                            crate::debug_log!("[MLS-FFI] Update proposal leaf index: {}", leaf_index);

                            ProposalInfo::Update {
                                info: UpdateProposalInfo {
                                    leaf_index,
                                    old_credential: credential_info.clone(),
                                    new_credential: credential_info,
                                }
                            }
                        },
                        _ => {
                            crate::error_log!("[MLS-FFI] ERROR: Unsupported proposal type");
                            return Err(MLSError::invalid_input("Unsupported proposal type"));
                        }
                    };

                    crate::debug_log!("[MLS-FFI] Proposal processed successfully");
                    Ok((ProcessedContent::Proposal {
                        proposal: proposal_info,
                        proposal_ref: ProposalRef {
                            data: proposal_ref_bytes,
                        },
                    }, None))
                },
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                    crate::debug_log!("[MLS-FFI] ExternalJoinProposalMessage received");
                    crate::warn_log!("[MLS-FFI] ⚠️ External join proposals not supported yet");
                    Err(MLSError::invalid_input("External join proposals not supported"))
                },
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    // Task #33: stage the incoming commit instead of auto-merging.
                    // Platform must explicitly call `merge_incoming_commit(group_id, target_epoch)`
                    // to advance the epoch (or `discard_incoming_commit` to abandon).
                    //
                    // NOTE on wire-format semantics change: `ProcessedContent::StagedCommit::new_epoch`
                    // used to mean "group is now at this epoch" (post-merge). After this refactor it
                    // means "group will be at this epoch once the platform calls merge_incoming_commit".
                    // Downstream (iOS/Android/catmos) must be updated.
                    let target_epoch = staged.group_context().epoch().as_u64();
                    crate::info_log!("[MLS-FFI] 📦 Staged commit received for epoch transition to {} — STAGING for explicit merge", target_epoch);

                    // Metadata: derive the new epoch's metadata key from the staged
                    // commit's exporter BEFORE the staged commit is moved into the tuple.
                    // The platform needs this in the event payload so it can unwrap the new
                    // epoch's metadata blob without having to redo the exporter derivation.
                    let metadata_key_bytes = match crate::metadata::derive_metadata_key(
                        &staged,
                        provider.crypto(),
                        &group_id,
                        target_epoch,
                    ) {
                        Ok(key) => {
                            crate::info_log!("[MLS-FFI] 🔑 metadata key derived for epoch {}", target_epoch);
                            Some(key.to_vec())
                        }
                        Err(e) => {
                            crate::warn_log!("[MLS-FFI] ⚠️ metadata key derivation failed: {:?}", e);
                            None
                        }
                    };

                    // Export current (pre-merge) epoch secret now — the forward-secrecy
                    // window covers the pre-merge epoch, and once we stage + release the
                    // lock, the next caller could in principle mutate the group before
                    // merge happens. Export here, while we still hold the group mutably.
                    if let Err(e) = crate::async_runtime::block_on(
                        epoch_manager.export_current_epoch_secret(group, provider)
                    ) {
                        crate::warn_log!("[MLS-FFI] ⚠️ Failed to export epoch secret before staging: {:?}", e);
                    }

                    // NB: metadata_reference_json reflects the *pre-merge* group context.
                    // We persist it here so the platform can reconcile after merge. It will be
                    // recomputed post-merge inside `merge_incoming_commit` if needed.
                    let metadata_reference_json = current_metadata_reference_json(group);
                    let metadata_info = metadata_key_bytes.map(|metadata_key| CommitMetadataInfo {
                        metadata_key,
                        epoch: target_epoch,
                        metadata_reference_json,
                    });

                    Ok((ProcessedContent::StagedCommit {
                        new_epoch: target_epoch,
                        commit_metadata: metadata_info,
                    }, Some(staged)))
                },
            }
        });

        // Task #33: if an incoming StagedCommit was produced, stash it for explicit confirmation.
        // Overwrites any prior pending entry for the same (group_id, epoch) — OpenMLS produces
        // deterministic StagedCommits for the same wire message, so overwrite is idempotent.
        let processed = match result {
            Ok((content, staged_opt)) => {
                if let Some(staged) = staged_opt {
                    // target_epoch is available as `new_epoch` on the StagedCommit variant.
                    let target_epoch = match &content {
                        ProcessedContent::StagedCommit { new_epoch, .. } => *new_epoch,
                        _ => {
                            crate::error_log!("[MLS-FFI] ❌ invariant violation: non-StagedCommit content paired with Some(staged)");
                            return Err(MLSError::ContextNotInitialized);
                        }
                    };
                    let mut pending = self.pending_incoming_merges.lock().map_err(|_| {
                        crate::error_log!("[MLS-FFI] ❌ pending_incoming_merges mutex poisoned");
                        MLSError::ContextNotInitialized
                    })?;
                    let key = (group_id.clone(), target_epoch);
                    if pending.insert(key, staged).is_some() {
                        crate::warn_log!(
                            "[MLS-FFI] ⚠️ Overwrote existing pending staged commit for group {} epoch {} (duplicate delivery)",
                            hex::encode(&group_id),
                            target_epoch
                        );
                    }
                }
                content
            }
            Err(e) => return Err(e),
        };

        Ok(processed)
    }

    /// Async variant of process_message - offloads crypto work to avoid blocking
    pub async fn process_message_async(
        &self,
        group_id: Vec<u8>,
        message_data: Vec<u8>,
    ) -> Result<ProcessedContent, MLSError> {
        self.check_suspended()?;
        let inner = self.inner.clone();
        // Task #33: carry the pending-merges map into the worker thread.
        let pending_incoming_merges = self.pending_incoming_merges.clone();

        tokio::task::spawn_blocking(move || {
            crate::debug_log!("[MLS-FFI-ASYNC] process_message_async: Starting");
            crate::debug_log!("[MLS-FFI-ASYNC] Group ID: {} ({} bytes)", hex::encode(&group_id), group_id.len());

            let mut guard = inner.lock()
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI-ASYNC] ERROR: Failed to acquire write lock: {:?}", e);
                    MLSError::ContextNotInitialized
                })?;
            let inner_ctx = guard.as_mut().ok_or(MLSError::ContextClosed)?;

            let gid = GroupId::from_slice(&group_id);

            // Capture epoch manager for use inside the closure
            let epoch_manager = inner_ctx.epoch_secret_manager().clone();

            let result: Result<(ProcessedContent, Option<Box<StagedCommit>>), MLSError> = inner_ctx.with_group(&gid, |group, provider, _signer| {
                let epoch_before = group.epoch().as_u64();
                crate::debug_log!("[MLS-FFI-ASYNC] 🔐 Current epoch: {}", epoch_before);

                // Strip padding envelope before MLS deserialization
                let message_data = strip_padding(&message_data);

                let (mls_msg, _) = MlsMessageIn::tls_deserialize_bytes(&message_data)
                    .map_err(|e| {
                        crate::error_log!("[MLS-FFI-ASYNC] ERROR: Failed to deserialize: {:?}", e);
                        MLSError::SerializationError
                    })?;

                let protocol_msg: ProtocolMessage = mls_msg.try_into()
                    .map_err(|e| {
                        crate::error_log!("[MLS-FFI-ASYNC] ERROR: Failed to convert: {:?}", e);
                        MLSError::DecryptionFailed
                    })?;

                let message_epoch = protocol_msg.epoch();

                if message_epoch != group.epoch() {
                    return Err(MLSError::invalid_input(format!(
                        "Epoch mismatch: {} vs {}",
                        message_epoch.as_u64(),
                        group.epoch().as_u64()
                    )));
                }

                let processed = process_protocol_message(
                    group,
                    provider,
                    protocol_msg,
                    "MLS-FFI-ASYNC",
                )
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI-ASYNC] ERROR: process_message failed: {:?}", e);
                    MLSError::DecryptionFailed
                })?;

                let sender_credential = processed.credential();
                let sender = CredentialData {
                    credential_type: format!("{:?}", sender_credential.credential_type()),
                    identity: sender_credential.serialized_content().to_vec(),
                };

                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(app_msg) => {
                        let plaintext = app_msg.into_bytes();
                        Ok((ProcessedContent::ApplicationMessage { plaintext, sender }, None))
                    },
                    ProcessedMessageContent::ProposalMessage(proposal_msg) => {
                        let proposal = proposal_msg.proposal();
                        let proposal_bytes = proposal
                            .tls_serialize_detached()
                            .map_err(|_| MLSError::SerializationError)?;

                        let proposal_ref_bytes = provider.crypto()
                            .hash(group.ciphersuite().hash_algorithm(), &proposal_bytes)
                            .map_err(|_| MLSError::OpenMLSError)?;

                        // Simplified proposal handling for async variant
                        let proposal_info = match proposal {
                            Proposal::Add(add_proposal) => {
                                let key_package = add_proposal.key_package();
                                let credential = key_package.leaf_node().credential();
                                ProposalInfo::Add {
                                    info: AddProposalInfo {
                                        credential: CredentialData {
                                            credential_type: format!("{:?}", credential.credential_type()),
                                            identity: credential.serialized_content().to_vec(),
                                        },
                                        key_package_ref: key_package.hash_ref(provider.crypto())
                                            .map_err(|_| MLSError::OpenMLSError)?
                                            .as_slice()
                                            .to_vec(),
                                    }
                                }
                            },
                            Proposal::Remove(remove_proposal) => {
                                ProposalInfo::Remove {
                                    info: RemoveProposalInfo {
                                        removed_index: remove_proposal.removed().u32(),
                                    }
                                }
                            },
                            Proposal::Update(update_proposal) => {
                                let leaf_node = update_proposal.leaf_node();
                                let credential = leaf_node.credential();
                                let leaf_index = group.own_leaf_index().u32();
                                ProposalInfo::Update {
                                    info: UpdateProposalInfo {
                                        leaf_index,
                                        old_credential: CredentialData {
                                            credential_type: format!("{:?}", credential.credential_type()),
                                            identity: credential.serialized_content().to_vec(),
                                        },
                                        new_credential: CredentialData {
                                            credential_type: format!("{:?}", credential.credential_type()),
                                            identity: credential.serialized_content().to_vec(),
                                        },
                                    }
                                }
                            },
                            _ => {
                                return Err(MLSError::invalid_input("Unsupported proposal type"));
                            }
                        };

                        Ok((ProcessedContent::Proposal {
                            proposal: proposal_info,
                            proposal_ref: ProposalRef {
                                data: proposal_ref_bytes,
                            },
                        }, None))
                    },
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        Err(MLSError::invalid_input("External join proposals not supported"))
                    },
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        // Task #33: stage the incoming commit for caller-driven merge.
                        // Semantics change: `new_epoch` here = "group will be at this epoch
                        // AFTER the platform calls merge_incoming_commit", not "group is now
                        // at this epoch."
                        let target_epoch = staged.group_context().epoch().as_u64();
                        crate::info_log!(
                            "[MLS-FFI-ASYNC] 📦 Staged commit received — STAGING for explicit merge (target epoch {})",
                            target_epoch
                        );

                        // Metadata: derive the new epoch's metadata key BEFORE staged is moved.
                        let metadata_key_bytes = match crate::metadata::derive_metadata_key(
                            &staged,
                            provider.crypto(),
                            &group_id,
                            target_epoch,
                        ) {
                            Ok(key) => {
                                crate::info_log!("[MLS-FFI-ASYNC] 🔑 metadata key derived for epoch {}", target_epoch);
                                Some(key.to_vec())
                            }
                            Err(e) => {
                                crate::warn_log!("[MLS-FFI-ASYNC] ⚠️ metadata key derivation failed: {:?}", e);
                                None
                            }
                        };

                        // Export the pre-merge epoch secret now (forward-secrecy window).
                        // Post-merge cleanup moves into `merge_incoming_commit`.
                        if let Err(e) = crate::async_runtime::block_on(
                            epoch_manager.export_current_epoch_secret(group, provider)
                        ) {
                            crate::warn_log!("[MLS-FFI-ASYNC] ⚠️ Failed to export epoch secret before staging: {:?}", e);
                        }

                        let metadata_reference_json = current_metadata_reference_json(group);
                        let metadata_info = metadata_key_bytes.map(|metadata_key| CommitMetadataInfo {
                            metadata_key,
                            epoch: target_epoch,
                            metadata_reference_json,
                        });

                        Ok((ProcessedContent::StagedCommit {
                            new_epoch: target_epoch,
                            commit_metadata: metadata_info,
                        }, Some(staged)))
                    },
                }
            });

            // Release the inner lock before touching `pending_incoming_merges`.
            drop(guard);

            // Task #33: stash incoming StagedCommit for explicit platform confirmation.
            match result {
                Ok((content, staged_opt)) => {
                    if let Some(staged) = staged_opt {
                        let target_epoch = match &content {
                            ProcessedContent::StagedCommit { new_epoch, .. } => *new_epoch,
                            _ => {
                                crate::error_log!("[MLS-FFI-ASYNC] ❌ invariant violation: non-StagedCommit content paired with Some(staged)");
                                return Err(MLSError::ContextNotInitialized);
                            }
                        };
                        let mut pending = pending_incoming_merges.lock().map_err(|_| {
                            crate::error_log!("[MLS-FFI-ASYNC] ❌ pending_incoming_merges mutex poisoned");
                            MLSError::ContextNotInitialized
                        })?;
                        let key = (group_id.clone(), target_epoch);
                        if pending.insert(key, staged).is_some() {
                            crate::warn_log!(
                                "[MLS-FFI-ASYNC] ⚠️ Overwrote existing pending staged commit for group {} epoch {} (duplicate delivery)",
                                hex::encode(&group_id),
                                target_epoch
                            );
                        }
                    }
                    Ok(content)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| {
            crate::error_log!("[MLS-FFI-ASYNC] ERROR: spawn_blocking join error: {:?}", e);
            MLSError::OpenMLSError
        })?
    }

    pub fn create_key_package(
        &self,
        identity_bytes: Vec<u8>,
    ) -> Result<KeyPackageResult, MLSError> {
        // Early bail-out if suspension is in progress (0xdead10cc prevention).
        self.check_suspended()?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(identity_bytes)
            .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;

        let credential = Credential::new(CredentialType::Basic, identity.as_bytes().to_vec());

        // Use persistent identity keypair instead of generating new one each time
        // Try to retrieve existing signature keypair for this identity
        crate::debug_log!(
            "[CREATE-KEY-PACKAGE] Looking for signer for identity: {}",
            identity
        );
        let signature_keys = match inner.get_signer_for_identity(&identity) {
            Some(existing_signer) => {
                crate::debug_log!(
                    "[CREATE-KEY-PACKAGE] Reusing existing signer, PK: {}",
                    hex::encode(existing_signer.public())
                );
                existing_signer
            }
            None => {
                // No existing signer - create a new persistent one
                crate::info_log!(
                    "[CREATE-KEY-PACKAGE] Creating NEW signer for identity: {}",
                    identity
                );
                let new_keys = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|e| {
                    MLSError::OpenMLS(format!("Failed to create SignatureKeyPair: {:?}", e))
                })?;

                let signer_public_key = new_keys.public().to_vec();
                crate::debug_log!(
                    "[CREATE-KEY-PACKAGE]   New signer PK: {}",
                    hex::encode(&signer_public_key)
                );

                // Store in OpenMLS storage
                crate::debug_log!("[CREATE-KEY-PACKAGE]   Calling new_keys.store()...");
                new_keys.store(inner.provider.storage()).map_err(|e| {
                    MLSError::OpenMLS(format!("Failed to store SignatureKeyPair: {:?}", e))
                })?;
                crate::debug_log!("[CREATE-KEY-PACKAGE]   store() completed without error");

                // Verify the signer can be loaded back immediately
                match SignatureKeyPair::read(
                    inner.provider.storage(),
                    &signer_public_key,
                    SignatureScheme::ED25519,
                ) {
                    Some(_) => {
                        crate::debug_log!("[CREATE-KEY-PACKAGE]   VERIFIED: Signer can be loaded back from storage");
                    }
                    None => {
                        crate::error_log!("[CREATE-KEY-PACKAGE]   CRITICAL: Signer NOT found in storage immediately after store()!");
                    }
                }

                // Register the signer for this identity so it can be found later
                inner.register_signer(&identity, signer_public_key.clone())?;
                crate::debug_log!("[CREATE-KEY-PACKAGE]   Registered signer mapping");

                new_keys
            }
        };

        // 🔥 SIGNATURE KEY FORENSICS: Log the public key being embedded in this KeyPackage
        let signer_public_key = signature_keys.public().to_vec();
        crate::info_log!("🔑 [SIGNATURE KEY FORENSICS - KeyPackage Creation]");
        crate::info_log!("   Identity: {}", identity);
        crate::info_log!(
            "   Public Signature Key (32 bytes): {}",
            hex::encode(&signer_public_key)
        );
        crate::info_log!("   ⚠️  This is the PERSISTENT identity key for this user");
        crate::info_log!("   ⚠️  All KeyPackages and messages will use THIS SAME KEY");

        let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

        // CRITICAL: Key packages must advertise support for RatchetTree extension
        // AND the Catbird metadata extension (0xff00) so members can join groups
        // that use encrypted group metadata in context extensions.
        let capabilities = Capabilities::builder()
            .extensions(vec![
                ExtensionType::RatchetTree,
                ExtensionType::AppDataDictionary,
                ExtensionType::Unknown(crate::group_metadata::CATBIRD_METADATA_EXTENSION_TYPE),
            ])
            .proposals(vec![ProposalType::AppDataUpdate])
            .build();

        let key_package_bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                ciphersuite,
                &inner.provider,
                &signature_keys,
                CredentialWithKey {
                    credential,
                    signature_key: signature_keys.public().into(),
                },
            )
            .map_err(|e| MLSError::OpenMLS(format!("Failed to build KeyPackage: {:?}", e)))?;

        // Serialize key package directly (raw format for compatibility)
        let key_package = key_package_bundle.key_package().clone();

        let key_package_data = key_package
            .tls_serialize_detached()
            .map_err(|_| MLSError::SerializationError)?;

        // Get hash reference (keep both typed and bytes versions)
        let hash_ref_typed = key_package.hash_ref(inner.provider_crypto()).map_err(|e| {
            MLSError::OpenMLS(format!("Failed to compute KeyPackage hash_ref: {:?}", e))
        })?;
        let hash_ref = hash_ref_typed.as_slice().to_vec();

        // CRITICAL FIX: Store the bundle in the cache for serialization and Welcome message processing
        // This ensures the private key material is available when processing Welcome messages
        crate::debug_log!(
            "[MLS-FFI] Storing key package bundle in cache (hash_ref: {})",
            hex::encode(&hash_ref)
        );
        crate::info_log!(
            "[MLS-WELCOME-DEBUG] 📦 Key package CREATED: hash_ref = {}",
            hex::encode(&hash_ref)
        );
        // Also log how many OpenMLS has in its internal table right after build()
        let openmls_count = inner.manifest_storage.debug_count_openmls_key_packages();
        crate::info_log!(
            "[MLS-WELCOME-DEBUG] 📦 OpenMLS internal key_packages count after build(): {}",
            openmls_count
        );
        inner
            .key_package_bundles_mut()
            .insert(hash_ref.clone(), key_package_bundle.clone());
        crate::debug_log!(
            "[MLS-FFI] Bundle cached successfully, cache now has {} bundles",
            inner.key_package_bundles_mut().len()
        );

        // 🔥 PERSISTENCE FIX: Serialize and store the bundle using serde_json
        // We can't use OpenMLS's write_key_package() because it causes UNIQUE constraint violations
        // (OpenMLS already persists the private key during .build(), but not the full bundle)
        // Instead, we serialize the bundle and store it using a custom storage key
        crate::info_log!("[MLS-FFI] ✍️ Persisting key package bundle to custom storage...");

        let bundle_json = serde_json::to_vec(&key_package_bundle).map_err(|e| {
            crate::error_log!("[MLS-FFI] ❌ Failed to serialize bundle: {:?}", e);
            MLSError::SerializationError
        })?;

        // Persist bundle to manifest storage
        let storage = &inner.manifest_storage;
        let hex_ref = hex::encode(&hash_ref);
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_json);

        // Read existing bundles map or create new one
        let mut bundles_map: HashMap<String, String> = storage
            .read_manifest("key_package_bundles")?
            .unwrap_or_else(HashMap::new);

        // Add or update this bundle
        bundles_map.insert(hex_ref.clone(), bundle_b64);

        // Write updated map back to storage (bail if app is suspending — 0xdead10cc prevention)
        self.check_suspended()?;
        storage.write_manifest("key_package_bundles", &bundles_map)?;

        crate::debug_log!(
            "[MLS-FFI] 📋 Updated bundle manifest, now tracking {} bundles",
            bundles_map.len()
        );

        // 🔒 CRITICAL FIX: Force database flush after key package bundle creation
        // Without this, SQLite WAL entries may not be checkpointed to the main database file,
        // causing NoMatchingKeyPackage errors after app restart when bundles are lost.
        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ WARNING: Failed to flush database after bundle creation: {:?}",
                e
            );
            e
        })?;
        crate::debug_log!("[MLS-FFI] ✅ Database flushed after bundle creation");

        crate::info_log!("[MLS-FFI] ✅ Key package bundle persisted successfully");

        Ok(KeyPackageResult {
            key_package_data,
            hash_ref,
            signature_public_key: signer_public_key,
        })
    }

    pub fn process_welcome(
        &self,
        welcome_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] process_welcome: Starting with {} byte Welcome message",
            welcome_bytes.len()
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let identity = String::from_utf8(identity_bytes)
            .map_err(|_| MLSError::invalid_input("Invalid UTF-8"))?;
        crate::info_log!("[MLS-FFI] process_welcome: Identity = {}", identity);

        let (mls_msg, _) = MlsMessageIn::tls_deserialize_bytes(&welcome_bytes).map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ERROR: Failed to deserialize Welcome message: {:?}",
                e
            );
            MLSError::SerializationError
        })?;
        crate::debug_log!("[MLS-FFI] process_welcome: Welcome message deserialized successfully");

        let welcome = match mls_msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                crate::error_log!("[MLS-FFI] ERROR: MlsMessage is not a Welcome message");
                return Err(MLSError::invalid_input("Not a Welcome message"));
            }
        };

        // 📦 NOTE: OpenMLS automatically loads KeyPackages from storage via the provider
        // The in-memory key_package_bundles HashMap is only used for optimization/caching
        // StagedWelcome::new_from_welcome will look up the key package from SQLite storage
        crate::info_log!("[MLS-FFI] process_welcome: OpenMLS will load KeyPackage from storage");

        // 🔍 DEBUG: Query OpenMLS's ACTUAL key package storage (not just our manifest)
        let openmls_kp_count = inner.manifest_storage.debug_count_openmls_key_packages();
        crate::info_log!(
            "[MLS-WELCOME-DEBUG] 🔍 OpenMLS internal key_packages table: {} entries",
            openmls_kp_count
        );
        let openmls_kp_refs = inner
            .manifest_storage
            .debug_list_openmls_key_package_refs(5);
        for (i, href) in openmls_kp_refs.iter().enumerate() {
            crate::info_log!(
                "[MLS-WELCOME-DEBUG]   OpenMLS-KP[{}] hash_ref = {}",
                i,
                &href[..href.len().min(32)]
            );
        }

        // 🔍 DEBUG: Log what the Welcome expects and what we have
        crate::info_log!(
            "[MLS-WELCOME-DEBUG] 🔍 Welcome secrets count: {}",
            welcome.secrets().len()
        );
        for (idx, egs) in welcome.secrets().iter().enumerate() {
            let hash_ref = egs.new_member();
            crate::info_log!(
                "[MLS-WELCOME-DEBUG]   Secret[{}] key_package hash_ref = {}",
                idx,
                hex::encode(hash_ref.as_slice())
            );
        }

        // List what's in our local key package manifest
        let manifest = &inner.manifest_storage;
        if let Ok(Some(bundles_map)) = manifest
            .read_manifest::<std::collections::HashMap<String, String>>("key_package_bundles")
        {
            crate::info_log!(
                "[MLS-WELCOME-DEBUG] 🔍 Local manifest has {} key package bundles:",
                bundles_map.len()
            );
            for (i, hash_hex) in bundles_map.keys().enumerate() {
                if i < 5 {
                    crate::info_log!("[MLS-WELCOME-DEBUG]   Local[{}] hash = {}", i, hash_hex);
                }
            }
            if bundles_map.len() > 5 {
                crate::info_log!(
                    "[MLS-WELCOME-DEBUG]   ... and {} more",
                    bundles_map.len() - 5
                );
            }

            // Check if any Welcome hash matches local manifest
            for (idx, egs) in welcome.secrets().iter().enumerate() {
                let hash_ref_hex = hex::encode(egs.new_member().as_slice());
                let found = bundles_map.contains_key(&hash_ref_hex);
                crate::info_log!(
                    "[MLS-WELCOME-DEBUG]   Secret[{}] hash {} MATCH in local manifest: {}",
                    idx,
                    &hash_ref_hex[..hash_ref_hex.len().min(16)],
                    found
                );
            }
        } else {
            crate::warn_log!("[MLS-WELCOME-DEBUG] ⚠️ No key_package_bundles manifest found");
        }

        let group_config = config.unwrap_or_default();
        crate::debug_log!("[MLS-FFI] process_welcome: Group config - max_past_epochs: {}, out_of_order_tolerance: {}, maximum_forward_distance: {}",
            group_config.max_past_epochs, group_config.out_of_order_tolerance, group_config.maximum_forward_distance);

        // Build join config with forward secrecy settings
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(group_config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                group_config.out_of_order_tolerance,
                group_config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true) // CRITICAL: Must match group creation config
            .build();
        crate::debug_log!(
            "[MLS-FFI] process_welcome: Join config created with ratchet tree extension"
        );

        crate::info_log!("[MLS-FFI] process_welcome: Calling StagedWelcome::new_from_welcome...");
        let mut group = {
            let provider = &inner.provider;
            StagedWelcome::new_from_welcome(
                provider,
                &join_config,
                welcome,
                None,
            )
            .map_err(|e| {
                crate::error_log!("[MLS-FFI] ❌ ERROR: StagedWelcome::new_from_welcome failed!");
                crate::error_log!("[MLS-FFI] ERROR: OpenMLS error details: {:?}", e);
                crate::error_log!("[MLS-FFI] ERROR: Error type: {}", std::any::type_name_of_val(&e));

                // Map specific WelcomeError variants to corresponding MLSError types
                match &e {
                    WelcomeError::NoMatchingKeyPackage => {
                        crate::error_log!("[MLS-FFI] ❌ NoMatchingKeyPackage: Welcome references a key package not in local storage");
                        crate::error_log!("[MLS-FFI] DIAGNOSTIC: This device may not have the key package used to create this Welcome");
                        crate::error_log!("[MLS-FFI] DIAGNOSTIC: The Welcome was likely created for a different device");
                        MLSError::no_matching_key_package("Welcome references a key package not found in local storage")
                    }
                    WelcomeError::NoMatchingEncryptionKey => {
                        crate::error_log!("[MLS-FFI] ❌ NoMatchingEncryptionKey: Encryption key not in storage");
                        MLSError::no_matching_key_package("No matching encryption key found in storage")
                    }
                    _ => {
                        crate::error_log!("[MLS-FFI] DIAGNOSTIC: Unhandled WelcomeError variant");
                        MLSError::OpenMLS(format!("StagedWelcome failed: {:?}", e))
                    }
                }
            })?
            .into_group(provider)
            .map_err(|e| {
                crate::error_log!("[MLS-FFI] ❌ ERROR: into_group failed!");
                crate::error_log!("[MLS-FFI] ERROR: OpenMLS error details: {:?}", e);
                MLSError::OpenMLS(format!("into_group failed: {:?}", e))
            })
        }?;

        crate::info_log!("[MLS-FFI] process_welcome: Successfully joined group via Welcome");

        let group_id = group.group_id().as_slice().to_vec();

        // 🔍 DEBUG: Log initial member count after processing Welcome
        let initial_member_count = group.members().count();
        crate::debug_log!(
            "[MLS-FFI] 🔍 DEBUG: Group created from Welcome with {} members at epoch {}",
            initial_member_count,
            group.epoch().as_u64()
        );

        // CRITICAL: Export epoch secret immediately after joining
        // The group may already be at epoch > 0 when we join via Welcome
        let epoch_manager = inner.epoch_secret_manager().clone();
        crate::debug_log!(
            "[MLS-FFI] process_welcome: Group joined at epoch {}",
            group.epoch().as_u64()
        );
        if let Err(e) = crate::async_runtime::block_on(
            epoch_manager.export_current_epoch_secret(&mut group, &inner.provider),
        ) {
            crate::warn_log!(
                "[MLS-FFI] ⚠️ WARNING: Failed to export epoch secret after Welcome: {:?}",
                e
            );
        } else {
            crate::info_log!(
                "[MLS-FFI] ✅ Exported epoch {} secret after processing Welcome",
                group.epoch().as_u64()
            );
        }

        inner.add_group(group, &identity)?;

        // 🔍 DIAGNOSTIC: Verify the group was successfully added and is accessible
        crate::info_log!(
            "[MLS-FFI] process_welcome: 🔍 Verifying group was stored successfully..."
        );
        let gid = GroupId::from_slice(&group_id);

        // Try to access the group to verify it's accessible
        // Note: OpenMLS SqliteStorageProvider automatically persists group state to SQLite
        inner.with_group_ref(&gid, |group, provider| {
            let stored_epoch = group.epoch().as_u64();
            crate::info_log!("[MLS-FFI] ✅ Group successfully stored and accessible in memory - epoch: {}", stored_epoch);

            // 🔍 DIAGNOSTIC: Immediately reload from storage to verify persistence
            crate::info_log!("[MLS-FFI] 🔍 Verifying storage round-trip...");
            match MlsGroup::load(provider.storage(), &gid) {
                Ok(Some(loaded_group)) => {
                    let loaded_epoch = loaded_group.epoch().as_u64();
                    if loaded_epoch == stored_epoch {
                        crate::info_log!("[MLS-FFI] ✅ Storage verification PASSED: Reloaded group at epoch {}", loaded_epoch);
                    } else {
                        crate::error_log!("[MLS-FFI] ❌ STORAGE MISMATCH: Memory epoch {} != Storage epoch {}",
                            stored_epoch, loaded_epoch);
                    }

                    // 🔍 DIAGNOSTIC: Verify member count matches
                    let memory_members = group.members().count();
                    let storage_members = loaded_group.members().count();
                    if memory_members == storage_members {
                        crate::info_log!("[MLS-FFI] ✅ Member count matches: {} members", memory_members);
                    } else {
                        crate::error_log!("[MLS-FFI] ❌ MEMBER COUNT MISMATCH: Memory {} != Storage {}",
                            memory_members, storage_members);
                    }
                }
                Ok(None) => {
                    crate::error_log!("[MLS-FFI] ❌ CRITICAL: Group NOT found in storage immediately after add!");
                    crate::error_log!("[MLS-FFI]   This indicates storage.save() may have failed silently");
                }
                Err(e) => {
                    crate::error_log!("[MLS-FFI] ❌ CRITICAL: Failed to reload group from storage: {:?}", e);
                }
            }

            Ok(())
        }).map_err(|e| {
            crate::error_log!("[MLS-FFI] ❌ CRITICAL: Group was not stored after Welcome processing!");
            crate::error_log!("[MLS-FFI] ERROR: {:?}", e);
            MLSError::StorageFailed
        })?;

        crate::info_log!("[MLS-FFI] process_welcome: Group storage verified successfully");

        // 🔒 CRITICAL FIX: Force database flush to ensure secret tree state is durably persisted
        // Without this, SQLite WAL entries may not be checkpointed to the main database file,
        // causing SecretReuseError after app restart when the group state is incomplete.
        self.check_suspended()?;
        crate::info_log!("[MLS-FFI] process_welcome: Flushing database to ensure persistence...");
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ❌ CRITICAL: Failed to flush database after Welcome processing!"
            );
            crate::error_log!("[MLS-FFI] ERROR: {:?}", e);
            e
        })?;

        // Signal-style budget checkpoint: keep WAL perpetually small
        inner.maybe_truncate_checkpoint();
        crate::info_log!("[MLS-FFI] ✅ Database flushed successfully - group state is durable");

        Ok(WelcomeResult { group_id })
    }

    pub fn export_secret(
        &self,
        group_id: Vec<u8>,
        label: String,
        context: Vec<u8>,
        key_length: u64,
    ) -> Result<ExportedSecret, MLSError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        let secret = inner.with_group(&gid, |group, provider, _signer| {
            group
                .export_secret(provider.crypto(), &label, &context, key_length as usize)
                .map_err(|_| MLSError::SecretExportFailed)
        })?;

        Ok(ExportedSecret {
            secret: secret.to_vec(),
        })
    }

    /// Export a secret using the Puncturable PRF tree (forward-secure within epoch).
    ///
    /// Falls back to `export_secret` with a deterministic label when the group
    /// does not have an `application_export_tree` (legacy groups created before
    /// extensions-draft-08).
    pub fn safe_export_secret(
        &self,
        group_id: Vec<u8>,
        component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |group, provider, _signer| {
            match group.safe_export_secret(provider.crypto(), provider.storage(), component_id) {
                Ok(secret) => Ok(secret),
                Err(_) => {
                    // Fallback: derive a deterministic label from the component ID
                    let label = format!("catbird/safe-export/component/{}", component_id);
                    let context = group_id.clone();
                    group
                        .export_secret(provider.crypto(), &label, &context, 32)
                        .map_err(|_| MLSError::SecretExportFailed)
                }
            }
        })
    }

    /// Export a secret from the pending commit's Puncturable PRF tree.
    ///
    /// Falls back to `export_secret` from the pending commit when the group
    /// does not support safe export.
    pub fn safe_export_secret_from_pending(
        &self,
        group_id: Vec<u8>,
        component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |group, provider, _signer| {
            match group.safe_export_secret_from_pending(
                provider.crypto(),
                provider.storage(),
                component_id,
            ) {
                Ok(secret) => Ok(secret),
                Err(_) => {
                    // Fallback: derive a deterministic label from the component ID
                    let label = format!("catbird/safe-export/component/{}", component_id);
                    let context = group_id.clone();
                    group
                        .export_secret(provider.crypto(), &label, &context, 32)
                        .map_err(|_| MLSError::SecretExportFailed)
                }
            }
        })
    }

    pub fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        crate::debug_log!("[MLS-FFI] get_epoch: Starting");
        crate::debug_log!("[MLS-FFI] Group ID: {}", hex::encode(&group_id));

        let guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire read lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |group, _provider| {
            let epoch = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] Current epoch: {}", epoch);
            Ok(epoch)
        })
    }

    /// Get the MLS confirmation tag for a group.
    /// Returns the TLS-serialized confirmation tag bytes from storage.
    pub fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        crate::debug_log!("[MLS-FFI] get_confirmation_tag: {}", hex::encode(&group_id));

        let guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |_group, provider| {
            let tag: Option<ConfirmationTag> = provider
                .storage()
                .confirmation_tag(&gid)
                .map_err(|_| MLSError::StorageError)?;
            match tag {
                Some(t) => {
                    let bytes = t
                        .tls_serialize_detached()
                        .map_err(|e| MLSError::Internal(format!("TLS serialize: {}", e)))?;
                    crate::debug_log!("[MLS-FFI] Confirmation tag: {} bytes", bytes.len());
                    Ok(bytes)
                }
                None => Err(MLSError::Internal("No confirmation tag found".to_string())),
            }
        })
    }

    /// Return the RFC 9420 §8.7 `epoch_authenticator` for the group's current
    /// epoch. Used to bind quorum-reset reports (spec §8.6 / ADR-002) so that a
    /// stale client can't forge a vote for an epoch it never observed.
    pub fn epoch_authenticator(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        crate::debug_log!("[MLS-FFI] epoch_authenticator: {}", hex::encode(&group_id));

        let guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |group, _provider| {
            let auth = group.epoch_authenticator();
            let bytes = auth.as_slice().to_vec();
            crate::debug_log!("[MLS-FFI] epoch_authenticator: {} bytes", bytes.len());
            Ok(bytes)
        })
    }

    /// Read encrypted group metadata from MLS group context.
    /// Returns JSON bytes of the metadata, or empty vec if none set.
    pub fn get_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        crate::info_log!("[MLS-FFI] get_group_metadata: {}", hex::encode(&group_id));

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        match inner.get_group_metadata(&group_id)? {
            Some(meta) => meta
                .to_extension_bytes()
                .map_err(|e| MLSError::Internal(format!("JSON serialize: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    /// Update group metadata. Returns commit bytes to send to server.
    ///
    /// DEPRECATED — produces a no-op for plaintext under the metadata cutover
    /// (Phase A removed the 0xff00 write). New callers should use
    /// `update_group_metadata_encrypted` which atomically returns the
    /// encrypted blob, locator, version, and final MetadataReference.
    pub fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] update_group_metadata (deprecated, no-op for plaintext): {}",
            hex::encode(&group_id)
        );

        let metadata =
            crate::group_metadata::GroupMetadata::from_extension_bytes(&metadata_json)
                .map_err(|e| MLSError::invalid_input(format!("Invalid metadata JSON: {}", e)))?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let commit_bytes = inner.update_group_metadata(&group_id, metadata)?;

        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!("[MLS-FFI] Failed to flush after metadata update: {:?}", e);
            e
        })?;
        inner.maybe_truncate_checkpoint();

        Ok(commit_bytes)
    }

    /// Atomic encrypted metadata update (Phase A.2).
    ///
    /// Stages the GroupContextExtensions commit + derives the post-commit
    /// metadata key from the staged commit's exporter + encrypts a fresh
    /// `GroupMetadataV1` payload, all in one call. Returns everything the
    /// caller needs to upload + send + merge:
    /// - `commit_bytes` → send to DS via `commitGroupChange`/`updateConvo`
    /// - `metadata_blob_ciphertext` → upload via `putGroupMetadataBlob` with
    ///   `metadata_blob_locator` and `metadata_version`
    /// - `metadata_reference_json` → cache locally (final reference, real hash)
    ///
    /// After server ACK, caller invokes `merge_pending_commit(group_id)` to
    /// apply the commit locally; joiners on the new epoch read the
    /// MetadataReference from AppDataDictionary 0x8001 and bootstrap the
    /// blob via `getGroupMetadataBlob`.
    pub fn update_group_metadata_encrypted(
        &self,
        group_id: Vec<u8>,
        title: Option<String>,
        description: Option<String>,
        avatar_blob_locator: Option<String>,
        avatar_content_type: Option<String>,
    ) -> Result<UpdateGroupMetadataResultFfi, MLSError> {
        self.check_suspended()?;
        crate::info_log!(
            "[MLS-FFI] update_group_metadata_encrypted: {}",
            hex::encode(&group_id)
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let result = inner.update_group_metadata_encrypted(
            &group_id,
            title,
            description,
            avatar_blob_locator,
            avatar_content_type,
        )?;

        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] Failed to flush after encrypted metadata update: {:?}",
                e
            );
            e
        })?;
        inner.maybe_truncate_checkpoint();

        Ok(UpdateGroupMetadataResultFfi {
            commit_bytes: result.commit_bytes,
            metadata_blob_ciphertext: result.metadata_blob_ciphertext,
            metadata_reference_json: result.metadata_reference_json,
            metadata_version: result.metadata_version,
            metadata_blob_locator: result.metadata_blob_locator,
        })
    }

    /// Get the tree hash for a group at its current epoch
    /// Used for tree hash pinning to detect state divergence
    pub fn get_tree_hash(&self, group_id: Vec<u8>) -> Result<TreeHashData, MLSError> {
        crate::debug_log!("[MLS-FFI] get_tree_hash: Starting");
        crate::debug_log!("[MLS-FFI] Group ID: {}", hex::encode(&group_id));

        let guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire read lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |group, _provider| {
            let epoch = group.epoch().as_u64();
            // tree_hash() returns &[u8] directly - no crypto provider needed
            let tree_hash = group.tree_hash().to_vec();

            crate::debug_log!(
                "[MLS-FFI] Tree hash at epoch {}: {} bytes",
                epoch,
                tree_hash.len()
            );

            Ok(TreeHashData { epoch, tree_hash })
        })
    }

    /// Manually export epoch secret for a group
    /// Call this after creating the conversation record in SQLCipher to ensure
    /// the foreign key constraint is satisfied when storing the epoch secret
    pub fn export_epoch_secret(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.check_suspended()?;
        crate::info_log!("[MLS-FFI] export_epoch_secret: Manually exporting epoch secret");
        crate::debug_log!("[MLS-FFI] Group ID: {}", hex::encode(&group_id));

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire read lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);
        let epoch_manager = inner.epoch_secret_manager().clone();

        inner.with_group(&gid, |group, provider, _signer| {
            let epoch = group.epoch().as_u64();
            crate::debug_log!("[MLS-FFI] Exporting secret for epoch {}", epoch);

            crate::async_runtime::block_on(
                epoch_manager.export_current_epoch_secret(group, provider),
            )
            .map_err(|e| {
                crate::error_log!("[MLS-FFI] ❌ Failed to export epoch secret: {:?}", e);
                MLSError::StorageFailed
            })?;

            crate::info_log!("[MLS-FFI] ✅ Successfully exported epoch {} secret", epoch);
            Ok(())
        })
    }

    /// Derive the current metadata key for an already-joined group.
    ///
    /// Call this immediately after joining a group via Welcome or External Commit
    /// to bootstrap metadata decryption without waiting for a subsequent commit.
    /// Returns `None` if the group is not found or key derivation fails.
    pub fn get_current_metadata(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Option<CurrentMetadataInfo>, MLSError> {
        let group_id_hex = hex::encode(&group_id);
        crate::info_log!(
            "[MLS-FFI] get_current_metadata: Deriving metadata key for group {}",
            &group_id_hex[..std::cmp::min(16, group_id_hex.len())]
        );

        let mut guard = self.inner.lock().map_err(|e| {
            crate::error_log!("[MLS-FFI] ERROR: Failed to acquire lock: {:?}", e);
            MLSError::ContextNotInitialized
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        match inner.with_group(&gid, |group, provider, _signer| {
            let epoch = group.epoch().as_u64();
            let metadata_reference_json = current_metadata_reference_json(group);
            if metadata_reference_json.is_none() {
                crate::info_log!(
                    "[MLS-FFI] No metadata reference found in AppDataDictionary for epoch {} — returning key without reference",
                    epoch
                );
            }

            let key = crate::metadata::derive_metadata_key_from_group(
                group,
                provider.crypto(),
                provider.storage(),
                &group_id,
                epoch,
            )
            .map_err(|e| {
                crate::error_log!(
                    "[MLS-FFI] ❌ Failed to derive metadata key at epoch {}: {:?}",
                    epoch,
                    e
                );
                MLSError::StorageFailed
            })?;

            crate::info_log!(
                "[MLS-FFI] ✅ Derived metadata key for epoch {}",
                epoch
            );

            Ok(Some(CurrentMetadataInfo {
                metadata_key: key.to_vec(),
                epoch,
                metadata_reference_json,
            }))
        }) {
            Ok(Some(info)) => Ok(Some(info)),
            Ok(None) => Ok(None),
            Err(MLSError::GroupNotFound { .. }) => {
                crate::info_log!("[MLS-FFI] Group not found — returning None");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn process_commit(
        &self,
        group_id: Vec<u8>,
        commit_data: Vec<u8>,
    ) -> Result<ProcessCommitResult, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        // Export epoch secret before processing (may advance epoch)
        let epoch_manager = inner.epoch_secret_manager().clone();

        // Task #33: stage-instead-of-merge. The closure now returns the proposals + metadata
        // derived from the StagedCommit, plus the StagedCommit itself as `Some(staged)` for
        // the caller to stash in `pending_incoming_merges`. Platform must explicitly call
        // `merge_incoming_commit(group_id, target_epoch)` to advance the epoch.
        let (
            update_proposals,
            add_proposals,
            remove_proposals,
            metadata_info,
            target_epoch,
            staged_commit_opt,
        ): (
            Vec<UpdateProposalInfo>,
            Vec<AddProposalInfo>,
            Vec<RemoveProposalInfo>,
            Option<CommitMetadataInfo>,
            u64,
            Option<Box<StagedCommit>>,
        ) = inner.with_group(&gid, |group, provider, _signer| {
                let (mls_msg, _) =
                    MlsMessageIn::tls_deserialize_bytes(&commit_data).map_err(|e| {
                        crate::error_log!(
                            "[MLS-FFI] ❌ process_commit: TLS deserialization failed: {:?}",
                            e
                        );
                        MLSError::SerializationError
                    })?;

                let protocol_msg: ProtocolMessage = mls_msg.try_into().map_err(|e| {
                    crate::error_log!(
                        "[MLS-FFI] ❌ process_commit: ProtocolMessage conversion failed: {:?}",
                        e
                    );
                    MLSError::commit_processing_failed(format!(
                        "ProtocolMessage conversion failed: {e:?}"
                    ))
                })?;

                let processed = process_protocol_message(
                    group,
                    provider,
                    protocol_msg,
                    "PROCESS-COMMIT",
                )
                .map_err(|e| {
                    crate::error_log!(
                        "[MLS-FFI] ❌ process_commit: OpenMLS process_message error: {:?}",
                        e
                    );
                    MLSError::commit_processing_failed(format!("OpenMLS: {e:?}"))
                })?;

                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        // Extract Update proposals
                        let updates: Vec<UpdateProposalInfo> = staged
                            .update_proposals()
                            .filter_map(|queued_proposal| {
                                let update_proposal = queued_proposal.update_proposal();
                                let leaf_node = update_proposal.leaf_node();
                                let new_credential = leaf_node.credential();

                                // Extract leaf index from sender
                                let leaf_index = match queued_proposal.sender() {
                                    Sender::Member(leaf_index) => leaf_index.u32(),
                                    _ => return None,
                                };

                                // Get old credential from current group state
                                if let Some(old_member) =
                                    group.members().find(|m| m.index.u32() == leaf_index)
                                {
                                    let old_cred_type =
                                        format!("{:?}", old_member.credential.credential_type());
                                    let old_identity =
                                        old_member.credential.serialized_content().to_vec();

                                    let new_cred_type =
                                        format!("{:?}", new_credential.credential_type());
                                    let new_identity = new_credential.serialized_content().to_vec();

                                    Some(UpdateProposalInfo {
                                        leaf_index,
                                        old_credential: CredentialData {
                                            credential_type: old_cred_type,
                                            identity: old_identity,
                                        },
                                        new_credential: CredentialData {
                                            credential_type: new_cred_type,
                                            identity: new_identity,
                                        },
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect();

                        // Extract Add proposals
                        let adds: Vec<AddProposalInfo> = staged
                            .add_proposals()
                            .filter_map(|queued_proposal| {
                                let add_proposal = queued_proposal.add_proposal();
                                let key_package = add_proposal.key_package();
                                let credential = key_package.leaf_node().credential();

                                let cred_type = format!("{:?}", credential.credential_type());
                                let identity = credential.serialized_content().to_vec();

                                // Extract key package reference (hash of key package)
                                let key_package_bytes =
                                    key_package.tls_serialize_detached().ok()?;
                                let key_package_ref = provider
                                    .crypto()
                                    .hash(group.ciphersuite().hash_algorithm(), &key_package_bytes)
                                    .ok()?;

                                Some(AddProposalInfo {
                                    credential: CredentialData {
                                        credential_type: cred_type,
                                        identity,
                                    },
                                    key_package_ref,
                                })
                            })
                            .collect();

                        // Extract Remove proposals
                        let removes: Vec<RemoveProposalInfo> = staged
                            .remove_proposals()
                            .map(|queued_proposal| {
                                let remove_proposal = queued_proposal.remove_proposal();
                                let removed_index = remove_proposal.removed().u32();

                                RemoveProposalInfo { removed_index }
                            })
                            .collect();

                        // Metadata: derive the new epoch's metadata key from the staged
                        // commit's exporter BEFORE `staged` is moved into the tuple.
                        let target_epoch = staged.group_context().epoch().as_u64();
                        let metadata_key_bytes = match crate::metadata::derive_metadata_key(
                            &staged,
                            provider.crypto(),
                            &group_id,
                            target_epoch,
                        ) {
                            Ok(key) => {
                                crate::info_log!(
                                    "[MLS-FFI] 🔑 process_commit: metadata key derived for epoch {}",
                                    target_epoch
                                );
                                Some(key.to_vec())
                            }
                            Err(e) => {
                                crate::warn_log!(
                                    "[MLS-FFI] ⚠️ process_commit: metadata key derivation failed: {:?}",
                                    e
                                );
                                None
                            }
                        };

                        // Task #33: export the pre-merge epoch secret now (forward-secrecy
                        // window). Merge itself is deferred to `merge_incoming_commit` —
                        // which also runs post-merge `cleanup_old_epochs`.
                        if let Err(e) = crate::async_runtime::block_on(
                            epoch_manager.export_current_epoch_secret(group, provider),
                        ) {
                            crate::warn_log!(
                                "[MLS-FFI] ⚠️ process_commit: Failed to export epoch secret: {:?}",
                                e
                            );
                        }

                        let metadata_reference_json = current_metadata_reference_json(group);
                        let metadata_derived =
                            metadata_key_bytes.map(|metadata_key| CommitMetadataInfo {
                                metadata_key,
                                epoch: target_epoch,
                                metadata_reference_json,
                            });

                        crate::info_log!(
                            "[MLS-FFI] 📦 process_commit: STAGING commit for explicit merge (target epoch {})",
                            target_epoch
                        );

                        Ok((updates, adds, removes, metadata_derived, target_epoch, Some(staged)))
                    }
                    _ => Err(MLSError::InvalidCommit),
                }
            })?;

        // NB: `new_epoch` in the returned `ProcessCommitResult` now reflects the
        // **target epoch** of the staged commit (the epoch the group will be at
        // AFTER the platform calls `merge_incoming_commit`), not the current group
        // epoch. This is a wire-semantics change vs. the prior auto-merge path.
        let new_epoch = target_epoch;

        // Flush database (no epoch advance yet, but persists staging-related writes
        // from process_protocol_message — proposal stores, etc.)
        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ process_commit: Failed to flush database: {:?}",
                e
            );
            e
        })?;
        inner.maybe_truncate_checkpoint();

        // Task #33: stash staged commit for explicit platform confirmation.
        // We release the `guard` (inner lock) first — `pending_incoming_merges` is a
        // separate mutex and we don't want to hold both.
        drop(guard);

        if let Some(staged) = staged_commit_opt {
            let mut pending = self.pending_incoming_merges.lock().map_err(|_| {
                crate::error_log!(
                    "[MLS-FFI] ❌ process_commit: pending_incoming_merges mutex poisoned"
                );
                MLSError::ContextNotInitialized
            })?;
            let key = (group_id.clone(), target_epoch);
            if pending.insert(key, staged).is_some() {
                crate::warn_log!(
                    "[MLS-FFI] ⚠️ process_commit: Overwrote existing pending staged commit for group {} epoch {} (duplicate delivery)",
                    hex::encode(&group_id),
                    target_epoch
                );
            }
        }

        Ok(ProcessCommitResult {
            new_epoch,
            update_proposals,
            add_proposals,
            remove_proposals,
            commit_metadata: metadata_info,
        })
    }

    /// Clear pending commit for a group
    /// This should be called when a commit is rejected by the delivery service
    /// to clean up pending state in OpenMLS
    pub fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |group, provider, _signer| {
            group
                .clear_pending_commit(provider.storage())
                .map_err(|_| MLSError::OpenMLSError)?;
            Ok(())
        })
    }

    /// Store a proposal in the proposal queue after validation
    /// The application should inspect the proposal before storing it
    pub fn store_proposal(
        &self,
        group_id: Vec<u8>,
        _proposal_ref: ProposalRef,
    ) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |_group, _provider, _signer| {
            // In OpenMLS, proposals are already stored when processed
            // This function is a placeholder for explicit application control
            // The proposal was stored during process_message call
            // Application can maintain its own list of approved proposals
            Ok(())
        })
    }

    /// List all pending proposals for a group
    pub fn list_pending_proposals(&self, group_id: Vec<u8>) -> Result<Vec<ProposalRef>, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |group, provider| {
            let proposal_refs: Vec<ProposalRef> = group
                .pending_proposals()
                .filter_map(|queued_proposal| {
                    // Compute proposal reference by hashing the proposal
                    // Since proposal_reference() is pub(crate), we compute our own identifier
                    let proposal = queued_proposal.proposal();
                    let proposal_bytes = proposal.tls_serialize_detached().ok()?;

                    let proposal_ref_bytes = provider
                        .crypto()
                        .hash(group.ciphersuite().hash_algorithm(), &proposal_bytes)
                        .ok()?;

                    Some(ProposalRef {
                        data: proposal_ref_bytes,
                    })
                })
                .collect();

            Ok(proposal_refs)
        })
    }

    /// List all pending proposals for a group with details
    pub fn get_pending_proposal_details(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Vec<PendingProposalDetail>, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        inner.get_pending_proposal_details(&group_id)
    }

    /// Remove a proposal from the proposal queue
    pub fn remove_proposal(
        &self,
        group_id: Vec<u8>,
        proposal_ref: ProposalRef,
    ) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |group, provider, _signer| {
            // Remove proposal from the store
            let proposal_reference =
                openmls::prelude::hash_ref::ProposalRef::tls_deserialize_exact_bytes(
                    &proposal_ref.data,
                )
                .map_err(|_| MLSError::OpenMLSError)?;
            group
                .remove_pending_proposal(provider.storage(), &proposal_reference)
                .map_err(|_| MLSError::OpenMLSError)?;
            Ok(())
        })
    }

    /// Commit all pending proposals that have been validated and stored
    pub fn commit_pending_proposals(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group(&gid, |group, provider, signer| {
            // Android H4 drift regression guard: this function is
            // `commit_pending_proposals`. If the proposal store is empty there
            // is nothing to commit — returning early prevents building an
            // empty/metadata-only commit that advances the local epoch while
            // the server rejects the no-op, causing a ~1-epoch-per-sync-tick
            // drift that breaks sendMessage with TreeStateDiverged 409s.
            // Both callers (orchestrator/sync.rs, groups.rs::commit_self_remove_proposals)
            // already handle `InvalidInput` as "nothing to commit".
            if group.pending_proposals().next().is_none() {
                return Err(MLSError::invalid_input("No pending proposals to commit"));
            }

            let planned_reference_json = crate::metadata::planned_metadata_reference_json(
                crate::metadata::current_metadata_reference(group).as_ref(),
                crate::metadata::metadata_payload_from_group(group).is_some(),
                false,
            )
            .map_err(|e| MLSError::Internal(format!("plan metadata reference: {:?}", e)))?;

            let mut commit_builder = group.commit_builder().consume_proposal_store(true);
            if let Some(ref_json) = planned_reference_json.clone() {
                commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                        ref_json,
                    ),
                )));
            }

            let mut commit_stage = commit_builder
                .load_psks(provider.storage())
                .map_err(|_| MLSError::OpenMLSError)?;

            if let Some(ref_json) = planned_reference_json {
                let mut updater = commit_stage.app_data_dictionary_updater();
                updater.set(ComponentData::from_parts(
                    crate::metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.into(),
                ));
                commit_stage.with_app_data_dictionary_updates(updater.changes());
            }

            let commit_bundle = commit_stage
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|_| MLSError::OpenMLSError)?
                .stage_commit(provider)
                .map_err(|_| MLSError::OpenMLSError)?;

            let (commit_msg, _welcome, _group_info) = commit_bundle.into_contents();

            // Merge the pending commit
            group
                .merge_pending_commit(provider)
                .map_err(|_| MLSError::OpenMLSError)?;

            // Serialize the commit
            let commit_data = commit_msg
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;

            Ok(commit_data)
        })
    }

    /// Merge a pending commit after validation
    /// This should be called after the commit has been accepted by the delivery service
    pub fn merge_pending_commit(
        &self,
        group_id: Vec<u8>,
    ) -> Result<MergePendingCommitResult, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        // CRITICAL: Export epoch secret BEFORE merging commit
        // This allows decrypting messages from the current epoch after the group advances
        let epoch_manager = inner.epoch_secret_manager().clone();

        inner.with_group(&gid, |group, provider, _signer| {
            // Secret tree state logging BEFORE merge
            let epoch_before = group.epoch().as_u64();
            let member_count_before_merge = group.members().count();

            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - merge_pending_commit");
            crate::debug_log!("[MLS-FFI]   Group: {}", hex::encode(&group_id));
            crate::debug_log!("[MLS-FFI]   Epoch before: {}", epoch_before);
            crate::debug_log!("[MLS-FFI]   Member count before: {}", member_count_before_merge);
            crate::debug_log!("[MLS-FFI]   Operation type: MERGE_COMMIT");

            crate::debug_log!("[MLS-FFI] merge_pending_commit: Exporting current epoch secret before advancing");

            // Export current epoch secret before the commit advances the epoch
            if let Err(e) = crate::async_runtime::block_on(
                epoch_manager.export_current_epoch_secret(group, provider)
            ) {
                crate::warn_log!("[MLS-FFI] ⚠️ WARNING: Failed to export epoch secret: {:?}", e);
                crate::debug_log!("[MLS-FFI]   This may cause decryption failures for delayed messages from current epoch");
                // Continue with merge - epoch secret export is best-effort
            }

            group.merge_pending_commit(provider)
                .map_err(|e| {
                    crate::error_log!("[MLS-FFI] 🔐 SECRET TREE ERROR - merge failed: {:?}", e);
                    MLSError::MergeFailed
                })?;

            // Secret tree state logging AFTER merge
            let epoch_after = group.epoch().as_u64();
            let member_count_after_merge = group.members().count();

            crate::debug_log!("[MLS-FFI] 🔐 SECRET TREE STATE - after merge");
            crate::debug_log!("[MLS-FFI]   Epoch after: {}", epoch_after);
            crate::debug_log!("[MLS-FFI]   Epoch change: {} -> {}", epoch_before, epoch_after);
            crate::debug_log!("[MLS-FFI]   Member count after: {}", member_count_after_merge);

            if epoch_after <= epoch_before {
                crate::error_log!("[MLS-FFI] ❌ CRITICAL: Epoch did not advance! Before: {}, After: {}", epoch_before, epoch_after);
            }

            if member_count_before_merge != member_count_after_merge {
                crate::debug_log!("[MLS-FFI]   Member count changed: {} -> {}", member_count_before_merge, member_count_after_merge);
            }

            crate::debug_log!("[MLS-FFI] merge_pending_commit: Advanced to epoch {}", epoch_after);
            Ok(epoch_after)
        })?;

        let (new_epoch, commit_metadata) = inner.with_group(&gid, |group, provider, _signer| {
            let epoch = group.epoch().as_u64();

            // Metadata (sender-side): derive the metadata key for the new epoch
            // from the group's exporter after merge. Uses safe_export_secret (PPRF)
            // when available for intra-epoch forward secrecy, falling back to
            // export_secret for legacy groups.
            let metadata_info = match crate::metadata::derive_metadata_key_from_group(
                group,
                provider.crypto(),
                provider.storage(),
                &group_id,
                epoch,
            ) {
                Ok(key) => {
                    crate::info_log!(
                        "[MLS-FFI] 🔑 merge_pending_commit: metadata key derived for epoch {}",
                        epoch
                    );
                    Some(CommitMetadataInfo {
                        metadata_key: key.to_vec(),
                        epoch,
                        metadata_reference_json: current_metadata_reference_json(group),
                    })
                }
                Err(e) => {
                    crate::warn_log!(
                        "[MLS-FFI] ⚠️ merge_pending_commit: metadata key derivation failed: {:?}",
                        e
                    );
                    None
                }
            };

            Ok((epoch, metadata_info))
        })?;

        // Cleanup old epoch secrets for forward secrecy
        // We retain the last 5 epochs to handle delayed messages/reordering
        let retention_epochs = 5u64;
        if let Err(e) = crate::async_runtime::block_on(epoch_manager.cleanup_old_epochs(
            gid.as_slice(),
            new_epoch,
            retention_epochs,
        )) {
            crate::warn_log!("[MLS-FFI] ⚠️ Failed to cleanup old epochs: {:?}", e);
            // Non-fatal - continue
        }

        // 🔒 CRITICAL: Force database flush after commit merge
        // Epoch advancement creates new secret tree state that must be persisted
        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ WARNING: Failed to flush database after commit merge: {:?}",
                e
            );
            e
        })?;

        // Signal-style budget checkpoint: keep WAL perpetually small
        inner.maybe_truncate_checkpoint();
        crate::debug_log!("[MLS-FFI] ✅ Database flushed after commit merge");

        Ok(MergePendingCommitResult {
            new_epoch,
            commit_metadata,
        })
    }

    /// Merge a staged commit after validation
    /// This should be called after validating incoming commits from other members
    pub fn merge_staged_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        // OpenMLS uses the same internal method for both pending and staged commits
        self.merge_pending_commit(group_id).map(|r| r.new_epoch)
    }

    /// Task #33: merge an incoming `StagedCommit` that was previously staged by
    /// `process_message` / `process_message_async` / `decrypt_message` /
    /// `decrypt_message_async` / `process_commit`.
    ///
    /// This is the caller-driven confirmation step that replaces the previous
    /// auto-merge behavior. The platform must call this once it has:
    ///   - Validated the incoming commit against its recovery/sync policy
    ///   - Persisted any pre-merge state it needs (ordering, ack state, etc.)
    ///
    /// Returns the new (post-merge) epoch.
    ///
    /// Errors:
    ///   - `MLSError::invalid_input` if no staged commit exists for
    ///     `(group_id, target_epoch)` — the entry was never staged, or
    ///     `discard_incoming_commit` already cleared it.
    ///   - `MLSError::MergeFailed` if OpenMLS `merge_staged_commit` fails; the
    ///     StagedCommit is dropped (caller must re-fetch from the DS if recovery
    ///     is needed). This matches the pre-refactor behavior where a failed
    ///     merge left no resumable state.
    pub fn merge_incoming_commit(
        &self,
        group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<u64, MLSError> {
        self.check_suspended()?;

        // Pop the staged commit under the pending-map lock, then release
        // before touching the inner MLS context — never hold both at once.
        let staged = {
            let mut pending = self.pending_incoming_merges.lock().map_err(|_| {
                crate::error_log!("[MLS-FFI] ❌ merge_incoming_commit: pending_incoming_merges mutex poisoned");
                MLSError::ContextNotInitialized
            })?;
            pending.remove(&(group_id.clone(), target_epoch))
        }
        .ok_or_else(|| {
            crate::warn_log!(
                "[MLS-FFI] ⚠️ merge_incoming_commit: no pending staged commit for group {} epoch {}",
                hex::encode(&group_id),
                target_epoch
            );
            MLSError::invalid_input(format!(
                "no pending staged commit for epoch {} (not staged, or already discarded)",
                target_epoch
            ))
        })?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;
        let gid = GroupId::from_slice(&group_id);
        let epoch_manager = inner.epoch_secret_manager().clone();

        let new_epoch = inner.with_group(&gid, |group, provider, _signer| {
            let epoch_before = group.epoch().as_u64();
            group.merge_staged_commit(provider, *staged).map_err(|e| {
                crate::error_log!(
                    "[MLS-FFI] ❌ merge_incoming_commit: merge_staged_commit failed: {:?}",
                    e
                );
                MLSError::MergeFailed
            })?;
            let epoch_after = group.epoch().as_u64();

            crate::info_log!(
                "[MLS-FFI] ✅ merge_incoming_commit: merged staged commit for group {}, epoch {} -> {}",
                hex::encode(&group_id),
                epoch_before,
                epoch_after
            );

            if epoch_after <= epoch_before {
                crate::error_log!(
                    "[MLS-FFI] ❌ CRITICAL: merge_incoming_commit did not advance epoch! {} -> {}",
                    epoch_before,
                    epoch_after
                );
            }

            // Cleanup old epoch secrets after incoming commit advances the epoch.
            // This was previously done in the auto-merge path; we move it here so
            // the retention policy still runs when the platform confirms the merge.
            let retention_epochs = 5u64;
            if let Err(e) = crate::async_runtime::block_on(
                epoch_manager.cleanup_old_epochs(
                    group.group_id().as_slice(),
                    epoch_after,
                    retention_epochs,
                ),
            ) {
                crate::warn_log!(
                    "[MLS-FFI] ⚠️ merge_incoming_commit: cleanup_old_epochs failed: {:?}",
                    e
                );
            }

            Ok(epoch_after)
        })?;

        // Persist merge result.
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ merge_incoming_commit: Failed to flush database: {:?}",
                e
            );
            e
        })?;
        inner.maybe_truncate_checkpoint();

        Ok(new_epoch)
    }

    /// Task #33: discard an incoming `StagedCommit` that was previously staged,
    /// without advancing the local epoch.
    ///
    /// Use this when the platform decides (e.g. via recovery policy) that the
    /// staged commit should not be applied — for instance if a fork/reset has
    /// been observed and the platform is about to initiate a rejoin.
    ///
    /// OpenMLS's own storage is **not** modified by this call. Only the
    /// in-memory staging handle is dropped. Any OpenMLS-side bookkeeping for
    /// the staged commit (proposal queue, etc.) is unaffected; the staged
    /// commit will be garbage collected via the normal epoch-advance path.
    ///
    /// Idempotent: no-op if no entry exists for `(group_id, target_epoch)`.
    pub fn discard_incoming_commit(
        &self,
        group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<(), MLSError> {
        self.check_suspended()?;
        let mut pending = self.pending_incoming_merges.lock().map_err(|_| {
            crate::error_log!(
                "[MLS-FFI] ❌ discard_incoming_commit: pending_incoming_merges mutex poisoned"
            );
            MLSError::ContextNotInitialized
        })?;
        if pending.remove(&(group_id.clone(), target_epoch)).is_some() {
            crate::info_log!(
                "[MLS-FFI] 🗑️ discard_incoming_commit: dropped staged commit for group {} epoch {}",
                hex::encode(&group_id),
                target_epoch
            );
        } else {
            crate::debug_log!(
                "[MLS-FFI] discard_incoming_commit: no staged commit to drop for group {} epoch {} (already merged, discarded, or never staged)",
                hex::encode(&group_id),
                target_epoch
            );
        }
        Ok(())
    }

    /// Task #33 (transitional): wrapper that runs `process_message` and
    /// immediately merges any incoming staged commit, preserving the
    /// pre-refactor auto-merge behavior.
    ///
    /// **DEPRECATED.** This exists only for platforms (iOS, Android, catmos)
    /// that have not yet migrated to the explicit stage/merge contract.
    /// New code should call `process_message` + (`merge_incoming_commit` or
    /// `discard_incoming_commit`).
    ///
    /// Logs a warning on every invocation — see server logs for migration
    /// progress.
    pub fn process_message_legacy_automerge(
        &self,
        group_id: Vec<u8>,
        message_data: Vec<u8>,
    ) -> Result<ProcessedContent, MLSError> {
        crate::warn_log!(
            "[MLS-FFI] ⚠️ DEPRECATED: process_message_legacy_automerge called for group {} — migrate the caller to explicit process_message + merge_incoming_commit",
            hex::encode(&group_id)
        );

        let processed = self.process_message(group_id.clone(), message_data)?;

        // Only StagedCommit results need the auto-merge step. Application/Proposal
        // results didn't stage anything and we simply return them unchanged.
        if let ProcessedContent::StagedCommit {
            new_epoch: target_epoch,
            ..
        } = &processed
        {
            let target_epoch = *target_epoch;
            // Best-effort: if merge fails, return the error. The staging was already
            // consumed by process_message, so the caller cannot retry.
            let merged_epoch = self.merge_incoming_commit(group_id.clone(), target_epoch)?;
            crate::info_log!(
                "[MLS-FFI] process_message_legacy_automerge: merged group {} to epoch {}",
                hex::encode(&group_id),
                merged_epoch
            );
        }

        Ok(processed)
    }

    /// Check if a group exists in local storage
    /// - Parameters:
    ///   - group_id: Group identifier to check
    /// - Returns: true if group exists, false otherwise
    pub fn group_exists(&self, group_id: Vec<u8>) -> bool {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.as_ref() {
            Some(inner) => inner.has_group(&group_id),
            None => false, // Context is closed
        }
    }

    /// Get the current member count of a group
    ///
    /// - Parameters:
    ///   - group_id: Group identifier
    /// - Returns: Number of members in the group
    /// - Throws: MLSError if group not found
    pub fn get_group_member_count(&self, group_id: Vec<u8>) -> Result<u32, MLSError> {
        crate::debug_log!(
            "[MLS-FFI] get_group_member_count: Starting for group {}",
            hex::encode(&group_id)
        );

        let gid = GroupId::from_slice(&group_id);
        let mut guard = self.inner.lock().map_err(|_| MLSError::InvalidInput {
            message: "Failed to acquire lock".to_string(),
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        inner.with_group(&gid, |group, _provider, _signer| {
            let member_count = group.members().count() as u32;
            crate::debug_log!(
                "[MLS-FFI] get_group_member_count: Group has {} members",
                member_count
            );
            Ok(member_count)
        })
    }

    /// Get detailed debug information about all group members
    ///
    /// Returns information about each member including their leaf index,
    /// credential identity, and credential type. Useful for diagnosing
    /// member duplication issues.
    ///
    /// - Parameters:
    ///   - group_id: Group identifier
    /// - Returns: GroupDebugInfo with all member details
    /// - Throws: MLSError if group not found
    pub fn debug_group_members(&self, group_id: Vec<u8>) -> Result<GroupDebugInfo, MLSError> {
        crate::debug_log!(
            "[MLS-FFI] 🔍 debug_group_members: Starting for group {}",
            hex::encode(&group_id)
        );

        let gid = GroupId::from_slice(&group_id);
        let mut guard = self.inner.lock().map_err(|_| MLSError::InvalidInput {
            message: "Failed to acquire lock".to_string(),
        })?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        inner.with_group(&gid, |group, _provider, _signer| {
            let epoch = group.epoch().as_u64();
            let total_members = group.members().count() as u32;

            crate::debug_log!("[MLS-FFI] 🔍 Group epoch: {}", epoch);
            crate::debug_log!("[MLS-FFI] 🔍 Total members: {}", total_members);

            let mut members = Vec::new();
            let mut identity_counts = std::collections::HashMap::new();

            for (index, member) in group.members().enumerate() {
                let credential = member.credential;
                let identity = credential.serialized_content().to_vec();
                let credential_type = format!("{:?}", credential.credential_type());
                let leaf_index = member.index.u32();

                // Track duplicates
                let identity_hex = hex::encode(&identity);
                *identity_counts.entry(identity_hex.clone()).or_insert(0) += 1;

                crate::debug_log!(
                    "[MLS-FFI] 🔍 Member {}: leaf_index={}, identity={} ({} bytes), type={}",
                    index,
                    leaf_index,
                    truncate_str(&identity_hex, 16),
                    identity.len(),
                    credential_type
                );

                members.push(GroupMemberDebugInfo {
                    leaf_index,
                    credential_identity: identity,
                    credential_type,
                });
            }

            // Report duplicates
            crate::debug_log!("[MLS-FFI] 🔍 Unique identities: {}", identity_counts.len());
            for (identity, count) in identity_counts.iter() {
                if *count > 1 {
                    crate::warn_log!(
                        "[MLS-FFI] ⚠️ DUPLICATE: Identity {} appears {} times!",
                        truncate_str(identity, 16),
                        count
                    );
                }
            }

            Ok(GroupDebugInfo {
                group_id: group_id.clone(),
                epoch,
                total_members,
                members,
            })
        })
    }

    /// Export a group's state for persistent storage
    ///
    /// Returns serialized bytes that can be stored in the keychain
    /// and later restored with import_group_state.
    ///
    /// - Parameters:
    ///   - group_id: Group identifier to export
    /// - Returns: Serialized group state bytes
    /// - Throws: MLSError if group not found or serialization fails
    pub fn export_group_state(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        crate::debug_log!("[MLS-FFI] export_group_state: Starting");

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let state_bytes = inner.export_group_state(&group_id)?;

        crate::debug_log!(
            "[MLS-FFI] export_group_state: Complete, {} bytes",
            state_bytes.len()
        );
        Ok(state_bytes)
    }

    /// Import a group's state from persistent storage
    ///
    /// Restores a previously exported group state. The group will be
    /// available for all MLS operations after import.
    ///
    /// - Parameters:
    ///   - state_bytes: Serialized group state from export_group_state
    /// - Returns: Group ID of the imported group
    /// - Throws: MLSError if deserialization fails
    pub fn import_group_state(&self, state_bytes: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.check_suspended()?;
        crate::debug_log!(
            "[MLS-FFI] import_group_state: Starting with {} bytes",
            state_bytes.len()
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        let group_id = inner.import_group_state(&state_bytes)?;

        crate::debug_log!(
            "[MLS-FFI] import_group_state: Complete, group ID: {}",
            hex::encode(&group_id)
        );
        Ok(group_id)
    }

    // Note: serialize_storage and deserialize_storage methods removed
    // With SqliteStorageProvider, persistence is automatic - no manual save/load needed
    // For per-DID isolation, just create separate contexts with different storage paths

    /// Get the number of key package bundles currently cached
    ///
    /// This provides a direct count of key package bundles available for
    /// processing Welcome messages. A count of 0 indicates that Welcome
    /// messages cannot be processed and bundles need to be created.
    ///
    /// - Returns: Number of cached key package bundles
    /// - Throws: MLSError if context is not initialized
    pub fn get_key_package_bundle_count(&self) -> Result<u64, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let count = inner.key_package_bundles().len() as u64;
        crate::debug_log!(
            "[MLS-FFI] get_key_package_bundle_count: {} bundles in cache",
            count
        );

        Ok(count)
    }

    /// 🔍 DEBUG: List all key package hashes from manifest storage
    ///
    /// Returns hex-encoded hash references for all key packages stored in the manifest.
    /// This is useful for diagnosing NoMatchingKeyPackage errors by comparing with
    /// the hash used in a Welcome message.
    ///
    /// - Returns: Array of hex-encoded hash references
    /// - Throws: MLSError if context is not initialized
    pub fn debug_list_key_package_hashes(&self) -> Result<Vec<String>, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let hashes: Vec<String> = inner
            .key_package_bundles()
            .keys()
            .map(hex::encode)
            .collect();

        crate::info_log!(
            "[MLS-FFI] 🔍 debug_list_key_package_hashes: Found {} hashes in manifest storage",
            hashes.len()
        );
        for (i, hash) in hashes.iter().enumerate().take(10) {
            crate::debug_log!("[MLS-FFI]   [{}] {}", i, hash);
        }
        if hashes.len() > 10 {
            crate::debug_log!("[MLS-FFI]   ... and {} more", hashes.len() - 10);
        }

        Ok(hashes)
    }

    /// 🔍 DEBUG: Check if a specific key package hash exists in local manifest storage
    ///
    /// This checks the manifest storage (KeyPackageBundle cache) which is the source of truth
    /// for which key packages this device can use to process Welcome messages.
    ///
    /// NOTE: This only checks the manifest, not OpenMLS internal storage. The manifest
    /// is what we control and what should contain all bundles we've created.
    ///
    /// - Parameters:
    ///   - hash_hex: Hex-encoded hash reference to search for (raw bytes, not TLS-encoded)
    /// - Returns: true if found in manifest, false otherwise
    /// - Throws: MLSError if context is not initialized or hex is invalid
    pub fn debug_check_key_package_hash(&self, hash_hex: String) -> Result<bool, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let hash_bytes =
            hex::decode(&hash_hex).map_err(|_| MLSError::invalid_input("Invalid hex string"))?;

        // Check manifest storage (our source of truth for key package bundles)
        let in_manifest = inner.key_package_bundles().contains_key(&hash_bytes);

        crate::info_log!(
            "[MLS-FFI] 🔍 debug_check_key_package_hash: {} -> in_manifest: {}",
            &hash_hex[..32.min(hash_hex.len())],
            in_manifest
        );

        Ok(in_manifest)
    }

    /// Delete consumed key package bundles from storage
    ///
    /// Removes specific key package bundles from both in-memory cache and persistent storage.
    /// This is useful for cleaning up bundles that were consumed by the server but remain in local storage.
    ///
    /// - Parameters:
    ///   - hash_refs: Array of hash references (as returned by create_key_package) to delete
    /// - Returns: Number of bundles successfully deleted
    /// - Throws: MLSError if storage operation fails
    pub fn delete_key_package_bundles(&self, hash_refs: Vec<Vec<u8>>) -> Result<u64, MLSError> {
        self.check_suspended()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;

        crate::info_log!(
            "[MLS-FFI] 🗑️ Deleting {} key package bundles",
            hash_refs.len()
        );

        let mut deleted_count = 0u64;

        // Get mutable access to in-memory bundles
        let bundles = inner.key_package_bundles_mut();

        // Delete from in-memory cache
        for hash_ref in &hash_refs {
            if bundles.remove(hash_ref).is_some() {
                deleted_count += 1;
                crate::debug_log!("[MLS-FFI]   ✅ Deleted bundle: {}", hex::encode(hash_ref));
            } else {
                crate::debug_log!(
                    "[MLS-FFI]   ⚠️  Bundle not found in memory: {}",
                    hex::encode(hash_ref)
                );
            }
        }

        crate::info_log!(
            "[MLS-FFI] 📊 In-memory deletion: {} bundles removed, {} remain",
            deleted_count,
            bundles.len()
        );

        // Delete from persistent storage
        let storage = &inner.manifest_storage;

        // Read existing bundles map
        let mut bundles_map: HashMap<String, String> = storage
            .read_manifest("key_package_bundles")?
            .unwrap_or_else(HashMap::new);

        let initial_persistent_count = bundles_map.len();

        // Remove bundles from persistent storage
        for hash_ref in &hash_refs {
            let hex_ref = hex::encode(hash_ref);
            if bundles_map.remove(&hex_ref).is_some() {
                crate::debug_log!(
                    "[MLS-FFI]   ✅ Deleted from persistent storage: {}",
                    hex_ref
                );
            }
        }

        // Write updated map back to storage (bail if app is suspending — 0xdead10cc prevention)
        self.check_suspended()?;
        storage.write_manifest("key_package_bundles", &bundles_map)?;

        // 🔒 CRITICAL FIX: Force database flush after bundle deletion
        // Ensures deleted bundles are not restored from WAL after app restart
        self.check_suspended()?;
        inner.flush_database().map_err(|e| {
            crate::error_log!(
                "[MLS-FFI] ⚠️ WARNING: Failed to flush database after bundle deletion: {:?}",
                e
            );
            e
        })?;
        crate::debug_log!("[MLS-FFI] ✅ Database flushed after bundle deletion");

        let persistent_deleted = initial_persistent_count - bundles_map.len();
        crate::info_log!(
            "[MLS-FFI] 💾 Persistent storage: {} bundles removed, {} remain",
            persistent_deleted,
            bundles_map.len()
        );

        crate::info_log!(
            "[MLS-FFI] ✅ Successfully deleted {} total bundles",
            deleted_count
        );

        Ok(deleted_count)
    }

    /// Force flush all pending database writes to disk
    ///
    /// This executes a SQLite WAL checkpoint to ensure all pending writes are
    /// durably persisted to the main database file. Call this after batch operations
    /// like creating multiple key packages to ensure they survive app restart.
    ///
    /// - Returns: Nothing on success
    /// - Throws: MLSError if flush fails
    pub fn flush_storage(&self) -> Result<(), MLSError> {
        self.check_suspended()?;
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        crate::info_log!("[MLS-FFI] 💾 Manual storage flush requested");
        inner.flush_database().map_err(|e| {
            crate::error_log!("[MLS-FFI] ❌ Failed to flush storage: {:?}", e);
            e
        })?;
        crate::info_log!("[MLS-FFI] ✅ Storage flushed successfully");
        Ok(())
    }

    /// Set the global MLS logger to receive Rust logs in Swift
    ///
    /// This allows forwarding internal MLS logs to OSLog or other Swift logging systems.
    /// The logger instance will be used for all subsequent MLS operations.
    ///
    /// - Parameters:
    ///   - logger: Logger implementation conforming to MLSLogger protocol
    pub fn set_logger(&self, logger: Box<dyn MLSLogger>) {
        crate::logging::set_logger(logger);
    }

    /// Compute the hash reference for a serialized KeyPackage
    ///
    /// Accepts either an MlsMessage-wrapped KeyPackage or raw KeyPackage bytes.
    /// This is useful when you need to compute a hash from KeyPackage bytes received from the server.
    ///
    /// - Parameters:
    ///   - key_package_bytes: Serialized KeyPackage data
    /// - Returns: Hash reference bytes
    /// - Throws: MLSError if deserialization or hashing fails
    pub fn compute_key_package_hash(
        &self,
        key_package_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        use openmls::prelude::*;

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let crypto = inner.provider_crypto();

        // Try MlsMessage-wrapped format first
        if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&key_package_bytes) {
            if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
                let kp = kp_in
                    .validate(crypto, ProtocolVersion::default())
                    .map_err(|_| MLSError::InvalidKeyPackage)?;
                return Ok(kp
                    .hash_ref(crypto)
                    .map_err(|_| MLSError::OpenMLSError)?
                    .as_slice()
                    .to_vec());
            }
        }

        // Fallback: raw KeyPackage format
        let (kp_in, _remaining) = KeyPackageIn::tls_deserialize_bytes(&key_package_bytes)
            .map_err(|_| MLSError::SerializationError)?;
        let kp = kp_in
            .validate(crypto, ProtocolVersion::default())
            .map_err(|_| MLSError::InvalidKeyPackage)?;
        Ok(kp
            .hash_ref(crypto)
            .map_err(|_| MLSError::OpenMLSError)?
            .as_slice()
            .to_vec())
    }

    /// Sign arbitrary bytes using the persistent MLS signer for an identity.
    ///
    /// This is used for declaration device proof-of-possession. The signature
    /// key is the same key used in MLS credentials/key packages for `identity`.
    pub fn sign_with_identity_key(
        &self,
        identity: String,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let signer = inner
            .get_signer_for_identity(&identity)
            .ok_or_else(|| MLSError::invalid_input("No signer registered for identity"))?;

        signer.sign(&payload).map_err(|_| MLSError::OpenMLSError)
    }

    /// 🔒 FIX #2: Force database synchronization
    ///
    /// Forces a full WAL checkpoint to ensure all MLS state is durably persisted.
    /// Call this after critical state transitions (Welcome processing, Commit merge)
    /// to prevent SecretReuseError from incomplete persistence.
    ///
    /// - Returns: Ok(()) on success
    /// - Throws: MLSError if flush fails
    pub fn sync_database(&self) -> Result<(), MLSError> {
        self.check_suspended()?;
        crate::info_log!("[MLS-FFI] sync_database: Forcing WAL checkpoint for durability");

        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        inner.flush_database().map_err(|e| {
            crate::error_log!("[MLS-FFI] sync_database: Failed to flush database: {:?}", e);
            e
        })?;

        crate::info_log!("[MLS-FFI] sync_database: Complete - all state durably persisted");
        Ok(())
    }

    /// 🔒 FIX #3: Validate GroupInfo format before upload
    ///
    /// Verifies that a GroupInfo blob can be successfully deserialized.
    /// Call this before uploading to server to catch corruption early.
    ///
    /// The GroupInfo is serialized as an MlsMessageOut wrapper containing the actual
    /// VerifiableGroupInfo. This function handles both the wrapped and unwrapped formats.
    ///
    /// - Parameters:
    ///   - group_info_bytes: The serialized GroupInfo (MlsMessageOut wrapper)
    /// - Returns: true if valid, false otherwise (with error logging)
    pub fn validate_group_info_format(&self, group_info_bytes: Vec<u8>) -> bool {
        crate::debug_log!(
            "[MLS-FFI] validate_group_info_format: Checking {} bytes",
            group_info_bytes.len()
        );

        // Basic size check
        if group_info_bytes.len() < 100 {
            crate::error_log!(
                "[MLS-FFI] validate_group_info_format: FAILED - Too small ({} bytes, minimum 100)",
                group_info_bytes.len()
            );
            return false;
        }

        // Check for base64 encoding issues (should be binary, not ASCII text)
        let is_ascii_only = group_info_bytes
            .iter()
            .all(|&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D);
        if is_ascii_only && group_info_bytes.len() > 50 {
            crate::error_log!("[MLS-FFI] validate_group_info_format: FAILED - Appears to be base64-encoded text, not binary MLS data");
            return false;
        }

        // GroupInfo is serialized as MlsMessageOut (wrapper format)
        // Try to deserialize as MlsMessageIn first (the input counterpart)
        match MlsMessageIn::tls_deserialize(&mut &*group_info_bytes) {
            Ok(mls_msg) => {
                // Verify it's actually a GroupInfo message
                match mls_msg.extract() {
                    MlsMessageBodyIn::GroupInfo(_) => {
                        crate::info_log!("[MLS-FFI] validate_group_info_format: SUCCESS - GroupInfo is valid (MlsMessage wrapper)");
                        true
                    }
                    _ => {
                        crate::error_log!("[MLS-FFI] validate_group_info_format: FAILED - MlsMessage is not GroupInfo type");
                        false
                    }
                }
            }
            Err(e) => {
                // Fallback: try raw VerifiableGroupInfo deserialization (older format)
                crate::debug_log!("[MLS-FFI] validate_group_info_format: MlsMessage wrapper failed, trying raw format...");
                match VerifiableGroupInfo::tls_deserialize(&mut &*group_info_bytes) {
                    Ok(_) => {
                        crate::info_log!("[MLS-FFI] validate_group_info_format: SUCCESS - GroupInfo is valid (raw format)");
                        true
                    }
                    Err(e2) => {
                        crate::error_log!(
                            "[MLS-FFI] validate_group_info_format: FAILED - Deserialization error"
                        );
                        crate::error_log!("[MLS-FFI]   MlsMessage wrapper error: {:?}", e);
                        crate::error_log!("[MLS-FFI]   Raw GroupInfo error: {:?}", e2);
                        crate::error_log!(
                            "[MLS-FFI]   First 16 bytes: {:02x?}",
                            &group_info_bytes[..group_info_bytes.len().min(16)]
                        );
                        false
                    }
                }
            }
        }
    }

    /// 🔍 DIAGNOSTIC: Get detailed debug state for a group
    ///
    /// Returns diagnostic information about a group's current state including:
    /// - Current epoch
    /// - Member count
    /// - Storage verification status
    ///
    /// This is useful for diagnosing SecretReuseError issues after app restart.
    ///
    /// - Parameters:
    ///   - group_id: Group identifier
    /// - Returns: JSON string with debug information
    /// - Throws: MLSError if group not found
    pub fn get_group_debug_state(&self, group_id: Vec<u8>) -> Result<String, MLSError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;

        let gid = GroupId::from_slice(&group_id);

        inner.with_group_ref(&gid, |group, provider| {
            let mut debug_info = HashMap::new();

            // Basic state
            debug_info.insert("group_id".to_string(), hex::encode(&group_id));
            debug_info.insert("epoch".to_string(), group.epoch().as_u64().to_string());
            debug_info.insert(
                "member_count".to_string(),
                group.members().count().to_string(),
            );

            // Verify storage round-trip
            match MlsGroup::load(provider.storage(), &gid) {
                Ok(Some(loaded)) => {
                    debug_info.insert("storage_accessible".to_string(), "true".to_string());
                    debug_info.insert(
                        "storage_epoch".to_string(),
                        loaded.epoch().as_u64().to_string(),
                    );
                    debug_info.insert(
                        "storage_member_count".to_string(),
                        loaded.members().count().to_string(),
                    );

                    let epoch_match = loaded.epoch() == group.epoch();
                    debug_info.insert("epoch_matches_storage".to_string(), epoch_match.to_string());
                }
                Ok(None) => {
                    debug_info.insert("storage_accessible".to_string(), "false".to_string());
                    debug_info.insert(
                        "error".to_string(),
                        "Group not found in storage".to_string(),
                    );
                }
                Err(e) => {
                    debug_info.insert("storage_accessible".to_string(), "error".to_string());
                    debug_info.insert("error".to_string(), format!("{:?}", e));
                }
            }

            // Serialize as JSON
            Ok(serde_json::to_string_pretty(&debug_info)
                .unwrap_or_else(|_| "Failed to serialize debug info".to_string()))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sender-side three-phase commit API on MLSContext (task #62)
//
// Mirrors the `MLSOrchestrator::{stage_commit, confirm_commit, discard_pending}`
// surface for platforms that call MLSContext directly (iOS MLSClient,
// catmos-cli) instead of going through OrchestratorBridge. The registry is
// duplicated from the orchestrator rather than shared: MLSContext and
// MLSOrchestrator are used by disjoint platform populations, so a per-layer
// registry keeps the std-mutex / tokio-mutex boundary clean and avoids
// coupling the orchestrator's async pending map to the FFI's sync pending
// map. See `PendingOutgoingCommitMeta` doc for the full rationale.
//
// Post-commit bookkeeping (storage writes, GroupInfo publish, group-state
// cache update, epoch-secret cleanup) is deliberately NOT performed here:
// those are orchestrator-level concerns, and iOS/catmos-cli own equivalent
// plumbing at the platform layer.
// ═══════════════════════════════════════════════════════════════════════════

/// Sentinel the caller passes when it has no meaningful server epoch to
/// fence against (mirror of `SKIP_SERVER_EPOCH_FENCE` on the orchestrator
/// side). When `server_epoch == SKIP_SERVER_EPOCH_FENCE`, `confirm_commit`
/// skips the fence check.
#[uniffi::export]
pub fn mls_skip_server_epoch_fence() -> u64 {
    SKIP_SERVER_EPOCH_FENCE
}

/// Value of [`mls_skip_server_epoch_fence`] exposed as a Rust constant for
/// in-crate callers.
pub const SKIP_SERVER_EPOCH_FENCE: u64 = 0;

#[uniffi::export]
impl MLSContext {
    /// Stage a commit without sending it to the delivery service or merging
    /// it locally. Returns a [`crate::orchestrator_bridge::FFICommitPlan`]
    /// the caller ships to the DS; the caller then passes the embedded
    /// handle back to [`confirm_commit`](Self::confirm_commit) on success or
    /// [`discard_pending`](Self::discard_pending) on failure.
    ///
    /// `signer_identity_bytes` is the UTF-8 DID of the caller — used to
    /// export GroupInfo for the pre-merge group state (identical shape to
    /// [`MLSContext::export_group_info`]).
    ///
    /// Only one pending commit may exist per group at a time (OpenMLS
    /// constraint). Staging a second commit while one is already pending
    /// returns `MLSError::InvalidInput`.
    pub fn stage_commit(
        &self,
        conversation_id: String,
        kind: crate::orchestrator_bridge::FFICommitKind,
        signer_identity_bytes: Vec<u8>,
    ) -> Result<crate::orchestrator_bridge::FFICommitPlan, crate::MLSCommitError> {
        use crate::orchestrator_bridge::{FFICommitKind, FFICommitPlan, FFIStagedCommitHandle};

        let group_id_bytes = hex::decode(&conversation_id)
            .map_err(|_| MLSError::invalid_input("Invalid hex group ID"))?;

        // OpenMLS allows at most one pending commit per group. Refuse to
        // stage another while one is already tracked.
        {
            let pending = self
                .pending_outgoing_commits
                .lock()
                .map_err(|_| MLSError::ContextNotInitialized)?;
            if pending.contains_key(&conversation_id) {
                return Err(MLSError::invalid_input(format!(
                    "A staged commit already exists for conversation {}; confirm or discard it before staging another",
                    conversation_id
                ))
                .into());
            }
        }

        let source_epoch = self.get_epoch(group_id_bytes.clone())?;

        let (commit_bytes, welcome_bytes) = match kind {
            FFICommitKind::AddMembers {
                member_dids: _,
                key_packages,
            } => {
                let kp_data: Vec<KeyPackageData> = key_packages
                    .into_iter()
                    .map(|data| KeyPackageData { data })
                    .collect();
                let add_result = self.add_members(group_id_bytes.clone(), kp_data)?;
                (add_result.commit_data, Some(add_result.welcome_data))
            }
            FFICommitKind::RemoveMembers { member_dids } => {
                let member_identities: Vec<Vec<u8>> = member_dids
                    .iter()
                    .map(|did| did.as_bytes().to_vec())
                    .collect();
                let commit = self.remove_members(group_id_bytes.clone(), member_identities)?;
                (commit, None)
            }
            FFICommitKind::SwapMembers {
                remove_dids,
                add_dids: _,
                add_key_packages,
            } => {
                let remove_ids: Vec<Vec<u8>> =
                    remove_dids.iter().map(|d| d.as_bytes().to_vec()).collect();
                let kp_data: Vec<KeyPackageData> = add_key_packages
                    .into_iter()
                    .map(|data| KeyPackageData { data })
                    .collect();
                let swap_result = self.swap_members(group_id_bytes.clone(), remove_ids, kp_data)?;
                (swap_result.commit_data, Some(swap_result.welcome_data))
            }
            FFICommitKind::UpdateMetadata {
                group_info_extension,
            } => {
                let commit =
                    self.update_group_metadata(group_id_bytes.clone(), group_info_extension)?;
                (commit, None)
            }
        };

        // Export GroupInfo from the pre-merge group state. OpenMLS will
        // re-export after merge; platforms that batch operations may want
        // to ship this pre-merge blob alongside the commit.
        let group_info = self.export_group_info(group_id_bytes.clone(), signer_identity_bytes)?;

        let nonce = self
            .staged_commit_nonce
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let target_epoch = source_epoch.saturating_add(1);

        self.pending_outgoing_commits
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?
            .insert(
                conversation_id.clone(),
                PendingOutgoingCommitMeta {
                    nonce,
                    source_epoch,
                    target_epoch,
                },
            );

        crate::debug_log!(
            "[MLS-FFI] stage_commit: conversation_id={}, nonce={}, source_epoch={}, target_epoch={}",
            conversation_id,
            nonce,
            source_epoch,
            target_epoch
        );

        Ok(FFICommitPlan {
            handle: FFIStagedCommitHandle {
                group_id: conversation_id,
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
    /// epoch, and remove the handle from the pending map.
    ///
    /// `server_epoch` is used to fence against confirm calls that reference
    /// a different epoch than the one the DS actually accepted. Pass the
    /// value returned by [`mls_skip_server_epoch_fence`] for API paths that
    /// don't echo an epoch; non-sentinel values must equal the plan's
    /// `target_epoch`, otherwise the staged commit is left in place and
    /// `MLSError::EpochMismatch` is returned so the caller can choose to
    /// `discard_pending` and re-sync.
    ///
    /// Post-merge bookkeeping (storage writes, GroupInfo publish,
    /// group-state cache update, epoch-secret cleanup) is the caller's
    /// responsibility — see the module-level comment for rationale.
    pub fn confirm_commit(
        &self,
        handle: crate::orchestrator_bridge::FFIStagedCommitHandle,
        server_epoch: u64,
    ) -> Result<crate::orchestrator_bridge::FFIConfirmedCommit, crate::MLSCommitError> {
        use crate::orchestrator_bridge::FFIConfirmedCommit;

        // Validate and pop the pending entry atomically to prevent a second
        // `confirm_commit` (or concurrent `discard_pending`) from operating
        // on the same handle.
        let meta = {
            let mut pending = self
                .pending_outgoing_commits
                .lock()
                .map_err(|_| MLSError::ContextNotInitialized)?;
            match pending.get(&handle.group_id) {
                Some(existing) if existing.nonce == handle.nonce => {
                    pending.remove(&handle.group_id).expect("just matched")
                }
                Some(_) => {
                    return Err(MLSError::invalid_input(format!(
                        "Staged commit handle nonce mismatch for conversation {} (already confirmed or superseded)",
                        handle.group_id
                    ))
                    .into());
                }
                None => {
                    return Err(MLSError::invalid_input(format!(
                        "No staged commit found for conversation {} (already confirmed or discarded)",
                        handle.group_id
                    ))
                    .into());
                }
            }
        };

        // Server epoch fence. Skipped when caller passes the sentinel.
        if server_epoch != SKIP_SERVER_EPOCH_FENCE && server_epoch != meta.target_epoch {
            // Re-insert so the caller can still `discard_pending` to clean
            // the OpenMLS-side state.
            self.pending_outgoing_commits
                .lock()
                .map_err(|_| MLSError::ContextNotInitialized)?
                .insert(handle.group_id.clone(), meta.clone());
            return Err(crate::MLSCommitError::EpochMismatch {
                local: meta.target_epoch,
                remote: server_epoch,
            });
        }

        let group_id_bytes = hex::decode(&handle.group_id)
            .map_err(|_| MLSError::invalid_input("Invalid hex group ID"))?;

        // Merge the pending commit. If this fails the local state is behind
        // the server — clear the stale pending commit so future sends don't
        // hit OpenMLS's "pending commit exists" assertion, and surface the
        // error. Platform-layer code owns marking the conversation for
        // rejoin (the orchestrator does `storage.mark_needs_rejoin(...)`
        // here; MLSContext has no storage reference).
        let new_epoch = match self.merge_pending_commit(group_id_bytes.clone()) {
            Ok(result) => result.new_epoch,
            Err(e) => {
                crate::error_log!(
                    "[MLS-FFI] confirm_commit: merge_pending_commit failed for conversation={}, target_epoch={}: {:?}",
                    handle.group_id,
                    meta.target_epoch,
                    e
                );
                if let Err(clear_err) = self.clear_pending_commit(group_id_bytes) {
                    crate::warn_log!(
                        "[MLS-FFI] confirm_commit: failed to clear stale pending commit for conversation={}: {:?}",
                        handle.group_id,
                        clear_err
                    );
                }
                return Err(e.into());
            }
        };

        crate::debug_log!(
            "[MLS-FFI] confirm_commit: conversation_id={}, new_epoch={}",
            handle.group_id,
            new_epoch
        );

        Ok(FFIConfirmedCommit {
            new_epoch,
            // Metadata key / reference plumbing is reserved for a future
            // trait extension on `MlsCryptoContext`. See the same field on
            // the orchestrator-side `ConfirmedCommit`.
            metadata_key: None,
            metadata_reference: None,
        })
    }

    /// Discard a previously staged commit without advancing the epoch.
    /// Clears the OpenMLS pending commit (so future sends can construct a
    /// new one) and removes the handle from the pending map.
    ///
    /// Calling `discard_pending` on an unknown or already-consumed handle
    /// returns `MLSError::InvalidInput`.
    pub fn discard_pending(
        &self,
        handle: crate::orchestrator_bridge::FFIStagedCommitHandle,
    ) -> Result<(), crate::MLSCommitError> {
        let removed = {
            let mut pending = self
                .pending_outgoing_commits
                .lock()
                .map_err(|_| MLSError::ContextNotInitialized)?;
            match pending.get(&handle.group_id) {
                Some(existing) if existing.nonce == handle.nonce => {
                    pending.remove(&handle.group_id)
                }
                Some(_) => {
                    return Err(MLSError::invalid_input(format!(
                        "Staged commit handle nonce mismatch for conversation {} (already discarded or confirmed)",
                        handle.group_id
                    ))
                    .into());
                }
                None => {
                    return Err(MLSError::invalid_input(format!(
                        "No staged commit found for conversation {} (already discarded or confirmed)",
                        handle.group_id
                    ))
                    .into());
                }
            }
        };

        // Tell MLS to forget the pending commit so future operations can
        // construct new ones. If hex-decode or the crypto layer fails we
        // still consider the discard "succeeded" from the caller's
        // perspective — the handle is gone from the pending map.
        if let Ok(group_id_bytes) = hex::decode(&handle.group_id) {
            if let Err(e) = self.clear_pending_commit(group_id_bytes) {
                crate::warn_log!(
                    "[MLS-FFI] discard_pending: clear_pending_commit failed for conversation={}: {:?}",
                    handle.group_id,
                    e
                );
            }
        }

        crate::debug_log!(
            "[MLS-FFI] discard_pending: conversation_id={}, nonce={}, source_epoch={}",
            handle.group_id,
            handle.nonce,
            removed.as_ref().map(|m| m.source_epoch).unwrap_or(0)
        );

        Ok(())
    }
}

// Free functions exported to UniFFI

/// Set the global MLS logger to receive Rust logs in Swift
/// This allows forwarding internal MLS logs to OSLog or other Swift logging systems
#[uniffi::export]
pub fn mls_set_logger(logger: Box<dyn MLSLogger>) {
    crate::logging::set_logger(logger);
}

/// Compute the hash reference for a serialized KeyPackage
/// Accepts either an MlsMessage-wrapped KeyPackage or raw KeyPackage bytes
/// This is useful when you need to compute a hash from KeyPackage bytes received from the server
#[uniffi::export]
pub fn mls_compute_key_package_hash(key_package_bytes: Vec<u8>) -> Result<Vec<u8>, MLSError> {
    use openmls::prelude::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;

    let provider = LibcruxProvider::default();

    // Try MlsMessage-wrapped format first
    if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&key_package_bytes) {
        if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
            let kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|_| MLSError::InvalidKeyPackage)?;
            return Ok(kp
                .hash_ref(provider.crypto())
                .map_err(|_| MLSError::OpenMLSError)?
                .as_slice()
                .to_vec());
        }
    }

    // Fallback: raw KeyPackage format
    let (kp_in, _remaining) = KeyPackageIn::tls_deserialize_bytes(&key_package_bytes)
        .map_err(|_| MLSError::SerializationError)?;
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .map_err(|_| MLSError::InvalidKeyPackage)?;
    Ok(kp
        .hash_ref(provider.crypto())
        .map_err(|_| MLSError::OpenMLSError)?
        .as_slice()
        .to_vec())
}

/// Extract the credential identity from a serialized KeyPackage
/// This returns the identity string (e.g., "did:plc:xxx" or "did:plc:xxx#deviceUUID")
/// embedded in the key package's leaf node credential.
///
/// This is useful for deduplicating key packages by device on the client side.
#[uniffi::export]
pub fn mls_extract_key_package_identity(key_package_bytes: Vec<u8>) -> Result<String, MLSError> {
    use openmls::prelude::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;

    let provider = LibcruxProvider::default();

    // Try MlsMessage-wrapped format first
    if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&key_package_bytes) {
        if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
            let kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|_| MLSError::InvalidKeyPackage)?;
            let identity_bytes = kp.leaf_node().credential().serialized_content();
            return String::from_utf8(identity_bytes.to_vec())
                .map_err(|_| MLSError::invalid_input("Credential identity is not valid UTF-8"));
        }
    }

    // Fallback: raw KeyPackage format
    let (kp_in, _remaining) = KeyPackageIn::tls_deserialize_bytes(&key_package_bytes)
        .map_err(|_| MLSError::SerializationError)?;
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .map_err(|_| MLSError::InvalidKeyPackage)?;
    let identity_bytes = kp.leaf_node().credential().serialized_content();
    String::from_utf8(identity_bytes.to_vec())
        .map_err(|_| MLSError::invalid_input("Credential identity is not valid UTF-8"))
}

/// Extract the MLS leaf signature public key from a serialized KeyPackage.
///
/// The returned key is the device key used to sign MLS leaf nodes/commits.
#[uniffi::export]
pub fn mls_extract_key_package_signature_public_key(
    key_package_bytes: Vec<u8>,
) -> Result<Vec<u8>, MLSError> {
    use openmls::prelude::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;

    let provider = LibcruxProvider::default();

    // Try MlsMessage-wrapped format first
    if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&key_package_bytes) {
        if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
            let kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|_| MLSError::InvalidKeyPackage)?;
            return Ok(kp.leaf_node().signature_key().as_slice().to_vec());
        }
    }

    // Fallback: raw KeyPackage format
    let (kp_in, _remaining) = KeyPackageIn::tls_deserialize_bytes(&key_package_bytes)
        .map_err(|_| MLSError::SerializationError)?;
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .map_err(|_| MLSError::InvalidKeyPackage)?;
    Ok(kp.leaf_node().signature_key().as_slice().to_vec())
}

/// Extract the MLS leaf signature algorithm from a serialized KeyPackage.
///
/// Returns a normalized lowercase algorithm label (e.g. "ed25519", "p256").
#[uniffi::export]
pub fn mls_extract_key_package_signature_algorithm(
    key_package_bytes: Vec<u8>,
) -> Result<String, MLSError> {
    use openmls::prelude::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;

    fn normalize_alg_label(ciphersuite_debug: &str) -> String {
        let lower = ciphersuite_debug.to_lowercase();
        if lower.contains("ed25519") {
            "ed25519".to_string()
        } else if lower.contains("p256") || lower.contains("secp256r1") || lower.contains("ecdsa") {
            "p256".to_string()
        } else {
            "unknown".to_string()
        }
    }

    let provider = LibcruxProvider::default();

    // Try MlsMessage-wrapped format first
    if let Ok((mls_msg, _)) = MlsMessageIn::tls_deserialize_bytes(&key_package_bytes) {
        if let MlsMessageBodyIn::KeyPackage(kp_in) = mls_msg.extract() {
            let kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::default())
                .map_err(|_| MLSError::InvalidKeyPackage)?;
            return Ok(normalize_alg_label(&format!("{:?}", kp.ciphersuite())));
        }
    }

    // Fallback: raw KeyPackage format
    let (kp_in, _remaining) = KeyPackageIn::tls_deserialize_bytes(&key_package_bytes)
        .map_err(|_| MLSError::SerializationError)?;
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::default())
        .map_err(|_| MLSError::InvalidKeyPackage)?;
    Ok(normalize_alg_label(&format!("{:?}", kp.ciphersuite())))
}

/// Generate a random Pre-Shared Key (PSK) for external commit authentication
/// Returns 32 random bytes (256 bits) suitable for use as a PSK
#[uniffi::export]
pub fn mls_generate_psk() -> Result<Vec<u8>, MLSError> {
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::random::OpenMlsRand;

    let provider = LibcruxProvider::default();
    let bytes = provider
        .rand()
        .random_array::<32>()
        .map_err(|_| MLSError::OpenMLSError)?;
    Ok(bytes.to_vec())
}

/// Hash a Pre-Shared Key (PSK) using SHA256
/// Returns a hex-encoded string (64 characters) that can be used as a PSK identifier
#[uniffi::export]
pub fn mls_hash_psk(psk: Vec<u8>) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&psk);
    let result = hasher.finalize();
    hex::encode(result)
}

// ---------------------------------------------------------------------------
// MlsCryptoContext trait implementation — delegates directly to MLSContext methods
// ---------------------------------------------------------------------------

impl MlsCryptoContext for MLSContext {
    fn create_key_package(&self, identity: Vec<u8>) -> Result<KeyPackageResult, MLSError> {
        self.create_key_package(identity)
    }

    fn create_group(
        &self,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.create_group(identity, config)
    }

    fn create_group_with_id(
        &self,
        identity: Vec<u8>,
        group_id: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.create_group_with_id(identity, group_id, config)
    }

    fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        self.add_members(group_id, key_packages)
    }

    fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        self.remove_members(group_id, member_identities)
    }

    fn swap_members(
        &self,
        group_id: Vec<u8>,
        remove_identities: Vec<Vec<u8>>,
        add_key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        self.swap_members(group_id, remove_identities, add_key_packages)
    }

    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.merge_pending_commit(group_id).map(|r| r.new_epoch)
    }

    fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.clear_pending_commit(group_id)
    }

    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.get_epoch(group_id)
    }

    fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.get_confirmation_tag(group_id)
    }

    fn epoch_authenticator(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.epoch_authenticator(group_id)
    }

    fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        self.export_group_info(group_id, signer_identity)
    }

    fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        self.encrypt_message(group_id, plaintext)
    }

    fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        self.decrypt_message(group_id, ciphertext)
    }

    fn merge_incoming_commit(&self, group_id: Vec<u8>, target_epoch: u64) -> Result<u64, MLSError> {
        self.merge_incoming_commit(group_id, target_epoch)
    }

    fn discard_incoming_commit(
        &self,
        group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<(), MLSError> {
        self.discard_incoming_commit(group_id, target_epoch)
    }

    fn create_external_commit(
        &self,
        group_info: Vec<u8>,
        identity: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        self.create_external_commit(group_info, identity)
    }

    fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.discard_pending_external_join(group_id)
    }

    fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.delete_group(group_id)
    }

    fn get_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.get_group_metadata(group_id)
    }

    fn update_group_metadata(
        &self,
        group_id: Vec<u8>,
        metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        self.update_group_metadata(group_id, metadata_json)
    }

    fn process_welcome(
        &self,
        welcome_data: Vec<u8>,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        self.process_welcome(welcome_data, identity, config)
    }

    fn cleanup_epoch_secrets(
        &self,
        group_id: Vec<u8>,
        current_epoch: u64,
        retention_epochs: u64,
    ) -> Result<(), MLSError> {
        if current_epoch <= retention_epochs {
            return Ok(());
        }
        let guard = self
            .inner
            .lock()
            .map_err(|_| MLSError::ContextNotInitialized)?;
        let inner = guard.as_ref().ok_or(MLSError::ContextClosed)?;
        let epoch_manager = inner.epoch_secret_manager().clone();
        drop(guard);

        if let Err(e) = crate::async_runtime::block_on(epoch_manager.cleanup_old_epochs(
            &group_id,
            current_epoch,
            retention_epochs,
        )) {
            crate::warn_log!(
                "[MLS-FFI] cleanup_epoch_secrets: failed for group {}: {:?}",
                hex::encode(&group_id),
                e
            );
        }
        Ok(())
    }

    /// Fork resolution via readd -- gated behind fork-resolution feature.
    #[cfg(feature = "fork-resolution")]
    fn recover_fork_by_readding(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), MLSError> {
        use openmls::prelude::*;
        use tls_codec::Serialize as TlsSerialize;
        crate::info_log!(
            "[MLS-FFI] recover_fork_by_readding: group={}, kps={}",
            hex::encode(&group_id),
            key_packages.len()
        );
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| MLSError::Internal(format!("Lock failed: {e}")))?;
        let inner = guard.as_mut().ok_or(MLSError::ContextClosed)?;
        let gid = GroupId::from_slice(&group_id);
        inner.with_group_mut(&gid, |group, provider| {
            let mut kps = Vec::new();
            for kp_bytes in &key_packages {
                let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(kp_bytes)
                    .map_err(|_| MLSError::SerializationError)?;
                let kp = kp_in
                    .validate(provider.crypto(), ProtocolVersion::default())
                    .map_err(|_| MLSError::InvalidKeyPackage)?;
                kps.push(kp);
            }
            let (commit, welcome, _gi) = group
                .recover_fork_by_readding(provider, &[], &kps)
                .map_err(|e| MLSError::Internal(format!("Fork recovery failed: {e}")))?;
            let cb = commit
                .tls_serialize_detached()
                .map_err(|_| MLSError::SerializationError)?;
            let wb = welcome.map(|w| w.tls_serialize_detached().unwrap_or_default());
            Ok((cb, wb))
        })
    }

    fn safe_export_secret(
        &self,
        group_id: Vec<u8>,
        component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        self.safe_export_secret(group_id, component_id)
    }

    fn safe_export_secret_from_pending(
        &self,
        group_id: Vec<u8>,
        component_id: u16,
    ) -> Result<Vec<u8>, MLSError> {
        self.safe_export_secret_from_pending(group_id, component_id)
    }

    fn propose_self_remove(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        MLSContext::propose_self_remove(self, group_id)
    }

    fn commit_pending_proposals(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        MLSContext::commit_pending_proposals(self, group_id)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metadata blob encryption / decryption (ChaCha20-Poly1305)
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypt a group metadata JSON blob using ChaCha20-Poly1305.
///
/// - `key`: 32-byte symmetric key derived from the MLS epoch exporter.
/// - `group_id_hex`: Hex-encoded MLS group ID (used in AAD construction).
/// - `epoch`: MLS epoch number (used in AAD construction).
/// - `metadata_version`: Monotonic metadata version counter (used in AAD).
/// - `metadata_json`: JSON-encoded `GroupMetadataV1` payload.
///
/// Returns the encrypted blob: `nonce (12) || ciphertext || tag (16)`.
#[uniffi::export]
pub fn mls_encrypt_metadata_blob(
    key: Vec<u8>,
    group_id_hex: String,
    epoch: u64,
    metadata_version: u64,
    metadata_json: Vec<u8>,
) -> Result<Vec<u8>, MLSError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| MLSError::invalid_input("metadata key must be 32 bytes"))?;
    let group_id =
        hex::decode(&group_id_hex).map_err(|e| MLSError::invalid_input(format!("{e}")))?;
    let metadata: crate::metadata::GroupMetadataV1 = serde_json::from_slice(&metadata_json)?;
    crate::metadata::encrypt_metadata_blob(&key, &group_id, epoch, metadata_version, &metadata)
        .map_err(|e| MLSError::Internal(format!("{e}")))
}

/// Decrypt a group metadata blob back into JSON.
///
/// - `key`: 32-byte symmetric key derived from the MLS epoch exporter.
/// - `group_id_hex`: Hex-encoded MLS group ID (used in AAD construction).
/// - `epoch`: MLS epoch number (used in AAD construction).
/// - `metadata_version`: Monotonic metadata version counter (used in AAD).
/// - `ciphertext`: Encrypted blob: `nonce (12) || ciphertext || tag (16)`.
///
/// Returns JSON-encoded `GroupMetadataV1`.
#[uniffi::export]
pub fn mls_decrypt_metadata_blob(
    key: Vec<u8>,
    group_id_hex: String,
    epoch: u64,
    metadata_version: u64,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, MLSError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| MLSError::invalid_input("metadata key must be 32 bytes"))?;
    let group_id =
        hex::decode(&group_id_hex).map_err(|e| MLSError::invalid_input(format!("{e}")))?;
    let metadata = crate::metadata::decrypt_metadata_blob(
        &key,
        &group_id,
        epoch,
        metadata_version,
        &ciphertext,
    )
    .map_err(|e| MLSError::Internal(format!("{e}")))?;
    serde_json::to_vec(&metadata).map_err(MLSError::from)
}

/// Encrypt raw avatar image bytes using ChaCha20-Poly1305.
///
/// Uses domain-separated AAD (appends `b"avatar"`) to prevent confusion
/// with metadata blobs encrypted under the same key.
#[uniffi::export]
pub fn mls_encrypt_avatar_blob(
    key: Vec<u8>,
    group_id_hex: String,
    epoch: u64,
    metadata_version: u64,
    avatar_bytes: Vec<u8>,
) -> Result<Vec<u8>, MLSError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| MLSError::invalid_input("metadata key must be 32 bytes"))?;
    let group_id =
        hex::decode(&group_id_hex).map_err(|e| MLSError::invalid_input(format!("{e}")))?;
    crate::metadata::encrypt_avatar_blob(&key, &group_id, epoch, metadata_version, &avatar_bytes)
        .map_err(|e| MLSError::Internal(format!("{e}")))
}

/// Decrypt an avatar blob back into raw image bytes.
///
/// Uses domain-separated AAD (appends `b"avatar"`).
#[uniffi::export]
pub fn mls_decrypt_avatar_blob(
    key: Vec<u8>,
    group_id_hex: String,
    epoch: u64,
    metadata_version: u64,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, MLSError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| MLSError::invalid_input("metadata key must be 32 bytes"))?;
    let group_id =
        hex::decode(&group_id_hex).map_err(|e| MLSError::invalid_input(format!("{e}")))?;
    crate::metadata::decrypt_avatar_blob(&key, &group_id, epoch, metadata_version, &ciphertext)
        .map_err(|e| MLSError::Internal(format!("{e}")))
}

#[cfg(test)]
mod padding_tests {
    use super::*;

    /// Build a fake MLS ciphertext of the given size starting with wire format byte 0x02.
    /// Real MLS ciphertexts start with a wire format byte in 0x00..=0x04;
    /// strip_padding requires this to recognise the padding envelope.
    fn fake_mls_ciphertext(len: usize) -> Vec<u8> {
        let mut ct = Vec::with_capacity(len);
        if len > 0 {
            ct.push(0x02); // valid MLS wire format byte
            for i in 1..len {
                ct.push((i % 256) as u8);
            }
        }
        ct
    }

    #[test]
    fn test_pad_strip_roundtrip_small() {
        let original = fake_mls_ciphertext(11);
        let (padded, size) = pad_ciphertext(&original);
        assert_eq!(size as usize, padded.len());
        assert!(padded.len() >= original.len() + 4); // 4-byte header
        let stripped = strip_padding(&padded);
        assert_eq!(stripped, original);
    }

    #[test]
    fn test_pad_strip_roundtrip_various_sizes() {
        // strip_padding requires data[4] (first byte of ciphertext) to be a
        // valid MLS wire format byte (0x00..=0x04), so we use fake_mls_ciphertext.
        for size in [1, 10, 100, 500, 1000, 2000, 4000, 8000, 16000] {
            let original = fake_mls_ciphertext(size);
            let (padded, padded_size) = pad_ciphertext(&original);
            assert_eq!(padded_size as usize, padded.len());
            let stripped = strip_padding(&padded);
            assert_eq!(stripped, original, "Roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_padding_bucket_sizes() {
        // Verify padded output snaps to expected bucket boundaries
        let ct = fake_mls_ciphertext(10);
        let (padded, _) = pad_ciphertext(&ct);
        assert_eq!(
            padded.len(),
            512,
            "Small payload should snap to 512-byte bucket"
        );

        let ct = fake_mls_ciphertext(600);
        let (padded, _) = pad_ciphertext(&ct);
        assert_eq!(
            padded.len(),
            1024,
            "~600-byte payload should snap to 1024-byte bucket"
        );
    }

    #[test]
    fn test_strip_padding_unpadded_data() {
        // Data that was never padded should pass through unchanged
        let data = b"just raw bytes without padding";
        let stripped = strip_padding(data);
        assert_eq!(stripped, data);
    }

    #[test]
    fn test_strip_padding_mls_ciphertext() {
        // MLS ciphertext starts with 0x00-0x04 wire format byte.
        // If someone passes raw MLS ciphertext (not padded), strip_padding should NOT modify it.
        let mut mls_ct = vec![0x00, 0x01, 0x02, 0x03]; // first 4 bytes read as length
        mls_ct.extend_from_slice(&[0xAA; 100]);
        let stripped = strip_padding(&mls_ct);
        // claimed_len = 0x00010203 = 66051, which > data.len() - 4 = 100
        // so strip_padding returns data as-is
        assert_eq!(stripped, mls_ct);
    }

    #[test]
    fn test_strip_padding_short_data() {
        // Data shorter than 5 bytes should pass through unchanged
        let data = b"hi";
        let stripped = strip_padding(data);
        assert_eq!(stripped, data);

        let empty: &[u8] = b"";
        let stripped = strip_padding(empty);
        assert_eq!(stripped, empty);
    }
}
