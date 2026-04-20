use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use web_time::Instant;

use super::api_client::MLSAPIClient;
use super::constants;
use super::credentials::CredentialStore;
use super::error::{OrchestratorError, Result};
use super::mls_provider::MlsCryptoContext;
use super::recovery::{GroupInfo404Tracker, RecoveryTracker, SequencerFailoverTracker};
use super::storage::MLSStorageBackend;
use super::types::*;

/// Configuration for the MLS orchestrator.
#[derive(Clone)]
pub struct OrchestratorConfig {
    /// Maximum devices per user.
    pub max_devices: u32,
    /// Number of key packages to maintain on the server.
    pub target_key_package_count: u32,
    /// Threshold below which key packages are replenished.
    pub key_package_replenish_threshold: u32,
    /// Cooldown between sync attempts in seconds.
    pub sync_cooldown_seconds: u64,
    /// Maximum consecutive sync failures before pausing.
    pub max_consecutive_sync_failures: u32,
    /// Pause duration after max sync failures in seconds.
    pub sync_pause_duration_seconds: u64,
    /// Cooldown between rejoin attempts per conversation in seconds.
    pub rejoin_cooldown_seconds: u64,
    /// Maximum rejoin attempts per conversation.
    pub max_rejoin_attempts: u32,
    /// MLS group configuration.
    pub group_config: crate::GroupConfig,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            max_devices: 20,
            target_key_package_count: constants::KEY_PACKAGE_TARGET,
            key_package_replenish_threshold: constants::KEY_PACKAGE_LOW_THRESHOLD,
            sync_cooldown_seconds: constants::SYNC_INTERVAL_SECS,
            max_consecutive_sync_failures: constants::SYNC_CIRCUIT_BREAKER_THRESHOLD,
            sync_pause_duration_seconds: constants::SYNC_CIRCUIT_BREAKER_BASE_SECS,
            rejoin_cooldown_seconds: 0, // Not used — REJOIN_BACKOFF schedule replaces this
            max_rejoin_attempts: constants::MAX_REJOIN_ATTEMPTS,
            group_config: crate::GroupConfig::default(),
        }
    }
}

/// Platform-agnostic MLS orchestrator.
///
/// Coordinates between the MLS crypto context, storage, API client, and credentials
/// to provide high-level MLS operations (create group, send message, sync, etc.).
///
/// Generic over:
/// - `S`: Storage backend (IndexedDB on WASM, SQLite on native)
/// - `A`: API client (fetch on WASM, reqwest on native)
/// - `C`: Credential store (IndexedDB on WASM, keychain on native)
/// - `M`: MLS crypto context (WasmMLSContext on WASM, MLSContext on native)
pub struct MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend,
    A: MLSAPIClient,
    C: CredentialStore,
    M: MlsCryptoContext,
{
    /// The low-level MLS crypto context.
    mls_context: Arc<M>,
    /// Persistent storage backend.
    storage: Arc<S>,
    /// API client for server communication.
    api_client: Arc<A>,
    /// Credential/keychain access.
    credentials: Arc<C>,
    /// Configuration.
    config: OrchestratorConfig,
    /// The authenticated user's DID.
    user_did: Mutex<Option<String>>,
    /// In-memory conversation cache.
    conversations: Mutex<HashMap<ConversationId, ConversationView>>,
    /// In-memory group state cache.
    group_states: Mutex<HashMap<GroupId, GroupState>>,
    /// Conversation lifecycle states.
    conversation_states: Mutex<HashMap<ConversationId, ConversationState>>,
    /// Pending message IDs for deduplication.
    pending_messages: Mutex<HashSet<String>>,
    /// Own commit hashes for self-commit detection (with insertion timestamp for TTL eviction).
    own_commits: Mutex<HashMap<Vec<u8>, Instant>>,
    /// Groups currently being created (protect from sync deletion).
    groups_being_created: Mutex<HashSet<GroupId>>,
    /// Per-conversation join/rejoin locks to deduplicate concurrent attempts.
    rejoin_locks: Mutex<HashMap<ConversationId, Arc<Mutex<()>>>>,
    /// Whether the orchestrator is shutting down.
    shutting_down: Mutex<bool>,
    /// Sync state lock.
    sync_in_progress: Mutex<bool>,
    /// Consecutive sync failures (for circuit breaker).
    consecutive_sync_failures: Mutex<u32>,
    /// When the circuit breaker was last tripped (for cooldown recovery).
    circuit_breaker_tripped_at: Mutex<Option<Instant>>,
    /// Current circuit breaker cooldown duration in seconds (exponential backoff).
    circuit_breaker_cooldown_secs: Mutex<u64>,
    /// Tracks failed rejoin attempts for cooldown/backoff suppression.
    recovery_tracker: Mutex<RecoveryTracker>,
    /// Tracks consecutive sequencer failures per conversation for failover.
    failover_tracker: Mutex<SequencerFailoverTracker>,
    /// Per-conversation consecutive decrypt failure counts for divergence detection.
    decrypt_fail_counts: Mutex<HashMap<String, u32>>,
    /// Tracks consecutive GroupInfo 404 responses per conversation (spec §8.3).
    groupinfo_404_tracker: Mutex<GroupInfo404Tracker>,
    fork_detection_states: std::sync::Mutex<HashMap<String, ForkDetectionState>>,
    /// Staged-but-not-yet-confirmed commits, keyed by group id (MLS only
    /// allows one pending commit per group). See the three-phase
    /// `stage_commit` / `confirm_commit` / `discard_pending` API.
    pending_staged_commits: Mutex<HashMap<GroupId, PendingCommitMeta>>,
    /// Monotonic counter used to generate handle nonces.
    staged_commit_nonce: Mutex<u64>,
}

/// Internal bookkeeping for a staged commit.
#[derive(Debug, Clone)]
pub(crate) struct PendingCommitMeta {
    /// Nonce that must match the handle passed to `confirm_commit` or
    /// `discard_pending`.
    pub nonce: u64,
    /// The epoch that `stage_commit` captured before constructing the
    /// pending commit. Used to fence `server_epoch` against echoes that
    /// reference a completely different epoch.
    pub source_epoch: u64,
    /// The epoch the group will advance to on confirm. Equals
    /// `source_epoch + 1` by MLS construction.
    pub target_epoch: u64,
    /// The kind of commit — used to update the in-memory group state on
    /// confirm (e.g. append/remove DIDs from the member list).
    pub kind: StagedCommitKindSummary,
}

/// Lightweight summary of what kind of commit was staged. Carried separately
/// from `CommitKind` so the heavy key-package / extension payloads don't live
/// in the pending map.
#[derive(Debug, Clone)]
pub(crate) enum StagedCommitKindSummary {
    AddMembers {
        member_dids: Vec<String>,
    },
    RemoveMembers {
        member_dids: Vec<String>,
    },
    SwapMembers {
        remove_dids: Vec<String>,
        add_dids: Vec<String>,
    },
    UpdateMetadata,
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend,
    A: MLSAPIClient,
    C: CredentialStore,
    M: MlsCryptoContext,
{
    /// Create a new orchestrator instance.
    pub fn new(
        mls_context: Arc<M>,
        storage: Arc<S>,
        api_client: Arc<A>,
        credentials: Arc<C>,
        config: OrchestratorConfig,
    ) -> Self {
        let recovery_tracker = RecoveryTracker::new(config.max_rejoin_attempts);
        Self {
            mls_context,
            storage,
            api_client,
            credentials,
            config,
            user_did: Mutex::new(None),
            conversations: Mutex::new(HashMap::new()),
            group_states: Mutex::new(HashMap::new()),
            conversation_states: Mutex::new(HashMap::new()),
            pending_messages: Mutex::new(HashSet::new()),
            own_commits: Mutex::new(HashMap::new()),
            groups_being_created: Mutex::new(HashSet::new()),
            rejoin_locks: Mutex::new(HashMap::new()),
            shutting_down: Mutex::new(false),
            sync_in_progress: Mutex::new(false),
            consecutive_sync_failures: Mutex::new(0),
            circuit_breaker_tripped_at: Mutex::new(None),
            circuit_breaker_cooldown_secs: Mutex::new(constants::SYNC_CIRCUIT_BREAKER_BASE_SECS),
            recovery_tracker: Mutex::new(recovery_tracker),
            failover_tracker: Mutex::new(SequencerFailoverTracker::new()),
            decrypt_fail_counts: Mutex::new(HashMap::new()),
            groupinfo_404_tracker: Mutex::new(GroupInfo404Tracker::new()),
            fork_detection_states: std::sync::Mutex::new(HashMap::new()),
            pending_staged_commits: Mutex::new(HashMap::new()),
            staged_commit_nonce: Mutex::new(0),
        }
    }

    /// Initialize the orchestrator for a user.
    pub async fn initialize(&self, user_did: &str) -> Result<()> {
        tracing::info!(user_did, "Initializing MLS orchestrator");
        *self.user_did.lock().await = Some(user_did.to_string());
        *self.shutting_down.lock().await = false;

        // Load cached group states from storage
        // (conversations will be populated on first sync)
        Ok(())
    }

    /// Shut down the orchestrator, releasing resources.
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down MLS orchestrator");
        *self.shutting_down.lock().await = true;
        self.conversations.lock().await.clear();
        self.group_states.lock().await.clear();
        self.conversation_states.lock().await.clear();
        self.pending_messages.lock().await.clear();
        self.own_commits.lock().await.clear();
        self.rejoin_locks.lock().await.clear();
        if let Ok(mut fds) = self.fork_detection_states.lock() {
            fds.clear();
        }
        self.pending_staged_commits.lock().await.clear();
        *self.user_did.lock().await = None;
    }

    /// Get the authenticated user DID or return an error.
    pub(crate) async fn require_user_did(&self) -> Result<String> {
        self.user_did
            .lock()
            .await
            .clone()
            .ok_or(OrchestratorError::NotAuthenticated)
    }

    /// Check if the orchestrator is shutting down, returning an error if so.
    pub(crate) async fn check_shutdown(&self) -> Result<()> {
        if *self.shutting_down.lock().await {
            Err(OrchestratorError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    /// Access the MLS crypto context.
    pub fn mls_context(&self) -> &Arc<M> {
        &self.mls_context
    }

    /// Access the storage backend.
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Access the API client.
    pub fn api_client(&self) -> &Arc<A> {
        &self.api_client
    }

    /// Access the credential store.
    pub fn credentials(&self) -> &Arc<C> {
        &self.credentials
    }

    /// Access the configuration.
    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    /// Access the conversations cache.
    pub fn conversations(&self) -> &Mutex<HashMap<ConversationId, ConversationView>> {
        &self.conversations
    }

    /// Access the group states cache.
    pub fn group_states(&self) -> &Mutex<HashMap<GroupId, GroupState>> {
        &self.group_states
    }

    /// Access the conversation states cache.
    pub fn conversation_states(&self) -> &Mutex<HashMap<ConversationId, ConversationState>> {
        &self.conversation_states
    }

    /// Access the pending messages set.
    pub fn pending_messages(&self) -> &Mutex<HashSet<String>> {
        &self.pending_messages
    }

    /// Access the own commits map.
    pub fn own_commits(&self) -> &Mutex<HashMap<Vec<u8>, Instant>> {
        &self.own_commits
    }

    /// Evict own-commit entries older than `OWN_COMMIT_TTL`.
    ///
    /// Called before insertions to bound memory growth. Commits that haven't
    /// been echoed back within 300 seconds are almost certainly orphaned.
    pub(crate) async fn evict_stale_commits(&self) {
        let now = Instant::now();
        let mut commits = self.own_commits.lock().await;
        let before = commits.len();
        commits.retain(|_, ts| now.duration_since(*ts) < constants::OWN_COMMIT_TTL);
        let evicted = before - commits.len();
        if evicted > 0 {
            tracing::debug!(
                evicted,
                remaining = commits.len(),
                "Evicted stale own_commits"
            );
        }
    }

    /// Access the groups being created set.
    pub fn groups_being_created(&self) -> &Mutex<HashSet<GroupId>> {
        &self.groups_being_created
    }

    /// Acquire the per-conversation join/rejoin lock object.
    pub(crate) async fn rejoin_lock(&self, conversation_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.rejoin_locks.lock().await;
        locks
            .entry(conversation_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Access the sync-in-progress flag.
    pub fn sync_in_progress(&self) -> &Mutex<bool> {
        &self.sync_in_progress
    }

    /// Access the consecutive sync failures counter.
    pub fn consecutive_sync_failures(&self) -> &Mutex<u32> {
        &self.consecutive_sync_failures
    }

    /// Access the circuit breaker tripped timestamp.
    pub fn circuit_breaker_tripped_at(&self) -> &Mutex<Option<Instant>> {
        &self.circuit_breaker_tripped_at
    }

    /// Access the circuit breaker cooldown duration.
    pub fn circuit_breaker_cooldown_secs(&self) -> &Mutex<u64> {
        &self.circuit_breaker_cooldown_secs
    }

    /// Access the rejoin recovery tracker.
    pub fn recovery_tracker(&self) -> &Mutex<RecoveryTracker> {
        &self.recovery_tracker
    }

    /// Access the sequencer failover tracker.
    pub fn failover_tracker(&self) -> &Mutex<SequencerFailoverTracker> {
        &self.failover_tracker
    }

    /// Access the per-conversation decrypt failure counts.
    pub(crate) fn decrypt_fail_counts(&self) -> &Mutex<HashMap<String, u32>> {
        &self.decrypt_fail_counts
    }

    /// Access the GroupInfo 404 circuit breaker tracker.
    pub(crate) fn groupinfo_404_tracker(&self) -> &Mutex<GroupInfo404Tracker> {
        &self.groupinfo_404_tracker
    }

    pub(crate) fn fork_detection_states(
        &self,
    ) -> &std::sync::Mutex<HashMap<String, ForkDetectionState>> {
        &self.fork_detection_states
    }

    /// Access the pending-staged-commits map (task #44).
    pub(crate) fn pending_staged_commits(&self) -> &Mutex<HashMap<GroupId, PendingCommitMeta>> {
        &self.pending_staged_commits
    }

    /// Allocate a fresh nonce for a staged commit handle. Wraps at `u64::MAX`
    /// — practically unreachable, but the map is keyed by group id anyway so
    /// a collision would still require the same group to produce `u64::MAX`
    /// staged commits in one process lifetime.
    pub(crate) async fn next_staged_commit_nonce(&self) -> u64 {
        let mut guard = self.staged_commit_nonce.lock().await;
        *guard = guard.wrapping_add(1);
        *guard
    }

    /// Clean up old epoch secrets after an epoch advance.
    ///
    /// Retains the last `MAX_PAST_EPOCHS_TO_RETAIN` epochs and deletes
    /// everything older. Cleans up both the MLS crypto layer (via
    /// `MlsCryptoContext`) and the platform storage layer (via
    /// `MLSStorageBackend`). Non-fatal: logs warnings on failure.
    pub(crate) async fn cleanup_epoch_secrets_if_needed(
        &self,
        conversation_id: &str,
        current_epoch: u64,
    ) {
        let retention = constants::MAX_PAST_EPOCHS_TO_RETAIN;
        if current_epoch <= retention {
            return;
        }
        let cutoff_epoch = current_epoch - retention;

        // Clean up via MLS crypto context (EpochSecretManager)
        if let Ok(group_id_bytes) = hex::decode(conversation_id) {
            if let Err(e) =
                self.mls_context()
                    .cleanup_epoch_secrets(group_id_bytes, current_epoch, retention)
            {
                tracing::warn!(
                    error = %e,
                    conversation_id,
                    current_epoch,
                    "Failed to cleanup epoch secrets via MLS context"
                );
            }
        }

        // Clean up via platform storage backend
        if let Err(e) = self
            .storage()
            .cleanup_old_epoch_data(conversation_id, cutoff_epoch)
            .await
        {
            tracing::warn!(
                error = %e,
                conversation_id,
                cutoff_epoch,
                "Failed to cleanup old epoch data in storage backend"
            );
        }

        tracing::debug!(
            conversation_id,
            current_epoch,
            cutoff_epoch,
            "Cleaned up epoch secrets: retained from epoch {} to {}",
            cutoff_epoch,
            current_epoch,
        );
    }
}
