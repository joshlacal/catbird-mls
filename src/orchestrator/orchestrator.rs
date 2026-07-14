use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum OrchestratorLifecycleState {
    Uninitialized,
    Initializing { user_did: String },
    Ready { user_did: String },
    Suspended { user_did: String },
    FailedInitialization,
    Shutdown,
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
    /// Authentication and shutdown readiness published atomically.
    lifecycle_state: Mutex<OrchestratorLifecycleState>,
    /// Owns one complete initialize/resume/shutdown transition.
    lifecycle_operation: Mutex<()>,
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
    /// Layer 3: optional event observer for quarantine entry/exit events.
    /// Installed via set_event_observer; additive so existing constructors
    /// keep working without binding regen.
    event_observer: Mutex<Option<Arc<dyn super::event_observer::OrchestratorEventObserver>>>,
    /// WS-3 stage 2 (ADR-009 D6): per-root-DID cache of authorized device
    /// signing keys resolved via `CredentialStore::get_authorized_device_keys`.
    /// Positive, negative, AND unsupported results all expire after
    /// `constants::DEVICE_KEY_CACHE_TTL` so revocation propagates.
    device_key_cache: Mutex<HashMap<String, super::credential_binding::DeviceKeyCacheEntry>>,
    /// Defaults off so existing clients keep dropping non-displayable control
    /// payloads. Catbird iOS enables this only in Rust-authoritative mode.
    store_control_messages: AtomicBool,
}

struct EpochCleanupTargets<'a> {
    storage_conversation_id: &'a str,
    crypto_group_id: Option<Vec<u8>>,
    cutoff_epoch: u64,
}

fn epoch_cleanup_targets<'a>(
    conversation_id: &'a str,
    group_id: &str,
    current_epoch: u64,
) -> Option<EpochCleanupTargets<'a>> {
    let retention = constants::MAX_PAST_EPOCHS_TO_RETAIN;
    (current_epoch > retention).then(|| EpochCleanupTargets {
        storage_conversation_id: conversation_id,
        crypto_group_id: hex::decode(group_id).ok(),
        cutoff_epoch: current_epoch - retention,
    })
}

/// Internal bookkeeping for a staged commit.
#[derive(Debug, Clone)]
pub(crate) struct PendingCommitMeta {
    /// Stable conversation ID to use for delivery-service side effects.
    /// This may differ from `group_id` after resets/rotations.
    pub conversation_id: String,
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
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
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
            lifecycle_state: Mutex::new(OrchestratorLifecycleState::Uninitialized),
            lifecycle_operation: Mutex::new(()),
            conversations: Mutex::new(HashMap::new()),
            group_states: Mutex::new(HashMap::new()),
            conversation_states: Mutex::new(HashMap::new()),
            pending_messages: Mutex::new(HashSet::new()),
            own_commits: Mutex::new(HashMap::new()),
            groups_being_created: Mutex::new(HashSet::new()),
            rejoin_locks: Mutex::new(HashMap::new()),
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
            event_observer: Mutex::new(None),
            device_key_cache: Mutex::new(HashMap::new()),
            store_control_messages: AtomicBool::new(false),
        }
    }

    /// Install (or replace) the Layer 3 event observer. Pass None to detach.
    pub async fn set_event_observer(
        &self,
        observer: Option<Arc<dyn super::event_observer::OrchestratorEventObserver>>,
    ) {
        *self.event_observer.lock().await = observer;
    }

    /// Internal: snapshot the currently-installed observer (cheap: clones an Arc).
    pub(crate) async fn current_event_observer(
        &self,
    ) -> Option<Arc<dyn super::event_observer::OrchestratorEventObserver>> {
        self.event_observer.lock().await.clone()
    }

    /// Initialize the orchestrator for a user.
    pub async fn initialize(&self, user_did: &str) -> Result<()> {
        let _lifecycle_owner = self.lifecycle_operation.lock().await;
        tracing::info!(user_did, "Initializing MLS orchestrator");
        *self.lifecycle_state.lock().await = OrchestratorLifecycleState::Initializing {
            user_did: user_did.to_string(),
        };

        // WS-5.6: capabilities check — make default no-op storage methods
        // observable so silently-dropped state (e.g. `mark_reset_pending`
        // dropping RESET_PENDING across restart) shows up in logs.
        {
            let implemented = self.storage.implemented_optional_methods();
            for method in super::storage::OPTIONAL_STORAGE_METHODS {
                if !implemented.contains(method) {
                    tracing::warn!(
                        method,
                        "Storage backend does not declare an override for optional trait \
                         method — if it is still the default no-op, state routed through \
                         it is silently dropped (declare via implemented_optional_methods)"
                    );
                }
            }
        }

        // WS-5.4: hydrate persisted rejoin-backoff/quarantine state so restart
        // cannot reset recovery backoff (invariant E7; TTL + never-extend
        // rules in RecoveryTracker::hydrate_from_persisted).
        match self.storage.get_recovery_state().await {
            Ok(state) => {
                if !state.entries.is_empty() || state.last_global_rejoin_attempt_at_ms.is_some() {
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let rejected = {
                        let mut tracker = self.recovery_tracker.lock().await;
                        tracker.hydrate_from_persisted(&state, now_ms)
                    };
                    tracing::info!(
                        entries = state.entries.len(),
                        rejected = rejected.len(),
                        has_global = state.last_global_rejoin_attempt_at_ms.is_some(),
                        "Hydrated RecoveryTracker from persisted state"
                    );
                    // Swift twin parity (MLSRecoveryManager.hydrateFromDatabase):
                    // rejected entries (TTL-expired / future-dated / invalid)
                    // are DELETED, not just ignored. A kept TTL-expired row
                    // could resurrect if the wall clock later regresses, and
                    // a kept future-dated row re-logs its drop warning on
                    // every restart. Failures escalate: a surviving rejected
                    // row keeps re-entering this path with stale gating data.
                    for convo_id in &rejected {
                        if let Err(e) = self.storage.clear_recovery_backoff(convo_id).await {
                            self.report_recovery_storage_failure(
                                convo_id,
                                "clear_recovery_backoff:hydration_reject",
                                &e,
                            )
                            .await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to read persisted RecoveryTracker state — backoff starts fresh"
                );
            }
        }

        // WS-5.3: finish any force_delete_local a crash interrupted between
        // the persisted intent and completion.
        self.reconcile_pending_local_deletes().await;

        // Rehydrate persisted conversation state (spec §8.2 / §8.5 Phase 1).
        // Conversations themselves are populated from server data on first
        // sync; we only need to recover the persisted state tag + payload
        // (`ResetPending { new_group_id, reset_generation, notified_at_ms }`,
        // `NeedsRejoin`, etc.) so deferred recovery can pick up where it
        // left off across app restart. Backends that don't override
        // `get_conversation_state` will return `None` here and the in-memory
        // map starts empty — same behavior as before this hook existed.
        match self.storage.list_conversations(user_did).await {
            Ok(convos) => {
                let mut states = self.conversation_states.lock().await;
                for convo in &convos {
                    match self
                        .storage
                        .get_conversation_state(&convo.conversation_id)
                        .await
                    {
                        Ok(Some(state)) => {
                            tracing::debug!(
                                convo_id = %convo.conversation_id,
                                state = state.tag(),
                                "Rehydrated conversation state from storage"
                            );
                            // Layer 3: when rehydrating Quarantined, also mirror
                            // the state into RecoveryTracker so the in-memory
                            // gates (should_skip / send preflight / force_rejoin
                            // guard) fire after restart. Without this mirror the
                            // gates only consult the tracker map and miss the
                            // persisted state.
                            if let ConversationState::Quarantined { reason, since_ms } = &state {
                                let mut tracker = self.recovery_tracker.lock().await;
                                tracker.mark_quarantined(
                                    &convo.conversation_id,
                                    *reason,
                                    *since_ms,
                                    Vec::new(),
                                );
                            }
                            states.insert(convo.conversation_id.clone(), state);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!(
                                convo_id = %convo.conversation_id,
                                error = ?e,
                                "Failed to rehydrate security-relevant conversation state; aborting initialization"
                            );
                            // Keep an explicit Failed projection for diagnostics
                            // and atomically fail the lifecycle closed. Holding
                            // lifecycle ownership prevents a newer retry,
                            // resume, or shutdown from being overwritten here.
                            states.insert(convo.conversation_id.clone(), ConversationState::Failed);
                            drop(states);
                            *self.lifecycle_state.lock().await =
                                OrchestratorLifecycleState::FailedInitialization;
                            return Err(e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "Failed to list conversations during init; \
                     conversation_states starts empty"
                );
            }
        }

        *self.lifecycle_state.lock().await = OrchestratorLifecycleState::Ready {
            user_did: user_did.to_string(),
        };
        Ok(())
    }

    /// Resume the orchestrator after a lifecycle suspend without replaying the
    /// full startup hydration / recovery path.
    pub async fn resume_after_suspend(&self, user_did: &str) -> Result<()> {
        let _lifecycle_owner = self.lifecycle_operation.lock().await;
        tracing::info!(user_did, "Resuming MLS orchestrator after suspend");
        let mut lifecycle = self.lifecycle_state.lock().await;
        match &*lifecycle {
            OrchestratorLifecycleState::Suspended {
                user_did: suspended_did,
            } if suspended_did == user_did => {
                *lifecycle = OrchestratorLifecycleState::Ready {
                    user_did: user_did.to_string(),
                };
                Ok(())
            }
            OrchestratorLifecycleState::Suspended { .. } => {
                Err(OrchestratorError::NotAuthenticated)
            }
            OrchestratorLifecycleState::FailedInitialization
            | OrchestratorLifecycleState::Shutdown => Err(OrchestratorError::ShuttingDown),
            _ => Err(OrchestratorError::InvalidInput(
                "resume requires a suspended orchestrator".to_string(),
            )),
        }
    }

    /// Enter the only lifecycle phase that `resume_after_suspend` accepts.
    pub async fn suspend(&self) -> Result<()> {
        let _lifecycle_owner = self.lifecycle_operation.lock().await;
        let user_did = {
            let mut lifecycle = self.lifecycle_state.lock().await;
            let user_did = match &*lifecycle {
                OrchestratorLifecycleState::Ready { user_did } => user_did.clone(),
                OrchestratorLifecycleState::Suspended { .. } => return Ok(()),
                OrchestratorLifecycleState::FailedInitialization
                | OrchestratorLifecycleState::Shutdown => {
                    return Err(OrchestratorError::ShuttingDown)
                }
                _ => return Err(OrchestratorError::NotAuthenticated),
            };
            *lifecycle = OrchestratorLifecycleState::Suspended {
                user_did: user_did.clone(),
            };
            user_did
        };
        tracing::info!(user_did, "Suspending MLS orchestrator");
        self.clear_runtime_state().await;
        Ok(())
    }

    /// Attach a fresh runtime to state whose suspension was established by
    /// the engine lifecycle owner. This is intentionally distinct from resume.
    pub async fn reattach_after_suspend(&self, user_did: &str) -> Result<()> {
        let _lifecycle_owner = self.lifecycle_operation.lock().await;
        let mut lifecycle = self.lifecycle_state.lock().await;
        match &*lifecycle {
            OrchestratorLifecycleState::Uninitialized => {
                *lifecycle = OrchestratorLifecycleState::Ready {
                    user_did: user_did.to_string(),
                };
                Ok(())
            }
            _ => Err(OrchestratorError::InvalidInput(
                "reattach requires a fresh orchestrator".to_string(),
            )),
        }
    }

    /// Shut down the orchestrator, releasing resources.
    pub async fn shutdown(&self) {
        let _lifecycle_owner = self.lifecycle_operation.lock().await;
        tracing::info!("Shutting down MLS orchestrator");
        *self.lifecycle_state.lock().await = OrchestratorLifecycleState::Shutdown;
        self.clear_runtime_state().await;
    }

    async fn clear_runtime_state(&self) {
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
    }

    /// Get the authenticated user DID or return an error.
    pub(crate) async fn require_user_did(&self) -> Result<String> {
        match &*self.lifecycle_state.lock().await {
            OrchestratorLifecycleState::Ready { user_did } => Ok(user_did.clone()),
            _ => Err(OrchestratorError::NotAuthenticated),
        }
    }

    /// Check if the orchestrator is shutting down, returning an error if so.
    pub(crate) async fn check_shutdown(&self) -> Result<()> {
        match &*self.lifecycle_state.lock().await {
            OrchestratorLifecycleState::Suspended { .. }
            | OrchestratorLifecycleState::FailedInitialization
            | OrchestratorLifecycleState::Shutdown => Err(OrchestratorError::ShuttingDown),
            _ => Ok(()),
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

    /// Opt in to returning/storing known non-displayable MLS control payloads
    /// from `process_incoming`.
    ///
    /// The default is `false` so existing clients do not accidentally render
    /// raw control JSON. Catbird iOS enables this in Rust-authoritative mode
    /// and consumes the payloads for local side effects.
    pub fn set_store_control_messages(&self, enabled: bool) {
        self.store_control_messages
            .store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn store_control_messages(&self) -> bool {
        self.store_control_messages.load(Ordering::Relaxed)
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

    /// Access the ADR-009 D6 authorized-device-key cache (WS-3 stage 2).
    pub(crate) fn device_key_cache(
        &self,
    ) -> &Mutex<HashMap<String, super::credential_binding::DeviceKeyCacheEntry>> {
        &self.device_key_cache
    }

    /// Drop all cached authorized-device-key lookups (ADR-009 D6 requires
    /// the cache to be bypassable for diagnostics or explicit refresh).
    /// The next credential-binding check re-resolves through
    /// `CredentialStore::get_authorized_device_keys`.
    pub async fn invalidate_device_key_cache(&self) {
        self.device_key_cache.lock().await.clear();
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
        group_id: &str,
        current_epoch: u64,
    ) {
        let Some(targets) = epoch_cleanup_targets(conversation_id, group_id, current_epoch) else {
            return;
        };
        let retention = constants::MAX_PAST_EPOCHS_TO_RETAIN;
        let cutoff_epoch = targets.cutoff_epoch;

        // Clean up via MLS crypto context (EpochSecretManager)
        if let Some(group_id_bytes) = targets.crypto_group_id {
            if let Err(e) =
                self.mls_context()
                    .cleanup_epoch_secrets(group_id_bytes, current_epoch, retention)
            {
                tracing::warn!(
                    error = %e,
                    conversation_id,
                    group_id,
                    current_epoch,
                    "Failed to cleanup epoch secrets via MLS context"
                );
            }
        }

        // Clean up via platform storage backend
        if let Err(e) = self
            .storage()
            .cleanup_old_epoch_data(targets.storage_conversation_id, cutoff_epoch)
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

#[cfg(test)]
mod epoch_cleanup_target_tests {
    use super::*;

    #[test]
    fn cleanup_targets_mutable_group_for_crypto_and_stable_conversation_for_storage() {
        let stable_conversation_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mutable_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let current_epoch = constants::MAX_PAST_EPOCHS_TO_RETAIN + 2;

        let targets =
            epoch_cleanup_targets(stable_conversation_id, mutable_group_id, current_epoch)
                .expect("epoch exceeds retention");

        assert_eq!(targets.storage_conversation_id, stable_conversation_id);
        assert_eq!(targets.crypto_group_id, hex::decode(mutable_group_id).ok());
        assert_ne!(
            targets.crypto_group_id,
            hex::decode(stable_conversation_id).ok(),
            "stable conversation id must never become the MLS cleanup target"
        );
        assert_eq!(targets.cutoff_epoch, 2);
    }
}
