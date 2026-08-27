//! MLS Echo Bot — deterministic test responder for MLS group chats.
//!
//! Joins MLS groups via Welcome messages, polls for new messages, and echoes
//! them back with an "[echo] " prefix. Uses the real MLS delivery service.
//!
//! Usage:
//!   cargo run --features echo-bot --bin echo-bot -- --bot-did did:plc:echobot --ds-url http://localhost:3001
//!
//! Or via environment variables:
//!   BOT_DID=did:plc:echobot DS_URL=http://localhost:3001 cargo run --features echo-bot --bin echo-bot

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use clap::Parser;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result as OrcResult};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;
use catbird_mls::orchestrator::{MLSAPIClient, MLSOrchestrator, OrchestratorConfig};
use catbird_mls::{KeychainAccess, MLSContext, MLSError};

// ═══════════════════════════════════════════════════════════════════════════
// CLI arguments
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(name = "echo-bot", about = "MLS echo bot for testing group chats")]
struct Args {
    /// The bot's AT Protocol DID
    #[arg(long, env = "BOT_DID", default_value = "did:plc:echobot")]
    bot_did: String,

    /// MLS delivery service URL
    #[arg(long, env = "DS_URL", default_value = "http://localhost:3001")]
    ds_url: String,

    /// Bearer token for DS authentication
    #[arg(long, env = "BOT_AUTH_TOKEN", default_value = "echo-bot-test-token")]
    auth_token: String,

    /// Poll interval in milliseconds
    #[arg(long, env = "POLL_INTERVAL_MS", default_value_t = 2000)]
    poll_interval_ms: u64,

    /// Delay before echoing in milliseconds
    #[arg(long, env = "ECHO_DELAY_MS", default_value_t = 1000)]
    echo_delay_ms: u64,

    /// Persistent directory for MLS and recovery state
    #[arg(long, env = "BOT_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

// ═══════════════════════════════════════════════════════════════════════════
// In-memory KeychainAccess
// ═══════════════════════════════════════════════════════════════════════════

struct InMemoryKeychain {
    store: StdMutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryKeychain {
    fn new() -> Self {
        Self {
            store: StdMutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeychainAccess for InMemoryKeychain {
    async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
        Ok(self.store.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// In-memory CredentialStore
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
struct BotCredentialEntry {
    mls_did: Option<String>,
    device_uuid: Option<String>,
    signing_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct BotCredentials {
    state: Arc<StdMutex<HashMap<String, BotCredentialEntry>>>,
}

impl BotCredentials {
    fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl CredentialStore for BotCredentials {
    async fn store_signing_key(&self, did: &str, key: &[u8]) -> OrcResult<()> {
        self.state
            .lock()
            .unwrap()
            .entry(did.to_string())
            .or_default()
            .signing_key = Some(key.to_vec());
        Ok(())
    }
    async fn get_signing_key(&self, did: &str) -> OrcResult<Option<Vec<u8>>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(did)
            .and_then(|c| c.signing_key.clone()))
    }
    async fn delete_signing_key(&self, did: &str) -> OrcResult<()> {
        if let Some(c) = self.state.lock().unwrap().get_mut(did) {
            c.signing_key = None;
        }
        Ok(())
    }
    async fn store_mls_did(&self, did: &str, mls_did: &str) -> OrcResult<()> {
        self.state
            .lock()
            .unwrap()
            .entry(did.to_string())
            .or_default()
            .mls_did = Some(mls_did.to_string());
        Ok(())
    }
    async fn get_mls_did(&self, did: &str) -> OrcResult<Option<String>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(did)
            .and_then(|c| c.mls_did.clone()))
    }
    async fn store_device_uuid(&self, did: &str, uuid: &str) -> OrcResult<()> {
        self.state
            .lock()
            .unwrap()
            .entry(did.to_string())
            .or_default()
            .device_uuid = Some(uuid.to_string());
        Ok(())
    }
    async fn get_device_uuid(&self, did: &str) -> OrcResult<Option<String>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(did)
            .and_then(|c| c.device_uuid.clone()))
    }
    async fn has_credentials(&self, did: &str) -> OrcResult<bool> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(did)
            .map_or(false, |c| c.mls_did.is_some() && c.device_uuid.is_some()))
    }
    async fn clear_all(&self, did: &str) -> OrcResult<()> {
        self.state.lock().unwrap().remove(did);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// In-memory StorageBackend
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Default)]
struct BotStorageInner {
    conversations: HashMap<String, ConversationView>,
    messages: HashMap<String, Vec<Message>>,
    message_ids: HashSet<String>,
    group_states: HashMap<String, GroupState>,
    sync_cursors: HashMap<String, SyncCursor>,
    conversation_states: HashMap<String, ConversationState>,
    pending_messages: HashSet<String>,
    recovery_backoff: HashMap<String, PersistedRecoveryBackoff>,
    last_global_rejoin_attempt_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
struct BotStorage {
    inner: Arc<StdMutex<BotStorageInner>>,
    recovery_path: Arc<PathBuf>,
    fail_next_directory_sync: Arc<std::sync::atomic::AtomicBool>,
}

impl BotStorage {
    fn with_recovery_path(recovery_path: PathBuf) -> OrcResult<Self> {
        let persisted = Self::read_recovery_state(&recovery_path)?;
        let inner = BotStorageInner {
            recovery_backoff: persisted
                .entries
                .into_iter()
                .map(|entry| (entry.conversation_id.clone(), entry))
                .collect(),
            last_global_rejoin_attempt_at_ms: persisted.last_global_rejoin_attempt_at_ms,
            ..BotStorageInner::default()
        };
        Ok(Self {
            inner: Arc::new(StdMutex::new(inner)),
            recovery_path: Arc::new(recovery_path),
            fail_next_directory_sync: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    fn read_recovery_state(path: &Path) -> OrcResult<PersistedRecoveryState> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                OrchestratorError::Storage(format!(
                    "invalid echo-bot recovery state {}: {error}",
                    path.display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PersistedRecoveryState::default())
            }
            Err(error) => Err(OrchestratorError::Storage(format!(
                "read echo-bot recovery state {}: {error}",
                path.display()
            ))),
        }
    }

    fn persist_recovery_state(
        &self,
        state: &PersistedRecoveryState,
        inner: &mut BotStorageInner,
    ) -> OrcResult<()> {
        if let Some(parent) = self.recovery_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OrchestratorError::Storage(format!(
                    "create echo-bot recovery directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let bytes = serde_json::to_vec(state).map_err(|error| {
            OrchestratorError::Storage(format!("serialize echo-bot recovery state: {error}"))
        })?;
        let temporary = self
            .recovery_path
            .with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
        let mut file = std::fs::File::create(&temporary).map_err(|error| {
            OrchestratorError::Storage(format!(
                "create echo-bot recovery state {}: {error}",
                temporary.display()
            ))
        })?;
        file.write_all(&bytes).map_err(|error| {
            OrchestratorError::Storage(format!(
                "write echo-bot recovery state {}: {error}",
                temporary.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            OrchestratorError::Storage(format!(
                "sync echo-bot recovery state {}: {error}",
                temporary.display()
            ))
        })?;
        std::fs::rename(&temporary, self.recovery_path.as_ref()).map_err(|error| {
            OrchestratorError::Storage(format!(
                "commit echo-bot recovery state {}: {error}",
                self.recovery_path.display()
            ))
        })?;
        // Rename publishes the new authoritative file. Install the same
        // snapshot in memory before directory fsync can report durability
        // uncertainty, so a later whole-file update cannot erase it.
        Self::install_recovery_state(inner, state);
        if self
            .fail_next_directory_sync
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(OrchestratorError::Storage(
                "injected echo-bot recovery directory sync failure".to_string(),
            ));
        }
        if let Some(parent) = self.recovery_path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    OrchestratorError::Storage(format!(
                        "sync echo-bot recovery directory {}: {error}",
                        parent.display()
                    ))
                })?;
        }
        Ok(())
    }

    fn recovery_state(inner: &BotStorageInner) -> PersistedRecoveryState {
        PersistedRecoveryState {
            entries: inner.recovery_backoff.values().cloned().collect(),
            last_global_rejoin_attempt_at_ms: inner.last_global_rejoin_attempt_at_ms,
        }
    }

    fn install_recovery_state(inner: &mut BotStorageInner, state: &PersistedRecoveryState) {
        inner.recovery_backoff = state
            .entries
            .iter()
            .cloned()
            .map(|entry| (entry.conversation_id.clone(), entry))
            .collect();
        inner.last_global_rejoin_attempt_at_ms = state.last_global_rejoin_attempt_at_ms;
    }

    #[cfg(test)]
    fn fail_next_directory_sync(&self) {
        self.fail_next_directory_sync
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[async_trait]
impl MLSStorageBackend for BotStorage {
    async fn ensure_conversation_exists(
        &self,
        _user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> OrcResult<()> {
        let mut s = self.inner.lock().unwrap();
        s.conversations
            .entry(conversation_id.to_string())
            .or_insert_with(|| ConversationView {
                group_id: group_id.to_string(),
                conversation_id: conversation_id.to_string(),
                epoch: 0,
                members: vec![],
                metadata: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                sequencer_did: None,
            });
        Ok(())
    }
    async fn update_join_info(
        &self,
        _conversation_id: &str,
        _user_did: &str,
        _join_method: JoinMethod,
        _join_epoch: u64,
    ) -> OrcResult<()> {
        Ok(())
    }
    async fn get_conversation(
        &self,
        _user_did: &str,
        conversation_id: &str,
    ) -> OrcResult<Option<ConversationView>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .conversations
            .get(conversation_id)
            .cloned())
    }
    async fn list_conversations(&self, _user_did: &str) -> OrcResult<Vec<ConversationView>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .conversations
            .values()
            .cloned()
            .collect())
    }
    async fn delete_conversations(&self, _user_did: &str, ids: &[&str]) -> OrcResult<()> {
        let mut s = self.inner.lock().unwrap();
        for id in ids {
            s.conversations.remove(*id);
        }
        Ok(())
    }
    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> OrcResult<()> {
        self.inner
            .lock()
            .unwrap()
            .conversation_states
            .insert(conversation_id.to_string(), state);
        Ok(())
    }
    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> OrcResult<Option<ConversationState>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .conversation_states
            .get(conversation_id)
            .cloned())
    }
    async fn mark_needs_rejoin(&self, conversation_id: &str) -> OrcResult<()> {
        self.inner
            .lock()
            .unwrap()
            .conversation_states
            .insert(conversation_id.to_string(), ConversationState::NeedsRejoin);
        Ok(())
    }
    async fn needs_rejoin(&self, conversation_id: &str) -> OrcResult<bool> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .conversation_states
            .get(conversation_id)
            == Some(&ConversationState::NeedsRejoin))
    }
    async fn clear_rejoin_flag(&self, conversation_id: &str) -> OrcResult<()> {
        let mut s = self.inner.lock().unwrap();
        if s.conversation_states.get(conversation_id) == Some(&ConversationState::NeedsRejoin) {
            s.conversation_states
                .insert(conversation_id.to_string(), ConversationState::Active);
        }
        Ok(())
    }
    async fn store_message(&self, message: &Message) -> OrcResult<()> {
        let mut s = self.inner.lock().unwrap();
        s.message_ids.insert(message.id.clone());
        s.messages
            .entry(message.conversation_id.clone())
            .or_default()
            .push(message.clone());
        Ok(())
    }
    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> OrcResult<Vec<Message>> {
        let s = self.inner.lock().unwrap();
        let msgs = s.messages.get(conversation_id).cloned().unwrap_or_default();
        let filtered: Vec<Message> = msgs
            .into_iter()
            .filter(|m| before_sequence.map_or(true, |seq| m.sequence_number < seq))
            .collect();
        Ok(filtered.into_iter().rev().take(limit as usize).collect())
    }
    async fn message_exists(&self, message_id: &str) -> OrcResult<bool> {
        Ok(self.inner.lock().unwrap().message_ids.contains(message_id))
    }
    async fn get_sync_cursor(&self, user_did: &str) -> OrcResult<SyncCursor> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .sync_cursors
            .get(user_did)
            .cloned()
            .unwrap_or_default())
    }
    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> OrcResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sync_cursors
            .insert(user_did.to_string(), cursor.clone());
        Ok(())
    }
    async fn set_group_state(&self, state: &GroupState) -> OrcResult<()> {
        self.inner
            .lock()
            .unwrap()
            .group_states
            .insert(state.group_id.clone(), state.clone());
        Ok(())
    }
    async fn get_group_state(&self, group_id: &str) -> OrcResult<Option<GroupState>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .group_states
            .get(group_id)
            .cloned())
    }
    async fn delete_group_state(&self, group_id: &str) -> OrcResult<()> {
        self.inner.lock().unwrap().group_states.remove(group_id);
        Ok(())
    }
    async fn store_pending_message(
        &self,
        _conversation_id: &str,
        message_id: &str,
    ) -> OrcResult<()> {
        self.inner
            .lock()
            .unwrap()
            .pending_messages
            .insert(message_id.to_string());
        Ok(())
    }
    async fn remove_pending_message(&self, message_id: &str) -> OrcResult<bool> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .pending_messages
            .remove(message_id))
    }
    async fn get_recovery_state(&self) -> OrcResult<PersistedRecoveryState> {
        Ok(Self::recovery_state(&self.inner.lock().unwrap()))
    }
    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> OrcResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut candidate = Self::recovery_state(&inner);
        candidate
            .entries
            .retain(|persisted| persisted.conversation_id != entry.conversation_id);
        candidate.entries.push(entry.clone());
        self.persist_recovery_state(&candidate, &mut inner)
    }
    async fn clear_recovery_backoff(&self, conversation_id: &str) -> OrcResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut candidate = Self::recovery_state(&inner);
        candidate
            .entries
            .retain(|entry| entry.conversation_id != conversation_id);
        self.persist_recovery_state(&candidate, &mut inner)
    }
    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> OrcResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut candidate = Self::recovery_state(&inner);
        candidate.last_global_rejoin_attempt_at_ms = Some(at_ms);
        self.persist_recovery_state(&candidate, &mut inner)
    }
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "store_pending_message",
            "remove_pending_message",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
        ]
    }
}

#[cfg(test)]
mod bot_storage_tests {
    use super::*;

    fn test_mls_context(path: &std::path::Path, label: &str) -> Arc<MLSContext> {
        MLSContext::new(
            path.to_string_lossy().to_string(),
            format!("echo-bot-storage-test-{label}"),
            Box::new(InMemoryKeychain::new()),
        )
        .expect("create test MLS context")
    }

    #[tokio::test]
    async fn bot_storage_definitively_reads_conversation_state_for_normal_resolution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = BotStorage::with_recovery_path(directory.path().join("recovery-state.json"))
            .expect("create bot storage");
        assert_eq!(
            storage
                .get_conversation_state("ordinary-conversation")
                .await
                .expect("ordinary resolution requires a definitive absence"),
            None
        );

        storage
            .set_conversation_state("tracked-conversation", ConversationState::NeedsRejoin)
            .await
            .expect("store tracked state");
        assert_eq!(
            storage
                .get_conversation_state("tracked-conversation")
                .await
                .expect("read tracked state"),
            Some(ConversationState::NeedsRejoin)
        );
    }

    #[tokio::test]
    async fn bot_storage_recovery_state_survives_restart_and_allows_initialization() {
        let directory = tempfile::tempdir().expect("tempdir");
        let recovery_path = directory.path().join("recovery-state.json");
        let did = "did:plc:echo-storage-test";
        let conversation_id = "durable-recovery-conversation";

        let storage = BotStorage::with_recovery_path(recovery_path.clone())
            .expect("create durable bot storage");
        storage
            .set_recovery_backoff(&PersistedRecoveryBackoff {
                conversation_id: conversation_id.to_string(),
                failed_rejoin_count: 2,
                last_attempt_at_ms: Utc::now().timestamp_millis(),
                quarantined_until_ms: None,
            })
            .await
            .expect("persist recovery backoff");
        drop(storage);

        let restarted =
            BotStorage::with_recovery_path(recovery_path).expect("reopen durable bot storage");
        let orchestrator = MLSOrchestrator::new(
            test_mls_context(&directory.path().join("restart.db"), "restart"),
            Arc::new(restarted),
            Arc::new(HttpDSClient::new("http://127.0.0.1:9", did, "test-token")),
            Arc::new(BotCredentials::new()),
            OrchestratorConfig::default(),
        );

        orchestrator
            .initialize(did)
            .await
            .expect("echo-bot storage must satisfy mandatory recovery persistence");
        let tracker = orchestrator.recovery_tracker().lock().await;
        assert_eq!(tracker.failed_attempts(conversation_id), 2);
        assert!(tracker.cooldown_remaining(conversation_id).is_some());
    }

    #[tokio::test]
    async fn post_rename_sync_failure_cannot_be_erased_by_later_write() {
        let directory = tempfile::tempdir().expect("tempdir");
        let recovery_path = directory.path().join("recovery-state.json");
        let storage = BotStorage::with_recovery_path(recovery_path.clone())
            .expect("create durable bot storage");
        let entry = |conversation_id: &str| PersistedRecoveryBackoff {
            conversation_id: conversation_id.to_string(),
            failed_rejoin_count: 1,
            last_attempt_at_ms: Utc::now().timestamp_millis(),
            quarantined_until_ms: None,
        };

        storage.fail_next_directory_sync();
        storage
            .set_recovery_backoff(&entry("conversation-a"))
            .await
            .expect_err("post-rename directory sync failure must propagate");
        storage
            .set_recovery_backoff(&entry("conversation-b"))
            .await
            .expect("later write must preserve the renamed snapshot");
        drop(storage);

        let restarted =
            BotStorage::with_recovery_path(recovery_path).expect("reopen durable bot storage");
        let persisted = restarted
            .get_recovery_state()
            .await
            .expect("read recovery state");
        let ids: HashSet<_> = persisted
            .entries
            .iter()
            .map(|entry| entry.conversation_id.as_str())
            .collect();
        assert_eq!(ids, HashSet::from(["conversation-a", "conversation-b"]));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP-based MLSAPIClient for the real delivery service
// ═══════════════════════════════════════════════════════════════════════════

struct HttpDSClient {
    client: reqwest::Client,
    base_url: String,
    did: String,
    auth_token: String,
}

impl HttpDSClient {
    fn new(base_url: &str, did: &str, auth_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            did: did.to_string(),
            auth_token: auth_token.to_string(),
        }
    }

    fn xrpc_url(&self, method: &str) -> String {
        format!("{}/xrpc/{}", self.base_url, method)
    }
}

#[async_trait]
impl MLSAPIClient for HttpDSClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.did == did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.did.clone())
    }
    async fn submit_prepared_request(
        &self,
        request: catbird_mls::orchestrator::canonical_transport::PreparedRequest,
    ) -> OrcResult<catbird_mls::orchestrator::canonical_transport::GatewayResponse> {
        let url = format!("{}{}", self.base_url, request.path);
        let mut builder = match request.method.as_str() {
            "POST" => self.client.post(&url),
            "GET" => self.client.get(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            _ => self.client.post(&url),
        };
        builder = builder.bearer_auth(&self.auth_token);
        if let Some(body) = request.body {
            builder = builder
                .body(body)
                .header("Content-Type", "application/json");
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?
            .to_vec();
        Ok(
            catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status,
                content_type,
                body,
            },
        )
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> OrcResult<ConversationListPage> {
        let mut params = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversations"))
            .bearer_auth(&self.auth_token)
            .query(&params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getConvos: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError { status, body });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getConvos parse: {e}")))?;

        let convos = body["convos"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| parse_convo_view(c))
            .collect();
        let cursor = body["cursor"].as_str().map(|s| s.to_string());

        Ok(ConversationListPage {
            conversations: convos,
            cursor,
        })
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> OrcResult<(Vec<IncomingEnvelope>, Option<String>)> {
        let mut params = vec![
            ("convoId", convo_id.to_string()),
            ("limit", limit.to_string()),
        ];
        if let Some(c) = cursor {
            params.push(("cursor", c.to_string()));
        }
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getEntries"))
            .bearer_auth(&self.auth_token)
            .query(&params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getMessages: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError { status, body });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getMessages parse: {e}")))?;

        let messages = body["messages"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| parse_incoming_envelope(convo_id, m))
            .collect();
        let next_cursor = body["cursor"].as_str().map(|s| s.to_string());

        Ok((messages, next_cursor))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        dids: &[String],
    ) -> OrcResult<Vec<KeyPackageRef>> {
        let dids_param = dids.join(",");
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getPendingWelcomes"))
            .bearer_auth(&self.auth_token)
            .query(&[("dids", &dids_param)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackages: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError { status, body });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackages parse: {e}")))?;

        let packages = val["packages"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|p| {
                let did = p["did"].as_str()?.to_string();
                let kp_data = p["keyPackage"]
                    .as_str()
                    .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())?;
                let hash_ref = p["hashRef"]
                    .as_str()
                    .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                    .unwrap_or_default();
                Some(KeyPackageRef {
                    did,
                    key_package_data: kp_data,
                    hash: None,
                    cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
                })
            })
            .collect();

        Ok(packages)
    }

    async fn get_key_package_stats(&self) -> OrcResult<KeyPackageStats> {
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getPendingWelcomes"))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackageStats: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError { status, body });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackageStats parse: {e}")))?;

        Ok(KeyPackageStats {
            available: val["available"].as_u64().unwrap_or(0) as u32,
            total: val["total"].as_u64().unwrap_or(0) as u32,
        })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> OrcResult<KeyPackageSyncResult> {
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn list_devices(&self, _actor_device_id: &str) -> OrcResult<Vec<DeviceInfo>> {
        Ok(vec![])
    }

    async fn get_group_info(&self, convo_id: &str) -> OrcResult<Vec<u8>> {
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversationState"))
            .bearer_auth(&self.auth_token)
            .query(&[("convoId", convo_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getGroupInfo: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError { status, body });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getGroupInfo parse: {e}")))?;

        let data = val["groupInfo"]
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default();

        Ok(data)
    }

    async fn get_welcome(&self, _convo_id: &str) -> OrcResult<Vec<u8>> {
        Err(OrchestratorError::Api(
            "Welcome retrieval via getMessages — use join_group flow".into(),
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON parsing helpers
// ═══════════════════════════════════════════════════════════════════════════

fn parse_convo_view(val: &serde_json::Value) -> Option<ConversationView> {
    let group_id = val["id"]
        .as_str()
        .or_else(|| val["groupId"].as_str())?
        .to_string();
    let members = val["members"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|m| {
            Some(MemberView {
                did: m["did"].as_str()?.to_string(),
                role: if m["role"].as_str() == Some("admin") {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
        })
        .collect();

    let conversation_id = val["conversationId"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    Some(ConversationView {
        group_id,
        conversation_id,
        epoch: val["epoch"].as_u64().unwrap_or(0),
        members,
        metadata: None,
        created_at: parse_datetime(val["createdAt"].as_str()),
        updated_at: parse_datetime(val["updatedAt"].as_str()),
        // Optional convoView.sequencerDid (ADR-010 D4); absent on
        // pre-rung-2 servers.
        sequencer_did: val["sequencerDid"].as_str().map(|s| s.to_string()),
    })
}

fn parse_incoming_envelope(convo_id: &str, val: &serde_json::Value) -> Option<IncomingEnvelope> {
    use base64::Engine;
    let ciphertext_b64 = val["ciphertext"].as_str()?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .ok()?;
    let sender_did = val["senderDid"]
        .as_str()
        .or_else(|| val["sender"].as_str())
        .unwrap_or("unknown")
        .to_string();
    let timestamp = parse_datetime(val["timestamp"].as_str()).unwrap_or_else(Utc::now);
    let server_message_id = val["id"]
        .as_str()
        .or_else(|| val["messageId"].as_str())
        .map(|s| s.to_string());
    let server_epoch = val["serverEpoch"]
        .as_u64()
        .or_else(|| val["server_epoch"].as_u64())
        .or_else(|| val["epoch"].as_u64());

    Some(IncomingEnvelope {
        conversation_id: convo_id.to_string(),
        sender_did,
        ciphertext,
        timestamp,
        server_message_id,
        server_epoch,
    })
}

fn parse_datetime(s: Option<&str>) -> Option<DateTime<Utc>> {
    s.and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(
        did = %args.bot_did,
        ds_url = %args.ds_url,
        poll_ms = args.poll_interval_ms,
        echo_delay_ms = args.echo_delay_ms,
        "Starting MLS echo bot"
    );

    let state_dir = args.state_dir.unwrap_or_else(|| {
        let safe_did: String = args
            .bot_did
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '_'
                }
            })
            .collect();
        std::env::temp_dir().join(format!("echo_bot_mls_{safe_did}"))
    });
    std::fs::create_dir_all(&state_dir)?;
    let db_path = state_dir.join("echo-bot.db");

    info!(db_path = %db_path.display(), "MLS database location");

    // Initialize MLS context
    let keychain = Box::new(InMemoryKeychain::new());
    let mls_context = MLSContext::new(
        db_path.to_string_lossy().to_string(),
        format!("echo-bot-key-{}", args.bot_did),
        keychain,
    )
    .map_err(|e| format!("Failed to create MLSContext: {e}"))?;

    // Create backend implementations
    let storage = BotStorage::with_recovery_path(state_dir.join("recovery-state.json"))
        .map_err(|e| format!("Failed to create durable BotStorage: {e}"))?;
    let credentials = BotCredentials::new();
    let api_client = HttpDSClient::new(&args.ds_url, &args.bot_did, &args.auth_token);

    let config = OrchestratorConfig {
        target_key_package_count: 10,
        key_package_replenish_threshold: 3,
        ..OrchestratorConfig::default()
    };

    let orchestrator = MLSOrchestrator::new(
        mls_context,
        Arc::new(storage),
        Arc::new(api_client),
        Arc::new(credentials),
        config,
    );

    // Initialize orchestrator
    orchestrator
        .initialize(&args.bot_did)
        .await
        .map_err(|e| format!("Failed to initialize orchestrator: {e}"))?;

    // Register device
    info!("Registering device with delivery service...");
    match orchestrator.ensure_device_registered().await {
        Ok(mls_did) => info!(mls_did = %mls_did, "Device registered"),
        Err(e) => {
            warn!(error = %e, "Device registration failed (DS may not be running). Continuing in offline mode...");
        }
    }

    info!("Echo bot ready — polling for messages");

    // Track per-conversation message cursors
    let cursors: Arc<Mutex<HashMap<String, Option<String>>>> = Arc::new(Mutex::new(HashMap::new()));

    // Main poll loop
    let poll_interval = tokio::time::Duration::from_millis(args.poll_interval_ms);
    let echo_delay = tokio::time::Duration::from_millis(args.echo_delay_ms);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                orchestrator.shutdown().await;
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                // Sync conversations
                if let Err(e) = orchestrator.sync_with_server(false).await {
                    warn!(error = %e, "Sync failed");
                    continue;
                }

                // Get known conversations
                let convos = {
                    let cache = orchestrator.conversations().lock().await;
                    cache.keys().cloned().collect::<Vec<_>>()
                };

                for convo_id in &convos {
                    let cursor = {
                        let c = cursors.lock().await;
                        c.get(convo_id).cloned().flatten()
                    };

                    match orchestrator
                        .fetch_messages(convo_id, cursor.as_deref(), 50, None, None, None)
                        .await
                    {
                        Ok((messages, new_cursor)) => {
                            // Update cursor
                            if new_cursor.is_some() {
                                cursors.lock().await.insert(convo_id.clone(), new_cursor);
                            }

                            // Echo non-own messages
                            for msg in &messages {
                                if msg.is_own {
                                    continue;
                                }
                                // Skip echo-of-echo (prevent infinite loops)
                                if msg.text.starts_with("[echo] ") {
                                    continue;
                                }

                                info!(
                                    convo = %convo_id,
                                    sender = %msg.sender_did,
                                    text = %msg.text,
                                    "Received message"
                                );

                                // Delay before echo
                                tokio::time::sleep(echo_delay).await;

                                let echo_text = format!("[echo] {}", msg.text);
                                match orchestrator.send_message(convo_id, &echo_text).await {
                                    Ok(sent) => {
                                        info!(
                                            convo = %convo_id,
                                            echo = %sent.text,
                                            "Echoed message"
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            convo = %convo_id,
                                            error = %e,
                                            "Failed to echo message"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                convo = %convo_id,
                                error = %e,
                                "Failed to fetch messages"
                            );
                        }
                    }
                }
            }
        }
    }

    info!("Echo bot stopped");
    Ok(())
}
