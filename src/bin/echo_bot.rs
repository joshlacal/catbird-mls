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
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use base64::Engine as _;
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
}

#[derive(Debug, Clone)]
struct BotStorage {
    inner: Arc<StdMutex<BotStorageInner>>,
}

impl BotStorage {
    fn new() -> Self {
        Self {
            inner: Arc::new(StdMutex::new(BotStorageInner::default())),
        }
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
                epoch: 0,
                members: vec![],
                metadata: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
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
        let msgs = s
            .messages
            .get(conversation_id)
            .cloned()
            .unwrap_or_default();
        let filtered: Vec<Message> = msgs
            .into_iter()
            .filter(|m| before_sequence.map_or(true, |seq| m.sequence_number < seq))
            .collect();
        Ok(filtered.into_iter().rev().take(limit as usize).collect())
    }
    async fn message_exists(&self, message_id: &str) -> OrcResult<bool> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .message_ids
            .contains(message_id))
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
            .get(self.xrpc_url("blue.catbird.mlsChat.getConvos"))
            .bearer_auth(&self.auth_token)
            .query(&params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getConvos: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
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

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> OrcResult<CreateConversationResult> {
        let mut body = serde_json::json!({ "groupId": group_id });
        if let Some(members) = initial_members {
            body["initialMembers"] = serde_json::json!(members);
        }
        if let Some(m) = metadata {
            body["metadata"] = serde_json::json!({
                "name": m.name,
                "description": m.description,
            });
        }
        if let Some(d) = commit_data {
            body["commitData"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(d));
        }
        if let Some(d) = welcome_data {
            body["welcomeData"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(d));
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.createConvo"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("createConvo: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("createConvo parse: {e}")))?;

        let convo = parse_convo_view(&val["convo"]).unwrap_or(ConversationView {
            group_id: group_id.to_string(),
            epoch: 0,
            members: vec![],
            metadata: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        });

        Ok(CreateConversationResult {
            conversation: convo,
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> OrcResult<()> {
        let body = serde_json::json!({ "convoId": convo_id });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.leaveConvo"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("leaveConvo: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }
        Ok(())
    }

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> OrcResult<AddMembersServerResult> {
        let mut body = serde_json::json!({
            "convoId": convo_id,
            "memberDids": member_dids,
            "commitData": base64::engine::general_purpose::STANDARD.encode(commit_data),
        });
        if let Some(w) = welcome_data {
            body["welcomeData"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(w));
        }
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.commitGroupChange"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("addMembers: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("addMembers parse: {e}")))?;
        Ok(AddMembersServerResult {
            success: true,
            new_epoch: val["epoch"].as_u64().unwrap_or(0),
            receipt: None,
        })
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> OrcResult<()> {
        let body = serde_json::json!({
            "convoId": convo_id,
            "memberDids": member_dids,
            "commitData": base64::engine::general_purpose::STANDARD.encode(commit_data),
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.commitGroupChange"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("removeMembers: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }
        Ok(())
    }

    async fn send_message(&self, convo_id: &str, ciphertext: &[u8], epoch: u64) -> OrcResult<()> {
        let body = serde_json::json!({
            "convoId": convo_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext),
            "epoch": epoch,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.sendMessage"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("sendMessage: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }
        Ok(())
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
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
            .get(self.xrpc_url("blue.catbird.mlsChat.getMessages"))
            .bearer_auth(&self.auth_token)
            .query(&params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getMessages: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getMessages parse: {e}")))?;

        let cursor = val["cursor"].as_str().map(|s| s.to_string());
        let envelopes = val["messages"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| parse_incoming_envelope(convo_id, m))
            .collect();

        Ok((envelopes, cursor))
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> OrcResult<()> {
        let body = serde_json::json!({
            "keyPackages": [{
                "data": base64::engine::general_purpose::STANDARD.encode(key_package),
                "cipherSuite": cipher_suite,
                "expiresAt": expires_at,
            }],
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.publishKeyPackages"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("publishKeyPackages: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }
        Ok(())
    }

    async fn get_key_packages(&self, dids: &[String]) -> OrcResult<Vec<KeyPackageRef>> {
        let params: Vec<(&str, &str)> = dids.iter().map(|d| ("dids", d.as_str())).collect();
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.mlsChat.getKeyPackages"))
            .bearer_auth(&self.auth_token)
            .query(&params)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackages: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackages parse: {e}")))?;

        let refs = val["keyPackages"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|kp| {
                let did = kp["did"].as_str()?.to_string();
                let data_b64 = kp["data"].as_str()?;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .ok()?;
                Some(KeyPackageRef {
                    did,
                    key_package_data: data,
                    hash: kp["hash"].as_str().map(|s| s.to_string()),
                    cipher_suite: kp["cipherSuite"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string(),
                })
            })
            .collect();

        Ok(refs)
    }

    async fn get_key_package_stats(&self) -> OrcResult<KeyPackageStats> {
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.mlsChat.getKeyPackageStatus"))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackageStatus: {e}")))?;

        if !resp.status().is_success() {
            // If the endpoint doesn't exist or fails, return 0 to trigger replenishment
            return Ok(KeyPackageStats {
                available: 0,
                total: 0,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getKeyPackageStatus parse: {e}")))?;

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

    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> OrcResult<DeviceInfo> {
        let kps: Vec<serde_json::Value> = key_packages
            .iter()
            .map(|kp| {
                serde_json::json!({
                    "data": base64::engine::general_purpose::STANDARD.encode(kp),
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "expiresAt": (Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
                })
            })
            .collect();

        let body = serde_json::json!({
            "deviceUuid": device_uuid,
            "deviceName": device_name,
            "mlsDid": mls_did,
            "signatureKey": base64::engine::general_purpose::STANDARD.encode(signature_key),
            "keyPackages": kps,
        });

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.registerDevice"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("registerDevice: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("registerDevice parse: {e}")))?;

        Ok(DeviceInfo {
            device_id: val["deviceId"]
                .as_str()
                .unwrap_or(device_uuid)
                .to_string(),
            mls_did: mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: Some(Utc::now()),
        })
    }

    async fn list_devices(&self) -> OrcResult<Vec<DeviceInfo>> {
        Ok(vec![])
    }

    async fn remove_device(&self, _device_id: &str) -> OrcResult<()> {
        Ok(())
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> OrcResult<()> {
        let body = serde_json::json!({
            "convoId": convo_id,
            "groupInfo": base64::engine::general_purpose::STANDARD.encode(group_info),
        });
        let _resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mls.updateGroupInfo"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("publishGroupInfo: {e}")))?;
        Ok(())
    }

    async fn get_group_info(&self, convo_id: &str) -> OrcResult<Vec<u8>> {
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.mls.getGroupInfo"))
            .bearer_auth(&self.auth_token)
            .query(&[("convoId", convo_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getGroupInfo: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
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

    async fn get_welcome(&self, convo_id: &str) -> OrcResult<Vec<u8>> {
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.mlsChat.getMessages"))
            .bearer_auth(&self.auth_token)
            .query(&[("convoId", convo_id), ("limit", "100")])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("getWelcome: {e}")))?;

        if !resp.status().is_success() {
            return Err(OrchestratorError::Api("No welcome available".into()));
        }

        // Welcome messages are delivered as part of normal message flow;
        // the orchestrator's join_group handles Welcome processing.
        Err(OrchestratorError::Api(
            "Welcome retrieval via getMessages — use join_group flow".into(),
        ))
    }

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
    ) -> OrcResult<ProcessExternalCommitResult> {
        let mut body = serde_json::json!({
            "convoId": convo_id,
            "commitData": base64::engine::general_purpose::STANDARD.encode(commit_data),
            "changeType": "externalJoin",
        });
        if let Some(gi) = group_info {
            body["groupInfo"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(gi));
        }
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.mlsChat.commitGroupChange"))
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(format!("processExternalCommit: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::ServerError {
                status,
                body,
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OrchestratorError::Api(format!("processExternalCommit parse: {e}")))?;

        Ok(ProcessExternalCommitResult {
            epoch: val["epoch"].as_u64().unwrap_or(0),
            rejoined_at: Utc::now().to_rfc3339(),
            receipt: None,
        })
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

    Some(ConversationView {
        group_id,
        epoch: val["epoch"].as_u64().unwrap_or(0),
        members,
        metadata: None,
        created_at: parse_datetime(val["createdAt"].as_str()),
        updated_at: parse_datetime(val["updatedAt"].as_str()),
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

    Some(IncomingEnvelope {
        conversation_id: convo_id.to_string(),
        sender_did,
        ciphertext,
        timestamp,
        server_message_id,
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

    // Create temp dir for MLS database
    let temp_dir = std::env::temp_dir().join(format!(
        "echo_bot_mls_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    ));
    std::fs::create_dir_all(&temp_dir)?;
    let db_path = temp_dir.join("echo-bot.db");

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
    let storage = BotStorage::new();
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
    orchestrator.initialize(&args.bot_did).await.map_err(|e| {
        format!("Failed to initialize orchestrator: {e}")
    })?;

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
    let cursors: Arc<Mutex<HashMap<String, Option<String>>>> =
        Arc::new(Mutex::new(HashMap::new()));

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
                        .fetch_messages(convo_id, cursor.as_deref(), 50)
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

    // Cleanup temp directory
    let _ = std::fs::remove_dir_all(&temp_dir);
    info!("Echo bot stopped");
    Ok(())
}
