//! Mock implementation of `MLSAPIClient` for testing the MLS orchestrator.
//!
//! Simulates the delivery service in-memory so multiple `MLSOrchestrator`
//! instances can share the same mock server via `Arc`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use catbird_mls::orchestrator::{
    error::{OrchestratorError, Result},
    types::*,
    MLSAPIClient,
};

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StoredMessage {
    id: String,
    conversation_id: String,
    sender_did: String,
    ciphertext: Vec<u8>,
    timestamp: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct StoredConversation {
    view: ConversationView,
    members: Vec<String>,
}

#[derive(Debug, Clone)]
struct StoredKeyPackage {
    data: Vec<u8>,
    cipher_suite: String,
    expires_at: String,
}

#[derive(Debug, Clone)]
struct StoredDevice {
    info: DeviceInfo,
}

#[derive(Debug, Default)]
struct FailureFlags {
    fail_next_send: bool,
    fail_next_create: bool,
    fail_next_get_messages: bool,
    fail_next_get_group_info: bool,
    fail_next_get_key_packages: bool,
    fail_next_add_members: bool,
    fail_next_remove_members: bool,
    fail_next_publish_key_package: bool,
    fail_next_register_device: bool,
    fail_next_get_conversations: bool,
    /// When > 0, fail the next N get_conversations calls.
    fail_get_conversations_count: u32,
    /// When true, next add_members returns success=false (server rejection).
    reject_next_add_members: bool,
}

#[derive(Debug, Default)]
struct MockState {
    /// The DID this client is authenticated as.
    authenticated_did: Option<String>,

    /// Conversations by ID.
    conversations: HashMap<String, StoredConversation>,

    /// Messages per conversation, in insertion order.
    messages: HashMap<String, Vec<StoredMessage>>,

    /// Key packages per DID (consumed FIFO by `get_key_packages`).
    key_packages: HashMap<String, Vec<StoredKeyPackage>>,

    /// Devices per DID.
    devices: HashMap<String, Vec<StoredDevice>>,

    /// Group info blobs by conversation ID.
    group_infos: HashMap<String, Vec<u8>>,
    /// Number of get_group_info calls per conversation.
    get_group_info_calls: HashMap<String, u32>,
    /// Number of external commits processed per conversation.
    external_commit_counts: HashMap<String, u32>,
    /// Artificial delay for process_external_commit (used by concurrency tests).
    process_external_commit_delay_ms: u64,

    /// Failure injection flags.
    failures: FailureFlags,
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

/// A mock delivery service that implements `MLSAPIClient` entirely in memory.
///
/// Wrap in `Arc` and share across orchestrator instances to simulate a real
/// server where all participants see the same state.
#[derive(Debug, Clone)]
pub struct MockDeliveryService {
    state: Arc<Mutex<MockState>>,
    /// Per-instance DID override (allows multiple clients to share one mock server).
    instance_did: Option<String>,
}

impl MockDeliveryService {
    /// Create a new mock service with the given DID pre-authenticated.
    pub fn new(authenticated_did: &str) -> Self {
        let state = MockState {
            authenticated_did: Some(authenticated_did.to_string()),
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            instance_did: None,
        }
    }

    /// Create a new mock that shares the same backing state but is
    /// authenticated as a different DID.
    pub fn clone_as(&self, did: &str) -> Self {
        MockDeliveryService {
            state: Arc::clone(&self.state),
            instance_did: Some(did.to_string()),
        }
    }

    /// Get the effective DID for this instance.
    fn effective_did_from_guard(&self, guard: &MockState) -> Option<String> {
        if let Some(ref did) = self.instance_did {
            Some(did.clone())
        } else {
            guard.authenticated_did.clone()
        }
    }

    // -- failure injection ----------------------------------------------------

    pub fn fail_next_send(&self) {
        self.state.lock().unwrap().failures.fail_next_send = true;
    }

    pub fn fail_next_create(&self) {
        self.state.lock().unwrap().failures.fail_next_create = true;
    }

    pub fn fail_next_get_messages(&self) {
        self.state.lock().unwrap().failures.fail_next_get_messages = true;
    }

    pub fn fail_next_get_group_info(&self) {
        self.state.lock().unwrap().failures.fail_next_get_group_info = true;
    }

    pub fn fail_next_get_key_packages(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_next_get_key_packages = true;
    }

    pub fn fail_next_add_members(&self) {
        self.state.lock().unwrap().failures.fail_next_add_members = true;
    }

    pub fn fail_next_remove_members(&self) {
        self.state.lock().unwrap().failures.fail_next_remove_members = true;
    }

    pub fn fail_next_publish_key_package(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_next_publish_key_package = true;
    }

    pub fn fail_next_register_device(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_next_register_device = true;
    }

    pub fn fail_next_get_conversations(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_next_get_conversations = true;
    }

    /// Make the next `n` get_conversations calls fail.
    pub fn fail_get_conversations_n_times(&self, n: u32) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_get_conversations_count = n;
    }

    /// Make the next add_members call return success=false (server rejection).
    pub fn reject_next_add_members(&self) {
        self.state.lock().unwrap().failures.reject_next_add_members = true;
    }

    // -- introspection --------------------------------------------------------

    /// Number of messages stored for a conversation.
    pub fn message_count(&self, convo_id: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .messages
            .get(convo_id)
            .map_or(0, |v| v.len())
    }

    /// Number of unconsumed key packages for a DID.
    pub fn key_package_count(&self, did: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .key_packages
            .get(did)
            .map_or(0, |v| v.len())
    }

    /// List all conversation IDs.
    pub fn conversation_ids(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .conversations
            .keys()
            .cloned()
            .collect()
    }

    /// Members of a conversation.
    pub fn members_of(&self, convo_id: &str) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .conversations
            .get(convo_id)
            .map_or_else(Vec::new, |c| c.members.clone())
    }

    /// Number of external commits processed for a conversation.
    pub fn external_commit_count(&self, convo_id: &str) -> u32 {
        self.state
            .lock()
            .unwrap()
            .external_commit_counts
            .get(convo_id)
            .copied()
            .unwrap_or(0)
    }

    /// Number of get_group_info calls for a conversation.
    pub fn get_group_info_call_count(&self, convo_id: &str) -> u32 {
        self.state
            .lock()
            .unwrap()
            .get_group_info_calls
            .get(convo_id)
            .copied()
            .unwrap_or(0)
    }

    /// Set an artificial delay for `process_external_commit`.
    pub fn set_process_external_commit_delay_ms(&self, delay_ms: u64) {
        self.state.lock().unwrap().process_external_commit_delay_ms = delay_ms;
    }
}

// ---------------------------------------------------------------------------
// Helper: check & clear a failure flag
// ---------------------------------------------------------------------------

fn check_fail(flag: &mut bool, msg: &str) -> Result<()> {
    if *flag {
        *flag = false;
        Err(OrchestratorError::Api(msg.to_string()))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MLSAPIClient implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl MLSAPIClient for MockDeliveryService {
    // -- Authentication ------------------------------------------------------

    async fn is_authenticated_as(&self, did: &str) -> bool {
        let guard = self.state.lock().unwrap();
        self.effective_did_from_guard(&guard).as_deref() == Some(did)
    }

    async fn current_did(&self) -> Option<String> {
        let guard = self.state.lock().unwrap();
        self.effective_did_from_guard(&guard)
    }

    // -- Conversations -------------------------------------------------------

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_get_conversations,
            "injected get_conversations failure",
        )?;
        if guard.failures.fail_get_conversations_count > 0 {
            guard.failures.fail_get_conversations_count -= 1;
            return Err(OrchestratorError::Api(
                "injected get_conversations failure (counted)".to_string(),
            ));
        }
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        // Return conversations where the authenticated DID is a member.
        let mut all: Vec<ConversationView> = guard
            .conversations
            .values()
            .filter(|c| c.members.contains(&did))
            .map(|c| c.view.clone())
            .collect();
        all.sort_by_key(|c| c.created_at);

        // Cursor-based pagination: cursor is the index (stringified).
        let start = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
        let end = (start + limit as usize).min(all.len());
        let page = all[start..end].to_vec();
        let next_cursor = if end < all.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok(ConversationListPage {
            conversations: page,
            cursor: next_cursor,
        })
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_create,
            "injected create failure",
        )?;

        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let now = Utc::now();
        let mut members = vec![did.clone()];
        if let Some(extra) = initial_members {
            for m in extra {
                if !members.contains(m) {
                    members.push(m.clone());
                }
            }
        }

        let member_views: Vec<MemberView> = members
            .iter()
            .enumerate()
            .map(|(i, d)| MemberView {
                did: d.clone(),
                role: if i == 0 {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect();

        let view = ConversationView {
            group_id: group_id.to_string(),
            epoch: 1,
            members: member_views,
            metadata: metadata.cloned(),
            created_at: Some(now),
            updated_at: Some(now),
        };

        let stored = StoredConversation {
            view: view.clone(),
            members: members.clone(),
        };

        guard.conversations.insert(group_id.to_string(), stored);
        guard.messages.entry(group_id.to_string()).or_default();

        Ok(CreateConversationResult {
            conversation: view,
            commit_data: commit_data.map(|d| d.to_vec()),
            welcome_data: welcome_data.map(|d| d.to_vec()),
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let convo = guard
            .conversations
            .get_mut(convo_id)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;
        convo.members.retain(|m| m != &did);
        convo.view.members.retain(|m| m.did != did);
        Ok(())
    }

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        _commit_data: &[u8],
        _welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_add_members,
            "injected add_members failure",
        )?;

        // Server rejection: return success=false without modifying state
        if guard.failures.reject_next_add_members {
            guard.failures.reject_next_add_members = false;
            let convo = guard
                .conversations
                .get(convo_id)
                .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;
            return Ok(AddMembersServerResult {
                success: false,
                new_epoch: convo.view.epoch,
                receipt: None,
            });
        }

        let convo = guard
            .conversations
            .get_mut(convo_id)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;

        for did in member_dids {
            if !convo.members.contains(did) {
                convo.members.push(did.clone());
                convo.view.members.push(MemberView {
                    did: did.clone(),
                    role: MemberRole::Member,
                });
            }
        }
        convo.view.epoch += 1;
        let new_epoch = convo.view.epoch;

        Ok(AddMembersServerResult {
            success: true,
            new_epoch,
            receipt: None,
        })
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        _commit_data: &[u8],
    ) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_remove_members,
            "injected remove_members failure",
        )?;

        let convo = guard
            .conversations
            .get_mut(convo_id)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;

        for did in member_dids {
            convo.members.retain(|m| m != did);
            convo.view.members.retain(|m| m.did != *did);
        }
        convo.view.epoch += 1;
        Ok(())
    }

    // -- Messages ------------------------------------------------------------

    async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        _epoch: u64,
    ) -> Result<SendMessageResponse> {
        let mut guard = self.state.lock().unwrap();
        check_fail(&mut guard.failures.fail_next_send, "injected send failure")?;

        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        if !guard.conversations.contains_key(convo_id) {
            return Err(OrchestratorError::ConversationNotFound(
                convo_id.to_string(),
            ));
        }

        let msg_id = Uuid::new_v4().to_string();
        let msg = StoredMessage {
            id: msg_id.clone(),
            conversation_id: convo_id.to_string(),
            sender_did: did,
            ciphertext: ciphertext.to_vec(),
            timestamp: Utc::now(),
        };

        guard
            .messages
            .entry(convo_id.to_string())
            .or_default()
            .push(msg);

        Ok(SendMessageResponse {
            message_id: msg_id,
            seq: 1,
            epoch: _epoch,
        })
    }

    async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        _epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let mut guard = self.state.lock().unwrap();
        check_fail(&mut guard.failures.fail_next_send, "injected send failure")?;

        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        if !guard.conversations.contains_key(convo_id) {
            return Err(OrchestratorError::ConversationNotFound(
                convo_id.to_string(),
            ));
        }

        let msg = StoredMessage {
            id: msg_id.to_string(),
            conversation_id: convo_id.to_string(),
            sender_did: did,
            ciphertext: ciphertext.to_vec(),
            timestamp: Utc::now(),
        };

        guard
            .messages
            .entry(convo_id.to_string())
            .or_default()
            .push(msg);

        Ok(SendMessageResponse {
            message_id: msg_id.to_string(),
            seq: 1,
            epoch: _epoch,
        })
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        _message_type: Option<&str>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_get_messages,
            "injected get_messages failure",
        )?;

        let messages = guard.messages.get(convo_id).cloned().unwrap_or_default();

        // Cursor is a 0-based index encoded as string.
        let start = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
        let end = (start + limit as usize).min(messages.len());
        let page: Vec<IncomingEnvelope> = messages[start..end]
            .iter()
            .map(|m| IncomingEnvelope {
                conversation_id: m.conversation_id.clone(),
                sender_did: m.sender_did.clone(),
                ciphertext: m.ciphertext.clone(),
                timestamp: m.timestamp,
                server_message_id: Some(m.id.clone()),
            })
            .collect();

        let next_cursor = if end < messages.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok((page, next_cursor))
    }

    // -- Key Packages --------------------------------------------------------

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_publish_key_package,
            "injected publish_key_package failure",
        )?;

        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        guard
            .key_packages
            .entry(did)
            .or_default()
            .push(StoredKeyPackage {
                data: key_package.to_vec(),
                cipher_suite: cipher_suite.to_string(),
                expires_at: expires_at.to_string(),
            });

        Ok(())
    }

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_get_key_packages,
            "injected get_key_packages failure",
        )?;

        let mut result = Vec::new();
        for did in dids {
            if let Some(packages) = guard.key_packages.get_mut(did) {
                if let Some(pkg) = packages.first().cloned() {
                    // Consume FIFO — remove the first element.
                    packages.remove(0);
                    result.push(KeyPackageRef {
                        did: did.clone(),
                        key_package_data: pkg.data,
                        hash: None,
                        cipher_suite: pkg.cipher_suite,
                    });
                }
            }
        }
        Ok(result)
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let available = guard.key_packages.get(&did).map_or(0, |v| v.len() as u32);

        Ok(KeyPackageStats {
            available,
            total: available,
        })
    }

    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        // Simplified: just report zero orphans.
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: local_hashes.len() as u32,
        })
    }

    // -- Devices -------------------------------------------------------------

    async fn register_device(
        &self,
        device_uuid: &str,
        _device_name: &str,
        mls_did: &str,
        _signature_key: &[u8],
        _key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_register_device,
            "injected register_device failure",
        )?;

        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let info = DeviceInfo {
            device_id: Uuid::new_v4().to_string(),
            mls_did: mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: Some(Utc::now()),
        };

        guard
            .devices
            .entry(did)
            .or_default()
            .push(StoredDevice { info: info.clone() });

        Ok(info)
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        Ok(guard.devices.get(&did).map_or_else(Vec::new, |devs| {
            devs.iter().map(|d| d.info.clone()).collect()
        }))
    }

    async fn remove_device(&self, device_id: &str) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        if let Some(devs) = guard.devices.get_mut(&did) {
            devs.retain(|d| d.info.device_id != device_id);
        }
        Ok(())
    }

    // -- Group Info ----------------------------------------------------------

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard
            .group_infos
            .insert(convo_id.to_string(), group_info.to_vec());
        Ok(())
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        *guard
            .get_group_info_calls
            .entry(convo_id.to_string())
            .or_default() += 1;
        check_fail(
            &mut guard.failures.fail_next_get_group_info,
            "injected get_group_info failure",
        )?;
        guard
            .group_infos
            .get(convo_id)
            .cloned()
            .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))
    }

    async fn get_welcome(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::ServerError {
            status: 404,
            body: "welcome not available".to_string(),
        })
    }

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        _group_info: Option<&[u8]>,
    ) -> Result<ProcessExternalCommitResult> {
        let delay_ms = self.state.lock().unwrap().process_external_commit_delay_ms;
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }

        let mut guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let new_epoch = {
            let convo = guard
                .conversations
                .get_mut(convo_id)
                .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;
            convo.view.epoch += 1;
            convo.view.epoch
        };

        *guard
            .external_commit_counts
            .entry(convo_id.to_string())
            .or_default() += 1;

        guard
            .messages
            .entry(convo_id.to_string())
            .or_default()
            .push(StoredMessage {
                id: Uuid::new_v4().to_string(),
                conversation_id: convo_id.to_string(),
                sender_did: did,
                ciphertext: commit_data.to_vec(),
                timestamp: Utc::now(),
            });

        Ok(ProcessExternalCommitResult {
            epoch: new_epoch,
            rejoined_at: Utc::now().to_rfc3339(),
            receipt: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests for the mock itself
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth() {
        let svc = MockDeliveryService::new("did:plc:alice");
        assert!(svc.is_authenticated_as("did:plc:alice").await);
        assert!(!svc.is_authenticated_as("did:plc:bob").await);
        assert_eq!(svc.current_did().await, Some("did:plc:alice".to_string()));
    }

    #[tokio::test]
    async fn test_create_and_list_conversations() {
        let svc = MockDeliveryService::new("did:plc:alice");
        let result = svc
            .create_conversation(
                "group-1",
                Some(&["did:plc:bob".to_string()]),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.conversation.group_id, "group-1");
        assert_eq!(result.conversation.members.len(), 2);

        let page = svc.get_conversations(10, None).await.unwrap();
        assert_eq!(page.conversations.len(), 1);
    }

    #[tokio::test]
    async fn test_send_and_receive_messages() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.create_conversation("conv-1", None, None, None, None)
            .await
            .unwrap();

        svc.send_message("conv-1", b"hello", 0).await.unwrap();
        svc.send_message("conv-1", b"world", 0).await.unwrap();

        let (msgs, cursor) = svc.get_messages("conv-1", None, 10, None).await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(cursor.is_none());
        assert_eq!(msgs[0].ciphertext, b"hello");
    }

    #[tokio::test]
    async fn test_message_pagination() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.create_conversation("conv-1", None, None, None, None)
            .await
            .unwrap();

        for i in 0..5 {
            svc.send_message("conv-1", format!("msg-{i}").as_bytes(), 0)
                .await
                .unwrap();
        }

        let (page1, cursor1) = svc.get_messages("conv-1", None, 2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert!(cursor1.is_some());

        let (page2, cursor2) = svc
            .get_messages("conv-1", cursor1.as_deref(), 2, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_some());

        let (page3, cursor3) = svc
            .get_messages("conv-1", cursor2.as_deref(), 2, None)
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert!(cursor3.is_none());
    }

    #[tokio::test]
    async fn test_key_packages_fifo() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.publish_key_package(b"kp-1", "suite-1", "2099-01-01")
            .await
            .unwrap();
        svc.publish_key_package(b"kp-2", "suite-1", "2099-01-01")
            .await
            .unwrap();

        assert_eq!(svc.key_package_count("did:plc:alice"), 2);

        let refs = svc
            .get_key_packages(&["did:plc:alice".to_string()])
            .await
            .unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].key_package_data, b"kp-1");

        // Second fetch consumes next package
        let refs2 = svc
            .get_key_packages(&["did:plc:alice".to_string()])
            .await
            .unwrap();
        assert_eq!(refs2[0].key_package_data, b"kp-2");

        assert_eq!(svc.key_package_count("did:plc:alice"), 0);
    }

    #[tokio::test]
    async fn test_device_registration() {
        let svc = MockDeliveryService::new("did:plc:alice");
        let info = svc
            .register_device(
                "uuid-1",
                "iPhone",
                "did:plc:alice",
                b"sig-key",
                &[vec![1, 2, 3]],
            )
            .await
            .unwrap();
        assert_eq!(info.mls_did, "did:plc:alice");

        let devices = svc.list_devices().await.unwrap();
        assert_eq!(devices.len(), 1);

        svc.remove_device(&info.device_id).await.unwrap();
        let devices = svc.list_devices().await.unwrap();
        assert_eq!(devices.len(), 0);
    }

    #[tokio::test]
    async fn test_failure_injection() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.create_conversation("conv-1", None, None, None, None)
            .await
            .unwrap();

        svc.fail_next_send();
        let err = svc.send_message("conv-1", b"fail", 0).await;
        assert!(err.is_err());

        // Next call should succeed (flag was cleared)
        svc.send_message("conv-1", b"ok", 0).await.unwrap();
    }

    #[tokio::test]
    async fn test_group_info() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.publish_group_info("conv-1", b"group-info-blob")
            .await
            .unwrap();
        let data = svc.get_group_info("conv-1").await.unwrap();
        assert_eq!(data, b"group-info-blob");
    }

    #[tokio::test]
    async fn test_leave_conversation() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.create_conversation(
            "conv-1",
            Some(&["did:plc:bob".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(svc.members_of("conv-1").len(), 2);
        svc.leave_conversation("conv-1").await.unwrap();
        assert_eq!(svc.members_of("conv-1").len(), 1);
    }

    #[tokio::test]
    async fn test_add_and_remove_members() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.create_conversation("conv-1", None, None, None, None)
            .await
            .unwrap();

        let result = svc
            .add_members("conv-1", &["did:plc:bob".to_string()], b"commit", None)
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(svc.members_of("conv-1").len(), 2);

        svc.remove_members("conv-1", &["did:plc:bob".to_string()], b"commit")
            .await
            .unwrap();
        assert_eq!(svc.members_of("conv-1").len(), 1);
    }
}
