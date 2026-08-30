//! Mock implementation of `MLSAPIClient` for testing the MLS orchestrator.
//!
//! Simulates the delivery service in-memory so multiple `MLSOrchestrator`
//! instances can share the same mock server via `Arc`.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
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
    is_commit: bool,
    epoch: Option<u64>,
}
#[derive(Debug, Clone)]
struct StoredConversation {
    view: ConversationView,
    members: Vec<String>,
    conversation_kind: String,
    metadata_snapshot: Option<serde_json::Value>,
    participants: Option<Vec<serde_json::Value>>,
}

fn conversation_state_json(conversation: &StoredConversation) -> serde_json::Value {
    let participants = conversation.participants.clone().unwrap_or_else(|| {
        conversation
            .members
            .iter()
            .map(|did| {
                serde_json::json!({
                    "userDid": did,
                    "role": "admin",
                    "status": "active"
                })
            })
            .collect()
    });
    let group_id_bytes = hex::decode(&conversation.view.group_id).unwrap_or_else(|_| vec![0u8; 32]);
    let metadata_snapshot = conversation.metadata_snapshot.clone().unwrap_or_else(|| {
        serde_json::json!({
            "metadataVersion": 1,
            "nonce": base64::engine::general_purpose::STANDARD.encode([0u8; 12]),
            "ciphertext": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
        })
    });
    serde_json::json!({
        "conversationKind": conversation.conversation_kind.clone(),
        "coordinates": {
            "conversationId": conversation.view.conversation_id.clone(),
            "groupId": base64::engine::general_purpose::STANDARD.encode(group_id_bytes),
            "epoch": conversation.view.epoch,
            "generation": 0,
            "stateVersion": 0,
            "lifecycle": "active",
            "groupContextHash": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            "confirmationTag": base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        },
        "participants": participants,
        "metadataSnapshot": metadata_snapshot,
        "snapshotSeq": 1
    })
}

#[derive(Debug, Clone)]
struct StoredKeyPackage {
    data: Vec<u8>,
    cipher_suite: String,
    expires_at: String,
    device_id: Option<String>,
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
    /// When true, next get_welcome fails with a generic (non-404) error.
    /// Drives `join_or_rejoin` straight to the External Commit fallback,
    /// bypassing the WelcomeRecoveryDecision policy (which only routes
    /// expected 404/410 welcome misses).
    fail_next_get_welcome: bool,
    fail_next_get_key_packages: bool,
    fail_next_add_members: bool,
    fail_next_remove_members: bool,
    fail_next_publish_key_package: bool,
    fail_next_register_device: bool,
    fail_next_get_conversations: bool,
    fail_next_commit_group_change: bool,
    /// When > 0, fail the next N get_conversations calls.
    fail_get_conversations_count: u32,
    /// When true, next add_members returns success=false (server rejection).
    reject_next_add_members: bool,
    /// When true, next add_members reports success with a stale zero epoch
    /// without applying the commit. Models a stale/idempotent DS ACK.
    no_advance_next_add_members: bool,
}

#[derive(Debug, Default)]
struct MockState {
    /// The DID this client is authenticated as.
    authenticated_did: Option<String>,

    /// Conversations by ID.
    conversations: HashMap<String, StoredConversation>,

    /// Optional stable conversation id returned by the next create. This lets
    /// concurrency tests model servers where stable conversation ids differ
    /// from mutable MLS group ids from the first response onward.
    next_create_conversation_id: Option<String>,

    /// Custom raw GatewayResponse for the next createConversation call.
    next_create_custom_response:
        Option<catbird_mls::orchestrator::canonical_transport::GatewayResponse>,
    /// Custom raw GatewayResponse for the next sendMessage call.
    next_send_custom_response:
        Option<catbird_mls::orchestrator::canonical_transport::GatewayResponse>,
    /// Conversations temporarily omitted from get_conversations, modeling the
    /// visibility gap between createConvo acceptance and list projection.
    hidden_conversation_ids: HashSet<String>,

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
    /// Number of get_welcome calls per conversation.
    get_welcome_calls: HashMap<String, u32>,
    /// Number of external commits processed per conversation.
    external_commit_counts: HashMap<String, u32>,
    /// Number of generic commit submissions per conversation and action.
    commit_group_change_counts: HashMap<(String, String), u32>,
    /// Number of bootstrap_reset_group attempts per conversation.
    bootstrap_reset_group_calls: HashMap<String, u32>,
    /// Whether bootstrap_reset_group returns a successful race-winner result.
    bootstrap_reset_group_succeeds: bool,
    /// After one accepted bootstrap, return authoritative AlreadyBootstrapped
    /// on later retries for the same conversation.
    bootstrap_already_bootstrapped_after_success: bool,
    /// Artificial delay for bootstrap_reset_group concurrency tests.
    bootstrap_reset_group_delay_ms: u64,
    /// Artificial delay for process_external_commit (used by concurrency tests).
    process_external_commit_delay_ms: u64,

    /// Key-package redirects for credential-binding tests (WS-3): when a key
    /// package is requested for the key DID, serve one from the value DID's
    /// pool instead — still labeled with the requested DID. Simulates a
    /// malicious or buggy DS substituting another user's key package.
    key_package_redirects: HashMap<String, String>,

    /// Envelope sender relabels for inbound credential-binding tests (WS-3
    /// stage 2, ADR-009 D4): when `get_messages` serves a stored message
    /// whose sender DID matches the key, the envelope's `sender_did` is
    /// relabeled to the value — the genuine MLS ciphertext is untouched.
    /// Simulates a malicious or buggy DS spoofing the envelope routing hint.
    envelope_sender_relabels: HashMap<String, String>,

    /// When true, `process_external_commit` returns a `SequencerReceipt`
    /// whose commit hash is SHA-256 of the submitted commit bytes
    /// (mirrors the real sequencer). Used by equivocation-detection tests.
    issue_external_commit_receipts: bool,

    /// Idempotency keys passed to `add_members_with_idempotency`, in call
    /// order. The Welcome-reissue responder test asserts the reissue
    /// `request_id` is forwarded here as the addMembers idempotency key.
    add_members_idempotency_keys: Vec<String>,

    /// Leaf recovery inbox items served to GetLeafRecoveryInbox.
    leaf_recovery_inbox_items: Vec<serde_json::Value>,
    /// Conversation control entries served to GetEntries.
    entries: Vec<serde_json::Value>,
    /// Cached `add_members_with_idempotency` results keyed by idempotency key.
    /// A repeat call with an already-seen key replays the cached result WITHOUT
    /// advancing the server epoch — mirroring the DS
    /// `mark_reissue_request_answered_tx` idempotent replay so the responder's
    /// epoch fence discards the duplicate instead of double-advancing.
    idempotent_add_results: HashMap<String, AddMembersServerResult>,

    /// Pending Welcomes per (conversation_id, recipient_did). Delivered FIFO by
    /// `get_welcome` for the currently-authenticated DID. A single Welcome blob
    /// from `add_members` or `create_conversation` typically targets multiple
    /// recipients (the newly added members); we fan it out by storing one copy
    /// per recipient DID.
    welcomes: HashMap<(String, String), Vec<Vec<u8>>>,

    /// Submitted prepared requests
    submitted_prepared_requests:
        Vec<catbird_mls::orchestrator::canonical_transport::PreparedRequest>,
    /// Call count for get_key_packages
    get_key_packages_call_count: usize,

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
    publish_group_info_gate: Arc<Mutex<Option<Arc<PublishGroupInfoGate>>>>,
    get_conversations_gate: Arc<Mutex<Option<Arc<PublishGroupInfoGate>>>>,
    get_messages_gate: Arc<Mutex<Option<Arc<PublishGroupInfoGate>>>>,
    /// Per-instance DID override (allows multiple clients to share one mock server).
    instance_did: Option<String>,
}

#[derive(Debug, Default)]
pub struct PublishGroupInfoGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl PublishGroupInfoGate {
    pub async fn wait_until_reached(&self) {
        self.reached.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
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
            publish_group_info_gate: Arc::new(Mutex::new(None)),
            get_conversations_gate: Arc::new(Mutex::new(None)),
            get_messages_gate: Arc::new(Mutex::new(None)),
            instance_did: None,
        }
    }

    /// Create a new mock that shares the same backing state but is
    /// authenticated as a different DID.
    pub fn clone_as(&self, did: &str) -> Self {
        MockDeliveryService {
            state: Arc::clone(&self.state),
            publish_group_info_gate: Arc::clone(&self.publish_group_info_gate),
            get_conversations_gate: Arc::clone(&self.get_conversations_gate),
            get_messages_gate: Arc::clone(&self.get_messages_gate),
            instance_did: Some(did.to_string()),
        }
    }

    pub fn set_next_create_conversation_id(&self, conversation_id: &str) {
        self.state.lock().unwrap().next_create_conversation_id = Some(conversation_id.to_string());
    }
    pub fn set_next_create_custom_response(&self, status: u16, body: serde_json::Value) {
        self.state.lock().unwrap().next_create_custom_response = Some(
            catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status,
                content_type: Some("application/json".into()),
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
    }
    pub fn set_next_send_custom_response(&self, status: u16, body: serde_json::Value) {
        self.state.lock().unwrap().next_send_custom_response = Some(
            catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status,
                content_type: Some("application/json".into()),
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
    }
    pub fn add_leaf_recovery_inbox_item(&self, item: serde_json::Value) {
        self.state
            .lock()
            .unwrap()
            .leaf_recovery_inbox_items
            .push(item);
    }
    pub fn add_entry(&self, entry: serde_json::Value) {
        self.state.lock().unwrap().entries.push(entry);
    }

    pub fn set_participant_leaf_count(&self, conversation_id: &str, did: &str, leaf_count: u64) {
        let mut state = self.state.lock().unwrap();
        let participant = state
            .conversations
            .get_mut(conversation_id)
            .and_then(|conversation| conversation.participants.as_mut())
            .and_then(|participants| {
                participants.iter_mut().find(|participant| {
                    participant.get("userDid").and_then(|value| value.as_str()) == Some(did)
                })
            })
            .and_then(serde_json::Value::as_object_mut);
        if let Some(participant) = participant {
            participant.insert("leafCount".to_string(), serde_json::json!(leaf_count));
        }
    }

    pub fn set_conversation_hidden_from_list(&self, conversation_id: &str, hidden: bool) {
        let mut state = self.state.lock().unwrap();
        if hidden {
            state
                .hidden_conversation_ids
                .insert(conversation_id.to_string());
        } else {
            state.hidden_conversation_ids.remove(conversation_id);
        }
    }

    pub fn pause_next_publish_group_info(&self) -> Arc<PublishGroupInfoGate> {
        let gate = Arc::new(PublishGroupInfoGate::default());
        *self.publish_group_info_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    pub fn pause_next_get_conversations(&self) -> Arc<PublishGroupInfoGate> {
        let gate = Arc::new(PublishGroupInfoGate::default());
        *self.get_conversations_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    pub fn pause_next_get_messages(&self) -> Arc<PublishGroupInfoGate> {
        let gate = Arc::new(PublishGroupInfoGate::default());
        *self.get_messages_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
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

    pub fn fail_next_get_welcome(&self) {
        self.state.lock().unwrap().failures.fail_next_get_welcome = true;
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

    pub fn fail_next_commit_group_change(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .fail_next_commit_group_change = true;
    }
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

    /// Make the next add_members call return success=true without advancing
    /// the server epoch or changing its roster.
    pub fn no_advance_next_add_members(&self) {
        self.state
            .lock()
            .unwrap()
            .failures
            .no_advance_next_add_members = true;
    }

    /// Force deterministic conversation ordering in pagination tests.
    pub fn set_conversation_created_at_for_test(
        &self,
        convo_id: &str,
        created_at: chrono::DateTime<Utc>,
    ) {
        let mut guard = self.state.lock().unwrap();
        let conversation = guard
            .conversations
            .get_mut(convo_id)
            .unwrap_or_else(|| panic!("conversation {convo_id} not found"));
        conversation.view.created_at = Some(created_at);
    }

    /// Test helper: change the stable conversation ID while preserving the
    /// MLS group ID inside the conversation view.
    /// Append a copy of `(convo_id, from_did)`'s queued Welcome blobs onto
    /// `(convo_id, to_did)`'s queue. Simulates the orphaned-key-package wedge:
    /// the recipient can FETCH a Welcome for the conversation, but it is
    /// sealed to key material their local storage does not hold, so
    /// `process_welcome` fails with `NoMatchingKeyPackage` (a device whose
    /// server-side key packages outlived a local storage wipe).
    pub fn copy_welcome_for_test(&self, convo_id: &str, from_did: &str, to_did: &str) {
        let mut guard = self.state.lock().unwrap();
        let source = guard
            .welcomes
            .get(&(convo_id.to_string(), from_did.to_string()))
            .cloned()
            .unwrap_or_else(|| panic!("no welcome stored for {convo_id}/{from_did}"));
        guard
            .welcomes
            .entry((convo_id.to_string(), to_did.to_string()))
            .or_default()
            .extend(source);
    }

    pub fn rekey_conversation_for_test(&self, old_convo_id: &str, new_convo_id: &str) {
        if old_convo_id == new_convo_id {
            return;
        }

        let mut guard = self.state.lock().unwrap();

        let matched_cid = if guard.conversations.contains_key(old_convo_id) {
            old_convo_id.to_string()
        } else {
            guard
                .conversations
                .iter()
                .find(|(_, c)| c.view.group_id == old_convo_id)
                .map(|(cid, _)| cid.clone())
                .unwrap_or_else(|| old_convo_id.to_string())
        };
        let mut stored = guard
            .conversations
            .remove(&matched_cid)
            .unwrap_or_else(|| panic!("conversation {old_convo_id} not found"));
        stored.view.conversation_id = new_convo_id.to_string();
        guard.conversations.insert(new_convo_id.to_string(), stored);

        let msgs = guard
            .messages
            .remove(old_convo_id)
            .or_else(|| guard.messages.remove(&matched_cid));
        if let Some(mut messages) = msgs {
            for message in &mut messages {
                message.conversation_id = new_convo_id.to_string();
            }
            guard.messages.insert(new_convo_id.to_string(), messages);
        }

        let gi = guard
            .group_infos
            .remove(old_convo_id)
            .or_else(|| guard.group_infos.remove(&matched_cid));
        if let Some(group_info) = gi {
            guard
                .group_infos
                .insert(new_convo_id.to_string(), group_info);
        }

        let welcome_keys: Vec<(String, String)> = guard
            .welcomes
            .keys()
            .filter(|(convo_id, _)| convo_id == old_convo_id)
            .cloned()
            .collect();
        for (convo_id, did) in welcome_keys {
            if let Some(welcomes) = guard.welcomes.remove(&(convo_id, did.clone())) {
                guard
                    .welcomes
                    .insert((new_convo_id.to_string(), did), welcomes);
            }
        }
    }

    /// Test helper: update only the mutable MLS group identifier projected by
    /// the server while retaining the stable conversation identifier.
    pub fn set_conversation_group_id_for_test(&self, convo_id: &str, group_id: &str) {
        let mut guard = self.state.lock().unwrap();
        let stored = guard
            .conversations
            .get_mut(convo_id)
            .unwrap_or_else(|| panic!("conversation {convo_id} not found"));
        stored.view.group_id = group_id.to_string();
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

    /// The server-minted `device_id` of the most recently registered device
    /// for a DID. Like the real delivery service, `register_device` mints its
    /// own id and ignores the client-supplied UUID; device-scoped publishes
    /// must reference this minted id, not the client UUID.
    pub fn latest_registered_device_id(&self, did: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .devices
            .get(did)
            .and_then(|v| v.last())
            .map(|d| d.info.device_id.clone())
    }

    /// The `device_id` captured for every key package published by a DID, in
    /// publish order. Used to assert the orchestrator scopes publishes to the
    /// registered device id.
    pub fn published_device_ids(&self, did: &str) -> Vec<Option<String>> {
        self.state
            .lock()
            .unwrap()
            .key_packages
            .get(did)
            .map(|v| v.iter().map(|kp| kp.device_id.clone()).collect())
            .unwrap_or_default()
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
        let guard = self.state.lock().unwrap();
        guard
            .conversations
            .get(convo_id)
            .map(|c| c.members.clone())
            .or_else(|| {
                guard
                    .conversations
                    .values()
                    .find(|c| c.view.group_id == convo_id)
                    .map(|c| c.members.clone())
            })
            .unwrap_or_default()
    }

    /// Server-side epoch of a conversation, if it exists.
    pub fn conversation_epoch(&self, convo_id: &str) -> Option<u64> {
        let guard = self.state.lock().unwrap();
        guard
            .conversations
            .get(convo_id)
            .map(|c| c.view.epoch)
            .or_else(|| {
                guard
                    .conversations
                    .values()
                    .find(|c| c.view.group_id == convo_id)
                    .map(|c| c.view.epoch)
            })
    }

    /// Force the server-side epoch of a conversation (stale-needs_rejoin
    /// tests where the local group must be >= the server listing epoch).
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn set_conversation_epoch_for_test(&self, convo_id: &str, epoch: u64) {
        let mut guard = self.state.lock().unwrap();
        if let Some(c) = guard.conversations.get_mut(convo_id) {
            c.view.epoch = epoch;
        } else if let Some(c) = guard
            .conversations
            .values_mut()
            .find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id)
        {
            c.view.epoch = epoch;
        }
    }
    #[allow(dead_code)]
    pub fn update_conversation_metadata_snapshot_for_test(
        &self,
        convo_id: &str,
        snapshot: serde_json::Value,
    ) {
        let mut guard = self.state.lock().unwrap();
        if let Some(c) = guard.conversations.get_mut(convo_id) {
            c.metadata_snapshot = Some(snapshot);
        } else if let Some(c) = guard
            .conversations
            .values_mut()
            .find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id)
        {
            c.metadata_snapshot = Some(snapshot);
        }
    }

    /// Force the server-side `sequencerDid` of a conversation (WS-4 rung 2
    /// exposure tests; ADR-010 D4).
    #[allow(dead_code)]
    pub fn set_conversation_sequencer_for_test(
        &self,
        convo_id: &str,
        sequencer_did: Option<String>,
    ) {
        let mut guard = self.state.lock().unwrap();
        if let Some(c) = guard.conversations.get_mut(convo_id) {
            c.view.sequencer_did = sequencer_did;
        }
    }

    /// Remove a conversation server-side (simulates deletion / membership
    /// loss so sync's stale-conversation cleanup fires).
    pub fn remove_conversation_for_test(&self, convo_id: &str) {
        let mut guard = self.state.lock().unwrap();
        guard.conversations.remove(convo_id);
        guard.messages.remove(convo_id);
        guard.group_infos.remove(convo_id);
    }

    /// Idempotency keys captured from `add_members_with_idempotency` calls, in
    /// call order. Used by the Welcome-reissue responder test to assert the
    /// reissue `request_id` is forwarded as the addMembers idempotency key.
    pub fn add_members_idempotency_keys(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .add_members_idempotency_keys
            .clone()
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

    pub fn commit_group_change_count(&self, convo_id: &str, action: &str) -> u32 {
        self.state
            .lock()
            .unwrap()
            .commit_group_change_counts
            .get(&(convo_id.to_string(), action.to_string()))
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

    /// Number of Welcome fetches for a conversation.
    pub fn welcome_fetch_count(&self, convo_id: &str) -> u32 {
        self.state
            .lock()
            .unwrap()
            .get_welcome_calls
            .get(convo_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn bootstrap_reset_group_call_count(&self, convo_id: &str) -> u32 {
        self.state
            .lock()
            .unwrap()
            .bootstrap_reset_group_calls
            .get(convo_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn set_bootstrap_reset_group_success(&self, succeeds: bool) {
        self.state.lock().unwrap().bootstrap_reset_group_succeeds = succeeds;
    }

    pub fn set_bootstrap_already_bootstrapped_after_success(&self, enabled: bool) {
        self.state
            .lock()
            .unwrap()
            .bootstrap_already_bootstrapped_after_success = enabled;
    }

    pub fn set_bootstrap_reset_group_delay_ms(&self, delay_ms: u64) {
        self.state.lock().unwrap().bootstrap_reset_group_delay_ms = delay_ms;
    }

    pub fn clear_group_info_for_test(&self, convo_id: &str) {
        self.state.lock().unwrap().group_infos.remove(convo_id);
    }

    /// Set an artificial delay for `process_external_commit`.
    pub fn set_process_external_commit_delay_ms(&self, delay_ms: u64) {
        self.state.lock().unwrap().process_external_commit_delay_ms = delay_ms;
    }

    /// WS-3 credential-binding tests: serve key packages from
    /// `serve_from_did`'s pool whenever `requested_did`'s packages are
    /// fetched, still labeling the result with `requested_did`. Simulates a
    /// malicious DS substituting another user's key package.
    pub fn redirect_key_packages_for_test(&self, requested_did: &str, serve_from_did: &str) {
        self.state
            .lock()
            .unwrap()
            .key_package_redirects
            .insert(requested_did.to_string(), serve_from_did.to_string());
    }

    /// WS-3 equivocation tests: make `process_external_commit` return a
    /// `SequencerReceipt` over the submitted commit (hash = SHA-256 of the
    /// commit bytes), as the real sequencer does.
    pub fn issue_external_commit_receipts_for_test(&self, enabled: bool) {
        self.state.lock().unwrap().issue_external_commit_receipts = enabled;
    }

    /// WS-3 stage-2 inbound credential-binding tests (ADR-009 D4): relabel
    /// the envelope `sender_did` of every stored message actually sent by
    /// `actual_sender_did` to `spoofed_sender_did` when served through
    /// `get_messages`. The MLS ciphertext is untouched — only the envelope
    /// routing hint lies, which is exactly the spoof a malicious DS can
    /// perform without breaking MLS decryption.
    pub fn relabel_envelope_sender_for_test(
        &self,
        actual_sender_did: &str,
        spoofed_sender_did: &str,
    ) {
        self.state.lock().unwrap().envelope_sender_relabels.insert(
            actual_sender_did.to_string(),
            spoofed_sender_did.to_string(),
        );
    }
    pub fn submitted_prepared_requests(
        &self,
    ) -> Vec<catbird_mls::orchestrator::canonical_transport::PreparedRequest> {
        self.state
            .lock()
            .unwrap()
            .submitted_prepared_requests
            .clone()
    }

    pub fn get_key_packages_call_count(&self) -> usize {
        self.state.lock().unwrap().get_key_packages_call_count
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

impl MockDeliveryService {
    pub async fn create_conversation(
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

        let conversation_id = guard
            .next_create_conversation_id
            .take()
            .unwrap_or_else(|| group_id.to_string());
        let view = ConversationView {
            group_id: group_id.to_string(),
            conversation_id: conversation_id.clone(),
            // A fresh creator-only MLS group is epoch 0. createConvo reaches
            // epoch 1 only when it atomically accepts the optional bootstrap
            // Add commit supplied below.
            epoch: u64::from(commit_data.is_some()),
            members: member_views,
            metadata: metadata.cloned(),
            created_at: Some(now),
            updated_at: Some(now),
            sequencer_did: None,
        };

        let conversation_kind = "group".to_string();
        let stored = StoredConversation {
            view: view.clone(),
            members: members.clone(),
            conversation_kind,
            metadata_snapshot: None,
            participants: None,
        };

        guard.conversations.insert(conversation_id.clone(), stored);
        guard.messages.entry(conversation_id.clone()).or_default();
        // Fan out the Welcome (if provided) to each initial member so they can
        // later pull it via `get_welcome`. Also store the commit as a message
        // so existing members (not relevant at creation time, but kept for
        // symmetry with `add_members`) can observe the epoch-advancing commit.
        if let Some(w) = welcome_data {
            if let Some(extra) = initial_members {
                for recipient in extra {
                    guard
                        .welcomes
                        .entry((conversation_id.clone(), recipient.clone()))
                        .or_default()
                        .push(w.to_vec());
                }
            }
        }
        if let Some(c) = commit_data {
            let msg = StoredMessage {
                id: Uuid::new_v4().to_string(),
                conversation_id: conversation_id.clone(),
                sender_did: did.clone(),
                ciphertext: c.to_vec(),
                timestamp: Utc::now(),
                is_commit: true,
                epoch: Some(0),
            };
            guard.messages.entry(conversation_id).or_default().push(msg);
        }

        Ok(CreateConversationResult {
            conversation: view,
            commit_data: commit_data.map(|d| d.to_vec()),
            welcome_data: welcome_data.map(|d| d.to_vec()),
        })
    }

    pub async fn bootstrap_reset_group(
        &self,
        original_convo_id: &str,
        new_group_id: &str,
        _cipher_suite: &str,
        group_info: &[u8],
        _members: &[String],
        _welcome_message: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let delay_ms = self.state.lock().unwrap().bootstrap_reset_group_delay_ms;
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let mut guard = self.state.lock().unwrap();
        let calls = guard
            .bootstrap_reset_group_calls
            .entry(original_convo_id.to_string())
            .or_default();
        *calls += 1;
        let call_number = *calls;
        if guard.bootstrap_already_bootstrapped_after_success && call_number > 1 {
            return Err(OrchestratorError::ServerError {
                status: 409,
                body: r#"{"error":"AlreadyBootstrapped"}"#.to_string(),
            });
        }
        if guard.bootstrap_reset_group_succeeds {
            let stored = guard
                .conversations
                .get_mut(original_convo_id)
                .ok_or_else(|| {
                    OrchestratorError::ConversationNotFound(original_convo_id.to_string())
                })?;
            stored.view.group_id = new_group_id.to_string();
            let conversation = stored.view.clone();
            guard
                .group_infos
                .insert(original_convo_id.to_string(), group_info.to_vec());
            Ok(CreateConversationResult {
                conversation,
                commit_data: None,
                welcome_data: None,
            })
        } else {
            Err(OrchestratorError::Api(
                "bootstrap_reset_group not implemented".to_string(),
            ))
        }
    }

    pub async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let convo = guard
            .conversations
            .get_mut(convo_id)
            .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;
        convo
            .members
            .retain(|m| m != &did && !m.starts_with(&format!("{did}#")));
        convo
            .view
            .members
            .retain(|m| m.did != did && !m.did.starts_with(&format!("{did}#")));
        Ok(())
    }

    pub async fn commit_group_change(
        &self,
        convo_id: &str,
        _commit_data: &[u8],
        action: &str,
        _confirmation_tag: Option<&str>,
    ) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_commit_group_change,
            "injected commit_group_change failure",
        )?;
        *guard
            .commit_group_change_counts
            .entry((convo_id.to_string(), action.to_string()))
            .or_default() += 1;
        Ok(())
    }

    pub async fn put_group_metadata_blob(
        &self,
        _convo_id: &str,
        _group_id_hex: &str,
        _blob_locator: &str,
        _ciphertext: &[u8],
        _kind: &str,
        _metadata_version: u64,
        _reset_generation: Option<i32>,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
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

        if guard.failures.no_advance_next_add_members {
            guard.failures.no_advance_next_add_members = false;
            guard
                .conversations
                .get(convo_id)
                .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))?;
            return Ok(AddMembersServerResult {
                success: true,
                new_epoch: 0,
                receipt: None,
            });
        }

        let sender_did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let convo = if guard.conversations.contains_key(convo_id) {
            guard.conversations.get_mut(convo_id)
        } else {
            guard
                .conversations
                .values_mut()
                .find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id)
        }
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

        // Distribute the commit to all members by storing it in the message
        // log — a real DS fans the commit out to every member so they can
        // advance their local MLS epoch. `process_incoming` on the sender
        // side deduplicates via the `own_commits` SHA-256 set.
        let commit_msg = StoredMessage {
            id: Uuid::new_v4().to_string(),
            conversation_id: convo_id.to_string(),
            sender_did: sender_did.clone(),
            ciphertext: commit_data.to_vec(),
            timestamp: Utc::now(),
            is_commit: true,
            epoch: Some(new_epoch),
        };
        guard
            .messages
            .entry(convo_id.to_string())
            .or_default()
            .push(commit_msg);

        // Fan out the Welcome (if provided) to each newly added member. A real
        // DS delivers Welcomes out-of-band; we queue them per (convo_id, DID)
        // and `get_welcome` pops the next one for the authenticated DID.
        if let Some(w) = welcome_data {
            for did in member_dids {
                guard
                    .welcomes
                    .entry((convo_id.to_string(), did.clone()))
                    .or_default()
                    .push(w.to_vec());
            }
        }

        Ok(AddMembersServerResult {
            success: true,
            new_epoch,
            receipt: None,
        })
    }

    pub async fn add_members_with_idempotency(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
        idempotency_key: &str,
    ) -> Result<AddMembersServerResult> {
        // Record the key, then replay idempotently. A repeat call with a key
        // we've already answered returns the cached result WITHOUT advancing
        // the server epoch (mirrors the DS marking the reissue request
        // answered). The guard is dropped before delegating to `add_members`
        // so we don't deadlock re-locking the mutex.
        {
            let mut guard = self.state.lock().unwrap();
            guard
                .add_members_idempotency_keys
                .push(idempotency_key.to_string());
            if let Some(cached) = guard.idempotent_add_results.get(idempotency_key) {
                return Ok(cached.clone());
            }
        }

        let result = self
            .add_members(convo_id, member_dids, commit_data, welcome_data)
            .await?;

        self.state
            .lock()
            .unwrap()
            .idempotent_add_results
            .insert(idempotency_key.to_string(), result.clone());
        Ok(result)
    }

    pub async fn remove_members(
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

    pub async fn send_message(
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
            is_commit: false,
            epoch: Some(_epoch),
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

    pub async fn send_message_with_id(
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

        let is_commit = msg_id.contains("commit") || _epoch > 0;
        let msg = StoredMessage {
            id: msg_id.to_string(),
            conversation_id: convo_id.to_string(),
            sender_did: did,
            ciphertext: ciphertext.to_vec(),
            timestamp: Utc::now(),
            is_commit,
            epoch: Some(_epoch),
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

    // -- Key Packages --------------------------------------------------------

    pub async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
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
                device_id: device_id.map(str::to_string),
            });

        Ok(())
    }

    pub async fn publish_key_packages(
        &self,
        key_packages: &[Vec<u8>],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
    ) -> Result<()> {
        for kp in key_packages {
            self.publish_key_package(kp, cipher_suite, expires_at, device_id)
                .await?;
        }
        Ok(())
    }

    // -- Devices -------------------------------------------------------------

    pub async fn register_device(
        &self,
        device_uuid: &str,
        _device_name: &str,
        mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
        _prepared_request_body: &[u8],
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
            device_id: device_uuid.to_string(),
            mls_did: mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: Some(Utc::now()),
            key_id: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(signature_key))),
            signature_public_key: Some(signature_key.to_vec()),
            auth_generation: Some(1),
            status: Some("active".into()),
            available_package_count: Some(key_packages.len() as u32),
            reserved_package_count: Some(0),
        };

        guard
            .devices
            .entry(did)
            .or_default()
            .push(StoredDevice { info: info.clone() });

        Ok(info)
    }

    pub async fn remove_device(&self, device_id: &str) -> Result<()> {
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

    pub async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        {
            let mut guard = self.state.lock().unwrap();
            guard
                .group_infos
                .insert(convo_id.to_string(), group_info.to_vec());
        }
        let gate = self.publish_group_info_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
        Ok(())
    }

    pub async fn request_welcome_reissue(
        &self,
        convo_id: &str,
        recipient_device_did: &str,
        reason: &str,
    ) -> Result<catbird_mls::orchestrator::welcome_recovery::WelcomeReissueRequestResult> {
        let _ = (convo_id, recipient_device_did, reason);
        Err(OrchestratorError::Api("not implemented".into()))
    }

    pub async fn request_failover(&self, convo_id: &str) -> Result<RequestFailoverResponse> {
        let _ = convo_id;
        Err(OrchestratorError::Api("not implemented".into()))
    }

    pub async fn report_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
        let _ = (convo_id, failure_type, epoch_authenticator, failure_mode);
        Ok(())
    }

    pub async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        _group_info: Option<&[u8]>,
        _confirmation_tag: Option<&str>,
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
                is_commit: true,
                epoch: Some(new_epoch),
            });
        // WS-3 equivocation tests: optionally issue a receipt over the
        // commit, mirroring the real sequencer's receipt shape.
        let receipt = if guard.issue_external_commit_receipts {
            use sha2::{Digest, Sha256};
            Some(SequencerReceipt {
                convo_id: convo_id.to_string(),
                epoch: new_epoch as i32,
                sequencer_term: 0,
                commit_hash: Sha256::digest(commit_data).to_vec(),
                sequencer_did: "did:web:sequencer.test".to_string(),
                issued_at: Utc::now().timestamp(),
                signature: vec![],
            })
        } else {
            None
        };

        Ok(ProcessExternalCommitResult {
            epoch: new_epoch,
            rejoined_at: Utc::now().to_rfc3339(),
            receipt,
        })
    }
}

#[async_trait]
impl MLSAPIClient for MockDeliveryService {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        let guard = self.state.lock().unwrap();
        self.effective_did_from_guard(&guard).as_deref() == Some(did)
    }

    async fn current_did(&self) -> Option<String> {
        let guard = self.state.lock().unwrap();
        self.effective_did_from_guard(&guard)
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        {
            let mut guard = self.state.lock().unwrap();
            guard
                .group_infos
                .insert(convo_id.to_string(), group_info.to_vec());
        }
        let gate = self.publish_group_info_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
        Ok(())
    }

    async fn publish_welcome(&self, convo_id: &str, welcome_data: &[u8]) -> Result<()> {
        let did = self.current_did().await.unwrap_or_default();
        let mut guard = self.state.lock().unwrap();
        let group_id_opt = guard
            .conversations
            .get(convo_id)
            .map(|c| c.view.group_id.clone());
        for (k, _) in guard.key_packages.clone() {
            if k != did {
                guard
                    .welcomes
                    .entry((convo_id.to_string(), k.clone()))
                    .or_default()
                    .push(welcome_data.to_vec());
                if let Some(ref gid) = group_id_opt {
                    guard
                        .welcomes
                        .entry((gid.clone(), k.clone()))
                        .or_default()
                        .push(welcome_data.to_vec());
                }
            }
        }
        Ok(())
    }

    async fn submit_prepared_request(
        &self,
        request: catbird_mls::orchestrator::canonical_transport::PreparedRequest,
    ) -> Result<catbird_mls::orchestrator::canonical_transport::GatewayResponse> {
        self.state
            .lock()
            .unwrap()
            .submitted_prepared_requests
            .push(request.clone());
        let body_bytes = request.body.as_deref().unwrap_or(&[]);
        let body_val: serde_json::Value = if !body_bytes.is_empty()
            && request.operation
                != catbird_mls::orchestrator::canonical_transport::CanonicalOperation::UploadBlob
        {
            serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        };
        let inner_body = body_val
            .get("signedRequest")
            .and_then(|s| s.get("body"))
            .unwrap_or(&body_val);

        match request.operation {
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::CreateConversation => {
                if let Some(resp) = self.state.lock().unwrap().next_create_custom_response.take() {
                    return Ok(resp);
                }
                let group_id = inner_body
                    .get("next")
                    .and_then(|n| n.get("groupId"))
                    .and_then(|g| g.as_str())
                    .or_else(|| inner_body.get("groupId").and_then(|g| g.as_str()))
                    .unwrap_or_default();
                let group_id_str = if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(group_id)
                {
                    hex::encode(bytes)
                } else {
                    group_id.to_string()
                };
                let has_next_id = self.state.lock().unwrap().next_create_conversation_id.is_some();
                if !has_next_id {
                    if let Some(cid) = inner_body.get("conversationId").and_then(|c| c.as_str()) {
                        self.set_next_create_conversation_id(cid);
                    }
                }
                let initial_members: Vec<String> = inner_body
                    .get("manifest")
                    .and_then(|m| m.get("participants"))
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| {
                                p.get("userDid")
                                    .and_then(|u| u.as_str())
                                    .map(|s| s.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let res = self
                    .create_conversation(
                        &group_id_str,
                        Some(&initial_members),
                        None,
                        None,
                        None,
                    )
                    .await?;

                if let Some(gi_b64) = inner_body
                    .get("genesisGroupInfo")
                    .and_then(|g| g.get("bytes"))
                    .and_then(|b| b.as_str())
                {
                    if let Ok(gi_bytes) =
                        base64::engine::general_purpose::STANDARD.decode(gi_b64)
                    {
                        self.state
                            .lock()
                            .unwrap()
                            .group_infos
                            .insert(res.conversation.conversation_id.clone(), gi_bytes);
                    }
                }
                let kind = inner_body
                    .get("conversationKind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("group");
                let manifest_participants = inner_body
                    .get("manifest")
                    .and_then(|m| m.get("participants"))
                    .and_then(|p| p.as_array())
                    .cloned();
                if let Some(stored) = self
                    .state
                    .lock()
                    .unwrap()
                    .conversations
                    .get_mut(&res.conversation.conversation_id)
                {
                    stored.conversation_kind = kind.to_string();
                    stored.metadata_snapshot = inner_body.get("metadataSnapshot").cloned();
                    stored.participants = manifest_participants;
                }
                let participants: Vec<serde_json::Value> = res
                    .conversation
                    .members
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "userDid": m.did,
                            "role": match m.role { MemberRole::Admin => "admin", _ => "member" },
                            "status": "active"
                        })
                    })
                    .collect();
                let group_id_bytes = hex::decode(&res.conversation.group_id)
                    .unwrap_or_else(|_| vec![0u8; 32]);
                let output = serde_json::json!({
                    "result": {
                        "$type": "blue.catbird.chat.defs#conversationCreatedResult",
                        "coordinates": {
                            "conversationId": res.conversation.conversation_id,
                            "groupId": {
                                "$bytes": base64::engine::general_purpose::STANDARD.encode(&group_id_bytes)
                            },
                            "epoch": res.conversation.epoch as i64,
                            "generation": 0,
                            "stateVersion": 0,
                            "lifecycle": "active",
                            "groupContextHash": {
                                "$bytes": base64::engine::general_purpose::STANDARD.encode([0u8; 32])
                            },
                            "confirmationTag": {
                                "$bytes": base64::engine::general_purpose::STANDARD.encode([0u8; 32])
                            }
                        },
                        "entry": {
                            "conversationId": res.conversation.conversation_id,
                            "entryId": uuid::Uuid::new_v4().to_string(),
                            "receivedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                            "seq": 1,
                            "signedRequest": {
                                "body": inner_body,
                                "signature": body_val
                                    .get("signature")
                                    .and_then(|s| s.as_str())
                                    .or_else(|| body_val.get("signedRequest").and_then(|s| s.get("signature")).and_then(|s| s.as_str()))
                                    .unwrap_or(&base64::engine::general_purpose::STANDARD.encode([0u8; 64]))
                            }
                        }
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SendMessage => {
                if let Some(resp) = self.state.lock().unwrap().next_send_custom_response.take() {
                    return Ok(resp);
                }
                let convo_id = inner_body
                    .get("prior")
                    .and_then(|p| p.get("conversationId"))
                    .and_then(|c| c.as_str())
                    .or_else(|| inner_body.get("conversationId").and_then(|c| c.as_str()))
                    .unwrap_or_default();
                let ciphertext_b64 = inner_body
                    .get("applicationMessage")
                    .and_then(|a| a.get("bytes"))
                    .and_then(|b| b.as_str())
                    .unwrap_or_default();
                let ciphertext = base64::engine::general_purpose::STANDARD
                    .decode(ciphertext_b64)
                    .unwrap_or_default();
                let epoch = inner_body
                    .get("prior")
                    .and_then(|p| p.get("epoch"))
                    .and_then(|e| e.as_u64())
                    .unwrap_or(0);
                let message_id = inner_body
                    .get("messageId")
                    .and_then(|m| m.as_str())
                    .unwrap_or_default();

                let mut guard = self.state.lock().unwrap();
                check_fail(&mut guard.failures.fail_next_send, "injected send failure")?;
                let did = self
                    .effective_did_from_guard(&guard)
                    .unwrap_or_else(|| "did:plc:mock".to_string());

                let server_entry_id = if message_id.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    message_id.to_string()
                };
                let msg = StoredMessage {
                    id: server_entry_id.clone(),
                    conversation_id: convo_id.to_string(),
                    sender_did: did,
                    ciphertext,
                    timestamp: Utc::now(),
                    is_commit: false,
                    epoch: Some(epoch),
                };
                guard
                    .messages
                    .entry(convo_id.to_string())
                    .or_default()
                    .push(msg);

                let default_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
                let sig_b64 = body_val
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .or_else(|| body_val.get("signedRequest").and_then(|s| s.get("signature")).and_then(|s| s.as_str()))
                    .unwrap_or(&default_sig);
                let output = serde_json::json!({
                    "entry": {
                        "conversationId": convo_id,
                        "entryId": server_entry_id,
                        "receivedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "seq": 1,
                        "signedRequest": {
                            "body": inner_body,
                            "signature": sig_b64
                        }
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::ReplenishKeyPackages => {
                let packages = inner_body
                    .get("keyPackages")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();
                let device_uuid = inner_body
                    .get("actorDeviceId")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let actor_did = inner_body
                    .get("actorDid")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let mut pkgs = Vec::new();
                for p in &packages {
                    if let Some(bytes_b64) = p.get("bytes").and_then(|b| b.as_str()) {
                        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(bytes_b64) {
                            pkgs.push(b);
                        }
                    }
                }
                let did = if !actor_did.is_empty() {
                    actor_did.to_string()
                } else {
                    self.effective_did_from_guard(&self.state.lock().unwrap())
                        .unwrap_or_default()
                };
                {
                    let mut guard = self.state.lock().unwrap();
                    for pkg in &pkgs {
                        guard.key_packages.entry(did.clone()).or_default().push(StoredKeyPackage {
                            data: pkg.clone(),
                            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                            expires_at: "".to_string(),
                            device_id: Some(device_uuid.to_string()),
                        });
                    }
                }
                let output = serde_json::json!({
                    "result": {
                        "available": pkgs.len() as i64
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::EnrollDevice => {
                let device_uuid = inner_body
                    .get("deviceId")
                    .or_else(|| inner_body.get("actorDeviceId"))
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let actor_did = inner_body
                    .get("actorDid")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let mls_did = format!("{actor_did}#{device_uuid}");
                let sig_pk_b64 = inner_body
                    .get("signaturePublicKey")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();
                let sig_pk = if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(sig_pk_b64)
                {
                    if bytes.len() == 32 {
                        bytes
                    } else {
                        vec![0u8; 32]
                    }
                } else {
                    vec![0u8; 32]
                };
                let key_id = inner_body
                    .get("keyId")
                    .and_then(|k| k.as_str())
                    .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

                let mut pkgs = Vec::new();
                if let Some(packages) = inner_body.get("keyPackages").and_then(|p| p.as_array()) {
                    for p in packages {
                        if let Some(bytes_b64) = p.get("bytes").and_then(|b| b.as_str()) {
                            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(bytes_b64) {
                                pkgs.push(b);
                            }
                        }
                    }
                }
                let info = self
                    .register_device(
                        device_uuid,
                        "Mock Device",
                        &mls_did,
                        &sig_pk,
                        &pkgs,
                        body_bytes,
                    )
                    .await?;
                {
                    let mut guard = self.state.lock().unwrap();
                    for pkg in &pkgs {
                        guard.key_packages.entry(actor_did.to_string()).or_default().push(StoredKeyPackage {
                            data: pkg.clone(),
                            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                            expires_at: "".to_string(),
                            device_id: Some(device_uuid.to_string()),
                        });
                        guard.key_packages.entry(mls_did.clone()).or_default().push(StoredKeyPackage {
                            data: pkg.clone(),
                            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                            expires_at: "".to_string(),
                            device_id: Some(device_uuid.to_string()),
                        });
                    }
                }
                let output = serde_json::json!({
                    "device": {
                        "deviceId": info.device_id,
                        "keyId": key_id,
                        "signaturePublicKey": {
                            "$bytes": base64::engine::general_purpose::STANDARD.encode(&sig_pk)
                        },
                        "authGeneration": 1,
                        "status": "active",
                        "availablePackageCount": 50,
                        "reservedPackageCount": 0,
                        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "updatedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RevokeDevice => {
                let target_device_id = inner_body
                    .get("targetDeviceId")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                self.remove_device(target_device_id).await?;
                let output = serde_json::json!({
                    "result": {
                        "revoked": true
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition => {
                let convo_id = inner_body
                    .get("prior")
                    .and_then(|p| p.get("conversationId"))
                    .or_else(|| inner_body.get("conversationId"))
                    .or_else(|| inner_body.get("aad").and_then(|a| a.get("conversationId")))
                    .and_then(|c| c.as_str())
                    .map(|c| {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(c) {
                            if let Ok(uuid) = uuid::Uuid::from_slice(&bytes) {
                                return uuid.to_string();
                            }
                        }
                        c.to_string()
                    })
                    .unwrap_or_default();
                let delay_ms = self.state.lock().unwrap().process_external_commit_delay_ms;
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let mut guard = self.state.lock().unwrap();
                let idempotency_key = inner_body
                    .get("idempotencyKey")
                    .and_then(|i| i.as_str())
                    .map(|s| s.to_string());
                let recovery_request_id = inner_body
                    .get("recoveryRequestId")
                    .and_then(|r| r.as_str())
                    .map(|s| s.to_string());
                if let Some(idem) = &idempotency_key {
                    guard.add_members_idempotency_keys.push(idem.clone());
                }
                if let Some(req_id) = &recovery_request_id {
                    guard.add_members_idempotency_keys.push(req_id.clone());
                }
                let cached = idempotency_key
                    .as_ref()
                    .and_then(|k| guard.idempotent_add_results.get(k))
                    .or_else(|| {
                        recovery_request_id
                            .as_ref()
                            .and_then(|k| guard.idempotent_add_results.get(k))
                    });
                if let Some(cached) = cached {
                    let output = serde_json::json!({
                        "result": {
                            "applied": true,
                            "epoch": cached.new_epoch,
                            "receipt": cached.receipt
                        }
                    });
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 200,
                        content_type: Some("application/json".into()),
                        body: serde_json::to_vec(&output).unwrap(),
                    });
                }
                check_fail(&mut guard.failures.fail_next_commit_group_change, "injected commit_group_change failure")?;
                check_fail(&mut guard.failures.fail_next_add_members, "injected add_members failure")?;
                check_fail(&mut guard.failures.fail_next_remove_members, "injected remove_members failure")?;
                if guard.failures.reject_next_add_members {
                    guard.failures.reject_next_add_members = false;
                    let output = serde_json::json!({
                        "result": {
                            "applied": false,
                            "epoch": guard.conversations.get(&convo_id).map_or(0, |c| c.view.epoch)
                        }
                    });
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 200,
                        content_type: Some("application/json".into()),
                        body: serde_json::to_vec(&output).unwrap(),
                    });
                }
                if guard.failures.no_advance_next_add_members {
                    guard.failures.no_advance_next_add_members = false;
                    let output = serde_json::json!({
                        "result": {
                            "applied": true,
                            "epoch": 0
                        }
                    });
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 200,
                        content_type: Some("application/json".into()),
                        body: serde_json::to_vec(&output).unwrap(),
                    });
                }
                let did = self
                    .effective_did_from_guard(&guard)
                    .unwrap_or_else(|| "did:plc:mock".to_string());

                let key_pkg_dids: Vec<String> = guard.key_packages.keys().cloned().collect();
                let is_policy_transition = inner_body.get("participantChanges").is_some();
                let mut new_epoch = if let Some(stored) = if guard.conversations.contains_key(&convo_id) {
                    guard.conversations.get(&convo_id)
                } else {
                    guard.conversations.values().find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id)
                } {
                    stored.view.epoch
                } else {
                    0
                };
                if !is_policy_transition {
                    if let Some(stored) = if guard.conversations.contains_key(&convo_id) {
                        guard.conversations.get_mut(&convo_id)
                    } else {
                        guard.conversations.values_mut().find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id)
                    } {
                        stored.view.epoch += 1;
                        new_epoch = stored.view.epoch;
                        if let Some(snapshot) = inner_body.get("metadataSnapshot") {
                            stored.metadata_snapshot = Some(snapshot.clone());
                        }
                        let leaf_changes = inner_body.get("manifest").and_then(|m| m.get("leafChanges")).and_then(|l| l.as_array());
                        if let Some(changes) = leaf_changes.filter(|c| !c.is_empty()) {
                            for change in changes {
                                if let Some(user_did) = change.get("userDid").and_then(|u| u.as_str()) {
                                    stored.members.retain(|m| m != user_did && !m.starts_with(&format!("{user_did}#")));
                                    stored.view.members.retain(|m| m.did != user_did && !m.did.starts_with(&format!("{user_did}#")));
                                }
                            }
                        } else {
                            for k in key_pkg_dids {
                                if !stored.members.contains(&k) {
                                    stored.members.push(k.clone());
                                    stored.view.members.push(MemberView {
                                        did: k,
                                        role: MemberRole::Member,
                                    });
                                }
                            }
                        }
                    }
                }
                let commit_bytes = inner_body
                    .get("commit")
                    .and_then(|c| c.get("bytes"))
                    .and_then(|b| b.as_str())
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .unwrap_or_default();
                let is_commit_transition = inner_body
                    .get("$type")
                    .and_then(|t| t.as_str())
                    .map_or(false, |t| t == "blue.catbird.chat.defs#commitTransitionBody");
                let is_external = is_commit_transition
                    && inner_body
                        .get("next")
                        .and_then(|n| n.get("stateVersion"))
                        .and_then(|v| v.as_i64())
                        .map_or(false, |sv| sv == 0);
                if is_external {
                    *guard.external_commit_counts.entry(convo_id.to_string()).or_default() += 1;
                    let group_id_opt = if let Some(c) = guard.conversations.get(&convo_id) {
                        Some(c.view.group_id.clone())
                    } else {
                        guard.conversations.values().find(|c| c.view.conversation_id == convo_id || c.view.group_id == convo_id).map(|c| c.view.group_id.clone())
                    };
                    if let Some(gid) = group_id_opt {
                        *guard.external_commit_counts.entry(gid).or_default() += 1;
                    }
                }
                if !commit_bytes.is_empty() {
                    guard
                        .messages
                        .entry(convo_id.to_string())
                        .or_default()
                        .push(StoredMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            conversation_id: convo_id.to_string(),
                            sender_did: did.clone(),
                            ciphertext: commit_bytes.clone(),
                            timestamp: Utc::now(),
                            is_commit: true,
                            epoch: None,
                        });
                }
                let welcome_bytes_opt = inner_body
                    .get("manifest")
                    .and_then(|m| m.get("welcomeBundle"))
                    .or_else(|| inner_body.get("welcomeBundle"))
                    .and_then(|w| w.get("opaqueWelcome").or_else(|| w.get("bytes")))
                    .and_then(|b| b.as_str())
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .or_else(|| {
                        inner_body
                            .get("welcomeMessage")
                            .and_then(|w| w.as_str())
                            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    });
                if let Some(w_bytes) = welcome_bytes_opt {
                    let group_id_opt = guard.conversations.get(&convo_id).map(|c| c.view.group_id.clone());
                    for (k, _) in guard.key_packages.clone() {
                        if k != did {
                            guard
                                .welcomes
                                 .entry((convo_id.to_string(), k.clone()))
                                .or_default()
                                .push(w_bytes.clone());
                            if let Some(ref gid) = group_id_opt {
                                guard
                                    .welcomes
                                    .entry((gid.clone(), k.clone()))
                                    .or_default()
                                    .push(w_bytes.clone());
                            }
                        }
                    }
                }
                let receipt = if guard.issue_external_commit_receipts {
                    use sha2::{Digest, Sha256};
                    Some(SequencerReceipt {
                        convo_id: convo_id.to_string(),
                        epoch: new_epoch as i32,
                        sequencer_term: 0,
                        commit_hash: Sha256::digest(&commit_bytes).to_vec(),
                        sequencer_did: "did:web:sequencer.test".to_string(),
                        issued_at: chrono::Utc::now().timestamp(),
                        signature: vec![],
                    })
                } else {
                    None
                };
                let output = serde_json::json!({
                    "result": {
                        "applied": true,
                        "epoch": new_epoch,
                        "receipt": receipt
                    }
                });
                if let Some(idem) = &idempotency_key {
                    guard.idempotent_add_results.insert(idem.clone(), AddMembersServerResult {
                        success: true,
                        new_epoch,
                        receipt: receipt.clone(),
                    });
                }
                if let Some(req_id) = &recovery_request_id {
                    guard.idempotent_add_results.insert(req_id.clone(), AddMembersServerResult {
                        success: true,
                        new_epoch,
                        receipt: receipt.clone(),
                    });
                }
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestLeave => {
                let convo_id = inner_body
                    .get("prior")
                    .and_then(|p| p.get("conversationId"))
                    .or_else(|| inner_body.get("conversationId"))
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                self.leave_conversation(convo_id).await?;
                let output = serde_json::json!({
                    "result": {
                        "left": true
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::PrepareBlobUpload => {
                let output = serde_json::json!({
                    "result": {
                        "uploadUrl": "/upload"
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::UploadBlob => {
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({"result": {"uploaded": true}})).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::AcceptConversation => {
                let convo_id = inner_body
                    .get("prior")
                    .and_then(|p| p.get("conversationId"))
                    .or_else(|| inner_body.get("conversationId"))
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                let actor_did = inner_body
                    .get("actorDid")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                let mut guard = self.state.lock().unwrap();
                let mut new_epoch = 1;
                if let Some(stored) = guard.conversations.get_mut(convo_id) {
                    stored.view.epoch += 1;
                    new_epoch = stored.view.epoch;
                    if let Some(ref mut parts) = stored.participants {
                        for p in parts.iter_mut() {
                            if p.get("userDid").and_then(|u| u.as_str()) == Some(actor_did) {
                                if let Some(obj) = p.as_object_mut() {
                                    obj.insert("status".to_string(), serde_json::json!("active"));
                                }
                            }
                        }
                    }
                }
                let output = serde_json::json!({
                    "result": {
                        "accepted": true,
                        "epoch": new_epoch
                    }
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestReset => {
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({"result": {"recorded": true}})).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::ActivateReset => {
                let delay_ms = self.state.lock().unwrap().bootstrap_reset_group_delay_ms;
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let convo_id = inner_body
                    .get("prior")
                    .and_then(|p| p.get("conversationId"))
                    .or_else(|| inner_body.get("conversationId"))
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                let new_group_id_b64 = inner_body
                    .get("successor")
                    .and_then(|s| s.get("groupId"))
                    .and_then(|g| g.as_str())
                    .unwrap_or_default();
                let new_group_id_hex = base64::engine::general_purpose::STANDARD
                    .decode(new_group_id_b64)
                    .map(|b| hex::encode(&b))
                    .unwrap_or_default();
                let group_info_bytes = inner_body
                    .get("genesisGroupInfo")
                    .and_then(|g| g.get("bytes"))
                    .and_then(|b| b.as_str())
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .unwrap_or_default();

                let mut guard = self.state.lock().unwrap();
                let calls = guard.bootstrap_reset_group_calls.entry(convo_id.to_string()).or_default();
                *calls += 1;
                let call_number = *calls;
                if guard.bootstrap_already_bootstrapped_after_success && call_number > 1 {
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 409,
                        content_type: Some("application/json".into()),
                        body: br#"{"error":"AlreadyBootstrapped"}"#.to_vec(),
                    });
                }
                if guard.bootstrap_reset_group_succeeds {
                    if let Some(stored) = guard.conversations.get_mut(convo_id) {
                        if !new_group_id_hex.is_empty() {
                            stored.view.group_id = new_group_id_hex;
                        }
                    }
                    guard.group_infos.insert(convo_id.to_string(), group_info_bytes);
                } else {
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 500,
                        content_type: Some("application/json".into()),
                        body: br#"{"error":"bootstrap_reset_group failed"}"#.to_vec(),
                    });
                }
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({"result": {"activated": true}})).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestLeafRecovery => {
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&serde_json::json!({"result": {"requested": true}})).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::GetConversationState => {
                let query = request.path.split_once('?').map_or("", |(_, query)| query);
                let conversation_id = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("conversationId="))
                    .ok_or_else(|| {
                        OrchestratorError::InvalidInput(
                            "getConversationState missing conversationId".into(),
                        )
                    })?;
                let guard = self.state.lock().unwrap();
                let Some(conversation) = guard.conversations.get(conversation_id) else {
                    return Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                        status: 404,
                        content_type: Some("application/json".into()),
                        body: serde_json::to_vec(&serde_json::json!({
                            "error": "ConversationNotFound"
                        }))
                        .unwrap(),
                    });
                };
                let output = serde_json::json!({
                    "state": conversation_state_json(conversation),
                    "pendingResetRequests": [],
                    "pendingLeaveRequests": []
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::GetConversations => {
                let guard = self.state.lock().unwrap();
                let items: Vec<serde_json::Value> = guard
                    .conversations
                    .values()
                    .filter(|conversation| {
                        !guard
                            .hidden_conversation_ids
                            .contains(&conversation.view.conversation_id)
                    })
                    .map(|conversation| {
                        serde_json::json!({"state": conversation_state_json(conversation)})
                    })
                    .collect();
                let output = serde_json::json!({
                    "items": items,
                    "inventorySessionId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
                    "snapshotEventCursor": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
                    "hasMore": false,
                    "snapshotExpiresAt": "2026-08-20T12:00:00.000Z"
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::GetLeafRecoveryInbox => {
                let guard = self.state.lock().unwrap();
                let output = serde_json::json!({
                    "items": guard.leaf_recovery_inbox_items.clone(),
                    "inventorySessionId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
                    "snapshotEventCursor": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
                    "hasMore": false,
                    "snapshotExpiresAt": "2026-08-20T12:00:00.000Z"
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::GetEntries => {
                let output = serde_json::json!({
                    "entries": self.state.lock().unwrap().entries.clone()
                });
                Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&output).unwrap(),
                })
            }
            _ => Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status: 200,
                content_type: Some("application/json".into()),
                body: serde_json::to_vec(&serde_json::json!({"result": {}})).unwrap(),
            }),
        }
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let result = {
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

            let mut all: Vec<ConversationView> = guard
                .conversations
                .values()
                .filter(|c| {
                    c.members.contains(&did)
                        && !guard
                            .hidden_conversation_ids
                            .contains(&c.view.conversation_id)
                })
                .map(|c| c.view.clone())
                .collect();
            all.sort_by_key(|c| c.created_at);

            let start = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
            let end = (start + limit as usize).min(all.len());
            let page = all[start..end].to_vec();
            let next_cursor = if end < all.len() {
                Some(end.to_string())
            } else {
                None
            };

            ConversationListPage {
                conversations: page,
                cursor: next_cursor,
            }
        };
        let gate = self.get_conversations_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
        Ok(result)
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let gate = self.get_messages_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }

        let mut guard = self.state.lock().unwrap();
        check_fail(
            &mut guard.failures.fail_next_get_messages,
            "injected get_messages failure",
        )?;

        let all_messages = guard
            .messages
            .get(convo_id)
            .cloned()
            .or_else(|| {
                let matched_cid = guard
                    .conversations
                    .iter()
                    .find(|(_, c)| c.view.group_id == convo_id)
                    .map(|(cid, _)| cid.clone());
                matched_cid.and_then(|cid| guard.messages.get(&cid).cloned())
            })
            .unwrap_or_default();

        let filtered_messages: Vec<StoredMessage> = all_messages
            .into_iter()
            .filter(|m| {
                if let Some(mt) = message_type {
                    if mt == "commit" && !m.is_commit {
                        return false;
                    }
                    if (mt == "message" || mt == "application") && m.is_commit {
                        return false;
                    }
                }
                if let Some(from) = from_epoch {
                    if let Some(e) = m.epoch {
                        if e < from as u64 {
                            return false;
                        }
                    }
                }
                if let Some(to) = to_epoch {
                    if let Some(e) = m.epoch {
                        if e > to as u64 {
                            return false;
                        }
                    }
                }
                true
            })
            .collect();

        // Cursor is a 0-based index encoded as string.
        let start = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
        let end = (start + limit as usize).min(filtered_messages.len());
        let page: Vec<IncomingEnvelope> = filtered_messages[start..end]
            .iter()
            .map(|m| IncomingEnvelope {
                conversation_id: m.conversation_id.clone(),
                sender_did: guard
                    .envelope_sender_relabels
                    .get(&m.sender_did)
                    .cloned()
                    .unwrap_or_else(|| m.sender_did.clone()),
                ciphertext: m.ciphertext.clone(),
                timestamp: m.timestamp,
                server_epoch: m.epoch,
                server_message_id: Some(m.id.clone()),
            })
            .collect();

        let next_cursor = if end < filtered_messages.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok((page, next_cursor))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        let mut guard = self.state.lock().unwrap();
        guard.get_key_packages_call_count += 1;
        check_fail(
            &mut guard.failures.fail_next_get_key_packages,
            "injected get_key_packages failure",
        )?;

        let mut result = Vec::new();
        for did in dids {
            let source_did = guard
                .key_package_redirects
                .get(did)
                .cloned()
                .unwrap_or_else(|| did.clone());
            let root_did = if let Some((root, _)) = source_did.split_once('#') {
                root.to_string()
            } else {
                source_did.clone()
            };
            let packages_opt = if guard.key_packages.contains_key(&source_did) {
                guard.key_packages.get_mut(&source_did)
            } else {
                guard.key_packages.get_mut(&root_did)
            };
            if let Some(packages) = packages_opt {
                if let Some(pkg) = packages.first().cloned() {
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
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: local_hashes.len() as u32,
        })
    }

    async fn list_devices(&self, _actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let guard = self.state.lock().unwrap();
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let devices = guard
            .devices
            .get(&did)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.info)
            .collect();

        Ok(devices)
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

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        *guard
            .get_welcome_calls
            .entry(convo_id.to_string())
            .or_default() += 1;
        check_fail(
            &mut guard.failures.fail_next_get_welcome,
            "injected get_welcome failure",
        )?;
        let did = self
            .effective_did_from_guard(&guard)
            .ok_or(OrchestratorError::NotAuthenticated)?;

        let welcome = guard
            .welcomes
            .get_mut(&(convo_id.to_string(), did.clone()))
            .and_then(|q| {
                if q.is_empty() {
                    None
                } else {
                    Some(q.remove(0))
                }
            })
            .or_else(|| {
                let matched_cid = guard
                    .conversations
                    .iter()
                    .find(|(_, c)| c.view.group_id == convo_id)
                    .map(|(cid, _)| cid.clone());
                if let Some(cid) = matched_cid {
                    guard.welcomes.get_mut(&(cid, did.clone())).and_then(|q| {
                        if q.is_empty() {
                            None
                        } else {
                            Some(q.remove(0))
                        }
                    })
                } else {
                    None
                }
            });
        welcome.ok_or(OrchestratorError::ServerError {
            status: 404,
            body: "welcome not available".to_string(),
        })
    }

    async fn get_delivery_status(
        &self,
        _convo_id: &str,
        _message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        Ok(vec![])
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

        let (msgs, cursor) = svc
            .get_messages("conv-1", None, 10, None, None, None)
            .await
            .unwrap();
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

        let (page1, cursor1) = svc
            .get_messages("conv-1", None, 2, None, None, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);
        assert!(cursor1.is_some());

        let (page2, cursor2) = svc
            .get_messages("conv-1", cursor1.as_deref(), 2, None, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_some());

        let (page3, cursor3) = svc
            .get_messages("conv-1", cursor2.as_deref(), 2, None, None, None)
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert!(cursor3.is_none());
    }

    #[tokio::test]
    async fn test_key_packages_fifo() {
        let svc = MockDeliveryService::new("did:plc:alice");
        svc.publish_key_package(b"kp-1", "suite-1", "2099-01-01", None)
            .await
            .unwrap();
        svc.publish_key_package(b"kp-2", "suite-1", "2099-01-01", None)
            .await
            .unwrap();

        assert_eq!(svc.key_package_count("did:plc:alice"), 2);

        let refs = svc
            .get_key_packages(
                "00000000-0000-4000-8000-000000000001",
                &["did:plc:alice".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].key_package_data, b"kp-1");

        // Second fetch consumes next package
        let refs2 = svc
            .get_key_packages(
                "00000000-0000-4000-8000-000000000001",
                &["did:plc:alice".to_string()],
            )
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
                b"{}",
            )
            .await
            .unwrap();
        assert_eq!(info.mls_did, "did:plc:alice");

        let devices = svc
            .list_devices("00000000-0000-4000-8000-000000000001")
            .await
            .unwrap();
        assert_eq!(devices.len(), 1);

        svc.remove_device(&info.device_id).await.unwrap();
        let devices = svc
            .list_devices("00000000-0000-4000-8000-000000000001")
            .await
            .unwrap();
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
