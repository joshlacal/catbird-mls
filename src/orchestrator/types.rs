use chrono::{DateTime, Utc};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A DID (Decentralized Identifier) string, e.g. "did:plc:abc123"
pub type DID = String;

/// Hex-encoded group ID
pub type GroupId = String;

/// Hex-encoded conversation ID (same as GroupId in current implementation)
pub type ConversationId = String;

/// A view of an MLS conversation, mirroring the server's ConvoView.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationView {
    pub group_id: GroupId,
    pub epoch: u64,
    pub members: Vec<MemberView>,
    pub metadata: Option<ConversationMetadata>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// A member within a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberView {
    pub did: DID,
    pub role: MemberRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemberRole {
    Admin,
    Member,
}

/// Conversation metadata (name, description, avatar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
}

/// Delivery status for a message across federated DSes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// All remote DSes acknowledged receipt.
    DeliveredToAll,
    /// Some but not all remote DSes acknowledged.
    Partial { acked_count: i32, total_count: i32 },
    /// No acknowledgments received yet.
    Pending,
    /// All members are on the same DS; no federation needed.
    LocalOnly,
}

/// A decrypted MLS message ready for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub conversation_id: ConversationId,
    pub sender_did: DID,
    pub text: String,
    pub timestamp: DateTime<Utc>,
    pub epoch: u64,
    pub sequence_number: u64,
    /// Whether this message was sent by the local user.
    pub is_own: bool,
    /// Delivery status from federated DSes, if known.
    pub delivery_status: Option<DeliveryStatus>,
}

/// The state of an MLS group tracked locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupState {
    pub group_id: GroupId,
    pub conversation_id: ConversationId,
    pub epoch: u64,
    pub members: Vec<DID>,
}

/// Sync cursor for paginated server fetches.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncCursor {
    pub conversations_cursor: Option<String>,
    pub messages_cursor: Option<String>,
}

/// Information about a registered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub mls_did: DID,
    pub device_uuid: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// State of a conversation from the orchestrator's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationState {
    Initializing,
    Active,
    NeedsRejoin,
    Failed,
}

/// How the local user joined a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinMethod {
    Creator,
    Welcome,
    ExternalCommit,
}

/// Result from processing an external commit on the server.
#[derive(Debug, Clone)]
pub struct ProcessExternalCommitResult {
    pub epoch: u64,
    pub rejoined_at: String,
    /// Sequencer receipt for the external commit, if the server returned one.
    pub receipt: Option<SequencerReceipt>,
}

/// Result of adding members to a group on the server.
#[derive(Debug, Clone)]
pub struct AddMembersServerResult {
    pub success: bool,
    pub new_epoch: u64,
    /// Sequencer receipt for the commit, if the server returned one.
    pub receipt: Option<SequencerReceipt>,
}

/// Result of creating a conversation on the server.
#[derive(Debug, Clone)]
pub struct CreateConversationResult {
    pub conversation: ConversationView,
    pub commit_data: Option<Vec<u8>>,
    pub welcome_data: Option<Vec<u8>>,
}

/// Paginated list of conversations from the server.
#[derive(Debug, Clone)]
pub struct ConversationListPage {
    pub conversations: Vec<ConversationView>,
    pub cursor: Option<String>,
}

/// Key package reference as returned by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageRef {
    pub did: DID,
    pub key_package_data: Vec<u8>,
    pub hash: Option<String>,
    pub cipher_suite: String,
}

/// Key package stats from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageStats {
    pub available: u32,
    pub total: u32,
}

/// Result from syncing key package hashes with the server.
#[derive(Debug, Clone)]
pub struct KeyPackageSyncResult {
    pub orphaned_count: u32,
    pub deleted_count: u32,
}

/// Response from a sequencer failover request.
#[derive(Debug, Clone)]
pub struct RequestFailoverResponse {
    pub new_sequencer_did: String,
    pub convo_id: String,
    pub epoch: i32,
}

/// Desync severity for recovery decisions.
#[derive(Debug, Clone)]
pub enum DesyncSeverity {
    None,
    Minor {
        local_count: u32,
        server_count: u32,
        difference: u32,
    },
    Severe {
        local_count: u32,
        server_count: u32,
        difference: u32,
    },
}

/// Incoming message envelope from the delivery service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingEnvelope {
    pub conversation_id: ConversationId,
    pub sender_did: DID,
    pub ciphertext: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    /// Server-assigned message ID for deduplication.
    pub server_message_id: Option<String>,
}

/// MLS message payload format, matching the iOS Catbird app's MLSMessagePayload.
///
/// All MLS application messages are JSON-encoded using this envelope so that
/// messages are interoperable across Catbird clients (iOS, macOS, catmos).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MLSMessagePayload {
    pub version: u32,
    pub message_type: MLSMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Message type discriminator, matching iOS MLSMessageType.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MLSMessageType {
    Text,
    Reaction,
    ReadReceipt,
    Typing,
    AdminRoster,
    AdminAction,
}

impl MLSMessagePayload {
    /// Create a text message payload.
    pub fn text(content: &str) -> Self {
        Self {
            version: 1,
            message_type: MLSMessageType::Text,
            text: Some(content.to_string()),
        }
    }

    /// Encode to JSON bytes for MLS encryption.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decode from JSON bytes after MLS decryption.
    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Extract the display text from a payload, with fallback for raw UTF-8.
    pub fn extract_text(data: &[u8]) -> Option<String> {
        if data.is_empty() {
            return None;
        }
        // Try JSON payload first
        if let Ok(payload) = Self::decode(data) {
            return payload.text;
        }
        // Fallback: treat as raw UTF-8 text (legacy / other clients)
        String::from_utf8(data.to_vec()).ok()
    }
}

/// Cryptographic receipt from the sequencer proving a specific commit was
/// assigned to a specific epoch. Used for equivocation detection.
///
/// Mirrors `mls-ds::federation::receipt::SequencerReceipt` so clients can
/// verify receipts offline and detect conflicting epoch assignments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerReceipt {
    pub convo_id: String,
    pub epoch: i32,
    /// SHA-256 hash of the commit ciphertext.
    pub commit_hash: Vec<u8>,
    /// DID of the sequencer that issued this receipt.
    pub sequencer_did: String,
    /// Unix timestamp (seconds) when the receipt was issued.
    pub issued_at: i64,
    /// ES256 signature over the canonical receipt bytes.
    pub signature: Vec<u8>,
}

impl SequencerReceipt {
    /// Verify the receipt signature against the sequencer's public key.
    ///
    /// Reconstructs the canonical byte representation and checks the ES256
    /// signature. Returns `true` if the signature is valid.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        // Same canonical bytes format as mls-ds:
        // "CATBIRD-RECEIPT-V1:" || len(convo_id) || convo_id || epoch || commit_hash || len(sequencer_did) || sequencer_did || issued_at
        let mut canonical = Vec::with_capacity(
            19 + 4
                + self.convo_id.len()
                + 4
                + self.commit_hash.len()
                + 4
                + self.sequencer_did.len()
                + 8,
        );
        canonical.extend_from_slice(b"CATBIRD-RECEIPT-V1:");
        canonical.extend_from_slice(&(self.convo_id.len() as u32).to_le_bytes());
        canonical.extend_from_slice(self.convo_id.as_bytes());
        canonical.extend_from_slice(&self.epoch.to_be_bytes());
        canonical.extend_from_slice(&self.commit_hash);
        canonical.extend_from_slice(&(self.sequencer_did.len() as u32).to_le_bytes());
        canonical.extend_from_slice(self.sequencer_did.as_bytes());
        canonical.extend_from_slice(&self.issued_at.to_be_bytes());

        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        verifying_key.verify(&canonical, &sig).is_ok()
    }

    /// Check if two receipts for the same (convo_id, epoch) have different
    /// commit hashes, which would prove sequencer equivocation.
    pub fn detect_equivocation(&self, other: &SequencerReceipt) -> bool {
        self.convo_id == other.convo_id
            && self.epoch == other.epoch
            && self.commit_hash != other.commit_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_json_matches_ios_format() {
        let payload = MLSMessagePayload::text("hello");
        let json = serde_json::to_string(&payload).unwrap();
        // Must match iOS MLSMessagePayload Codable output exactly
        assert_eq!(json, r#"{"version":1,"messageType":"text","text":"hello"}"#);
    }

    #[test]
    fn payload_roundtrip() {
        let payload = MLSMessagePayload::text("test message");
        let bytes = payload.encode().unwrap();
        let decoded = MLSMessagePayload::decode(&bytes).unwrap();
        assert_eq!(decoded.text.unwrap(), "test message");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.message_type, MLSMessageType::Text);
    }

    #[test]
    fn extract_text_json_payload() {
        let json = r#"{"version":1,"messageType":"text","text":"from ios"}"#;
        assert_eq!(
            MLSMessagePayload::extract_text(json.as_bytes()),
            Some("from ios".to_string())
        );
    }

    #[test]
    fn extract_text_raw_utf8_fallback() {
        let raw = b"raw text message";
        assert_eq!(
            MLSMessagePayload::extract_text(raw),
            Some("raw text message".to_string())
        );
    }

    #[test]
    fn extract_text_invalid_bytes() {
        let invalid = &[0xFF, 0xFE, 0xFD];
        assert_eq!(MLSMessagePayload::extract_text(invalid), None);
    }

    #[test]
    fn extract_text_empty_payload() {
        assert_eq!(MLSMessagePayload::extract_text(&[]), None);
    }
}
