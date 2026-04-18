use chrono::{DateTime, Utc};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// A DID (Decentralized Identifier) string, e.g. "did:plc:abc123"
pub type DID = String;

/// Hex-encoded group ID
pub type GroupId = String;

/// Stable conversation identifier (survives group resets).
pub type ConversationId = String;

/// A view of an MLS conversation, mirroring the server's ConvoView.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationView {
    pub group_id: GroupId,
    /// Stable conversation identifier (survives group resets).
    /// May differ from `group_id` after a group reset.
    pub conversation_id: ConversationId,
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
    /// Full JSON payload for rich embeds. Raw UTF-8 fallback messages leave this empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_json: Option<String>,
}

impl Message {
    pub fn payload(&self) -> Option<MLSMessagePayload> {
        self.payload_json
            .as_ref()
            .and_then(|json| serde_json::from_str::<MLSMessagePayload>(json).ok())
    }

    pub fn image_embed(&self) -> Option<MLSImageEmbed> {
        self.payload().and_then(|payload| payload.image_embed())
    }

    pub fn has_displayable_body(&self) -> bool {
        !self.text.trim().is_empty() || self.image_embed().is_some()
    }
}

/// Response from the delivery service after sending a message.
#[derive(Debug, Clone)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub seq: u64,
    pub epoch: u64,
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
///
/// This is the Rust-orchestrator internal enum; it is *not* the 7-state
/// client-layer machine from spec §8.1. See `CLAUDE.md` ("Layering: Rust 5
/// states vs spec 7 states") for the mapping.
///
/// `ResetPending` is carried here (rather than derived on the platform side)
/// so the orchestrator's Phase-1 recovery path (spec §8.5) can schedule the
/// External Commit against the *new* group id handed down by the server's
/// `GroupResetEvent`. It must survive orchestrator restart — platform
/// storage backends should persist the payload (hex-encoded group id +
/// reset_generation + millis-since-epoch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationState {
    Initializing,
    Active,
    ForkDetected,
    NeedsRejoin,
    /// The server has reset the group (quorum-based auto-reset, spec §8.6).
    /// The orchestrator must delete local MLS state and join the new group.
    ResetPending {
        /// The new MLS group id handed down by the server, hex-encoded.
        /// After successful adoption, `group_states[convo_id].group_id`
        /// becomes this value.
        new_group_id: String,
        /// Server reset generation counter (monotonic per conversation).
        reset_generation: i32,
        /// When the GroupResetEvent was observed locally, as Unix
        /// milliseconds. Stored as i64 (rather than SystemTime) so the
        /// wire format is portable across platforms and wasm32.
        notified_at_ms: i64,
    },
    Failed,
}

impl ConversationState {
    /// Short string tag used for logs, FFI bridges, and storage keys.
    pub fn tag(&self) -> &'static str {
        match self {
            ConversationState::Initializing => "initializing",
            ConversationState::Active => "active",
            ConversationState::ForkDetected => "fork_detected",
            ConversationState::NeedsRejoin => "needs_rejoin",
            ConversationState::ResetPending { .. } => "reset_pending",
            ConversationState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ForkDetectionState {
    pub detected_at_epoch: u64,
    pub readd_attempts: u32,
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

/// Encrypted reaction to a message (add or remove emoji).
/// Matches the iOS `MLSReactionPayload` Codable struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MLSReactionPayload {
    pub message_id: String,
    pub emoji: String,
    pub action: ReactionAction,
}

/// Whether a reaction is being added or removed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReactionAction {
    Add,
    Remove,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<MLSEmbedData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reaction: Option<MLSReactionPayload>,
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
    System,
}

/// Rich embed wrapper matching Catbird's wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLSEmbedData {
    #[serde(rename = "type")]
    pub kind: String,
    pub data: serde_json::Value,
}

impl MLSEmbedData {
    pub fn image(image: MLSImageEmbed) -> Result<Self, serde_json::Error> {
        Ok(Self {
            kind: "image".to_string(),
            data: serde_json::to_value(image)?,
        })
    }

    pub fn as_image(&self) -> Option<MLSImageEmbed> {
        if self.kind != "image" {
            return None;
        }
        serde_json::from_value(self.data.clone()).ok()
    }

    pub fn audio(audio: MLSAudioEmbed) -> Result<Self, serde_json::Error> {
        Ok(Self {
            kind: "audio".to_string(),
            data: serde_json::to_value(audio)?,
        })
    }

    pub fn as_audio(&self) -> Option<MLSAudioEmbed> {
        if self.kind != "audio" {
            return None;
        }
        serde_json::from_value(self.data.clone()).ok()
    }
}

/// First-class encrypted voice message attachment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct MLSAudioEmbed {
    pub blob_id: String,
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub iv: Vec<u8>,
    pub sha256: String,
    pub content_type: String,
    pub size: u64,
    pub duration_ms: u64,
    pub waveform: Vec<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<String>,
}

/// First-class encrypted image attachment. Mirrors the iOS Codable layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MLSImageEmbed {
    pub blob_id: String,
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub iv: Vec<u8>,
    pub sha256: String,
    pub content_type: String,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blurhash: Option<String>,
}

impl MLSMessagePayload {
    /// Create a system message payload (e.g., history boundary markers).
    pub fn system(content_key: &str) -> Self {
        Self {
            version: 1,
            message_type: MLSMessageType::System,
            text: Some(content_key.to_string()),
            embed: None,
            reaction: None,
        }
    }

    /// Create a text message payload.
    pub fn text(content: &str) -> Self {
        Self {
            version: 1,
            message_type: MLSMessageType::Text,
            text: Some(content.to_string()),
            embed: None,
            reaction: None,
        }
    }

    /// Create a text message with an embed payload.
    pub fn text_with_embed(content: &str, embed: MLSEmbedData) -> Self {
        Self {
            version: 1,
            message_type: MLSMessageType::Text,
            text: Some(content.to_string()),
            embed: Some(embed),
            reaction: None,
        }
    }

    /// Create a reaction payload (add or remove emoji on a message).
    pub fn reaction(message_id: &str, emoji: &str, action: ReactionAction) -> Self {
        Self {
            version: 1,
            message_type: MLSMessageType::Reaction,
            text: None,
            embed: None,
            reaction: Some(MLSReactionPayload {
                message_id: message_id.to_string(),
                emoji: emoji.to_string(),
                action,
            }),
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

    pub fn image_embed(&self) -> Option<MLSImageEmbed> {
        self.embed.as_ref().and_then(MLSEmbedData::as_image)
    }

    pub fn audio_embed(&self) -> Option<MLSAudioEmbed> {
        self.embed.as_ref().and_then(MLSEmbedData::as_audio)
    }

    pub fn display_text(&self) -> String {
        if let Some(text) = &self.text {
            if !text.is_empty() {
                return text.clone();
            }
            // Empty text with image embed → return empty (image carries content)
            if self.image_embed().is_some() || self.embed.is_none() {
                return text.clone();
            }
        }
        if self.audio_embed().is_some() {
            return "🎤 Voice message".to_string();
        }
        if self.embed.is_some() {
            return "[Attachment]".to_string();
        }
        String::new()
    }

    pub fn is_displayable(&self) -> bool {
        match self.message_type {
            MLSMessageType::Text => {
                !self.display_text().trim().is_empty()
                    || self.image_embed().is_some()
                    || self.audio_embed().is_some()
            }
            MLSMessageType::System => true,
            _ => false,
        }
    }

    /// Extract the display text from a payload, with fallback for raw UTF-8.
    pub fn extract_text(data: &[u8]) -> Option<String> {
        if data.is_empty() {
            return None;
        }
        // Try JSON payload first
        if let Ok(payload) = Self::decode(data) {
            return Some(payload.display_text());
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
        assert!(decoded.embed.is_none());
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

    #[test]
    fn image_embed_matches_ios_json_shape() {
        let payload = MLSMessagePayload::text_with_embed(
            "",
            MLSEmbedData::image(MLSImageEmbed {
                blob_id: "blob-123".to_string(),
                key: vec![1, 2, 3, 4],
                iv: vec![5, 6, 7, 8],
                sha256: "deadbeef".to_string(),
                content_type: "image/jpeg".to_string(),
                size: 1234,
                width: 640,
                height: 480,
                alt_text: Some("cat".to_string()),
                blurhash: None,
            })
            .unwrap(),
        );

        let json = serde_json::to_string(&payload).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{"version":1,"messageType":"text","text":"","embed":{"type":"image","data":{"blob_id":"blob-123","key":"AQIDBA==","iv":"BQYHCA==","sha256":"deadbeef","content_type":"image/jpeg","size":1234,"width":640,"height":480,"alt_text":"cat"}}}"#,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let decoded = MLSMessagePayload::decode(json.as_bytes()).unwrap();
        let image = decoded.image_embed().unwrap();
        assert_eq!(image.blob_id, "blob-123");
        assert_eq!(image.key, vec![1, 2, 3, 4]);
        assert_eq!(image.iv, vec![5, 6, 7, 8]);
    }

    #[test]
    fn audio_embed_roundtrip() {
        let audio = MLSAudioEmbed {
            blob_id: "audio-456".to_string(),
            key: vec![10, 20, 30],
            iv: vec![40, 50, 60],
            sha256: "abc123".to_string(),
            content_type: "audio/ogg; codecs=opus".to_string(),
            size: 9876,
            duration_ms: 3500,
            waveform: vec![0.0, 0.5, 1.0, 0.3],
            transcript: Some("Hello world".to_string()),
        };

        let payload =
            MLSMessagePayload::text_with_embed("", MLSEmbedData::audio(audio.clone()).unwrap());

        let bytes = payload.encode().unwrap();
        let decoded = MLSMessagePayload::decode(&bytes).unwrap();
        let decoded_audio = decoded.audio_embed().unwrap();
        assert_eq!(decoded_audio.blob_id, "audio-456");
        assert_eq!(decoded_audio.duration_ms, 3500);
        assert_eq!(decoded_audio.waveform, vec![0.0, 0.5, 1.0, 0.3]);
        assert_eq!(decoded_audio.transcript.as_deref(), Some("Hello world"));
    }

    #[test]
    fn audio_embed_display_text() {
        let audio = MLSAudioEmbed {
            blob_id: "a".to_string(),
            key: vec![],
            iv: vec![],
            sha256: String::new(),
            content_type: "audio/ogg; codecs=opus".to_string(),
            size: 100,
            duration_ms: 1000,
            waveform: vec![],
            transcript: None,
        };
        let payload = MLSMessagePayload::text_with_embed("", MLSEmbedData::audio(audio).unwrap());
        assert_eq!(payload.display_text(), "🎤 Voice message");
        assert!(payload.is_displayable());
    }
}
