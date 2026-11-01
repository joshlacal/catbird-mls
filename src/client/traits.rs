//! The 3 thin platform integration traits (`Spec §6.3`):
//! 1. [`PlatformKeyStore`] — `sha256(normalized_did)`-keyed DB key, device signing keypair, and cached `chat-dpop`
//! 2. [`PlatformTransport`] — home `mls-ds` XRPC + WebSocket stream + PDS OAuth Space writes preserving `Atproto-Space-Mac`
//! 3. [`PlatformChangeObserver`] — UI reactive invalidation notifications

use serde::{Deserialize, Serialize};

use crate::error::MLSError;

/// HTTP header pair preserved across FFI (critically including `Atproto-Space-Mac` and `Atproto-Space-Credential`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PlatformHttpHeader {
    pub name: String,
    pub value: String,
}

/// Outbound HTTP request dispatched through the host platform's HTTP stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PlatformHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<PlatformHttpHeader>,
    pub body: Option<Vec<u8>>,
}

/// Inbound HTTP response preserving status code, headers (e.g. `Atproto-Space-Mac`), and body bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct PlatformHttpResponse {
    pub status: u16,
    pub headers: Vec<PlatformHttpHeader>,
    pub body: Vec<u8>,
}

impl PlatformHttpResponse {
    /// Case-insensitive header lookup (e.g. `"atproto-space-mac"`).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

/// Reactive state-change event emitted to UI layers (`SwiftUI`, `Compose`, `Svelte`, `TUI`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum PlatformChangeEvent {
    ConversationsUpdated,
    MessagesUpdated { conversation_id: String },
    RequestsUpdated,
    GroupMetadataUpdated { conversation_id: String },
    SpacesEligibilityChanged { eligible: bool },
    LabyrinthStatusChanged { epoch_seq: u64 },
    Backgrounded,
    Resumed,
}

/// Platform key custody trait (`Spec §6.3`, `Gate 9`, `I8`).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait PlatformKeyStore: Send + Sync {
    /// Load or generate the 32-byte raw SQLCipher key for `<account_did_hash>.db`.
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError>;

    /// Load a serialized OpenMLS signature keypair by canonical key ID.
    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError>;

    /// Persist a serialized OpenMLS signature keypair by canonical key ID.
    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError>;

    /// Delete all Keychain/Keystore secrets for `account_did_hash` on sign-out.
    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError>;

    /// Load a non-expired cached `chat-dpop` / service-auth token (`I10`).
    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError>;

    /// Cache a fresh `chat-dpop` / service-auth token for NSE / background push catch-up (`I10`).
    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError>;
}

/// Platform network transport trait (`Spec §6.3`, `D1`, `Gate 7`).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait PlatformTransport: Send + Sync {
    /// Execute an HTTP request against the user's home `mls-ds` or ATProto PDS,
    /// preserving `Atproto-Space-Mac` and `Atproto-Space-Credential` headers.
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError>;

    /// Start or reconnect the single home-`mls-ds` realtime WebSocket stream (`D1`).
    fn connect_realtime_stream(
        &self,
        home_ds_endpoint: String,
        cursor_seq: Option<i64>,
    ) -> Result<(), MLSError>;

    /// Close the realtime WebSocket stream cleanly (e.g. on backgrounding or sign-out).
    fn disconnect_realtime_stream(&self) -> Result<(), MLSError>;
}

/// Platform UI invalidation observer (`Spec §6.3`).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait PlatformChangeObserver: Send + Sync {
    fn on_change(&self, event: PlatformChangeEvent);
}
