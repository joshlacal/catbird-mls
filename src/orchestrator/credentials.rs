use async_trait::async_trait;

use super::credential_binding::{check_identity_claim, CredentialVerification};
use super::error::Result;

/// Public signing result returned by a credential authority.
///
/// This record intentionally contains no private-key material. A platform
/// credential store owns the key and signs the exact transcript supplied by
/// the orchestrator, returning only the signature, public key, and the one
/// atomic device-authentication snapshot used for the binding check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanChatSigningAuthority {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub device_id: String,
    pub dpop_jkt: String,
    pub auth_generation: Option<i64>,
}

#[cfg(not(target_arch = "wasm32"))]
pub trait CredentialStoreBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> CredentialStoreBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait CredentialStoreBounds {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> CredentialStoreBounds for T {}

/// Platform-agnostic credential/keychain access for MLS identity management.
///
/// On iOS this wraps Keychain; on desktop it can use OS keyring or encrypted file.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CredentialStore: CredentialStoreBounds {
    /// Store a signing key for a user DID.
    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()>;

    /// Retrieve the signing key for a user DID.
    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>>;

    /// Delete the signing key for a user DID.
    async fn delete_signing_key(&self, user_did: &str) -> Result<()>;

    /// Sign one canonical clean-chat transcript without exporting the private
    /// key. Implementations must resolve the key and binding tuple from one
    /// atomic authority snapshot and return only the public key, signature,
    /// and snapshot metadata. The caller's claimed device/JKT/generation are
    /// deliberately not callback arguments, so an implementation cannot
    /// accidentally turn caller-controlled binding fields into authority.
    ///
    /// The default is deliberately unsupported. In particular, it must not
    /// fall back to `get_signing_key`, because callback implementations may
    /// expose that legacy method across FFI and raw private-key bytes must not
    /// cross the boundary for signed requests.
    async fn sign_clean_chat_transcript(
        &self,
        _user_did: &str,
        _transcript: &[u8],
        _key_id: &str,
    ) -> Result<Option<CleanChatSigningAuthority>> {
        Ok(None)
    }

    /// Store the MLS DID (device-specific identity) for a user.
    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()>;

    /// Retrieve the MLS DID for a user.
    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>>;

    /// Store a device UUID.
    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()>;

    /// Retrieve the device UUID.
    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>>;

    /// Check if credentials exist for a user (device is registered).
    async fn has_credentials(&self, user_did: &str) -> Result<bool>;

    /// Clear all credentials for a user (used during recovery).
    async fn clear_all(&self, user_did: &str) -> Result<()>;

    /// Verify that a member's MLS leaf credential belongs to the expected
    /// ATProto DID (ADR-009, WS-3).
    ///
    /// `claimed_identity` is the UTF-8 identity extracted from the MLS
    /// BasicCredential (bare DID or `did:...#device-id`); `expected_did` is
    /// the DID the credential was presented for (the DID a key package was
    /// fetched for, or the envelope sender DID on inbound processing).
    ///
    /// The default implementation is the **stage-1 structural check**: the
    /// credential's DID root must equal the expected DID (fragment-aware).
    /// The orchestrator separately enforces the second half of the ADR-009
    /// proof by resolving the leaf signature key through
    /// `get_authorized_device_keys`. Overrides may add platform-specific
    /// identity policy here. `Err` is reserved for verifier infrastructure
    /// failures and is propagated fail-closed before MLS state changes.
    async fn verify_member_credential(
        &self,
        expected_did: &str,
        claimed_identity: &str,
    ) -> Result<CredentialVerification> {
        Ok(check_identity_claim(expected_did, claimed_identity))
    }

    /// Optional capability (WS-3 stage 2): resolve the set of MLS device
    /// signing public keys currently authorized for `root_did`, enabling the
    /// second half of the ADR-009 proof (DID-rooted credential AND leaf
    /// signing key published as an authorized device key).
    ///
    /// Return values:
    /// - `Ok(None)` — this platform provides no DID-resolution surface. This
    ///   is a configuration error for any operation that consumes a remote
    ///   KeyPackage; the orchestrator rejects before state changes.
    /// - `Ok(Some(keys))` — resolution succeeded; `keys` are the raw signing
    ///   public keys authorized for `root_did` (per ADR-009 D1: active
    ///   `blue.catbird.mlsChat.device` records in the DID's ATProto repo,
    ///   or equivalently the DID document's `#atproto_mls` verification
    ///   method key). An EMPTY vec means "resolved, zero authorized keys" —
    ///   every presented key then fails the enforced check.
    /// - `Err(_)` — verifier infrastructure failure (network/storage).
    ///   The orchestrator fails closed and the next operation may retry.
    ///
    /// Implementations do NOT need their own cache: the orchestrator caches
    /// results per root DID for `constants::DEVICE_KEY_CACHE_TTL` (ADR-009
    /// D6), bounding positive and negative results by the same TTL, so no
    /// network resolution happens in hot paths beyond the first lookup.
    async fn get_authorized_device_keys(&self, _root_did: &str) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(None)
    }
}
