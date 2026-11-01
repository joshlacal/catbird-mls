//! `D1` + `3A` home-DS relay client for cross-server Space credentials (`relaySpaceCredential`)
//! and stateless Space reads (`relaySpaceRead`) with mandatory Gate 7 `Atproto-Space-Mac`
//! verification (`Spec §3.1 D1/3A, §6.5`).

use std::sync::Arc;

use atproto_spaces::mac::verify_record_mac;
use serde::{Deserialize, Serialize};

use crate::orchestrator::canonical_transport::encode_query;
use crate::MLSError;

#[cfg(not(target_arch = "wasm32"))]
pub trait RelaySendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> RelaySendSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait RelaySendSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> RelaySendSync for T {}

/// HTTP payload returned by `blue.catbird.chat.relaySpaceRead` on the caller's home `mls-ds`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayedSpaceResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub space_mac_header: Option<String>,
    pub body: Vec<u8>,
}

/// Transport abstraction backed by the caller's authenticated home `mls-ds` (`chat-dpop`).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HomeDsRelayTransport: RelaySendSync {
    async fn relay_space_credential(
        &self,
        target_ds_did: &str,
        space_uri: &str,
        delegation_token: &str,
    ) -> Result<String, MLSError>;

    async fn relay_space_read(
        &self,
        target_endpoint: &str,
        nsid: &str,
        query_string: &str,
        credential_token: &str,
    ) -> Result<RelayedSpaceResponse, MLSError>;
}

/// Client executing `D1` / `3A` cross-server Space credential issuance and MAC-verified Space reads
/// strictly through the caller's home `mls-ds` (`nest` stays single-target on the user's home DS).
pub struct HomeDsSpaceRelayClient {
    transport: Arc<dyn HomeDsRelayTransport>,
}

impl HomeDsSpaceRelayClient {
    pub fn new(transport: Arc<dyn HomeDsRelayTransport>) -> Self {
        Self { transport }
    }

    /// Obtain a short-lived Space credential for `space_uri` on `target_ds_did` via home `mls-ds`
    /// `blue.catbird.chat.relaySpaceCredential`.
    pub async fn fetch_remote_space_credential(
        &self,
        target_ds_did: &str,
        space_uri: &str,
        delegation_token: &str,
    ) -> Result<String, MLSError> {
        if target_ds_did.trim().is_empty()
            || space_uri.trim().is_empty()
            || delegation_token.trim().is_empty()
        {
            return Err(MLSError::invalid_input(
                "relay_space_credential requires non-empty target_ds_did, space_uri, and delegation_token",
            ));
        }
        let token = self
            .transport
            .relay_space_credential(target_ds_did, space_uri, delegation_token)
            .await?;
        if token.trim().is_empty() {
            return Err(MLSError::Internal(
                "home DS relaySpaceCredential returned empty credential token".into(),
            ));
        }
        Ok(token)
    }

    /// Fetch a remote Space record via home `mls-ds` `blue.catbird.chat.relaySpaceRead` and
    /// verify its `Atproto-Space-Mac` (`atproto-space-record`) in Rust BEFORE returning the JSON.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch_verified_remote_record(
        &self,
        target_pds_endpoint: &str,
        space_uri: &str,
        repo_did: &str,
        collection: &str,
        rkey: &str,
        credential_token: &str,
        shared_secret: &[u8; 32],
    ) -> Result<serde_json::Value, MLSError> {
        let query = format!(
            "space={}&repo={}&collection={}&rkey={}",
            encode_query(space_uri),
            encode_query(repo_did),
            encode_query(collection),
            encode_query(rkey),
        );
        let resp = self
            .transport
            .relay_space_read(
                target_pds_endpoint,
                "com.atproto.space.getRecord",
                &query,
                credential_token,
            )
            .await?;

        if !(200..300).contains(&resp.status) {
            return Err(MLSError::Internal(format!(
                "relaySpaceRead getRecord failed with HTTP {}",
                resp.status
            )));
        }

        let mac_header = resp.space_mac_header.as_deref().ok_or_else(|| {
            MLSError::Cryptography("Gate 7: relayed getRecord missing Atproto-Space-Mac header".into())
        })?;

        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| {
            MLSError::Internal(format!("relayed getRecord invalid JSON: {e}"))
        })?;

        let uri = parsed["uri"]
            .as_str()
            .ok_or_else(|| MLSError::Internal("relayed getRecord missing uri".into()))?;
        let cid_str = parsed["cid"]
            .as_str()
            .ok_or_else(|| MLSError::Internal("relayed getRecord missing cid".into()))?;
        let (_base, cid_bytes) = multibase::decode(cid_str)
            .map_err(|e| MLSError::Internal(format!("relayed getRecord invalid multibase CID: {e}")))?;

        let uri_with_space = if uri.contains("?space=") {
            uri.to_owned()
        } else {
            format!("{uri}?space={space_uri}")
        };
        verify_record_mac(shared_secret, mac_header, &uri_with_space, &cid_bytes).map_err(|e| {
            MLSError::Cryptography(format!(
                "Gate 7: relayed getRecord Atproto-Space-Mac mismatch: {e}"
            ))
        })?;

        Ok(parsed)
    }
}
