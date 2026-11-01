//! Spaces-required eligibility gate (`Spec §2`, `Spec §5 I15`, `Spec §6.7`).
//!
//! Before enrollment, verifies that:
//! 1. The user's PDS advertises/supports `com.atproto.space.*`, AND
//! 2. The active OAuth session grants all required Labyrinth Space, repo, and blob scopes.
//!
//! When unavailable, Catbird MLS chat displays a clear explanation while Unified Chat
//! continues serving standard Bluesky DMs (`bluesky_dms_available == true`).

use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::error::MLSError;

/// Exact OAuth scopes required for Catbird MLS + Labyrinth over ATProto Spaces (`Spec §6.7`).
pub const REQUIRED_LABYRINTH_OAUTH_SCOPES: &[&str; 6] = &[
    "atproto",
    "blob:*/*",
    "repo:blue.catbird.labyrinth.mailboxKeys",
    "repo:blue.catbird.mlsChat.device",
    "space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete",
    "space:blue.catbird.labyrinth.conversation?authority=*",
];

/// Reason why MLS chat over ATProto Spaces is available or unavailable (`I15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
pub enum SpacesUnavailableReason {
    Available,
    PdsDoesNotSupportSpaces,
    MissingOAuthScopes { missing_scopes: Vec<String> },
}

/// Input parameters for evaluating `I15` Spaces eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct SpacesEligibilityInput {
    pub account_did: String,
    pub pds_endpoint: String,
    pub pds_supports_spaces: bool,
    pub granted_oauth_scopes: Vec<String>,
}

/// Output of `I15` Spaces eligibility verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct SpacesEligibilityStatus {
    pub eligible: bool,
    pub reason: SpacesUnavailableReason,
    /// Standard Bluesky DMs remain active even when MLS Spaces chat is unavailable (`Spec §2`).
    pub bluesky_dms_available: bool,
    pub user_message: String,
}

fn scope_granted(granted_scopes: &[String], required: &str) -> bool {
    granted_scopes.iter().any(|g| {
        let trimmed = g.trim();
        trimmed == required || trimmed == "transition:generic" && required == "atproto"
    })
}

/// Pure deterministic evaluation of `I15` Spaces capability + OAuth scope requirements.
pub fn evaluate_spaces_eligibility(input: &SpacesEligibilityInput) -> SpacesEligibilityStatus {
    if !input.pds_supports_spaces {
        return SpacesEligibilityStatus {
            eligible: false,
            reason: SpacesUnavailableReason::PdsDoesNotSupportSpaces,
            bluesky_dms_available: true,
            user_message: format!(
                "End-to-end encrypted Catbird MLS chat requires ATProto Spaces (com.atproto.space.*) on your PDS ({}). Standard Bluesky DMs remain available.",
                input.pds_endpoint
            ),
        };
    }

    let missing_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .filter(|req| !scope_granted(&input.granted_oauth_scopes, req))
        .map(|s| (*s).to_string())
        .collect();

    if !missing_scopes.is_empty() {
        return SpacesEligibilityStatus {
            eligible: false,
            reason: SpacesUnavailableReason::MissingOAuthScopes {
                missing_scopes: missing_scopes.clone(),
            },
            bluesky_dms_available: true,
            user_message: format!(
                "Re-authentication is required to grant ATProto Spaces backup permissions ({}). Standard Bluesky DMs remain available.",
                missing_scopes.join(", ")
            ),
        };
    }

    SpacesEligibilityStatus {
        eligible: true,
        reason: SpacesUnavailableReason::Available,
        bluesky_dms_available: true,
        user_message: "ATProto Spaces and Labyrinth post-quantum backup are ready.".to_string(),
    }
}

/// Probe `pds_endpoint` for `com.atproto.space.*` support via [`super::traits::PlatformTransport`]
/// and evaluate full `I15` eligibility.
#[cfg(not(target_arch = "wasm32"))]
pub fn probe_and_check_spaces_eligibility(
    account_did: &str,
    pds_endpoint: &str,
    granted_oauth_scopes: &[String],
    transport: &dyn super::traits::PlatformTransport,
) -> Result<SpacesEligibilityStatus, MLSError> {
    let trimmed_pds = pds_endpoint.trim_end_matches('/');
    if !trimmed_pds.starts_with("https://")
        && !trimmed_pds.starts_with("http://127.0.0.1")
        && !trimmed_pds.starts_with("http://localhost")
    {
        return Err(MLSError::invalid_input(format!(
            "invalid PDS endpoint URL `{pds_endpoint}`"
        )));
    }

    let probe_url = format!("{trimmed_pds}/xrpc/com.atproto.space.getSpace");
    let response = transport.execute_http(super::traits::PlatformHttpRequest {
        method: "GET".to_string(),
        url: probe_url,
        headers: Vec::new(),
        body: None,
    })?;

    // On an ATProto PDS implementing `com.atproto.space.*`, calling `getSpace` without params
    // returns 400 InvalidRequest / 401 AuthMissing (or 200), whereas a PDS without Spaces
    // returns 404 / 501 XRPCNotSupported / MethodNotImplemented.
    let body_text = String::from_utf8_lossy(&response.body);
    let not_implemented = matches!(response.status, 404 | 501)
        || body_text.contains("XRPCNotSupported")
        || body_text.contains("MethodNotImplemented");
    let pds_supports_spaces = !not_implemented && response.status < 500;

    Ok(evaluate_spaces_eligibility(&SpacesEligibilityInput {
        account_did: account_did.to_string(),
        pds_endpoint: trimmed_pds.to_string(),
        pds_supports_spaces,
        granted_oauth_scopes: granted_oauth_scopes.to_vec(),
    }))
}
