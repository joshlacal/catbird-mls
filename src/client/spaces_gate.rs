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

/// OAuth requests explicitly state delegation read, record verbs, and declared collections.
pub const REQUIRED_LABYRINTH_OAUTH_SCOPES: &[&str; 6] = &[
    "atproto",
    "blob:*/*",
    "repo:blue.catbird.labyrinth.mailboxKeys",
    "repo:blue.catbird.chat.device?action=create",
    "space:blue.catbird.labyrinth.mailbox?action=create&action=delete&action=read&action=update&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.circleOwnerState&collection=blue.catbird.labyrinth.device&collection=blue.catbird.labyrinth.epoch&collection=blue.catbird.labyrinth.epochMember&collection=blue.catbird.labyrinth.otcSession&collection=blue.catbird.labyrinth.ownerBatch&collection=blue.catbird.labyrinth.readState&collection=blue.catbird.labyrinth.virtualDevice&manage=create&manage=delete",
    "space:blue.catbird.labyrinth.conversation?action=create&action=delete&action=read&action=update&authority=*&collection=blue.catbird.labyrinth.attachmentManifest&collection=blue.catbird.labyrinth.authorRedaction&collection=blue.catbird.labyrinth.batch&collection=blue.catbird.labyrinth.mek",
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

// Static scope coverage is not a credential authorization result. Returned scope
// strings cannot prove the issuer retained original explicit-action provenance.
fn repo_scope_granted(granted_scopes: &[String], required: &str) -> bool {
    let (req_base, req_query) = match required.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (required, None),
    };
    let req_nsid = match req_base.strip_prefix("repo:") {
        Some(nsid) if !nsid.is_empty() => nsid,
        _ => return false,
    };
    let req_actions: Vec<&str> = match req_query {
        Some(q) => {
            let mut actions = Vec::new();
            for pair in q.split('&') {
                let Some(("action", val)) = pair.split_once('=') else {
                    return false;
                };
                if !matches!(val, "create" | "update" | "delete") {
                    return false;
                }
                actions.push(val);
            }
            if actions.is_empty() {
                return false;
            }
            actions
        }
        None => vec!["create", "update", "delete"],
    };

    granted_scopes.iter().any(|grant| {
        let grant = grant.trim();
        let (grant_base, grant_query) = match grant.split_once('?') {
            Some((base, query)) => (base, Some(query)),
            None => (grant, None),
        };
        let mut granted_collections = Vec::new();
        match grant_base.strip_prefix("repo:") {
            Some("") => {}
            Some(col) => granted_collections.push(col),
            None => return false,
        }
        let mut granted_actions = Vec::new();
        if let Some(q) = grant_query {
            for pair in q.split('&') {
                let Some((k, v)) = pair.split_once('=') else {
                    return false;
                };
                if v.is_empty() {
                    return false;
                }
                match k {
                    "action" if matches!(v, "create" | "update" | "delete") => {
                        granted_actions.push(v);
                    }
                    "collection"
                        if v == "*"
                            || v.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')) =>
                    {
                        granted_collections.push(v);
                    }
                    _ => return false,
                }
            }
        }
        if granted_collections.is_empty() {
            return false;
        }
        let collection_matches =
            granted_collections.contains(&"*") || granted_collections.contains(&req_nsid);
        if !collection_matches {
            return false;
        }
        if granted_actions.is_empty() {
            // Unparameterized `repo:<nsid>` or `repo:*` grants create, update, and delete.
            true
        } else {
            req_actions.iter().all(|req| granted_actions.contains(req))
        }
    })
}

fn scope_granted(granted_scopes: &[String], required: &str, account_did: &str) -> bool {
    if required.starts_with("repo:") {
        return repo_scope_granted(granted_scopes, required);
    }
    let Some((family, required_query)) = required
        .split_once('?')
        .filter(|(family, _)| family.starts_with("space:"))
    else {
        return granted_scopes.iter().any(|grant| {
            let grant = grant.trim();
            grant == required || grant == "transition:generic" && required == "atproto"
        });
    };
    let required: Vec<_> = required_query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();
    granted_scopes.iter().any(|grant| {
        let Some((granted_family, query)) = grant.trim().split_once('?') else {
            return false;
        };
        if granted_family != family {
            return false;
        }
        let mut params = Vec::new();
        let mut authority = None;
        let mut skey = None;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                return false;
            };
            if value.is_empty() {
                return false;
            }
            match key {
                "authority" if authority.is_none() => authority = Some(value),
                "skey" if skey.is_none() => skey = Some(value),
                "collection"
                    if value == "*"
                        || value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')) => {}
                "action"
                    if matches!(value, "read" | "read_self" | "create" | "update" | "delete") => {}
                "manage" if matches!(value, "create" | "update" | "delete") => {}
                _ => return false,
            }
            params.push((key, value));
        }
        let authority = authority.unwrap_or("self");
        let any_authority = required.contains(&("authority", "*"));
        let authority_matches = if any_authority {
            authority == "*"
        } else {
            authority == "self" || authority == account_did || authority == "*"
        };
        if !authority_matches {
            return false;
        }
        let personal = family == "space:blue.catbird.labyrinth.mailbox";
        if skey.is_some_and(|key| key != "*" && !(personal && key == "self")) {
            return false;
        }
        required.iter().all(|&(key, value)| {
            key == "authority"
                || params.contains(&(key, value))
                || key == "collection" && params.contains(&("collection", "*"))
        })
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
        .filter(|req| !scope_granted(&input.granted_oauth_scopes, req, &input.account_did))
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
        user_message: "ATProto Spaces and required backup scopes are available; archive operations still authenticate each Space credential.".to_string(),
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
    let error = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    let not_implemented = matches!(response.status, 404 | 501)
        || matches!(
            error.as_ref().and_then(|value| value["error"].as_str()),
            Some("XRPCNotSupported" | "MethodNotImplemented")
        );
    let pds_supports_spaces = !not_implemented && response.status < 500;

    Ok(evaluate_spaces_eligibility(&SpacesEligibilityInput {
        account_did: account_did.to_string(),
        pds_endpoint: trimmed_pds.to_string(),
        pds_supports_spaces,
        granted_oauth_scopes: granted_oauth_scopes.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_scope_gate_requires_explicit_actions_and_collection_coverage() {
        let did = "did:plc:scopeuser";
        for required in &REQUIRED_LABYRINTH_OAUTH_SCOPES[4..] {
            assert!(scope_granted(&[required.to_string()], required, did));
            let (family, query) = required.split_once('?').unwrap();
            let mut pairs: Vec<_> = query.split('&').collect();
            pairs.reverse();
            let reordered = format!("{family}?{}", pairs.join("&"));
            assert!(scope_granted(&[reordered], required, did));
            let no_read = required.replace("&action=read", "");
            assert!(!scope_granted(&[no_read], required, did));
            let no_collections = format!(
                "{family}?{}",
                query
                    .split('&')
                    .filter(|pair| !pair.starts_with("collection="))
                    .collect::<Vec<_>>()
                    .join("&")
            );
            assert!(!scope_granted(&[no_collections], required, did));
            let duplicate_authority = format!("{required}&authority=did:plc:other&authority=*");
            assert!(!scope_granted(&[duplicate_authority], required, did));
        }
        for legacy in [
            "space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete",
            "space:blue.catbird.labyrinth.conversation?authority=*",
        ] {
            assert!(!REQUIRED_LABYRINTH_OAUTH_SCOPES[4..]
                .iter()
                .any(|required| scope_granted(&[legacy.into()], required, did)));
        }

        // Verify repo scope rules & subsumption (`Y-6` / `D-12`):
        // `mailboxKeys` requires full CRUD (`putRecord` updates on epoch rotation),
        // while `chat.device` is create-only (`?action=create`).
        let mailbox_req = REQUIRED_LABYRINTH_OAUTH_SCOPES[2];
        assert_eq!(mailbox_req, "repo:blue.catbird.labyrinth.mailboxKeys");
        assert!(scope_granted(&[mailbox_req.to_string()], mailbox_req, did));
        assert!(scope_granted(&["repo:*".to_string()], mailbox_req, did));
        assert!(
            !scope_granted(
                &["repo:blue.catbird.labyrinth.mailboxKeys?action=create".to_string()],
                mailbox_req,
                did
            ),
            "create-only scope must not satisfy full mailboxKeys rotation requirement"
        );

        let device_req = REQUIRED_LABYRINTH_OAUTH_SCOPES[3];
        assert_eq!(device_req, "repo:blue.catbird.chat.device?action=create");
        assert!(scope_granted(&[device_req.to_string()], device_req, did));
        assert!(scope_granted(
            &["repo:blue.catbird.chat.device".to_string()],
            device_req,
            did
        ));
        assert!(
            !scope_granted(
                &["repo:blue.catbird.chat.device?action=delete".to_string()],
                device_req,
                did
            ),
            "delete-only scope must not satisfy create requirement"
        );
    }
}
