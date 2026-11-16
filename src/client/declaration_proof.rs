//! Proven reads of a peer's `blue.catbird.chat.declaration/self` (native).
//!
//! The declaration names the delivery service that coordinates direct requests with a peer, so
//! it is read only from the peer's own PDS (named by its independently resolved DID document) as
//! a `com.atproto.sync.getRecord` CAR proof signed by the document's `#atproto` key, under the
//! per-DID commit rev floor. The last proven answer is cached per DID with its rev and is served
//! only when the peer's PDS cannot be reached; a proof that fails is an error, never a default.

use serde::{Deserialize, Serialize};

use super::chat_wire;
use super::native_client::CatbirdMlsClient;
use super::traits::PlatformHttpRequest;
use crate::error::MLSError;

pub(crate) const DECLARATION_COLLECTION: &str = "blue.catbird.chat.declaration";
const DECLARATION_RKEY: &str = "self";

pub(crate) fn proven_declaration_cache_key(did: &str) -> String {
    format!("declaration_proven:{did}")
}

/// Last proven state of a peer declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProvenDeclaration {
    /// `None` when the proof showed the record does not exist.
    pub delivery_service: Option<String>,
    pub rev: String,
    pub proven_at_ms: i64,
}

/// Why a proven read did not produce an answer.
#[derive(Debug)]
enum DeclarationReadError {
    /// The peer's PDS could not be reached; a last proven answer may stand in.
    Unreachable(MLSError),
    /// An answer arrived and did not verify; nothing may stand in.
    Invalid(MLSError),
}

#[derive(Deserialize)]
struct DeclarationRecord {
    #[serde(rename = "$type")]
    record_type: Option<String>,
    #[serde(rename = "deliveryService")]
    delivery_service: Option<String>,
    #[serde(rename = "allowIncoming")]
    allow_incoming: Option<String>,
    #[serde(rename = "protocolVersion")]
    protocol_version: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

fn invalid(message: impl Into<String>) -> DeclarationReadError {
    DeclarationReadError::Invalid(MLSError::Cryptography(message.into()))
}

/// The declared delivery service DID from a proven DAG-CBOR record.
pub(crate) fn declared_delivery_service(record_dagcbor: &[u8]) -> Result<String, MLSError> {
    let record: DeclarationRecord = serde_ipld_dagcbor::from_slice(record_dagcbor)
        .map_err(|e| MLSError::Cryptography(format!("chat.declaration record: {e}")))?;
    if record.record_type.as_deref() != Some(DECLARATION_COLLECTION) {
        return Err(MLSError::Cryptography(
            "chat.declaration record has the wrong $type".into(),
        ));
    }
    if !matches!(
        record.allow_incoming.as_deref(),
        Some("all" | "none" | "following")
    ) || !matches!(record.protocol_version.as_deref(), Some("1" | "2"))
        || !record
            .created_at
            .as_deref()
            .is_some_and(|at| chrono::DateTime::parse_from_rfc3339(at).is_ok())
    {
        return Err(MLSError::Cryptography(
            "chat.declaration lacks required policy, protocol version or timestamp".into(),
        ));
    }
    let declared = record
        .delivery_service
        .map(|ds| ds.trim().to_owned())
        .filter(|ds| !ds.is_empty())
        .ok_or_else(|| {
            MLSError::Cryptography("chat.declaration names no delivery service".into())
        })?;
    super::did_url::did_document_url(&declared).map_err(|e| {
        MLSError::Cryptography(format!(
            "chat.declaration delivery service is not a valid DID: {e}"
        ))
    })?;
    if declared.contains('#') {
        return Err(MLSError::Cryptography(
            "chat.declaration delivery service must be a bare DID".into(),
        ));
    }
    Ok(declared)
}

impl CatbirdMlsClient {
    /// The delivery service `target_did` declares, from a proven read of its PDS.
    ///
    /// `Ok(None)` means the proof showed no declaration exists. A fetch that cannot reach the
    /// peer's PDS falls back to the last proven answer for that DID; with none, it is an error.
    /// A proof that does not verify, a rev below the floor, or an unparseable record is an error
    /// with no fallback.
    pub(crate) fn resolve_peer_home_ds_did(
        &self,
        target_did: &str,
    ) -> Result<Option<String>, MLSError> {
        let cache_key = proven_declaration_cache_key(target_did);
        match self.read_proven_declaration(target_did) {
            Ok((delivery_service, rev)) => {
                let proven = ProvenDeclaration {
                    delivery_service: delivery_service.clone(),
                    rev,
                    proven_at_ms: self.hooks.now_ms(),
                };
                let encoded = serde_json::to_string(&proven)
                    .map_err(|e| MLSError::Internal(format!("encode proven declaration: {e}")))?;
                let now_ms = proven.proven_at_ms;
                self.db
                    .write_tx(|tx| tx.put_account_meta(&cache_key, &encoded, now_ms))?;
                Ok(delivery_service)
            }
            Err(DeclarationReadError::Invalid(error)) => Err(error),
            Err(DeclarationReadError::Unreachable(error)) => {
                let (cached, changed) = self.db.read_tx(|tx| {
                    Ok((
                        tx.get_account_meta(&cache_key)?,
                        tx.get_account_meta(&super::did_resolution::did_identity_changed_key(
                            target_did,
                        ))?,
                    ))
                })?;
                if changed.is_some() {
                    return Err(MLSError::Cryptography(format!(
                        "chat.declaration last-proven answer predates the repository identity change for `{target_did}`"
                    )));
                }
                match cached.and_then(|raw| serde_json::from_str::<ProvenDeclaration>(&raw).ok()) {
                    Some(proven) => {
                        #[cfg(feature = "labyrinth")]
                        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
                            &self.db,
                            target_did,
                            &proven.rev,
                            self.hooks.now_ms(),
                        )
                        .map_err(|e| {
                            MLSError::Cryptography(format!(
                                "chat.declaration cached rev for `{target_did}`: {e}"
                            ))
                        })?;
                        Ok(proven.delivery_service)
                    }
                    None => Err(error),
                }
            }
        }
    }

    fn read_proven_declaration(
        &self,
        target_did: &str,
    ) -> Result<(Option<String>, String), DeclarationReadError> {
        let doc = self
            .resolve_did_document(target_did)
            // The strict resolver already uses its own fresh, provenance-tagged cache on an
            // outage. Without such a document, the declaration cache cannot justify routing.
            .map_err(DeclarationReadError::Invalid)?
            .ok_or_else(|| invalid(format!("no DID document for `{target_did}`")))?;
        let pds = self
            .repo_pds_endpoint(target_did, Some(&doc))
            .map_err(DeclarationReadError::Invalid)?;
        #[cfg(not(feature = "labyrinth"))]
        {
            let _ = pds;
            Err(invalid(
                "chat.declaration proofs require the labyrinth feature",
            ))
        }
        #[cfg(feature = "labyrinth")]
        {
            let atproto_key =
                atproto_spaces::did_resolver::DidDocument::parse_json(target_did, &doc)
                    .ok()
                    .and_then(|d| d.atproto_key)
                    .ok_or_else(|| {
                        invalid(format!(
                        "no #atproto repository signing key in the DID document of `{target_did}`"
                    ))
                    })?;
            let url = format!(
                "{}/xrpc/com.atproto.sync.getRecord?did={}&collection={DECLARATION_COLLECTION}&rkey={DECLARATION_RKEY}",
                pds.trim_end_matches('/'),
                chat_wire::urlencode_form_component(target_did),
            );
            let resp = self
                .transport
                .execute_http(PlatformHttpRequest {
                    method: "GET".to_string(),
                    url,
                    headers: Vec::new(),
                    body: None,
                })
                .map_err(DeclarationReadError::Unreachable)?;
            if resp.status >= 500 || resp.status == 429 || resp.status == 408 {
                return Err(DeclarationReadError::Unreachable(MLSError::Internal(
                    format!(
                        "chat.declaration sync.getRecord for `{target_did}` failed with HTTP {}",
                        resp.status
                    ),
                )));
            }
            if resp.status != 200 {
                return Err(invalid(format!(
                    "chat.declaration sync.getRecord for `{target_did}` returned HTTP {} without a proof",
                    resp.status
                )));
            }
            let (proved, rev) = crate::labyrinth::repo_proof::verify_car_record_proof_with_rev(
                &resp.body,
                target_did,
                DECLARATION_COLLECTION,
                DECLARATION_RKEY,
                &atproto_key,
            )
            .map_err(|e| invalid(format!("chat.declaration proof for `{target_did}`: {e}")))?;
            crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
                &self.db,
                target_did,
                &rev,
                self.hooks.now_ms(),
            )
            .map_err(|e| invalid(format!("chat.declaration rev for `{target_did}`: {e}")))?;
            let declared = match proved {
                Some((_, record)) => Some(
                    declared_delivery_service(&record).map_err(DeclarationReadError::Invalid)?,
                ),
                None => None,
            };
            Ok((declared, rev))
        }
    }
}

#[cfg(test)]
#[path = "declaration_unit_tests.rs"]
mod declaration_unit_tests;
