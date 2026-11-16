//! Strict DID document resolution and its local cache (native).
//!
//! Every native resolver in this crate (the live plane, the Labyrinth transport gateway and the
//! archive gateway) calls [`resolve_did_document_strict`]:
//!
//! * The URL comes from [`super::did_url::did_document_url`]: the PLC directory for `did:plc`, the
//!   host's own `did.json` for `did:web`. No account PDS is asked about any DID, the account's own
//!   included, and no request carries credentials.
//! * A redirect is refused, the body is bounded, and the document's `id` must equal the DID.
//! * A fetched document replaces the cached `did_doc:<did>` row and its `did_doc_meta:<did>`
//!   provenance row in one transaction, so the row is never absent between the old and new
//!   document. The push processor reads `did_doc:<did>` directly for sequencer receipt keys and
//!   never applies the age limit, so background decryption keeps working while the app is
//!   suspended and the network is unreachable.
//! * When the network fails, a cached document is served only if this resolver wrote it within
//!   [`DID_DOC_CACHE_TTL_MS`]. A row with no provenance (written by an earlier build, possibly from
//!   an account PDS) or an older one is not served; the caller fails closed instead.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::chat_wire;
use super::did_url::{bare_did, did_document_url};
use super::traits::{PlatformHttpRequest, PlatformTransport};
use crate::error::MLSError;
use crate::storage::MlsAccountDb;

/// Largest DID document accepted from a resolver (64 KiB).
pub(crate) const MAX_DID_DOCUMENT_BYTES: usize = 64 * 1024;
/// How long a cached document may stand in for an unreachable resolver (7 days).
pub(crate) const DID_DOC_CACHE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Provenance tag for cache rows written by [`resolve_did_document_strict`].
pub(crate) const DID_DOC_CACHE_SOURCE: &str = "strict-v1";

pub(crate) fn did_doc_cache_key(did: &str) -> String {
    format!("did_doc:{did}")
}

pub(crate) fn did_doc_meta_key(did: &str) -> String {
    format!("did_doc_meta:{did}")
}

/// Provenance stored beside a cached DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DidDocCacheMeta {
    pub source: String,
    pub fetched_at_ms: i64,
    /// `publicKeyMultibase` of the document's `#atproto` verification method, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atproto_key: Option<String>,
}

/// What one resolution observed, for callers that track identity changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DidDocObservation {
    pub did: String,
    pub previous_atproto_key: Option<String>,
    pub current_atproto_key: Option<String>,
}

impl DidDocObservation {
    /// The `#atproto` key differs from the one this resolver last fetched for the DID.
    pub fn atproto_key_changed(&self) -> bool {
        self.previous_atproto_key.is_some() && self.previous_atproto_key != self.current_atproto_key
    }
}

/// `publicKeyMultibase` of the `#atproto` verification method in `doc`.
pub(crate) fn atproto_key_multibase(doc: &Value, did: &str) -> Option<String> {
    let methods = doc.get("verificationMethod")?.as_array()?;
    let full_id = format!("{did}#atproto");
    methods
        .iter()
        .find(|method| {
            matches!(
                method.get("id").and_then(Value::as_str),
                Some(id) if id == "#atproto" || id == full_id
            )
        })
        .and_then(|method| method.get("publicKeyMultibase"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn parse_fetched_document(body: &[u8], did: &str) -> Result<(Vec<u8>, Value), MLSError> {
    if body.len() > MAX_DID_DOCUMENT_BYTES {
        return Err(MLSError::Cryptography(format!(
            "DID document for `{did}` exceeds {MAX_DID_DOCUMENT_BYTES} bytes"
        )));
    }
    let doc_bytes = chat_wire::extract_did_doc_from_resolve_response(body)?;
    let doc: Value = serde_json::from_slice(&doc_bytes)
        .map_err(|e| MLSError::Cryptography(format!("invalid DID document JSON: {e}")))?;
    if doc.get("id").and_then(Value::as_str) != Some(did) {
        return Err(MLSError::Cryptography(format!(
            "resolved DID document id {:?} does not match expected `{did}`",
            doc.get("id")
        )));
    }
    Ok((doc_bytes, doc))
}

/// Cached document for `did` if this resolver wrote it no more than
/// [`DID_DOC_CACHE_TTL_MS`] before `now_ms`.
pub(crate) fn fresh_cached_did_document(
    db: &MlsAccountDb,
    did: &str,
    now_ms: i64,
) -> Result<Option<Vec<u8>>, MLSError> {
    let did = bare_did(did);
    let (doc, meta) = db.read_tx(|tx| {
        Ok((
            tx.get_account_meta(&did_doc_cache_key(did))?,
            tx.get_account_meta(&did_doc_meta_key(did))?,
        ))
    })?;
    let (Some(doc), Some(meta)) = (doc, meta) else {
        return Ok(None);
    };
    let Ok(meta) = serde_json::from_str::<DidDocCacheMeta>(&meta) else {
        return Ok(None);
    };
    let age = now_ms.saturating_sub(meta.fetched_at_ms);
    if meta.source != DID_DOC_CACHE_SOURCE || !(0..=DID_DOC_CACHE_TTL_MS).contains(&age) {
        return Ok(None);
    }
    Ok(Some(doc.into_bytes()))
}

/// Resolve `did`'s DID document strictly (see the module documentation).
///
/// Only a 200 is a document. Any other answer (a 404 included) or transport failure falls back
/// to a fresh cached document written by this resolver, and otherwise is an error: a missing
/// document is never reported as "no keys".
pub(crate) fn resolve_did_document_strict(
    db: &MlsAccountDb,
    transport: &dyn PlatformTransport,
    now_ms: i64,
    did: &str,
) -> Result<Option<Vec<u8>>, MLSError> {
    resolve_did_document_observed(db, transport, now_ms, did).map(|(doc, _)| doc)
}

/// [`resolve_did_document_strict`], also reporting the `#atproto` key transition when a
/// document was fetched.
pub(crate) fn resolve_did_document_observed(
    db: &MlsAccountDb,
    transport: &dyn PlatformTransport,
    now_ms: i64,
    did: &str,
) -> Result<(Option<Vec<u8>>, Option<DidDocObservation>), MLSError> {
    let did = bare_did(did);
    let url = did_document_url(did).map_err(MLSError::invalid_input)?;
    let failure = match transport.execute_http(PlatformHttpRequest {
        method: "GET".to_string(),
        url,
        headers: Vec::new(),
        body: None,
    }) {
        Ok(resp) if resp.status == 200 => match parse_fetched_document(&resp.body, did) {
            Ok((doc_bytes, doc)) => {
                let observation = store_fetched_document(db, did, &doc_bytes, &doc, now_ms)?;
                return Ok((Some(doc_bytes), Some(observation)));
            }
            Err(error) => error,
        },
        Ok(resp) if (300..400).contains(&resp.status) => MLSError::Cryptography(format!(
            "DID document fetch for `{did}` was redirected (HTTP {}); redirects are refused",
            resp.status
        )),
        Ok(resp) => MLSError::Internal(format!(
            "DID document fetch for `{did}` failed with HTTP {}",
            resp.status
        )),
        Err(error) => error,
    };
    match fresh_cached_did_document(db, did, now_ms)? {
        Some(cached) => Ok((Some(cached), None)),
        None => Err(failure),
    }
}

fn store_fetched_document(
    db: &MlsAccountDb,
    did: &str,
    doc_bytes: &[u8],
    doc: &Value,
    now_ms: i64,
) -> Result<DidDocObservation, MLSError> {
    let current_atproto_key = atproto_key_multibase(doc, did);
    let meta = DidDocCacheMeta {
        source: DID_DOC_CACHE_SOURCE.to_owned(),
        fetched_at_ms: now_ms,
        atproto_key: current_atproto_key.clone(),
    };
    let meta_json = serde_json::to_string(&meta)
        .map_err(|e| MLSError::Internal(format!("serialize DID document cache meta: {e}")))?;
    let doc_text = std::str::from_utf8(doc_bytes)
        .map_err(|_| MLSError::Cryptography("DID document is not UTF-8".into()))?;
    let previous_atproto_key = db.write_tx(|tx| {
        let previous = tx
            .get_account_meta(&did_doc_meta_key(did))?
            .and_then(|raw| serde_json::from_str::<DidDocCacheMeta>(&raw).ok())
            .filter(|meta| meta.source == DID_DOC_CACHE_SOURCE)
            .and_then(|meta| meta.atproto_key);
        tx.put_account_meta(&did_doc_cache_key(did), doc_text, now_ms)?;
        tx.put_account_meta(&did_doc_meta_key(did), &meta_json, now_ms)?;
        Ok(previous)
    })?;
    Ok(DidDocObservation {
        did: did.to_owned(),
        previous_atproto_key,
        current_atproto_key,
    })
}

#[cfg(test)]
#[path = "identity_unit_tests.rs"]
pub(crate) mod identity_unit_tests;
