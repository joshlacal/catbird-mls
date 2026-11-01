//! DID -> `(home_ds_did, home_ds_endpoint, pds_endpoint)` resolution cache over `routing_cache`.

use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::storage::{MlsAccountDb, RoutingCacheRow};
#[cfg(not(target_arch = "wasm32"))]
use crate::MLSError;

/// Default TTL (`15 minutes`) for cached DID service endpoints.
pub const ROUTING_CACHE_TTL_MS: i64 = 15 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEndpoints {
    pub did: String,
    pub home_ds_did: String,
    pub home_ds_endpoint: Option<String>,
    pub pds_endpoint: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn lookup_fresh_routing_cache(
    db: &MlsAccountDb,
    did: &str,
    now_ms: i64,
) -> Result<Option<ResolvedEndpoints>, MLSError> {
    db.read_tx(|rx| {
        let Some(row) = rx.get_routing_cache(did)? else {
            return Ok(None);
        };
        if now_ms.saturating_sub(row.resolved_at_ms) > ROUTING_CACHE_TTL_MS {
            return Ok(None);
        }
        Ok(Some(ResolvedEndpoints {
            did: row.did,
            home_ds_did: row.home_ds_did,
            home_ds_endpoint: row.home_ds_endpoint,
            pds_endpoint: row.pds_endpoint,
        }))
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn store_routing_cache(
    db: &MlsAccountDb,
    endpoints: &ResolvedEndpoints,
    now_ms: i64,
) -> Result<(), MLSError> {
    db.write_tx(|tx| {
        tx.upsert_routing_cache(&RoutingCacheRow {
            did: endpoints.did.clone(),
            home_ds_did: endpoints.home_ds_did.clone(),
            home_ds_endpoint: endpoints.home_ds_endpoint.clone(),
            pds_endpoint: endpoints.pds_endpoint.clone(),
            resolved_at_ms: now_ms,
        })
    })
}
