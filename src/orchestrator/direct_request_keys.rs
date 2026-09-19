//! Durable request-purpose KeyPackage publication; ordinary key counts are not authority.
use crate::{
    chat_v2::transcript::direct_request::{self as transcript, DirectRequestKind},
    MLSError,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct DirectRequestKeyPublicationInput {
    pub actor_did: String,
    pub actor_device_id: String,
    pub auth_generation: i64,
    pub revision: i64,
    pub count: u32,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestKeyPublication {
    pub actor_did: String,
    pub actor_device_id: String,
    pub public_key: Vec<u8>,
    /// The complete HTTP body, persisted together with all private bundles.
    pub exact_request: Vec<u8>,
    pub acknowledged: bool,
}
fn invalid() -> MLSError {
    MLSError::invalid_input("Invalid protected request key publication")
}
fn bytes(value: &Value) -> Result<Vec<u8>, MLSError> {
    STANDARD
        .decode(
            value
                .as_str()
                .or_else(|| value["$bytes"].as_str())
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())
}
impl DirectRequestKeyPublication {
    pub fn decode(raw: &[u8], owner: &str, device: &str) -> Result<Self, MLSError> {
        let record: Self = serde_json::from_slice(raw).map_err(|_| invalid())?;
        if record.actor_did != owner || record.actor_device_id != device {
            return Err(invalid());
        }
        record.body()?;
        Ok(record)
    }
    pub fn body(&self) -> Result<Value, MLSError> {
        crate::chat_v2::transcript::decode_strict_json(&self.exact_request)
            .map_err(|_| invalid())?;
        let request: Value = serde_json::from_slice(&self.exact_request).map_err(|_| invalid())?;
        if request
            .as_object()
            .is_none_or(|o| o.len() != 1 || !o.contains_key("signedRequest"))
        {
            return Err(invalid());
        }
        let signed = transcript::verify_signed_request(
            DirectRequestKind::Keys,
            &serde_json::to_vec(&request["signedRequest"]).map_err(|_| invalid())?,
            &self.public_key,
        )
        .map_err(|_| invalid())?;
        let body = signed.body();
        if body["actorDid"] != self.actor_did || body["actorDeviceId"] != self.actor_device_id {
            return Err(invalid());
        }
        let keys = body["keys"].as_array().ok_or_else(invalid)?;
        if keys.len() > 64 || (body["enabled"] == false && !keys.is_empty()) {
            return Err(invalid());
        }
        let mut refs = std::collections::HashSet::new();
        for entry in keys {
            let package = bytes(&entry["keyPackage"]["bytes"])?;
            let binding = super::credential_binding::extract_key_package_binding(&package)
                .map_err(|_| invalid())?;
            if binding.identity != format!("{}#{}", self.actor_did, self.actor_device_id)
                || binding.signature_key != self.public_key
            {
                return Err(invalid());
            }
            let grant = transcript::verify_signed_request(
                DirectRequestKind::Grant,
                &serde_json::to_vec(&entry["grant"]).map_err(|_| invalid())?,
                &self.public_key,
            )
            .map_err(|_| invalid())?;
            for field in ["actorDid", "actorDeviceId", "keyId", "authGeneration"] {
                if grant.body()[field] != body[field] {
                    return Err(invalid());
                }
            }
            if grant.body()["grantRevision"] != body["revision"]
                || grant.body()["keyPackageRef"] != entry["keyPackage"]["keyPackageRef"]
                || bytes(&grant.body()["keyPackageSha256"])? != Sha256::digest(&package).as_slice()
                || bytes(&entry["keyPackage"]["sha256"])? != Sha256::digest(&package).as_slice()
                || !refs.insert(bytes(&grant.body()["keyPackageRef"])?)
            {
                return Err(invalid());
            }
        }
        Ok(body.clone())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use super::*;
    use crate::orchestrator::direct_request_journal::native::{error, Provider};
    use openmls::prelude::*;
    use openmls_traits::{signatures::Signer, OpenMlsProvider};
    use rusqlite::OptionalExtension;
    use tls_codec::Serialize as _;
    fn key(device: &str) -> Result<String, MLSError> {
        crate::chat_v2::ids::CanonicalUuid::parse(device).map_err(|_| invalid())?;
        Ok(format!("direct_request_key_publication_v2:{device}"))
    }
    pub(crate) fn read(
        storage: &crate::mls_context::ManifestStorage,
        device: &str,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        storage
            .welcome_ack_connection()
            .query_row(
                "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
                [key(device)?],
                |r| r.get(0),
            )
            .optional()
            .map_err(error)
    }
    pub(crate) fn cas(
        storage: &crate::mls_context::ManifestStorage,
        device: &str,
        expected: &[u8],
        next: &[u8],
    ) -> Result<bool, MLSError> {
        let old: DirectRequestKeyPublication = serde_json::from_slice(expected).map_err(error)?;
        let new = DirectRequestKeyPublication::decode(next, &old.actor_did, device)?;
        if old.exact_request != new.exact_request
            || old.public_key != new.public_key
            || !new.acknowledged
        {
            return Err(invalid());
        }
        let changed = storage
            .welcome_ack_connection()
            .execute(
                "UPDATE mls_manifests SET value=?1 WHERE key=?2 AND CAST(value AS BLOB)=?3",
                rusqlite::params![next, key(device)?, expected],
            )
            .map_err(error)?;
        storage.flush_database()?;
        Ok(changed == 1)
    }
    pub(crate) fn prepare(
        inner: &mut crate::mls_context::MLSContext,
        input: &DirectRequestKeyPublicationInput,
        expected: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        crate::chat_v2::ids::BareDid::parse(&input.actor_did).map_err(|_| invalid())?;
        let storage_key = key(&input.actor_device_id)?;
        if input.count > 64
            || (!input.enabled && input.count != 0)
            || input.auth_generation < 1
            || input.revision < 1
        {
            return Err(invalid());
        }
        let identity = format!("{}#{}", input.actor_did, input.actor_device_id);
        let signer = inner
            .get_signer_for_identity(&identity)
            .ok_or(MLSError::StorageFailed)?;
        let now = chrono::Utc::now().timestamp();
        let tx = inner
            .manifest_storage
            .welcome_ack_connection()
            .unchecked_transaction()
            .map_err(error)?;
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
                [&storage_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(error)?;
        if old.as_deref() != expected {
            return Ok(None);
        }
        // Unknown publications retain private custody. Bound new allocation;
        // reaching the limit never discards old evidence or infers failure.
        let private_count: u64 = tx
            .query_row("SELECT count(*) FROM mls_key_package_bundles", [], |r| {
                r.get(0)
            })
            .map_err(error)?;
        let history_count: u64 = tx.query_row(
            "SELECT count(*) FROM mls_manifests WHERE key LIKE 'direct_request_key_publication_history_v2:%'", [], |r| r.get(0)
        ).map_err(error)?;
        if (input.count > 0 && private_count.saturating_add(u64::from(input.count)) > 128)
            || history_count >= 256
        {
            return Err(MLSError::OperationNotSupported {
                reason: "Request key custody quota reached; reconcile retained publications before replenishing".into(),
            });
        }
        if let Some(raw) = &old {
            let previous =
                DirectRequestKeyPublication::decode(raw, &input.actor_did, &input.actor_device_id)?;
            let body = previous.body()?;
            // A higher signed capability revision fences late older writes.
            // Preserve all old evidence/private bundles; supersession does not
            // claim that the old publication never happened.
            if body["revision"].as_i64().ok_or_else(invalid)? >= input.revision {
                return Err(invalid());
            }
            tx.execute(
                "INSERT OR IGNORE INTO mls_manifests(key,value) VALUES(?1,?2)",
                rusqlite::params![
                    format!(
                        "direct_request_key_publication_history_v2:{}",
                        hex::encode(Sha256::digest(raw))
                    ),
                    raw
                ],
            )
            .map_err(error)?;
        }
        let provider = Provider {
            storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
            crypto: inner.provider.crypto(),
        };
        let (raw, bundles) =
            super::super::direct_request_shared_crypto::build_request_key_publication(
                &provider, &signer, input, now,
            )?;
        for (reference, bundle) in &bundles {
            tx.execute("INSERT INTO mls_key_package_bundles(hash_ref,bundle_b64,created_at) VALUES(?1,?2,?3)",rusqlite::params![hex::encode(reference),STANDARD.encode(serde_json::to_vec(bundle).map_err(error)?),now]).map_err(error)?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
            rusqlite::params![storage_key, &raw],
        )
        .map_err(error)?;
        tx.commit().map_err(error)?;
        for (reference, bundle) in bundles {
            inner.key_package_bundles.insert(reference, bundle);
        }
        inner.manifest_storage.flush_database()?;
        Ok(Some(raw))
    }
}

impl<S, A, C, M> super::MLSOrchestrator<S, A, C, M>
where
    S: super::MLSStorageBackend + 'static,
    A: super::MLSAPIClient + 'static,
    C: super::CredentialStore + 'static,
    M: super::MlsCryptoContext + 'static,
{
    /// Bounded maintenance of an already enabled exact-device request pool.
    /// This never opts a device into request pre-enrollment.
    pub async fn replenish_direct_request_keys_if_needed(&self) -> super::Result<()> {
        self.update_direct_request_keys(None).await
    }

    /// Last acknowledged preference for this exact current device authority.
    /// None means absent, unresolved, or rebound; it never means disabled.
    pub async fn get_direct_request_delivery_enabled(&self) -> super::Result<Option<bool>> {
        self.require_direct_request_support()?;
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let Some(raw) = self
            .mls_context()
            .read_direct_request_key_publication(&device)?
        else {
            return Ok(None);
        };
        let record = DirectRequestKeyPublication::decode(&raw, &owner, &device)?;
        let body = record.body()?;
        let generation = self.credentials().get_auth_generation(&owner).await?;
        let public = self
            .mls_context()
            .identity_public_key(format!("{owner}#{device}").into_bytes())?;
        if !record.acknowledged
            || body["authGeneration"].as_i64() != generation
            || record.public_key != public
        {
            return Ok(None);
        }
        Ok(body["enabled"].as_bool())
    }

    /// Explicit exact-device enrollment or revocation. Errors leave the
    /// persisted operation unresolved; callers must not display confirmation.
    pub async fn set_direct_request_delivery_enabled(&self, enabled: bool) -> super::Result<()> {
        self.require_direct_request_support()?;
        self.update_direct_request_keys(Some(enabled)).await
    }

    async fn update_direct_request_keys(&self, desired: Option<bool>) -> super::Result<()> {
        use super::{
            canonical_transport::{CanonicalOperation, PreparedRequest},
            OrchestratorError,
        };
        if !self.mls_context().supports_direct_request_bootstrap() {
            return Ok(());
        }
        let owner = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if !self.api_client().is_authenticated_as(&owner).await {
            return Err(OrchestratorError::NotAuthenticated);
        }
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(invalid)?;
        let public = self
            .mls_context()
            .identity_public_key(format!("{owner}#{device}").into_bytes())?;
        let lock = self
            .direct_request_operation_lock(&format!("keys:{device}"))
            .await;
        let _guard = lock.lock().await;
        let mut cursor = None::<String>;
        let mut seen = std::collections::HashSet::new();
        let mut own = None;
        // Own-device stats are pagination-bound hints, never peer-key authority.
        for _ in 0..16 {
            let mut query = format!("actorDeviceId={device}&limit=100");
            if let Some(cursor) = &cursor {
                query.push_str("&pageCursor=");
                query.push_str(&super::canonical_transport::encode_query(cursor));
            }
            let response = self
                .request_query(CanonicalOperation::GetOwnDevices, query)
                .await?;
            for item in response["items"].as_array().ok_or_else(invalid)? {
                if item["device"]["deviceId"] == device {
                    if own.is_some() {
                        return Err(invalid().into());
                    }
                    own = Some(item.clone());
                } else if item
                    .get("directRequestKeyPool")
                    .is_some_and(|v| !v.is_null())
                {
                    return Err(invalid().into());
                }
            }
            if response["hasMore"] == false {
                break;
            }
            let next = response["nextPageCursor"]
                .as_str()
                .ok_or_else(invalid)?
                .to_string();
            if !seen.insert(next.clone()) {
                return Err(invalid().into());
            }
            cursor = Some(next);
        }
        let Some(own) = own else {
            return if desired.is_some() {
                Err(invalid().into())
            } else {
                Ok(())
            };
        };
        let auth = &own["device"];
        if auth["status"] != "active"
            || auth["authGeneration"] != generation
            || auth["keyId"] != URL_SAFE_NO_PAD.encode(Sha256::digest(&public))
            || bytes(&auth["signaturePublicKey"])? != public
        {
            return Err(invalid().into());
        }
        let stats: Option<crate::atproto::blue_catbird::chat::DirectRequestKeyPoolStats<String>> =
            own.get("directRequestKeyPool")
                .filter(|s| !s.is_null())
                .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid()))
                .transpose()?;
        if let Some(stats) = &stats {
            let as_of = chrono::DateTime::parse_from_rfc3339(&stats.as_of.to_string())
                .map_err(|_| invalid())?
                .timestamp();
            let until = chrono::DateTime::parse_from_rfc3339(&stats.usable_until.to_string())
                .map_err(|_| invalid())?
                .timestamp();
            if stats.revision < 1
                || stats.usable_count < 0
                || stats.reserved_count < 0
                || until - as_of < 605400
                || (chrono::Utc::now().timestamp() - as_of).abs() > 300
            {
                return Err(invalid().into());
            }
        }
        let mut raw = self
            .mls_context()
            .read_direct_request_key_publication(&device)?;
        let previous = raw
            .as_deref()
            .map(|raw| DirectRequestKeyPublication::decode(raw, &owner, &device))
            .transpose()?;
        let previous_body = previous
            .as_ref()
            .map(DirectRequestKeyPublication::body)
            .transpose()?;
        let unresolved = previous.as_ref().is_some_and(|p| !p.acknowledged)
            && previous_body.as_ref().is_some_and(|b| {
                b["authGeneration"] == generation && previous.as_ref().unwrap().public_key == public
            });
        let expired = previous_body
            .as_ref()
            .and_then(|b| b["signedAt"].as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|t| chrono::Utc::now().signed_duration_since(t).num_seconds() > 300);
        let changed_preference = desired.is_some_and(|wanted| {
            previous_body
                .as_ref()
                .is_some_and(|b| b["enabled"] != wanted)
        });
        let replay = unresolved && !expired && !changed_preference;
        if !replay {
            let superseding = unresolved && (expired || changed_preference);
            let prior_revision = previous_body
                .as_ref()
                .and_then(|b| b["revision"].as_i64())
                .unwrap_or(0);
            let inherited =
                if superseding && stats.as_ref().is_none_or(|s| s.revision <= prior_revision) {
                    previous_body
                        .as_ref()
                        .and_then(|b| b["enabled"].as_bool())
                        .unwrap_or(false)
                } else {
                    stats.as_ref().is_some_and(|s| s.enabled)
                };
            let enabled = desired.unwrap_or(inherited);
            if desired.is_none() && !enabled && !superseding {
                return Ok(());
            }
            let total = stats
                .as_ref()
                .map(|s| s.usable_count.saturating_add(s.reserved_count))
                .unwrap_or(0);
            if desired.is_none()
                && !superseding
                && (total >= 64 || stats.as_ref().is_some_and(|s| s.usable_count >= 16))
            {
                return Ok(());
            }
            let prior_revision = previous_body
                .as_ref()
                .and_then(|b| b["revision"].as_i64())
                .unwrap_or(0);
            let revision = stats
                .as_ref()
                .map(|s| s.revision)
                .unwrap_or(0)
                .max(prior_revision)
                .checked_add(1)
                .ok_or_else(invalid)?;
            raw = self.mls_context().prepare_direct_request_key_publication(
                &DirectRequestKeyPublicationInput {
                    actor_did: owner.clone(),
                    actor_device_id: device.clone(),
                    auth_generation: generation,
                    revision,
                    count: if enabled {
                        64i64.saturating_sub(total).max(0) as u32
                    } else {
                        0
                    },
                    enabled,
                },
                raw.as_deref(),
            )?;
        }
        let Some(raw) = raw else {
            return Ok(());
        };
        let mut record = DirectRequestKeyPublication::decode(&raw, &owner, &device)?;
        let body = record.body()?;
        if body["authGeneration"] != generation || record.public_key != public {
            return Err(invalid().into());
        }
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::PublishDirectRequestKeys,
                method: "POST".into(),
                path: CanonicalOperation::PublishDirectRequestKeys.path().into(),
                body: Some(record.exact_request.clone()),
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::Api(format!(
                "Request key publication unresolved (HTTP {})",
                response.status
            )));
        }
        crate::chat_v2::transcript::decode_strict_json(&response.body).map_err(|_| invalid())?;
        let result: Value = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
        if result["revision"] != body["revision"] || result["enabled"] != body["enabled"] {
            return Err(invalid().into());
        }
        record.acknowledged = true;
        if !self
            .mls_context()
            .acknowledge_direct_request_key_publication(
                &device,
                &raw,
                &serde_json::to_vec(&record).map_err(|_| invalid())?,
            )?
        {
            return Err(invalid().into());
        }
        Ok(())
    }
}
