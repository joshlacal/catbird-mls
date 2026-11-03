//! Live `mls-ds` `/xrpc/blue.catbird.chat.*` data plane for `CatbirdMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! All network dispatches execute strictly outside `MlsAccountDb::write_tx` (`I6`).

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::client::chat_wire;
use crate::client::traits::{
    PlatformChangeEvent, PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse,
};
use crate::client::QueuedLabyrinthArchivePayload;
use crate::error::MLSError;
use crate::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use crate::groups::metadata_v1::{validate_metadata_snapshot_size, SpaceAvatarPointer};
use crate::messaging::receive::PrivateMessagePlaintextEnvelope;
use crate::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use crate::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use crate::orchestrator::direct_request_bootstrap::{self, DirectRequestBootstrapInput};
use crate::orchestrator::direct_request_keys::{
    DirectRequestKeyPublication, DirectRequestKeyPublicationInput,
};
use crate::orchestrator::direct_request_shared_crypto::build_request_key_publication;
use crate::push::AuthorizedPeerDeviceKey;
const ORDINARY_KP_LIFETIME_SECS: u64 = 29 * 86_400;
use crate::storage::driver_native::map_rusqlite_err;
use crate::storage::{
    ConversationRow, GroupMetadataRow, KvWriteBatch, KvWriteOverlay, LabyrinthQueueRow, MessageRow,
    OpenMlsKvStorage, RequestRow, RusqliteKvBackend,
};

use super::native_client::CatbirdMlsClient;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingApplicationSend {
    pub(crate) body: Value,
    pub(crate) archive: QueuedLabyrinthArchivePayload,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingCommitTransition {
    pub(crate) conversation_id: String,
    pub(crate) transition_id: String,
    pub(crate) commit_sha256: [u8; 32],
    pub(crate) prior: Value,
    pub(crate) next: Value,
    pub(crate) kv_batch: KvWriteBatch,
    #[serde(default)]
    pub(crate) removed_participant_did: Option<String>,
}

/// The membership effect of a generic `#commitTransitionBody` Commit (besides the mandatory
/// sender update). The generic form forbids participant changes: removing a participant is
/// this leaf removal followed by a `#policyTransitionBody` once the target has zero leaves.
#[derive(Clone, Copy)]
pub(crate) enum GenericCommitOp<'a> {
    RemoveLeaves {
        target_did: &'a str,
    },
    #[cfg_attr(not(feature = "sim"), allow(dead_code))]
    SelfUpdate,
}

/// `pending_ops` kind of a participant removal whose policy step has not been accepted.
pub(super) const PARTICIPANT_REMOVAL_OP: &str = "participant_removal";

pub(super) fn participant_removal_key(conversation_id: &str, target_did: &str) -> String {
    format!("{conversation_id}:{target_did}")
}

pub(super) fn participant_removal_payload(conversation_id: &str, target_did: &str) -> String {
    json!({ "conversation_id": conversation_id, "target_did": target_did }).to_string()
}

/// `pending_ops` kind holding the exact signed `acceptConversation` request per direct request:
/// the DS retains the first acceptance even when relaying it fails, so retries replay it.
pub(super) const DIRECT_REQUEST_ACCEPTANCE_OP: &str = "direct_request_acceptance";

/// A deterministic rejection: timeouts, Too Early, rate limits, and 5xx stay uncertain.
fn is_terminal_rejection(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 425 | 429)
}

#[derive(Deserialize)]
struct ChatProtocolFailure<'a> {
    #[serde(borrow)]
    error: std::borrow::Cow<'a, str>,
}

fn canonical_labyrinth_frame_for_text(input: &str) -> (String, String) {
    if serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(input).is_ok() {
        return (input.to_string(), input.to_string());
    }
    if let Ok(val) = serde_json::from_str::<Value>(input) {
        if let Some(txt) = val.get("text").and_then(|v| v.as_str()) {
            if let Ok(frame) =
                serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(txt))
            {
                return (input.to_string(), frame);
            }
        }
    }
    let display_json = json!({ "text": input }).to_string();
    let frame_json = serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(input))
        .unwrap_or_else(|_| display_json.clone());
    (display_json, frame_json)
}

impl CatbirdMlsClient {
    pub(crate) fn canonical_uuid_v4_device_id(&self) -> Option<String> {
        if crate::chat_v2::ids::BareDid::parse(&self.normalized_did).is_err() {
            return None;
        }
        uuid::Uuid::parse_str(self.config.device_id.trim())
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .map(|u| u.hyphenated().to_string())
    }

    pub(crate) fn ds_base(&self) -> String {
        self.config
            .home_ds_endpoint
            .trim_end_matches('/')
            .to_string()
    }

    pub(crate) fn pds_base(&self) -> String {
        self.config.pds_endpoint.trim_end_matches('/').to_string()
    }

    pub(crate) fn load_enrolled_signer_and_auth_gen(
        &self,
    ) -> Result<(SignatureKeyPair, i64), MLSError> {
        self.db.read_tx(|tx| {
            let signer_json = tx
                .get_account_meta("enrolled_signer_json")?
                .ok_or_else(|| {
                    MLSError::InvalidState("MLS device signer is not enrolled".to_string())
                })?;
            let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            Ok((signer, auth_gen))
        })
    }

    pub(crate) fn persist_pending_commit_transition(
        &self,
        pending: PendingCommitTransition,
    ) -> Result<KvWriteBatch, MLSError> {
        let payload = serde_json::to_string(&pending)
            .map_err(|e| MLSError::Internal(format!("serialize pending commit: {e}")))?;
        self.db.write_tx(|tx| {
            tx.put_pending_op(
                "commit_transition",
                &pending.transition_id,
                &payload,
                self.hooks.now_ms(),
            )
        })?;
        Ok(pending.kv_batch)
    }

    /// Retire private staged epoch keys as soon as their prior MLS state is superseded.
    pub(crate) fn prune_pending_commit_transitions(
        tx: &crate::storage::SqlTx<'_>,
        conversation_id: &str,
        generation: i64,
        epoch: i64,
        kicked: bool,
    ) -> Result<(), MLSError> {
        tx.conn()
            .execute(
                "DELETE FROM pending_ops WHERE op_kind = 'commit_transition' \
                 AND json_extract(payload_json, '$.conversation_id') = ?1 \
                 AND (?4 OR json_extract(payload_json, '$.prior.generation') < ?2 \
                   OR (json_extract(payload_json, '$.prior.generation') = ?2 \
                       AND json_extract(payload_json, '$.prior.epoch') < ?3))",
                rusqlite::params![conversation_id, generation, epoch, kicked],
            )
            .map_err(|e| map_rusqlite_err("prune pending commit transitions", &e))?;
        Ok(())
    }

    pub(crate) fn execute_json_post(
        &self,
        url: String,
        body: Vec<u8>,
    ) -> Result<PlatformHttpResponse, MLSError> {
        self.execute_json_post_with_pending_commit(url, body, None)
    }

    /// POST JSON outside `write_tx` (`I6`; planted `P3` moves it inside) and return the raw
    /// response.
    fn post_json_raw(&self, url: &str, body: Vec<u8>) -> Result<PlatformHttpResponse, MLSError> {
        let req = PlatformHttpRequest {
            method: "POST".to_string(),
            url: url.to_string(),
            headers: vec![PlatformHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: Some(body),
        };
        if crate::planted::is_planted_bug_active(crate::planted::PlantedBug::P3NetworkInsideWriteTx)
        {
            self.db.write_tx(|_tx| self.transport.execute_http(req))
        } else {
            self.transport.execute_http(req)
        }
    }

    fn execute_json_post_with_pending_commit(
        &self,
        url: String,
        body: Vec<u8>,
        pending_transition_id: Option<&str>,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let resp = self.post_json_raw(&url, body)?;
        if resp.status >= 400 {
            if serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body)
                .is_ok_and(|failure| failure.error == "StaleCoordinates")
            {
                return Err(MLSError::InvalidState("StaleCoordinates".into()));
            }
            // Other 4xx responses deterministically reject this attempt and must not retain
            // epoch keys.
            if is_terminal_rejection(resp.status) {
                if let Some(transition_id) = pending_transition_id {
                    self.db.write_tx(|tx| {
                        tx.delete_pending_op("commit_transition", transition_id)?;
                        Ok(())
                    })?;
                }
            }
            let snippet = String::from_utf8_lossy(&resp.body);
            return Err(MLSError::Internal(format!(
                "POST {url} failed with HTTP {}: {snippet}",
                resp.status
            )));
        }
        Ok(resp)
    }

    pub(crate) fn submit_signed_chat_op(
        &self,
        device_id: &str,
        auth_generation: Option<i64>,
        operation: CanonicalOperation,
        body_value: &Value,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.normalized_did,
            device_id,
            auth_generation,
            operation,
            body_value,
            signer,
        )?;
        let url = format!("{}{}", self.ds_base(), prepared.path);
        let pending_transition_id = if matches!(operation, CanonicalOperation::SubmitTransition) {
            body_value.get("transitionId").and_then(Value::as_str)
        } else {
            None
        };
        let resp = self.execute_json_post_with_pending_commit(
            url,
            prepared.body.unwrap_or_default(),
            pending_transition_id,
        )?;
        if resp.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MLSError::Internal(format!(
                "empty HTTP {} response body for {operation:?}",
                resp.status
            )));
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| MLSError::Internal(format!("parse {operation:?} JSON response: {e}")))
    }

    pub(crate) fn query_signed_chat_ds(
        &self,
        nsid: &str,
        params: &[(&str, &str)],
        device_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let canonical_query = chat_wire::canonical_query_string(params);
        let headers = chat_wire::build_chat_read_headers(
            nsid,
            &canonical_query,
            &self.normalized_did,
            device_id,
            signer,
            self.hooks.now_ms(),
        )?;
        let url = if canonical_query.is_empty() {
            format!("{}/xrpc/{nsid}", self.ds_base())
        } else {
            format!("{}/xrpc/{nsid}?{canonical_query}", self.ds_base())
        };
        let resp = self.transport.execute_http(PlatformHttpRequest {
            method: "GET".to_string(),
            url: url.clone(),
            headers,
            body: None,
        })?;
        if resp.status >= 400 {
            let snippet = String::from_utf8_lossy(&resp.body);
            return Err(MLSError::Internal(format!(
                "GET {url} failed with HTTP {}: {snippet}",
                resp.status
            )));
        }
        if resp.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MLSError::Internal(format!(
                "GET {url} returned empty HTTP {} body",
                resp.status
            )));
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| MLSError::Internal(format!("parse {nsid} JSON: {e}")))
    }

    pub(crate) fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        // 1. Try com.atproto.identity.resolveDid on PDS, then .well-known/did.json for did:web / home_ds_did.
        let pds_resolve_url = format!(
            "{}/xrpc/com.atproto.identity.resolveDid?did={}",
            self.pds_base(),
            chat_wire::urlencode_form_component(did)
        );
        if let Ok(resp) = self.transport.execute_http(PlatformHttpRequest {
            method: "GET".to_string(),
            url: pds_resolve_url,
            headers: Vec::new(),
            body: None,
        }) {
            if resp.status == 200 {
                if let Ok(doc_bytes) = chat_wire::extract_did_doc_from_resolve_response(&resp.body)
                {
                    let now_ms = self.hooks.now_ms();
                    let _ = self.db.write_tx(|tx| {
                        tx.put_account_meta(
                            &format!("did_doc:{did}"),
                            &String::from_utf8_lossy(&doc_bytes),
                            now_ms,
                        )
                    });
                    return Ok(Some(doc_bytes));
                }
            }
        }

        if let Some(rest) = did.strip_prefix("did:web:") {
            let authority = rest.replace("%3A", ":").replace("%3a", ":");
            let scheme = if authority.starts_with("127.0.0.1") || authority.starts_with("localhost")
            {
                "http"
            } else {
                "https"
            };
            let wk_url = format!("{scheme}://{authority}/.well-known/did.json");
            if let Ok(resp) = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: wk_url,
                headers: Vec::new(),
                body: None,
            }) {
                if resp.status == 200 {
                    if let Ok(doc_bytes) =
                        chat_wire::extract_did_doc_from_resolve_response(&resp.body)
                    {
                        let now_ms = self.hooks.now_ms();
                        let _ = self.db.write_tx(|tx| {
                            tx.put_account_meta(
                                &format!("did_doc:{did}"),
                                &String::from_utf8_lossy(&doc_bytes),
                                now_ms,
                            )
                        });
                        return Ok(Some(doc_bytes));
                    }
                }
            }
        }

        if did == self.config.home_ds_did {
            let wk_url = format!("{}/.well-known/did.json", self.ds_base());
            if let Ok(resp) = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: wk_url,
                headers: Vec::new(),
                body: None,
            }) {
                if resp.status == 200 {
                    if let Ok(doc_bytes) =
                        chat_wire::extract_did_doc_from_resolve_response(&resp.body)
                    {
                        return Ok(Some(doc_bytes));
                    }
                }
            }
        }

        let cached = self
            .db
            .read_tx(|tx| tx.get_account_meta(&format!("did_doc:{did}")))?;
        Ok(cached.map(|s| s.into_bytes()))
    }

    pub(crate) fn resolve_sequencer_receipt_key(
        &self,
        sequencer_did: &str,
        kid_hint: &str,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        if let Some(doc_bytes) = self.resolve_did_document(sequencer_did)? {
            let key =
                chat_wire::decode_p256_sec1_from_did_doc(&doc_bytes, sequencer_did, kid_hint)?;
            return Ok(Some(key));
        }
        Ok(None)
    }

    /// Resolve and cache `ADR-009` `blue.catbird.chat.device` records for `target_did` (`Spec §5 I4`).
    pub(crate) fn fetch_and_cache_authorized_pds_device_keys(
        &self,
        target_did: &str,
    ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
        let pds_endpoint = self
            .resolve_did_document(target_did)?
            .and_then(|doc| chat_wire::extract_pds_endpoint_from_did_doc(&doc))
            .unwrap_or_else(|| self.pds_base());

        let list_url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=blue.catbird.chat.device&limit=100",
            pds_endpoint.trim_end_matches('/'),
            chat_wire::urlencode_form_component(target_did),
        );
        let resp = self.transport.execute_http(PlatformHttpRequest {
            method: "GET".to_string(),
            url: list_url,
            headers: Vec::new(),
            body: None,
        })?;
        if resp.status >= 400 {
            return Err(MLSError::Internal(format!(
                "I4 PDS listRecords({target_did}) failed with HTTP {}",
                resp.status
            )));
        }

        let pairs = chat_wire::parse_pds_device_list_records(target_did, &resp.body)?;
        let authorized: Vec<AuthorizedPeerDeviceKey> = pairs
            .into_iter()
            .map(
                |(device_id, signature_public_key)| AuthorizedPeerDeviceKey {
                    did: target_did.to_string(),
                    device_id,
                    signature_public_key,
                },
            )
            .collect();

        let now_ms = self.hooks.now_ms();
        let encoded =
            serde_json::to_string(&authorized).map_err(|e| MLSError::Internal(e.to_string()))?;
        self.db.write_tx(|tx| {
            tx.put_account_meta(
                &format!("authorized_device_keys:{target_did}"),
                &encoded,
                now_ms,
            )
        })?;
        Ok(authorized)
    }

    pub(crate) fn resolve_peer_home_ds_did(&self, target_did: &str) -> Option<String> {
        let pds_endpoint = self
            .resolve_did_document(target_did)
            .ok()
            .flatten()
            .and_then(|doc| chat_wire::extract_pds_endpoint_from_did_doc(&doc))
            .unwrap_or_else(|| self.pds_base());
        let url = format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.declaration&rkey=self",
            pds_endpoint.trim_end_matches('/'),
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
            .ok()?;
        if resp.status != 200 {
            return None;
        }
        let val: Value = serde_json::from_slice(&resp.body).ok()?;
        val.pointer("/value/deliveryService")
            .or_else(|| val.pointer("/value/homeDsDid"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    pub(crate) fn enroll_device_live(
        &self,
        canonical_device_id: &str,
        pub_key: &[u8],
    ) -> Result<(), MLSError> {
        // 1. Publish ADR-009 PDS `blue.catbird.chat.device/{device_id}` + `blue.catbird.chat.declaration/self`.
        let put_record_url = format!("{}/xrpc/com.atproto.repo.putRecord", self.pds_base());
        let dev_record_body = chat_wire::build_pds_device_put_record_body_at(
            &self.normalized_did,
            canonical_device_id,
            pub_key,
            &self.hooks.now_rfc3339_millis(),
        )?;
        let _ = self.execute_json_post(put_record_url.clone(), dev_record_body)?;

        let decl_body = chat_wire::build_pds_chat_declaration_put_record_body_at(
            &self.normalized_did,
            &self.config.home_ds_did,
            &self.hooks.now_rfc3339_millis(),
        )?;
        let _ = self.execute_json_post(put_record_url, decl_body)?;

        // 2. Build 2 X-Wing KeyPackages in `write_tx` (`MlsMessageOut` framing, sorted by hash_ref).
        let now_secs = self.hooks.now_secs();
        let (signer, key_packages_json) = self.db.write_tx(|tx| {
            let signer_json = tx
                .get_account_meta("enrolled_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("signer missing".to_string()))?;
            let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let scoped_id = format!("{}#{}", self.normalized_did, canonical_device_id);
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                signature_key: signer.public().into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(2);
            for _ in 0..2 {
                let kp_bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_secs.saturating_sub(60),
                        now_secs + ORDINARY_KP_LIFETIME_SECS,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build enroll KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(kp_bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize enroll KP: {e:?}")))?;
                let kp_ref = kp_bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                let sha_b64 = STANDARD.encode(Sha256::digest(&kp_bytes));
                let entry = json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                    "sha256": sha_b64,
                    "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                });
                items.push((kp_ref, entry));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            let kps: Vec<Value> = items.into_iter().map(|(_, v)| v).collect();
            Ok((signer, kps))
        })?;

        let key_id = derive_key_id(pub_key);
        let idem = self.hooks.uuid_v4().to_string();
        let enroll_body = json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\0",
            "actorDid": self.normalized_did,
            "deviceId": canonical_device_id,
            "deviceName": "Catbird",
            "keyId": key_id,
            "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": key_packages_json,
            "idempotencyKey": idem,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });

        let enroll_resp = self.submit_signed_chat_op(
            canonical_device_id,
            None,
            CanonicalOperation::EnrollDevice,
            &enroll_body,
            &signer,
        )?;
        let auth_generation = enroll_resp
            .get("device")
            .and_then(|d| d.get("authGeneration"))
            .and_then(|g| g.as_i64())
            .or_else(|| enroll_resp.get("authGeneration").and_then(|g| g.as_i64()))
            .ok_or_else(|| {
                MLSError::Internal("enrollDevice response missing authGeneration".to_string())
            })?
            .max(1);

        // 3. Persist authoritative `auth_generation` + generate C33 DirectRequestKeyPublication.
        let now_ms = self.hooks.now_ms();
        let dr_exact_request = self.db.write_tx(|tx| {
            tx.put_account_meta("auth_generation", &auth_generation.to_string(), now_ms)?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let (raw_pub_rec, _bundles) = build_request_key_publication(
                &provider,
                &signer,
                &DirectRequestKeyPublicationInput {
                    actor_did: self.normalized_did.clone(),
                    actor_device_id: canonical_device_id.to_string(),
                    auth_generation,
                    revision: 1,
                    enabled: true,
                    count: 8,
                },
                now_secs as i64,
            )?;
            let parsed_rec: DirectRequestKeyPublication = serde_json::from_slice(&raw_pub_rec)
                .map_err(|e| {
                    MLSError::Internal(format!("parse DirectRequestKeyPublication: {e}"))
                })?;
            Ok(parsed_rec.exact_request)
        })?;

        // 4. Publish C33 direct-request keys + replenish conversation key packages.
        let dr_keys_url = format!(
            "{}/xrpc/blue.catbird.chat.publishDirectRequestKeys",
            self.ds_base()
        );
        let _ = self.execute_json_post(dr_keys_url, dr_exact_request)?;
        let _ = self.replenish_key_packages(4)?;
        Ok(())
    }

    /// Generate and upload `count` fresh `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` key packages.
    pub fn replenish_key_packages(&self, count: u32) -> Result<u32, MLSError> {
        let clamped = count.clamp(1, 32);
        let now_secs = self.hooks.now_secs();
        let device_str = self
            .canonical_uuid_v4_device_id()
            .unwrap_or_else(|| self.config.device_id.clone());

        let (signer, auth_generation, kps_json) = self.db.write_tx(|tx| {
            let signer_json = tx
                .get_account_meta("enrolled_signer_json")?
                .ok_or_else(|| {
                    MLSError::InvalidState("MLS device signer not enrolled".to_string())
                })?;
            let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let scoped_id = format!("{}#{}", self.normalized_did, device_str);
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                signature_key: signer.public().into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(clamped as usize);
            for _ in 0..clamped {
                let bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_secs.saturating_sub(60),
                        now_secs + ORDINARY_KP_LIFETIME_SECS,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build replenish KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize replenish KP: {e:?}")))?;
                let kp_ref = bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                let sha_b64 = STANDARD.encode(Sha256::digest(&kp_bytes));
                items.push((
                    kp_ref.clone(),
                    json!({
                        "framing": "mlsMessage",
                        "contentType": "keyPackage",
                        "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                        "sha256": sha_b64,
                        "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                    }),
                ));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Ok((
                signer,
                auth_gen,
                items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            ))
        })?;

        if let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() {
            let pub_key = signer.public();
            let key_id = derive_key_id(pub_key);
            let idem = self.hooks.uuid_v4().to_string();
            let body = json!({
                "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\0",
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "authGeneration": auth_generation,
                "idempotencyKey": idem,
                "keyId": key_id,
                "keyPackages": kps_json,
                "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            let _ = self.submit_signed_chat_op(
                &canonical_dev_id,
                Some(auth_generation),
                CanonicalOperation::ReplenishKeyPackages,
                &body,
                &signer,
            )?;
        }

        Ok(clamped)
    }

    pub(crate) fn create_group_live_or_offline(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
        member_dids: Vec<String>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if trimmed.is_empty() {
                continue;
            }
            let norm = super::normalize_account_did(trimmed)?;
            if norm != self.normalized_did {
                peer_set.insert(norm);
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();

        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return self.create_group_local_offline(
                conversation_id,
                sequencer_did,
                title,
                description,
            );
        };
        let Ok(convo_uuid) = uuid::Uuid::parse_str(conversation_id.trim())
            .ok()
            .filter(|u| u.get_version_num() == 4)
            .ok_or(())
        else {
            if peers.is_empty() {
                return self.create_group_local_offline(
                    conversation_id,
                    sequencer_did,
                    title,
                    description,
                );
            }
            return Err(MLSError::invalid_input(
                "live create_group with member_dids requires a canonical UUIDv4 conversation_id",
            ));
        };
        for peer in &peers {
            if let Err(e) = crate::chat_v2::ids::BareDid::parse(peer) {
                return Err(MLSError::invalid_input(format!(
                    "peer DID '{peer}' is not a valid bare DID: {e}"
                )));
            }
        }
        let canonical_convo_id = convo_uuid.hyphenated().to_string();

        // Verify PDS `blue.catbird.chat.device` keys (`I4`) for all peers up front.
        let mut auth_keys_by_did: BTreeMap<String, Vec<AuthorizedPeerDeviceKey>> = BTreeMap::new();
        auth_keys_by_did.insert(
            self.normalized_did.clone(),
            self.fetch_and_cache_authorized_pds_device_keys(&self.normalized_did)?,
        );
        for peer in &peers {
            auth_keys_by_did.insert(
                peer.clone(),
                self.fetch_and_cache_authorized_pds_device_keys(peer)?,
            );
        }

        let is_untitle_one_to_one =
            peers.len() == 1 && title.as_deref().unwrap_or("").trim().is_empty();
        if is_untitle_one_to_one {
            return self.create_c33_direct_request_live(
                &canonical_convo_id,
                sequencer_did,
                &canonical_dev_id,
                &peers[0],
                description,
                &auth_keys_by_did,
            );
        }

        self.create_group_conversation_live(
            &canonical_convo_id,
            &convo_uuid,
            sequencer_did,
            &canonical_dev_id,
            &peers,
            title,
            description,
        )
    }

    fn create_c33_direct_request_live(
        &self,
        canonical_convo_id: &str,
        sequencer_did: &str,
        canonical_dev_id: &str,
        peer_did: &str,
        description: Option<String>,
        auth_keys_by_did: &BTreeMap<String, Vec<AuthorizedPeerDeviceKey>>,
    ) -> Result<ConversationRow, MLSError> {
        let (signer, auth_generation) = self.load_enrolled_signer_and_auth_gen()?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
        let request_id = self.hooks.uuid_v4().to_string();
        let first_message_id = self.hooks.uuid_v4().to_string();

        let prepare_body = json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": key_id,
            "authGeneration": auth_generation,
            "requestId": request_id,
            "firstMessageId": first_message_id,
            "conversationId": canonical_convo_id,
            "recipientDid": peer_did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": request_id,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });

        let prepare_wrapper_bytes = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Prepare,
            prepare_body.clone(),
            &signer,
        )?;
        let prepare_verified = dr_transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &prepare_wrapper_bytes,
            signer.public(),
        )
        .map_err(|e| MLSError::Cryptography(format!("verify self C33 prepare: {e}")))?;
        let prepare_wrapper_val: Value = serde_json::from_slice(&prepare_wrapper_bytes)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        let prepare_url = format!(
            "{}/xrpc/blue.catbird.chat.prepareDirectRequest",
            self.ds_base()
        );
        let prepare_http = self.execute_json_post(
            prepare_url,
            serde_json::to_vec(&json!({ "signedRequest": prepare_wrapper_val }))
                .map_err(|e| MLSError::Internal(e.to_string()))?,
        )?;

        let prep_outer: Value = serde_json::from_slice(&prepare_http.body)
            .map_err(|e| MLSError::Internal(format!("parse prepareDirectRequest: {e}")))?;
        let preparation = prep_outer
            .pointer("/outcome/preparation")
            .or_else(|| prep_outer.get("preparation"))
            .or_else(|| prep_outer.get("outcome"))
            .unwrap_or(&prep_outer);
        let selected = preparation
            .get("selectedDevices")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                MLSError::Internal(format!(
                    "prepareDirectRequest did not return selectedDevices: {prep_outer}"
                ))
            })?;

        let mut packages: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut min_deadline = u64::MAX;

        for dev in selected {
            let d_did = dev
                .get("actorDid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::invalid_input("selectedDevice missing actorDid"))?;
            let _d_dev_id = dev
                .get("actorDeviceId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::invalid_input("selectedDevice missing actorDeviceId"))?;
            let kp_bytes = chat_wire::json_bytes(&dev["keyPackage"]["bytes"])?;
            let kp_ref = chat_wire::json_bytes(&dev["keyPackage"]["keyPackageRef"])?;

            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize selected KP: {e:?}")))?
                    .extract()
            else {
                return Err(MLSError::Cryptography(
                    "selectedDevice bytes is not a KeyPackage".to_string(),
                ));
            };

            // Enforce I4 (`ADR-009`) against PDS `blue.catbird.chat.device` BEFORE group creation!
            let authorized_for_did = auth_keys_by_did
                .get(d_did)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_slice_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                authorized_for_did,
            )?;

            let exp_str = dev["grant"]["body"]["expiresAt"]
                .as_str()
                .ok_or_else(|| MLSError::invalid_input("grant missing expiresAt"))?;
            let exp_secs = chrono::DateTime::parse_from_rfc3339(exp_str)
                .map_err(|e| MLSError::invalid_input(format!("invalid grant expiresAt: {e}")))?
                .timestamp()
                .max(0) as u64;
            min_deadline = min_deadline.min(exp_secs);
            packages.push(kp_bytes);
            refs.push(kp_ref);
        }

        let authority_did = preparation
            .get("authorityDid")
            .and_then(|v| v.as_str())
            .unwrap_or(sequencer_did);
        let receipt_kid = preparation
            .get("receiptKeyId")
            .and_then(|v| v.as_str())
            .unwrap_or("#mls-receipt-1");
        let authority_key = self
            .resolve_sequencer_receipt_key(authority_did, receipt_kid)?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "C33/I13: unable to resolve `{authority_did}` DID document for `{receipt_kid}`"
                ))
            })?;

        let effective_convo_id = preparation
            .get("conversationId")
            .and_then(|v| v.as_str())
            .unwrap_or(canonical_convo_id)
            .to_string();
        let prep_digest_b64 =
            STANDARD.encode(chat_wire::json_bytes(&preparation["preparationDigest"])?);
        let context_val = json!({
            "protocolVersion": "2",
            "requestId": request_id,
            "firstMessageId": first_message_id,
            "conversationId": effective_convo_id,
            "origin": prepare_body["origin"],
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "actorKeyId": key_id,
            "recipientDid": peer_did,
            "preparationDigest": prep_digest_b64,
        });
        let context_json =
            serde_json::to_vec(&context_val).map_err(|e| MLSError::Internal(e.to_string()))?;

        let intro_text = description
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "👋".to_string());
        let group_id_bytes = self.hooks.random_array::<32>().to_vec();
        let now_secs = self.hooks.now_secs();

        let (bootstrap, kv_batch) = self.db.read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let boot = {
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = self.hooks.openmls_provider(storage);
                let (_group, boot) = direct_request_bootstrap::prepare_with_provider(
                    &provider,
                    &signer,
                    &DirectRequestBootstrapInput {
                        draft_id: request_id.clone(),
                        context_json,
                        group_id: group_id_bytes.clone(),
                        generation: 0,
                        state_version: 1,
                        key_packages: packages,
                        expected_package_refs: refs,
                        authority_import_until: min_deadline,
                        preparation_request_digest: *prepare_verified.request_digest(),
                        receipt_authority_key: authority_key,
                        text: intro_text.clone(),
                        invitation: None,
                        metadata: GroupMetadataV1 {
                            version: 1,
                            title: String::new(),
                            description: String::new(),
                            avatar_blob_locator: None,
                            avatar_content_type: None,
                            space_avatar: None,
                        },
                    },
                    now_secs,
                )?;
                boot
            };
            Ok((boot, overlay.into_batch()))
        })?;

        let import_until = bootstrap.import_until;
        let import_until_str = chat_wire::unix_secs_rfc3339_millis(import_until)?;
        let artifact = |data: &[u8], content_type: &str| {
            json!({
                "framing": "mlsMessage",
                "contentType": content_type,
                "bytes": STANDARD.encode(data),
                "sha256": STANDARD.encode(Sha256::digest(data)),
            })
        };
        let mut deliveries: Vec<Value> = Vec::with_capacity(selected.len());
        for d in selected {
            let kp_ref_b64 =
                STANDARD.encode(chat_wire::json_bytes(&d["keyPackage"]["keyPackageRef"])?);
            deliveries.push(json!({
                "recipientDid": d["actorDid"],
                "recipientDeviceId": d["actorDeviceId"],
                "provenance": {
                    "requestId": request_id,
                    "preparationDigest": prep_digest_b64,
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": d["grant"]["body"]["grantId"],
                    "grantRevision": d["grant"]["body"]["grantRevision"],
                    "keyPackageRef": kp_ref_b64,
                    "importUntil": import_until_str,
                }
            }));
        }
        let author_proof = json!({
            "authorDid": self.normalized_did,
            "authorDeviceId": canonical_dev_id,
            "authorKeyId": key_id,
            "signaturePublicKey": STANDARD.encode(signer.public()),
            "authGenerationAtOrigin": auth_generation,
            "originTransitionId": request_id,
            "originSeq": 1,
            "roleAtOrigin": "admin",
            "deviceStatusAtOrigin": "active",
        });

        let mut publish_body = prepare_verified.body().clone();
        publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        publish_body["signedAt"] = json!(self.hooks.now_rfc3339_millis());
        publish_body["preparationDigest"] = json!(prep_digest_b64);
        publish_body["preparationRequestDigest"] =
            json!(STANDARD.encode(prepare_verified.request_digest()));
        publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
        publish_body["next"] = bootstrap.coordinates.clone();
        publish_body["importUntil"] = json!(import_until_str);
        publish_body["artifacts"] = json!({
            "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
            "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
            "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
            "welcome": {
                "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
                "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
                "deliveries": deliveries,
            },
            "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext),
            "metadataSnapshot": {
                "coordinate": direct_request_bootstrap::metadata_coordinate(&bootstrap.coordinates)?,
                "originTransitionId": request_id,
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
                "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
                "ciphertextSize": bootstrap.metadata_ciphertext.len(),
                "authorProof": author_proof,
            }
        });

        let publish_wrapper_bytes = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Publish,
            publish_body,
            &signer,
        )?;
        let publish_wrapper_val: Value = serde_json::from_slice(&publish_wrapper_bytes)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let publish_url = format!(
            "{}/xrpc/blue.catbird.chat.publishDirectRequest",
            self.ds_base()
        );
        if crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
        ) {
            self.db.write_tx(|tx| {
                self.clear_cached_groups();
                Ok(kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
            })?;
        }
        let _ = self.execute_json_post(
            publish_url,
            serde_json::to_vec(&json!({ "signedRequest": publish_wrapper_val }))
                .map_err(|e| MLSError::Internal(e.to_string()))?,
        )?;

        let own_ds = self.config.home_ds_did.trim();
        let effective_sequencer = if !own_ds.is_empty() && own_ds <= authority_did {
            own_ds.to_string()
        } else {
            authority_did.to_string()
        };
        let space_uri = Some(format!(
            "at://{effective_sequencer}/space/blue.catbird.labyrinth.conversation/{effective_convo_id}-0"
        ));
        let now_ms = self.hooks.now_ms();
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(&intro_text);
        let coords_str = serde_json::to_string(&bootstrap.coordinates)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        let convo_row = self.db.write_tx(|tx| {
            kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
            self.clear_cached_groups();
            let row = ConversationRow {
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                generation: 0,
                epoch: 1,
                last_seq: 1,
                sequencer_did: effective_sequencer.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: 0,
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{effective_convo_id}"),
                &coords_str,
                now_ms,
            )?;
            tx.upsert_request(&RequestRow {
                request_id: request_id.clone(),
                conversation_id: effective_convo_id.clone(),
                sender_did: self.normalized_did.clone(),
                recipient_did: peer_did.to_string(),
                consent: "outgoingPending".to_string(),
                first_message_id: Some(first_message_id.clone()),
                first_message_archived: false,
                payload_json: display_json.clone(),
                expires_at_ms: (import_until as i64).saturating_mul(1000),
                updated_at_ms: now_ms,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.clone(),
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                epoch: 1,
                seq: 1,
                sender_did: self.normalized_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                plaintext_json: display_json.clone(),
                created_at_ms: now_ms,
                is_own: true,
            })?;

            // Stage C33 opening message for conversation Space archival ONLY after recipient acceptance!
            let staged_opening = QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id,
                conversation_id: effective_convo_id.clone(),
                group_id_hex: hex::encode(&group_id_bytes),
                epoch: 1,
                seq: 1,
                sender_did: self.normalized_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sequencer_did: effective_sequencer,
                space_uri,
                plaintext_json: display_json,
                labyrinth_frame_json: frame_json,
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: None,
                sequencer_receipt_json: None,
                created_at_ms: now_ms,
            };
            tx.put_account_meta(
                &format!("c33_pending_opening:{effective_convo_id}"),
                &serde_json::to_string(&staged_opening)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            Ok(row)
        })?;

        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        Ok(convo_row)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_group_conversation_live(
        &self,
        canonical_convo_id: &str,
        convo_uuid: &uuid::Uuid,
        sequencer_did: &str,
        canonical_dev_id: &str,
        peers: &[String],
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let group_id_bytes = self.hooks.random_array::<32>().to_vec();
        let now_secs = self.hooks.now_secs();
        let now_ms = self.hooks.now_ms();
        let transition_id = self.hooks.uuid_v4().to_string();
        let title_str = title.clone().unwrap_or_default();
        let desc_str = description.clone().unwrap_or_default();

        let (
            signer,
            new_signer_json,
            auth_generation,
            ggi_bytes,
            gch,
            ctag,
            meta_snap_json,
            kv_batch,
        ) = self.db.read_tx(|tx| {
            let signer_json = tx.get_account_meta("enrolled_signer_json")?;
            let (signer, new_signer_str) = if let Some(raw) = signer_json {
                let s = serde_json::from_str::<SignatureKeyPair>(&raw)
                    .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
                (s, None)
            } else {
                let s = self
                    .hooks
                    .signature_keypair(CIPHERSUITE.signature_algorithm())?;
                let serialized =
                    serde_json::to_string(&s).map_err(|e| MLSError::Internal(e.to_string()))?;
                (s, Some(serialized))
            };
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);

            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let (ggi, gch, ctag, snap) = {
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = self.hooks.openmls_provider(storage);
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store group signer: {e:?}")))?;

                let scoped_id = format!("{}#{}", self.normalized_did, canonical_dev_id);
                let caps = Capabilities::new(
                    Some(&[ProtocolVersion::Mls10]),
                    Some(&[CIPHERSUITE]),
                    Some(&[]),
                    Some(&[]),
                    Some(&[CredentialType::Basic]),
                );
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .capabilities(caps)
                    .lifetime(Lifetime::init(
                        now_secs.saturating_sub(60),
                        now_secs + 29 * 86_400,
                    ))
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .max_past_epochs(5)
                    .build();

                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    CredentialWithKey {
                        credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                        signature_key: signer.public().into(),
                    },
                )
                .map_err(|e| MLSError::Cryptography(format!("create X-Wing group: {e:?}")))?;

                let ggi = group
                    .export_group_info(provider.crypto(), &signer, true)
                    .map_err(|e| MLSError::Cryptography(format!("export_group_info: {e:?}")))?
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize ggi: {e:?}")))?;
                let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let meta_key = derive_metadata_key_from_group(
                    &mut group,
                    provider.crypto(),
                    provider.storage(),
                    &group_id_bytes,
                    0,
                )
                .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                let snap = chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
                    &meta_key,
                    &group_id_bytes,
                    convo_uuid,
                    0,
                    0,
                    &gch,
                    &ctag,
                    &transition_id,
                    1,
                    1,
                    &self.normalized_did,
                    canonical_dev_id,
                    auth_gen,
                    signer.public(),
                    &title_str,
                    &desc_str,
                    None,
                    self.hooks.random_array::<12>(),
                )?;
                (ggi, gch, ctag, snap)
            };

            Ok((
                signer,
                new_signer_str,
                auth_gen,
                ggi,
                gch,
                ctag,
                snap,
                overlay.into_batch(),
            ))
        })?;

        let mut participants = vec![json!({
            "userDid": self.normalized_did,
            "status": "active",
            "role": "admin"
        })];
        for peer in peers {
            participants.push(json!({
                "userDid": peer,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitationTransitionId": transition_id,
                    "invitedByDid": self.normalized_did,
                    "invitedByDeviceId": canonical_dev_id,
                }
            }));
        }
        participants.sort_by(|a, b| {
            a["userDid"]
                .as_str()
                .unwrap_or("")
                .cmp(b["userDid"].as_str().unwrap_or(""))
        });

        let next_coords = json!({
            "conversationId": canonical_convo_id,
            "generation": 0,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
            "epoch": 0,
            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
            "lifecycle": "active",
        });

        let create_body = json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "signatureDomain": "CATBIRD-CHAT-CREATE\0",
            "conversationId": canonical_convo_id,
            "conversationKind": "group",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_generation,
            "absence": true,
            "next": next_coords,
            "manifest": {
                "participants": participants,
                "actorLeaf": {
                    "userDid": self.normalized_did,
                    "deviceId": canonical_dev_id,
                    "leafOrigin": "genesis",
                }
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(&ggi_bytes) },
                "sha256": STANDARD.encode(Sha256::digest(&ggi_bytes)),
            },
            "metadataSnapshot": meta_snap_json,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });

        if crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
        ) {
            self.db.write_tx(|tx| {
                self.clear_cached_groups();
                Ok(kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
            })?;
        }
        let resp_val = self.submit_signed_chat_op(
            canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::CreateConversation,
            &create_body,
            &signer,
        )?;

        let server_coords = resp_val
            .get("state")
            .and_then(|s| s.get("coordinates"))
            .or_else(|| resp_val.get("coordinates"))
            .cloned()
            .unwrap_or(next_coords);
        let server_seq = resp_val
            .get("seq")
            .and_then(|s| s.as_i64())
            .or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("seq"))
                    .and_then(|s| s.as_i64())
            })
            .unwrap_or(1)
            .max(1);
        let generation = server_coords
            .get("generation")
            .and_then(|g| g.as_i64())
            .unwrap_or(0);
        let space_uri = Some(format!(
            "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{canonical_convo_id}-{generation}"
        ));
        let coords_str =
            serde_json::to_string(&server_coords).map_err(|e| MLSError::Internal(e.to_string()))?;
        let snap_str = serde_json::to_string(&meta_snap_json)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        let convo = self.db.write_tx(|tx| {
            if let Some(ref raw_signer) = new_signer_json {
                tx.put_account_meta("enrolled_signer_json", raw_signer, now_ms)?;
            }
            kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
            self.clear_cached_groups();
            if title.is_some() || description.is_some() {
                let meta_v1 = GroupMetadataV1 {
                    version: 1,
                    title: title_str.clone(),
                    description: desc_str.clone(),
                    avatar_blob_locator: None,
                    avatar_content_type: None,
                    space_avatar: None,
                };
                let meta_row = chat_wire::group_metadata_row_from_v1(
                    canonical_convo_id,
                    1,
                    0,
                    &meta_v1,
                    now_ms,
                )?;
                tx.upsert_group_metadata(&meta_row)?;
            }
            let row = ConversationRow {
                conversation_id: canonical_convo_id.to_string(),
                group_id: group_id_bytes,
                generation,
                epoch: 0,
                last_seq: server_seq,
                sequencer_did: sequencer_did.to_string(),
                space_uri,
                title: title.clone(),
                unread_count: 0,
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{canonical_convo_id}"),
                &coords_str,
                now_ms,
            )?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{canonical_convo_id}"),
                &snap_str,
                now_ms,
            )?;
            Ok(row)
        })?;

        self.cache_title_if_present(canonical_convo_id, &convo.title);
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(convo)
    }

    /// Invite or add `member_dids` to an existing group conversation (`#policyTransitionBody` + leaf-recovery fulfillment).
    pub fn add_group_members(
        &self,
        conversation_id: &str,
        member_dids: Vec<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if trimmed.is_empty() {
                continue;
            }
            let norm = super::normalize_account_did(trimmed)?;
            if norm != self.normalized_did {
                peer_set.insert(norm);
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();

        let existing = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {conversation_id} not found"),
            })?;
        if peers.is_empty() {
            return Ok(existing);
        }

        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(existing);
        };

        for peer in &peers {
            let _ = self.fetch_and_cache_authorized_pds_device_keys(peer)?;
        }

        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords
            .get("stateVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let mut next_coords = prior_coords.clone();
        next_coords["stateVersion"] = json!(prior_sv + 1);

        let (signer, auth_generation) = self.load_enrolled_signer_and_auth_gen()?;
        let transition_id = self.hooks.uuid_v4().to_string();
        let changes: Vec<Value> = peers
            .iter()
            .map(|peer| {
                json!({
                    "$type": "blue.catbird.chat.defs#addParticipant",
                    "userDid": peer,
                    "role": "member",
                    "status": "pending",
                    "invitationProvenance": {
                        "$type": "blue.catbird.chat.defs#invitationProvenance",
                        "invitationTransitionId": transition_id,
                        "invitedByDid": self.normalized_did,
                        "invitedByDeviceId": canonical_dev_id,
                    }
                })
            })
            .collect();

        let policy_body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_generation,
            "prior": prior_coords,
            "next": next_coords,
            "participantChanges": changes,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });

        let resp_val = self.submit_signed_chat_op(
            &canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::SubmitTransition,
            &policy_body,
            &signer,
        )?;
        let updated_coords = resp_val
            .get("state")
            .and_then(|s| s.get("coordinates"))
            .or_else(|| resp_val.get("coordinates"))
            .cloned()
            .unwrap_or(next_coords);
        let new_seq = resp_val
            .get("seq")
            .and_then(|s| s.as_i64())
            .or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("seq"))
                    .and_then(|s| s.as_i64())
            })
            .unwrap_or(existing.last_seq.saturating_add(1));
        let now_ms = self.hooks.now_ms();
        let coords_str = serde_json::to_string(&updated_coords)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        let (updated, needs_gap_sync) = self.db.write_tx(|tx| {
            let mut row = tx.get_conversation(conversation_id)?.unwrap_or(existing);
            let mut gap = false;
            if new_seq == row.last_seq.saturating_add(1) {
                row.last_seq = new_seq;
            } else if new_seq > row.last_seq.saturating_add(1) {
                gap = true;
            }
            row.updated_at_ms = now_ms;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords_str,
                now_ms,
            )?;
            Ok((row, gap))
        })?;

        if needs_gap_sync {
            let _ = self.sync_conversation_entries(&canonical_dev_id, &signer, &updated);
        }

        let _ = self.fulfill_pending_leaf_recoveries(&canonical_dev_id, &signer, auth_generation);
        let refreshed = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .unwrap_or(updated);
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(refreshed)
    }

    pub(crate) fn load_or_build_conversation_coords(
        &self,
        conversation_id: &str,
    ) -> Result<Value, MLSError> {
        if self.is_conversation_closed(conversation_id)? {
            return Err(MLSError::InvalidState("conversation is closed".to_string()));
        }
        if let Some(raw) = self
            .db
            .read_tx(|tx| tx.get_account_meta(&format!("conversation_coords:{conversation_id}")))?
        {
            let parsed: Value =
                serde_json::from_str(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            return chat_wire::canonicalize_wire_coordinate(&parsed, Some(conversation_id));
        }
        self.db.read_tx(|tx| {
            let convo =
                tx.get_conversation(conversation_id)?
                    .ok_or_else(|| MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    })?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                .ok_or_else(|| MLSError::GroupNotFound {
                    message: format!("MlsGroup missing for {conversation_id}"),
                })?;
            let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            Ok(json!({
                "conversationId": conversation_id,
                "generation": convo.generation,
                "stateVersion": 0,
                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                "epoch": group.epoch().as_u64(),
                "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                "lifecycle": "active",
            }))
        })
    }

    pub(crate) fn send_message_live_or_offline(
        &self,
        conversation_id: &str,
        message_id: &str,
        text: &str,
    ) -> Result<MessageRow, MLSError> {
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(text);
        let frame_nonce = self.hooks.random_array::<32>();
        let archive_commitment = labyrinth_protocol::receipt::compute_archive_commitment(
            &frame_nonce,
            frame_json.as_bytes(),
        );
        let now_ms = self.hooks.now_ms();

        let live_ids = self.canonical_uuid_v4_device_id().and_then(|dev_id| {
            let c_uuid = uuid::Uuid::parse_str(conversation_id.trim())
                .ok()
                .filter(|u| u.get_version_num() == 4)?;
            let m_uuid = uuid::Uuid::parse_str(message_id.trim())
                .ok()
                .filter(|u| u.get_version_num() == 4)?;
            Some((dev_id, c_uuid, m_uuid))
        });

        let Some((canonical_dev_id, convo_uuid, msg_uuid)) = live_ids else {
            return self.send_message_local_offline(
                conversation_id,
                message_id,
                &display_json,
                &frame_json,
                frame_nonce,
                now_ms,
            );
        };

        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let inner_plaintext = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
            frame_nonce,
            canonical_payload_bytes: frame_json.as_bytes().to_vec(),
        })
        .map_err(|e| {
            MLSError::Internal(format!("serialize PrivateMessagePlaintextEnvelope: {e}"))
        })?;

        let prior_coords = self.load_or_build_conversation_coords(&canonical_convo_id)?;
        let generation = prior_coords
            .get("generation")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let state_version = prior_coords
            .get("stateVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let epoch_u64 = prior_coords
            .get("epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;

        // Reserve the sender generation and immutable recovery material atomically before HTTP.
        // A timeout can still publish the ciphertext; rolling the ratchet back would reuse its key.
        let (signer, auth_generation, pending, send_retry) = self.db.write_tx(|tx| {
            let convo = tx.get_conversation(&canonical_convo_id)?.ok_or_else(|| {
                MLSError::GroupNotFound {
                    message: format!("conversation {canonical_convo_id} not found"),
                }
            })?;
            let signer_json = tx
                .get_account_meta("enrolled_signer_json")?
                .ok_or_else(|| {
                    MLSError::InvalidState("device signer not initialized".to_string())
                })?;
            let signer: SignatureKeyPair = serde_json::from_str(&signer_json)
                .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            if let Some(raw) = tx.get_pending_op("application_send", &canonical_msg_id)? {
                let pending: PendingApplicationSend = serde_json::from_str(&raw)
                    .map_err(|e| MLSError::Internal(format!("parse pending send: {e}")))?;
                if pending.archive.conversation_id != canonical_convo_id
                    || pending.archive.plaintext_json != display_json
                    || pending.archive.sender_device_id != canonical_dev_id
                {
                    return Err(MLSError::invalid_input(
                        "message_id already reserved for a different send",
                    ));
                }
                let auth_gen = pending.body["authGeneration"].as_i64().ok_or_else(|| {
                    MLSError::Internal("pending send missing authGeneration".into())
                })?;
                return Ok((signer, auth_gen, pending, true));
            }

            let aad_prior = chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                &convo.group_id,
                generation,
                state_version,
                epoch_u64 as i64,
                &gch,
                &ctag,
            );
            let aad_val = json!({
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": generation,
                "messageId": STANDARD.encode(msg_uuid.as_bytes()),
                "prior": aad_prior,
                "archiveCommitment": { "$bytes": STANDARD.encode(archive_commitment) },
            });
            let aad_bytes = canonical_application_aad_bytes(&aad_val).map_err(|e| {
                MLSError::Cryptography(format!("canonical_application_aad_bytes: {e}"))
            })?;

            let ciphertext = {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let (ct, active_epoch) = self
                    .with_cached_sender_group(
                        &convo.group_id,
                        || {
                            MlsGroup::load(
                                provider.storage(),
                                &GroupId::from_slice(&convo.group_id),
                            )
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))
                        },
                        |group| {
                            group.set_aad(aad_bytes);
                            let mls_out = group
                                .create_message(&provider, &signer, &inner_plaintext)
                                .map_err(|e| {
                                    MLSError::Cryptography(format!("create_message: {e:?}"))
                                });
                            group.set_aad(Vec::new());
                            let ct = mls_out?.tls_serialize_detached().map_err(|e| {
                                MLSError::Internal(format!("serialize message: {e:?}"))
                            })?;
                            Ok((ct, group.epoch().as_u64() as i64))
                        },
                    )?
                    .ok_or_else(|| MLSError::GroupNotFound {
                        message: format!("MlsGroup missing for {canonical_convo_id}"),
                    })?;
                (ct, active_epoch)
            };

            let body = json!({
                "$type": "blue.catbird.chat.defs#applicationSendBody",
                "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
                "messageId": canonical_msg_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": self.hooks.now_rfc3339_millis(),
                "prior": prior_coords,
                "aad": aad_val,
                "applicationMessage": {
                    "framing": "mlsMessage",
                    "contentType": "privateMessageApplication",
                    "bytes": { "$bytes": STANDARD.encode(&ciphertext.0) },
                    "sha256": { "$bytes": STANDARD.encode(Sha256::digest(&ciphertext.0)) },
                },
                "blobBindings": [],
            });
            let pending = PendingApplicationSend {
                body,
                archive: QueuedLabyrinthArchivePayload {
                    version: 1,
                    message_id: canonical_msg_id.clone(),
                    conversation_id: canonical_convo_id.clone(),
                    group_id_hex: hex::encode(&convo.group_id),
                    epoch: ciphertext.1,
                    seq: 0,
                    sender_did: self.normalized_did.clone(),
                    sender_device_id: canonical_dev_id.clone(),
                    sequencer_did: convo.sequencer_did,
                    space_uri: convo.space_uri,
                    plaintext_json: display_json.clone(),
                    labyrinth_frame_json: frame_json,
                    mls_ciphertext_b64: STANDARD.encode(&ciphertext.0),
                    frame_nonce_b64: Some(STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    created_at_ms: now_ms,
                },
            };
            let payload = serde_json::to_string(&pending)
                .map_err(|e| MLSError::Internal(format!("serialize pending send: {e}")))?;
            tx.put_pending_op("application_send", &canonical_msg_id, &payload, now_ms)?;
            Ok((signer, auth_gen, pending, false))
        })?;

        // Strictly outside `write_tx` (`I6`); retries reuse the journal's exact signed body.
        let resp_val = self.submit_signed_chat_op(
            &canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::SendMessage,
            &pending.body,
            &signer,
        )?;

        // Enforce mandatory `I13` ES256 `sequencerReceipt` verification against `{sequencer_did}#mls-receipt-1`!
        let receipt_val = resp_val
            .get("sequencerReceipt")
            .or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("sequencerReceipt"))
            })
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                MLSError::Cryptography(
                    "I13: sendMessage response missing non-null sequencerReceipt".to_string(),
                )
            })?;
        let expected_entry_id = resp_val
            .pointer("/entry/entryId")
            .and_then(|v| v.as_str())
            .unwrap_or(&canonical_msg_id);
        let (final_row, needs_gap_sync) = self.finish_application_send(
            pending,
            receipt_val,
            expected_entry_id,
            None,
            send_retry,
        )?;

        if needs_gap_sync {
            if let Some(convo_now) = self
                .db
                .read_tx(|tx| tx.get_conversation(&canonical_convo_id))?
            {
                self.sync_conversation_entries(&canonical_dev_id, &signer, &convo_now)?;
            }
        }

        self.notify_change(PlatformChangeEvent::MessagesUpdated {
            conversation_id: canonical_convo_id,
        });
        Ok(final_row)
    }

    pub(crate) fn finish_application_send(
        &self,
        pending: PendingApplicationSend,
        receipt: &Value,
        entry_id: &str,
        ordered_seq: Option<i64>,
        send_retry: bool,
    ) -> Result<(MessageRow, bool), MLSError> {
        let mut queued = pending.archive;
        let group_id = hex::decode(&queued.group_id_hex)
            .map_err(|e| MLSError::Internal(format!("pending send group_id: {e}")))?;
        let nonce = STANDARD
            .decode(queued.frame_nonce_b64.as_deref().unwrap_or(""))
            .map_err(|e| MLSError::Internal(format!("pending send frame nonce: {e}")))?;
        let nonce: [u8; 32] = nonce
            .try_into()
            .map_err(|_| MLSError::Internal("pending send frame nonce must be 32 bytes".into()))?;
        let commitment = labyrinth_protocol::receipt::compute_archive_commitment(
            &nonce,
            queued.labyrinth_frame_json.as_bytes(),
        );
        let kid = receipt
            .get("kid")
            .and_then(|v| v.as_str())
            .unwrap_or("#mls-receipt-1");
        let sec1_key = self
            .resolve_sequencer_receipt_key(&queued.sequencer_did, kid)?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13: unable to resolve `{}` receipt key",
                    queued.sequencer_did
                ))
            })?;
        let (seq, generation, archived_json) = chat_wire::parse_and_verify_i13_sequencer_receipt(
            receipt,
            &sec1_key,
            &queued.sequencer_did,
            &queued.conversation_id,
            &group_id,
            queued.epoch.max(0) as u64,
            entry_id,
            &commitment,
        )?;
        let seq = i64::try_from(seq)
            .map_err(|_| MLSError::Cryptography("I13: receipt seq exceeds i64".into()))?;
        if ordered_seq.is_some_and(|expected| expected != seq)
            || receipt["senderDid"].as_str() != Some(queued.sender_did.as_str())
            || receipt["senderDeviceId"].as_str() != Some(queued.sender_device_id.as_str())
            || pending.body["prior"]["generation"].as_u64() != Some(generation)
        {
            return Err(MLSError::Cryptography(
                "I13: receipt seq, generation, or sender mismatch".into(),
            ));
        }
        if ordered_seq.is_none() && crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }
        queued.seq = seq;
        queued.sequencer_receipt_json = Some(archived_json);
        self.db.write_tx(|tx| {
            let row = MessageRow {
                message_id: queued.message_id.clone(),
                conversation_id: queued.conversation_id.clone(),
                group_id,
                epoch: queued.epoch,
                seq,
                sender_did: queued.sender_did.clone(),
                sender_device_id: queued.sender_device_id.clone(),
                plaintext_json: queued.plaintext_json.clone(),
                created_at_ms: queued.created_at_ms,
                is_own: true,
            };
            tx.insert_message(&row)?;
            let mut gap = false;
            if let Some(mut c) = tx.get_conversation(&queued.conversation_id)? {
                if ordered_seq.is_some() || seq == c.last_seq.saturating_add(1) {
                    c.last_seq = c.last_seq.max(seq);
                } else if seq > c.last_seq.saturating_add(1) {
                    gap = true;
                }
                c.updated_at_ms = self.hooks.now_ms();
                tx.upsert_conversation(&c)?;
            }
            if !(send_retry
                && crate::planted::is_planted_bug_active(
                    crate::planted::PlantedBug::P4SkipLabyrinthEnqueueAfterSendRetry,
                ))
            {
                let payload_bytes = serde_json::to_vec(&queued)
                    .map_err(|e| MLSError::Internal(format!("serialize queue payload: {e}")))?;
                tx.dequeue_labyrinth_item(&queued.message_id)?;
                tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                    item_id: queued.message_id.clone(),
                    conversation_id: queued.conversation_id.clone(),
                    group_id_hex: queued.group_id_hex.clone(),
                    seq,
                    payload_bytes,
                    created_at_ms: queued.created_at_ms,
                })?;
            }
            tx.delete_pending_op("application_send", &queued.message_id)?;
            Ok((row, gap))
        })
    }

    pub(crate) fn remove_group_member_live_or_offline(
        &self,
        actor_role: MemberRole,
        conversation_id: &str,
        target_did: &str,
    ) -> Result<(), MLSError> {
        if target_did.trim().is_empty() {
            return Err(MLSError::invalid_input("target_did must not be empty"));
        }
        enforce_admin_removal_policy(&self.normalized_did, actor_role, &[target_did.to_string()])?;
        let now_ms = self.hooks.now_ms();
        let convo = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {conversation_id} not found"),
            })?;

        let live_ids = self.canonical_uuid_v4_device_id().and_then(|dev_id| {
            let c_uuid = uuid::Uuid::parse_str(conversation_id.trim())
                .ok()
                .filter(|u| u.get_version_num() == 4)?;
            Some((dev_id, c_uuid))
        });
        let Some((canonical_dev_id, convo_uuid)) = live_ids else {
            self.db.write_tx(|tx| {
                tx.put_account_meta(
                    &format!("last_removed_member:{}", convo.conversation_id),
                    target_did,
                    now_ms,
                )
            })?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(());
        };

        // Step 1 removes every target leaf; its journal carries the durable removal intent.
        let removal = GenericCommitOp::RemoveLeaves { target_did };
        if !self.commit_generic_transition(
            conversation_id,
            &canonical_dev_id,
            &convo_uuid,
            removal,
        )? {
            // A zero-leaf participant (e.g. a pending invitee) needs only the policy step.
            self.db.write_tx(|tx| {
                tx.put_pending_op(
                    PARTICIPANT_REMOVAL_OP,
                    &participant_removal_key(conversation_id, target_did),
                    &participant_removal_payload(conversation_id, target_did),
                    now_ms,
                )
            })?;
        }
        // Step 2 removes the zero-leaf participant by policy; `sync` resumes it after a lost
        // response or a Commit recovered from its journal.
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        if self.complete_participant_removals(conversation_id, &canonical_dev_id, &signer)? {
            if let Some(convo_now) = self.db.read_tx(|tx| tx.get_conversation(conversation_id))? {
                let _ = self.sync_conversation_entries(&canonical_dev_id, &signer, &convo_now);
            }
        }
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(())
    }

    /// Proposal-free sender self-update Commit: fresh leaf and path secrets advance the epoch
    /// without any membership change (generic `#commitTransitionBody`, empty manifest).
    #[cfg(feature = "sim")]
    pub fn self_update(&self, conversation_id: &str) -> Result<(), MLSError> {
        let (canonical_dev_id, convo_uuid) = self
            .canonical_uuid_v4_device_id()
            .and_then(|dev_id| {
                let c_uuid = uuid::Uuid::parse_str(conversation_id.trim())
                    .ok()
                    .filter(|u| u.get_version_num() == 4)?;
                Some((dev_id, c_uuid))
            })
            .ok_or_else(|| {
                MLSError::InvalidState("self_update requires a live conversation".to_string())
            })?;
        if !self.commit_generic_transition(
            conversation_id,
            &canonical_dev_id,
            &convo_uuid,
            GenericCommitOp::SelfUpdate,
        )? {
            return Err(MLSError::InvalidState(
                "self_update requires an enrolled device signer".to_string(),
            ));
        }
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(())
    }

    /// Stage, journal, submit, and apply one generic `#commitTransitionBody` Commit.
    /// Returns `false` without any network call when there is nothing to commit (no target
    /// leaves, or no enrolled signer).
    #[cfg_attr(not(feature = "sim"), allow(clippy::never_loop))]
    fn commit_generic_transition(
        &self,
        conversation_id: &str,
        canonical_dev_id: &str,
        convo_uuid: &uuid::Uuid,
        op: GenericCommitOp<'_>,
    ) -> Result<bool, MLSError> {
        let now_ms = self.hooks.now_ms();
        let convo = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {conversation_id} not found"),
            })?;
        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords
            .get("stateVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let prior_epoch = prior_coords
            .get("epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let prior_gen = prior_coords
            .get("generation")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        // Only the sim-only P15 calibration retries; production submits each Commit once.
        #[cfg_attr(not(feature = "sim"), allow(unused_mut, unused_variables))]
        let mut first_attempt = true;
        loop {
            let transition_uuid = self.hooks.uuid_v4();
            let transition_id = transition_uuid.to_string();

            // Stage without changing `openmls_kv`; journal the merged batch before HTTP so
            // an accepted transition can be recovered even after a timeout or restart.
            let maybe_commit = self.db.read_tx(|tx| {
                let signer_json = tx.get_account_meta("enrolled_signer_json")?;
                let Some(signer_str) = signer_json else {
                    return Ok(None);
                };
                let signer: SignatureKeyPair = serde_json::from_str(&signer_str)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let auth_gen = tx
                    .get_account_meta("auth_generation")?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1)
                    .max(1);
                let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                let built = {
                    let storage = OpenMlsKvStorage::new(&overlay);
                    let provider = self.hooks.openmls_provider(storage);
                    let mut group =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                            .ok_or_else(|| MLSError::GroupNotFound {
                                message: format!("MlsGroup missing for {conversation_id}"),
                            })?;

                    let mut target_leaves = Vec::new();
                    let mut removed_leaf_entries = Vec::new();
                    if let GenericCommitOp::RemoveLeaves { target_did } = op {
                        let prefix = format!("{target_did}#");
                        for member in group.members() {
                            if let Ok(id_str) =
                                std::str::from_utf8(member.credential.serialized_content())
                            {
                                if let Some(dev_part) = id_str.strip_prefix(&prefix) {
                                    target_leaves.push(member.index);
                                    removed_leaf_entries.push(json!({
                                        "$type": "blue.catbird.chat.defs#removeLeaf",
                                        "userDid": target_did,
                                        "deviceId": dev_part,
                                    }));
                                }
                            }
                        }
                        if target_leaves.is_empty() {
                            return Ok(None);
                        }
                    }

                    let aad_prior = chat_wire::build_aad_prior_coordinate(
                        convo_uuid,
                        &convo.group_id,
                        prior_gen,
                        prior_sv,
                        prior_epoch as i64,
                        &prior_gch,
                        &prior_ctag,
                    );
                    let commit_aad_val = json!({
                        "protocolVersion": "1",
                        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                        "generation": prior_gen,
                        "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                        "prior": aad_prior,
                    });
                    let commit_aad_bytes =
                        canonical_commit_aad_bytes(&commit_aad_val).map_err(|e| {
                            MLSError::Cryptography(format!("canonical_commit_aad_bytes: {e}"))
                        })?;
                    group.set_aad(commit_aad_bytes);
                    let commit_bytes = match op {
                        GenericCommitOp::RemoveLeaves { .. } => group
                            .remove_members(&provider, &signer, &target_leaves)
                            .map_err(|e| MLSError::Cryptography(format!("remove_members: {e:?}")))?
                            .0
                            .tls_serialize_detached(),
                        GenericCommitOp::SelfUpdate => group
                            .self_update(&provider, &signer, LeafNodeParameters::builder().build())
                            .map_err(|e| MLSError::Cryptography(format!("self_update: {e:?}")))?
                            .commit()
                            .tls_serialize_detached(),
                    }
                    .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                    let staged_pending_batch = overlay.clone_batch();
                    group.merge_pending_commit(&provider).map_err(|e| {
                        MLSError::Cryptography(format!("merge_pending_commit: {e:?}"))
                    })?;
                    group.set_aad(Vec::new());

                    let next_epoch = group.epoch().as_u64();
                    let (next_gch, next_ctag) =
                        chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                    let meta_row = tx.get_group_metadata(conversation_id)?;
                    let meta_ver = meta_row
                        .as_ref()
                        .map(|m| m.metadata_version.max(1) as u64)
                        .unwrap_or(1);
                    let title_s = meta_row
                        .as_ref()
                        .and_then(|m| m.title.clone())
                        .unwrap_or_default();
                    let desc_s = meta_row
                        .as_ref()
                        .and_then(|m| m.description.clone())
                        .unwrap_or_default();
                    let avatar_opt = meta_row
                        .as_ref()
                        .and_then(chat_wire::space_avatar_from_metadata_row);
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &convo.group_id,
                        next_epoch,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                    let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                        tx,
                        conversation_id,
                        &meta_key,
                        &convo.group_id,
                        convo_uuid,
                        prior_gen,
                        next_epoch,
                        &next_gch,
                        &next_ctag,
                        &transition_id,
                        meta_ver,
                        canonical_dev_id,
                        auth_gen,
                        signer.public(),
                        &title_s,
                        &desc_s,
                        avatar_opt,
                    )?;
                    (
                        signer,
                        auth_gen,
                        commit_aad_val,
                        commit_bytes,
                        removed_leaf_entries,
                        next_epoch,
                        next_gch,
                        next_ctag,
                        carried_snap,
                        staged_pending_batch,
                    )
                };
                Ok(Some((built, overlay.into_batch())))
            })?;

            let Some((
                (
                    signer,
                    auth_gen,
                    commit_aad_val,
                    commit_bytes,
                    removed_leaves,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                    staged_pending_batch,
                ),
                kv_batch,
            )) = maybe_commit
            else {
                return Ok(false);
            };
            let next_coords = json!({
                "conversationId": conversation_id,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });
            let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
            let body = json!({
                "$type": "blue.catbird.chat.defs#commitTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": self.hooks.now_rfc3339_millis(),
                "prior": prior_coords,
                "next": next_coords,
                "aad": commit_aad_val,
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": removed_leaves,
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(commit_sha256),
                },
                "metadataSnapshot": carried_snap,
            });
            let removed_participant_did = match op {
                GenericCommitOp::RemoveLeaves { target_did } => Some(target_did.to_string()),
                GenericCommitOp::SelfUpdate => None,
            };
            let kv_batch = self.persist_pending_commit_transition(PendingCommitTransition {
                conversation_id: conversation_id.to_string(),
                transition_id: transition_id.clone(),
                commit_sha256,
                prior: prior_coords.clone(),
                next: next_coords.clone(),
                kv_batch,
                removed_participant_did,
            })?;
            if crate::planted::is_planted_bug_active(
                crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
            ) {
                self.db.write_tx(|tx| {
                    self.clear_cached_groups();
                    Ok(kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
                })?;
            }
            #[cfg(feature = "sim")]
            if first_attempt
                && crate::planted::is_planted_bug_active(
                    crate::planted::PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes,
                )
            {
                if let (GenericCommitOp::RemoveLeaves { target_did }, Some(space)) =
                    (op, &convo.space_uri)
                {
                    self.execute_json_post(
                        format!(
                            "{}/xrpc/com.atproto.memberspace.removeMember",
                            self.pds_base()
                        ),
                        serde_json::to_vec(&json!({ "space": space, "did": target_did }))
                            .map_err(|e| MLSError::Internal(e.to_string()))?,
                    )?;
                }
            }
            let resp_val = match self.submit_signed_chat_op(
                canonical_dev_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                &body,
                &signer,
            ) {
                Ok(val) => val,
                Err(err) => {
                    if err.is_stale_coordinates() {
                        self.db.write_tx(|tx| {
                            tx.delete_pending_op("commit_transition", &transition_id)?;
                            if crate::planted::is_planted_bug_active(
                                crate::planted::PlantedBug::P1KeepLoserStagedCommit,
                            ) {
                                staged_pending_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                                self.clear_cached_groups();
                            }
                            Ok(())
                        })?;
                        return Err(err);
                    }
                    #[cfg(feature = "sim")]
                    if first_attempt
                        && crate::planted::is_planted_bug_active(
                            crate::planted::PlantedBug::P15NonIdempotentCommitSubmitRetry,
                        )
                        && self
                            .db
                            .read_tx(|tx| tx.get_pending_op("commit_transition", &transition_id))?
                            .is_some()
                    {
                        first_attempt = false;
                        self.db.write_tx(|tx| {
                            tx.delete_pending_op("commit_transition", &transition_id)?;
                            Ok(())
                        })?;
                        continue;
                    }
                    return Err(err);
                }
            };
            let auth_seq_opt = resp_val.get("seq").and_then(|v| v.as_i64()).or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("seq"))
                    .and_then(|v| v.as_i64())
            });
            let updated_coords = resp_val
                .get("state")
                .and_then(|s| s.get("coordinates"))
                .or_else(|| resp_val.get("coordinates"))
                .cloned()
                .unwrap_or(next_coords);
            let coords_str = serde_json::to_string(&updated_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let snap_str = serde_json::to_string(&carried_snap)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            if crate::buggify!("after_http_2xx_before_db_commit") {
                return Err(MLSError::Internal(
                    "sim buggify: after_http_2xx_before_db_commit".to_string(),
                ));
            }
            let needs_gap_sync = self.db.write_tx(|tx| {
                let current = tx.get_conversation(conversation_id)?;
                if let Some(c) = &current {
                    if auth_seq_opt.is_some_and(|seq| seq > c.last_seq.saturating_add(1)) {
                        // Prior applications still need this epoch's roster for strict I4.
                        // Keep the journal and recover this Commit at its ordered entry.
                        return Ok(true);
                    }
                }
                kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                self.clear_cached_groups();
                if let GenericCommitOp::RemoveLeaves { target_did } = op {
                    tx.put_account_meta(
                        &format!("last_removed_member:{conversation_id}"),
                        target_did,
                        now_ms,
                    )?;
                    tx.put_pending_op(
                        PARTICIPANT_REMOVAL_OP,
                        &participant_removal_key(conversation_id, target_did),
                        &participant_removal_payload(conversation_id, target_did),
                        now_ms,
                    )?;
                }
                if let Some(mut c) = current {
                    c.epoch = next_epoch as i64;
                    if let Some(auth_seq) = auth_seq_opt {
                        if auth_seq == c.last_seq.saturating_add(1) {
                            c.last_seq = auth_seq;
                        }
                    }
                    c.updated_at_ms = now_ms;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    now_ms,
                )?;
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{conversation_id}"),
                    &snap_str,
                    now_ms,
                )?;
                Self::prune_pending_commit_transitions(
                    tx,
                    conversation_id,
                    prior_gen,
                    next_epoch as i64,
                    false,
                )?;
                Ok(false)
            })?;
            if needs_gap_sync {
                if let Some(convo_now) =
                    self.db.read_tx(|tx| tx.get_conversation(conversation_id))?
                {
                    self.sync_conversation_entries(canonical_dev_id, &signer, &convo_now)?;
                }
            }
            return Ok(true);
        }
    }

    /// Remove zero-leaf participants whose leaf-removal Commit is applied, by a
    /// `#policyTransitionBody` at the server's current coordinate. Runs after a nominal
    /// removal and at the end of every conversation `sync`, so a Commit accepted without
    /// its response (and recovered from the journal) still completes. Returns whether an
    /// accepted policy entry left a cursor gap.
    pub(crate) fn complete_participant_removals(
        &self,
        conversation_id: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<bool, MLSError> {
        let intents: Vec<(String, String)> = self.db.read_tx(|tx| {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT op_key, json_extract(payload_json, '$.target_did') FROM pending_ops \
                     WHERE op_kind = ?1 AND json_extract(payload_json, '$.conversation_id') = ?2 \
                     ORDER BY op_key",
                )
                .map_err(|e| map_rusqlite_err("participant removal intents.prepare", &e))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![PARTICIPANT_REMOVAL_OP, conversation_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(|e| map_rusqlite_err("participant removal intents.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("participant removal intents.row", &e))
        })?;
        if intents.is_empty() {
            return Ok(false);
        }
        let forget = |op_key: &str| {
            self.db.write_tx(|tx| {
                tx.delete_pending_op(PARTICIPANT_REMOVAL_OP, op_key)?;
                Ok(())
            })
        };
        if self.is_conversation_closed(conversation_id)? {
            for (op_key, _) in &intents {
                forget(op_key.as_str())?;
            }
            return Ok(false);
        }
        let (_, auth_generation) = self.load_enrolled_signer_and_auth_gen()?;
        let mut state: Option<Value> = None;
        let mut gap = false;
        for (op_key, target_did) in intents {
            // Wait while the leaf-removal Commit is in flight; forget a rejected one.
            let local = self.db.read_tx(|tx| {
                let Some(convo) = tx.get_conversation(conversation_id)? else {
                    return Ok(None);
                };
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let Some(group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                else {
                    return Ok(None);
                };
                let prefix = format!("{target_did}#");
                let has_leaf = group.members().any(|m| {
                    std::str::from_utf8(m.credential.serialized_content())
                        .is_ok_and(|id| id.starts_with(&prefix))
                });
                let journaled: i64 = tx
                    .conn()
                    .query_row(
                        "SELECT COUNT(*) FROM pending_ops WHERE op_kind = 'commit_transition' \
                         AND json_extract(payload_json, '$.conversation_id') = ?1",
                        [conversation_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| map_rusqlite_err("participant removal journal count", &e))?;
                Ok(Some((has_leaf, journaled > 0)))
            })?;
            match local {
                Some((false, _)) => {}
                Some((true, true)) => continue,
                None | Some((true, false)) => {
                    forget(op_key.as_str())?;
                    continue;
                }
            }

            let current = match state.take() {
                Some(current) => current,
                None => match self.query_signed_chat_ds(
                    "blue.catbird.chat.getConversationState",
                    &[
                        ("actorDeviceId", canonical_dev_id),
                        ("conversationId", conversation_id),
                    ],
                    canonical_dev_id,
                    signer,
                ) {
                    Ok(current) => current,
                    Err(MLSError::Internal(msg)) if msg.contains("ConversationNotFound") => {
                        forget(op_key.as_str())?;
                        continue;
                    }
                    Err(err) => return Err(err),
                },
            };
            let participant = current
                .pointer("/state/participants")
                .and_then(Value::as_array)
                .and_then(|participants| {
                    participants
                        .iter()
                        .find(|p| p["userDid"].as_str() == Some(target_did.as_str()))
                });
            let Some(participant) = participant else {
                forget(op_key.as_str())?;
                state = Some(current);
                continue;
            };
            let Some(prior_raw) = current.pointer("/state/coordinates") else {
                state = Some(current);
                continue;
            };
            if participant["leafCount"].as_u64().unwrap_or(0) > 0 {
                // The server has not accepted the leaf removal yet.
                state = Some(current);
                continue;
            }
            let prior = chat_wire::canonicalize_wire_coordinate(prior_raw, Some(conversation_id))?;
            let mut next = prior.clone();
            next["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap_or(0) + 1);
            let transition_id = self.hooks.uuid_v4().to_string();
            let body = json!({
                "$type": "blue.catbird.chat.defs#policyTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-POLICY\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_generation,
                "prior": prior,
                "next": next,
                "participantChanges": [{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": target_did,
                }],
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            let prepared = chat_wire::sign_clean_chat_mutation(
                &self.normalized_did,
                canonical_dev_id,
                Some(auth_generation),
                CanonicalOperation::SubmitTransition,
                &body,
                signer,
            )?;
            let resp = self.post_json_raw(
                &format!("{}{}", self.ds_base(), prepared.path),
                prepared.body.unwrap_or_default(),
            )?;
            if resp.status >= 400 {
                if serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body)
                    .is_ok_and(|failure| failure.error == "StaleCoordinates")
                {
                    // Another transition took this coordinate; a later sync retries.
                    continue;
                }
                if is_terminal_rejection(resp.status) {
                    // Definitively refused (e.g. this device is no longer an admin).
                    forget(op_key.as_str())?;
                }
                return Err(MLSError::Internal(format!(
                    "participant removal policy failed with HTTP {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                )));
            }
            let resp_val: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| MLSError::Internal(format!("parse policy response: {e}")))?;
            let updated_coords = resp_val
                .get("state")
                .and_then(|s| s.get("coordinates"))
                .or_else(|| resp_val.get("coordinates"))
                .cloned()
                .unwrap_or(next);
            let coords_str = serde_json::to_string(&updated_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let new_seq = resp_val
                .get("seq")
                .or_else(|| resp_val.pointer("/entry/seq"))
                .and_then(Value::as_i64);
            let now_ms = self.hooks.now_ms();
            gap |= self.db.write_tx(|tx| {
                tx.delete_pending_op(PARTICIPANT_REMOVAL_OP, &op_key)?;
                tx.put_account_meta(
                    &format!("last_removed_member:{conversation_id}"),
                    &target_did,
                    now_ms,
                )?;
                let Some(mut c) = tx.get_conversation(conversation_id)? else {
                    return Ok(false);
                };
                // Behind unseen entries, let `sync` apply them and this policy echo in order.
                let Some(seq) = new_seq.filter(|seq| *seq == c.last_seq.saturating_add(1)) else {
                    return Ok(new_seq.is_some_and(|seq| seq > c.last_seq));
                };
                c.last_seq = seq;
                c.updated_at_ms = now_ms;
                tx.upsert_conversation(&c)?;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    now_ms,
                )?;
                Ok(false)
            })?;
        }
        Ok(gap)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reencrypt_metadata_snapshot_for_epoch(
        &self,
        tx: &crate::storage::SqlReadTx<'_>,
        conversation_id: &str,
        metadata_key: &[u8; 32],
        group_id: &[u8],
        convo_uuid: &uuid::Uuid,
        generation: i64,
        target_epoch: u64,
        next_gch: &[u8],
        next_ctag: &[u8],
        fallback_transition_id: &str,
        fallback_version: u64,
        actor_device_id: &str,
        auth_generation: i64,
        public_key: &[u8],
        title: &str,
        description: &str,
        space_avatar: Option<SpaceAvatarPointer>,
    ) -> Result<Value, MLSError> {
        if let Some(prev_str) =
            tx.get_account_meta(&format!("metadata_snapshot_json:{conversation_id}"))?
        {
            if let Ok(prev_snap) = serde_json::from_str::<Value>(&prev_str) {
                let prev_ver = prev_snap
                    .get("metadataVersion")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(fallback_version);
                let origin_tid = prev_snap
                    .get("originTransitionId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(fallback_transition_id)
                    .to_string();
                let author_proof = prev_snap.get("authorProof").cloned();
                let nonce = self.hooks.random_array::<12>();
                let payload = GroupMetadataV1 {
                    version: 1,
                    title: title.to_string(),
                    description: description.to_string(),
                    avatar_blob_locator: None,
                    avatar_content_type: space_avatar.as_ref().and_then(|a| a.mime_type.clone()),
                    space_avatar: space_avatar.clone(),
                };
                let ct = encrypt_metadata_snapshot_with_nonce(
                    metadata_key,
                    group_id,
                    target_epoch,
                    prev_ver,
                    &nonce,
                    &payload,
                )?;
                if let Some(proof) = author_proof {
                    return Ok(json!({
                        "authorProof": proof,
                        "ciphertext": { "$bytes": STANDARD.encode(&ct) },
                        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ct)),
                        "ciphertextSize": ct.len(),
                        "coordinate": {
                            "confirmationTag": { "$bytes": STANDARD.encode(next_ctag) },
                            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                            "epoch": target_epoch,
                            "generation": generation,
                            "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                            "groupId": { "$bytes": STANDARD.encode(group_id) },
                        },
                        "metadataVersion": prev_ver,
                        "nonce": { "$bytes": STANDARD.encode(nonce) },
                        "originTransitionId": origin_tid,
                    }));
                }
            }
        }
        chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
            metadata_key,
            group_id,
            convo_uuid,
            generation,
            target_epoch,
            next_gch,
            next_ctag,
            fallback_transition_id,
            fallback_version,
            1,
            &self.normalized_did,
            actor_device_id,
            auth_generation,
            public_key,
            title,
            description,
            space_avatar,
            self.hooks.random_array::<12>(),
        )
    }

    pub(crate) fn update_group_metadata_live_or_offline(
        &self,
        conversation_id: &str,
        title: String,
        description: String,
        space_avatar: Option<SpaceAvatarPointer>,
    ) -> Result<GroupMetadataRow, MLSError> {
        let now_ms = self.hooks.now_ms();
        let (staged_row, maybe_live) = self.db.read_tx(|tx| {
            let convo =
                tx.get_conversation(conversation_id)?
                    .ok_or_else(|| MLSError::GroupNotFound {
                        message: format!("conversation {conversation_id} not found"),
                    })?;
            let existing_meta = tx.get_group_metadata(conversation_id)?;
            let next_ver = existing_meta
                .as_ref()
                .map(|m| m.metadata_version.saturating_add(1))
                .unwrap_or(1);
            let effective_avatar = space_avatar.clone().or_else(|| {
                existing_meta
                    .as_ref()
                    .and_then(chat_wire::space_avatar_from_metadata_row)
            });

            let meta_v1 = GroupMetadataV1 {
                version: 1,
                title: title.clone(),
                description: description.clone(),
                avatar_blob_locator: None,
                avatar_content_type: effective_avatar.as_ref().and_then(|a| a.mime_type.clone()),
                space_avatar: effective_avatar,
            };
            let serialized = serde_json::to_vec(&meta_v1)
                .map_err(|e| MLSError::Internal(format!("serialize GroupMetadataV1: {e}")))?;
            validate_metadata_snapshot_size(&serialized)?;

            let row = chat_wire::group_metadata_row_from_v1(
                conversation_id,
                next_ver,
                convo.epoch,
                &meta_v1,
                now_ms,
            )?;

            let live_bundle = if let (Some(dev_id), Ok(convo_uuid), Some(signer_str)) = (
                self.canonical_uuid_v4_device_id(),
                uuid::Uuid::parse_str(conversation_id.trim())
                    .ok()
                    .filter(|u| u.get_version_num() == 4)
                    .ok_or(()),
                tx.get_account_meta("enrolled_signer_json")?,
            ) {
                let signer: SignatureKeyPair = serde_json::from_str(&signer_str)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let auth_gen = tx
                    .get_account_meta("auth_generation")?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1)
                    .max(1);
                let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
                let snap_opt = {
                    let storage = OpenMlsKvStorage::new(&overlay);
                    let provider = self.hooks.openmls_provider(storage);
                    if let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    {
                        let epoch_u64 = group.epoch().as_u64();
                        let (gch, ctag) =
                            chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                        let meta_key = derive_metadata_key_from_group(
                            &mut group,
                            provider.crypto(),
                            provider.storage(),
                            &convo.group_id,
                            epoch_u64,
                        )
                        .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                        let tid = self.hooks.uuid_v4().to_string();
                        let nonce = self.hooks.random_array::<12>();
                        let ct = encrypt_metadata_snapshot_with_nonce(
                            &meta_key,
                            &convo.group_id,
                            epoch_u64,
                            next_ver as u64,
                            &nonce,
                            &meta_v1,
                        )?;
                        validate_metadata_snapshot_size(&ct)?;
                        let snap = json!({
                            "authorProof": {
                                "authGenerationAtOrigin": auth_gen,
                                "authorDeviceId": dev_id,
                                "authorDid": self.normalized_did,
                                "authorKeyId": derive_key_id(signer.public()),
                                "deviceStatusAtOrigin": "active",
                                "originSeq": convo.last_seq.saturating_add(1),
                                "originTransitionId": tid,
                                "roleAtOrigin": "admin",
                                "signaturePublicKey": { "$bytes": STANDARD.encode(signer.public()) },
                            },
                            "ciphertext": { "$bytes": STANDARD.encode(&ct) },
                            "ciphertextSha256": STANDARD.encode(Sha256::digest(&ct)),
                            "ciphertextSize": ct.len(),
                            "coordinate": {
                                "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                                "epoch": epoch_u64,
                                "generation": convo.generation,
                                "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                            },
                            "metadataVersion": next_ver,
                            "nonce": { "$bytes": STANDARD.encode(nonce) },
                            "originTransitionId": tid,
                        });
                        Some((tid, snap))
                    } else {
                        None
                    }
                };
                snap_opt.map(|(tid, snap)| {
                    (dev_id, signer, auth_gen, tid, snap, overlay.into_batch())
                })
            } else {
                None
            };
            Ok((row, live_bundle))
        })?;

        if let Some((dev_id, signer, auth_gen, tid, snap, kv_batch)) = maybe_live {
            let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
            let prior_sv = prior_coords
                .get("stateVersion")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let mut next_coords = prior_coords.clone();
            next_coords["stateVersion"] = json!(prior_sv + 1);
            let body = json!({
                "$type": "blue.catbird.chat.defs#metadataTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-METADATA\0",
                "transitionId": tid,
                "idempotencyKey": tid,
                "actorDid": self.normalized_did,
                "actorDeviceId": dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "prior": prior_coords,
                "next": next_coords,
                "metadataSnapshot": snap,
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            if crate::planted::is_planted_bug_active(
                crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
            ) {
                self.db.write_tx(|tx| {
                    self.clear_cached_groups();
                    Ok(kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
                })?;
            }
            let resp_val = self.submit_signed_chat_op(
                &dev_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                &body,
                &signer,
            )?;
            let auth_seq_opt = resp_val.get("seq").and_then(|v| v.as_i64()).or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("seq"))
                    .and_then(|v| v.as_i64())
            });
            let updated_coords = resp_val
                .get("state")
                .and_then(|s| s.get("coordinates"))
                .or_else(|| resp_val.get("coordinates"))
                .cloned()
                .unwrap_or(next_coords);
            let coords_str = serde_json::to_string(&updated_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let snap_str =
                serde_json::to_string(&snap).map_err(|e| MLSError::Internal(e.to_string()))?;
            if crate::buggify!("after_http_2xx_before_db_commit") {
                return Err(MLSError::Internal(
                    "sim buggify: after_http_2xx_before_db_commit".to_string(),
                ));
            }
            let needs_gap_sync = self.db.write_tx(|tx| {
                kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
                self.clear_cached_groups();
                tx.upsert_group_metadata(&staged_row)?;
                let mut gap = false;
                if let Some(mut convo) = tx.get_conversation(conversation_id)? {
                    convo.title = staged_row.title.clone();
                    if let Some(auth_seq) = auth_seq_opt {
                        if auth_seq == convo.last_seq.saturating_add(1) {
                            convo.last_seq = auth_seq;
                        } else if auth_seq > convo.last_seq.saturating_add(1) {
                            gap = true;
                        }
                    }
                    convo.updated_at_ms = now_ms;
                    tx.upsert_conversation(&convo)?;
                }
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    now_ms,
                )?;
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{conversation_id}"),
                    &snap_str,
                    now_ms,
                )?;
                Ok(gap)
            })?;
            if needs_gap_sync {
                if let Some(convo) = self.db.read_tx(|tx| tx.get_conversation(conversation_id))? {
                    let _ = self.sync_conversation_entries(&dev_id, &signer, &convo);
                }
            }
        } else {
            self.db.write_tx(|tx| {
                tx.upsert_group_metadata(&staged_row)?;
                if let Some(mut convo) = tx.get_conversation(conversation_id)? {
                    convo.title = staged_row.title.clone();
                    convo.updated_at_ms = now_ms;
                    tx.upsert_conversation(&convo)?;
                }
                Ok(())
            })?;
        }

        self.notify_change(PlatformChangeEvent::GroupMetadataUpdated {
            conversation_id: conversation_id.to_string(),
        });
        Ok(staged_row)
    }

    pub(crate) fn accept_direct_request_live_or_offline(
        &self,
        request_id: &str,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        let req_opt = self.db.read_tx(|tx| {
            let rows = tx.list_requests(None)?;
            Ok(rows
                .into_iter()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id))
        })?;
        if req_opt.as_ref().is_some_and(|r| r.consent == "accepted") {
            // Accepted here or by another of this account's devices: a freshly signed
            // acceptance could only be an `IdempotencyConflict`.
            return Ok(());
        }

        if let (Some(canonical_dev_id), Some(req)) =
            (self.canonical_uuid_v4_device_id(), req_opt.as_ref())
        {
            if let Some(pub_str) = self.db.read_tx(|tx| {
                tx.get_account_meta(&format!("c33_publication_json:{}", req.conversation_id))
            })? {
                let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
                // The DS keeps the first signed acceptance even when relaying it to a remote
                // coordinator fails, so every retry replays exactly those bytes.
                let journaled = self.db.read_tx(|tx| {
                    tx.get_pending_op(DIRECT_REQUEST_ACCEPTANCE_OP, &req.request_id)
                })?;
                let (wrapper_bytes, next) = if let Some(raw) = journaled {
                    let saved: Value = serde_json::from_str(&raw).map_err(|e| {
                        MLSError::Internal(format!("parse pending acceptance: {e}"))
                    })?;
                    let wrapper = STANDARD
                        .decode(saved["wrapper"].as_str().unwrap_or_default())
                        .map_err(|e| {
                            MLSError::Internal(format!("pending acceptance wrapper: {e}"))
                        })?;
                    (wrapper, saved["next"].clone())
                } else {
                    let pub_val: Value = serde_json::from_str(&pub_str)
                        .map_err(|e| MLSError::Internal(e.to_string()))?;
                    let p_body = pub_val.get("body").unwrap_or(&pub_val);
                    let prior = p_body["next"].clone();
                    let prior_sv = prior["stateVersion"].as_u64().unwrap_or(1);
                    let mut next = prior.clone();
                    next["stateVersion"] = json!(prior_sv + 1);
                    let transition = self.hooks.uuid_v4().to_string();
                    let accept_body = json!({
                        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
                        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
                        "protocolVersion": "2",
                        "actorDid": self.normalized_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public())),
                        "authGeneration": auth_gen,
                        "requestId": p_body["requestId"],
                        "transitionId": transition,
                        "prior": prior,
                        "next": next,
                        "invitationProvenance": {
                            "invitationTransitionId": p_body["requestId"],
                            "invitedByDid": p_body["actorDid"],
                            "invitedByDeviceId": p_body["actorDeviceId"],
                        },
                        "idempotencyKey": transition,
                        "signedAt": self.hooks.now_rfc3339_millis(),
                    });
                    let wrapper_bytes = chat_wire::sign_direct_request_wrapper(
                        DirectRequestKind::Accept,
                        accept_body,
                        &signer,
                    )?;
                    let saved = json!({ "wrapper": STANDARD.encode(&wrapper_bytes), "next": next });
                    self.db.write_tx(|tx| {
                        tx.put_pending_op(
                            DIRECT_REQUEST_ACCEPTANCE_OP,
                            &req.request_id,
                            &saved.to_string(),
                            now_ms,
                        )
                    })?;
                    (wrapper_bytes, next)
                };
                let mut wire = b"{\"directRequest\":".to_vec();
                wire.extend_from_slice(&wrapper_bytes);
                wire.push(b'}');
                let accept_url = format!(
                    "{}/xrpc/blue.catbird.chat.acceptConversation",
                    self.ds_base()
                );
                let resp = self.post_json_raw(&accept_url, wire)?;
                if resp.status >= 400 {
                    if is_terminal_rejection(resp.status) {
                        // The DS will never accept these bytes; a later attempt signs afresh.
                        self.db.write_tx(|tx| {
                            tx.delete_pending_op(DIRECT_REQUEST_ACCEPTANCE_OP, &req.request_id)?;
                            Ok(())
                        })?;
                    }
                    if serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body)
                        .is_ok_and(|failure| failure.error == "StaleCoordinates")
                    {
                        return Err(MLSError::InvalidState("StaleCoordinates".into()));
                    }
                    return Err(MLSError::Internal(format!(
                        "POST {accept_url} failed with HTTP {}: {}",
                        resp.status,
                        String::from_utf8_lossy(&resp.body)
                    )));
                }
                let resp_val: Value = serde_json::from_slice(&resp.body).map_err(|e| {
                    MLSError::Internal(format!("parse acceptConversation JSON: {e}"))
                })?;
                let auth_seq_opt = resp_val.get("seq").and_then(|v| v.as_i64()).or_else(|| {
                    resp_val
                        .get("entry")
                        .and_then(|e| e.get("seq"))
                        .and_then(|v| v.as_i64())
                });
                let next_coords = resp_val
                    .get("coordinates")
                    .cloned()
                    .or_else(|| {
                        resp_val
                            .get("acceptanceProof")
                            .and_then(|p| p.get("receipt"))
                            .and_then(|r| r.get("body"))
                            .and_then(|b| b.get("next"))
                            .cloned()
                    })
                    .unwrap_or(next);
                let next_coords = chat_wire::canonicalize_wire_coordinate(
                    &next_coords,
                    Some(&req.conversation_id),
                )?;
                let coords_str = serde_json::to_string(&next_coords)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                if crate::buggify!("after_http_2xx_before_db_commit") {
                    return Err(MLSError::Internal(
                        "sim buggify: after_http_2xx_before_db_commit".to_string(),
                    ));
                }
                let needs_gap_sync = self.db.write_tx(|tx| {
                    let mut gap = false;
                    if let Some(mut c) = tx.get_conversation(&req.conversation_id)? {
                        let target_seq = auth_seq_opt.unwrap_or(2);
                        if target_seq == c.last_seq.saturating_add(1) {
                            c.last_seq = target_seq;
                        } else if target_seq > c.last_seq.saturating_add(1) {
                            gap = true;
                        }
                        c.updated_at_ms = now_ms;
                        tx.upsert_conversation(&c)?;
                    }
                    tx.put_account_meta(
                        &format!("conversation_coords:{}", req.conversation_id),
                        &coords_str,
                        now_ms,
                    )?;
                    Ok(gap)
                })?;
                if needs_gap_sync {
                    if let Some(convo) = self
                        .db
                        .read_tx(|tx| tx.get_conversation(&req.conversation_id))?
                    {
                        let _ = self.sync_conversation_entries(&canonical_dev_id, &signer, &convo);
                    }
                }
                self.archive_accepted_opening_messages(&req.conversation_id)?;
            }
        }

        self.db.write_tx(|tx| {
            let mut rows = tx.list_requests(None)?;
            if let Some(req) = rows
                .iter_mut()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id)
            {
                // Retries replay the journaled acceptance until consent is durable.
                tx.delete_pending_op(DIRECT_REQUEST_ACCEPTANCE_OP, &req.request_id)?;
                req.consent = "accepted".to_string();
                req.updated_at_ms = now_ms;
                tx.upsert_request(req)?;
            }
            Ok(())
        })?;
        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(())
    }

    /// Enqueue and archive a staged `C33` opening message ONLY after `directRequestAcceptance` (`Spec §2 C33`).
    pub(crate) fn archive_accepted_opening_messages(
        &self,
        conversation_id: &str,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        let enqueued = self.db.write_tx(|tx| {
            let key = format!("c33_pending_opening:{conversation_id}");
            let Some(staged_str) = tx.get_account_meta(&key)? else {
                return Ok(false);
            };
            if staged_str.is_empty() || staged_str == "archived" {
                return Ok(false);
            }
            let staged: QueuedLabyrinthArchivePayload = serde_json::from_str(&staged_str)
                .map_err(|e| MLSError::Internal(format!("parse c33_pending_opening: {e}")))?;
            let payload_bytes = serde_json::to_vec(&staged)
                .map_err(|e| MLSError::Internal(format!("serialize c33_pending_opening: {e}")))?;
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: staged.message_id.clone(),
                conversation_id: conversation_id.to_string(),
                group_id_hex: staged.group_id_hex.clone(),
                seq: staged.seq,
                payload_bytes,
                created_at_ms: now_ms,
            })?;
            tx.put_account_meta(&key, "archived", now_ms)?;
            Ok(true)
        })?;
        let _ = enqueued;
        Ok(())
    }

    pub(crate) fn decline_direct_request_live_or_offline(
        &self,
        request_id: &str,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        let req_opt = self.db.read_tx(|tx| {
            let rows = tx.list_requests(None)?;
            Ok(rows
                .into_iter()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id))
        })?;

        if let Some(req) = &req_opt {
            if uuid::Uuid::parse_str(&req.conversation_id)
                .ok()
                .filter(|u| u.get_version_num() == 4)
                .is_some()
                && self.canonical_uuid_v4_device_id().is_some()
                && self.load_enrolled_signer_and_auth_gen().is_ok()
                && self.db.read_tx(|tx| {
                    Ok(tx
                        .get_account_meta(&format!("conversation_coords:{}", req.conversation_id))?
                        .is_some()
                        || tx.get_conversation(&req.conversation_id)?.is_some())
                })?
            {
                self.close_conversation(&req.conversation_id)?;
            }
        }

        self.db.write_tx(|tx| {
            let mut rows = tx.list_requests(None)?;
            if let Some(req) = rows
                .iter_mut()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id)
            {
                req.consent = "declined".to_string();
                req.updated_at_ms = now_ms;
                tx.upsert_request(req)?;
                tx.put_account_meta(
                    &format!("c33_pending_opening:{}", req.conversation_id),
                    "",
                    now_ms,
                )?;
            }
            Ok(())
        })?;
        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        Ok(())
    }

    pub(crate) fn is_conversation_closed(&self, conversation_id: &str) -> Result<bool, MLSError> {
        let cid = conversation_id.trim();
        self.db.read_tx(|tx| {
            if tx
                .get_account_meta(&format!("conversation_closed:{cid}"))?
                .is_some_and(|v| v == "true")
            {
                return Ok(true);
            }
            if let Some(raw) = tx.get_account_meta(&format!("conversation_coords:{cid}"))? {
                if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                    if parsed.get("lifecycle").and_then(Value::as_str) == Some("superseded") {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    /// Close a conversation on the authoritative `mls-ds` (`Spec §6.3`, `O7`, `I14`).
    ///
    /// Signs a canonical `CATBIRD-CHAT-CLOSE\0` `conversationCloseBody` and submits
    /// `blue.catbird.chat.closeConversation`, retiring the current coordinate to
    /// `lifecycle = "superseded"` while retaining local history unsendable.
    pub fn close_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let trimmed = conversation_id.trim();
        if trimmed.is_empty() {
            return Err(MLSError::invalid_input("conversation_id must not be empty"));
        }
        let now_ms = self.hooks.now_ms();
        let is_direct = self.db.read_tx(|tx| {
            let rows = tx.list_requests(None)?;
            Ok(rows.iter().any(|r| r.conversation_id == trimmed))
        })?;

        let live_convo_uuid = uuid::Uuid::parse_str(trimmed)
            .ok()
            .filter(|u| u.get_version_num() == 4);
        let Some((canonical_dev_id, convo_uuid)) =
            self.canonical_uuid_v4_device_id().zip(live_convo_uuid)
        else {
            self.db.write_tx(|tx| {
                if tx.get_conversation(trimmed)?.is_none() && !is_direct {
                    return Err(MLSError::GroupNotFound {
                        message: format!("conversation {trimmed} not found"),
                    });
                }
                tx.put_account_meta(&format!("conversation_closed:{trimmed}"), "true", now_ms)?;
                Ok(())
            })?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(());
        };

        let canonical_cid = convo_uuid.hyphenated().to_string();
        if self.is_conversation_closed(&canonical_cid)? {
            return Ok(());
        }
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let prior_coords = self.load_or_build_conversation_coords(&canonical_cid)?;
        let prior_sv = prior_coords
            .get("stateVersion")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let mut retired_coords = prior_coords.clone();
        retired_coords["stateVersion"] = json!(prior_sv + 1);
        retired_coords["lifecycle"] = json!("superseded");

        let kind = if is_direct { "direct" } else { "group" };
        let transition = self.hooks.uuid_v4().to_string();
        let close_body = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseBody",
            "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
            "transitionId": transition,
            "idempotencyKey": transition,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "conversationKind": kind,
            "prior": prior_coords,
            "retired": retired_coords,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let resp = self.submit_signed_chat_op(
            &canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::CloseConversation,
            &close_body,
            &signer,
        )?;
        let terminal_seq = resp
            .pointer("/result/tombstone/terminalSeq")
            .or_else(|| resp.pointer("/result/entry/seq"))
            .and_then(Value::as_i64);
        let retired_wire = resp
            .pointer("/result/tombstone/retired")
            .cloned()
            .unwrap_or(retired_coords);
        let retired_canon =
            chat_wire::canonicalize_wire_coordinate(&retired_wire, Some(&canonical_cid))?;
        let retired_str =
            serde_json::to_string(&retired_canon).map_err(|e| MLSError::Internal(e.to_string()))?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        self.db.write_tx(|tx| {
            if let Some(mut convo) = tx.get_conversation(&canonical_cid)? {
                if let Some(seq) = terminal_seq {
                    convo.last_seq = convo.last_seq.max(seq);
                }
                convo.updated_at_ms = now_ms;
                tx.upsert_conversation(&convo)?;
            }
            tx.put_account_meta(
                &format!("conversation_coords:{canonical_cid}"),
                &retired_str,
                now_ms,
            )?;
            tx.put_account_meta(
                &format!("conversation_closed:{canonical_cid}"),
                "true",
                now_ms,
            )?;
            Self::prune_pending_commit_transitions(tx, &canonical_cid, 0, i64::MAX, true)?;
            Ok(())
        })?;

        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(())
    }

    pub fn list_members(&self, conversation_id: &str) -> Result<Vec<String>, MLSError> {
        self.db.read_tx(|tx| {
            let Some(convo) = tx.get_conversation(conversation_id)? else {
                return Ok(Vec::new());
            };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            else {
                return Ok(vec![self.normalized_did.clone()]);
            };
            let mut dids = std::collections::BTreeSet::new();
            for member in group.members() {
                if let Ok(id_str) = std::str::from_utf8(member.credential.serialized_content()) {
                    let did = id_str.split('#').next().unwrap_or(id_str).trim();
                    if !did.is_empty() {
                        dids.insert(did.to_string());
                    }
                }
            }
            if dids.is_empty() {
                dids.insert(self.normalized_did.clone());
            }
            Ok(dids.into_iter().collect())
        })
    }

    /// Inspect durable OpenMLS group state directly from `openmls_kv` for simulation oracles.
    #[cfg(feature = "sim")]
    pub fn inspect_sim_group(
        &self,
        conversation_id: &str,
    ) -> Result<Option<crate::planted::SimGroupState>, MLSError> {
        self.db.read_tx(|tx| {
            let Some(convo) = tx.get_conversation(conversation_id)? else {
                return Ok(None);
            };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            else {
                return Ok(None);
            };
            let mut members: Vec<String> = group
                .members()
                .filter_map(|m| {
                    std::str::from_utf8(m.credential.serialized_content())
                        .ok()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                })
                .collect();
            members.sort();
            members.dedup();
            Ok(Some(crate::planted::SimGroupState {
                group_id: group.group_id().as_slice().to_vec(),
                epoch: group.epoch().as_u64(),
                tree_hash: group.public_group().group_context().tree_hash().to_vec(),
                members,
                has_pending_commit: group.pending_commit().is_some(),
            }))
        })
    }
}
