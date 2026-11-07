//! Live `mls-ds` `/xrpc/blue.catbird.chat.*` data plane for `CatbirdMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! All network dispatches execute strictly outside `MlsAccountDb::write_tx` (`I6`).

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::chat_v2::wire::{
    COMMIT_ENTRY_KIND, CONVERSATION_CLOSE_ENTRY_KIND, CREATION_ENTRY_KIND, METADATA_ENTRY_KIND,
    POLICY_ENTRY_KIND,
};
use crate::client::chat_wire;
use crate::client::traits::{
    PlatformChangeEvent, PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse,
};
use crate::client::QueuedLabyrinthArchivePayload;
use crate::error::MLSError;
use crate::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use crate::groups::metadata_v1::{validate_metadata_snapshot_size, SpaceAvatarPointer};
use crate::messaging::receive::{
    OriginalSenderArchiveAttestationEnvelope, PrivateMessagePlaintextEnvelope,
};
use crate::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use crate::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id,
    is_transient_wire_failure, retry_after_secs, CanonicalOperation, PreparedRequest,
    MAX_RETRY_AFTER_SECS,
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

pub(crate) use super::chat_wire::PendingCommitTransition;

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

/// `pending_ops` kind holding this device's exact signed close per conversation (the
/// `signedRequest` JSON), journaled before HTTP and replayed byte for byte until applied.
const CONVERSATION_CLOSE_OP: &str = "conversation_close";

/// `pending_ops` kind holding the one outgoing `C33` creation per normalized peer DID. The DS
/// fences one live preparation per pair while the app names a new conversation on every tap,
/// so the peer keys it. Retries replay the exact signed prepare and, once prepared, the exact
/// publication over the unapplied MLS bootstrap: a transient failure never rebuilds MLS or
/// reserves another recipient key package.
const DIRECT_REQUEST_CREATION_OP: &str = "direct_request_creation";
const DIRECT_REQUEST_CREATION_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PendingDirectRequestCreation {
    version: u32,
    request_id: String,
    first_message_id: String,
    conversation_id: String,
    intro_text: String,
    prepare_wrapper: Vec<u8>,
    /// `hooks.now_ms()` before which a retry answers `retry_code` without any request.
    retry_at_ms: i64,
    retry_code: Option<String>,
    /// Present once the verified preparation is built into a signed publication.
    publish: Option<PendingDirectRequestPublication>,
}

#[derive(Serialize, Deserialize)]
struct PendingDirectRequestPublication {
    group_id: Vec<u8>,
    sequencer_did: String,
    bootstrap: direct_request_bootstrap::DirectRequestBootstrap,
    kv_batch: KvWriteBatch,
    publish_wrapper: Vec<u8>,
}

fn same_direct_request_attempt(
    left: &PendingDirectRequestCreation,
    right: &PendingDirectRequestCreation,
) -> Result<bool, MLSError> {
    Ok(left.version == right.version
        && left.request_id == right.request_id
        && left.first_message_id == right.first_message_id
        && left.conversation_id == right.conversation_id
        && left.intro_text == right.intro_text
        && left.prepare_wrapper == right.prepare_wrapper
        && serde_json::to_vec(&left.publish)
            .map_err(|e| MLSError::Internal(format!("serialize C33 publication: {e}")))?
            == serde_json::to_vec(&right.publish)
                .map_err(|e| MLSError::Internal(format!("serialize C33 publication: {e}")))?)
}
/// `{"signedRequest":<wrapper>}`, byte-identical on every replay of a journaled wrapper.
fn signed_request_body(wrapper: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(wrapper.len() + 18);
    body.extend_from_slice(b"{\"signedRequest\":");
    body.extend_from_slice(wrapper);
    body.push(b'}');
    body
}

/// Whether the DS will refuse these exact bytes again: a semantic 4xx. A transient failure
/// ([`is_transient_wire_failure`], e.g. `503 CapacityUnavailable`, `429`) and every 5xx keep
/// the journaled bytes for the identical retry.
fn is_terminal_rejection(resp: &PlatformHttpResponse) -> bool {
    let failure = serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body).ok();
    (400..500).contains(&resp.status)
        && !is_transient_wire_failure(resp.status, failure.as_ref().map(|f| &*f.error))
}

#[derive(Deserialize)]
struct ChatProtocolFailure<'a> {
    #[serde(borrow)]
    error: std::borrow::Cow<'a, str>,
}

pub(super) fn chat_response_error(
    context: impl std::fmt::Display,
    resp: &PlatformHttpResponse,
) -> MLSError {
    match serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body) {
        Ok(failure) => MLSError::InvalidState(failure.error.into_owned()),
        Err(_) => MLSError::Internal(format!(
            "{context} failed with HTTP {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body),
        )),
    }
}

/// The 2xx answer to this device's own signed control, verified before anything moves: its
/// `entry` is an `entry_kind` entry of `conversation_id` that strictly projects and carries
/// exactly `sent`, the signed request this device submitted (so it verifies under this
/// device's key), and its `coordinates` are that request's signed `next`. Returns the entry
/// seq. Callers write only the signed coordinates; an answer that does not verify is refused
/// like a lost response, so the journal stays and sync applies the own echo.
pub(super) fn verify_own_answer(
    answer: &Value,
    sent: &Value,
    conversation_id: &str,
    entry_kind: &str,
) -> Result<i64, MLSError> {
    let refused = |why: String| MLSError::Cryptography(format!("own {entry_kind} answer: {why}"));
    // `createConversation` and `closeConversation` answer `{"result": {...}}`.
    let answer = answer.get("result").unwrap_or(answer);
    let raw = answer
        .get("entry")
        .ok_or_else(|| refused("missing entry".into()))?;
    let entry = dr_transcript::normalize_read_presentation(
        &serde_json::to_vec(raw)?,
        entry_kind.trim_start_matches(crate::chat_v2::transcript::TYPE_PREFIX),
        raw.get("$type").is_some(),
    )
    .map_err(|e| refused(e.to_string()))?;
    if entry["conversationId"] != conversation_id || entry["signedRequest"] != *sent {
        return Err(refused("not this device's signed request".into()));
    }
    if let Some(next) = sent["body"].get("next") {
        let answered = answer
            .get("coordinates")
            .ok_or_else(|| refused("missing coordinates".into()))?;
        if chat_wire::canonicalize_wire_coordinate(answered, None)?
            != chat_wire::canonicalize_wire_coordinate(next, None)?
        {
            return Err(refused("coordinates are not the signed next".into()));
        }
    }
    entry["seq"]
        .as_i64()
        .ok_or_else(|| refused("missing seq".into()))
}

fn active_member_dids(group: &MlsGroup) -> Result<Vec<String>, MLSError> {
    group
        .members()
        .map(|member| {
            crate::push::root_did_from_credential_bytes(member.credential.serialized_content())
                .map(|(did, _)| did)
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|dids| dids.into_iter().collect())
}

/// Queue verified archive evidence for `flush_labyrinth_queue`, inside the caller's write
/// transaction: an own send, or a witness copy of a received message whose frame, nonce and
/// `I13` receipt were verified at receive time (the receive-time MLS roster travels with it).
pub(super) fn enqueue_labyrinth_archive(
    tx: &crate::storage::SqlTx<'_>,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<(), MLSError> {
    tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
        item_id: payload.message_id.clone(),
        conversation_id: payload.conversation_id.clone(),
        group_id_hex: payload.group_id_hex.clone(),
        seq: payload.seq,
        payload_bytes: serde_json::to_vec(payload)
            .map_err(|e| MLSError::Internal(format!("serialize queue payload: {e}")))?,
        created_at_ms: payload.created_at_ms,
    })
}

pub(super) fn canonical_labyrinth_frame_for_text(input: &str) -> (String, String) {
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

/// Parses a client-generated ID that must be a UUIDv4 (`InvalidInput` otherwise).
fn uuid_v4(raw: &str, field: &str) -> Result<uuid::Uuid, MLSError> {
    uuid::Uuid::parse_str(raw.trim())
        .ok()
        .filter(|u| {
            u.get_version() == Some(uuid::Version::Random)
                && u.get_variant() == uuid::Variant::RFC4122
        })
        .ok_or_else(|| MLSError::invalid_input(format!("{field} must be a UUIDv4")))
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

    /// The device ID a live mutation acts as; there is no local-only fallback.
    fn live_device_id(&self) -> Result<String, MLSError> {
        self.canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::invalid_input("device_id must be a UUIDv4"))
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
            // A terminal refusal deterministically rejects this attempt and must not retain
            // epoch keys; a transient one (e.g. `503 CapacityUnavailable`) keeps them.
            if is_terminal_rejection(&resp) {
                if let Some(transition_id) = pending_transition_id {
                    self.db.write_tx(|tx| {
                        tx.delete_pending_op("commit_transition", transition_id)?;
                        Ok(())
                    })?;
                }
            }
            return Err(chat_response_error(format_args!("POST {url}"), &resp));
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
        self.submit_prepared(prepared, body_value)
    }

    /// [`Self::submit_signed_chat_op`] for this device's own control: also returns the exact
    /// `signedRequest` it sent, which [`verify_own_answer`] holds the answer to.
    pub(super) fn submit_own_control(
        &self,
        device_id: &str,
        auth_generation: i64,
        operation: CanonicalOperation,
        body_value: &Value,
        signer: &SignatureKeyPair,
    ) -> Result<(Value, Value), MLSError> {
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.normalized_did,
            device_id,
            Some(auth_generation),
            operation,
            body_value,
            signer,
        )?;
        let mut sent: Value = serde_json::from_slice(prepared.body.as_deref().unwrap_or_default())?;
        let answer = self.submit_prepared(prepared, body_value)?;
        Ok((answer, sent["signedRequest"].take()))
    }

    fn submit_prepared(
        &self,
        prepared: PreparedRequest,
        body_value: &Value,
    ) -> Result<Value, MLSError> {
        let operation = prepared.operation;
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
            return Err(chat_response_error(format_args!("GET {url}"), &resp));
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

    /// `mls-ds` bootstrap: `enrollDevice`, PDS device + declaration records, request keys and
    /// KeyPackages. Completion is bound to the authoritative generation, canonical device ID and
    /// signer key; a retry after a crash or lost response confirms the exact enrollment because
    /// `enrollDevice` is create-only and request-key revisions must advance by one. The PDS
    /// records are written only once `mls-ds` holds this device under this exact key, so a
    /// device ID registered under another key keeps that key's PDS record.
    pub(crate) fn enroll_device_live(
        &self,
        canonical_device_id: &str,
        pub_key: &[u8],
    ) -> Result<(), MLSError> {
        let key_id = derive_key_id(pub_key);
        let completion = self.db.read_tx(|tx| {
            Ok((
                tx.get_account_meta("auth_generation")?,
                tx.get_account_meta("enrolled_device_id")?,
                tx.get_account_meta("enrolled_signer_key_id")?,
                tx.get_account_meta("scoped_identity")?,
                tx.get_account_meta("enrolled_signer_json")?,
            ))
        })?;
        if let (Some(auth_generation), bound_device, bound_key, scoped_identity, signer_json) =
            completion
        {
            let expected_identity = format!("{}#{canonical_device_id}", self.normalized_did);
            let device_matches = bound_device.as_deref() == Some(canonical_device_id)
                || (bound_device.is_none()
                    && scoped_identity.as_deref() == Some(expected_identity.as_str()));
            if !device_matches
                || bound_key
                    .as_deref()
                    .is_some_and(|bound| bound != key_id.as_str())
            {
                return Err(MLSError::InvalidState(
                    "EnrollmentDeviceIdentityMismatch".into(),
                ));
            }
            if bound_key.as_deref() == Some(key_id.as_str()) {
                return Ok(());
            }
            // Migrate a legacy completion marker only after the DS confirms this exact signer and
            // device. An account-wide generation alone is never an enrollment identity.
            let signer: SignatureKeyPair = serde_json::from_str(
                signer_json
                    .as_deref()
                    .ok_or_else(|| MLSError::InvalidState("signer missing".into()))?,
            )
            .map_err(|e| MLSError::Internal(format!("deserialize signer: {e}")))?;
            if signer.public() != pub_key {
                return Err(MLSError::InvalidState(
                    "EnrollmentSignerIdentityMismatch".into(),
                ));
            }
            let own = self.own_enrolled_device(canonical_device_id, &signer)?;
            if own
                .pointer("/device/authGeneration")
                .or_else(|| own.get("authGeneration"))
                .and_then(Value::as_i64)
                != auth_generation.parse::<i64>().ok()
            {
                return Err(MLSError::InvalidState(
                    "EnrollmentDeviceIdentityMismatch".into(),
                ));
            }
            self.db.write_tx(|tx| {
                tx.put_account_meta(
                    "enrolled_device_id",
                    canonical_device_id,
                    self.hooks.now_ms(),
                )?;
                tx.put_account_meta("enrolled_signer_key_id", &key_id, self.hooks.now_ms())
            })?;
            return Ok(());
        }
        // 1. Build 2 X-Wing KeyPackages in `write_tx` (`MlsMessageOut` framing, sorted by hash_ref).
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

        // 2. `enrollDevice`, or adopt the enrollment a lost response left behind.
        let (enroll_resp, request_keys_published) = match self.submit_signed_chat_op(
            canonical_device_id,
            None,
            CanonicalOperation::EnrollDevice,
            &enroll_body,
            &signer,
        ) {
            Ok(resp) => (resp, false),
            // An earlier attempt registered this device, but its response was lost.
            Err(MLSError::InvalidState(code)) if code == "DeviceAlreadyExists" => {
                let own = self.own_enrolled_device(canonical_device_id, &signer)?;
                let published = own.get("directRequestKeyPool").is_some();
                (own, published)
            }
            Err(e) => return Err(e),
        };
        // The key check precedes every PDS write: a fresh answer or an adopted enrollment
        // naming another device, key or generation leaves both PDS records untouched.
        let auth_generation = chat_wire::own_active_device(
            &json!({ "items": [&enroll_resp] }),
            canonical_device_id,
            pub_key,
        )
        .filter(|own| own["device"]["keyId"] == key_id.as_str())
        .and_then(|own| own["device"]["authGeneration"].as_i64())
        .filter(|generation| *generation >= 1)
        .ok_or_else(|| MLSError::InvalidState("EnrollmentDeviceIdentityMismatch".into()))?;

        // 3. Publish ADR-009 PDS `blue.catbird.chat.device/{device_id}` + `blue.catbird.chat.declaration/self`.
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

        // 4. Generate + publish the C33 DirectRequestKeyPublication unless the DS already has it.
        let now_ms = self.hooks.now_ms();
        if !request_keys_published {
            let dr_exact_request = self.db.write_tx(|tx| {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let (raw_pub_rec, _) = build_request_key_publication(
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
            let dr_keys_url = format!(
                "{}/xrpc/blue.catbird.chat.publishDirectRequestKeys",
                self.ds_base()
            );
            let _ = self.execute_json_post(dr_keys_url, dr_exact_request)?;
        }

        // 5. Persist the authoritative completion binding atomically. The generation, exact
        // canonical device, and signer key must all match before a future call is a local no-op.
        self.db.write_tx(|tx| {
            tx.put_account_meta("auth_generation", &auth_generation.to_string(), now_ms)?;
            tx.put_account_meta("enrolled_device_id", canonical_device_id, now_ms)?;
            tx.put_account_meta("enrolled_signer_key_id", &key_id, now_ms)
        })?;
        let _ = self.replenish_key_packages(4)?;
        Ok(())
    }

    /// The DS's active enrollment of this device under `signer` (`chat_wire::own_active_device`).
    /// The DS also verifies this signed read against the device's registered key.
    fn own_enrolled_device(
        &self,
        canonical_device_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        // ponytail: first page only (100 items; accounts hold at most 20 active devices); follow
        // `nextPageCursor` if revoked devices ever push this one past it.
        let devices = self.query_signed_chat_ds(
            "blue.catbird.chat.getOwnDevices",
            &[("actorDeviceId", canonical_device_id), ("limit", "100")],
            canonical_device_id,
            signer,
        )?;
        chat_wire::own_active_device(&devices, canonical_device_id, signer.public())
            .cloned()
            .ok_or_else(|| {
                MLSError::InvalidState(format!(
                    "DeviceAlreadyExists: mls-ds holds device {canonical_device_id} under another key"
                ))
            })
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

    pub(crate) fn create_group_live(
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

        let canonical_dev_id = self.live_device_id()?;
        let convo_uuid = uuid_v4(conversation_id, "conversation_id")?;
        for peer in &peers {
            if let Err(e) = crate::chat_v2::ids::BareDid::parse(peer) {
                return Err(MLSError::invalid_input(format!(
                    "peer DID '{peer}' is not a valid bare DID: {e}"
                )));
            }
        }
        let canonical_convo_id = convo_uuid.hyphenated().to_string();

        let is_untitle_one_to_one =
            peers.len() == 1 && title.as_deref().unwrap_or("").trim().is_empty();
        if is_untitle_one_to_one {
            // Before any network effect: a journaled attempt may still be inside `Retry-After`.
            return self.create_c33_direct_request_live(
                &canonical_convo_id,
                &canonical_dev_id,
                &peers[0],
                description,
            );
        }

        // Verify PDS `blue.catbird.chat.device` keys (`I4`) for all peers up front.
        self.fetch_and_cache_authorized_pds_device_keys(&self.normalized_did)?;
        for peer in &peers {
            self.fetch_and_cache_authorized_pds_device_keys(peer)?;
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

    /// Untitled 1:1 creation (`C33`). The peer-keyed journal is created and advanced with CAS,
    /// so concurrent callers can only publish the one immutable bootstrap that won ownership.
    fn create_c33_direct_request_live(
        &self,
        canonical_convo_id: &str,
        canonical_dev_id: &str,
        peer_did: &str,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let (signer, auth_generation) = self.load_enrolled_signer_and_auth_gen()?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
        let mut caller_description = description;
        loop {
            let journaled = self
                .db
                .read_tx(|tx| tx.get_pending_op(DIRECT_REQUEST_CREATION_OP, peer_did))?;
            let mut raw = if let Some(raw) = journaled {
                raw
            } else {
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
                let candidate = PendingDirectRequestCreation {
                    version: DIRECT_REQUEST_CREATION_VERSION,
                    prepare_wrapper: chat_wire::sign_direct_request_wrapper(
                        DirectRequestKind::Prepare,
                        prepare_body,
                        &signer,
                    )?,
                    request_id,
                    first_message_id,
                    conversation_id: canonical_convo_id.to_string(),
                    intro_text: caller_description
                        .take()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| "👋".to_string()),
                    retry_at_ms: 0,
                    retry_code: None,
                    publish: None,
                };
                let candidate_raw = serde_json::to_string(&candidate).map_err(|e| {
                    MLSError::Internal(format!("serialize pending direct request: {e}"))
                })?;
                self.db.write_tx(|tx| {
                    if tx.compare_exchange_pending_op(
                        DIRECT_REQUEST_CREATION_OP,
                        peer_did,
                        None,
                        &candidate_raw,
                        self.hooks.now_ms(),
                    )? {
                        return Ok(candidate_raw.clone());
                    }
                    tx.get_pending_op(DIRECT_REQUEST_CREATION_OP, peer_did)?
                        .ok_or_else(|| {
                            MLSError::Internal(
                                "C33 journal ownership changed during creation".into(),
                            )
                        })
                })?
            };
            let mut pending: PendingDirectRequestCreation = serde_json::from_str(&raw)
                .map_err(|e| MLSError::Internal(format!("parse pending direct request: {e}")))?;
            if pending.version != DIRECT_REQUEST_CREATION_VERSION {
                return Err(MLSError::Internal(format!(
                    "unsupported pending direct request version {}",
                    pending.version
                )));
            }
            let wait_ms = pending.retry_at_ms.saturating_sub(self.hooks.now_ms());
            if wait_ms > 0 && wait_ms <= MAX_RETRY_AFTER_SECS as i64 * 1_000 {
                return Err(match pending.retry_code {
                    Some(code) => MLSError::InvalidState(code),
                    None => MLSError::Internal("C33 direct request deferred by Retry-After".into()),
                });
            }
            let prepare = dr_transcript::verify_signed_request(
                DirectRequestKind::Prepare,
                &pending.prepare_wrapper,
                signer.public(),
            )
            .map_err(|e| MLSError::Cryptography(format!("verify self C33 prepare: {e}")))?;
            if pending.publish.is_none()
                && !self.prepare_c33_publication(
                    &mut pending,
                    &mut raw,
                    &prepare,
                    peer_did,
                    canonical_dev_id,
                    &signer,
                    &key_id,
                    auth_generation,
                )?
            {
                continue;
            }
            return self.publish_c33_direct_request(
                pending,
                raw,
                &prepare,
                peer_did,
                canonical_dev_id,
                &signer,
                &key_id,
                auth_generation,
            );
        }
    }

    /// Prepare stage of [`Self::create_c33_direct_request_live`]: replay the journaled prepare,
    /// verify the preparation, build the MLS bootstrap as an unapplied overlay, sign its
    /// publication and journal all of it before anything is published.
    #[allow(clippy::too_many_arguments)]
    fn prepare_c33_publication(
        &self,
        pending: &mut PendingDirectRequestCreation,
        raw: &mut String,
        prepare: &dr_transcript::VerifiedDirectRequest,
        peer_did: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        key_id: &str,
        auth_generation: i64,
    ) -> Result<bool, MLSError> {
        // Verify PDS `blue.catbird.chat.device` keys (`I4`) for both accounts up front.
        let mut auth_keys_by_did: BTreeMap<String, Vec<AuthorizedPeerDeviceKey>> = BTreeMap::new();
        for did in [self.normalized_did.as_str(), peer_did] {
            auth_keys_by_did.insert(
                did.to_string(),
                self.fetch_and_cache_authorized_pds_device_keys(did)?,
            );
        }

        let prepare_url = format!(
            "{}/xrpc/blue.catbird.chat.prepareDirectRequest",
            self.ds_base()
        );
        let prepare_http =
            self.post_json_raw(&prepare_url, signed_request_body(&pending.prepare_wrapper))?;
        if prepare_http.status >= 400 {
            return Err(self.c33_refused(peer_did, pending, raw, &prepare_url, &prepare_http));
        }

        let prep_outer: Value = serde_json::from_slice(&prepare_http.body)
            .map_err(|e| MLSError::Internal(format!("parse prepareDirectRequest: {e}")))?;
        // The coordinator signs both a preparation and a terminal receipt.
        let peer_ds = self.resolve_peer_home_ds_did(peer_did).ok_or_else(|| {
            MLSError::Cryptography("C33 peer home DS authority unavailable".into())
        })?;
        let effective_sequencer = dr_transcript::derive_deterministic_coordinator(
            self.config.home_ds_did.trim(),
            &peer_ds,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 coordinator: {e}")))?;
        let authority_did = effective_sequencer.as_str();
        let authority_doc = self.resolve_did_document(authority_did)?.ok_or_else(|| {
            MLSError::Cryptography(format!(
                "C33: missing receipt authority DID document {authority_did}"
            ))
        })?;
        let receipt_key = |kid: &str| {
            dr_transcript::resolve_direct_request_receipt_key_for_authority(
                authority_did,
                &authority_doc,
                kid,
            )
            .map_err(|e| MLSError::Cryptography(format!("C33 receipt authority: {e}")))
        };
        let outcome = &prep_outer["outcome"];
        if outcome["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt" {
            // A signed durable decision (e.g. the replayed lease expired) drops the attempt only
            // once it verifies like a publication outcome; anything else fails closed.
            let key = receipt_key(outcome["body"]["keyId"].as_str().unwrap_or_default())?;
            let receipt = chat_wire::verify_c33_outcome(outcome, authority_did, &key)?;
            let code = chat_wire::c33_terminal_receipt_code(&receipt, prepare, None)?
                .ok_or_else(|| MLSError::Cryptography("C33 outcome binding mismatch".into()))?;
            return Err(self.forget_c33_creation(peer_did, raw, MLSError::InvalidState(code)));
        }
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

        if preparation["authorityDid"].as_str() != Some(authority_did) {
            return Err(MLSError::Cryptography(
                "C33 preparation authority mismatch".into(),
            ));
        }
        let receipt_kid = preparation
            .get("receiptKeyId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 preparation missing receiptKeyId".into()))?;
        let authority_key = receipt_key(receipt_kid)?;
        // The bootstrap input pins the sequencer's current receipt method; the published
        // opening receipt itself is verified under the method its own `kid` names.
        let sequencer_receipt_key = chat_wire::current_sequencer_receipt_key(
            &self
                .resolve_did_document(&effective_sequencer)?
                .ok_or_else(|| {
                    MLSError::Cryptography("C33: missing sequencer DID document".into())
                })?,
            &effective_sequencer,
        )?;

        if preparation["conversationId"].as_str() != Some(pending.conversation_id.as_str()) {
            return Err(MLSError::Cryptography(
                "C33 preparation conversation mismatch".into(),
            ));
        }
        let prep_digest_b64 =
            STANDARD.encode(chat_wire::json_bytes(&preparation["preparationDigest"])?);
        let context_val = json!({
            "protocolVersion": "2",
            "requestId": pending.request_id,
            "firstMessageId": pending.first_message_id,
            "conversationId": pending.conversation_id,
            "origin": prepare.body()["origin"],
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "actorKeyId": key_id,
            "recipientDid": peer_did,
            "preparationDigest": prep_digest_b64,
        });
        let context_json =
            serde_json::to_vec(&context_val).map_err(|e| MLSError::Internal(e.to_string()))?;

        let group_id_bytes = self.hooks.random_array::<32>().to_vec();
        let now_secs = self.hooks.now_secs();

        let (bootstrap, kv_batch) = self.db.read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let boot = {
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = self.hooks.openmls_provider(storage);
                let (_group, boot) = direct_request_bootstrap::prepare_with_provider(
                    &provider,
                    signer,
                    &DirectRequestBootstrapInput {
                        draft_id: pending.request_id.clone(),
                        context_json,
                        group_id: group_id_bytes.clone(),
                        generation: 0,
                        state_version: 1,
                        key_packages: packages,
                        expected_package_refs: refs,
                        authority_import_until: min_deadline,
                        preparation_request_digest: *prepare.request_digest(),
                        receipt_authority_key: authority_key.clone(),
                        sequencer_did: effective_sequencer.clone(),
                        sequencer_receipt_authority_key: sequencer_receipt_key,
                        text: pending.intro_text.clone(),
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

        let import_until_str = chat_wire::unix_secs_rfc3339_millis(bootstrap.import_until)?;
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
                    "requestId": pending.request_id,
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
            "originTransitionId": pending.request_id,
            "originSeq": 1,
            "roleAtOrigin": "admin",
            "deviceStatusAtOrigin": "active",
        });

        let mut publish_body = prepare.body().clone();
        publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        publish_body["signedAt"] = json!(self.hooks.now_rfc3339_millis());
        publish_body["preparationDigest"] = json!(prep_digest_b64);
        publish_body["preparationRequestDigest"] = json!(STANDARD.encode(prepare.request_digest()));
        publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
        publish_body["next"] = bootstrap.coordinates.clone();
        publish_body["archiveCommitment"] = json!(STANDARD.encode(bootstrap.archive_commitment));
        publish_body["originalSenderAttestation"] = json!({
            "senderDid": bootstrap.original_sender_attestation.sender_did,
            "senderDeviceId": bootstrap.original_sender_attestation.sender_device_id,
            "senderTransportPubkey": STANDARD.encode(
                &bootstrap
                    .original_sender_attestation
                    .sender_transport_public_key
            ),
            "signature": STANDARD.encode(&bootstrap.original_sender_attestation.signature),
        });
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
                "originTransitionId": pending.request_id,
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
                "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
                "ciphertextSize": bootstrap.metadata_ciphertext.len(),
                "authorProof": author_proof,
            }
        });

        let publish_wrapper = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Publish,
            publish_body,
            signer,
        )?;
        pending.publish = Some(PendingDirectRequestPublication {
            group_id: group_id_bytes,
            sequencer_did: effective_sequencer,
            bootstrap,
            kv_batch,
            publish_wrapper,
        });
        // CAS before send: a concurrent builder that lost ownership reloads this exact winner
        // instead of publishing a second MLS bootstrap.
        self.save_direct_request_creation(peer_did, pending, raw)
    }

    /// Publish stage of [`Self::create_c33_direct_request_live`]: replay the journaled
    /// publication and commit its bootstrap only on the verified published receipt, in the
    /// same write that drops the journal.
    #[allow(clippy::too_many_arguments)]
    fn publish_c33_direct_request(
        &self,
        mut pending: PendingDirectRequestCreation,
        mut raw: String,
        prepare: &dr_transcript::VerifiedDirectRequest,
        peer_did: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        key_id: &str,
        auth_generation: i64,
    ) -> Result<ConversationRow, MLSError> {
        let publication = pending
            .publish
            .as_ref()
            .ok_or_else(|| MLSError::Internal("C33 creation journal has no publication".into()))?;
        let verified_publication = dr_transcript::verify_signed_request(
            DirectRequestKind::Publish,
            &publication.publish_wrapper,
            signer.public(),
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 signed publication: {e}")))?;
        let publish_url = format!(
            "{}/xrpc/blue.catbird.chat.publishDirectRequest",
            self.ds_base()
        );
        if crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P2PrematureMergeBeforeServerAccept,
        ) {
            self.db.write_tx(|tx| {
                self.clear_cached_groups();
                Ok(publication.kv_batch.apply(&RusqliteKvBackend(tx.conn()))?)
            })?;
        }
        let published_http = self.post_json_raw(
            &publish_url,
            signed_request_body(&publication.publish_wrapper),
        )?;
        if published_http.status >= 400 {
            return Err(self.c33_refused(
                peer_did,
                &mut pending,
                &mut raw,
                &publish_url,
                &published_http,
            ));
        }
        let PendingDirectRequestCreation {
            request_id,
            first_message_id,
            conversation_id: effective_convo_id,
            intro_text,
            ..
        } = &pending;
        let PendingDirectRequestPublication {
            group_id: group_id_bytes,
            sequencer_did: effective_sequencer,
            bootstrap,
            kv_batch,
            ..
        } = publication;

        let published: Value = serde_json::from_slice(&published_http.body)?;
        let outcome = published.get("outcome").ok_or_else(|| {
            MLSError::Cryptography("C33 publication response missing signed outcome".into())
        })?;
        let receipt_method = outcome
            .pointer("/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| MLSError::Cryptography("C33 outcome missing receipt keyId".into()))?;
        let authority_doc = self
            .resolve_did_document(effective_sequencer)?
            .ok_or_else(|| {
                MLSError::Cryptography("C33 publication authority document unavailable".into())
            })?;
        let authority_key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            effective_sequencer,
            &authority_doc,
            receipt_method,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 publication receipt key: {e}")))?;
        let publication_receipt =
            chat_wire::verify_c33_outcome(outcome, effective_sequencer, &authority_key)?;
        // A signed decision not to publish (e.g. the lease expired before this replay).
        if let Some(code) = chat_wire::c33_terminal_receipt_code(
            &publication_receipt,
            prepare,
            Some(&verified_publication),
        )? {
            return Err(self.forget_c33_creation(peer_did, &raw, MLSError::InvalidState(code)));
        }
        if publication_receipt["$type"] != "blue.catbird.chat.defs#directRequestPublishedReceipt"
            || publication_receipt["requestId"] != *request_id
            || publication_receipt["conversationId"] != *effective_convo_id
            || publication_receipt["firstMessageId"] != *first_message_id
            || publication_receipt["requestKind"] != "publish"
            || publication_receipt["actorDid"].as_str() != Some(self.normalized_did.as_str())
            || publication_receipt["actorDeviceId"].as_str() != Some(canonical_dev_id)
            || publication_receipt["actorKeyId"] != key_id
            || publication_receipt["authGeneration"].as_i64() != Some(auth_generation)
            || publication_receipt["requestDigest"].as_str()
                != Some(
                    STANDARD
                        .encode(verified_publication.request_digest())
                        .as_str(),
                )
            || publication_receipt["preparationRequestDigest"].as_str()
                != Some(STANDARD.encode(prepare.request_digest()).as_str())
            || publication_receipt["coordinates"] != bootstrap.coordinates
        {
            return Err(MLSError::Cryptography(
                "C33 publication outcome binding mismatch".into(),
            ));
        }
        let opening_receipt = &publication_receipt["sequencerReceipt"];
        let sequencer_receipt_key = chat_wire::decode_p256_sec1_from_did_doc(
            &authority_doc,
            effective_sequencer,
            chat_wire::sequencer_receipt_kid(effective_sequencer, opening_receipt)?,
        )?;
        let (opening_seq, _, opening_receipt_json) =
            direct_request_bootstrap::verify_opening_receipt(
                bootstrap,
                opening_receipt,
                effective_sequencer,
                &sequencer_receipt_key,
            )?;
        let opening_seq = i64::try_from(opening_seq)
            .map_err(|_| MLSError::Cryptography("C33 sequence overflow".into()))?;
        let opening = bootstrap.opening.as_ref().ok_or_else(|| {
            MLSError::Cryptography("C33 sender missing authenticated opening frame".into())
        })?;
        let space_uri = Some(format!(
            "at://{effective_sequencer}/space/blue.catbird.labyrinth.conversation/{effective_convo_id}-0"
        ));
        let now_ms = self.hooks.now_ms();
        let display_json = json!({ "text": intro_text }).to_string();
        let frame_json = String::from_utf8(opening.canonical_payload_bytes.clone())
            .map_err(|e| MLSError::Cryptography(format!("C33 opening frame: {e}")))?;
        let coords_str = serde_json::to_string(&bootstrap.coordinates)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        let convo_row = self.db.write_tx(|tx| {
            let Some(current_raw) = tx.get_pending_op(DIRECT_REQUEST_CREATION_OP, peer_did)? else {
                return tx.get_conversation(effective_convo_id)?.ok_or_else(|| {
                    MLSError::Internal("C33 journal disappeared before publication commit".into())
                });
            };
            let current: PendingDirectRequestCreation = serde_json::from_str(&current_raw)
                .map_err(|e| MLSError::Internal(format!("parse current C33 journal: {e}")))?;
            if !same_direct_request_attempt(&pending, &current)? {
                return Err(MLSError::InvalidState(
                    "DirectRequestOwnershipChanged".into(),
                ));
            }
            kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
            self.clear_cached_groups();
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id_bytes))
                .map_err(|e| MLSError::Internal(format!("load C33 roster: {e:?}")))?
                .ok_or_else(|| MLSError::group_not_found(effective_convo_id))?;
            let expected_member_dids = active_member_dids(&group)?;
            let row = ConversationRow {
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                generation: 0,
                epoch: 1,
                last_seq: opening_seq,
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
                expires_at_ms: (bootstrap.import_until as i64).saturating_mul(1000),
                updated_at_ms: now_ms,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.clone(),
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                epoch: 1,
                seq: opening_seq,
                sender_did: self.normalized_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                plaintext_json: display_json.clone(),
                created_at_ms: now_ms,
                is_own: true,
            })?;

            // Stage C33 opening message for conversation Space archival ONLY after recipient acceptance!
            let staged_opening = QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id.clone(),
                conversation_id: effective_convo_id.clone(),
                group_id_hex: hex::encode(group_id_bytes),
                epoch: 1,
                expected_member_dids,
                seq: opening_seq,
                sender_did: self.normalized_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sequencer_did: effective_sequencer.clone(),
                space_uri,
                plaintext_json: display_json,
                labyrinth_frame_json: frame_json,
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: Some(STANDARD.encode(opening.frame_nonce)),
                sequencer_receipt_json: Some(opening_receipt_json),
                original_sender_attestation_json: Some(
                    serde_json::to_string(&bootstrap.original_sender_attestation).map_err(
                        |error| {
                            MLSError::Internal(format!(
                                "serialize C33 original sender attestation: {error}"
                            ))
                        },
                    )?,
                ),
                created_at_ms: now_ms,
            };
            tx.put_labyrinth_state(
                &format!(
                    "native.message:{effective_convo_id}:{}",
                    staged_opening.message_id
                ),
                &serde_json::to_vec(&staged_opening)?,
                now_ms,
            )?;
            tx.put_account_meta(
                &format!("c33_pending_opening:{effective_convo_id}"),
                &serde_json::to_string(&staged_opening)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                now_ms,
            )?;
            // The attempt is resolved in the same write that applies its bootstrap.
            if !tx.delete_pending_op_if_payload(
                DIRECT_REQUEST_CREATION_OP,
                peer_did,
                &current_raw,
            )? {
                return Err(MLSError::InvalidState(
                    "DirectRequestOwnershipChanged".into(),
                ));
            }
            Ok(row)
        })?;

        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        self.notify_change(PlatformChangeEvent::RequestsUpdated);
        Ok(convo_row)
    }

    /// CAS `pending` in its own write transaction, never around HTTP (`I6`). Losing ownership
    /// leaves the winner untouched so the caller can reload its immutable publication.
    fn save_direct_request_creation(
        &self,
        peer_did: &str,
        pending: &PendingDirectRequestCreation,
        expected_raw: &mut String,
    ) -> Result<bool, MLSError> {
        let payload = serde_json::to_string(pending)
            .map_err(|e| MLSError::Internal(format!("serialize pending direct request: {e}")))?;
        let changed = self.db.write_tx(|tx| {
            tx.compare_exchange_pending_op(
                DIRECT_REQUEST_CREATION_OP,
                peer_did,
                Some(expected_raw.as_str()),
                &payload,
                self.hooks.now_ms(),
            )
        })?;
        if changed {
            *expected_raw = payload;
        }
        Ok(changed)
    }

    /// Drop the creation journal only if this caller still owns the exact bytes.
    fn forget_c33_creation(&self, peer_did: &str, expected_raw: &str, error: MLSError) -> MLSError {
        match self.db.write_tx(|tx| {
            tx.delete_pending_op_if_payload(DIRECT_REQUEST_CREATION_OP, peer_did, expected_raw)
        }) {
            Ok(true) => error,
            Ok(false) => MLSError::InvalidState("DirectRequestOwnershipChanged".into()),
            Err(db) => db,
        }
    }

    /// A refused prepare may resolve its pre-publication journal. Once publication bytes exist,
    /// no unsigned response proves nonpublication: every 4xx/5xx/auth failure retains them.
    fn c33_refused(
        &self,
        peer_did: &str,
        pending: &mut PendingDirectRequestCreation,
        expected_raw: &mut String,
        url: &str,
        resp: &PlatformHttpResponse,
    ) -> MLSError {
        let error = chat_response_error(format_args!("POST {url}"), resp);
        let terminal = is_terminal_rejection(resp);
        if terminal && pending.publish.is_none() {
            return self.forget_c33_creation(peer_did, expected_raw, error);
        }
        let delay_ms = if terminal {
            0
        } else {
            retry_after_secs(resp.header("retry-after")).unwrap_or(0) * 1_000
        };
        pending.retry_at_ms = self.hooks.now_ms().saturating_add(delay_ms as i64);
        pending.retry_code = match &error {
            MLSError::InvalidState(code) => Some(code.clone()),
            _ => None,
        };
        match self.save_direct_request_creation(peer_did, pending, expected_raw) {
            Ok(true) => error,
            Ok(false) => MLSError::InvalidState("DirectRequestOwnershipChanged".into()),
            Err(db) => db,
        }
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
                    .sender_ratchet_configuration(
                        crate::types::GroupConfig::default().sender_ratchet_configuration(),
                    )
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
        let (resp_val, sent) = self.submit_own_control(
            canonical_dev_id,
            auth_generation,
            CanonicalOperation::CreateConversation,
            &create_body,
            &signer,
        )?;
        // A creation is its conversation's first entry; any other answer changes nothing.
        let server_seq =
            verify_own_answer(&resp_val, &sent, canonical_convo_id, CREATION_ENTRY_KIND)?;
        if server_seq != 1 {
            return Err(MLSError::Cryptography(format!(
                "own creation answer: seq {server_seq} is not the first entry"
            )));
        }
        let generation = next_coords
            .get("generation")
            .and_then(|g| g.as_i64())
            .unwrap_or(0);
        let space_uri = Some(format!(
            "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{canonical_convo_id}-{generation}"
        ));
        let coords_str =
            serde_json::to_string(&next_coords).map_err(|e| MLSError::Internal(e.to_string()))?;
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
        uuid_v4(conversation_id, "conversation_id")?;
        if peers.is_empty() {
            return Err(MLSError::invalid_input(
                "member_dids must name another account",
            ));
        }
        let canonical_dev_id = self.live_device_id()?;

        let existing = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {conversation_id} not found"),
            })?;

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

        let (resp_val, sent) = self.submit_own_control(
            &canonical_dev_id,
            auth_generation,
            CanonicalOperation::SubmitTransition,
            &policy_body,
            &signer,
        )?;
        // A foreign answer changes nothing, as a lost response; sync applies the own echo.
        let new_seq = verify_own_answer(&resp_val, &sent, conversation_id, POLICY_ENTRY_KIND)?;
        let now_ms = self.hooks.now_ms();
        let coords_str =
            serde_json::to_string(&next_coords).map_err(|e| MLSError::Internal(e.to_string()))?;

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
            self.sync_conversation_entries(&canonical_dev_id, &signer, &updated)?;
        }

        self.fulfill_pending_leaf_recoveries(&canonical_dev_id, &signer, auth_generation)?;
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

    pub(crate) fn send_message_live(
        &self,
        conversation_id: &str,
        message_id: &str,
        text: &str,
    ) -> Result<MessageRow, MLSError> {
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(text);
        // Validate before any MLS, DB or archive effect: a non-UUIDv4 send has no live path.
        let convo_uuid = uuid_v4(conversation_id, "conversation_id")?;
        let msg_uuid = uuid_v4(message_id, "message_id")?;
        let canonical_dev_id = self.live_device_id()?;
        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let reserve = || {
            self.reserve_application_send(
                convo_uuid,
                msg_uuid,
                &canonical_dev_id,
                &display_json,
                &frame_json,
            )
        };
        // `StaleSend` refuses those exact bytes for good: their journal goes, in its own write,
        // before anything else can fail, so no later retry of this message id resubmits them.
        let discard_refused = || {
            self.db.write_tx(|tx| {
                tx.delete_pending_op("application_send", &canonical_msg_id)
                    .map(drop)
            })
        };
        // Strictly outside `write_tx` (`I6`); retries reuse the journal's exact signed body.
        let submit =
            |signer: &SignatureKeyPair, auth_generation, pending: &PendingApplicationSend| {
                self.submit_signed_chat_op(
                    &canonical_dev_id,
                    Some(auth_generation),
                    CanonicalOperation::SendMessage,
                    &pending.body,
                    signer,
                )
            };
        let (mut signer, mut auth_generation, mut pending, mut send_retry) = reserve()?;
        let resp_val = match submit(&signer, auth_generation, &pending) {
            // `mls-ds` already sequenced a newer send from this device and refuses these bytes
            // for good. Send the same message id once more as a fresh frame and counter.
            Err(error) if chat_wire::is_stale_send(&error) => {
                discard_refused()?;
                (signer, auth_generation, pending, send_retry) = reserve()?;
                match submit(&signer, auth_generation, &pending) {
                    Err(error) if chat_wire::is_stale_send(&error) => {
                        discard_refused()?;
                        return Err(error);
                    }
                    result => result?,
                }
            }
            result => result?,
        };

        // Mandatory `I13` ES256 `sequencerReceipt`, verified under the method its `kid` names.
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

    /// Reserve the sender generation, `sendCounter` and immutable recovery material atomically
    /// before HTTP. A timeout can still publish the ciphertext; rolling the ratchet back would
    /// reuse its key. An existing journal for the message id is returned unchanged: only a
    /// `StaleSend` refusal discards one (those exact bytes are refused for good).
    fn reserve_application_send(
        &self,
        convo_uuid: uuid::Uuid,
        msg_uuid: uuid::Uuid,
        canonical_dev_id: &str,
        display_json: &str,
        frame_json: &str,
    ) -> Result<(SignatureKeyPair, i64, PendingApplicationSend, bool), MLSError> {
        let frame_nonce = self.hooks.random_array::<32>();
        let archive_commitment = labyrinth_protocol::receipt::compute_archive_commitment(
            &frame_nonce,
            frame_json.as_bytes(),
        );
        let now_ms = self.hooks.now_ms();

        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        let canonical_msg_id = msg_uuid.hyphenated().to_string();

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

        self.db.write_tx(|tx| {
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
            // Strictly above every counter this device signed here, so `mls-ds` sequences its
            // sends in MLS generation order; persisted with this frame's ratchet advance below.
            let counter_key = chat_wire::send_counter_key(&canonical_convo_id);
            let send_counter =
                chat_wire::next_send_counter(tx.get_account_meta(&counter_key)?.as_deref())?;

            let attestation_transcript =
                labyrinth_protocol::transcripts::original_sender_archive_transcript(
                    &canonical_convo_id,
                    &canonical_msg_id,
                    &archive_commitment,
                );
            let original_sender_attestation = OriginalSenderArchiveAttestationEnvelope {
                sender_did: self.normalized_did.clone(),
                sender_device_id: canonical_dev_id.to_owned(),
                sender_transport_public_key: signer.public().to_vec(),
                signature: signer.sign(&attestation_transcript).map_err(|error| {
                    MLSError::Cryptography(format!(
                        "sign original sender archive attestation: {error:?}"
                    ))
                })?,
            };
            original_sender_attestation.verify(
                &canonical_convo_id,
                &canonical_msg_id,
                &archive_commitment,
            )?;
            let inner_plaintext = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
                frame_nonce,
                canonical_payload_bytes: frame_json.as_bytes().to_vec(),
                original_sender_attestation: Some(original_sender_attestation.clone()),
            })
            .map_err(|error| {
                MLSError::Internal(format!(
                    "serialize PrivateMessagePlaintextEnvelope: {error}"
                ))
            })?;
            let original_sender_attestation_json =
                serde_json::to_string(&original_sender_attestation).map_err(|error| {
                    MLSError::Internal(format!(
                        "serialize original sender archive attestation: {error}"
                    ))
                })?;

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
                "originalSenderAttestation": original_sender_attestation.to_aad_json(),
            });
            let aad_bytes = canonical_application_aad_bytes(&aad_val).map_err(|e| {
                MLSError::Cryptography(format!("canonical_application_aad_bytes: {e}"))
            })?;

            let ciphertext = {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                let (ct, active_epoch, expected_member_dids) = self
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
                            if group.epoch().as_u64() != epoch_u64
                                || convo.generation != generation
                                || convo.epoch != epoch_u64 as i64
                                || chat_wire::json_bytes(&prior_coords["groupId"])?
                                    != convo.group_id
                            {
                                return Err(MLSError::InvalidState("StaleCoordinates".into()));
                            }
                            let (active_gch, active_ctag) =
                                chat_wire::compute_group_context_hash_and_tag(group, &provider)?;
                            if active_gch.as_slice() != gch.as_slice() || active_ctag != ctag {
                                return Err(MLSError::InvalidState("StaleCoordinates".into()));
                            }
                            let expected_member_dids = active_member_dids(group)?;
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
                            Ok((ct, group.epoch().as_u64() as i64, expected_member_dids))
                        },
                    )?
                    .ok_or_else(|| MLSError::GroupNotFound {
                        message: format!("MlsGroup missing for {canonical_convo_id}"),
                    })?;
                (ct, active_epoch, expected_member_dids)
            };

            let body = json!({
                "$type": "blue.catbird.chat.defs#applicationSendBody",
                "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
                "messageId": canonical_msg_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "sendCounter": send_counter,
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
                    expected_member_dids: ciphertext.2,
                    seq: 0,
                    sender_did: self.normalized_did.clone(),
                    sender_device_id: canonical_dev_id.to_owned(),
                    sequencer_did: convo.sequencer_did,
                    space_uri: convo.space_uri,
                    plaintext_json: display_json.to_owned(),
                    labyrinth_frame_json: frame_json.to_owned(),
                    mls_ciphertext_b64: STANDARD.encode(&ciphertext.0),
                    frame_nonce_b64: Some(STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    original_sender_attestation_json: Some(original_sender_attestation_json),
                    created_at_ms: now_ms,
                },
            };
            let payload = serde_json::to_string(&pending)
                .map_err(|e| MLSError::Internal(format!("serialize pending send: {e}")))?;
            tx.put_account_meta(&counter_key, &send_counter.to_string(), now_ms)?;
            tx.put_pending_op("application_send", &canonical_msg_id, &payload, now_ms)?;
            Ok((signer, auth_gen, pending, false))
        })
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
        let kid = chat_wire::sequencer_receipt_kid(&queued.sequencer_did, receipt)?;
        let sec1_key = self
            .resolve_sequencer_receipt_key(&queued.sequencer_did, kid)?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13: unable to resolve `{}` receipt method {kid}",
                    queued.sequencer_did
                ))
            })?;
        let original_sender_attestation: OriginalSenderArchiveAttestationEnvelope =
            serde_json::from_str(
                queued
                    .original_sender_attestation_json
                    .as_deref()
                    .ok_or_else(|| {
                        MLSError::Cryptography(
                            "pending send missing original sender archive attestation".into(),
                        )
                    })?,
            )
            .map_err(|error| {
                MLSError::Cryptography(format!(
                    "invalid original sender archive attestation: {error}"
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
            &queued.message_id,
            &commitment,
            Some(&original_sender_attestation),
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
            tx.put_labyrinth_state(
                &format!(
                    "native.message:{}:{}",
                    queued.conversation_id, queued.message_id
                ),
                &serde_json::to_vec(&queued)?,
                self.hooks.now_ms(),
            )?;
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
                tx.dequeue_labyrinth_item(&queued.message_id)?;
                enqueue_labyrinth_archive(tx, &queued)?;
            }
            tx.delete_pending_op("application_send", &queued.message_id)?;
            Ok((row, gap))
        })
    }

    pub(crate) fn remove_group_member_live(
        &self,
        actor_role: MemberRole,
        conversation_id: &str,
        target_did: &str,
    ) -> Result<(), MLSError> {
        if target_did.trim().is_empty() {
            return Err(MLSError::invalid_input("target_did must not be empty"));
        }
        enforce_admin_removal_policy(&self.normalized_did, actor_role, &[target_did.to_string()])?;
        let convo_uuid = uuid_v4(conversation_id, "conversation_id")?;
        let canonical_dev_id = self.live_device_id()?;
        let now_ms = self.hooks.now_ms();
        self.db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::GroupNotFound {
                message: format!("conversation {conversation_id} not found"),
            })?;

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
                self.sync_conversation_entries(&canonical_dev_id, &signer, &convo_now)?;
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
            let (resp_val, sent) = match self.submit_own_control(
                canonical_dev_id,
                auth_gen,
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
            // Only this device's own sequenced Commit moves anything. A foreign answer keeps
            // the journal unmerged, as a lost response does, for the own echo in sync.
            let auth_seq = verify_own_answer(&resp_val, &sent, conversation_id, COMMIT_ENTRY_KIND)?;
            let coords_str = serde_json::to_string(&next_coords)
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
                    if auth_seq > c.last_seq.saturating_add(1) {
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
                    if auth_seq == c.last_seq.saturating_add(1) {
                        c.last_seq = auth_seq;
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
                    Err(MLSError::InvalidState(code)) if code == "ConversationNotFound" => {
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
            let wire = prepared.body.unwrap_or_default();
            let sent: Value = serde_json::from_slice(&wire)?;
            let resp = self.post_json_raw(&format!("{}{}", self.ds_base(), prepared.path), wire)?;
            if resp.status >= 400 {
                if serde_json::from_slice::<ChatProtocolFailure<'_>>(&resp.body)
                    .is_ok_and(|failure| failure.error == "StaleCoordinates")
                {
                    // Another transition took this coordinate; a later sync retries.
                    continue;
                }
                if is_terminal_rejection(&resp) {
                    // Definitively refused (e.g. this device is no longer an admin).
                    forget(op_key.as_str())?;
                }
                return Err(chat_response_error("participant removal policy", &resp));
            }
            let resp_val: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| MLSError::Internal(format!("parse policy response: {e}")))?;
            // A foreign answer keeps the intent, as a lost response; sync applies the own echo.
            let new_seq = verify_own_answer(
                &resp_val,
                &sent["signedRequest"],
                conversation_id,
                POLICY_ENTRY_KIND,
            )?;
            let coords_str =
                serde_json::to_string(&next).map_err(|e| MLSError::Internal(e.to_string()))?;
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
                if new_seq != c.last_seq.saturating_add(1) {
                    return Ok(new_seq > c.last_seq);
                }
                c.last_seq = new_seq;
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
            let (resp_val, sent) = self.submit_own_control(
                &dev_id,
                auth_gen,
                CanonicalOperation::SubmitTransition,
                &body,
                &signer,
            )?;
            // A foreign answer changes nothing, as a lost response; sync applies the own echo.
            let auth_seq =
                verify_own_answer(&resp_val, &sent, conversation_id, METADATA_ENTRY_KIND)?;
            let coords_str = serde_json::to_string(&next_coords)
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
                    if auth_seq == convo.last_seq.saturating_add(1) {
                        convo.last_seq = auth_seq;
                    } else if auth_seq > convo.last_seq.saturating_add(1) {
                        gap = true;
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
                    self.sync_conversation_entries(&dev_id, &signer, &convo)?;
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
        if req_opt.as_ref().is_some_and(|r| {
            r.consent == crate::orchestrator::direct_request_bootstrap::C33_OPENING_UNAVAILABLE
        }) {
            // No signed opening survives to accept against: terminal, never re-requested.
            return Err(MLSError::InvalidState("OpeningUnavailable".into()));
        }

        if let (Some(canonical_dev_id), Some(req)) =
            (self.canonical_uuid_v4_device_id(), req_opt.as_ref())
        {
            if let Some(pub_str) = self.db.read_tx(|tx| {
                tx.get_account_meta(&format!("c33_publication_json:{}", req.conversation_id))
            })? {
                let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
                let pub_val: Value = serde_json::from_str(&pub_str)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let p_body = pub_val.get("body").unwrap_or(&pub_val);
                // The DS keeps the first signed acceptance even when relaying it to a remote
                // coordinator fails, so every retry replays exactly those bytes.
                let journaled = self.db.read_tx(|tx| {
                    tx.get_pending_op(DIRECT_REQUEST_ACCEPTANCE_OP, &req.request_id)
                })?;
                let wrapper_bytes = if let Some(raw) = journaled {
                    let saved: Value = serde_json::from_str(&raw).map_err(|e| {
                        MLSError::Internal(format!("parse pending acceptance: {e}"))
                    })?;
                    STANDARD
                        .decode(saved["wrapper"].as_str().unwrap_or_default())
                        .map_err(|e| {
                            MLSError::Internal(format!("pending acceptance wrapper: {e}"))
                        })?
                } else {
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
                    wrapper_bytes
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
                    if is_terminal_rejection(&resp) {
                        // The DS will never accept these bytes (a transient refusal such as
                        // `503 CapacityUnavailable` keeps them); a later attempt signs afresh.
                        self.db.write_tx(|tx| {
                            tx.delete_pending_op(DIRECT_REQUEST_ACCEPTANCE_OP, &req.request_id)?;
                            Ok(())
                        })?;
                    }
                    return Err(chat_response_error(
                        format_args!("POST {accept_url}"),
                        &resp,
                    ));
                }
                // The cursor moves only over the verified acceptance entry, and only when it is
                // the next one. An unverifiable answer keeps the journal for the exact replay.
                let (accepted_seq, next_coords) = self.verify_direct_request_acceptance(
                    &req.conversation_id,
                    &resp.body,
                    signer.public(),
                    p_body,
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
                        if accepted_seq == c.last_seq.saturating_add(1) {
                            c.last_seq = accepted_seq;
                        } else if accepted_seq > c.last_seq.saturating_add(1) {
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
                        self.sync_conversation_entries(&canonical_dev_id, &signer, &convo)?;
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

    /// The `acceptConversation` answer's `acceptanceProof`, verified: the conversation
    /// coordinator's acceptance-commit receipt, under the method its `keyId` names, over the
    /// exact sequenced entry carrying this device's signed acceptance of `publication`'s
    /// request. Returns that entry's seq and the receipt's next coordinates.
    fn verify_direct_request_acceptance(
        &self,
        conversation_id: &str,
        response: &[u8],
        own_signature_key: &[u8],
        publication: &Value,
    ) -> Result<(i64, Value), MLSError> {
        let refused = |what: String| MLSError::Cryptography(format!("C33 acceptance: {what}"));
        let response: Value = serde_json::from_slice(response)?;
        let proof = response
            .get("acceptanceProof")
            .ok_or_else(|| refused("missing acceptanceProof".into()))?;
        let authority = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::group_not_found(conversation_id))?
            .sequencer_did;
        let document = self
            .resolve_did_document(&authority)?
            .ok_or_else(|| refused("coordinator document unavailable".into()))?;
        let method = proof
            .pointer("/receipt/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("receipt keyId".into()))?;
        let key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            &authority, &document, method,
        )
        .map_err(|e| refused(e.to_string()))?;
        let verified =
            dr_transcript::verify_received_direct_request_acceptance_proof_for_authority(
                &authority,
                &serde_json::to_vec(proof)?,
                &key,
                own_signature_key,
            )
            .map_err(|e| refused(e.to_string()))?;
        let accepted = &verified["entry"]["signedRequest"]["body"];
        if accepted["requestId"] != publication["requestId"]
            || accepted["prior"] != publication["next"]
        {
            return Err(refused("proof is for another request".into()));
        }
        let seq = verified["entry"]["seq"]
            .as_i64()
            .ok_or_else(|| refused("entry seq".into()))?;
        let next = chat_wire::canonicalize_wire_coordinate(
            &verified["receipt"]["body"]["next"],
            Some(conversation_id),
        )?;
        Ok((seq, next))
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

    /// Erase terminal conversation secrets and plaintext mutation journals in the
    /// same transaction as the terminal marker. Receipt-bound archive evidence remains
    /// available for post-leave rescue and durable unsend reconciliation.
    pub(crate) fn apply_terminal_close(
        &self,
        cid: &str,
        retired: Option<&Value>,
        terminal_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        let now_ms = self.hooks.now_ms();
        self.db.write_tx(|tx| {
            self.clear_cached_groups();
            if let Some(mut convo) = tx.get_conversation(cid)? {
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                if let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load closing group: {e:?}")))?
                {
                    group
                        .delete(provider.storage())
                        .map_err(|e| MLSError::Internal(format!("delete closing group: {e:?}")))?;
                }
                tx.conn()
                    .execute(
                        "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 OR group_id_hex = ?2",
                        rusqlite::params![hex::encode(&convo.group_id), cid],
                    )
                    .map_err(|e| map_rusqlite_err("erase closed epoch secrets", &e))?;
                if let Some(seq) = terminal_seq {
                    convo.last_seq = convo.last_seq.max(seq);
                }
                convo.updated_at_ms = now_ms;
                tx.upsert_conversation(&convo)?;
            }
            tx.conn()
                .execute(
                    "DELETE FROM pending_ops WHERE \
                 json_extract(payload_json, '$.conversation_id') = ?1 OR \
                 json_extract(payload_json, '$.archive.conversation_id') = ?1 OR \
                 json_extract(payload_json, '$.prior.conversationId') = ?1 OR \
                 json_extract(payload_json, '$.next.conversationId') = ?1 OR \
                 json_extract(payload_json, '$.body.prior.conversationId') = ?1 OR \
                 (op_kind = 'direct_request_acceptance' AND op_key IN \
                    (SELECT request_id FROM requests WHERE conversation_id = ?1))",
                    [cid],
                )
                .map_err(|e| map_rusqlite_err("erase closed pending journals", &e))?;
            tx.delete_account_meta(&format!("c33_pending_opening:{cid}"))?;
            tx.conn()
                .execute(
                    "DELETE FROM labyrinth_queue WHERE conversation_id = ?1",
                    [cid],
                )
                .map_err(|e| map_rusqlite_err("erase closed archive queue", &e))?;
            if let Some(retired) = retired {
                tx.put_account_meta(
                    &format!("conversation_coords:{cid}"),
                    &serde_json::to_string(retired)?,
                    now_ms,
                )?;
            }
            tx.put_account_meta(&format!("conversation_closed:{cid}"), "true", now_ms)
        })
    }

    /// Close a conversation on the authoritative `mls-ds` (`Spec §6.3`, `O7`, `I14`).
    ///
    /// Signs a canonical `CATBIRD-CHAT-CLOSE\0` `conversationCloseBody` and submits
    /// `blue.catbird.chat.closeConversation`, retiring the current coordinate to
    /// `lifecycle = "superseded"` while retaining local history unsendable. The signed close is
    /// journaled before HTTP and every later attempt replays exactly those bytes
    /// ([`Self::replay_journaled_close`]); it is never re-signed while journaled.
    pub fn close_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let trimmed = conversation_id.trim();
        if trimmed.is_empty() {
            return Err(MLSError::invalid_input("conversation_id must not be empty"));
        }
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
                Ok(())
            })?;
            self.apply_terminal_close(trimmed, None, None)?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(());
        };

        let canonical_cid = convo_uuid.hyphenated().to_string();
        if self.is_conversation_closed(&canonical_cid)? {
            return self.apply_terminal_close(&canonical_cid, None, None);
        }
        let journaled = self
            .db
            .read_tx(|tx| tx.get_pending_op(CONVERSATION_CLOSE_OP, &canonical_cid))?;
        let raw = match journaled {
            Some(raw) => raw,
            None => {
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
                let prepared = chat_wire::sign_clean_chat_mutation(
                    &self.normalized_did,
                    &canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::CloseConversation,
                    &close_body,
                    &signer,
                )?;
                let mut wire: Value =
                    serde_json::from_slice(prepared.body.as_deref().unwrap_or_default())?;
                let raw = wire["signedRequest"].take().to_string();
                self.db.write_tx(|tx| {
                    tx.put_pending_op(
                        CONVERSATION_CLOSE_OP,
                        &canonical_cid,
                        &raw,
                        self.hooks.now_ms(),
                    )
                })?;
                raw
            }
        };
        self.replay_journaled_close(&canonical_cid, &raw)?;
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(())
    }

    /// Submit the journaled close `raw` (the exact `signedRequest` JSON) of `cid` and apply the
    /// terminal close once the answer verifies ([`verify_own_answer`]); that write erases the
    /// journal (`$.body.prior.conversationId`). A lost, transient or unverifiable answer keeps the
    /// journal for the identical replay, which mls-ds answers with its recorded result even after
    /// the close wipe. A semantic 4xx proves mls-ds never sequenced these bytes and never will
    /// (e.g. `StaleCoordinates`), so it drops the journal and the next close signs afresh.
    fn replay_journaled_close(&self, cid: &str, raw: &str) -> Result<(), MLSError> {
        let url = format!(
            "{}/xrpc/blue.catbird.chat.closeConversation",
            self.ds_base()
        );
        let resp = self.post_json_raw(&url, signed_request_body(raw.as_bytes()))?;
        if resp.status >= 400 {
            if is_terminal_rejection(&resp) {
                self.db.write_tx(|tx| {
                    tx.delete_pending_op_if_payload(CONVERSATION_CLOSE_OP, cid, raw)?;
                    Ok(())
                })?;
            }
            return Err(chat_response_error(format_args!("POST {url}"), &resp));
        }
        let answer: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| MLSError::Internal(format!("parse closeConversation answer: {e}")))?;
        let sent: Value = serde_json::from_str(raw)?;
        // Only this device's own sequenced close moves the cursor, and only onto the next entry.
        let close_seq = verify_own_answer(&answer, &sent, cid, CONVERSATION_CLOSE_ENTRY_KIND)?;
        let last_seq = self
            .db
            .read_tx(|tx| tx.get_conversation(cid))?
            .map(|c| c.last_seq);
        let terminal_seq =
            Some(close_seq).filter(|seq| last_seq.map(|last| last.saturating_add(1)) == Some(*seq));
        // The terminal coordinate is the one this device signed, not a mutable
        // response/tombstone presentation supplied by the DS.
        let retired_canon =
            chat_wire::canonicalize_wire_coordinate(&sent["body"]["retired"], None)?;

        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }

        self.apply_terminal_close(cid, Some(&retired_canon), terminal_seq)
    }

    /// `sync` replays every journaled close before any conversation's entries (a lost close
    /// answer never arrives as an echo: mls-ds wipes the conversation) and applies each verified
    /// answer. A failed replay keeps its journal for the next sync. Returns how many closed.
    pub(crate) fn complete_pending_closes(&self) -> Result<u32, MLSError> {
        let journaled: Vec<(String, String)> = self.db.read_tx(|tx| {
            let mut stmt = tx
                .conn()
                .prepare(
                    "SELECT op_key, payload_json FROM pending_ops WHERE op_kind = ?1 \
                     ORDER BY op_key",
                )
                .map_err(|e| map_rusqlite_err("pending closes.prepare", &e))?;
            let rows = stmt
                .query_map([CONVERSATION_CLOSE_OP], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(|e| map_rusqlite_err("pending closes.query", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("pending closes.row", &e))
        })?;
        let mut closed = 0;
        for (cid, raw) in journaled {
            match self.replay_journaled_close(&cid, &raw) {
                Ok(()) => closed += 1,
                Err(error) => {
                    tracing::warn!(conversation_id = cid, %error, "journaled close not completed")
                }
            }
        }
        Ok(closed)
    }

    pub fn list_members(&self, conversation_id: &str) -> Result<Vec<String>, MLSError> {
        self.db.read_tx(|tx| {
            let Some(convo) = tx.get_conversation(conversation_id)? else {
                return Err(MLSError::group_not_found(conversation_id));
            };
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let Some(group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            else {
                return Err(MLSError::group_not_found(conversation_id));
            };
            let dids = active_member_dids(&group)?;
            if dids.is_empty() {
                return Err(MLSError::Cryptography(
                    "MLS group has no authenticated members".into(),
                ));
            }
            Ok(dids)
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
