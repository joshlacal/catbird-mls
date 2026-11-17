//! Live `mls-ds` `/xrpc/blue.catbird.chat.*` data plane for `CatbirdMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! All network dispatches execute strictly outside `MlsAccountDb::write_tx` (`I6`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};

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
use crate::chat_v2::transcript::SignedMutationKind;
use crate::chat_v2::wire::{
    COMMIT_ENTRY_KIND, CONVERSATION_CLOSE_ENTRY_KIND, CREATION_ENTRY_KIND,
    LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND, METADATA_ENTRY_KIND, POLICY_ENTRY_KIND,
    RESET_ACTIVATION_ENTRY_KIND, ZERO_LEAF_LEAVE_ENTRY_KIND,
};
use crate::client::chat_wire;
use crate::client::traits::{
    PlatformChangeEvent, PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse,
};
use crate::client::{LeaveConversationOutcome, QueuedLabyrinthArchivePayload};
use crate::error::MLSError;
use crate::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use crate::groups::metadata_v1::{validate_metadata_snapshot_size, SpaceAvatarPointer};
use crate::messaging::receive::{
    OriginalSenderArchiveAttestationEnvelope, PrivateMessagePlaintextEnvelope,
};
use crate::metadata::{
    decrypt_metadata_snapshot_plaintext, derive_metadata_key_from_group,
    encrypt_metadata_snapshot_plaintext_with_nonce, encrypt_metadata_snapshot_with_nonce,
    GroupMetadataV1,
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
use crate::push::{AuthorizedPeerDeviceKey, NSE_DEFERRED_CONTROL_OP};
const ORDINARY_KP_LIFETIME_SECS: u64 = 29 * 86_400;
use crate::storage::driver_native::map_rusqlite_err;
use crate::storage::{
    ConversationRow, GroupMetadataRow, KvWriteBatch, KvWriteOverlay, MessageRow, OpenMlsKvStorage,
    RequestRow, RusqliteKvBackend,
};

use super::native_client::CatbirdMlsClient;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

#[derive(Serialize, Deserialize)]
pub(crate) struct PendingApplicationSend {
    pub(crate) body: Value,
    pub(crate) archive: QueuedLabyrinthArchivePayload,
}

/// The AEAD/exporter construction of an authenticated metadata snapshot.
enum MetadataCarryScheme {
    Legacy,
    Canonical { origin_transition_id: String },
}

/// Authenticated prior metadata held only across one Commit build.
pub(crate) struct MetadataCarryForward {
    snapshot: Value,
    plaintext: Vec<u8>,
    nonce: [u8; 12],
    ciphertext_len: usize,
    scheme: MetadataCarryScheme,
}

fn canonical_metadata_coordinates_from_wire(coordinate: &Value) -> Result<Value, MLSError> {
    let refused =
        |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
    let conversation_id = uuid::Uuid::from_slice(&chat_wire::json_bytes(
        coordinate
            .get("conversationId")
            .ok_or_else(|| refused("missing conversation id"))?,
    )?)
    .map_err(|_| refused("invalid conversation id"))?;
    let group_id = chat_wire::json_bytes(
        coordinate
            .get("groupId")
            .ok_or_else(|| refused("missing group id"))?,
    )?;
    let generation = coordinate
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing generation"))?;
    let epoch = coordinate
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing epoch"))?;
    let group_context_hash = chat_wire::json_bytes(
        coordinate
            .get("groupContextHash")
            .ok_or_else(|| refused("missing group context hash"))?,
    )?;
    let confirmation_tag = chat_wire::json_bytes(
        coordinate
            .get("confirmationTag")
            .ok_or_else(|| refused("missing confirmation tag"))?,
    )?;
    Ok(direct_request_bootstrap::canonical_metadata_coordinates(
        &conversation_id.to_string(),
        &group_id,
        generation,
        epoch,
        &group_context_hash,
        &confirmation_tag,
    ))
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
    RemoveSpecificDevice {
        target_did: &'a str,
        target_device_id: &'a str,
    },
    #[cfg_attr(not(feature = "sim"), allow(dead_code))]
    SelfUpdate,
}

fn require_send_coordinate<P: OpenMlsProvider>(
    conversation: &ConversationRow,
    coordinate: &Value,
    group: &MlsGroup,
    provider: &P,
) -> Result<(), MLSError> {
    if coordinate["generation"].as_i64() != Some(conversation.generation)
        || coordinate["epoch"].as_i64() != Some(conversation.epoch)
        || chat_wire::require_coordinate_names_group(coordinate, group, provider).is_err()
    {
        return Err(MLSError::InvalidState("StaleCoordinates".into()));
    }
    Ok(())
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
/// `pending_ops` kind holding the exact signed creation request and staged epoch-zero MLS state.
pub(super) const GROUP_CREATION_OP: &str = "group_creation";
fn group_creation_record(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> Result<Option<(String, String)>, MLSError> {
    let mut statement = connection
        .prepare(
            "SELECT op_key, payload_json FROM pending_ops \
             WHERE op_kind = ?1 AND json_extract(payload_json, '$.conversation_id') = ?2 \
             ORDER BY created_at_ms, op_key LIMIT 2",
        )
        .map_err(|e| map_rusqlite_err("prepare group creation lookup", &e))?;
    let mut rows = statement
        .query(rusqlite::params![GROUP_CREATION_OP, conversation_id])
        .map_err(|e| map_rusqlite_err("query group creation lookup", &e))?;
    let Some(row) = rows
        .next()
        .map_err(|e| map_rusqlite_err("read group creation lookup", &e))?
    else {
        return Ok(None);
    };
    let found = (
        row.get(0)
            .map_err(|e| map_rusqlite_err("read group creation operation id", &e))?,
        row.get(1)
            .map_err(|e| map_rusqlite_err("read group creation payload", &e))?,
    );
    if rows
        .next()
        .map_err(|e| map_rusqlite_err("read duplicate group creation", &e))?
        .is_some()
    {
        return Err(MLSError::InvalidState(
            "multiple pending creations for one conversation".into(),
        ));
    }
    Ok(Some(found))
}

struct VerifiedGroupCreationAttempt {
    submitted: Value,
    body: Value,
    digest: [u8; 32],
}

enum GroupCreationPresence {
    Absent,
    Exists,
}

#[derive(Clone, Copy)]
enum GroupCreationResolutionMode {
    Retry,
    ExplicitRetry,
    Cancel,
}

enum GroupCreationResolution {
    Missing,
    Adopted(ConversationRow),
    Cancelled,
}

enum GroupCreationEntryProof {
    Own(usize),
    Foreign,
}

static GROUP_CREATION_FLIGHTS: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

struct GroupCreationFlightGuard {
    key: String,
}

impl GroupCreationFlightGuard {
    fn try_acquire(storage_root: &str, account_did: &str, conversation_id: &str) -> Option<Self> {
        let key = format!("{storage_root}\0{account_did}\0{conversation_id}");
        let mut flights = GROUP_CREATION_FLIGHTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        flights.insert(key.clone()).then(|| Self { key })
    }

    fn is_active(storage_root: &str, account_did: &str, conversation_id: &str) -> bool {
        let key = format!("{storage_root}\0{account_did}\0{conversation_id}");
        GROUP_CREATION_FLIGHTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&key)
    }
}

impl Drop for GroupCreationFlightGuard {
    fn drop(&mut self) {
        GROUP_CREATION_FLIGHTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

/// `pending_ops` kind of this device's own reset activation, keyed by its `transitionId` and
/// journaled before HTTP ([`CatbirdMlsClient::reset_conversation`]). Only the verified activation,
/// its answer or its echo in sync, applies it; any reset of the conversation drops it.
pub(super) const RESET_ACTIVATION_OP: &str = "reset_activation";

/// The successor generation this device's own reset activation opens, as journaled.
#[derive(Serialize, Deserialize)]
pub(super) struct PendingResetActivation {
    pub(super) conversation_id: String,
    /// The canonical `successor` coordinate the activation signs.
    pub(super) successor: Value,
    /// The staged writes of the successor's genesis group, this device its only leaf.
    pub(super) kv_batch: KvWriteBatch,
}

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
        Ok(failure) if failure.error == "DevicePendingApproval" => MLSError::PendingDeviceAccess {
            reason: failure.error.into_owned(),
        },
        Ok(failure) => MLSError::InvalidState(failure.error.into_owned()),
        Err(_) => MLSError::Internal(format!(
            "{context} failed with HTTP {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body),
        )),
    }
}

/// The 2xx answer to this device's own signed control, verified before anything moves: its
/// `entry` is either an `entry_kind` tagged presentation or the untagged ref output, names
/// `conversation_id`, and carries exactly `sent`, the signed request this device submitted.
/// Its `coordinates` are that request's signed `next`. Returns the entry seq. Callers write only
/// the signed coordinates; an answer that does not verify is refused like a lost response, so
/// the journal stays and sync applies the own echo.
pub(super) fn verify_own_answer(
    answer: &Value,
    sent: &Value,
    conversation_id: &str,
    entry_kind: &str,
) -> Result<i64, MLSError> {
    let refused = |why: String| MLSError::Cryptography(format!("own {entry_kind} answer: {why}"));
    // `createConversation` and `closeConversation` answer `{"result": {...}}`.
    let answer = answer.get("result").unwrap_or(answer);
    let entry = answer
        .get("entry")
        .ok_or_else(|| refused("missing entry".into()))?;
    let kind = sent
        .pointer("/body/$type")
        .and_then(Value::as_str)
        .and_then(SignedMutationKind::from_type_id)
        .ok_or_else(|| refused("submitted request has no control kind".into()))?;
    let submitted = serde_json::to_vec(&chat_wire::normalize_signed_mutation_presentation(
        sent, kind,
    )?)?;
    let returned = serde_json::to_vec(&chat_wire::normalize_signed_mutation_presentation(
        &entry["signedRequest"],
        kind,
    )?)?;
    if entry
        .get("$type")
        .is_some_and(|presented_kind| presented_kind != entry_kind)
        || entry["conversationId"] != conversation_id
        || returned != submitted
    {
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
    super::archive_policy::enqueue(tx, payload).map(drop)
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
        self.submit_own_control_for_authority(
            device_id,
            auth_generation,
            operation,
            body_value,
            signer,
            None,
        )
    }

    pub(super) fn submit_own_control_for_authority(
        &self,
        device_id: &str,
        auth_generation: i64,
        operation: CanonicalOperation,
        body_value: &Value,
        signer: &SignatureKeyPair,
        receipt_authority: Option<&str>,
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
        let signed_request = &sent["signedRequest"];
        let kind = signed_request
            .pointer("/body/$type")
            .and_then(Value::as_str)
            .and_then(SignedMutationKind::from_type_id)
            .ok_or_else(|| MLSError::Cryptography("own answer has no control kind".into()))?;
        let (verified_body, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
            signed_request,
            kind,
            signer.public(),
        )?;
        let cid = verified_body
            .get("next")
            .or_else(|| verified_body.get("prior"))
            .or_else(|| verified_body.get("successor"))
            .and_then(|coordinate| coordinate["conversationId"].as_str())
            .or_else(|| verified_body["conversationId"].as_str())
            .ok_or_else(|| MLSError::Cryptography("own control has no conversationId".into()))?;
        if receipt_authority.is_some() {
            verify_own_answer(
                &answer,
                &sent["signedRequest"],
                cid,
                chat_wire::entry_kind_of(kind).ok_or_else(|| {
                    MLSError::Cryptography("own answer has no sequenced entry kind".into())
                })?,
            )?;
        }
        let response = answer.get("result").unwrap_or(&answer);
        let entry = response
            .get("entry")
            .ok_or_else(|| MLSError::Cryptography("own control answer missing entry".into()))?;
        let seq = entry["seq"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("own control answer missing seq".into()))?;
        let sequencer_did = match receipt_authority {
            Some(authority) => authority.to_owned(),
            None => self
                .db
                .read_tx(|tx| tx.get_conversation(cid))?
                .map(|conversation| conversation.sequencer_did)
                .unwrap_or_else(|| self.config.home_ds_did.clone()),
        };
        self.verify_control_entry_receipt(
            &sequencer_did,
            cid,
            entry,
            seq,
            &verified_body,
            &request_digest,
        )?;
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

    /// Resolve `did`'s DID document through the crate's one strict resolver
    /// ([`super::did_resolution::resolve_did_document_strict`]): PLC directory or the `did:web`
    /// host only, never an account PDS, with a bounded, provenance-tagged cache.
    pub(crate) fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        let (doc, observation) = super::did_resolution::resolve_did_document_observed(
            &self.db,
            self.transport.as_ref(),
            self.hooks.now_ms(),
            did,
        )?;
        if let Some(observation) = observation {
            self.observe_did_document(&observation)?;
        }
        Ok(doc)
    }

    /// The PDS that hosts `target_did`'s repository: the `#atproto_pds` service of its
    /// independently resolved DID document. No account PDS fallback is allowed, including for
    /// this account's own repository.
    pub(crate) fn repo_pds_endpoint(
        &self,
        target_did: &str,
        resolved_doc: Option<&[u8]>,
    ) -> Result<String, MLSError> {
        if let Some(endpoint) = resolved_doc
            .and_then(|doc| chat_wire::extract_pds_endpoint_from_did_doc(doc, target_did))
        {
            return Ok(endpoint);
        }
        Err(MLSError::Cryptography(format!(
            "no #atproto_pds service in the DID document of `{target_did}`"
        )))
    }

    /// Hook for identity observations made while resolving a DID document.
    pub(crate) fn observe_did_document(
        &self,
        _observation: &super::did_resolution::DidDocObservation,
    ) -> Result<(), MLSError> {
        Ok(())
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
        self.fetch_and_cache_authorized_pds_device_keys_checked(
            target_did,
            target_did != self.normalized_did,
        )
    }

    fn paginate_pds_list_records(
        &self,
        pds_endpoint: &str,
        target_did: &str,
        collection: &str,
        allow_404_empty: bool,
    ) -> Result<Option<Vec<Value>>, MLSError> {
        let mut all_records = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let base = pds_endpoint.trim_end_matches('/');

        for page_idx in 0..chat_wire::MAX_PDS_LIST_RECORDS_PAGES {
            let mut list_url = format!(
                "{base}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
                chat_wire::urlencode_form_component(target_did),
                chat_wire::urlencode_form_component(collection),
            );
            if let Some(ref c) = cursor {
                list_url.push_str(&format!(
                    "&cursor={}",
                    chat_wire::urlencode_form_component(c)
                ));
            }
            let resp = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: list_url,
                headers: Vec::new(),
                body: None,
            })?;
            if page_idx == 0
                && resp.status == 503
                && collection == "blue.catbird.chat.device"
                && crate::planted::is_planted_bug_active(
                    crate::planted::PlantedBug::P14TofuOnDeviceDirectory503,
                )
            {
                return Ok(None);
            }
            if page_idx == 0 && resp.status == 404 && allow_404_empty {
                return Ok(Some(Vec::new()));
            }
            if resp.status >= 400 {
                return Err(MLSError::Internal(format!(
                    "I4 PDS listRecords({target_did}, {collection}) failed with HTTP {}",
                    resp.status
                )));
            }
            let (page_records, next_cursor) =
                chat_wire::parse_pds_list_records_page(target_did, collection, &resp.body)?;
            all_records.extend(page_records);
            if all_records.len() > chat_wire::MAX_PDS_LIST_RECORDS_ITEMS {
                return Err(MLSError::Cryptography(format!(
                    "I4 PDS listRecords({target_did}, {collection}) exceeded {} record ceiling",
                    chat_wire::MAX_PDS_LIST_RECORDS_ITEMS
                )));
            }
            match next_cursor {
                None => return Ok(Some(all_records)),
                Some(next) => {
                    if !seen_cursors.insert(next.clone()) {
                        return Err(MLSError::Cryptography(format!(
                            "I4 PDS listRecords({target_did}, {collection}) repeated pagination cursor"
                        )));
                    }
                    if page_idx + 1 == chat_wire::MAX_PDS_LIST_RECORDS_PAGES {
                        return Err(MLSError::Cryptography(format!(
                            "I4 PDS listRecords({target_did}, {collection}) truncated past {} pages",
                            chat_wire::MAX_PDS_LIST_RECORDS_PAGES
                        )));
                    }
                    cursor = Some(next);
                }
            }
        }
        Ok(Some(all_records))
    }

    #[cfg(feature = "labyrinth")]
    fn verify_pds_record_car_proof_and_pin_rev(
        &self,
        pds_endpoint: &str,
        target_did: &str,
        collection: &str,
        rkey: &str,
        record_entry: &Value,
        atproto_key: &atproto_spaces::tokens::SpaceVerifyingKey,
    ) -> Result<(), MLSError> {
        let expected_uri = format!("at://{target_did}/{collection}/{rkey}");
        let Some(expected_cid) = record_entry["cid"].as_str().filter(|c| !c.is_empty()) else {
            return Err(MLSError::Cryptography(format!(
                "I4 missing record CID for `{expected_uri}`"
            )));
        };
        let Some(record_val) = record_entry.get("value") else {
            return Err(MLSError::Cryptography(format!(
                "I4 missing record value for `{expected_uri}`"
            )));
        };
        let inline_proof = record_entry.get("proof").and_then(|p| {
            p.as_str()
                .or_else(|| p.get("$bytes").and_then(Value::as_str))
        });
        let car_bytes = if let Some(b64) = inline_proof {
            STANDARD.decode(b64).map_err(|error| {
                MLSError::Cryptography(format!(
                    "I4 inline CAR proof base64 decode failed for `{expected_uri}`: {error}"
                ))
            })?
        } else {
            let proof_url = format!(
                "{}/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
                pds_endpoint.trim_end_matches('/'),
                chat_wire::urlencode_form_component(target_did),
                chat_wire::urlencode_form_component(collection),
                chat_wire::urlencode_form_component(rkey),
            );
            let proof_resp = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: proof_url,
                headers: Vec::new(),
                body: None,
            })?;
            if proof_resp.status >= 400 {
                return Err(MLSError::Cryptography(format!(
                    "I4 sync.getRecord({expected_uri}) failed with HTTP {}",
                    proof_resp.status
                )));
            }
            proof_resp.body
        };
        let (_, commit_rev) = crate::labyrinth::repo_proof::verify_car_record_json_match_with_rev(
            &car_bytes,
            target_did,
            collection,
            rkey,
            Some(expected_cid),
            record_val,
            atproto_key,
        )
        .map_err(|error| {
            MLSError::Cryptography(format!(
                "I4 CARv1 repo proof failed for `{expected_uri}`: {error}"
            ))
        })?;
        crate::labyrinth::repo_proof::observe_pds_repo_rev_floor(
            &self.db,
            target_did,
            &commit_rev,
            self.hooks.now_ms(),
        )
        .map_err(|error| {
            MLSError::Cryptography(format!(
                "I4 repository commit rev check failed for `{expected_uri}`: {error}"
            ))
        })?;
        Ok(())
    }

    pub(crate) fn fetch_and_cache_authorized_pds_device_keys_checked(
        &self,
        target_did: &str,
        require_repo_proof: bool,
    ) -> Result<Vec<AuthorizedPeerDeviceKey>, MLSError> {
        let cache_key = format!("authorized_device_keys:{target_did}");
        let invalidate = || self.db.write_tx(|tx| tx.delete_account_meta(&cache_key));
        let resolved = match self.resolve_did_document(target_did) {
            Ok(resolved) => resolved,
            Err(error) => {
                invalidate()?;
                return Err(error);
            }
        };
        #[cfg(feature = "labyrinth")]
        let atproto_key = resolved
            .as_deref()
            .and_then(|bytes| {
                atproto_spaces::did_resolver::DidDocument::parse_json(target_did, bytes).ok()
            })
            .and_then(|d| d.atproto_key);
        #[cfg(not(feature = "labyrinth"))]
        let _ = require_repo_proof;
        let pds_endpoint = match self.repo_pds_endpoint(target_did, resolved.as_deref()) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                // A missing repository host cannot authorize a chat device. Service DIDs are
                // excluded before device-directory prefetch; they do not justify an empty set.
                invalidate()?;
                return Err(error);
            }
        };

        let raw_device_records = match self.paginate_pds_list_records(
            &pds_endpoint,
            target_did,
            "blue.catbird.chat.device",
            false,
        ) {
            Ok(Some(records)) => records,
            Ok(None) => {
                // P14 calibration: an empty directory is interpreted by the leaf verifier as TOFU.
                return Ok(Vec::new());
            }
            Err(error) => {
                invalidate()?;
                return Err(error);
            }
        };

        let entries = chat_wire::parse_pds_device_entries(target_did, &raw_device_records);
        if entries.is_empty() {
            invalidate()?;
            return Err(MLSError::insufficient_permissions(format!(
                "I4: zero valid blue.catbird.chat.device records on PDS for `{target_did}`"
            )));
        }
        #[cfg(feature = "labyrinth")]
        if require_repo_proof {
            let Some(ref atproto_key) = atproto_key else {
                invalidate()?;
                return Err(MLSError::Cryptography(format!(
                    "I4 missing #atproto repository signing key in DID document for `{target_did}`"
                )));
            };
            for (device_id, _, record_entry) in &entries {
                if let Err(error) = self.verify_pds_record_car_proof_and_pin_rev(
                    &pds_endpoint,
                    target_did,
                    "blue.catbird.chat.device",
                    device_id,
                    record_entry,
                    atproto_key,
                ) {
                    invalidate()?;
                    return Err(error);
                }
            }
        }

        let mut enrolled_map = BTreeMap::new();
        for (device_id, pk, _) in &entries {
            enrolled_map.insert(device_id.clone(), pk.clone());
        }

        let raw_revocation_records = match self.paginate_pds_list_records(
            &pds_endpoint,
            target_did,
            "blue.catbird.chat.deviceRevocation",
            !require_repo_proof,
        ) {
            Ok(Some(records)) => records,
            Ok(None) => Vec::new(),
            Err(error) => {
                invalidate()?;
                return Err(error);
            }
        };
        let revocation_prefix = format!("at://{target_did}/blue.catbird.chat.deviceRevocation/");
        let mut revoked_device_ids = std::collections::BTreeSet::new();
        for rev_entry in &raw_revocation_records {
            let Some(uri) = rev_entry.get("uri").and_then(Value::as_str) else {
                continue;
            };
            let Some(rkey) = uri
                .strip_prefix(&revocation_prefix)
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.contains('/'))
            else {
                continue;
            };
            let Some(record_val) = rev_entry.get("value") else {
                invalidate()?;
                return Err(MLSError::Cryptography(format!(
                    "I4 missing value on `{uri}`"
                )));
            };
            #[cfg(feature = "labyrinth")]
            if require_repo_proof {
                let Some(ref atproto_key) = atproto_key else {
                    invalidate()?;
                    return Err(MLSError::Cryptography(format!(
                        "I4 missing #atproto key for `{target_did}`"
                    )));
                };
                if let Err(error) = self.verify_pds_record_car_proof_and_pin_rev(
                    &pds_endpoint,
                    target_did,
                    "blue.catbird.chat.deviceRevocation",
                    rkey,
                    rev_entry,
                    atproto_key,
                ) {
                    invalidate()?;
                    return Err(error);
                }
            }
            match chat_wire::verify_pds_device_revocation_record(
                target_did,
                rkey,
                record_val,
                &enrolled_map,
            ) {
                Ok(target_id) => {
                    // Preserve positive, repository-proven revocation evidence after the PDS
                    // disappears. Account deletion later checks it at the device-signed instant.
                    #[cfg(feature = "labyrinth")]
                    if require_repo_proof {
                        let revoked_at_ms = record_val["createdAt"]
                            .as_str()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|at| at.timestamp_millis())
                            .ok_or_else(|| {
                                MLSError::Cryptography(
                                    "I4 verified revocation has invalid createdAt".into(),
                                )
                            })?;
                        let key = super::deletion_authority::verified_device_revocation_key(
                            target_did, &target_id,
                        );
                        self.db.write_tx(|tx| {
                            let earliest = tx
                                .get_account_meta(&key)?
                                .and_then(|raw| raw.parse::<i64>().ok())
                                .map_or(revoked_at_ms, |old| old.min(revoked_at_ms));
                            tx.put_account_meta(&key, &earliest.to_string(), self.hooks.now_ms())
                        })?;
                    }
                    revoked_device_ids.insert(target_id);
                }
                Err(error) => {
                    invalidate()?;
                    return Err(error);
                }
            }
        }

        let authorized: Vec<AuthorizedPeerDeviceKey> = entries
            .into_iter()
            .filter(|(device_id, _, _)| !revoked_device_ids.contains(device_id))
            .map(
                |(device_id, signature_public_key, _)| AuthorizedPeerDeviceKey {
                    did: target_did.to_string(),
                    device_id,
                    signature_public_key,
                },
            )
            .collect();
        if authorized.is_empty() {
            invalidate()?;
            return Err(MLSError::insufficient_permissions(format!(
                "I4: all blue.catbird.chat.device records on PDS for `{target_did}` are revoked"
            )));
        }

        let now_ms = self.hooks.now_ms();
        let encoded =
            serde_json::to_string(&authorized).map_err(|e| MLSError::Internal(e.to_string()))?;
        self.db
            .write_tx(|tx| tx.put_account_meta(&cache_key, &encoded, now_ms))?;
        Ok(authorized)
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
                tx.get_account_meta("enrollment_status")?,
            ))
        })?;
        let was_pending_approval = completion.5.as_deref() == Some("pending_approval");
        if let (
            Some(auth_generation),
            bound_device,
            bound_key,
            scoped_identity,
            signer_json,
            enrollment_status,
        ) = completion
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
            if bound_key.as_deref() == Some(key_id.as_str())
                && enrollment_status.as_deref() != Some("pending_approval")
            {
                return Ok(());
            }
            if bound_key.is_none() {
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
            // An earlier attempt registered this device, but its response was lost (or it was
            // previously `pending_approval` and is now completing post-approval setup).
            Err(MLSError::InvalidState(code)) if code == "DeviceAlreadyExists" => {
                let own = self.own_enrolled_device(canonical_device_id, &signer)?;
                let published = own.get("directRequestKeyPool").is_some();
                (own, published)
            }
            Err(e) => return Err(e),
        };
        // The key check precedes every PDS write: a fresh answer or an adopted enrollment
        // naming another device, key or generation leaves both PDS records untouched.
        let (auth_generation, enrolled_status) = {
            let dev_view = enroll_resp.get("device").unwrap_or(&enroll_resp);
            let status_str = dev_view["status"].as_str().unwrap_or("");
            let matches_identity = dev_view["deviceId"].as_str() == Some(canonical_device_id)
                && dev_view["keyId"].as_str() == Some(key_id.as_str())
                && chat_wire::json_bytes(&dev_view["signaturePublicKey"])
                    .ok()
                    .as_deref()
                    == Some(pub_key)
                && matches!(status_str, "active" | "pending_approval");
            let gen_opt = dev_view["authGeneration"].as_i64().filter(|g| *g >= 1);
            match (matches_identity, gen_opt) {
                (true, Some(g)) => (g, status_str.to_owned()),
                _ => {
                    return Err(MLSError::InvalidState(
                        "EnrollmentDeviceIdentityMismatch".into(),
                    ))
                }
            }
        };
        let is_pending_approval = enrolled_status == "pending_approval";

        // 3. Publish ADR-009 PDS `blue.catbird.chat.device/{device_id}` + `blue.catbird.chat.declaration/self`
        //    via `com.atproto.repo.createRecord` (append-only; `nest` forbids `putRecord`/`deleteRecord`).
        let dev_record_body = chat_wire::build_pds_device_put_record_body_at(
            &self.normalized_did,
            canonical_device_id,
            pub_key,
            &self.hooks.now_rfc3339_millis(),
        )?;
        self.publish_pds_record_create_only(
            "blue.catbird.chat.device",
            canonical_device_id,
            dev_record_body,
            |existing_val| chat_wire::pds_device_record_matches(existing_val, pub_key),
        )?;

        let decl_body = chat_wire::build_pds_chat_declaration_put_record_body_at(
            &self.normalized_did,
            &self.config.home_ds_did,
            &self.hooks.now_rfc3339_millis(),
        )?;
        // Create-only, like the device record: the session's OAuth scope grants no update.
        // An existing declaration naming this home DS is success; one naming another DS is a
        // conflict this device cannot resolve on its own.
        let home_ds_did = self.config.home_ds_did.clone();
        self.publish_pds_record_create_only(
            super::declaration_proof::DECLARATION_COLLECTION,
            "self",
            decl_body,
            |existing_val| chat_wire::pds_chat_declaration_matches(existing_val, &home_ds_did),
        )?;

        // 4. Generate + publish the C33 DirectRequestKeyPublication once the device is active and
        //    the DS does not yet hold it (real `mls-ds` rejects `pending_approval` callers with
        //    `400 PreparationConflict`).
        let now_ms = self.hooks.now_ms();
        if !request_keys_published && !is_pending_approval {
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
            if is_pending_approval {
                tx.put_account_meta("enrollment_status", "pending_approval", now_ms)?;
            } else if was_pending_approval {
                tx.delete_account_meta("enrollment_status")?;
            }
            tx.put_account_meta("enrolled_signer_key_id", &key_id, now_ms)
        })?;
        if !is_pending_approval {
            self.replenish_key_packages(4)?;
        }
        Ok(())
    }

    pub(super) fn publish_pds_record_create_only(
        &self,
        collection: &str,
        rkey: &str,
        create_body: Vec<u8>,
        matches_expected: impl FnOnce(&Value) -> bool,
    ) -> Result<(), MLSError> {
        let create_url = format!("{}/xrpc/com.atproto.repo.createRecord", self.pds_base());
        let resp = self.transport.execute_http(PlatformHttpRequest {
            method: "POST".to_string(),
            url: create_url.clone(),
            headers: vec![PlatformHttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            body: Some(create_body),
        })?;
        if resp.status < 400 {
            return Ok(());
        }
        if matches!(resp.status, 400 | 409) {
            let get_url = format!(
                "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                self.pds_base(),
                chat_wire::urlencode_form_component(&self.normalized_did),
                chat_wire::urlencode_form_component(collection),
                chat_wire::urlencode_form_component(rkey),
            );
            let get_resp = self.transport.execute_http(PlatformHttpRequest {
                method: "GET".to_string(),
                url: get_url,
                headers: Vec::new(),
                body: None,
            })?;
            if get_resp.status == 200 {
                let parsed: Value = serde_json::from_slice(&get_resp.body).map_err(|e| {
                    MLSError::Cryptography(format!(
                        "parse existing PDS {collection}/{rkey} getRecord JSON: {e}"
                    ))
                })?;
                let expected_uri = format!("at://{}/{collection}/{rkey}", self.normalized_did);
                if let Some(uri) = parsed.get("uri").and_then(Value::as_str) {
                    if uri != expected_uri {
                        return Err(MLSError::Cryptography(format!(
                            "PDS getRecord({collection}/{rkey}) returned mismatched URI `{uri}`"
                        )));
                    }
                }
                let Some(existing_val) = parsed.get("value") else {
                    return Err(MLSError::Cryptography(format!(
                        "PDS getRecord({collection}/{rkey}) missing record value"
                    )));
                };
                if matches_expected(existing_val) {
                    return Ok(());
                }
                return Err(MLSError::InvalidState(format!(
                    "EnrollmentPdsRecordConflict:{collection}/{rkey}"
                )));
            }
        }
        Err(chat_response_error(
            format_args!("POST {create_url}"),
            &resp,
        ))
    }

    /// Whether this device's latest DS enrollment recorded `status == "pending_approval"`.
    pub fn is_device_pending_approval(&self) -> Result<bool, MLSError> {
        Ok(self
            .db
            .read_tx(|tx| tx.get_account_meta("enrollment_status"))?
            .as_deref()
            == Some("pending_approval"))
    }

    /// Approve a sibling `pending_approval` device on `mls-ds` from an active enrolled device,
    /// signing `CATBIRD-CHAT-DEVICE-APPROVE\0` (`blue.catbird.chat.approveDevice`).
    ///
    /// Resolves the target device's `signaturePublicKey` and `authGeneration` via `getOwnDevices`
    /// and cross-checks against the account's PDS `blue.catbird.chat.device/{target_device_id}`
    /// record (including CARv1 repo proof when `#atproto` is published) before signing.
    pub fn approve_device(&self, target_device_id: &str) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let target_uuid = uuid_v4(target_device_id, "target_device_id")?;
        let canonical_target = target_uuid.hyphenated().to_string();
        let actor_dev_id = self.live_device_id()?;
        if canonical_target == actor_dev_id {
            return Err(MLSError::invalid_input(
                "cannot self-approve the current device",
            ));
        }
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let own_devices = self.query_signed_chat_ds(
            "blue.catbird.chat.getOwnDevices",
            &[("actorDeviceId", &actor_dev_id), ("limit", "100")],
            &actor_dev_id,
            &signer,
        )?;
        let items = own_devices
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| MLSError::Internal("getOwnDevices missing items array".into()))?;
        let target_item = items
            .iter()
            .find(|item| {
                item.pointer("/device/deviceId")
                    .or_else(|| item.get("deviceId"))
                    .and_then(Value::as_str)
                    == Some(canonical_target.as_str())
            })
            .ok_or_else(|| {
                MLSError::InvalidState(format!(
                    "target device {canonical_target} not found in getOwnDevices"
                ))
            })?;
        let dev_view = target_item.get("device").unwrap_or(target_item);
        let ds_pub_key = chat_wire::json_bytes(&dev_view["signaturePublicKey"])?;
        let target_auth_gen = dev_view["authGeneration"]
            .as_i64()
            .filter(|g| *g >= 1)
            .ok_or_else(|| {
                MLSError::Cryptography("target device missing valid authGeneration".into())
            })?;

        // Cross-verify against PDS `blue.catbird.chat.device` (enforcing CARv1 repo proof if `#atproto` is present).
        let authorized_pds =
            self.fetch_and_cache_authorized_pds_device_keys_checked(&self.normalized_did, true)?;
        let pds_match = authorized_pds
            .iter()
            .find(|k| k.device_id == canonical_target)
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "target device {canonical_target} missing verified PDS blue.catbird.chat.device record"
                ))
            })?;
        if pds_match.signature_public_key != ds_pub_key {
            return Err(MLSError::Cryptography(format!(
                "target device {canonical_target} signaturePublicKey mismatch between mls-ds and PDS"
            )));
        }

        self.approve_device_with_key(&canonical_target, &ds_pub_key, target_auth_gen)
    }

    /// Sign and submit `blue.catbird.chat.approveDevice` (`CATBIRD-CHAT-DEVICE-APPROVE\0`)
    /// binding the exact `(target_device_id, target_signature_public_key, target_auth_generation)`.
    pub fn approve_device_with_key(
        &self,
        target_device_id: &str,
        target_signature_public_key: &[u8],
        target_auth_generation: i64,
    ) -> Result<(), MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let target_uuid = uuid_v4(target_device_id, "target_device_id")?;
        let canonical_target = target_uuid.hyphenated().to_string();
        if target_signature_public_key.len() != 32 {
            return Err(MLSError::invalid_input(
                "target_signature_public_key must be a 32-byte Ed25519 key",
            ));
        }
        if target_auth_generation < 1 {
            return Err(MLSError::invalid_input(
                "target_auth_generation must be >= 1",
            ));
        }
        let actor_dev_id = self.live_device_id()?;
        if canonical_target == actor_dev_id {
            return Err(MLSError::invalid_input(
                "cannot self-approve the current device",
            ));
        }
        let (signer, actor_auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceApprovalBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-APPROVE\0",
            "actorDid": self.normalized_did,
            "actorDeviceId": actor_dev_id,
            "authGeneration": actor_auth_gen,
            "keyId": derive_key_id(signer.public()),
            "targetDeviceId": canonical_target,
            "targetKeyId": derive_key_id(target_signature_public_key),
            "targetAuthGeneration": target_auth_generation,
            "targetSignaturePublicKey": { "$bytes": STANDARD.encode(target_signature_public_key) },
            "idempotencyKey": self.hooks.uuid_v4().to_string(),
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let _ = self.submit_signed_chat_op(
            &actor_dev_id,
            Some(actor_auth_gen),
            CanonicalOperation::ApproveDevice,
            &body,
            &signer,
        )?;
        // The explicit approval is the only automatic recognition of another device. A
        // getOwnDevices read by itself never silently accepts a new or changed key.
        self.db.write_tx(|tx| {
            tx.put_account_meta(
                &format!("recognized_own_device:{canonical_target}"),
                &hex::encode(target_signature_public_key),
                self.hooks.now_ms(),
            )
        })?;
        Ok(())
    }

    /// The DS's enrollment of this device under `signer` (`active` or `pending_approval`).
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
        let expected_key_id = derive_key_id(signer.public());
        devices
            .get("items")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    let dev = item.get("device").unwrap_or(item);
                    dev["deviceId"].as_str() == Some(canonical_device_id)
                        && dev["keyId"].as_str() == Some(expected_key_id.as_str())
                        && chat_wire::json_bytes(&dev["signaturePublicKey"])
                            .ok()
                            .as_deref()
                            == Some(signer.public())
                        && matches!(dev["status"].as_str(), Some("active" | "pending_approval"))
                })
            })
            .cloned()
            .ok_or_else(|| {
                MLSError::InvalidState(format!(
                    "DeviceAlreadyExists: mls-ds holds device {canonical_device_id} under another key"
                ))
            })
    }

    /// Generate and upload `count` fresh `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` key packages.
    pub fn replenish_key_packages(&self, count: u32) -> Result<u32, MLSError> {
        if self.is_device_pending_approval()? {
            return Err(MLSError::PendingDeviceAccess {
                reason: "DevicePendingApproval".to_string(),
            });
        }
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
        if let Some(conversation) = self
            .db
            .read_tx(|tx| tx.get_conversation(&canonical_convo_id))?
        {
            return Ok(conversation);
        }
        if let Some(conversation) = self.resume_pending_group_creation(&canonical_convo_id)? {
            return Ok(conversation);
        }

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
        const MAX_DIRECT_REQUEST_JOURNAL_ATTEMPTS: usize = 4;
        for _ in 0..MAX_DIRECT_REQUEST_JOURNAL_ATTEMPTS {
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
        Err(MLSError::InvalidState(
            "DirectRequestJournalContention".into(),
        ))
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
        let peer_ds = self.resolve_peer_home_ds_did(peer_did)?.ok_or_else(|| {
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
                            extra: Default::default(),
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
        let space_uri =
            super::live_sync::conversation_space_uri(effective_sequencer, effective_convo_id, 0);
        let now_ms = self.hooks.now_ms();
        let display_json = json!({ "text": intro_text }).to_string();
        let frame_json = String::from_utf8(opening.canonical_payload_bytes.clone())
            .map_err(|e| MLSError::Cryptography(format!("C33 opening frame: {e}")))?;
        let coords_str = serde_json::to_string(&bootstrap.coordinates)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let metadata_snapshot_json = serde_json::to_string(
            verified_publication
                .body()
                .pointer("/artifacts/metadataSnapshot")
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "C33 signed publication missing metadata snapshot".into(),
                    )
                })?,
        )
        .map_err(|e| MLSError::Internal(format!("serialize C33 metadata snapshot: {e}")))?;

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
                space_uri: Some(space_uri.clone()),
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
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{effective_convo_id}"),
                &metadata_snapshot_json,
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
                space_uri: Some(space_uri),
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
            tx.put_labyrinth_state(
                &format!("push.verified_receipt:{effective_convo_id}:{first_message_id}"),
                b"1",
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

    /// Stages a genesis MLS group `group_id` of generation `generation`, this device its only
    /// leaf, in an overlay over `tx` (nothing is written): the group-creation config, its
    /// GroupInfo, GroupContext hash and confirmation tag, and its metadata snapshot (`title` and
    /// `description` at `metadata_version`, authored under `transition_id` at `origin_seq`) keyed
    /// by its epoch-0 exporter. Returns those and the staged writes.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn stage_genesis_group(
        &self,
        tx: &crate::storage::SqlReadTx<'_>,
        signer: &SignatureKeyPair,
        auth_generation: i64,
        canonical_dev_id: &str,
        convo_uuid: &uuid::Uuid,
        group_id: &[u8],
        generation: i64,
        transition_id: &str,
        metadata_version: u64,
        origin_seq: u64,
        title: &str,
        description: &str,
    ) -> Result<(Vec<u8>, [u8; 32], Vec<u8>, Value, KvWriteBatch), MLSError> {
        let now_secs = self.hooks.now_secs();
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
                signer,
                &create_cfg,
                GroupId::from_slice(group_id),
                CredentialWithKey {
                    credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                    signature_key: signer.public().into(),
                },
            )
            .map_err(|e| MLSError::Cryptography(format!("create X-Wing group: {e:?}")))?;

            let ggi = group
                .export_group_info(provider.crypto(), signer, true)
                .map_err(|e| MLSError::Cryptography(format!("export_group_info: {e:?}")))?
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize ggi: {e:?}")))?;
            let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
            let meta_key = derive_metadata_key_from_group(
                &mut group,
                provider.crypto(),
                provider.storage(),
                group_id,
                0,
            )
            .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
            let snap = chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
                &meta_key,
                group_id,
                convo_uuid,
                generation,
                0,
                &gch,
                &ctag,
                transition_id,
                metadata_version,
                origin_seq,
                &self.normalized_did,
                canonical_dev_id,
                auth_generation,
                signer.public(),
                title,
                description,
                None,
                self.hooks.random_array::<12>(),
            )?;
            (ggi, gch, ctag, snap)
        };
        Ok((ggi, gch, ctag, snap, overlay.into_batch()))
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
        if sequencer_did.split('#').next() != self.config.home_ds_did.split('#').next() {
            return Err(MLSError::invalid_input(
                "sequencerDid must name the configured home DS for creation",
            ));
        }
        let group_id_bytes = self.hooks.random_array::<32>().to_vec();
        let now_ms = self.hooks.now_ms();
        let transition_id = self.hooks.uuid_v4().to_string();
        let title_str = title.clone().unwrap_or_default();
        let desc_str = description.clone().unwrap_or_default();

        let (
            signer,
            new_signer_json,
            auth_generation,
            (ggi_bytes, gch, ctag, meta_snap_json, kv_batch),
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
            let genesis = self.stage_genesis_group(
                tx,
                &signer,
                auth_gen,
                canonical_dev_id,
                convo_uuid,
                &group_id_bytes,
                0,
                &transition_id,
                1,
                1,
                &title_str,
                &desc_str,
            )?;
            Ok((signer, new_signer_str, auth_gen, genesis))
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

        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.normalized_did,
            canonical_dev_id,
            Some(auth_generation),
            CanonicalOperation::CreateConversation,
            &create_body,
            &signer,
        )?;
        let request = prepared.body.unwrap_or_default();
        let request_value: Value = serde_json::from_slice(&request)?;
        let signed_at = request_value["signedRequest"]["body"]["signedAt"]
            .as_str()
            .ok_or_else(|| MLSError::Internal("creation signedAt missing".into()))?
            .to_string();
        let pending = chat_wire::PendingGroupCreation {
            version: chat_wire::GROUP_CREATION_JOURNAL_VERSION,
            conversation_id: canonical_convo_id.to_string(),
            journal_id: transition_id.clone(),
            sequencer_did: sequencer_did.to_string(),
            group_id: group_id_bytes,
            signer_public_key: signer.public().to_vec(),
            attempts: vec![chat_wire::PendingGroupCreationAttempt {
                operation_id: transition_id,
                signed_at,
                request,
                expired_confirmed: false,
            }],
            kv_batch,
            title,
            description,
            new_signer_json,
            created_at_ms: now_ms,
            retry_at_ms: 0,
            retry_count: 0,
            retry_code: None,
        };
        let payload = serde_json::to_string(&pending)?;
        self.db.write_tx(|tx| {
            if group_creation_record(tx.conn(), canonical_convo_id)?.is_none() {
                tx.put_pending_op(GROUP_CREATION_OP, &pending.journal_id, &payload, now_ms)?;
            }
            Ok(())
        })?;
        self.resume_pending_group_creation(canonical_convo_id)?
            .ok_or_else(|| MLSError::Internal("group creation journal disappeared".into()))
    }

    fn pending_group_creation_endpoint(
        &self,
        pending: &chat_wire::PendingGroupCreation,
    ) -> Result<String, MLSError> {
        if pending.sequencer_did.split('#').next() != self.config.home_ds_did.split('#').next() {
            return Err(MLSError::Cryptography(
                "group creation journal sequencer identity changed".into(),
            ));
        }
        let endpoint = self.ds_base();
        if endpoint.trim().is_empty() {
            return Err(MLSError::InvalidState(
                "group creation sequencer endpoint is unavailable".into(),
            ));
        }
        Ok(endpoint)
    }

    fn verified_pending_group_creation(
        &self,
        pending: &chat_wire::PendingGroupCreation,
    ) -> Result<Vec<VerifiedGroupCreationAttempt>, MLSError> {
        if pending.attempts.is_empty() || pending.attempts[0].operation_id != pending.journal_id {
            return Err(MLSError::Cryptography(
                "group creation journal has no stable first attempt".into(),
            ));
        }
        if pending.attempts.len() > chat_wire::GROUP_CREATION_MAX_ATTEMPTS {
            return Err(MLSError::Cryptography(
                "group creation journal exceeds maximum attempts".into(),
            ));
        }
        let mut operation_ids = BTreeSet::new();
        let mut first_next = None;
        let mut first_group_info = None;
        let mut verified = Vec::with_capacity(pending.attempts.len());
        for attempt in &pending.attempts {
            if !operation_ids.insert(attempt.operation_id.as_str()) {
                return Err(MLSError::Cryptography(
                    "group creation journal repeats an operation id".into(),
                ));
            }
            let submitted: Value = serde_json::from_slice(&attempt.request)
                .map_err(|e| MLSError::Internal(format!("parse group creation request: {e}")))?;
            let signed = &submitted["signedRequest"];
            let (body, digest) = chat_wire::verify_signed_mutation_body_and_digest(
                signed,
                SignedMutationKind::Creation,
                &pending.signer_public_key,
            )?;
            let signed_at = body["signedAt"].as_str().ok_or_else(|| {
                MLSError::Cryptography("creation attempt signedAt missing".into())
            })?;
            let next = chat_wire::canonicalize_wire_coordinate(&body["next"], None)?;
            let pending_provenance_matches = body
                .pointer("/manifest/participants")
                .and_then(Value::as_array)
                .is_some_and(|participants| {
                    participants.iter().all(|participant| {
                        participant["status"] != "pending"
                            || participant
                                .pointer("/invitationProvenance/invitationTransitionId")
                                .and_then(Value::as_str)
                                == Some(attempt.operation_id.as_str())
                    })
                });
            let mismatch = if body["conversationId"] != pending.conversation_id {
                Some("conversationId")
            } else if body["transitionId"] != attempt.operation_id {
                Some("transitionId")
            } else if body["idempotencyKey"] != attempt.operation_id {
                Some("idempotencyKey")
            } else if body["actorDid"] != self.normalized_did {
                Some("actorDid")
            } else if body["keyId"] != derive_key_id(&pending.signer_public_key) {
                Some("keyId")
            } else if signed_at != attempt.signed_at {
                Some("signedAt")
            } else if chat_wire::json_bytes(&next["groupId"])? != pending.group_id {
                Some("groupId")
            } else if body
                .pointer("/metadataSnapshot/originTransitionId")
                .and_then(Value::as_str)
                != Some(attempt.operation_id.as_str())
                || body
                    .pointer("/metadataSnapshot/authorProof/originTransitionId")
                    .and_then(Value::as_str)
                    != Some(attempt.operation_id.as_str())
            {
                Some("metadata provenance")
            } else if !pending_provenance_matches {
                Some("invitation provenance")
            } else if first_next
                .as_ref()
                .is_some_and(|baseline| baseline != &next)
            {
                Some("genesis coordinates")
            } else if first_group_info
                .as_ref()
                .is_some_and(|baseline| baseline != &body["genesisGroupInfo"])
            {
                Some("genesis GroupInfo")
            } else {
                None
            };
            if let Some(field) = mismatch {
                return Err(MLSError::Cryptography(format!(
                    "group creation journal signed {field} mismatch"
                )));
            }
            chat_wire::group_creation_attempt_signed_at_ms(attempt)?;
            first_next.get_or_insert_with(|| next.clone());
            first_group_info.get_or_insert_with(|| body["genesisGroupInfo"].clone());
            verified.push(VerifiedGroupCreationAttempt {
                submitted,
                body,
                digest,
            });
        }
        Ok(verified)
    }

    fn pending_group_creation_signer(
        &self,
        pending: &chat_wire::PendingGroupCreation,
    ) -> Result<SignatureKeyPair, MLSError> {
        let signer = if let Some(raw) = &pending.new_signer_json {
            serde_json::from_str(raw)
                .map_err(|e| MLSError::Internal(format!("deserialize pending signer: {e}")))?
        } else {
            self.load_enrolled_signer_and_auth_gen()?.0
        };
        if signer.public() != pending.signer_public_key {
            return Err(MLSError::Cryptography(
                "group creation journal signer changed".into(),
            ));
        }
        Ok(signer)
    }

    /// The signed state read uses the journaled sequencer identity and the currently resolved URL.
    /// Only exact `ConversationNotFound` is absence; every other refusal remains unverified.
    fn pending_group_creation_presence(
        &self,
        pending: &chat_wire::PendingGroupCreation,
        verified_body: &Value,
    ) -> Result<GroupCreationPresence, MLSError> {
        const NSID: &str = "blue.catbird.chat.getConversationState";
        let signer = self.pending_group_creation_signer(pending)?;
        let actor_device_id = verified_body["actorDeviceId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("creation actorDeviceId missing".into()))?;
        let params = [
            ("conversationId", pending.conversation_id.as_str()),
            ("actorDeviceId", actor_device_id),
        ];
        let canonical_query = chat_wire::canonical_query_string(&params);
        let headers = chat_wire::build_chat_read_headers(
            NSID,
            &canonical_query,
            &self.normalized_did,
            actor_device_id,
            &signer,
            self.hooks.now_ms(),
        )?;
        let base = self.pending_group_creation_endpoint(pending)?;
        let url = format!(
            "{}/xrpc/{NSID}?{canonical_query}",
            base.trim_end_matches('/')
        );
        let response = self.transport.execute_http(PlatformHttpRequest {
            method: "GET".into(),
            url: url.clone(),
            headers,
            body: None,
        })?;
        if response.status >= 400 {
            let code = serde_json::from_slice::<ChatProtocolFailure<'_>>(&response.body)
                .ok()
                .map(|failure| failure.error.into_owned());
            if response.status == 400 && code.as_deref() == Some("ConversationNotFound") {
                return Ok(GroupCreationPresence::Absent);
            }
            return Err(chat_response_error(format_args!("GET {url}"), &response));
        }
        if response.body.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Err(MLSError::Internal(
                "empty group creation existence response".into(),
            ));
        }
        let answer: Value = serde_json::from_slice(&response.body)
            .map_err(|e| MLSError::Internal(format!("parse creation existence response: {e}")))?;
        let state = answer
            .get("state")
            .or_else(|| answer.pointer("/result/state"))
            .ok_or_else(|| {
                MLSError::Cryptography("creation existence answer missing state".into())
            })?;
        if state
            .pointer("/coordinates/conversationId")
            .and_then(Value::as_str)
            != Some(pending.conversation_id.as_str())
        {
            return Err(MLSError::Cryptography(
                "creation existence answer names another conversation".into(),
            ));
        }
        Ok(GroupCreationPresence::Exists)
    }

    /// Verify the receipted first entry. An exact journaled signed request is ours; otherwise the
    /// creator signature must verify under its current PDS device record before it is foreign proof.
    fn pending_group_creation_entry_proof(
        &self,
        pending: &chat_wire::PendingGroupCreation,
        attempts: &[VerifiedGroupCreationAttempt],
    ) -> Result<GroupCreationEntryProof, MLSError> {
        let actor_device_id = attempts[0].body["actorDeviceId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("creation actorDeviceId missing".into()))?;
        let page = self.query_signed_chat_ds(
            "blue.catbird.chat.getEntries",
            &[
                ("actorDeviceId", actor_device_id),
                ("afterSeq", "0"),
                ("conversationId", pending.conversation_id.as_str()),
                ("limit", "1"),
            ],
            actor_device_id,
            &self.pending_group_creation_signer(pending)?,
        )?;
        let entry = page
            .get("entries")
            .and_then(Value::as_array)
            .and_then(|entries| entries.first())
            .ok_or_else(|| {
                MLSError::Cryptography("existing conversation has no creation entry".into())
            })?;
        if entry["$type"] != CREATION_ENTRY_KIND
            || entry["seq"].as_i64() != Some(1)
            || entry["conversationId"] != pending.conversation_id
        {
            return Err(MLSError::Cryptography(
                "first conversation entry is not its creation".into(),
            ));
        }
        let signed = entry
            .get("signedRequest")
            .ok_or_else(|| MLSError::Cryptography("creation entry missing signedRequest".into()))?;
        if let Some((index, attempt)) = attempts
            .iter()
            .enumerate()
            .find(|(_, attempt)| signed == &attempt.submitted["signedRequest"])
        {
            self.verify_control_entry_receipt(
                &pending.sequencer_did,
                &pending.conversation_id,
                entry,
                1,
                &attempt.body,
                &attempt.digest,
            )?;
            return Ok(GroupCreationEntryProof::Own(index));
        }

        let unverified_body = signed.get("body").ok_or_else(|| {
            MLSError::Cryptography("foreign creation signedRequest has no body".into())
        })?;
        let actor_did = unverified_body["actorDid"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("foreign creation actorDid missing".into()))?;
        let actor_device_id = unverified_body["actorDeviceId"].as_str().ok_or_else(|| {
            MLSError::Cryptography("foreign creation actorDeviceId missing".into())
        })?;
        let key_id = unverified_body["keyId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("foreign creation keyId missing".into()))?;
        let authorized = self.fetch_and_cache_authorized_pds_device_keys(actor_did)?;
        let key = authorized
            .iter()
            .find(|candidate| {
                candidate.did == actor_did
                    && candidate.device_id == actor_device_id
                    && derive_key_id(&candidate.signature_public_key) == key_id
            })
            .ok_or_else(|| {
                MLSError::Cryptography("foreign creation signer is not PDS-authorized".into())
            })?;
        let (body, digest) = chat_wire::verify_signed_mutation_body_and_digest(
            signed,
            SignedMutationKind::Creation,
            &key.signature_public_key,
        )?;
        if body["conversationId"] != pending.conversation_id
            || body["transitionId"] != entry["entryId"]
            || body["idempotencyKey"] != body["transitionId"]
            || body["actorDid"] != actor_did
            || body["actorDeviceId"] != actor_device_id
            || body["keyId"] != key_id
        {
            return Err(MLSError::Cryptography(
                "foreign creation entry coordinates do not verify".into(),
            ));
        }
        self.verify_control_entry_receipt(
            &pending.sequencer_did,
            &pending.conversation_id,
            entry,
            1,
            &body,
            &digest,
        )?;
        Ok(GroupCreationEntryProof::Foreign)
    }

    fn resign_pending_group_creation(
        &self,
        journal_id: &str,
        expected_payload: &str,
        pending: &mut chat_wire::PendingGroupCreation,
        verified_body: &Value,
    ) -> Result<(), MLSError> {
        let signer = self.pending_group_creation_signer(pending)?;
        let convo_uuid = uuid::Uuid::parse_str(&pending.conversation_id)
            .map_err(|_| MLSError::Cryptography("journaled conversationId is not a UUID".into()))?;
        let actor_device_id = verified_body["actorDeviceId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("creation actorDeviceId missing".into()))?;
        let auth_generation = verified_body["authGeneration"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("creation authGeneration missing".into()))?;
        let next = chat_wire::canonicalize_wire_coordinate(&verified_body["next"], None)?;
        let generation = next["generation"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("creation generation missing".into()))?;
        let epoch = next["epoch"]
            .as_u64()
            .ok_or_else(|| MLSError::Cryptography("creation epoch missing".into()))?;
        let group_context_hash = chat_wire::json_bytes(&next["groupContextHash"])?;
        let confirmation_tag = chat_wire::json_bytes(&next["confirmationTag"])?;
        let metadata_snapshot = &verified_body["metadataSnapshot"];
        let metadata_version = metadata_snapshot["metadataVersion"]
            .as_u64()
            .ok_or_else(|| MLSError::Cryptography("creation metadataVersion missing".into()))?;
        let origin_seq = metadata_snapshot
            .pointer("/authorProof/originSeq")
            .and_then(Value::as_u64)
            .ok_or_else(|| MLSError::Cryptography("creation metadata originSeq missing".into()))?;
        let metadata_key = self.db.read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            pending.kv_batch.apply(&overlay)?;
            let storage = OpenMlsKvStorage::new(&overlay);
            let provider = self.hooks.openmls_provider(storage);
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&pending.group_id))
                    .map_err(|e| MLSError::Internal(format!("load staged genesis group: {e:?}")))?
                    .ok_or_else(|| MLSError::group_not_found(&pending.conversation_id))?;
            chat_wire::require_coordinate_names_group(&next, &group, &provider)?;
            derive_metadata_key_from_group(
                &mut group,
                provider.crypto(),
                provider.storage(),
                &pending.group_id,
                epoch,
            )
            .map_err(|e| MLSError::Cryptography(format!("derive staged metadata key: {e}")))
        })?;

        let fresh_operation_id = self.hooks.uuid_v4().to_string();
        let fresh_metadata = chat_wire::build_encrypted_metadata_snapshot_json_with_nonce(
            &metadata_key,
            &pending.group_id,
            &convo_uuid,
            generation,
            epoch,
            &group_context_hash,
            &confirmation_tag,
            &fresh_operation_id,
            metadata_version,
            origin_seq,
            &self.normalized_did,
            actor_device_id,
            auth_generation,
            signer.public(),
            pending.title.as_deref().unwrap_or_default(),
            pending.description.as_deref().unwrap_or_default(),
            None,
            self.hooks.random_array::<12>(),
        )?;
        let signed_at = self.hooks.now_rfc3339_millis();
        let mut fresh_body = verified_body.clone();
        fresh_body["transitionId"] = json!(fresh_operation_id);
        fresh_body["idempotencyKey"] = json!(fresh_operation_id);
        fresh_body["signedAt"] = json!(signed_at);
        fresh_body["metadataSnapshot"] = fresh_metadata;
        if let Some(participants) = fresh_body
            .pointer_mut("/manifest/participants")
            .and_then(Value::as_array_mut)
        {
            for participant in participants {
                if let Some(invitation_transition_id) =
                    participant.pointer_mut("/invitationProvenance/invitationTransitionId")
                {
                    *invitation_transition_id = json!(fresh_operation_id);
                }
            }
        }
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.normalized_did,
            actor_device_id,
            Some(auth_generation),
            CanonicalOperation::CreateConversation,
            &fresh_body,
            &signer,
        )?;
        while pending.attempts.len() >= chat_wire::GROUP_CREATION_MAX_ATTEMPTS {
            pending.attempts.remove(1);
        }
        pending
            .attempts
            .push(chat_wire::PendingGroupCreationAttempt {
                operation_id: fresh_operation_id,
                signed_at,
                request: prepared.body.unwrap_or_default(),
                expired_confirmed: false,
            });
        let now_ms = self.hooks.now_ms();
        pending.retry_at_ms = now_ms;
        pending.retry_count = 0;
        pending.retry_code = Some("GroupCreationResigned".into());
        let updated = serde_json::to_string(pending)
            .map_err(|e| MLSError::Internal(format!("serialize resigned creation: {e}")))?;
        let changed = self.db.write_tx(|tx| {
            tx.compare_exchange_pending_op(
                GROUP_CREATION_OP,
                journal_id,
                Some(expected_payload),
                &updated,
                pending.created_at_ms,
            )
        })?;
        if !changed {
            return Err(MLSError::InvalidState(
                "GroupCreationOwnershipChanged".into(),
            ));
        }
        Ok(())
    }

    fn defer_pending_group_creation_retry(
        &self,
        journal_id: &str,
        expected_payload: &str,
        pending: &mut chat_wire::PendingGroupCreation,
        retry_code: String,
        retry_after: Option<&str>,
    ) -> Result<(), MLSError> {
        pending.retry_count = pending.retry_count.saturating_add(1);
        pending.retry_at_ms =
            self.hooks
                .now_ms()
                .saturating_add(chat_wire::group_creation_retry_delay_ms(
                    pending.retry_count,
                    retry_after_secs(retry_after),
                ));
        pending.retry_code = Some(retry_code);
        let updated = serde_json::to_string(pending)
            .map_err(|e| MLSError::Internal(format!("serialize group creation journal: {e}")))?;
        let changed = self.db.write_tx(|tx| {
            tx.compare_exchange_pending_op(
                GROUP_CREATION_OP,
                journal_id,
                Some(expected_payload),
                &updated,
                pending.created_at_ms,
            )
        })?;
        if !changed {
            return Err(MLSError::InvalidState(
                "GroupCreationOwnershipChanged".into(),
            ));
        }
        Ok(())
    }

    fn delete_pending_group_creation(
        &self,
        journal_id: &str,
        expected_payload: &str,
    ) -> Result<(), MLSError> {
        if !self.db.write_tx(|tx| {
            tx.delete_pending_op_if_payload(GROUP_CREATION_OP, journal_id, expected_payload)
        })? {
            return Err(MLSError::InvalidState(
                "GroupCreationOwnershipChanged".into(),
            ));
        }
        Ok(())
    }

    fn pending_group_creation_error(pending: &chat_wire::PendingGroupCreation) -> MLSError {
        MLSError::GroupCreationPending {
            conversation_id: pending.conversation_id.clone(),
            retry_at_ms: pending.retry_at_ms,
            last_error_code: pending
                .retry_code
                .clone()
                .unwrap_or_else(|| "GroupCreationRetryDeferred".into()),
        }
    }

    fn adopt_pending_group_creation(
        &self,
        journal_id: &str,
        payload: &str,
        pending: &chat_wire::PendingGroupCreation,
        attempt: &VerifiedGroupCreationAttempt,
        server_seq: i64,
    ) -> Result<ConversationRow, MLSError> {
        if crate::buggify!("after_http_2xx_before_db_commit") {
            return Err(MLSError::Internal(
                "sim buggify: after_http_2xx_before_db_commit".to_string(),
            ));
        }
        let conversation_id = pending.conversation_id.as_str();
        let next = chat_wire::canonicalize_wire_coordinate(&attempt.body["next"], None)?;
        let metadata_snapshot = &attempt.body["metadataSnapshot"];
        let roster =
            chat_wire::roster_from_participants(&attempt.body["manifest"]["participants"])?;
        let generation = next["generation"].as_i64().unwrap_or_default();
        let epoch = next["epoch"].as_i64().unwrap_or_default();
        let space_uri = super::live_sync::conversation_space_uri(
            &pending.sequencer_did,
            conversation_id,
            generation,
        );
        let coords = serde_json::to_string(&next)?;
        let snapshot = serde_json::to_string(metadata_snapshot)?;
        let title_str = pending.title.clone().unwrap_or_default();
        let description_str = pending.description.clone().unwrap_or_default();
        let now_ms = pending.created_at_ms;
        let row = self.db.write_tx(|tx| {
            if tx.get_pending_op(GROUP_CREATION_OP, journal_id)?.as_deref() != Some(payload) {
                if let Some(conversation) = tx.get_conversation(conversation_id)? {
                    return Ok(conversation);
                }
                return Err(MLSError::InvalidState(
                    "GroupCreationOwnershipChanged".into(),
                ));
            }
            pending.kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
            let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
            let provider = self.hooks.openmls_provider(storage);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&pending.group_id))
                .map_err(|e| MLSError::Internal(format!("load journaled genesis group: {e:?}")))?
                .ok_or_else(|| MLSError::group_not_found(conversation_id))?;
            chat_wire::require_coordinate_names_group(&next, &group, &provider)?;
            if let Some(raw_signer) = &pending.new_signer_json {
                tx.put_account_meta("enrolled_signer_json", raw_signer, now_ms)?;
            }
            if pending.title.is_some() || pending.description.is_some() {
                let metadata = GroupMetadataV1 {
                    version: 1,
                    title: title_str.clone(),
                    description: description_str.clone(),
                    avatar_blob_locator: None,
                    avatar_content_type: None,
                    extra: Default::default(),
                    space_avatar: None,
                };
                tx.upsert_group_metadata(&chat_wire::group_metadata_row_from_v1(
                    conversation_id,
                    1,
                    0,
                    &metadata,
                    now_ms,
                )?)?;
            }
            let row = ConversationRow {
                conversation_id: conversation_id.to_string(),
                group_id: pending.group_id.clone(),
                generation,
                epoch,
                last_seq: server_seq,
                sequencer_did: pending.sequencer_did.clone(),
                space_uri: Some(space_uri),
                title: pending.title.clone(),
                unread_count: 0,
                updated_at_ms: now_ms,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords,
                now_ms,
            )?;
            super::live_sync::store_roster(tx, conversation_id, &roster, now_ms)?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{conversation_id}"),
                &snapshot,
                now_ms,
            )?;
            if !tx.delete_pending_op_if_payload(GROUP_CREATION_OP, journal_id, payload)? {
                return Err(MLSError::InvalidState(
                    "GroupCreationOwnershipChanged".into(),
                ));
            }
            Ok(row)
        })?;
        self.clear_cached_groups();
        self.cache_title_if_present(conversation_id, &row.title);
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        Ok(row)
    }

    /// One explicit state machine owns replay, retry, cancellation, and adoption:
    ///
    /// | Evidence after ordered exact replay | all attempts expired at authenticated server time | action |
    /// | --- | --- | --- |
    /// | verified completion for any attempt | either | adopt its coordinates; atomically delete |
    /// | no verified state/entry proof | either | retain with bounded retry |
    /// | verified existing, but not verified own/foreign | either | retain with bounded retry |
    /// | verified absent/foreign | no | retain; a delayed attempt may still commit |
    /// | verified foreign | yes | typed loss; atomically delete |
    /// | verified absent + permanent refusal | yes | typed rejection; atomically delete |
    /// | verified absent + retryable expiry | yes | append one attempt over the same genesis |
    /// | verified absent/foreign + cancel | yes | atomically delete as cancelled |
    /// | another resolver/POST is in flight | either | refuse/defer without journal mutation |
    fn resolve_pending_group_creation(
        &self,
        conversation_id: &str,
        mode: GroupCreationResolutionMode,
    ) -> Result<GroupCreationResolution, MLSError> {
        let Some((journal_id, payload)) = self
            .db
            .read_tx(|tx| group_creation_record(tx.conn(), conversation_id))?
        else {
            return Ok(GroupCreationResolution::Missing);
        };
        let mut pending: chat_wire::PendingGroupCreation = serde_json::from_str(&payload)
            .map_err(|e| MLSError::Internal(format!("parse group creation journal: {e}")))?;
        if pending.version != chat_wire::GROUP_CREATION_JOURNAL_VERSION
            || pending.conversation_id != conversation_id
            || pending.journal_id != journal_id
        {
            return Err(MLSError::InvalidState(
                "unsupported or mismatched group creation journal".into(),
            ));
        }
        if matches!(mode, GroupCreationResolutionMode::Retry)
            && pending.retry_count > 0
            && pending.retry_is_deferred_at(self.hooks.now_ms())
        {
            return Err(Self::pending_group_creation_error(&pending));
        }

        let endpoint = self.pending_group_creation_endpoint(&pending)?;
        let attempts = self.verified_pending_group_creation(&pending)?;
        let url = format!(
            "{}/xrpc/blue.catbird.chat.createConversation",
            endpoint.trim_end_matches('/')
        );
        let mut latest_code = "GroupCreationTransportUnavailable".to_string();
        let mut latest_retry_after = None;
        let mut latest_permanent = false;
        let mut saw_exists_evidence = false;
        let mut saw_unverifiable_success = false;
        for (index, attempt) in attempts.iter().enumerate() {
            let response = match self.post_json_raw(&url, pending.attempts[index].request.clone()) {
                Ok(response) => response,
                Err(_) => {
                    latest_code = "GroupCreationTransportUnavailable".into();
                    latest_retry_after = None;
                    latest_permanent = false;
                    continue;
                }
            };
            if response.status >= 400 {
                let code = serde_json::from_slice::<ChatProtocolFailure<'_>>(&response.body)
                    .ok()
                    .map(|failure| failure.error.into_owned());
                if chat_wire::group_creation_refusal_is_expired(response.status, code.as_deref()) {
                    pending.attempts[index].expired_confirmed = true;
                }
                saw_exists_evidence |= chat_wire::group_creation_refusal_is_exists_evidence(
                    response.status,
                    code.as_deref(),
                );
                latest_permanent = chat_wire::group_creation_refusal_is_permanent(
                    response.status,
                    code.as_deref(),
                );
                latest_code = code.unwrap_or_else(|| "GroupCreationRefused".into());
                latest_retry_after = response.header("retry-after").map(str::to_owned);
                continue;
            }

            let verified_answer = (|| -> Result<i64, MLSError> {
                if response.body.iter().all(|byte| byte.is_ascii_whitespace()) {
                    return Err(MLSError::Internal(
                        "empty group creation response body".into(),
                    ));
                }
                let answer: Value = serde_json::from_slice(&response.body).map_err(|e| {
                    MLSError::Internal(format!("parse group creation response: {e}"))
                })?;
                let signed = &attempt.submitted["signedRequest"];
                let server_seq =
                    verify_own_answer(&answer, signed, conversation_id, CREATION_ENTRY_KIND)?;
                if server_seq != 1 {
                    return Err(MLSError::Cryptography(format!(
                        "own creation answer: seq {server_seq} is not the first entry"
                    )));
                }
                let result = answer.get("result").unwrap_or(&answer);
                let entry = result.get("entry").ok_or_else(|| {
                    MLSError::Cryptography("creation answer missing entry".into())
                })?;
                self.verify_control_entry_receipt(
                    &pending.sequencer_did,
                    conversation_id,
                    entry,
                    server_seq,
                    &attempt.body,
                    &attempt.digest,
                )?;
                Ok(server_seq)
            })();
            match verified_answer {
                Ok(server_seq) => {
                    match self.adopt_pending_group_creation(
                        &journal_id,
                        &payload,
                        &pending,
                        attempt,
                        server_seq,
                    ) {
                        Ok(row) => return Ok(GroupCreationResolution::Adopted(row)),
                        Err(error) => {
                            self.defer_pending_group_creation_retry(
                                &journal_id,
                                &payload,
                                &mut pending,
                                "GroupCreationAdoptionDeferred".into(),
                                None,
                            )?;
                            return Err(error);
                        }
                    }
                }
                Err(_) => {
                    latest_code = "UnverifiableGroupCreationAnswer".into();
                    latest_retry_after = None;
                    latest_permanent = false;
                    saw_unverifiable_success = true;
                }
            }
        }

        let presence = match self.pending_group_creation_presence(&pending, &attempts[0].body) {
            Ok(presence) => presence,
            Err(error) => {
                self.defer_pending_group_creation_retry(
                    &journal_id,
                    &payload,
                    &mut pending,
                    "CreationStateUnverified".into(),
                    latest_retry_after.as_deref(),
                )?;
                if matches!(mode, GroupCreationResolutionMode::Cancel) {
                    return Err(MLSError::GroupCreationCancellationUnproven {
                        conversation_id: conversation_id.to_string(),
                        reason: error.to_string(),
                    });
                }
                return Err(Self::pending_group_creation_error(&pending));
            }
        };

        let foreign = match presence {
            GroupCreationPresence::Absent => false,
            GroupCreationPresence::Exists => {
                match self.pending_group_creation_entry_proof(&pending, &attempts) {
                    Ok(GroupCreationEntryProof::Own(index)) => {
                        match self.adopt_pending_group_creation(
                            &journal_id,
                            &payload,
                            &pending,
                            &attempts[index],
                            1,
                        ) {
                            Ok(row) => return Ok(GroupCreationResolution::Adopted(row)),
                            Err(error) => {
                                self.defer_pending_group_creation_retry(
                                    &journal_id,
                                    &payload,
                                    &mut pending,
                                    "GroupCreationAdoptionDeferred".into(),
                                    None,
                                )?;
                                return Err(error);
                            }
                        }
                    }
                    Ok(GroupCreationEntryProof::Foreign) => true,
                    Err(error) => {
                        self.defer_pending_group_creation_retry(
                            &journal_id,
                            &payload,
                            &mut pending,
                            "CreationEntryUnverified".into(),
                            latest_retry_after.as_deref(),
                        )?;
                        if matches!(mode, GroupCreationResolutionMode::Cancel) {
                            return Err(MLSError::GroupCreationCancellationUnproven {
                                conversation_id: conversation_id.to_string(),
                                reason: error.to_string(),
                            });
                        }
                        return Err(Self::pending_group_creation_error(&pending));
                    }
                }
            }
        };

        let attempts_expired =
            chat_wire::group_creation_attempts_expired_at(&pending, self.hooks.now_ms())?;
        if !attempts_expired
            || (saw_exists_evidence
                && !foreign
                && !matches!(mode, GroupCreationResolutionMode::Cancel))
        {
            let code = if saw_exists_evidence {
                "ConversationExistsUnresolved"
            } else {
                "CreationAttemptsMayStillCommit"
            };
            self.defer_pending_group_creation_retry(
                &journal_id,
                &payload,
                &mut pending,
                code.into(),
                latest_retry_after.as_deref(),
            )?;
            if matches!(mode, GroupCreationResolutionMode::Cancel) {
                return Err(MLSError::GroupCreationCancellationUnproven {
                    conversation_id: conversation_id.to_string(),
                    reason: code.into(),
                });
            }
            return Err(Self::pending_group_creation_error(&pending));
        }

        if matches!(mode, GroupCreationResolutionMode::Cancel) {
            self.delete_pending_group_creation(&journal_id, &payload)?;
            return Ok(GroupCreationResolution::Cancelled);
        }
        if foreign {
            self.delete_pending_group_creation(&journal_id, &payload)?;
            return Err(MLSError::GroupCreationRejected {
                conversation_id: conversation_id.to_string(),
                code: "ForeignConversationCreation".into(),
            });
        }
        if latest_permanent {
            self.delete_pending_group_creation(&journal_id, &payload)?;
            return Err(MLSError::GroupCreationRejected {
                conversation_id: conversation_id.to_string(),
                code: latest_code,
            });
        }
        if saw_unverifiable_success {
            self.defer_pending_group_creation_retry(
                &journal_id,
                &payload,
                &mut pending,
                "UnverifiableGroupCreationAnswer".into(),
                None,
            )?;
            return Err(Self::pending_group_creation_error(&pending));
        }
        if !matches!(
            latest_code.as_str(),
            "SignedOperationExpired" | "InvalidSignature"
        ) {
            self.defer_pending_group_creation_retry(
                &journal_id,
                &payload,
                &mut pending,
                "CreationAttemptsMayStillCommit".into(),
                latest_retry_after.as_deref(),
            )?;
            return Err(Self::pending_group_creation_error(&pending));
        }

        self.resign_pending_group_creation(
            &journal_id,
            &payload,
            &mut pending,
            &attempts.last().expect("non-empty attempts").body,
        )?;
        Err(Self::pending_group_creation_error(&pending))
    }

    pub fn pending_group_creation_status(
        &self,
        conversation_id: &str,
    ) -> Result<Option<chat_wire::PendingGroupCreationStatus>, MLSError> {
        let canonical = uuid_v4(conversation_id, "conversationId")?
            .hyphenated()
            .to_string();
        let Some((journal_id, payload)) = self
            .db
            .read_tx(|tx| group_creation_record(tx.conn(), &canonical))?
        else {
            return Ok(None);
        };
        let pending: chat_wire::PendingGroupCreation = serde_json::from_str(&payload)
            .map_err(|e| MLSError::Internal(format!("parse group creation journal: {e}")))?;
        if pending.version != chat_wire::GROUP_CREATION_JOURNAL_VERSION
            || pending.conversation_id != canonical
            || pending.journal_id != journal_id
        {
            return Err(MLSError::InvalidState(
                "unsupported or mismatched group creation journal".into(),
            ));
        }
        self.pending_group_creation_endpoint(&pending)?;
        self.verified_pending_group_creation(&pending)?;
        let now_ms = self.hooks.now_ms();
        let mut status = pending.status_at(now_ms);
        if GroupCreationFlightGuard::is_active(
            &self.config.storage_root,
            &self.normalized_did,
            &canonical,
        ) {
            status.retry_at_ms = Some(now_ms.saturating_add(1_000));
            status.last_error_code = Some("CreationRequestInFlight".into());
        }
        Ok(Some(status))
    }

    pub fn retry_pending_group_creation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationRow>, MLSError> {
        let canonical = uuid_v4(conversation_id, "conversationId")?
            .hyphenated()
            .to_string();
        let Some(_guard) = GroupCreationFlightGuard::try_acquire(
            &self.config.storage_root,
            &self.normalized_did,
            &canonical,
        ) else {
            let now_ms = self.hooks.now_ms();
            return Err(MLSError::GroupCreationPending {
                conversation_id: canonical,
                retry_at_ms: now_ms.saturating_add(1_000),
                last_error_code: "CreationRequestInFlight".into(),
            });
        };
        match self.resolve_pending_group_creation(
            &canonical,
            GroupCreationResolutionMode::ExplicitRetry,
        )? {
            GroupCreationResolution::Missing => Ok(None),
            GroupCreationResolution::Adopted(row) => Ok(Some(row)),
            GroupCreationResolution::Cancelled => Err(MLSError::InvalidState(
                "explicit retry cancelled a creation".into(),
            )),
        }
    }

    pub fn cancel_pending_group_creation(&self, conversation_id: &str) -> Result<bool, MLSError> {
        let canonical = uuid_v4(conversation_id, "conversationId")?
            .hyphenated()
            .to_string();
        let Some(_guard) = GroupCreationFlightGuard::try_acquire(
            &self.config.storage_root,
            &self.normalized_did,
            &canonical,
        ) else {
            return Err(MLSError::GroupCreationCancellationUnproven {
                conversation_id: canonical,
                reason: "CreationRequestInFlight".into(),
            });
        };
        match self
            .resolve_pending_group_creation(&canonical, GroupCreationResolutionMode::Cancel)?
        {
            GroupCreationResolution::Missing => Ok(false),
            GroupCreationResolution::Cancelled => Ok(true),
            GroupCreationResolution::Adopted(_) => {
                Err(MLSError::GroupCreationCancellationUnproven {
                    conversation_id: canonical,
                    reason: "ConversationExists".into(),
                })
            }
        }
    }

    pub(crate) fn resume_pending_group_creation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationRow>, MLSError> {
        let Some(_guard) = GroupCreationFlightGuard::try_acquire(
            &self.config.storage_root,
            &self.normalized_did,
            conversation_id,
        ) else {
            let now_ms = self.hooks.now_ms();
            return Err(MLSError::GroupCreationPending {
                conversation_id: conversation_id.to_string(),
                retry_at_ms: now_ms.saturating_add(1_000),
                last_error_code: "CreationRequestInFlight".into(),
            });
        };
        match self
            .resolve_pending_group_creation(conversation_id, GroupCreationResolutionMode::Retry)?
        {
            GroupCreationResolution::Missing => Ok(None),
            GroupCreationResolution::Adopted(row) => Ok(Some(row)),
            GroupCreationResolution::Cancelled => Err(MLSError::InvalidState(
                "retry resolver cancelled a creation".into(),
            )),
        }
    }
    /// Attempt each durable group creation once. A retained failure is isolated to its
    /// conversation and returned to `sync`; later conversations still reconcile.
    pub(crate) fn complete_pending_group_creations(
        &self,
    ) -> Result<(u32, BTreeSet<String>, Vec<(String, MLSError)>), MLSError> {
        let conversation_ids = self.db.read_tx(|tx| {
            let mut statement = tx
                .conn()
                .prepare(
                    "SELECT json_extract(payload_json, '$.conversation_id') FROM pending_ops \
                     WHERE op_kind = ?1 ORDER BY created_at_ms, op_key",
                )
                .map_err(|e| map_rusqlite_err("prepare list group creations", &e))?;
            let rows = statement
                .query_map([GROUP_CREATION_OP], |row| row.get::<_, String>(0))
                .map_err(|e| map_rusqlite_err("query group creations", &e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| map_rusqlite_err("read group creations", &e))
        })?;
        let mut completed = 0u32;
        let mut retained = BTreeSet::new();
        let mut failures = Vec::new();
        for conversation_id in conversation_ids {
            match self.resume_pending_group_creation(&conversation_id) {
                Ok(Some(_)) => completed = completed.saturating_add(1),
                Ok(None) => {}
                Err(error) => {
                    if self
                        .db
                        .read_tx(|tx| group_creation_record(tx.conn(), &conversation_id))?
                        .is_some()
                    {
                        retained.insert(conversation_id.clone());
                    }
                    failures.push((conversation_id, error));
                }
            }
        }
        Ok((completed, retained, failures))
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
            // The verified answer applies the policy: its echo then moves only the cursor.
            super::live_sync::apply_verified_roster_effects(
                tx,
                conversation_id,
                SignedMutationKind::PolicyTransition,
                &sent["body"],
                now_ms,
            )?;
            Ok((row, gap))
        })?;

        if needs_gap_sync {
            self.sync_conversation_entries(&canonical_dev_id, &signer, &updated)?;
        }

        self.fulfill_leaf_recovery(conversation_id, &canonical_dev_id, &signer, auth_generation)?;
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
        // D3 leaves Commit/control pushes untouched. A durable NSE marker is the reason to
        // foreground-sync before reserving sender state; ordinary sends make no preflight request.
        // An existing send journal keeps its exact-ciphertext retry semantics until a definitive
        // stale-coordinate refusal.
        let has_pending_send = self.db.read_tx(|tx| {
            Ok(tx
                .get_pending_op("application_send", &canonical_msg_id)?
                .is_some())
        })?;
        let catch_up_controls = || -> Result<(), MLSError> {
            let convo = self
                .db
                .read_tx(|tx| tx.get_conversation(&canonical_convo_id))?
                .ok_or_else(|| MLSError::group_not_found(&canonical_convo_id))?;
            let (sync_signer, _) = self.load_enrolled_signer_and_auth_gen()?;
            self.sync_conversation_entries(&canonical_dev_id, &sync_signer, &convo)?;
            if self.db.read_tx(|tx| {
                Ok(tx
                    .get_pending_op(NSE_DEFERRED_CONTROL_OP, &canonical_convo_id)?
                    .is_some())
            })? {
                return Err(MLSError::InvalidState(format!(
                    "NSE-deferred control for {canonical_convo_id} remains unapplied"
                )));
            }
            Ok(())
        };
        if !has_pending_send {
            // Reject a corrupt local coordinate before any foreground network read. This first
            // write boundary also performs I7 cache eviction after an NSE application write.
            let coordinate = self.load_or_build_conversation_coords(&canonical_convo_id)?;
            let has_deferred_control = self.db.write_tx(|tx| {
                let convo = tx
                    .get_conversation(&canonical_convo_id)?
                    .ok_or_else(|| MLSError::group_not_found(&canonical_convo_id))?;
                let storage = OpenMlsKvStorage::new(RusqliteKvBackend(tx.conn()));
                let provider = self.hooks.openmls_provider(storage);
                self.with_cached_sender_group(
                    &convo.group_id,
                    || {
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|error| MLSError::Internal(format!("load group: {error:?}")))
                    },
                    |group| require_send_coordinate(&convo, &coordinate, group, &provider),
                )?
                .ok_or_else(|| MLSError::group_not_found(&canonical_convo_id))?;
                Ok(tx
                    .get_pending_op(NSE_DEFERRED_CONTROL_OP, &canonical_convo_id)?
                    .is_some())
            })?;
            if has_deferred_control {
                catch_up_controls()?;
            }
        }
        let reserve = || {
            self.reserve_application_send(
                convo_uuid,
                msg_uuid,
                &canonical_dev_id,
                &display_json,
                &frame_json,
            )
        };
        // A definitive refusal retires these exact bytes. `StaleCoordinates` first catches up
        // verified controls and retries once from fresh MLS state. `StaleSend` proves that this
        // counter is at or below the sequencer's accepted watermark, so advances it first.
        let discard_refused = |pending: &PendingApplicationSend,
                               stale_send: bool|
         -> Result<(), MLSError> {
            self.db.write_tx(|tx| {
                if stale_send {
                    let send_counter = pending.body["sendCounter"].as_u64().ok_or_else(|| {
                        MLSError::Internal("pending send missing valid sendCounter".into())
                    })?;
                    let counter_key = chat_wire::send_counter_key(&pending.archive.conversation_id);
                    let confirmed = chat_wire::confirmed_send_counter(
                        tx.get_account_meta(&counter_key)?.as_deref(),
                        send_counter,
                    )?;
                    tx.put_account_meta(&counter_key, &confirmed.to_string(), self.hooks.now_ms())?;
                }
                tx.delete_pending_op("application_send", &canonical_msg_id)
                    .map(drop)
            })
        };
        // Strictly outside `write_tx` (`I6`); retries reuse the journal's exact signed body.
        // The boolean on an error says whether a semantic 4xx definitively refused these bytes.
        let submit = |signer: &SignatureKeyPair,
                      auth_generation,
                      pending: &PendingApplicationSend|
         -> Result<Value, (MLSError, bool)> {
            let prepared = chat_wire::sign_clean_chat_mutation(
                &self.normalized_did,
                &canonical_dev_id,
                Some(auth_generation),
                CanonicalOperation::SendMessage,
                &pending.body,
                signer,
            )
            .map_err(|error| (error, false))?;
            let operation = prepared.operation;
            let url = format!("{}{}", self.ds_base(), prepared.path);
            let response = self
                .post_json_raw(&url, prepared.body.unwrap_or_default())
                .map_err(|error| (error, false))?;
            if response.status >= 400 {
                let terminal = is_terminal_rejection(&response);
                return Err((
                    chat_response_error(format_args!("POST {url}"), &response),
                    terminal,
                ));
            }
            if response.body.iter().all(|byte| byte.is_ascii_whitespace()) {
                return Err((
                    MLSError::Internal(format!(
                        "empty HTTP {} response body for {operation:?}",
                        response.status
                    )),
                    false,
                ));
            }
            serde_json::from_slice(&response.body).map_err(|error| {
                (
                    MLSError::Internal(format!("parse {operation:?} JSON response: {error}")),
                    false,
                )
            })
        };
        let (mut signer, mut auth_generation, mut pending, mut send_retry) = reserve()?;
        let resp_val = match submit(&signer, auth_generation, &pending) {
            // A concurrent control or a journal older than the NSE marker reached the DS first.
            // Its semantic refusal proves these bytes were not sequenced, so catch up and retry
            // this message id once from fresh coordinates.
            Err((error, _)) if error.is_stale_coordinates() => {
                discard_refused(&pending, false)?;
                catch_up_controls()?;
                (signer, auth_generation, pending, send_retry) = reserve()?;
                match submit(&signer, auth_generation, &pending) {
                    Err((error, _)) if chat_wire::is_stale_send(&error) => {
                        discard_refused(&pending, true)?;
                        return Err(error);
                    }
                    Err((error, terminal)) => {
                        if terminal {
                            discard_refused(&pending, false)?;
                        }
                        return Err(error);
                    }
                    Ok(response) => response,
                }
            }
            // `mls-ds` already sequenced this counter or a newer one. Retire these bytes,
            // advance the confirmed watermark, then try this message id once as a fresh frame.
            Err((error, _)) if chat_wire::is_stale_send(&error) => {
                discard_refused(&pending, true)?;
                (signer, auth_generation, pending, send_retry) = reserve()?;
                match submit(&signer, auth_generation, &pending) {
                    Err((error, _)) if chat_wire::is_stale_send(&error) => {
                        discard_refused(&pending, true)?;
                        return Err(error);
                    }
                    Err((error, terminal)) => {
                        if terminal {
                            discard_refused(&pending, false)?;
                        }
                        return Err(error);
                    }
                    Ok(response) => response,
                }
            }
            Err((error, terminal)) => {
                if terminal {
                    discard_refused(&pending, false)?;
                }
                return Err(error);
            }
            Ok(response) => response,
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

    /// Reserve the sender generation, candidate `sendCounter` and immutable recovery material
    /// atomically before HTTP. A timeout can still publish the ciphertext; rolling the ratchet
    /// back would reuse its key. An existing journal for the message id is returned unchanged.
    /// The accepted-counter watermark advances only after a verified response or own echo.
    fn reserve_application_send(
        &self,
        convo_uuid: uuid::Uuid,
        msg_uuid: uuid::Uuid,
        canonical_dev_id: &str,
        display_json: &str,
        frame_json: &str,
    ) -> Result<(SignatureKeyPair, i64, PendingApplicationSend, bool), MLSError> {
        let frame_nonce = self.hooks.random_array::<32>();
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
            // The candidate after this device's last confirmed send. An uncertain attempt keeps
            // this exact journal; reservation itself must not burn the accepted-send watermark.
            let counter_key = chat_wire::send_counter_key(&canonical_convo_id);
            let send_counter =
                chat_wire::next_send_counter(tx.get_account_meta(&counter_key)?.as_deref())?;

            let frame_json =
                super::archive_policy::stamp_outgoing(tx, &canonical_convo_id, frame_json)?;
            let archive_commitment = labyrinth_protocol::receipt::compute_archive_commitment(
                &frame_nonce,
                frame_json.as_bytes(),
            );

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
                            require_send_coordinate(&convo, &prior_coords, group, &provider)?;
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
                    labyrinth_frame_json: frame_json,
                    mls_ciphertext_b64: STANDARD.encode(&ciphertext.0),
                    frame_nonce_b64: Some(STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    original_sender_attestation_json: Some(original_sender_attestation_json),
                    created_at_ms: now_ms,
                },
            };
            let payload = serde_json::to_string(&pending)
                .map_err(|e| MLSError::Internal(format!("serialize pending send: {e}")))?;
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
        let send_counter = pending.body["sendCounter"]
            .as_u64()
            .ok_or_else(|| MLSError::Internal("pending send missing valid sendCounter".into()))?;
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
            let counter_key = chat_wire::send_counter_key(&queued.conversation_id);
            let confirmed = chat_wire::confirmed_send_counter(
                tx.get_account_meta(&counter_key)?.as_deref(),
                send_counter,
            )?;
            tx.put_account_meta(&counter_key, &confirmed.to_string(), self.hooks.now_ms())?;
            super::send_counter::check_own_receipt_slot(
                tx,
                &queued.conversation_id,
                seq,
                &queued.message_id,
                self.hooks.now_ms(),
            )?;
            tx.insert_message(&row)?;
            tx.put_labyrinth_state(
                &format!(
                    "native.message:{}:{}",
                    queued.conversation_id, queued.message_id
                ),
                &serde_json::to_vec(&queued)?,
                self.hooks.now_ms(),
            )?;
            super::archive_policy::observe_frame(tx, &queued)?;
            tx.put_labyrinth_state(
                &format!(
                    "push.verified_receipt:{}:{}",
                    queued.conversation_id, queued.message_id
                ),
                b"1",
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
                    match op {
                        GenericCommitOp::RemoveLeaves { target_did } => {
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
                        GenericCommitOp::RemoveSpecificDevice {
                            target_did,
                            target_device_id,
                        } => {
                            let expected_scoped = format!("{target_did}#{target_device_id}");
                            for member in group.members() {
                                if let Ok(id_str) =
                                    std::str::from_utf8(member.credential.serialized_content())
                                {
                                    if id_str == expected_scoped {
                                        target_leaves.push(member.index);
                                        removed_leaf_entries.push(json!({
                                            "$type": "blue.catbird.chat.defs#removeLeaf",
                                            "userDid": target_did,
                                            "deviceId": target_device_id,
                                        }));
                                    }
                                }
                            }
                            if target_leaves.is_empty() {
                                return Ok(None);
                            }
                        }
                        GenericCommitOp::SelfUpdate => {}
                    }

                    let metadata_carry = self
                        .metadata_snapshot_plaintext_for_carry_forward(
                            tx,
                            conversation_id,
                            &convo.group_id,
                            &mut group,
                            &provider,
                        )?;

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
                        GenericCommitOp::RemoveLeaves { .. }
                        | GenericCommitOp::RemoveSpecificDevice { .. } => group
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
                    let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                        metadata_carry,
                        &mut group,
                        &provider,
                        &convo.group_id,
                        convo_uuid,
                        prior_gen,
                        next_epoch,
                        &next_gch,
                        &next_ctag,
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
                GenericCommitOp::RemoveSpecificDevice { .. } | GenericCommitOp::SelfUpdate => None,
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
            let entry = resp_val
                .get("result")
                .unwrap_or(&resp_val)
                .get("entry")
                .ok_or_else(|| MLSError::Cryptography("own policy answer missing entry".into()))?;
            let (verified_body, request_digest) =
                chat_wire::verify_signed_mutation_body_and_digest(
                    &entry["signedRequest"],
                    SignedMutationKind::PolicyTransition,
                    signer.public(),
                )?;
            let sequencer_did = self
                .db
                .read_tx(|tx| tx.get_conversation(conversation_id))?
                .map(|conversation| conversation.sequencer_did)
                .unwrap_or_else(|| self.config.home_ds_did.clone());
            self.verify_control_entry_receipt(
                &sequencer_did,
                conversation_id,
                entry,
                new_seq,
                &verified_body,
                &request_digest,
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
                super::live_sync::apply_verified_roster_effects(
                    tx,
                    conversation_id,
                    SignedMutationKind::PolicyTransition,
                    &sent["signedRequest"]["body"],
                    now_ms,
                )?;
                Ok(false)
            })?;
        }
        Ok(gap)
    }

    /// Decrypt the current, authenticated metadata snapshot before mutating the MLS group. The
    /// returned plaintext lives only for the surrounding Commit build and is never persisted.
    pub(crate) fn metadata_snapshot_plaintext_for_carry_forward<P: OpenMlsProvider>(
        &self,
        tx: &crate::storage::SqlReadTx<'_>,
        conversation_id: &str,
        group_id: &[u8],
        group: &mut MlsGroup,
        provider: &P,
    ) -> Result<MetadataCarryForward, MLSError> {
        let refused =
            |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
        let encoded = tx
            .get_account_meta(&format!("metadata_snapshot_json:{conversation_id}"))?
            .ok_or_else(|| MLSError::InvalidState("MetadataSnapshotUnavailable".into()))?;
        let snapshot: Value =
            serde_json::from_str(&encoded).map_err(|_| refused("invalid cached snapshot"))?;
        let coordinate = snapshot
            .get("coordinate")
            .and_then(Value::as_object)
            .ok_or_else(|| refused("missing coordinate"))?;
        let epoch = coordinate
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("missing epoch"))?;
        let snapshot_group_id = chat_wire::json_bytes(
            coordinate
                .get("groupId")
                .ok_or_else(|| refused("missing group id"))?,
        )?;
        if epoch != group.epoch().as_u64()
            || group.group_id().as_slice() != group_id
            || snapshot_group_id.as_slice() != group_id
        {
            return Err(MLSError::InvalidState("StaleMetadataSnapshot".into()));
        }
        let convo_uuid = uuid::Uuid::parse_str(conversation_id)
            .map_err(|_| refused("invalid conversation id"))?;
        let snapshot_conversation_id = chat_wire::json_bytes(
            coordinate
                .get("conversationId")
                .ok_or_else(|| refused("missing conversation id"))?,
        )?;
        if snapshot_conversation_id.as_slice() != convo_uuid.as_bytes() {
            return Err(refused("snapshot names another conversation"));
        }
        let metadata_version = snapshot
            .get("metadataVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("missing metadata version"))?;
        let origin_transition_id = snapshot
            .get("originTransitionId")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("missing authenticated origin"))?
            .to_string();
        if !snapshot
            .get("authorProof")
            .is_some_and(Value::is_object)
        {
            return Err(refused("missing authenticated origin"));
        }
        let scheme = match tx.get_request(&origin_transition_id)? {
            Some(request) if request.conversation_id == conversation_id => {
                if metadata_version != 1 {
                    return Err(refused("canonical metadata version is not 1"));
                }
                MetadataCarryScheme::Canonical {
                    origin_transition_id,
                }
            }
            _ => MetadataCarryScheme::Legacy,
        };
        let nonce_vec = chat_wire::json_bytes(
            snapshot
                .get("nonce")
                .ok_or_else(|| refused("missing nonce"))?,
        )?;
        let nonce: [u8; 12] = nonce_vec
            .try_into()
            .map_err(|_| refused("invalid nonce"))?;
        let ciphertext = chat_wire::json_bytes(
            snapshot
                .get("ciphertext")
                .ok_or_else(|| refused("missing ciphertext"))?,
        )?;
        let declared_size = snapshot
            .get("ciphertextSize")
            .and_then(Value::as_u64)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| refused("missing ciphertext size"))?;
        let declared_hash = chat_wire::json_bytes(
            snapshot
                .get("ciphertextSha256")
                .ok_or_else(|| refused("missing ciphertext digest"))?,
        )?;
        if declared_size != ciphertext.len()
            || declared_hash.as_slice() != &Sha256::digest(&ciphertext)[..]
        {
            return Err(refused("ciphertext binding mismatch"));
        }
        let plaintext = match &scheme {
            MetadataCarryScheme::Legacy => {
                let metadata_key = derive_metadata_key_from_group(
                    group,
                    provider.crypto(),
                    provider.storage(),
                    group_id,
                    epoch,
                )
                .map_err(|e| refused(&format!("derive prior key: {e}")))?;
                decrypt_metadata_snapshot_plaintext(
                    &metadata_key,
                    group_id,
                    epoch,
                    metadata_version,
                    &nonce,
                    &ciphertext,
                )
                .map_err(|e| refused(&format!("decrypt prior snapshot: {e}")))?
            }
            MetadataCarryScheme::Canonical {
                origin_transition_id,
            } => {
                let coordinates =
                    canonical_metadata_coordinates_from_wire(&snapshot["coordinate"])?;
                let metadata_key =
                    direct_request_bootstrap::request_metadata_key(group, provider, &coordinates)
                        .map_err(|e| refused(&format!("derive prior canonical key: {e}")))?;
                direct_request_bootstrap::open_request_metadata(
                    &metadata_key,
                    &coordinates,
                    origin_transition_id,
                    &nonce,
                    &ciphertext,
                )
                .map_err(|e| refused(&format!("decrypt prior canonical snapshot: {e}")))?
            }
        };
        validate_metadata_snapshot_size(&plaintext)?;
        Ok(MetadataCarryForward {
            snapshot,
            plaintext,
            nonce,
            ciphertext_len: ciphertext.len(),
            scheme,
        })
    }

    /// Re-encrypt exact prior metadata plaintext for a Commit's next epoch. Only the AEAD and
    /// coordinate bindings change; metadata version, origin, author proof, avatar binding, unknown
    /// envelope fields, and every plaintext byte remain untouched.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reencrypt_metadata_snapshot_for_epoch<P: OpenMlsProvider>(
        &self,
        carry: MetadataCarryForward,
        group: &mut MlsGroup,
        provider: &P,
        group_id: &[u8],
        convo_uuid: &uuid::Uuid,
        generation: i64,
        target_epoch: u64,
        next_gch: &[u8],
        next_ctag: &[u8],
    ) -> Result<Value, MLSError> {
        let refused =
            |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
        let MetadataCarryForward {
            mut snapshot,
            plaintext,
            nonce: previous_nonce,
            ciphertext_len: previous_len,
            scheme,
        } = carry;
        let metadata_version = snapshot
            .get("metadataVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("missing metadata version"))?;
        let nonce = self.hooks.random_array::<12>();
        if previous_nonce == nonce {
            return Err(refused("nonce repeated across epochs"));
        }
        let ciphertext = match scheme {
            MetadataCarryScheme::Legacy => {
                let metadata_key = derive_metadata_key_from_group(
                    group,
                    provider.crypto(),
                    provider.storage(),
                    group_id,
                    target_epoch,
                )
                .map_err(|e| refused(&format!("derive next key: {e}")))?;
                encrypt_metadata_snapshot_plaintext_with_nonce(
                    &metadata_key,
                    group_id,
                    target_epoch,
                    metadata_version,
                    &nonce,
                    &plaintext,
                )
                .map_err(|e| refused(&format!("encrypt next snapshot: {e}")))?
            }
            MetadataCarryScheme::Canonical {
                origin_transition_id,
            } => {
                if metadata_version != 1 {
                    return Err(refused("canonical metadata version is not 1"));
                }
                let generation = u64::try_from(generation)
                    .map_err(|_| refused("negative canonical generation"))?;
                let coordinates = direct_request_bootstrap::canonical_metadata_coordinates(
                    &convo_uuid.to_string(),
                    group_id,
                    generation,
                    target_epoch,
                    next_gch,
                    next_ctag,
                );
                let metadata_key =
                    direct_request_bootstrap::request_metadata_key(group, provider, &coordinates)
                        .map_err(|e| refused(&format!("derive next canonical key: {e}")))?;
                direct_request_bootstrap::seal_request_metadata(
                    &metadata_key,
                    &coordinates,
                    &origin_transition_id,
                    &nonce,
                    &plaintext,
                )
                .map_err(|e| refused(&format!("encrypt next canonical snapshot: {e}")))?
            }
        };
        if ciphertext.len() != previous_len {
            return Err(refused("plaintext length changed"));
        }
        snapshot["ciphertext"] = json!({ "$bytes": STANDARD.encode(&ciphertext) });
        snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&ciphertext)));
        snapshot["ciphertextSize"] = json!(ciphertext.len());
        snapshot["nonce"] = json!({ "$bytes": STANDARD.encode(nonce) });
        let coordinate = snapshot
            .get_mut("coordinate")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| refused("missing coordinate"))?;
        coordinate.insert(
            "confirmationTag".into(),
            json!({ "$bytes": STANDARD.encode(next_ctag) }),
        );
        coordinate.insert(
            "conversationId".into(),
            json!(STANDARD.encode(convo_uuid.as_bytes())),
        );
        coordinate.insert("epoch".into(), json!(target_epoch));
        coordinate.insert("generation".into(), json!(generation));
        coordinate.insert(
            "groupContextHash".into(),
            json!({ "$bytes": STANDARD.encode(next_gch) }),
        );
        coordinate.insert(
            "groupId".into(),
            json!({ "$bytes": STANDARD.encode(group_id) }),
        );
        Ok(snapshot)
    }

    /// Authenticate a peer Commit's metadata as an exact epoch carry before storing it. A member
    /// knows the metadata key, so the server's ciphertext-shape checks alone cannot prove that a
    /// malicious committer preserved plaintext or the original authorship envelope.
    pub(crate) fn decrypt_verified_metadata_carry_for_epoch<P: OpenMlsProvider>(
        &self,
        carry: MetadataCarryForward,
        snapshot: &Value,
        group: &mut MlsGroup,
        provider: &P,
    ) -> Result<(i64, i64, GroupMetadataV1), MLSError> {
        let refused =
            |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
        let immutable_envelope = |value: &Value| -> Result<Value, MLSError> {
            let mut immutable = value.clone();
            let object = immutable
                .as_object_mut()
                .ok_or_else(|| refused("snapshot is not an object"))?;
            for field in [
                "coordinate",
                "ciphertext",
                "ciphertextSha256",
                "ciphertextSize",
                "nonce",
            ] {
                object
                    .remove(field)
                    .ok_or_else(|| refused(&format!("missing {field}")))?;
            }

            // Generated wire uses plain base64, while legacy persisted snapshots wrapped these
            // two schema byte fields in `{"$bytes": ...}`. Normalize only those known paths;
            // every other immutable and opaque field remains raw-Value-equal.
            let author_proof = object
                .get_mut("authorProof")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| refused("missing author proof"))?;
            let public_key = chat_wire::json_bytes(
                author_proof
                    .get("signaturePublicKey")
                    .ok_or_else(|| refused("missing author signature key"))?,
            )?;
            if public_key.len() != 32 {
                return Err(refused("invalid author signature key"));
            }
            author_proof.insert(
                "signaturePublicKey".into(),
                json!(STANDARD.encode(public_key)),
            );

            if let Some(avatar_binding) = object.get_mut("avatarBinding") {
                let avatar_binding = avatar_binding
                    .as_object_mut()
                    .ok_or_else(|| refused("invalid avatar binding"))?;
                if let Some(hash_value) = avatar_binding.get("ciphertextSha256") {
                    let hash = chat_wire::json_bytes(hash_value)?;
                    if hash.len() != 32 {
                        return Err(refused("invalid avatar ciphertext digest"));
                    }
                    avatar_binding
                        .insert("ciphertextSha256".into(), json!(STANDARD.encode(hash)));
                }
            }
            Ok(immutable)
        };
        let MetadataCarryForward {
            snapshot: prior_snapshot,
            plaintext: prior_plaintext,
            nonce: prior_nonce,
            ciphertext_len: prior_ciphertext_len,
            scheme,
        } = carry;
        let prior_coordinate = prior_snapshot
            .get("coordinate")
            .ok_or_else(|| refused("prior snapshot missing coordinate"))?;
        let coordinate = snapshot
            .get("coordinate")
            .ok_or_else(|| refused("missing coordinate"))?;
        if prior_coordinate["generation"] != coordinate["generation"]
            || chat_wire::json_bytes(&prior_coordinate["conversationId"])?
                != chat_wire::json_bytes(&coordinate["conversationId"])?
            || chat_wire::json_bytes(&prior_coordinate["groupId"])?
                != chat_wire::json_bytes(&coordinate["groupId"])?
        {
            return Err(refused("static coordinate binding changed"));
        }
        if immutable_envelope(&prior_snapshot)? != immutable_envelope(snapshot)? {
            return Err(refused("authenticated envelope changed"));
        }

        chat_wire::require_coordinate_names_group(coordinate, group, provider)?;
        let target_epoch = coordinate
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("missing epoch"))?;
        let metadata_version = snapshot
            .get("metadataVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| refused("missing metadata version"))?;
        let nonce_vec = chat_wire::json_bytes(
            snapshot
                .get("nonce")
                .ok_or_else(|| refused("missing nonce"))?,
        )?;
        let nonce: [u8; 12] = nonce_vec
            .try_into()
            .map_err(|_| refused("invalid nonce"))?;
        if nonce == prior_nonce {
            return Err(refused("nonce repeated across epochs"));
        }
        let ciphertext = chat_wire::json_bytes(
            snapshot
                .get("ciphertext")
                .ok_or_else(|| refused("missing ciphertext"))?,
        )?;
        let declared_size = snapshot
            .get("ciphertextSize")
            .and_then(Value::as_u64)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| refused("missing ciphertext size"))?;
        let declared_hash = chat_wire::json_bytes(
            snapshot
                .get("ciphertextSha256")
                .ok_or_else(|| refused("missing ciphertext digest"))?,
        )?;
        if declared_size != ciphertext.len()
            || ciphertext.len() != prior_ciphertext_len
            || declared_hash.as_slice() != &Sha256::digest(&ciphertext)[..]
        {
            return Err(refused("ciphertext binding changed"));
        }
        let group_id = group.group_id().as_slice().to_vec();
        let plaintext = match &scheme {
            MetadataCarryScheme::Legacy => {
                let metadata_key = derive_metadata_key_from_group(
                    group,
                    provider.crypto(),
                    provider.storage(),
                    &group_id,
                    target_epoch,
                )
                .map_err(|e| refused(&format!("derive next key: {e}")))?;
                decrypt_metadata_snapshot_plaintext(
                    &metadata_key,
                    &group_id,
                    target_epoch,
                    metadata_version,
                    &nonce,
                    &ciphertext,
                )
                .map_err(|e| refused(&format!("decrypt next snapshot: {e}")))?
            }
            MetadataCarryScheme::Canonical {
                origin_transition_id,
            } => {
                if metadata_version != 1 {
                    return Err(refused("canonical metadata version is not 1"));
                }
                let coordinates = canonical_metadata_coordinates_from_wire(coordinate)?;
                let metadata_key =
                    direct_request_bootstrap::request_metadata_key(group, provider, &coordinates)
                        .map_err(|e| refused(&format!("derive next canonical key: {e}")))?;
                direct_request_bootstrap::open_request_metadata(
                    &metadata_key,
                    &coordinates,
                    origin_transition_id,
                    &nonce,
                    &ciphertext,
                )
                .map_err(|e| refused(&format!("decrypt next canonical snapshot: {e}")))?
            }
        };
        validate_metadata_snapshot_size(&plaintext)?;
        if plaintext != prior_plaintext {
            return Err(refused("plaintext changed"));
        }
        let metadata = match scheme {
            MetadataCarryScheme::Legacy => serde_json::from_slice(&plaintext)
                .map_err(|e| refused(&format!("invalid metadata plaintext: {e}")))?,
            MetadataCarryScheme::Canonical { .. } => {
                direct_request_bootstrap::decode_request_metadata(&plaintext)
                    .map_err(|e| refused(&format!("invalid canonical metadata plaintext: {e}")))?
            }
        };
        Ok((
            i64::try_from(target_epoch).map_err(|_| refused("epoch overflows storage"))?,
            i64::try_from(metadata_version)
                .map_err(|_| refused("metadata version overflows storage"))?,
            metadata,
        ))
    }

    /// The conversation's stored metadata with `title`, `description` and the avatar replaced:
    /// every other field the last applied snapshot carried, known or not, is kept. This is used
    /// only for an explicitly authorized metadata transition, never for Commit carry-forward.
    pub(crate) fn rebuilt_group_metadata(
        tx: &crate::storage::SqlReadTx<'_>,
        conversation_id: &str,
        title: &str,
        description: &str,
        space_avatar: Option<SpaceAvatarPointer>,
    ) -> Result<GroupMetadataV1, MLSError> {
        let mut meta = tx
            .get_group_metadata(conversation_id)?
            .as_ref()
            .map(chat_wire::group_metadata_v1_from_row)
            .unwrap_or_else(|| GroupMetadataV1::new("", ""));
        meta.version = 1;
        meta.title = title.to_string();
        meta.description = description.to_string();
        meta.avatar_blob_locator = None;
        meta.avatar_content_type = space_avatar.as_ref().and_then(|a| a.mime_type.clone());
        meta.space_avatar = space_avatar;
        super::archive_policy::stamp_current_metadata_policy(tx, conversation_id, &mut meta)?;
        Ok(meta)
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

            let meta_v1 = Self::rebuilt_group_metadata(
                tx,
                conversation_id,
                &title,
                &description,
                effective_avatar,
            )?;
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
                                "signaturePublicKey": STANDARD.encode(signer.public()),
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
            // Cache the authenticated signed-body representation that peers replay, not the
            // pre-signing builder value: canonical request encoding may normalize byte fields.
            let authenticated_snap = sent
                .pointer("/body/metadataSnapshot")
                .ok_or_else(|| MLSError::Cryptography("signed metadata snapshot missing".into()))?;
            let snap_str = serde_json::to_string(authenticated_snap)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
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
        let receipt_entry = proof
            .get("entry")
            .cloned()
            .ok_or_else(|| refused("missing acceptance entry".into()))?;
        if receipt_entry
            .get("sequencerReceipt")
            .filter(|receipt| receipt.is_object())
            .is_none()
        {
            return Err(refused("missing I13 sequencerReceipt".into()));
        }
        let mut legacy_proof = proof.clone();
        legacy_proof["entry"]
            .as_object_mut()
            .ok_or_else(|| refused("acceptance entry is not an object".into()))?
            .remove("sequencerReceipt");
        let authority = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::group_not_found(conversation_id))?
            .sequencer_did;
        let document = self
            .resolve_did_document(&authority)?
            .ok_or_else(|| refused("coordinator document unavailable".into()))?;
        let method = legacy_proof
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
                &serde_json::to_vec(&legacy_proof)?,
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
        let actor_transcript = dr_transcript::direct_request_signing_bytes(
            DirectRequestKind::Accept,
            &serde_json::to_vec(accepted)?,
        )
        .map_err(|e| refused(e.to_string()))?;
        let actor_digest: [u8; 32] = Sha256::digest(actor_transcript).into();
        self.verify_control_entry_receipt(
            &authority,
            conversation_id,
            &receipt_entry,
            seq,
            accepted,
            &actor_digest,
        )?;
        let next = chat_wire::canonicalize_wire_coordinate(
            &verified["receipt"]["body"]["next"],
            Some(conversation_id),
        )?;
        let actor_next =
            chat_wire::canonicalize_wire_coordinate(&accepted["next"], Some(conversation_id))?;
        if actor_next != next {
            return Err(refused(
                "legacy proof and I13 receipt name different successor coordinates".into(),
            ));
        }
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
            super::archive_policy::enqueue(tx, &staged)?;
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
        let entry = answer
            .get("result")
            .unwrap_or(&answer)
            .get("entry")
            .ok_or_else(|| MLSError::Cryptography("own close answer missing entry".into()))?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let (verified_body, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &entry["signedRequest"],
            SignedMutationKind::ConversationClose,
            signer.public(),
        )?;
        let sequencer_did = self
            .db
            .read_tx(|tx| tx.get_conversation(cid))?
            .map(|conversation| conversation.sequencer_did)
            .unwrap_or_else(|| self.config.home_ds_did.clone());
        self.verify_control_entry_receipt(
            &sequencer_did,
            cid,
            entry,
            close_seq,
            &verified_body,
            &request_digest,
        )?;
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
    /// answer. A failed replay keeps its journal and is returned as a conversation-scoped failure
    /// while the remaining closes continue.
    pub(crate) fn complete_pending_closes(
        &self,
    ) -> Result<(u32, Vec<(String, MLSError)>), MLSError> {
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
        let mut failures = Vec::new();
        for (cid, raw) in journaled {
            match self.replay_journaled_close(&cid, &raw) {
                Ok(()) => closed += 1,
                Err(error) => failures.push((cid, error)),
            }
        }
        Ok((closed, failures))
    }

    /// Resets `conversation_id` to a successor generation this device activates (`CHAT_PROTOCOL`
    /// §6). Rust-only: never UniFFI-exported. Only an active admin by this device's verified
    /// roster may ([`chat_wire::require_active_admin`]); anyone else requests nothing. mls-ds must
    /// hold the conversation exactly as this device verified it (its coordinate, and its roster's
    /// DIDs, roles and statuses). The ordinary sync path first verifies and contiguously applies
    /// the entry tail; only an own reset request recorded by that path may be reused.
    ///
    /// Requests the reset (`manualRecovery`) at that coordinate, verifies its exact own answer and
    /// I13 receipt, then runs the same ordered sync path before deriving the activation's tail.
    /// It stages the successor's genesis group (a fresh group ID, the creation config) with an
    /// empty metadata snapshot at the next metadata version, keyed by its
    /// epoch-0 exporter and authored at the seq the activation takes; and journals it
    /// ([`RESET_ACTIVATION_OP`]) before `activateReset`. Only an answer that verifies applies it
    /// ([`Self::apply_reset_activation`]): the entry carrying exactly the signed activation at
    /// that seq, with the signed retired and successor coordinates. The verified request and
    /// activation move the cursor through the activation; its echo is idempotent. A lost,
    /// transient or unverifiable activation answer keeps the journal for echo sync to apply; a
    /// semantic refusal (mls-ds never sequenced those bytes)
    /// drops it and returns its typed error. Returns the conversation as reset.
    pub fn reset_conversation(&self, conversation_id: &str) -> Result<ConversationRow, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let canonical_dev_id = self.live_device_id()?;
        let convo_uuid = uuid_v4(conversation_id, "conversation_id")?;
        let cid = convo_uuid.hyphenated().to_string();
        let mut convo = self
            .db
            .read_tx(|tx| tx.get_conversation(&cid))?
            .ok_or_else(|| MLSError::group_not_found(&cid))?;
        if self.is_conversation_closed(&cid)? {
            return Err(MLSError::InvalidState("conversation is closed".into()));
        }
        let mut roster = self
            .db
            .read_tx(|tx| super::live_sync::stored_roster(tx, &cid))?;
        chat_wire::require_active_admin(roster.as_ref(), &self.normalized_did, &cid)?;
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        self.sync_conversation_entries(&canonical_dev_id, &signer, &convo)?;
        convo = self
            .db
            .read_tx(|tx| tx.get_conversation(&cid))?
            .ok_or_else(|| MLSError::group_not_found(&cid))?;
        if self.is_conversation_closed(&cid)? {
            return Err(MLSError::InvalidState("conversation is closed".into()));
        }
        roster = self
            .db
            .read_tx(|tx| super::live_sync::stored_roster(tx, &cid))?;
        chat_wire::require_active_admin(roster.as_ref(), &self.normalized_did, &cid)?;
        let stale = || MLSError::InvalidState("StaleCoordinates".into());
        let prior = self.local_coordinates(&cid)?.ok_or_else(stale)?;

        let view = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversationState",
            &[
                ("actorDeviceId", &canonical_dev_id),
                ("conversationId", &cid),
            ],
            &canonical_dev_id,
            &signer,
        )?;
        let state = &view["state"];
        if chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(&cid))? != prior {
            return Err(stale());
        }
        if chat_wire::roster_from_participants(&state["participants"]).ok() != roster {
            return Err(MLSError::Cryptography(
                "reset: mls-ds roster is not this device's verified roster".into(),
            ));
        }
        // The manifest echoes mls-ds's participant rows exactly: order, role, status, provenance.
        let participants: Vec<Value> = state["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let mut participant = json!({
                    "userDid": row["userDid"],
                    "role": row["role"],
                    "status": row["status"],
                });
                if let Some(provenance) = row.get("invitationProvenance") {
                    participant["invitationProvenance"] = provenance.clone();
                }
                participant
            })
            .collect();
        let metadata_version = state["metadataSnapshot"]["metadataVersion"]
            .as_u64()
            .and_then(|version| version.checked_add(1))
            .ok_or_else(|| MLSError::InvalidState("reset: no metadata version".into()))?;
        let verified_pending = || -> Result<Option<String>, MLSError> {
            let raw = self
                .db
                .read_tx(|tx| tx.get_account_meta(&chat_wire::verified_reset_request_key(&cid)))?;
            let Some(raw) = raw else {
                return Ok(None);
            };
            let request: Value = serde_json::from_str(&raw)?;
            if request["actorDid"] != self.normalized_did.as_str()
                || request["actorDeviceId"] != canonical_dev_id.as_str()
                || chat_wire::canonicalize_wire_coordinate(&request["prior"], Some(&cid))? != prior
            {
                return Ok(None);
            }
            Ok(request["resetRequestId"].as_str().map(str::to_owned))
        };
        let reset_request_id = match verified_pending()? {
            Some(id) => id,
            None => {
                let id = self.hooks.uuid_v4().to_string();
                let body = json!({
                    "$type": "blue.catbird.chat.defs#resetRequestBody",
                    "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
                    "resetRequestId": id,
                    "idempotencyKey": id,
                    "actorDid": self.normalized_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_gen,
                    "prior": prior,
                    "reason": "manualRecovery",
                    "signedAt": self.hooks.now_rfc3339_millis(),
                });
                let (answer, sent) = self.submit_own_control(
                    &canonical_dev_id,
                    auth_gen,
                    CanonicalOperation::RequestReset,
                    &body,
                    &signer,
                )?;
                let request_seq = verify_own_answer(
                    &answer,
                    &sent,
                    &cid,
                    crate::chat_v2::wire::RESET_REQUEST_ENTRY_KIND,
                )?;
                let current = self
                    .db
                    .read_tx(|tx| tx.get_conversation(&cid))?
                    .ok_or_else(|| MLSError::group_not_found(&cid))?;
                self.sync_conversation_entries(&canonical_dev_id, &signer, &current)?;
                convo = self
                    .db
                    .read_tx(|tx| tx.get_conversation(&cid))?
                    .ok_or_else(|| MLSError::group_not_found(&cid))?;
                if convo.last_seq < request_seq || verified_pending()?.as_deref() != Some(&id) {
                    return Err(MLSError::Cryptography(
                        "own reset request did not enter the verified contiguous tail".into(),
                    ));
                }
                id
            }
        };

        // The activation lands one past the normal sync path's authenticated contiguous tail.
        let origin_seq = convo
            .last_seq
            .checked_add(1)
            .ok_or_else(|| MLSError::Cryptography("reset: entry sequence exhausted".into()))?;

        let generation = prior["generation"]
            .as_i64()
            .and_then(|generation| generation.checked_add(1))
            .ok_or_else(|| MLSError::Cryptography("reset: generation".into()))?;
        let transition_id = self.hooks.uuid_v4().to_string();
        let group_id = self.hooks.random_array::<32>().to_vec();
        let (group_info, gch, ctag, snapshot, kv_batch) = self.db.read_tx(|tx| {
            self.stage_genesis_group(
                tx,
                &signer,
                auth_gen,
                &canonical_dev_id,
                &convo_uuid,
                &group_id,
                generation,
                &transition_id,
                metadata_version,
                origin_seq as u64,
                "",
                "",
            )
        })?;
        let successor = chat_wire::canonicalize_wire_coordinate(
            &json!({
                "conversationId": cid,
                "generation": generation,
                "stateVersion": 0,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": 0,
                "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                "lifecycle": "active",
            }),
            None,
        )?;
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(prior["stateVersion"]
            .as_i64()
            .and_then(|version| version.checked_add(1))
            .ok_or_else(|| MLSError::Cryptography("reset: stateVersion".into()))?);
        retired["lifecycle"] = json!("superseded");
        let body = json!({
            "$type": "blue.catbird.chat.defs#resetActivationBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
            "resetRequestId": reset_request_id,
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "conversationKind": state["conversationKind"],
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "prior": prior,
            "retired": retired,
            "successor": successor,
            "manifest": {
                "participants": participants,
                "actorLeaf": {
                    "userDid": self.normalized_did,
                    "deviceId": canonical_dev_id,
                    "leafOrigin": "genesis",
                },
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(&group_info) },
                "sha256": STANDARD.encode(Sha256::digest(&group_info)),
            },
            "metadataSnapshot": snapshot,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.normalized_did,
            &canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::ActivateReset,
            &body,
            &signer,
        )?;
        let url = format!("{}{}", self.ds_base(), prepared.path);
        let wire = prepared.body.unwrap_or_default();
        let mut wire_json: Value = serde_json::from_slice(&wire)?;
        let sent = wire_json["signedRequest"].take();
        let journal = PendingResetActivation {
            conversation_id: cid.clone(),
            successor: successor.clone(),
            kv_batch,
        };
        let payload = serde_json::to_string(&journal)?;
        self.db.write_tx(|tx| {
            tx.put_pending_op(
                RESET_ACTIVATION_OP,
                &transition_id,
                &payload,
                self.hooks.now_ms(),
            )
        })?;
        let resp = self.post_json_raw(&url, wire)?;
        if resp.status >= 400 {
            if is_terminal_rejection(&resp) {
                self.db.write_tx(|tx| {
                    tx.delete_pending_op(RESET_ACTIVATION_OP, &transition_id)?;
                    Ok(())
                })?;
            }
            return Err(chat_response_error(format_args!("POST {url}"), &resp));
        }
        let answer: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| MLSError::Internal(format!("parse activateReset answer: {e}")))?;
        let seq = verify_own_answer(&answer, &sent, &cid, RESET_ACTIVATION_ENTRY_KIND)?;
        let entry = answer
            .get("result")
            .unwrap_or(&answer)
            .get("entry")
            .ok_or_else(|| MLSError::Cryptography("own reset answer missing entry".into()))?;
        let (verified_body, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &entry["signedRequest"],
            SignedMutationKind::ResetActivation,
            signer.public(),
        )?;
        let sequencer_did = self
            .db
            .read_tx(|tx| tx.get_conversation(&cid))?
            .map(|conversation| conversation.sequencer_did)
            .unwrap_or_else(|| self.config.home_ds_did.clone());
        self.verify_control_entry_receipt(
            &sequencer_did,
            &cid,
            entry,
            seq,
            &verified_body,
            &request_digest,
        )?;
        if seq != origin_seq
            || chat_wire::canonicalize_wire_coordinate(&answer["retiredCoordinates"], None)?
                != retired
            || chat_wire::canonicalize_wire_coordinate(&answer["successorCoordinates"], None)?
                != successor
        {
            return Err(MLSError::Cryptography(
                "own resetActivationEntry answer: not the signed activation at its seq".into(),
            ));
        }
        let roster = chat_wire::roster_from_participants(&body["manifest"]["participants"])?;
        let last_seq = self
            .db
            .read_tx(|tx| tx.get_conversation(&cid))?
            .map(|c| c.last_seq);
        let cursor =
            Some(seq).filter(|seq| last_seq.map(|last| last.saturating_add(1)) == Some(*seq));
        self.apply_reset_activation(
            &cid,
            &successor,
            &roster,
            cursor,
            Some((&journal.kv_batch, &snapshot)),
        )?;
        self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        self.db
            .read_tx(|tx| tx.get_conversation(&cid))?
            .ok_or_else(|| MLSError::group_not_found(&cid))
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

    /// Remove a specific sibling device leaf (`{own_did}#{target_device_id}`) from every active
    /// local MLS group without removing the account participant (`revoke_device` unified flow).
    pub(super) fn remove_specific_device_from_active_groups(
        &self,
        target_device_id: &str,
    ) -> Result<u32, MLSError> {
        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(0);
        };
        if canonical_dev_id == target_device_id {
            return Err(MLSError::invalid_input(
                "cannot remove current device leaf via remove_specific_device_from_active_groups",
            ));
        }
        let convos = self.db.read_tx(|tx| tx.list_conversations(None, 200))?;
        let mut removed = 0u32;
        for convo in convos {
            let cid = convo.conversation_id.as_str();
            if self.is_conversation_closed(cid)? {
                continue;
            }
            let Some(convo_uuid) = uuid::Uuid::parse_str(cid)
                .ok()
                .filter(|u| u.get_version_num() == 4)
            else {
                continue;
            };
            match self.commit_generic_transition(
                cid,
                &canonical_dev_id,
                &convo_uuid,
                GenericCommitOp::RemoveSpecificDevice {
                    target_did: &self.normalized_did,
                    target_device_id,
                },
            ) {
                Ok(true) => removed = removed.saturating_add(1),
                Ok(false) => {}
                Err(err) if err.is_stale_coordinates() => {}
                Err(err) => return Err(err),
            }
        }
        if removed > 0 {
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        }
        Ok(removed)
    }

    /// Leave a conversation cleanly (`FC-07` lifted onto `CatbirdMlsClient`):
    /// - Re-archives local conversation history to `OwnerMailbox` before exiting;
    /// - Closes `direct` 1:1 conversations or solo 1-member groups (`CATBIRD-CHAT-CLOSE\0`);
    /// - Refuses if this account is the last active admin of a multi-member group;
    /// - Submits a zero-leaf leave (`CATBIRD-CHAT-LEAVE-ZERO-LEAF\0`) when the account holds `0` leaves;
    /// - Submits a durable leave request (`CATBIRD-CHAT-LEAVE-REQUEST\0`) when the account holds `> 0`
    ///   leaves in a multi-member group, keeping local state until another member fulfills it.
    pub fn leave_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<LeaveConversationOutcome, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let convo_uuid = uuid_v4(conversation_id, "conversation_id")?;
        let canonical_cid = convo_uuid.hyphenated().to_string();
        let canonical_dev_id = self.live_device_id()?;
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;

        #[cfg(feature = "labyrinth")]
        let rearchived_messages = self
            .rescue_conversation_on_kick(&canonical_cid)
            .unwrap_or(0);
        #[cfg(not(feature = "labyrinth"))]
        let rearchived_messages = 0u32;

        let resp = self.query_signed_chat_ds(
            "blue.catbird.chat.getConversationState",
            &[
                ("actorDeviceId", &canonical_dev_id),
                ("conversationId", &canonical_cid),
            ],
            &canonical_dev_id,
            &signer,
        )?;
        let state = resp.get("state").unwrap_or(&resp);
        let prior =
            chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(&canonical_cid))?;
        if prior["lifecycle"].as_str() != Some("active") {
            self.apply_terminal_close(&canonical_cid, Some(&prior), None)?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }
        let kind = state
            .get("conversationKind")
            .or_else(|| state.get("kind"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MLSError::Cryptography("getConversationState missing conversationKind".into())
            })?;
        if !matches!(kind, "direct" | "group") {
            return Err(MLSError::Cryptography(format!(
                "unsupported conversationKind `{kind}`"
            )));
        }
        let participants = state
            .get("participants")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MLSError::Cryptography("getConversationState missing participants".into())
            })?;
        let Some(own) = participants
            .iter()
            .find(|p| p["userDid"].as_str() == Some(self.normalized_did.as_str()))
        else {
            self.apply_terminal_close(&canonical_cid, None, None)?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        };
        let active_admin =
            own["status"].as_str() == Some("active") && own["role"].as_str() == Some("admin");
        let active_participant_count = participants
            .iter()
            .filter(|p| matches!(p["status"].as_str(), Some("active" | "pending")))
            .count();
        let close = kind == "direct" || (active_participant_count <= 1 && active_admin);
        if kind == "group" && !close && active_admin {
            let another_active_admin = participants.iter().any(|p| {
                p["userDid"].as_str() != Some(self.normalized_did.as_str())
                    && p["status"].as_str() == Some("active")
                    && p["role"].as_str() == Some("admin")
            });
            if !another_active_admin {
                return Err(MLSError::InvalidState("LastAdminCannotLeave".into()));
            }
        }

        let prior_sv = prior["stateVersion"].as_i64().unwrap_or(0);
        let request_id = self.hooks.uuid_v4().to_string();
        let key_id = derive_key_id(signer.public());

        if close {
            let mut retired = prior.clone();
            retired["stateVersion"] = json!(prior_sv + 1);
            retired["lifecycle"] = json!("superseded");
            let close_body = json!({
                "$type": "blue.catbird.chat.defs#conversationCloseBody",
                "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
                "transitionId": request_id,
                "idempotencyKey": request_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": key_id,
                "authGeneration": auth_gen,
                "conversationKind": kind,
                "prior": prior,
                "retired": retired,
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            let (answer, sent) = self.submit_own_control(
                &canonical_dev_id,
                auth_gen,
                CanonicalOperation::CloseConversation,
                &close_body,
                &signer,
            )?;
            let close_seq = verify_own_answer(
                &answer,
                &sent,
                &canonical_cid,
                CONVERSATION_CLOSE_ENTRY_KIND,
            )?;
            self.apply_terminal_close(&canonical_cid, Some(&retired), Some(close_seq))?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }

        let leaf_count = own
            .get("leafCount")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                state
                    .get("leaves")
                    .and_then(Value::as_array)
                    .map(|leaves| {
                        leaves
                            .iter()
                            .filter(|l| l["userDid"].as_str() == Some(self.normalized_did.as_str()))
                            .count() as u64
                    })
                    .unwrap_or(0)
            });

        if leaf_count == 0 {
            let mut next = prior.clone();
            next["stateVersion"] = json!(prior_sv + 1);
            let zero_body = json!({
                "$type": "blue.catbird.chat.defs#zeroLeafLeaveBody",
                "signatureDomain": "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
                "transitionId": request_id,
                "idempotencyKey": request_id,
                "actorDid": self.normalized_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": key_id,
                "authGeneration": auth_gen,
                "prior": prior,
                "next": next,
                "signedAt": self.hooks.now_rfc3339_millis(),
            });
            let (answer, sent) = self.submit_own_control(
                &canonical_dev_id,
                auth_gen,
                CanonicalOperation::RequestLeave,
                &zero_body,
                &signer,
            )?;
            let seq =
                verify_own_answer(&answer, &sent, &canonical_cid, ZERO_LEAF_LEAVE_ENTRY_KIND)?;
            self.apply_terminal_close(&canonical_cid, None, Some(seq))?;
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }

        if let Some(existing_id) = resp
            .get("pendingLeaveRequests")
            .and_then(Value::as_array)
            .and_then(|reqs| {
                reqs.iter().find_map(|req| {
                    let is_mine =
                        req["requesterDid"].as_str() == Some(self.normalized_did.as_str());
                    let is_pending = req["status"].as_str() == Some("pending");
                    let same_coord = chat_wire::canonicalize_wire_coordinate(
                        &req["prior"],
                        Some(&canonical_cid),
                    )
                    .ok()
                    .as_ref()
                        == Some(&prior);
                    (is_mine && is_pending && same_coord)
                        .then(|| req["leaveRequestId"].as_str().map(str::to_owned))
                        .flatten()
                })
            })
        {
            return Ok(LeaveConversationOutcome {
                left_immediately: false,
                leave_request_id: Some(existing_id),
                rearchived_messages,
            });
        }

        let leave_body = json!({
            "$type": "blue.catbird.chat.defs#leaveRequestBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\0",
            "leaveRequestId": request_id,
            "idempotencyKey": request_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": key_id,
            "authGeneration": auth_gen,
            "prior": prior,
            "signedAt": self.hooks.now_rfc3339_millis(),
        });
        let answer = self.submit_signed_chat_op(
            &canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::RequestLeave,
            &leave_body,
            &signer,
        )?;
        let res = answer.get("result").unwrap_or(&answer);
        if res
            .get("$type")
            .and_then(Value::as_str)
            .is_some_and(|t| t != "blue.catbird.chat.defs#durableLeaveRequestResult")
        {
            return Err(MLSError::Cryptography(
                "unexpected RequestLeave response variant".into(),
            ));
        }
        Ok(LeaveConversationOutcome {
            left_immediately: false,
            leave_request_id: Some(request_id),
            rearchived_messages,
        })
    }

    /// Fulfill at most one pending group leave request per active conversation (`FC-07`).
    pub fn fulfill_pending_group_leaves(&self) -> Result<u32, MLSError> {
        if self.is_handle_closed() {
            return Err(MLSError::ContextClosed);
        }
        let convos = self.db.read_tx(|tx| tx.list_conversations(None, 200))?;
        let mut fulfilled = 0u32;
        for convo in convos {
            if self.is_conversation_closed(&convo.conversation_id)? {
                continue;
            }
            match self.fulfill_pending_group_leave_for_conversation(&convo.conversation_id) {
                Ok(true) => fulfilled = fulfilled.saturating_add(1),
                Ok(false) => {}
                Err(err) if err.is_stale_coordinates() => {}
                Err(err) => return Err(err),
            }
        }
        if fulfilled > 0 {
            self.notify_change(PlatformChangeEvent::ConversationsUpdated);
        }
        Ok(fulfilled)
    }

    pub(crate) fn fulfill_pending_group_leave_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<bool, MLSError> {
        let Some(canonical_dev_id) = self.canonical_uuid_v4_device_id() else {
            return Ok(false);
        };
        let Some(convo_uuid) = uuid::Uuid::parse_str(conversation_id.trim())
            .ok()
            .filter(|u| u.get_version_num() == 4)
        else {
            return Ok(false);
        };
        let canonical_cid = convo_uuid.hyphenated().to_string();
        if self.is_conversation_closed(&canonical_cid)? {
            return Ok(false);
        }
        let Ok((signer, auth_gen)) = self.load_enrolled_signer_and_auth_gen() else {
            return Ok(false);
        };
        let resp = match self.query_signed_chat_ds(
            "blue.catbird.chat.getConversationState",
            &[
                ("actorDeviceId", &canonical_dev_id),
                ("conversationId", &canonical_cid),
            ],
            &canonical_dev_id,
            &signer,
        ) {
            Ok(resp) => resp,
            Err(MLSError::InvalidState(code))
                if matches!(
                    code.as_str(),
                    "ConversationNotFound" | "NotEntitled" | "AccessOutsideMembershipInterval"
                ) =>
            {
                return Ok(false)
            }
            Err(err) => return Err(err),
        };
        self.fulfill_pending_group_leave_from_state(
            &canonical_cid,
            &canonical_dev_id,
            &convo_uuid,
            &signer,
            auth_gen,
            &resp,
        )
    }

    pub(crate) fn fulfill_pending_group_leave_from_state(
        &self,
        conversation_id: &str,
        canonical_dev_id: &str,
        convo_uuid: &uuid::Uuid,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        resp: &Value,
    ) -> Result<bool, MLSError> {
        let Some(requests) = resp
            .get("pendingLeaveRequests")
            .and_then(Value::as_array)
            .filter(|r| !r.is_empty())
        else {
            return Ok(false);
        };
        let state = resp.get("state").unwrap_or(resp);
        if state
            .get("conversationKind")
            .or_else(|| state.get("kind"))
            .and_then(Value::as_str)
            != Some("group")
        {
            return Ok(false);
        }
        let prior =
            chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(conversation_id))?;
        if prior["lifecycle"].as_str() != Some("active") {
            return Ok(false);
        }
        let Some(local_coords) = self.local_coordinates(conversation_id)? else {
            return Ok(false);
        };
        if local_coords != prior {
            return Ok(false);
        }
        let participants = state
            .get("participants")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let now_ms = self.hooks.now_ms();

        let mut sorted_reqs: Vec<&Value> = requests.iter().collect();
        sorted_reqs.sort_by_key(|r| r["requestedAt"].as_str());

        let chosen = sorted_reqs.into_iter().find_map(|req| {
            if req["status"].as_str() != Some("pending") {
                return None;
            }
            let requester_did = req["requesterDid"].as_str()?;
            if requester_did == self.normalized_did {
                return None;
            }
            if let Some(exp_str) = req["expiresAt"].as_str() {
                if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                    if exp_dt.timestamp_millis() <= now_ms {
                        return None;
                    }
                }
            }
            let req_prior =
                chat_wire::canonicalize_wire_coordinate(&req["prior"], Some(conversation_id))
                    .ok()?;
            if req_prior != prior {
                return None;
            }
            let req_p = participants
                .iter()
                .find(|p| p["userDid"].as_str() == Some(requester_did))?;
            if req_p["status"].as_str() != Some("active") {
                return None;
            }
            if req_p["role"].as_str() == Some("admin") {
                let other_admin = participants.iter().any(|p| {
                    p["userDid"].as_str() != Some(requester_did)
                        && p["status"].as_str() == Some("active")
                        && p["role"].as_str() == Some("admin")
                });
                if !other_admin {
                    return None;
                }
            }
            let leave_request_id = req["leaveRequestId"].as_str()?.to_owned();
            Some((leave_request_id, requester_did.to_owned()))
        });
        let Some((leave_request_id, requester_did)) = chosen else {
            return Ok(false);
        };

        let convo = self
            .db
            .read_tx(|tx| tx.get_conversation(conversation_id))?
            .ok_or_else(|| MLSError::group_not_found(conversation_id))?;
        let prior_sv = prior["stateVersion"].as_i64().unwrap_or(0);
        let prior_epoch = prior["epoch"].as_u64().unwrap_or(0);
        let prior_gen = prior["generation"].as_i64().unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior["confirmationTag"])?;

        let transition_uuid = self.hooks.uuid_v4();
        let transition_id = transition_uuid.to_string();

        let maybe_built = self.db.read_tx(|tx| {
            let overlay = KvWriteOverlay::new(RusqliteKvBackend(tx.conn()));
            let built = {
                let storage = OpenMlsKvStorage::new(&overlay);
                let provider = self.hooks.openmls_provider(storage);
                let mut group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        .ok_or_else(|| MLSError::group_not_found(conversation_id))?;
                let own_scoped = format!("{}#{canonical_dev_id}", self.normalized_did);
                if !group.members().any(|m| {
                    std::str::from_utf8(m.credential.serialized_content())
                        == Ok(own_scoped.as_str())
                }) {
                    return Ok(None);
                }
                let prefix = format!("{requester_did}#");
                let mut target_leaves = Vec::new();
                let mut removed_leaf_entries = Vec::new();
                for member in group.members() {
                    if let Ok(id_str) = std::str::from_utf8(member.credential.serialized_content())
                    {
                        if let Some(dev_part) = id_str.strip_prefix(&prefix) {
                            target_leaves.push(member.index);
                            removed_leaf_entries.push(json!({
                                "$type": "blue.catbird.chat.defs#removeLeaf",
                                "userDid": requester_did,
                                "deviceId": dev_part,
                            }));
                        }
                    }
                }
                if target_leaves.is_empty() {
                    return Ok(None);
                }
                let metadata_carry = self
                    .metadata_snapshot_plaintext_for_carry_forward(
                        tx,
                        conversation_id,
                        &convo.group_id,
                        &mut group,
                        &provider,
                    )?;

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
                let commit_bytes = group
                    .remove_members(&provider, signer, &target_leaves)
                    .map_err(|e| MLSError::Cryptography(format!("remove_members: {e:?}")))?
                    .0
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("merge_pending_commit: {e:?}")))?;
                group.set_aad(Vec::new());

                let next_epoch = group.epoch().as_u64();
                let (next_gch, next_ctag) =
                    chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let carried_snap = self.reencrypt_metadata_snapshot_for_epoch(
                    metadata_carry,
                    &mut group,
                    &provider,
                    &convo.group_id,
                    convo_uuid,
                    prior_gen,
                    next_epoch,
                    &next_gch,
                    &next_ctag,
                )?;
                (
                    commit_aad_val,
                    commit_bytes,
                    removed_leaf_entries,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                )
            };
            Ok(Some((built, overlay.into_batch())))
        })?;
        let Some((
            (
                commit_aad_val,
                commit_bytes,
                removed_leaves,
                next_epoch,
                next_gch,
                next_ctag,
                carried_snap,
            ),
            kv_batch,
        )) = maybe_built
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
            "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "leaveRequestId": leave_request_id,
            "actorDid": self.normalized_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "signedAt": self.hooks.now_rfc3339_millis(),
            "prior": prior,
            "next": next_coords,
            "aad": commit_aad_val,
            "manifest": {
                "participantChanges": [{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": requester_did,
                }],
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
        let kv_batch = self.persist_pending_commit_transition(PendingCommitTransition {
            conversation_id: conversation_id.to_string(),
            transition_id: transition_id.clone(),
            commit_sha256,
            prior: prior.clone(),
            next: next_coords.clone(),
            kv_batch,
            removed_participant_did: Some(requester_did.clone()),
        })?;

        let (resp_val, sent) = match self.submit_own_control(
            canonical_dev_id,
            auth_gen,
            CanonicalOperation::SubmitTransition,
            &body,
            signer,
        ) {
            Ok(val) => val,
            Err(err) => {
                if err.is_stale_coordinates() {
                    self.db.write_tx(|tx| {
                        tx.delete_pending_op("commit_transition", &transition_id)?;
                        Ok(())
                    })?;
                }
                return Err(err);
            }
        };
        let auth_seq = verify_own_answer(
            &resp_val,
            &sent,
            conversation_id,
            LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        )?;
        let coords_str =
            serde_json::to_string(&next_coords).map_err(|e| MLSError::Internal(e.to_string()))?;
        let snap_str =
            serde_json::to_string(&carried_snap).map_err(|e| MLSError::Internal(e.to_string()))?;
        let needs_gap_sync = self.db.write_tx(|tx| {
            let current = tx.get_conversation(conversation_id)?;
            if let Some(c) = &current {
                if auth_seq > c.last_seq.saturating_add(1) {
                    return Ok(true);
                }
            }
            kv_batch.apply(&RusqliteKvBackend(tx.conn()))?;
            self.clear_cached_groups();
            tx.put_account_meta(
                &format!("last_removed_member:{conversation_id}"),
                &requester_did,
                now_ms,
            )?;
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
            super::live_sync::apply_verified_roster_effects(
                tx,
                conversation_id,
                SignedMutationKind::LeaveCommitFulfillment,
                &body,
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
            if let Some(convo_now) = self.db.read_tx(|tx| tx.get_conversation(conversation_id))? {
                self.sync_conversation_entries(canonical_dev_id, signer, &convo_now)?;
            }
        }
        Ok(true)
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
            let group_key = serde_json::to_vec(group.group_id())?;
            let message_secrets = crate::storage::KvBackend::kv_get(
                &RusqliteKvBackend(tx.conn()),
                openmls_traits::storage::CURRENT_VERSION,
                crate::storage::SCOPE_MESSAGE_SECRETS,
                &group_key,
            )
            .map_err(|error| {
                MLSError::Internal(format!("inspect MessageSecrets storage: {error}"))
            })?
            .ok_or_else(|| MLSError::Internal("inspect MessageSecrets missing".into()))?;
            let mut message_secrets: Value = serde_json::from_slice(&message_secrets)?;
            let secret_tree = message_secrets
                .pointer_mut("/message_secrets/secret_tree")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| MLSError::Internal("inspect SecretTree missing".into()))?;
            let own_index = secret_tree
                .get("own_index")
                .and_then(Value::as_u64)
                .and_then(|index| usize::try_from(index).ok())
                .ok_or_else(|| MLSError::Internal("inspect own leaf index missing".into()))?;
            let peer_ratchets = secret_tree
                .get_mut("application_sender_ratchets")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    MLSError::Internal("inspect application sender ratchets missing".into())
                })?;
            *peer_ratchets
                .get_mut(own_index)
                .ok_or_else(|| MLSError::Internal("inspect own ratchet out of bounds".into()))? =
                Value::Null;
            let peer_application_ratchets_hash =
                Sha256::digest(serde_json::to_vec(peer_ratchets)?).to_vec();
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
                peer_application_ratchets_hash,
                members,
                has_pending_commit: group.pending_commit().is_some(),
            }))
        })
    }
}

#[cfg(test)]
mod verification_boundary_tests {
    use super::*;
    use crate::client::{CatbirdMlsClientConfig, PlatformKeyStore, PlatformTransport};
    use openmls_traits::types::SignatureScheme;
    use std::sync::Arc;

    #[test]
    fn verify_own_answer_rejects_kind_conversation_and_request_mismatches_independently() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("ed25519 signer");
        let cid = "00000000-0000-4000-8000-00000000c401";
        let dev = "00000000-0000-4000-8000-00000000d401";
        let op_id = "00000000-0000-4000-8000-00000000e401";
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let key_id = derive_key_id(signer.public());
        let next = json!({
            "conversationId": cid,
            "generation": 0,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode([0x11u8; 32]) },
            "epoch": 0,
            "groupContextHash": { "$bytes": STANDARD.encode([0x22u8; 32]) },
            "confirmationTag": { "$bytes": STANDARD.encode([0x33u8; 32]) },
            "lifecycle": "active",
        });
        let body = json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "signatureDomain": "CATBIRD-CHAT-CREATE\0",
            "conversationId": cid,
            "transitionId": op_id,
            "conversationKind": "group",
            "absence": true,
            "actorDid": did,
            "actorDeviceId": dev,
            "authGeneration": 1,
            "idempotencyKey": op_id,
            "keyId": key_id,
            "signedAt": "2026-11-13T00:00:00.000Z",
            "next": next,
            "manifest": {
                "actorLeaf": {
                    "userDid": did,
                    "deviceId": dev,
                    "leafOrigin": "genesis",
                },
                "participants": [{
                    "userDid": did,
                    "status": "active",
                    "role": "admin",
                }],
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode([0x44u8; 16]) },
                "sha256": STANDARD.encode(Sha256::digest([0x44u8; 16])),
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": { "$bytes": STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes()) },
                    "generation": 0,
                    "groupId": { "$bytes": STANDARD.encode([0x11u8; 32]) },
                    "epoch": 0,
                    "groupContextHash": { "$bytes": STANDARD.encode([0x22u8; 32]) },
                    "confirmationTag": { "$bytes": STANDARD.encode([0x33u8; 32]) },
                },
                "originTransitionId": op_id,
                "metadataVersion": 1,
                "nonce": { "$bytes": STANDARD.encode([0x55u8; 12]) },
                "ciphertext": { "$bytes": STANDARD.encode([0x66u8; 32]) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest([0x66u8; 32])),
                "ciphertextSize": 32,
                "authorProof": {
                    "authorDid": did,
                    "authorDeviceId": dev,
                    "authorKeyId": key_id,
                    "signaturePublicKey": { "$bytes": STANDARD.encode(signer.public()) },
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": op_id,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
        });
        let prepared = chat_wire::sign_clean_chat_mutation(
            did,
            dev,
            Some(1),
            CanonicalOperation::CreateConversation,
            &body,
            &signer,
        )
        .expect("sign creation");
        let submitted: Value =
            serde_json::from_slice(&prepared.body.expect("request bytes")).expect("json");
        let signed = &submitted["signedRequest"];
        let valid_answer = json!({
            "result": {
                "coordinates": next,
                "entry": {
                    "$type": CREATION_ENTRY_KIND,
                    "conversationId": cid,
                    "seq": 1,
                    "signedRequest": signed,
                }
            }
        });
        assert_eq!(
            verify_own_answer(&valid_answer, signed, cid, CREATION_ENTRY_KIND).expect("exact"),
            1
        );

        let mut wrong_kind = valid_answer.clone();
        wrong_kind["result"]["entry"]["$type"] =
            json!("blue.catbird.chat.defs#participantAcceptanceEntry");
        assert!(
            verify_own_answer(&wrong_kind, signed, cid, CREATION_ENTRY_KIND).is_err(),
            "mismatched entry $type alone must fail verify_own_answer"
        );

        let mut wrong_convo = valid_answer.clone();
        wrong_convo["result"]["entry"]["conversationId"] =
            json!("00000000-0000-4000-8000-00000000c499");
        assert!(
            verify_own_answer(&wrong_convo, signed, cid, CREATION_ENTRY_KIND).is_err(),
            "mismatched entry conversationId alone must fail verify_own_answer"
        );

        let mut other_body = body.clone();
        other_body["signedAt"] = json!("2026-11-13T00:00:01.000Z");
        let other_prepared = chat_wire::sign_clean_chat_mutation(
            did,
            dev,
            Some(1),
            CanonicalOperation::CreateConversation,
            &other_body,
            &signer,
        )
        .expect("sign other creation");
        let other_submitted: Value =
            serde_json::from_slice(&other_prepared.body.expect("other bytes")).expect("json");
        let mut wrong_request = valid_answer;
        wrong_request["result"]["entry"]["signedRequest"] =
            other_submitted["signedRequest"].clone();
        assert!(
            verify_own_answer(&wrong_request, signed, cid, CREATION_ENTRY_KIND).is_err(),
            "mismatched signedRequest alone must fail verify_own_answer"
        );
    }

    #[test]
    fn did_web_url_refuses_loopback_and_plc_resolution_uses_plc_directory_authority() {
        use std::sync::Mutex;

        // 1. The shared builder refuses loopback, IP literals and lookalike local names, and
        //    never downgrades to plaintext HTTP.
        use crate::client::did_url::did_document_url;
        for loopback in [
            "did:web:localhost%3A8080",
            "did:web:127.0.0.1%3A9000",
            "did:web:localhost",
            "did:web:127.0.0.1",
        ] {
            assert!(did_document_url(loopback).is_err(), "{loopback}");
        }
        assert_eq!(
            did_document_url("did:web:127.0.0.1.attacker.example").as_deref(),
            Ok("https://127.0.0.1.attacker.example/.well-known/did.json")
        );
        assert!(did_document_url("did:web:localhost.attacker.example").is_err());
        assert!(did_document_url("did:plc:short").is_err());

        // 2. `resolve_did_document` for `did:plc:*` queries `https://plc.directory/{did}` directly
        //    and ignores any forged response from own PDS `resolveDid`.
        struct MockKeyStore;
        impl PlatformKeyStore for MockKeyStore {
            fn load_or_create_db_key(&self, _: String) -> Result<Vec<u8>, MLSError> {
                Ok(vec![0x33u8; 32])
            }
            fn store_signature_keypair(&self, _: String, _: Vec<u8>) -> Result<(), MLSError> {
                Ok(())
            }
            fn load_signature_keypair(&self, _: String) -> Result<Option<Vec<u8>>, MLSError> {
                Ok(None)
            }
            fn delete_account_keys(&self, _: String) -> Result<(), MLSError> {
                Ok(())
            }
            fn load_cached_chat_dpop_token(&self, _: String) -> Result<Option<String>, MLSError> {
                Ok(None)
            }
            fn store_cached_chat_dpop_token(
                &self,
                _: String,
                _: String,
                _: i64,
            ) -> Result<(), MLSError> {
                Ok(())
            }
        }
        struct RecordingTransport {
            urls: Mutex<Vec<String>>,
            mismatched_id: bool,
        }
        impl PlatformTransport for RecordingTransport {
            fn execute_http(
                &self,
                request: PlatformHttpRequest,
            ) -> Result<PlatformHttpResponse, MLSError> {
                self.urls.lock().unwrap().push(request.url.clone());
                if request
                    .url
                    .contains("/xrpc/com.atproto.identity.resolveDid")
                {
                    // Poisoned own-PDS answer that must never be trusted for `did:plc:*`.
                    return Ok(PlatformHttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: serde_json::to_vec(&json!({
                            "didDoc": {
                                "id": "did:plc:targetpeer22222222222222",
                                "service": [{
                                    "id": "#atproto_pds",
                                    "type": "AtprotoPersonalDataServer",
                                    "serviceEndpoint": "https://forged.attacker.example"
                                }]
                            }
                        }))
                        .unwrap(),
                    });
                }
                if let Some(did) = request.url.strip_prefix("https://plc.directory/") {
                    let doc_id = if self.mismatched_id {
                        "did:plc:wrongidentity33333333333"
                    } else {
                        did
                    };
                    return Ok(PlatformHttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: serde_json::to_vec(&json!({
                            "id": doc_id,
                            "service": [{
                                "id": "#atproto_pds",
                                "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": "https://authoritative.pds.example"
                            }]
                        }))
                        .unwrap(),
                    });
                }
                Ok(PlatformHttpResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                })
            }
            fn connect_realtime_stream(&self, _: String, _: Option<i64>) -> Result<(), MLSError> {
                Ok(())
            }
            fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let transport = Arc::new(RecordingTransport {
            urls: Mutex::new(Vec::new()),
            mismatched_id: false,
        });
        let client = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: dir.path().to_string_lossy().into_owned(),
                account_did: "did:plc:ownaccount22222222222222".to_string(),
                device_id: "00000000-0000-4000-8000-00000000d777".to_string(),
                home_ds_did: "did:web:ds.catbird.test".to_string(),
                home_ds_endpoint: "https://ds.catbird.test".to_string(),
                pds_endpoint: "https://own.pds.example".to_string(),
            },
            Arc::new(MockKeyStore),
            transport.clone(),
            None,
        )
        .unwrap();

        let target = "did:plc:targetpeer22222222222222";
        let doc_bytes = client
            .resolve_did_document(target)
            .unwrap()
            .expect("plc doc");
        let ep = chat_wire::extract_pds_endpoint_from_did_doc(&doc_bytes, target).unwrap();
        assert_eq!(ep, "https://authoritative.pds.example");
        let urls = transport.urls.lock().unwrap().clone();
        assert_eq!(urls, vec![format!("https://plc.directory/{target}")]);

        // Mismatched DID document `id` fails closed with `Cryptography`.
        let dir2 = tempfile::tempdir().unwrap();
        let bad_client = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: dir2.path().to_string_lossy().into_owned(),
                account_did: "did:plc:ownaccount22222222222222".to_string(),
                device_id: "00000000-0000-4000-8000-00000000d778".to_string(),
                home_ds_did: "did:web:ds.catbird.test".to_string(),
                home_ds_endpoint: "https://ds.catbird.test".to_string(),
                pds_endpoint: "https://own.pds.example".to_string(),
            },
            Arc::new(MockKeyStore),
            Arc::new(RecordingTransport {
                urls: Mutex::new(Vec::new()),
                mismatched_id: true,
            }),
            None,
        )
        .unwrap();
        assert!(matches!(
            bad_client.resolve_did_document(target),
            Err(MLSError::Cryptography(_))
        ));
    }
}

#[cfg(test)]
#[path = "live_plane_unit_tests.rs"]
mod live_plane_unit_tests;
