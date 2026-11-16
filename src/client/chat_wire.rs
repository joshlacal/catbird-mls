//! Shared canonical `/xrpc/blue.catbird.chat.*`, `C33` direct-request, `I4` PDS key,
//! and `I13` ES256 receipt wire helpers for `CatbirdMlsClient` (native) and `WasmMlsClient` (`wasm32`).

use std::collections::BTreeMap;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer as _, storage::StorageProvider as _, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use tls_codec::Serialize as _;

use crate::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use crate::chat_v2::transcript::{
    normalize_read_presentation, project_signed_body, SignedMutationKind, SignedWrapper,
    VerifiedMutation,
};
use crate::client::traits::PlatformHttpHeader;
use crate::error::MLSError;
use crate::metadata::{
    decrypt_metadata_snapshot, derive_metadata_key_from_group,
    encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use crate::orchestrator::canonical_transport::{
    derive_key_id, CanonicalOperation, CleanChatSigningContext, PreparedRequest,
};

pub const CHAT_READ_HEADER: &str = "catbird-chat-read";
pub const CHAT_READ_SIG_HEADER: &str = "catbird-chat-read-signature";
const CHAT_READ_DOMAIN: &[u8] = b"CATBIRD-CHAT-READ\0";
const ACK_ENTRIES_DOMAIN: &[u8] = b"CATBIRD-CHAT-ACK-ENTRIES\0";
pub const PDS_DEVICE_REVOCATION_DOMAIN: &[u8] = b"CATBIRD-CHAT-PDS-DEVICE-REVOCATION-V1\0";
pub const PDS_LIST_RECORDS_PAGE_LIMIT: usize = 100;
pub const MAX_PDS_LIST_RECORDS_PAGES: usize = 10;
pub const MAX_PDS_LIST_RECORDS_ITEMS: usize = 1_000;

/// Decode a base64 field in either bare string or ATProto `{"$bytes": "..."}` JSON form.
pub fn json_bytes(v: &Value) -> Result<Vec<u8>, MLSError> {
    let raw = v
        .as_str()
        .or_else(|| v.get("$bytes").and_then(|b| b.as_str()))
        .ok_or_else(|| MLSError::invalid_input("expected base64 string or $bytes object"))?;
    STANDARD
        .decode(raw.trim())
        .map_err(|e| MLSError::invalid_input(format!("invalid base64 bytes: {e}")))
}

/// The active `getOwnDevices` item for `device_id` under `signature_public_key`. After a lost
/// `enrollDevice` response (`DeviceAlreadyExists` on retry) it is the only proof that `mls-ds`
/// holds this signer; without it enrollment fails closed (a new key needs a new device ID).
pub fn own_active_device<'a>(
    own_devices: &'a Value,
    device_id: &str,
    signature_public_key: &[u8],
) -> Option<&'a Value> {
    own_devices["items"].as_array()?.iter().find(|item| {
        let device = &item["device"];
        device["deviceId"] == device_id
            && device["status"] == "active"
            && json_bytes(&device["signaturePublicKey"])
                .is_ok_and(|key| key == signature_public_key)
    })
}

/// `mls-ds` error for a send whose `(prior.generation, prior.epoch, sendCounter)` does not exceed
/// this device's last accepted send in the conversation. Nothing was sequenced or retired: the
/// sender re-sends the same message id as a freshly encrypted frame, never the refused bytes.
pub const STALE_SEND: &str = "StaleSend";

pub fn is_stale_send(error: &MLSError) -> bool {
    matches!(error, MLSError::InvalidState(code) if code == STALE_SEND)
}

/// SQLite `account_meta` key of the last send this device knows the sequencer accepted.
pub fn send_counter_key(conversation_id: &str) -> String {
    format!("send_counter:{conversation_id}")
}
/// SQLite `account_meta` key of the last verified peer `sendCounter` in one MLS epoch.
pub fn peer_send_counter_key(
    conversation_id: &str,
    generation: i64,
    epoch: i64,
    sender_did: &str,
    sender_device_id: &str,
) -> String {
    format!(
        "peer_last_send_counter:{conversation_id}:{generation}:{epoch}:{sender_did}:{sender_device_id}"
    )
}

/// Require a verified peer sender's counter to increase once initialized.
pub fn verify_next_peer_send_counter(last: Option<&str>, next: u64) -> Result<(), MLSError> {
    if next > 9_007_199_254_740_991 {
        return Err(MLSError::Cryptography(
            "peer sendCounter exceeds the canonical safe-integer range".into(),
        ));
    }
    let Some(last) = last else {
        return Ok(());
    };
    let last = last
        .parse::<u64>()
        .map_err(|_| MLSError::Internal(format!("corrupt peer send counter {last:?}")))?;
    if next <= last {
        return Err(MLSError::Cryptography(format!(
            "non-increasing peer sendCounter: last {last}, received {next}"
        )));
    }
    Ok(())
}

/// Durable fork evidence for a conversation whose peer signed a different current-epoch prior.
pub fn fork_detected_key(conversation_id: &str) -> String {
    format!("fork_detected:{conversation_id}")
}

/// Latest own reset request that ordinary entry sync verified and applied contiguously.
pub fn verified_reset_request_key(conversation_id: &str) -> String {
    format!("verified_reset_request:{conversation_id}")
}

/// The counter after the last send known to be sequenced (absent before the first send). A
/// reservation does not advance this value: uncertain delivery keeps its exact journal, while a
/// definitive unsequenced refusal may safely reuse the counter with a fresh MLS frame.
pub fn next_send_counter(last: Option<&str>) -> Result<u64, MLSError> {
    let last = match last {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| MLSError::Internal(format!("corrupt send counter {raw:?}")))?,
        None => 0,
    };
    last.checked_add(1)
        .filter(|next| *next <= 9_007_199_254_740_991)
        .ok_or_else(|| MLSError::Internal("send counter exhausted".into()))
}

/// Advance the durable accepted-send watermark without ever moving it backwards.
pub fn confirmed_send_counter(last: Option<&str>, confirmed: u64) -> Result<u64, MLSError> {
    if !(1..=9_007_199_254_740_991).contains(&confirmed) {
        return Err(MLSError::Internal(
            "confirmed send counter is outside the safe-integer range".into(),
        ));
    }
    let last = match last {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| MLSError::Internal(format!("corrupt send counter {raw:?}")))?,
        None => 0,
    };
    Ok(last.max(confirmed))
}

/// Why a current-epoch application message can never be decrypted by this device: its
/// generation left the sender-ratchet window or was consumed, or its key or framing cannot open
/// it. Re-fetching the same signed entry cannot change any of these. A library, storage or
/// non-decryption failure returns `None` and stays fatal for the sync pass.
pub fn permanent_decrypt_failure<E>(error: &ProcessMessageError<E>) -> Option<&'static str> {
    use openmls::framing::errors::{MessageDecryptionError as D, SecretTreeError as S};
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(error)) = error
    else {
        return None;
    };
    Some(match error {
        D::SecretTreeError(S::TooDistantInThePast) => "TooDistantInThePast",
        D::SecretTreeError(S::TooDistantInTheFuture) => "TooDistantInTheFuture",
        D::SecretTreeError(S::SecretReuseError) => "SecretReuse",
        D::SecretTreeError(S::IndexOutOfBounds | S::RatchetTooLong) => "SenderRatchetUnavailable",
        D::GenerationOutOfBound => "GenerationOutOfBound",
        D::AeadError => "AeadFailure",
        D::MalformedContent | D::WrongWireFormat => "MalformedContent",
        _ => return None,
    })
}

/// System notice content key of the row that stands in for an undecryptable message.
pub const UNDECRYPTABLE_MESSAGE_NOTICE: &str = "message.undecryptable";

/// `labyrinth_state` key of the evidence that this device can never decrypt `message_id`. It
/// holds no plaintext, frame nonce or receipt, so no witness or archive copy exists for it: kick
/// rescue records the message as evidence-less and restore may replace the gap row with a
/// verified archive copy.
pub fn undecryptable_evidence_key(conversation_id: &str, message_id: &str) -> String {
    format!("native.undecryptable:{conversation_id}:{message_id}")
}

/// One sequenced application entry, its outer signed request verified, that this device can
/// never decrypt (`permanent_decrypt_failure`). The sender fields come from that signed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndecryptableEntryEvidence {
    pub version: u32,
    pub conversation_id: String,
    pub message_id: String,
    pub entry_id: String,
    pub seq: i64,
    pub epoch: i64,
    pub sender_did: String,
    pub sender_device_id: String,
    /// The signed peer counter, absent only in legacy persisted evidence.
    #[serde(default)]
    pub send_counter: Option<u64>,
    pub reason: String,
    pub recorded_at_ms: i64,
}

impl UndecryptableEntryEvidence {
    /// The timeline row marking the gap: a system notice at the entry's seq.
    pub fn gap_row(
        &self,
        group_id: &[u8],
        is_own: bool,
    ) -> Result<crate::storage::MessageRow, MLSError> {
        Ok(crate::storage::MessageRow {
            message_id: self.message_id.clone(),
            conversation_id: self.conversation_id.clone(),
            group_id: group_id.to_vec(),
            epoch: self.epoch,
            seq: self.seq,
            sender_did: self.sender_did.clone(),
            sender_device_id: self.sender_device_id.clone(),
            plaintext_json: serde_json::to_string(
                &crate::orchestrator::MLSMessagePayload::system(UNDECRYPTABLE_MESSAGE_NOTICE),
            )?,
            created_at_ms: self.recorded_at_ms,
            is_own,
        })
    }
}

/// Normalize a signed mutation's JSON read presentation so equivalent byte encodings compare
/// identically while its closed body and signature wrapper remain exact.
pub fn normalize_signed_mutation_presentation(
    signed_request: &serde_json::Value,
    kind: SignedMutationKind,
) -> Result<serde_json::Value, MLSError> {
    let wrapper_name = signed_wrapper_name(kind)
        .ok_or_else(|| MLSError::Cryptography("unexpected signed transition kind".into()))?;
    normalize_read_presentation(&serde_json::to_vec(signed_request)?, wrapper_name, false)
        .map_err(|e| MLSError::Cryptography(format!("normalize signed transition: {e}")))
}

/// Verify an outer signed transition or application send and return its strictly projected body
/// plus SHA-256 request transcript digest.
pub fn verify_signed_mutation_body_and_digest(
    signed_request: &serde_json::Value,
    kind: SignedMutationKind,
    public_key: &[u8],
) -> Result<(serde_json::Value, [u8; 32]), MLSError> {
    let mut normalized = normalize_signed_mutation_presentation(signed_request, kind)?;
    let wrapper = SignedWrapper::decode(&serde_json::to_vec(&normalized)?)
        .map_err(|e| MLSError::Cryptography(format!("decode signed transition: {e}")))?;
    if wrapper.kind() != Some(kind) {
        return Err(MLSError::Cryptography(
            "signed transition has the wrong kind".into(),
        ));
    }
    let projected = project_signed_body(kind, &wrapper.body)
        .map_err(|e| MLSError::Cryptography(format!("project signed transition: {e}")))?;
    let verified = VerifiedMutation::verify(projected, wrapper.signature, public_key)
        .map_err(|e| MLSError::Cryptography(format!("verify signed transition: {e}")))?;
    Ok((normalized["body"].take(), *verified.request_digest()))
}

/// Verify an outer signed transition or application send under `public_key` and return its
/// strictly projected body (native sync, NSE and `wasm32` sync share this one check).
pub fn verify_signed_mutation_body(
    signed_request: &serde_json::Value,
    kind: SignedMutationKind,
    public_key: &[u8],
) -> Result<serde_json::Value, MLSError> {
    verify_signed_mutation_body_and_digest(signed_request, kind, public_key).map(|(body, _)| body)
}

/// Authenticate this device's own sequenced transition under its signer before any own-echo
/// shortcut, retaining the request digest used by its sequencer receipt.
pub fn verify_own_commit_body_and_digest(
    signed_request: &Value,
    public_key: &[u8],
) -> Result<(Value, [u8; 32]), MLSError> {
    let kind = signed_request
        .pointer("/body/$type")
        .and_then(Value::as_str)
        .and_then(SignedMutationKind::from_type_id)
        .ok_or_else(|| MLSError::Cryptography("own Commit has no signed mutation kind".into()))?;
    verify_signed_mutation_body_and_digest(signed_request, kind, public_key)
}

/// Authenticate this device's own sequenced transition under its signer before any own-echo
/// shortcut: the entry's actor labels are only a routing hint.
pub fn verify_own_commit_body(
    signed_request: &Value,
    public_key: &[u8],
) -> Result<Value, MLSError> {
    verify_own_commit_body_and_digest(signed_request, public_key).map(|(body, _)| body)
}

/// A group creation journaled before HTTP. The staged epoch-zero MLS state exists once; signed
/// attempts are append-only (bounded at [`GROUP_CREATION_MAX_ATTEMPTS`]) so every operation that
/// could have committed remains exactly replayable.
pub const GROUP_CREATION_JOURNAL_VERSION: u32 = 3;

/// Maximum signed attempts retained in one group-creation journal.
pub const GROUP_CREATION_MAX_ATTEMPTS: usize = 8;

/// One exact signed attempt over a journal's single staged genesis.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingGroupCreationAttempt {
    pub operation_id: String,
    pub signed_at: String,
    pub request: Vec<u8>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired_confirmed: bool,
}

/// App-visible disposition of a durable group-creation journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[serde(rename_all = "camelCase")]
pub enum PendingGroupCreationState {
    PendingRetry,
    /// ABI-reserved. The creation resolver currently has no state with a user-remediable action.
    NeedsUserAction,
}

/// Current state of one durable group creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PendingGroupCreationStatus {
    pub conversation_id: String,
    pub state: PendingGroupCreationState,
    pub retry_at_ms: Option<i64>,
    pub last_error_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PendingGroupCreation {
    pub version: u32,
    pub conversation_id: String,
    /// Stable storage key: the first attempt's operation id.
    pub journal_id: String,
    /// Stable sequencer identity. The endpoint is resolved from current client configuration.
    pub sequencer_did: String,
    pub group_id: Vec<u8>,
    pub signer_public_key: Vec<u8>,
    pub attempts: Vec<PendingGroupCreationAttempt>,
    pub kv_batch: crate::storage::KvWriteBatch,
    pub title: Option<String>,
    pub description: Option<String>,
    pub new_signer_json: Option<String>,
    pub created_at_ms: i64,
    /// Earliest wall-clock time at which sync may resolve this journal.
    #[serde(default)]
    pub retry_at_ms: i64,
    /// Consecutive retained failures, used for bounded exponential backoff.
    #[serde(default)]
    pub retry_count: u32,
    /// Typed server refusal reported while a retained request is deferred.
    #[serde(default)]
    pub retry_code: Option<String>,
}

impl PendingGroupCreation {
    pub fn status_at(&self, now_ms: i64) -> PendingGroupCreationStatus {
        let retry_at_ms = (self.retry_count > 0 || self.retry_code.is_some()).then_some(
            self.retry_at_ms
                .min(now_ms.saturating_add(GROUP_CREATION_MAX_RETRY_MS)),
        );
        PendingGroupCreationStatus {
            conversation_id: self.conversation_id.clone(),
            state: PendingGroupCreationState::PendingRetry,
            retry_at_ms,
            last_error_code: self.retry_code.clone(),
        }
    }

    /// Ignore a persisted deadline farther than the maximum delay from the current wall clock.
    /// This bounds a backward clock jump instead of deferring the journal forever.
    pub fn retry_is_deferred_at(&self, now_ms: i64) -> bool {
        self.retry_count > 0
            && self.retry_at_ms > now_ms
            && self.retry_at_ms.saturating_sub(now_ms) <= GROUP_CREATION_MAX_RETRY_MS
    }
}

/// Server's maximum accepted age for a first-execution signed operation.
///
/// Keep aligned with `mls-ds/server/src/chat_protocol/validation.rs:14,444-465`.
pub const GROUP_CREATION_FRESHNESS_WINDOW_MS: i64 = 300_000;

/// The server's accepted future skew is also the guard beyond the first-execution window.
///
/// Keep aligned with `mls-ds/server/src/chat_protocol/validation.rs:15,444-465`.
pub const GROUP_CREATION_FRESHNESS_SAFETY_MARGIN_MS: i64 = 60_000;

pub const GROUP_CREATION_ABANDON_AFTER_MS: i64 =
    GROUP_CREATION_FRESHNESS_WINDOW_MS + GROUP_CREATION_FRESHNESS_SAFETY_MARGIN_MS;

/// Maximum generated or honored delay for a retained group-creation retry.
pub const GROUP_CREATION_MAX_RETRY_MS: i64 = 300_000;

pub fn group_creation_attempt_signed_at_ms(
    attempt: &PendingGroupCreationAttempt,
) -> Result<i64, MLSError> {
    chrono::DateTime::parse_from_rfc3339(&attempt.signed_at)
        .map(|value| value.timestamp_millis())
        .map_err(|_| MLSError::Cryptography("creation attempt signedAt is invalid".into()))
}

pub fn group_creation_attempts_expired_at(
    pending: &PendingGroupCreation,
    local_now_ms: i64,
) -> Result<bool, MLSError> {
    if pending.attempts.is_empty() {
        return Err(MLSError::Cryptography(
            "group creation journal has no signed attempts".into(),
        ));
    }
    pending.attempts.iter().try_fold(true, |all, attempt| {
        let signed_at_ms = group_creation_attempt_signed_at_ms(attempt)?;
        Ok(all
            && (attempt.expired_confirmed
                || local_now_ms.saturating_sub(signed_at_ms) > GROUP_CREATION_ABANDON_AFTER_MS))
    })
}

pub fn group_creation_refusal_is_expired(status: u16, code: Option<&str>) -> bool {
    matches!((status, code), (400, Some("SignedOperationExpired")))
}

pub fn group_creation_refusal_is_exists_evidence(status: u16, code: Option<&str>) -> bool {
    matches!(
        (status, code),
        (
            400 | 409,
            Some("ConversationAlreadyExists" | "IdempotencyConflict")
        )
    )
}

/// Refusals that re-signing the same stale credentials/request cannot repair. This is only a
/// classifier: deletion additionally requires authenticated absence/foreign proof and expiry of
/// every attempt.
pub fn group_creation_refusal_is_permanent(status: u16, code: Option<&str>) -> bool {
    if group_creation_refusal_is_exists_evidence(status, code)
        || group_creation_refusal_is_expired(status, code)
    {
        return false;
    }
    match status {
        400 | 403 => true,
        401 => matches!(
            code,
            Some(
                "NotAuthorized"
                    | "DeviceRevoked"
                    | "DeviceBindingMismatch"
                    | "InvalidRequest"
                    | "CutoverRequired"
                    | "ProtocolUpgradeRequired"
            )
        ),
        500 => matches!(code, Some("InvalidRequest")),
        _ => false,
    }
}

/// One attempt per caller; retained failures wait exponentially from 1 s, capped at 300 s.
/// A valid `Retry-After` replaces the exponential delay but is capped to the same bound.
pub fn group_creation_retry_delay_ms(retry_count: u32, retry_after_secs: Option<u64>) -> i64 {
    let fallback = 1_u64 << retry_count.saturating_sub(1).min(8);
    retry_after_secs
        .unwrap_or(fallback)
        .clamp(1, (GROUP_CREATION_MAX_RETRY_MS / 1_000) as u64)
        .saturating_mul(1_000) as i64
}

/// An own Commit-bearing transition journaled before HTTP (`pending_ops` kind
/// `commit_transition`, keyed by `transition_id`): the staged MLS batch an accepted answer or
/// its own sequenced echo applies. Native and `wasm32` clients share this one shape.
#[derive(Serialize, Deserialize)]
pub struct PendingCommitTransition {
    pub conversation_id: String,
    pub transition_id: String,
    pub commit_sha256: [u8; 32],
    pub prior: Value,
    pub next: Value,
    pub kv_batch: crate::storage::KvWriteBatch,
    #[serde(default)]
    pub removed_participant_did: Option<String>,
}

/// The signed wrapper definition that carries `kind` in a conversation entry or an answer.
fn signed_wrapper_name(kind: SignedMutationKind) -> Option<&'static str> {
    use SignedMutationKind as K;
    Some(match kind {
        K::ApplicationSend => "signedApplicationSend",
        K::Creation => "signedCreation",
        K::CommitTransition => "signedCommitTransition",
        K::PolicyTransition => "signedPolicyTransition",
        K::MetadataTransition => "signedMetadataTransition",
        K::ParticipantAcceptance => "signedParticipantAcceptance",
        K::ConversationClose => "signedConversationClose",
        K::ResetRequest => "signedResetRequest",
        K::ResetActivation => "signedResetActivation",
        K::LeafRecoveryFulfillment => "signedLeafRecoveryFulfillment",
        K::LeafRecoveryRequest => "signedLeafRecoveryRequest",
        K::LeaveRequest => "signedLeaveRequest",
        K::ZeroLeafLeave => "signedZeroLeafLeave",
        K::LeaveCancellation => "signedLeaveCancellation",
        K::LeaveCommitFulfillment => "signedLeaveCommitFulfillment",
        K::DeviceApproval => "signedDeviceApproval",
        K::DeviceRevocation => "signedDeviceRevocation",
        _ => return None,
    })
}

/// The `#conversationEntry` arm whose `signedRequest` is a `kind` body.
pub fn entry_kind_of(kind: SignedMutationKind) -> Option<&'static str> {
    use crate::chat_v2::wire as w;
    use SignedMutationKind as K;
    Some(match kind {
        K::ApplicationSend => w::APPLICATION_ENTRY_KIND,
        K::Creation => w::CREATION_ENTRY_KIND,
        K::CommitTransition => w::COMMIT_ENTRY_KIND,
        K::PolicyTransition => w::POLICY_ENTRY_KIND,
        K::MetadataTransition => w::METADATA_ENTRY_KIND,
        K::ParticipantAcceptance => w::PARTICIPANT_ACCEPTANCE_ENTRY_KIND,
        K::ConversationClose => w::CONVERSATION_CLOSE_ENTRY_KIND,
        K::ResetRequest => w::RESET_REQUEST_ENTRY_KIND,
        K::ResetActivation => w::RESET_ACTIVATION_ENTRY_KIND,
        K::LeafRecoveryFulfillment => w::LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
        K::LeaveRequest => w::LEAVE_REQUEST_ENTRY_KIND,
        K::ZeroLeafLeave => w::ZERO_LEAF_LEAVE_ENTRY_KIND,
        K::LeaveCancellation => w::LEAVE_CANCELLATION_ENTRY_KIND,
        K::LeaveCommitFulfillment => w::LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        _ => return None,
    })
}

/// The signed kind of a sequenced entry, read from its signed body (unverified until the caller
/// verifies that body under the kind's authority). A labelled entry must be the arm that carries
/// that body, so a relabelled entry never borrows another kind's effects.
pub fn signed_entry_kind(entry: &Value) -> Result<SignedMutationKind, MLSError> {
    let kind = entry
        .pointer("/signedRequest/body/$type")
        .and_then(Value::as_str)
        .and_then(SignedMutationKind::from_type_id)
        .filter(|kind| entry_kind_of(*kind).is_some())
        .ok_or_else(|| {
            MLSError::Cryptography("entry carries no signed conversation body".into())
        })?;
    match entry.get("$type") {
        Some(label) if label.as_str() != entry_kind_of(kind) => Err(MLSError::Cryptography(
            "entry kind differs from its signed body".into(),
        )),
        _ => Ok(kind),
    }
}

/// `to` is `from` with `stateVersion + 1` and lifecycle `to_lifecycle`, every other coordinate
/// equal, both bound to `cid`, `from` active. Policy, metadata, acceptance and zero-leaf leave
/// step to `active`; a close retires to `superseded`. Returns the canonical `to`.
pub fn verify_coordinate_step(
    from: &Value,
    to: &Value,
    cid: &str,
    to_lifecycle: &str,
) -> Result<Value, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("coordinate step: {what}"));
    if from["conversationId"].as_str() != Some(cid) || to["conversationId"].as_str() != Some(cid) {
        return Err(refused("not this conversation"));
    }
    if from["lifecycle"].as_str() != Some("active")
        || to["lifecycle"].as_str() != Some(to_lifecycle)
    {
        return Err(refused("lifecycle"));
    }
    let from = canonicalize_wire_coordinate(from, None)?;
    let to = canonicalize_wire_coordinate(to, None)?;
    let mut expected = from.clone();
    expected["stateVersion"] = json!(from["stateVersion"]
        .as_i64()
        .and_then(|version| version.checked_add(1))
        .ok_or_else(|| refused("stateVersion"))?);
    expected["lifecycle"] = json!(to_lifecycle);
    if to != expected {
        return Err(refused("changes more than stateVersion"));
    }
    Ok(to)
}

/// [`verify_coordinate_step`] from a verified body's `prior` to its active `next`.
pub fn verify_state_version_step(body: &Value, cid: &str) -> Result<Value, MLSError> {
    verify_coordinate_step(&body["prior"], &body["next"], cid, "active")
}

/// Whether a verified coordinate step from `prior` to `next` applies against `local`, the
/// conversation's current coordinate as this device last recorded it (`None` before it recorded
/// any). It applies when it steps from `local`. `Ok(false)`: this device's `own` transition whose
/// verified answer already recorded its `next`, which then only moves the cursor. Any other
/// `prior` is an entry replayed or reordered by the delivery service and is refused, so no entry
/// ever moves this device back to a coordinate it already left.
pub fn steps_from_local(
    prior: &Value,
    next: &Value,
    local: Option<&Value>,
    own: bool,
    cid: &str,
) -> Result<bool, MLSError> {
    let Some(local) = local else {
        return Ok(true);
    };
    let local = canonicalize_wire_coordinate(local, Some(cid))?;
    if canonicalize_wire_coordinate(prior, Some(cid))? == local {
        return Ok(true);
    }
    if own && canonicalize_wire_coordinate(next, Some(cid))? == local {
        return Ok(false);
    }
    Err(MLSError::Cryptography(
        "coordinate step: prior is not this device's current coordinate".into(),
    ))
}

/// The successor a verified `resetActivationBody` of `cid` opens, once it retires exactly its
/// `prior`: `retired` is `prior` one `stateVersion` on and superseded, and `successor` is the
/// next generation of `cid` at `stateVersion` 0 and epoch 0, active, on a fresh group ID.
/// Returns the canonical `successor`.
pub fn reset_successor(body: &Value, cid: &str) -> Result<Value, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("reset activation: {what}"));
    verify_coordinate_step(&body["prior"], &body["retired"], cid, "superseded")?;
    let prior = canonicalize_wire_coordinate(&body["prior"], None)?;
    let successor = &body["successor"];
    if successor["conversationId"].as_str() != Some(cid)
        || successor["lifecycle"].as_str() != Some("active")
    {
        return Err(refused(
            "successor is not this conversation's active successor",
        ));
    }
    let successor = canonicalize_wire_coordinate(successor, None)?;
    let generation = prior["generation"]
        .as_i64()
        .and_then(|generation| generation.checked_add(1))
        .ok_or_else(|| refused("generation"))?;
    if successor["generation"].as_i64() != Some(generation)
        || successor["stateVersion"].as_i64() != Some(0)
        || successor["epoch"].as_i64() != Some(0)
        || successor["groupId"] == prior["groupId"]
    {
        return Err(refused(
            "successor is not a fresh group at the next generation's start",
        ));
    }
    Ok(successor)
}

/// `account_meta` key of the seq at which `did`'s pending invitation to `cid` last ended: this
/// device verified that DID's acceptance or its removal there. An invitation sequenced at or
/// before it is no longer pending and authorizes nothing.
pub fn invitation_closed_key(cid: &str, did: &str) -> String {
    format!("invitation_closed:{cid}:{did}")
}

/// The participants a verified body of `kind` removes from its conversation: the
/// `removeParticipant` rows of a policy transition or a Commit manifest, and a zero-leaf
/// leave's own actor.
pub fn removed_participants(kind: SignedMutationKind, body: &Value) -> Vec<String> {
    let changes = match kind {
        SignedMutationKind::PolicyTransition => &body["participantChanges"],
        SignedMutationKind::CommitTransition | SignedMutationKind::LeaveCommitFulfillment => {
            &body["manifest"]["participantChanges"]
        }
        SignedMutationKind::ZeroLeafLeave => {
            return body["actorDid"]
                .as_str()
                .map(str::to_owned)
                .into_iter()
                .collect()
        }
        _ => return Vec::new(),
    };
    changes
        .as_array()
        .into_iter()
        .flatten()
        .filter(|change| change["$type"] == "blue.catbird.chat.defs#removeParticipant")
        .filter_map(|change| change["userDid"].as_str().map(str::to_owned))
        .collect()
}

/// `account_meta` key of `cid`'s acceptance authorization: the one add recovery a verified
/// participant acceptance authorizes this device to fulfill, recorded when it verified that
/// acceptance together with the invitation the acceptance names.
pub fn leaf_recovery_authorization_key(cid: &str) -> String {
    format!("leaf_recovery_authorization:{cid}")
}

/// Durable proof that this device verified an account's signed invitation and acceptance for
/// `cid`. Server participant state never creates this marker.
pub fn verified_participant_admission_key(cid: &str, did: &str) -> String {
    format!("verified_participant_admission:{cid}:{did}")
}

/// The authorization a verified `participantAcceptanceBody` of `cid` grants: the add request it
/// signed for exactly the accepting device, key ID and auth generation, bound to the acceptance's
/// `next` (mls-ds binds an acceptance's request to that coordinate, never to `prior`).
pub fn leaf_recovery_authorization(acceptance: &Value, cid: &str) -> Result<Value, MLSError> {
    Ok(json!({
        "recoveryRequestId": acceptance["recoveryRequestId"],
        "requesterDid": acceptance["actorDid"],
        "requesterDeviceId": acceptance["actorDeviceId"],
        "keyId": acceptance["keyId"],
        "authGeneration": acceptance["authGeneration"],
        "recoveryKind": "add",
        "boundCoordinate": verify_state_version_step(acceptance, cid)?,
    }))
}

/// The authorization a `leafRecoveryRequestBody` of `cid`, verified under its signing device's
/// PDS-authorized key, grants: exactly the `add` or `replace` recovery of that device, key ID and
/// auth generation, bound to its signed active `prior` (mls-ds binds an ordinary request to the
/// coordinate it was signed at). Same shape as [`leaf_recovery_authorization`]. Whether its
/// requester may be fulfilled at all is [`recovery_request_entitled`].
pub fn leaf_recovery_request_authorization(body: &Value, cid: &str) -> Result<Value, MLSError> {
    let prior = canonicalize_wire_coordinate(&body["prior"], None)?;
    if prior["conversationId"] != cid
        || prior["lifecycle"] != "active"
        || !matches!(body["recoveryKind"].as_str(), Some("add" | "replace"))
    {
        return Err(MLSError::Cryptography(
            "leaf recovery: not an active recovery request of this conversation".into(),
        ));
    }
    Ok(json!({
        "recoveryRequestId": body["recoveryRequestId"],
        "requesterDid": body["actorDid"],
        "requesterDeviceId": body["actorDeviceId"],
        "keyId": body["keyId"],
        "authGeneration": body["authGeneration"],
        "recoveryKind": body["recoveryKind"],
        "boundCoordinate": prior,
    }))
}

/// Whether this device (`own_did`, `own_device`) may fulfill the request `authorization` (from
/// [`leaf_recovery_request_authorization`]) in a group whose current leaves are `leaves`
/// (`(did, device)`), given its verified `roster` and durable `verified_admission`. Never its own
/// request. A `replace` re-adds an exact current leaf and may be fulfilled by any active group
/// member other than the requesting device itself (`did != own_did || device != own_device`),
/// including an online sibling device on the same account. An `add` adds a
/// device the tree does not hold, for a DID that either holds another current leaf or is active in
/// the verified roster and whose invitation and acceptance this device verified. Server roster
/// state alone never entitles a zero-leaf account.
pub fn recovery_request_entitled(
    authorization: &Value,
    leaves: &[(String, String)],
    roster: Option<&Value>,
    verified_admission: bool,
    own_did: &str,
    own_device: &str,
) -> bool {
    let (Some(did), Some(device)) = (
        authorization["requesterDid"].as_str(),
        authorization["requesterDeviceId"].as_str(),
    ) else {
        return false;
    };
    if did == own_did && device == own_device {
        return false;
    }
    let holds_leaf = leaves
        .iter()
        .any(|(leaf_did, leaf_device)| leaf_did == did && leaf_device == device);
    match authorization["recoveryKind"].as_str() {
        Some("replace") => holds_leaf && (did != own_did || device != own_device),
        Some("add") => {
            !holds_leaf
                && (leaves.iter().any(|(leaf_did, _)| leaf_did == did)
                    || (verified_admission && roster_active(roster, did)))
        }
        _ => false,
    }
}

/// The `leafChanges` of the fulfillment of `authorization` with the reserved KeyPackage
/// `key_package_ref`: its `addLeafByRecovery`, preceded for a `replace` by the `removeLeaf` of
/// the same device (`removeLeaf` ranks before `addLeafByRecovery` for one device).
pub fn recovery_leaf_changes(authorization: &Value, key_package_ref: &[u8]) -> Value {
    let did = &authorization["requesterDid"];
    let device = &authorization["requesterDeviceId"];
    let mut changes = Vec::with_capacity(2);
    if authorization["recoveryKind"] == "replace" {
        changes.push(json!({
            "$type": "blue.catbird.chat.defs#removeLeaf",
            "userDid": did,
            "deviceId": device,
        }));
    }
    changes.push(json!({
        "$type": "blue.catbird.chat.defs#addLeafByRecovery",
        "userDid": did,
        "deviceId": device,
        "recoveryRequestId": authorization["recoveryRequestId"],
        "keyPackageRef": { "$bytes": STANDARD.encode(key_package_ref) },
    }));
    Value::Array(changes)
}

/// `account_meta` key of the record of this device's own open leaf-recovery request in `cid`
/// ([`own_leaf_recovery_record`]).
pub fn own_leaf_recovery_key(cid: &str) -> String {
    format!("own_leaf_recovery:{cid}")
}

/// This device's `requestLeafRecovery` body: a `recovery_kind` (`add` or `replace`) recovery of
/// exactly the signing device, bound to `prior`, the conversation's current coordinate as mls-ds
/// presents it.
#[allow(clippy::too_many_arguments)]
pub fn leaf_recovery_request_body(
    recovery_request_id: &str,
    actor_did: &str,
    actor_device_id: &str,
    key_id: &str,
    auth_generation: i64,
    prior: &Value,
    recovery_kind: &str,
    signed_at: &str,
) -> Result<Value, MLSError> {
    Ok(json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryRequestBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0",
        "recoveryRequestId": recovery_request_id,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "authGeneration": auth_generation,
        "prior": canonicalize_wire_coordinate(prior, None)?,
        "recoveryKind": recovery_kind,
        "idempotencyKey": recovery_request_id,
        "signedAt": signed_at,
    }))
}

/// What this device records of its own open request from mls-ds's `view` of it (the answer to
/// its `requestLeafRecovery`, or its acceptance's `recovery`): the request ID, the coordinate it
/// is bound to and its expiry in Unix milliseconds. A view of anything but an open request of
/// this exact device in `cid` is refused.
pub fn own_leaf_recovery_record(
    view: &Value,
    cid: &str,
    own_did: &str,
    own_device: &str,
) -> Result<Value, MLSError> {
    let refused = || MLSError::Cryptography("leaf recovery: not this device's open request".into());
    let bound = canonicalize_wire_coordinate(&view["boundCoordinate"], None)?;
    if view["conversationId"] != cid
        || bound["conversationId"] != cid
        || view["requesterDid"] != own_did
        || view["requesterDeviceId"] != own_device
        || view["status"] != "open"
        || !view["recoveryRequestId"].is_string()
    {
        return Err(refused());
    }
    let expires_at_ms = view["expiresAt"]
        .as_str()
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| at.timestamp_millis())
        .ok_or_else(refused)?;
    Ok(json!({
        "recoveryRequestId": view["recoveryRequestId"],
        "boundCoordinate": bound,
        "expiresAtMs": expires_at_ms,
    }))
}

/// Whether the recorded own request `record` is still open at `current` (`cid`'s coordinate as
/// mls-ds now presents it) at `now_ms`: bound to exactly that coordinate and unexpired. Every
/// coordinate-changing transition supersedes an open request (`CHAT_PROTOCOL` §5), so any other
/// record is renewed with a request bound to `current`.
pub fn own_leaf_recovery_open(record: &Value, current: &Value, cid: &str, now_ms: i64) -> bool {
    canonicalize_wire_coordinate(current, Some(cid))
        .is_ok_and(|current| record["boundCoordinate"] == current)
        && record["expiresAtMs"]
            .as_i64()
            .is_some_and(|expires| now_ms < expires)
}

/// The recovery `authorization` permits, as mls-ds presents it in `request` (a
/// `leafRecoveryView`): the open recovery of exactly the authorized request and kind, by exactly
/// its device, key ID and auth generation, in `cid`, with the request, its reservation and
/// mls-ds's `state` coordinate all bound to `coordinate` — the conversation's current coordinate
/// as this device verified it, which must still be the authorization's. Returns the
/// reservation's KeyPackage bytes and reference, which [`require_recovery_key_package`] binds to
/// the requester device.
pub fn authorized_recovery_reservation(
    authorization: &Value,
    request: &Value,
    state: &Value,
    coordinate: &Value,
    cid: &str,
) -> Result<(Vec<u8>, Vec<u8>), MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("leaf recovery: {what}"));
    let reservation = &request["reservation"];
    let current = canonicalize_wire_coordinate(coordinate, Some(cid))?;
    let bound_to_current = |bound: &Value| {
        bound["conversationId"] == cid
            && canonicalize_wire_coordinate(bound, None).is_ok_and(|bound| bound == current)
    };
    if ![
        &authorization["boundCoordinate"],
        &request["boundCoordinate"],
        &reservation["boundCoordinate"],
        state,
    ]
    .into_iter()
    .all(bound_to_current)
    {
        return Err(refused("not bound to the current coordinate"));
    }
    let id = &authorization["recoveryRequestId"];
    let did = &authorization["requesterDid"];
    let device = &authorization["requesterDeviceId"];
    if !id.is_string()
        || !did.is_string()
        || !device.is_string()
        || [request, reservation].into_iter().any(|view| {
            view["recoveryRequestId"] != *id
                || view["conversationId"] != cid
                || view["requesterDid"] != *did
                || view["requesterDeviceId"] != *device
        })
        || !matches!(
            authorization["recoveryKind"].as_str(),
            Some("add" | "replace")
        )
        || request["recoveryKind"] != authorization["recoveryKind"]
        || request["status"] != "open"
        || reservation["requesterKeyId"] != authorization["keyId"]
        || reservation["requesterAuthGeneration"] != authorization["authGeneration"]
    {
        return Err(refused("not the authorized request"));
    }
    Ok((
        json_bytes(&reservation["keyPackage"]["bytes"])?,
        json_bytes(&reservation["keyPackageRef"])?,
    ))
}

/// The validated recovery `key_package` is the authorized requester device's own: its leaf
/// credential is exactly `requesterDid#requesterDeviceId`, its signature key is `pds_key` (that
/// device's PDS-authorized key) under the key ID the authorization's signed body names, and its
/// reference is the reservation's `reserved_ref`.
pub fn require_recovery_key_package<P: OpenMlsProvider>(
    authorization: &Value,
    key_package: &KeyPackage,
    reserved_ref: &[u8],
    pds_key: &[u8],
    provider: &P,
) -> Result<(), MLSError> {
    let identity = format!(
        "{}#{}",
        authorization["requesterDid"].as_str().unwrap_or_default(),
        authorization["requesterDeviceId"]
            .as_str()
            .unwrap_or_default()
    );
    let leaf = key_package.leaf_node();
    let reference = key_package
        .hash_ref(provider.crypto())
        .map_err(|e| MLSError::Cryptography(format!("recovery KeyPackage reference: {e:?}")))?;
    if leaf.credential().serialized_content() != identity.as_bytes()
        || leaf.signature_key().as_slice() != pds_key
        || authorization["keyId"].as_str() != Some(derive_key_id(pds_key).as_str())
        || reference.as_slice() != reserved_ref
    {
        return Err(MLSError::Cryptography(
            "leaf recovery: KeyPackage is not the authorized device's own".into(),
        ));
    }
    Ok(())
}

/// `account_meta` key of `cid`'s verified roster: `{userDid: {role, status}}` as this device
/// verified it (the conversation's creation, a verified reset activation's manifest, or a
/// recovery Welcome's roster attestation from its verified fulfiller) and kept current from every
/// verified entry since ([`apply_roster_effects`]). Without it this device knows no participant's
/// role, and no zero-leaf participant's entitlement, in `cid`.
pub fn conversation_roster_key(cid: &str) -> String {
    format!("conversation_roster:{cid}")
}

/// The verified roster a creation or reset manifest's `participants` state: each row a distinct
/// `userDid` with role `admin` or `member` and status `active` or `pending`. A pending row retains
/// its immutable invitation provenance when present, so a member-authenticated baseline can prove
/// an invitation that predates this device's membership interval.
pub fn roster_from_participants(participants: &Value) -> Result<Value, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("roster: {what}"));
    let rows = participants
        .as_array()
        .filter(|rows| (1..=100).contains(&rows.len()))
        .ok_or_else(|| refused("participants"))?;
    let mut roster = serde_json::Map::new();
    for row in rows {
        let (Some(did), Some(role @ ("admin" | "member")), Some(status @ ("active" | "pending"))) = (
            row["userDid"].as_str(),
            row["role"].as_str(),
            row["status"].as_str(),
        ) else {
            return Err(refused("participant row"));
        };
        let mut verified = json!({ "role": role, "status": status });
        if status == "pending" {
            if let Some(provenance) = canonical_invitation_provenance(row) {
                verified["invitationProvenance"] = provenance;
            }
        }
        if roster.insert(did.to_owned(), verified).is_some() {
            return Err(refused("duplicate participant"));
        }
    }
    Ok(Value::Object(roster))
}

/// The participant effects a verified body of `kind` has on `roster`: a policy transition's or a
/// Commit manifest's `addParticipant` (a pending member), `removeParticipant` and
/// `changeParticipantRole`; an acceptance activates its actor; a zero-leaf leave removes its
/// actor. A reset replaces the roster with its manifest's ([`roster_from_participants`]); every
/// other kind leaves it as it is.
pub fn apply_roster_effects(roster: &mut Value, kind: SignedMutationKind, body: &Value) {
    use SignedMutationKind as K;
    let Some(roster) = roster.as_object_mut() else {
        return;
    };
    let changes = match kind {
        K::PolicyTransition => &body["participantChanges"],
        K::CommitTransition | K::LeaveCommitFulfillment | K::LeafRecoveryFulfillment => {
            &body["manifest"]["participantChanges"]
        }
        K::ParticipantAcceptance => {
            if let Some(did) = body["actorDid"].as_str() {
                if let Some(row) = roster.get_mut(did).filter(|row| row["status"] == "pending") {
                    row["status"] = json!("active");
                    row.as_object_mut()
                        .map(|row| row.remove("invitationProvenance"));
                }
            }
            return;
        }
        K::ZeroLeafLeave => {
            if let Some(did) = body["actorDid"].as_str() {
                roster.remove(did);
            }
            return;
        }
        _ => return,
    };
    for change in changes.as_array().into_iter().flatten() {
        let Some(did) = change["userDid"].as_str() else {
            continue;
        };
        match change["$type"].as_str() {
            Some("blue.catbird.chat.defs#addParticipant") => {
                let mut row = json!({ "role": "member", "status": "pending" });
                if let Some(provenance) = canonical_invitation_provenance(change) {
                    row["invitationProvenance"] = provenance;
                }
                roster.insert(did.to_owned(), row);
            }
            Some("blue.catbird.chat.defs#removeParticipant") => {
                roster.remove(did);
            }
            Some("blue.catbird.chat.defs#changeParticipantRole") => {
                if let (Some(row), Some(role)) = (roster.get_mut(did), change["role"].as_str()) {
                    row["role"] = json!(role);
                }
            }
            _ => {}
        }
    }
}

/// `did` is an active participant of the verified `roster`.
pub fn roster_active(roster: Option<&Value>, did: &str) -> bool {
    roster.is_some_and(|roster| roster[did]["status"] == "active")
}

/// Whether `did` has the exact pending invitation provenance in a verified roster. The
/// provenance is useful only when all three immutable fields are present and canonical.
pub fn roster_has_pending_invitation(
    roster: Option<&Value>,
    did: &str,
    provenance: &Value,
) -> bool {
    let Some(claimed) = canonical_invitation_provenance_value(provenance) else {
        return false;
    };
    roster
        .and_then(|roster| roster.get(did))
        .filter(|row| row["status"] == "pending")
        .and_then(canonical_invitation_provenance)
        .is_some_and(|stored| stored == claimed)
}

fn canonical_invitation_provenance(row: &Value) -> Option<Value> {
    canonical_invitation_provenance_value(row.get("invitationProvenance")?)
}

fn canonical_invitation_provenance_value(provenance: &Value) -> Option<Value> {
    let transition = provenance["invitationTransitionId"].as_str()?;
    let inviter = provenance["invitedByDid"].as_str()?;
    let device = provenance["invitedByDeviceId"].as_str()?;
    (!transition.is_empty() && !inviter.is_empty() && !device.is_empty()).then(|| {
        json!({
            "invitationTransitionId": transition,
            "invitedByDid": inviter,
            "invitedByDeviceId": device,
        })
    })
}

/// `did` is an active admin of `cid` by this device's verified `roster`, the only authority an
/// admin action (a reset activation) is accepted under. Without a verified roster nothing
/// establishes it ([`MLSError::RosterUnverified`]): a participant's signature alone never does.
pub fn require_active_admin(roster: Option<&Value>, did: &str, cid: &str) -> Result<(), MLSError> {
    let roster = roster.ok_or_else(|| MLSError::RosterUnverified {
        conversation_id: cid.to_owned(),
    })?;
    if roster[did]["status"] == "active" && roster[did]["role"] == "admin" {
        return Ok(());
    }
    Err(MLSError::insufficient_permissions(format!(
        "{did} is not an active admin of {cid}"
    )))
}

/// Private-use (`RFC 9420` §17.3) GroupInfo extension type of a recovery Welcome's roster
/// attestation ([`roster_attestation_extension`]).
pub const ROSTER_ATTESTATION_EXTENSION_TYPE: u16 = 0xff01;

/// The roster attestation a fulfiller puts in the GroupInfo of its recovery Welcome: `cid`, the
/// joined `generation`, and the fulfiller's verified roster as of the coordinate it fulfills
/// from. The GroupInfo is signed by the fulfiller's leaf and encrypted to the joiner, so the
/// joiner learns its roster MLS-authenticated by the fulfiller it verifies ([`attested_roster`]).
pub fn roster_attestation_extension(
    cid: &str,
    generation: i64,
    roster: &Value,
) -> Result<Extension, MLSError> {
    let attestation = json!({
        "conversationId": cid,
        "generation": generation,
        "roster": roster,
    });
    Ok(Extension::Unknown(
        ROSTER_ATTESTATION_EXTENSION_TYPE,
        UnknownExtension(serde_json::to_vec(&attestation)?),
    ))
}

/// The roster a recovery Welcome's `attestation` ([`roster_attestation_extension`]) grants this
/// device (`own_did`) joining `cid` at `generation`. The caller has staged the Welcome (so
/// OpenMLS verified the GroupInfo signature) and verified that its sender is the fulfiller whose
/// signed fulfillment it verified. The roster must be well-formed and consistent with the joined
/// group: this account and every DID holding a leaf (`leaf_dids`) are active in it.
pub fn attested_roster(
    attestation: &[u8],
    cid: &str,
    generation: i64,
    own_did: &str,
    leaf_dids: &[String],
) -> Result<Value, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("roster attestation: {what}"));
    let attestation: Value =
        serde_json::from_slice(attestation).map_err(|_| refused("not a roster attestation"))?;
    if attestation["conversationId"] != cid
        || attestation["generation"].as_i64() != Some(generation)
    {
        return Err(refused("not this conversation's generation"));
    }
    let rows = attestation["roster"]
        .as_object()
        .ok_or_else(|| refused("roster"))?
        .iter()
        .map(|(did, row)| {
            let mut participant =
                json!({ "userDid": did, "role": row["role"], "status": row["status"] });
            if let Some(provenance) = row.get("invitationProvenance") {
                participant["invitationProvenance"] = provenance.clone();
            }
            participant
        })
        .collect();
    let roster = roster_from_participants(&Value::Array(rows))?;
    if attestation["roster"] != roster
        || !std::iter::once(own_did)
            .chain(leaf_dids.iter().map(String::as_str))
            .all(|did| roster_active(Some(&roster), did))
    {
        return Err(refused("not consistent with the joined group"));
    }
    Ok(roster)
}

/// The invitation `invitee` holds in a verified `creationBody` or `policyTransitionBody` of
/// `cid`: its one pending row, whose provenance names exactly this transition and its signer.
/// `None` when the body invites no such row.
pub fn invitation_provenance(
    kind: SignedMutationKind,
    body: &Value,
    cid: &str,
    invitee: &str,
) -> Option<Value> {
    let rows = match kind {
        SignedMutationKind::Creation if body["conversationId"].as_str() == Some(cid) => {
            &body["manifest"]["participants"]
        }
        SignedMutationKind::PolicyTransition
            if body["prior"]["conversationId"].as_str() == Some(cid) =>
        {
            &body["participantChanges"]
        }
        _ => return None,
    };
    if body["next"]["conversationId"].as_str() != Some(cid) {
        return None;
    }
    let mut matching = rows
        .as_array()?
        .iter()
        .filter(|row| row["userDid"].as_str() == Some(invitee));
    let row = matching.next()?;
    if matching.next().is_some()
        || row["status"] != "pending"
        || (kind == SignedMutationKind::PolicyTransition
            && row["$type"] != "blue.catbird.chat.defs#addParticipant")
    {
        return None;
    }
    let provenance = &row["invitationProvenance"];
    (provenance["invitationTransitionId"] == body["transitionId"]
        && provenance["invitedByDid"] == body["actorDid"]
        && provenance["invitedByDeviceId"] == body["actorDeviceId"])
        .then(|| provenance.clone())
}

/// The verified `leafRecoveryFulfillmentBody` of `cid` that produced `welcome` for exactly
/// `(did, device)`: its signed bundle carries these Welcome bytes and digest, delivered only to
/// that device, whose `addLeafByRecovery` the Commit makes under the request the bundle names.
/// Returns its canonical `next`: the coordinate the joined group must name.
pub fn fulfillment_welcome_next(
    body: &Value,
    cid: &str,
    welcome: &[u8],
    did: &str,
    device: &str,
) -> Result<Value, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("recovery Welcome: {what}"));
    if body["prior"]["conversationId"].as_str() != Some(cid)
        || body["next"]["conversationId"].as_str() != Some(cid)
    {
        return Err(refused("not this conversation's fulfillment"));
    }
    let request = &body["recoveryRequestId"];
    let manifest = &body["manifest"];
    let bundle = &manifest["welcomeBundle"];
    let deliveries = bundle["deliveries"]
        .as_array()
        .ok_or_else(|| refused("deliveries"))?;
    let adds_device = manifest["leafChanges"]
        .as_array()
        .ok_or_else(|| refused("leafChanges"))?
        .iter()
        .any(|change| {
            change["$type"] == "blue.catbird.chat.defs#addLeafByRecovery"
                && change["userDid"] == did
                && change["deviceId"] == device
                && change["recoveryRequestId"] == *request
        });
    if !request.is_string()
        || manifest["leafRecoveryRequestId"] != *request
        || !adds_device
        || deliveries.len() != 1
        || deliveries[0]["recipientDid"] != did
        || deliveries[0]["recipientDeviceId"] != device
        || deliveries[0]["provenance"]["recoveryRequestId"] != *request
        || json_bytes(&bundle["opaqueWelcome"])? != welcome
        || json_bytes(&bundle["sha256"])? != Sha256::digest(welcome)[..]
    {
        return Err(refused("not this device's Welcome"));
    }
    canonicalize_wire_coordinate(&body["next"], None)
}

/// A canonical coordinate names exactly `group`'s MLS state: group ID, epoch, GroupContext hash
/// and confirmation tag. Generation and `stateVersion` have no MLS counterpart.
pub fn require_coordinate_names_group<P: OpenMlsProvider>(
    coordinate: &Value,
    group: &MlsGroup,
    provider: &P,
) -> Result<(), MLSError> {
    let (gch, tag) = compute_group_context_hash_and_tag(group, provider)?;
    if json_bytes(&coordinate["groupId"])? != group.group_id().as_slice()
        || coordinate["epoch"].as_u64() != Some(group.epoch().as_u64())
        || json_bytes(&coordinate["groupContextHash"])? != gch
        || json_bytes(&coordinate["confirmationTag"])? != tag
    {
        return Err(MLSError::Cryptography(
            "coordinate does not name the local MLS state".into(),
        ));
    }
    Ok(())
}

/// The key of `(did, device)`'s current leaf in `group` when that is the device's authorized
/// key: PDS authorization alone grants no conversation authority, and a leaf whose key the PDS
/// does not authorize grants none either.
pub fn authorized_leaf_key(
    group: &MlsGroup,
    did: &str,
    device: &str,
    authorized_by_did: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Result<Vec<u8>, MLSError> {
    group
        .members()
        .find(|member| {
            parse_scoped_credential_did_device(member.credential.serialized_content())
                .is_ok_and(|(leaf_did, leaf_device)| leaf_did == did && leaf_device == device)
        })
        .map(|member| member.signature_key)
        .filter(|key| authorized_device_key(did, device, authorized_by_did) == Some(key.as_slice()))
        .ok_or_else(|| {
            MLSError::Cryptography(
                "I4: control entry signer is not an authorized current leaf".into(),
            )
        })
}

/// The PDS-authorized signing key of exactly `(did, device)`.
pub fn authorized_device_key<'a>(
    did: &str,
    device: &str,
    authorized_by_did: &'a BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Option<&'a [u8]> {
    authorized_by_did
        .get(did)?
        .iter()
        .find(|(authorized, _)| authorized == device)
        .map(|(_, key)| key.as_slice())
}

/// Inner deletion record transcript retained by the server's v2 authority signature.
const ACCOUNT_DELETION_DOMAIN: &[u8] = b"catbird-mls-account-deletion-v1\0";
/// Signature domain that binds the exact retained receipt verification method to the deletion.
const ACCOUNT_DELETION_AUTHORITY_DOMAIN: &[u8] = b"catbird-mls-account-deletion-authority-v2\0";

fn append_account_deletion_text(bytes: &mut Vec<u8>, text: &str) -> Option<()> {
    bytes.extend_from_slice(&u32::try_from(text.len()).ok()?.to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
    Some(())
}

/// Server transcript: v2 domain, key ID, then the complete v1 deletion record transcript.
fn account_deletion_authority_signing_bytes(key_id: &str, fields: &[&str]) -> Option<Vec<u8>> {
    let fields_len = fields.iter().try_fold(0usize, |len, field| {
        len.checked_add(4)?.checked_add(field.len())
    })?;
    let capacity = ACCOUNT_DELETION_AUTHORITY_DOMAIN
        .len()
        .checked_add(4)?
        .checked_add(key_id.len())?
        .checked_add(ACCOUNT_DELETION_DOMAIN.len())?
        .checked_add(fields_len)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(ACCOUNT_DELETION_AUTHORITY_DOMAIN);
    append_account_deletion_text(&mut bytes, key_id)?;
    bytes.extend_from_slice(ACCOUNT_DELETION_DOMAIN);
    for field in fields {
        append_account_deletion_text(&mut bytes, field)?;
    }
    Some(bytes)
}

fn account_deletion_signature_valid(
    public_key: &[u8],
    signature: &[u8],
    key_id: &str,
    fields: &[&str],
) -> bool {
    let Some(message) = account_deletion_authority_signing_bytes(key_id, fields) else {
        return false;
    };
    p256::ecdsa::Signature::from_slice(signature)
        .ok()
        .filter(|signature| signature.normalize_s().is_none())
        .zip(p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).ok())
        .is_some_and(|(signature, key)| {
            use p256::ecdsa::signature::Verifier as _;
            key.verify(&message, &signature).is_ok()
        })
}

/// `labyrinth_state` key: `cid` sequenced `did`'s account deletion; the value is its seq.
pub fn account_deletion_key(cid: &str, did: &str) -> String {
    format!("native.account_deleted:{cid}:{did}")
}

fn non_empty_text(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty())
}

/// The exact versioned receipt method (`sequencerAuthority.keyId`) of an `accountDeletedEntry`
/// bound to `cid` and the conversation's pinned `sequencer_did`. `None` for any other entry: it
/// never has an effect.
pub fn account_deleted_entry_key_id<'a>(
    cid: &str,
    sequencer_did: &str,
    entry: &'a Value,
) -> Option<&'a str> {
    let sequencer = sequencer_did.split('#').next().unwrap_or(sequencer_did);
    let authority = &entry["sequencerAuthority"];
    entry["seq"].as_i64().filter(|seq| *seq > 0)?;
    let key_id = non_empty_text(&authority["keyId"])?;
    labyrinth_protocol::receipt::receipt_key_generation(sequencer, key_id).ok()?;
    non_empty_text(&entry["deletedDid"])?;
    non_empty_text(&entry["entryId"])?;
    non_empty_text(&entry["receivedAt"])?;
    (entry
        .get("$type")
        .is_none_or(|t| t == crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND)
        && non_empty_text(&entry["conversationId"]) == Some(cid)
        && non_empty_text(&entry["sequencerDid"]) == Some(sequencer)
        && non_empty_text(&authority["sequencerDid"]) == Some(sequencer))
    .then_some(key_id)
}

/// Verify the low-S ES256 v2 `sequencerAuthority` of an `accountDeletedEntry` under the key of
/// the method [`account_deleted_entry_key_id`] named. Returns the deleted DID and seq.
pub fn verify_account_deleted_entry_signature(
    cid: &str,
    sequencer_did: &str,
    entry: &Value,
    authority_key_sec1: &[u8],
) -> Option<(String, i64)> {
    let sequencer = sequencer_did.split('#').next().unwrap_or(sequencer_did);
    let key_id = account_deleted_entry_key_id(cid, sequencer_did, entry)?;
    let seq = entry["seq"].as_i64()?;
    let deleted_did = non_empty_text(&entry["deletedDid"])?;
    let seq_text = seq.to_string();
    let fields = [
        sequencer,
        cid,
        deleted_did,
        seq_text.as_str(),
        non_empty_text(&entry["entryId"])?,
        non_empty_text(&entry["receivedAt"])?,
    ];
    let signature = json_bytes(&entry["sequencerAuthority"]["signature"]).ok()?;
    account_deletion_signature_valid(authority_key_sec1, &signature, key_id, &fields)
        .then(|| (deleted_did.to_owned(), seq))
}

/// Format current UTC wall-clock time as canonical RFC 3339 milliseconds (`YYYY-MM-DDTHH:MM:SS.sssZ`).
pub fn now_rfc3339_millis() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Format a Unix timestamp in seconds as canonical RFC 3339 milliseconds.
pub fn unix_secs_rfc3339_millis(seconds: u64) -> Result<String, MLSError> {
    let secs_i64 =
        i64::try_from(seconds).map_err(|_| MLSError::invalid_input("timestamp overflow"))?;
    chrono::DateTime::from_timestamp(secs_i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(|| MLSError::invalid_input("invalid unix timestamp"))
}

/// Encode a single component with `application/x-www-form-urlencoded` rules matching
/// `url::form_urlencoded::Serializer` (`mls-ds/server/src/chat_protocol/read_auth.rs`).
pub fn urlencode_form_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((byte & 0x0f) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Build a canonical sorted query string matching `mls-ds` `canonical_query`.
pub fn canonical_query_string(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<(&str, &str)> = pairs.to_vec();
    sorted.sort();
    let mut out = String::new();
    for (idx, (k, v)) in sorted.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&urlencode_form_component(k));
        out.push('=');
        out.push_str(&urlencode_form_component(v));
    }
    out
}

#[derive(Serialize)]
struct ReadClaimPayload<'a> {
    v: u8,
    nsid: &'a str,
    query: &'a str,
    did: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    #[serde(rename = "issuedAt")]
    issued_at: i64,
}

/// Sign `catbird-chat-read` + `catbird-chat-read-signature` headers (`M-F07`) for a GET query.
pub fn build_chat_read_headers(
    nsid: &str,
    canonical_query: &str,
    actor_did: &str,
    device_id: &str,
    signer: &SignatureKeyPair,
    now_ms: i64,
) -> Result<Vec<PlatformHttpHeader>, MLSError> {
    let claim = ReadClaimPayload {
        v: 1,
        nsid,
        query: canonical_query,
        did: actor_did,
        device_id,
        issued_at: now_ms,
    };
    let claim_bytes = serde_json::to_vec(&claim)
        .map_err(|e| MLSError::Internal(format!("serialize ReadClaim: {e}")))?;
    let mut transcript = Vec::with_capacity(CHAT_READ_DOMAIN.len() + claim_bytes.len());
    transcript.extend_from_slice(CHAT_READ_DOMAIN);
    transcript.extend_from_slice(&claim_bytes);
    let sig = signer
        .sign(&transcript)
        .map_err(|e| MLSError::Cryptography(format!("sign ReadClaim failed: {e:?}")))?;
    Ok(vec![
        PlatformHttpHeader {
            name: CHAT_READ_HEADER.to_string(),
            value: URL_SAFE_NO_PAD.encode(&claim_bytes),
        },
        PlatformHttpHeader {
            name: CHAT_READ_SIG_HEADER.to_string(),
            value: URL_SAFE_NO_PAD.encode(&sig),
        },
    ])
}

#[derive(Serialize)]
struct AckTranscriptPayload<'a> {
    #[serde(rename = "keyId")]
    key_id: &'a str,
    #[serde(rename = "upToSeq")]
    up_to_seq: i64,
    #[serde(rename = "signedAt")]
    signed_at: &'a str,
    generation: i64,
    #[serde(rename = "actorDeviceId")]
    actor_device_id: &'a str,
    #[serde(rename = "authGeneration")]
    auth_generation: i64,
    #[serde(rename = "conversationId")]
    conversation_id: &'a str,
}

/// Build a signed `POST /xrpc/blue.catbird.chat.acknowledgeEntries` JSON body (`I14`).
pub fn build_acknowledge_entries_request(
    conversation_id: &str,
    generation: i64,
    actor_device_id: &str,
    auth_generation: i64,
    up_to_seq: i64,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, MLSError> {
    let signed_at = now_rfc3339_millis();
    build_acknowledge_entries_request_at(
        conversation_id,
        generation,
        actor_device_id,
        auth_generation,
        up_to_seq,
        signer,
        &signed_at,
    )
}

/// Build a signed `POST /xrpc/blue.catbird.chat.acknowledgeEntries` JSON body (`I14`)
/// using a caller-supplied RFC 3339 millisecond timestamp (`signed_at`).
pub fn build_acknowledge_entries_request_at(
    conversation_id: &str,
    generation: i64,
    actor_device_id: &str,
    auth_generation: i64,
    up_to_seq: i64,
    signer: &SignatureKeyPair,
    signed_at: &str,
) -> Result<Vec<u8>, MLSError> {
    let key_id = derive_key_id(signer.public());
    let payload = AckTranscriptPayload {
        key_id: &key_id,
        up_to_seq,
        signed_at,
        generation,
        actor_device_id,
        auth_generation,
        conversation_id,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload)
        .map_err(|e| MLSError::Internal(format!("encode AckTranscriptPayload CBOR: {e}")))?;
    let mut transcript = Vec::with_capacity(ACK_ENTRIES_DOMAIN.len() + cbor.len());
    transcript.extend_from_slice(ACK_ENTRIES_DOMAIN);
    transcript.extend_from_slice(&cbor);
    let sig = signer
        .sign(&transcript)
        .map_err(|e| MLSError::Cryptography(format!("sign acknowledgeEntries failed: {e:?}")))?;
    serde_json::to_vec(&json!({
        "conversationId": conversation_id,
        "generation": generation,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "authGeneration": auth_generation,
        "upToSeq": up_to_seq,
        "signedAt": signed_at,
        "signature": { "$bytes": STANDARD.encode(&sig) }
    }))
    .map_err(|e| MLSError::Internal(format!("serialize acknowledgeEntries JSON: {e}")))
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.device/{device_id}` (`ADR-009`, `I4`).
pub fn build_pds_device_put_record_body(
    repo_did: &str,
    device_id: &str,
    mls_signature_public_key: &[u8],
) -> Result<Vec<u8>, MLSError> {
    let created_at = now_rfc3339_millis();
    build_pds_device_put_record_body_at(repo_did, device_id, mls_signature_public_key, &created_at)
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.device/{device_id}`
/// using a caller-supplied RFC 3339 millisecond timestamp (`created_at`).
pub fn build_pds_device_put_record_body_at(
    repo_did: &str,
    device_id: &str,
    mls_signature_public_key: &[u8],
    created_at: &str,
) -> Result<Vec<u8>, MLSError> {
    serde_json::to_vec(&json!({
        "repo": repo_did,
        "collection": "blue.catbird.chat.device",
        "rkey": device_id,
        "record": {
            "$type": "blue.catbird.chat.device",
            "mlsSignaturePublicKey": { "$bytes": STANDARD.encode(mls_signature_public_key) },
            "algorithm": "ed25519",
            "createdAt": created_at,
        }
    }))
    .map_err(|e| MLSError::Internal(format!("serialize blue.catbird.chat.device putRecord: {e}")))
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.declaration/self`.
pub fn build_pds_chat_declaration_put_record_body(
    repo_did: &str,
    delivery_service_did: &str,
) -> Result<Vec<u8>, MLSError> {
    let created_at = now_rfc3339_millis();
    build_pds_chat_declaration_put_record_body_at(repo_did, delivery_service_did, &created_at)
}

/// Build `com.atproto.repo.putRecord` JSON body for `blue.catbird.chat.declaration/self`
/// using a caller-supplied RFC 3339 millisecond timestamp (`created_at`).
pub fn build_pds_chat_declaration_put_record_body_at(
    repo_did: &str,
    delivery_service_did: &str,
    created_at: &str,
) -> Result<Vec<u8>, MLSError> {
    serde_json::to_vec(&json!({
        "repo": repo_did,
        "collection": "blue.catbird.chat.declaration",
        "rkey": "self",
        "record": {
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": delivery_service_did,
            "protocolVersion": "2",
            "createdAt": created_at,
        }
    }))
    .map_err(|e| {
        MLSError::Internal(format!(
            "serialize blue.catbird.chat.declaration putRecord: {e}"
        ))
    })
}

/// Parse a single `com.atproto.repo.listRecords` JSON page into `(records, optional_cursor)`.
pub fn parse_pds_list_records_page(
    did: &str,
    collection: &str,
    body_bytes: &[u8],
) -> Result<(Vec<Value>, Option<String>), MLSError> {
    let val: Value = serde_json::from_slice(body_bytes).map_err(|e| {
        MLSError::Internal(format!(
            "invalid listRecords({collection}) JSON for `{did}`: {e}"
        ))
    })?;
    let records = val
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            MLSError::insufficient_permissions(format!(
                "I4: PDS listRecords({did}, {collection}) has no records array"
            ))
        })?
        .clone();
    let cursor = val
        .get("cursor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok((records, cursor))
}

/// Extract valid `(device_id, pubkey_32, raw_entry)` tuples from `listRecords` entries for `blue.catbird.chat.device`.
pub fn parse_pds_device_entries(did: &str, records: &[Value]) -> Vec<(String, Vec<u8>, Value)> {
    let expected_prefix = format!("at://{did}/blue.catbird.chat.device/");
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let Some(uri) = rec.get("uri").and_then(Value::as_str) else {
            continue;
        };
        let rkey = if let Some(rest) = uri.strip_prefix(&expected_prefix) {
            rest.trim()
        } else {
            uri.rsplit('/').next().unwrap_or("").trim()
        };
        if rkey.is_empty() || rkey.contains('/') {
            continue;
        }
        let Some(value) = rec.get("value").and_then(Value::as_object) else {
            continue;
        };
        let Some(alg) = value.get("algorithm").and_then(Value::as_str) else {
            continue;
        };
        if !alg.eq_ignore_ascii_case("ed25519") {
            continue;
        }
        let Some(pk_val) = value.get("mlsSignaturePublicKey") else {
            continue;
        };
        let Ok(pk_bytes) = json_bytes(pk_val) else {
            continue;
        };
        if pk_bytes.len() != 32 {
            continue;
        }
        out.push((rkey.to_string(), pk_bytes, rec.clone()));
    }
    out
}

/// Check whether an existing `blue.catbird.chat.device` record value matches `expected_pubkey` under Ed25519.
pub fn pds_device_record_matches(record_val: &Value, expected_pubkey: &[u8]) -> bool {
    let Some(obj) = record_val.as_object() else {
        return false;
    };
    let Some(alg) = obj.get("algorithm").and_then(Value::as_str) else {
        return false;
    };
    if !alg.eq_ignore_ascii_case("ed25519") {
        return false;
    }
    let Some(pk_val) = obj.get("mlsSignaturePublicKey") else {
        return false;
    };
    json_bytes(pk_val).is_ok_and(|pk| pk.as_slice() == expected_pubkey)
}

/// Check whether an existing `blue.catbird.chat.declaration` record value declares `expected_ds_did`.
pub fn pds_chat_declaration_matches(record_val: &Value, expected_ds_did: &str) -> bool {
    if record_val.get("$type").and_then(Value::as_str) != Some("blue.catbird.chat.declaration")
        || !matches!(
            record_val.get("allowIncoming").and_then(Value::as_str),
            Some("all" | "none" | "following")
        )
        || !matches!(
            record_val.get("protocolVersion").and_then(Value::as_str),
            Some("1" | "2")
        )
        || !record_val
            .get("createdAt")
            .and_then(Value::as_str)
            .is_some_and(|at| chrono::DateTime::parse_from_rfc3339(at).is_ok())
    {
        return false;
    }
    record_val
        .get("deliveryService")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|ds| ds == expected_ds_did.trim())
}

#[derive(Serialize)]
struct PdsDeviceRevocationTranscriptPayload<'a> {
    // Ordered strictly by DAG-CBOR map key `(byte_len, utf8_bytes)`:
    // "repoDid" (7), "createdAt" (9), "actorDeviceId" (13), "targetDeviceId" (14).
    #[serde(rename = "repoDid")]
    repo_did: &'a str,
    #[serde(rename = "createdAt")]
    created_at: &'a str,
    #[serde(rename = "actorDeviceId")]
    actor_device_id: &'a str,
    #[serde(rename = "targetDeviceId")]
    target_device_id: &'a str,
}

/// Build the canonical signing bytes `CATBIRD-CHAT-PDS-DEVICE-REVOCATION-V1\0 || dag_cbor(...)`
/// for an append-only `blue.catbird.chat.deviceRevocation` record.
pub fn pds_device_revocation_signing_bytes(
    repo_did: &str,
    actor_device_id: &str,
    target_device_id: &str,
    created_at: &str,
) -> Result<Vec<u8>, MLSError> {
    let payload = PdsDeviceRevocationTranscriptPayload {
        repo_did,
        created_at,
        actor_device_id,
        target_device_id,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload).map_err(|e| {
        MLSError::Internal(format!(
            "encode PdsDeviceRevocationTranscriptPayload CBOR: {e}"
        ))
    })?;
    #[cfg(feature = "labyrinth")]
    crate::labyrinth::repo_proof::verify_canonical_dagcbor(&cbor)
        .map_err(|e| MLSError::Internal(format!("non-canonical deviceRevocation DAG-CBOR: {e}")))?;
    let mut transcript = Vec::with_capacity(PDS_DEVICE_REVOCATION_DOMAIN.len() + cbor.len());
    transcript.extend_from_slice(PDS_DEVICE_REVOCATION_DOMAIN);
    transcript.extend_from_slice(&cbor);
    Ok(transcript)
}

/// Build `com.atproto.repo.createRecord` JSON body for `blue.catbird.chat.deviceRevocation/{target_device_id}`.
pub fn build_pds_device_revocation_create_record_body_at(
    repo_did: &str,
    actor_device_id: &str,
    target_device_id: &str,
    created_at: &str,
    signer: &SignatureKeyPair,
    reason: Option<&str>,
) -> Result<Vec<u8>, MLSError> {
    let transcript = pds_device_revocation_signing_bytes(
        repo_did,
        actor_device_id,
        target_device_id,
        created_at,
    )?;
    let sig = signer.sign(&transcript).map_err(|e| {
        MLSError::Cryptography(format!("sign blue.catbird.chat.deviceRevocation: {e:?}"))
    })?;
    let mut record = json!({
        "$type": "blue.catbird.chat.deviceRevocation",
        "targetDeviceId": target_device_id,
        "actorDeviceId": actor_device_id,
        "signerPublicKey": { "$bytes": STANDARD.encode(signer.public()) },
        "signature": { "$bytes": STANDARD.encode(&sig) },
        "algorithm": "ed25519",
        "createdAt": created_at,
    });
    if let Some(reason_str) = reason {
        record["reason"] = json!(reason_str);
    }
    serde_json::to_vec(&json!({
        "repo": repo_did,
        "collection": "blue.catbird.chat.deviceRevocation",
        "rkey": target_device_id,
        "record": record,
    }))
    .map_err(|e| {
        MLSError::Internal(format!(
            "serialize blue.catbird.chat.deviceRevocation createRecord: {e}"
        ))
    })
}

/// Verify an append-only `blue.catbird.chat.deviceRevocation/{rkey}` record against the account's
/// enrolled `blue.catbird.chat.device` Ed25519 public keys (`enrolled_devices`).
pub fn verify_pds_device_revocation_record(
    repo_did: &str,
    rkey: &str,
    record_val: &Value,
    enrolled_devices: &BTreeMap<String, Vec<u8>>,
) -> Result<String, MLSError> {
    let target_device_id = record_val
        .get("targetDeviceId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MLSError::Cryptography("deviceRevocation missing targetDeviceId".to_string())
        })?;
    if target_device_id != rkey.trim() {
        return Err(MLSError::Cryptography(format!(
            "deviceRevocation targetDeviceId `{target_device_id}` does not match rkey `{rkey}`"
        )));
    }
    let actor_device_id = record_val
        .get("actorDeviceId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MLSError::Cryptography("deviceRevocation missing actorDeviceId".to_string())
        })?;
    if let Some(alg) = record_val.get("algorithm").and_then(Value::as_str) {
        if !alg.eq_ignore_ascii_case("ed25519") {
            return Err(MLSError::Cryptography(format!(
                "unsupported deviceRevocation algorithm `{alg}`"
            )));
        }
    }
    let created_at = record_val
        .get("createdAt")
        .and_then(Value::as_str)
        .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
        .ok_or_else(|| {
            MLSError::Cryptography("deviceRevocation invalid RFC3339 createdAt".to_string())
        })?;
    let enrolled_pk = enrolled_devices.get(actor_device_id).ok_or_else(|| {
        MLSError::Cryptography(format!(
            "deviceRevocation signer `{actor_device_id}` is not an enrolled chat.device for `{repo_did}`"
        ))
    })?;
    let signer_pk = json_bytes(record_val.get("signerPublicKey").ok_or_else(|| {
        MLSError::Cryptography("deviceRevocation missing signerPublicKey".into())
    })?)?;
    if signer_pk.len() != 32 || signer_pk.as_slice() != enrolled_pk.as_slice() {
        return Err(MLSError::Cryptography(
            "deviceRevocation signerPublicKey does not match enrolled actorDeviceId key".into(),
        ));
    }
    let sig_vec = json_bytes(
        record_val
            .get("signature")
            .ok_or_else(|| MLSError::Cryptography("deviceRevocation missing signature".into()))?,
    )?;
    let sig_64: [u8; 64] = sig_vec.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("deviceRevocation Ed25519 signature must be 64 bytes".into())
    })?;
    let pk_32: [u8; 32] = signer_pk.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("deviceRevocation Ed25519 public key must be 32 bytes".into())
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_32).map_err(|e| {
        MLSError::Cryptography(format!("deviceRevocation invalid Ed25519 key: {e}"))
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_64);
    let transcript = pds_device_revocation_signing_bytes(
        repo_did,
        actor_device_id,
        target_device_id,
        created_at,
    )?;
    vk.verify_strict(&transcript, &sig).map_err(|e| {
        MLSError::Cryptography(format!("deviceRevocation signature verify failed: {e}"))
    })?;
    Ok(target_device_id.to_owned())
}

/// Parse `com.atproto.repo.listRecords?collection=blue.catbird.chat.device` into `(device_id, pubkey_32)`.
pub fn parse_pds_device_list_records(
    did: &str,
    body_bytes: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, MLSError> {
    let (records, _) = parse_pds_list_records_page(did, "blue.catbird.chat.device", body_bytes)?;
    Ok(parse_pds_device_entries(did, &records)
        .into_iter()
        .map(|(id, pk, _)| (id, pk))
        .collect())
}

/// Unwrap either `{ "didDoc": { ... } }` (`com.atproto.identity.resolveDid`) or a direct DID document.
pub fn extract_did_doc_from_resolve_response(body_bytes: &[u8]) -> Result<Vec<u8>, MLSError> {
    let val: Value = serde_json::from_slice(body_bytes)
        .map_err(|e| MLSError::Internal(format!("invalid DID document JSON: {e}")))?;
    if let Some(doc) = val.get("didDoc") {
        if doc.is_object() {
            return serde_json::to_vec(doc)
                .map_err(|e| MLSError::Internal(format!("re-serialize didDoc: {e}")));
        }
    }
    if val.get("id").and_then(|v| v.as_str()).is_some() {
        return Ok(body_bytes.to_vec());
    }
    Err(MLSError::Internal(
        "response did not contain a valid DID document".to_string(),
    ))
}

/// Extract the `#atproto_pds` service endpoint from `did`'s DID document.
/// `None` unless the document's `id` is exactly `did` (a resolver must not
/// answer for another identity) and the endpoint is an `https://` URL.
pub fn extract_pds_endpoint_from_did_doc(did_doc_bytes: &[u8], did: &str) -> Option<String> {
    let val: Value = serde_json::from_slice(did_doc_bytes).ok()?;
    if val.get("id").and_then(|v| v.as_str()) != Some(did) {
        return None;
    }
    let services = val.get("service")?.as_array()?;
    for svc in services {
        let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let ty = svc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if id.ends_with("#atproto_pds") || ty == "AtprotoPersonalDataServer" {
            if let Some(ep) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                let trimmed = ep.trim_end_matches('/').to_string();
                let host = trimmed.strip_prefix("https://").unwrap_or("");
                if !host.is_empty() && !host.starts_with('/') {
                    return Some(trimmed);
                }
            }
        }
    }
    None
}

/// Derive a fallback `did:web:...` identifier from an HTTP(S) base URL when `/.well-known/did.json`
/// is not served (e.g. unit-test mock endpoints).
pub fn fallback_did_web_from_endpoint(endpoint: &str) -> String {
    let without_scheme = endpoint
        .trim()
        .strip_prefix("https://")
        .or_else(|| endpoint.trim().strip_prefix("http://"))
        .unwrap_or(endpoint.trim());
    let authority = without_scheme.split('/').next().unwrap_or("localhost");
    let encoded = authority.replace(':', "%3A");
    format!("did:web:{encoded}")
}

/// Decode a compressed P-256 SEC1 public key (`33` bytes) from a DID document's `verificationMethod`
/// matching `fragment_or_kid` (e.g. `#mls-receipt-1` or `{did}#mls-receipt-1`).
pub fn decode_p256_sec1_from_did_doc(
    did_doc_bytes: &[u8],
    expected_did: &str,
    fragment_or_kid: &str,
) -> Result<Vec<u8>, MLSError> {
    let doc: Value = serde_json::from_slice(did_doc_bytes)
        .map_err(|e| MLSError::Cryptography(format!("invalid DID document JSON: {e}")))?;
    if doc.get("id").and_then(|v| v.as_str()) != Some(expected_did) {
        return Err(MLSError::Cryptography(format!(
            "DID document id {:?} does not match expected `{expected_did}`",
            doc.get("id")
        )));
    }
    let fragment = if let Some((_, frag)) = fragment_or_kid.split_once('#') {
        format!("#{frag}")
    } else if fragment_or_kid.starts_with('#') {
        fragment_or_kid.to_string()
    } else {
        format!("#{fragment_or_kid}")
    };
    let full_id = format!("{expected_did}{fragment}");
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MLSError::Cryptography("DID document missing verificationMethod".into()))?;
    for method in methods {
        let id = method.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id != full_id && id != fragment {
            continue;
        }
        if let Some(multibase_str) = method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            let (_, raw) = multibase::decode(multibase_str).map_err(|e| {
                MLSError::Cryptography(format!("invalid publicKeyMultibase on `{id}`: {e}"))
            })?;
            // P-256 compressed multicodec prefix is `[0x80, 0x24]` + 33-byte SEC1 point.
            if raw.len() == 35 && raw[0] == 0x80 && raw[1] == 0x24 {
                return Ok(raw[2..].to_vec());
            }
            if raw.len() == 33 || raw.len() == 65 {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let pk = p256::PublicKey::from_sec1_bytes(&raw).map_err(|e| {
                    MLSError::Cryptography(format!("invalid P-256 SEC1 point on `{id}`: {e}"))
                })?;
                return Ok(pk.to_encoded_point(true).as_bytes().to_vec());
            }
            return Err(MLSError::Cryptography(format!(
                "unexpected multicodec key length {} on `{id}`",
                raw.len()
            )));
        }
        if let Some(jwk) = method.get("publicKeyJwk") {
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "EC" || crv != "P-256" {
                return Err(MLSError::Cryptography(format!(
                    "unsupported publicKeyJwk ({kty}/{crv}) on `{id}`"
                )));
            }
            let x_b64 = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::Cryptography(format!("JWK `{id}` missing x")))?;
            let y_b64 = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MLSError::Cryptography(format!("JWK `{id}` missing y")))?;
            let x = URL_SAFE_NO_PAD
                .decode(x_b64)
                .map_err(|e| MLSError::Cryptography(format!("JWK `{id}` invalid x: {e}")))?;
            let y = URL_SAFE_NO_PAD
                .decode(y_b64)
                .map_err(|e| MLSError::Cryptography(format!("JWK `{id}` invalid y: {e}")))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(MLSError::Cryptography(format!(
                    "JWK `{id}` P-256 x/y coordinates must be 32 bytes"
                )));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let pk = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| {
                MLSError::Cryptography(format!("JWK `{id}` invalid P-256 curve point: {e}"))
            })?;
            return Ok(pk.to_encoded_point(true).as_bytes().to_vec());
        }
        return Err(MLSError::Cryptography(format!(
            "verificationMethod `{id}` missing publicKeyMultibase and publicKeyJwk"
        )));
    }
    Err(MLSError::Cryptography(format!(
        "DID document for `{expected_did}` missing verificationMethod `{full_id}`"
    )))
}

/// Verify an `I13` ES256 `sequencerReceipt` wire JSON object under `sec1_pubkey`, the retained
/// method its exact `kid` names ([`sequencer_receipt_kid`]), and return
/// `(seq, generation, archived_receipt_json)` ready for `labyrinth::message::seal_sender_committed`.
#[allow(clippy::too_many_arguments)]
pub fn parse_and_verify_i13_sequencer_receipt(
    receipt_val: &Value,
    sec1_pubkey: &[u8],
    expected_sequencer_did: &str,
    expected_convo_id: &str,
    expected_group_id: &[u8],
    expected_epoch: u64,
    expected_entry_id: &str,
    expected_message_id: &str,
    expected_commitment: &[u8; 32],
    original_sender_attestation: Option<
        &crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope,
    >,
) -> Result<(u64, u64, String), MLSError> {
    let conversation_id = receipt_val
        .get("conversationId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing conversationId".into()))?
        .to_string();
    let generation = receipt_val
        .get("generation")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let group_id = json_bytes(
        receipt_val
            .get("groupId")
            .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing groupId".into()))?,
    )?;
    let epoch = receipt_val
        .get("epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing epoch".into()))?;
    let entry_id = receipt_val
        .get("entryId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing entryId".into()))?
        .to_string();
    let seq = receipt_val
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing seq".into()))?;
    let sender_did = receipt_val
        .get("senderDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDid".into()))?;
    let sender_device_id = receipt_val
        .get("senderDeviceId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDeviceId".into()))?;
    let commitment_vec = json_bytes(receipt_val.get("archiveCommitment").ok_or_else(|| {
        MLSError::Cryptography("sequencerReceipt missing archiveCommitment".into())
    })?)?;
    let archive_commitment: [u8; 32] = commitment_vec.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("sequencerReceipt archiveCommitment must be 32 bytes".into())
    })?;
    let issued_at_ms = receipt_val
        .get("issuedAtMs")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing issuedAtMs".into()))?;
    let sequencer_did = receipt_val
        .get("sequencerDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing sequencerDid".into()))?
        .to_string();
    let key_id = receipt_val
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing kid".into()))?
        .to_string();
    let sig_vec = json_bytes(
        receipt_val
            .get("signature")
            .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing signature".into()))?,
    )?;
    let signature: [u8; 64] = sig_vec.as_slice().try_into().map_err(|_| {
        MLSError::Cryptography("sequencerReceipt ES256 signature must be 64 bytes".into())
    })?;

    if conversation_id != expected_convo_id
        || group_id.as_slice() != expected_group_id
        || epoch != expected_epoch
        || entry_id != expected_entry_id
        || !bool::from(archive_commitment.ct_eq(expected_commitment))
    {
        return Err(MLSError::Cryptography(
            "I13 sequencerReceipt coordinates or archiveCommitment mismatch".to_string(),
        ));
    }
    if let Some(original_sender_attestation) = original_sender_attestation {
        if original_sender_attestation.sender_did != sender_did
            || original_sender_attestation.sender_device_id != sender_device_id
        {
            return Err(MLSError::Cryptography(
                "sequencer receipt sender differs from original sender attestation".into(),
            ));
        }
        original_sender_attestation.verify(
            expected_convo_id,
            expected_message_id,
            expected_commitment,
        )?;
    }

    let signed = labyrinth_protocol::receipt::SignedSequencerReceipt {
        payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did,
            conversation_id,
            group_id,
            epoch,
            sender_device_did_url: format!("{sender_did}#{sender_device_id}"),
            entry_id,
            archive_commitment,
            seq,
            issued_at_ms,
        },
        key_id,
        signature,
    };

    if !crate::planted::is_planted_bug_active(
        crate::planted::PlantedBug::P7SkipSequencerReceiptSignatureCheck,
    ) {
        labyrinth_protocol::receipt::verify_sequencer_receipt_sec1(
            sec1_pubkey,
            expected_sequencer_did,
            &signed,
        )
        .map_err(|e| MLSError::Cryptography(format!("I13 sequencerReceipt verify failed: {e}")))?;
    }

    let stored = StoredArchivedReceipt {
        sequencer_did: signed.payload.sequencer_did,
        conversation_id: signed.payload.conversation_id,
        group_id: signed.payload.group_id,
        epoch: signed.payload.epoch,
        sender_device_did_url: signed.payload.sender_device_did_url,
        entry_id: signed.payload.entry_id,
        archive_commitment: signed.payload.archive_commitment.to_vec(),
        seq: signed.payload.seq,
        issued_at_ms: signed.payload.issued_at_ms,
        key_id: signed.key_id,
        signature: signed.signature.to_vec(),
        generation,
        original_sender_attestation: original_sender_attestation.cloned(),
    };
    let archived_json = serde_json::to_string(&stored)
        .map_err(|e| MLSError::Internal(format!("serialize StoredArchivedReceipt JSON: {e}")))?;

    Ok((seq, generation, archived_json))
}

/// The exact versioned method (`kid`) that signed an `I13` receipt: required, and a valid
/// `{sequencer_did}#mls-receipt-<generation>` of the conversation's sequencer. Callers resolve
/// that retained method; there is no default generation.
pub fn sequencer_receipt_kid<'a>(
    sequencer_did: &str,
    receipt: &'a Value,
) -> Result<&'a str, MLSError> {
    let sequencer = sequencer_did.split('#').next().unwrap_or(sequencer_did);
    let kid = receipt
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing kid".into()))?;
    labyrinth_protocol::receipt::receipt_key_generation(sequencer, kid)
        .map_err(|e| MLSError::Cryptography(format!("sequencerReceipt kid: {e}")))?;
    Ok(kid)
}

/// SEC1 key of the sequencer's current receipt method, the highest retained
/// `{sequencer_did}#mls-receipt-<generation>` in its DID document. Only a pin made before any
/// receipt exists uses it; a received receipt verifies under the method its own `kid` names.
pub fn current_sequencer_receipt_key(
    did_doc_bytes: &[u8],
    sequencer_did: &str,
) -> Result<Vec<u8>, MLSError> {
    let doc: Value = serde_json::from_slice(did_doc_bytes)
        .map_err(|e| MLSError::Cryptography(format!("invalid DID document JSON: {e}")))?;
    let kid = doc["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|method| method["id"].as_str())
        .filter_map(|id| {
            let kid = if id.starts_with('#') {
                format!("{sequencer_did}{id}")
            } else {
                id.to_owned()
            };
            labyrinth_protocol::receipt::receipt_key_generation(sequencer_did, &kid)
                .ok()
                .map(|generation| (generation, kid))
        })
        .max_by_key(|(generation, _)| *generation)
        .map(|(_, kid)| kid)
        .ok_or_else(|| {
            MLSError::Cryptography(format!(
                "DID document for `{sequencer_did}` has no receipt verification method"
            ))
        })?;
    decode_p256_sec1_from_did_doc(did_doc_bytes, sequencer_did, &kid)
}

/// Verify the sequencer's receipt for a signed control entry before any transition effect.
#[allow(clippy::too_many_arguments)]
pub fn verify_control_sequencer_receipt(
    receipt: &Value,
    sec1_pubkey: &[u8],
    sequencer_did: &str,
    conversation_id: &str,
    entry_id: &str,
    entry_seq: i64,
    actor_did: &str,
    actor_device_id: &str,
    coordinate: &Value,
    request_digest: &[u8; 32],
) -> Result<(), MLSError> {
    let coordinate = canonicalize_wire_coordinate(coordinate, Some(conversation_id))?;
    let generation = coordinate["generation"]
        .as_u64()
        .ok_or_else(|| MLSError::Cryptography("control receipt coordinate generation".into()))?;
    let epoch = coordinate["epoch"]
        .as_u64()
        .ok_or_else(|| MLSError::Cryptography("control receipt coordinate epoch".into()))?;
    let group_id = json_bytes(&coordinate["groupId"])?;
    let (receipt_seq, receipt_generation, _) = parse_and_verify_i13_sequencer_receipt(
        receipt,
        sec1_pubkey,
        sequencer_did,
        conversation_id,
        &group_id,
        epoch,
        entry_id,
        entry_id,
        request_digest,
        None,
    )?;
    if i64::try_from(receipt_seq).ok() != Some(entry_seq)
        || receipt_generation != generation
        || receipt["senderDid"].as_str() != Some(actor_did)
        || receipt["senderDeviceId"].as_str() != Some(actor_device_id)
    {
        return Err(MLSError::Cryptography(
            "I13 control sequencerReceipt entry, coordinate, or actor mismatch".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedApplicationReceipt {
    pub generation: i64,
    pub epoch: i64,
    pub sender_did: String,
    pub sender_device_id: String,
}

/// A `payloadPruned` application entry this device holds no evidence for: only its signed
/// receipt remains. It must name this conversation, group, entry and seq under `sec1_pubkey`
/// (its own `kid`). Its epoch and commitment can only be self-bound, and a pruned entry carries
/// no sender attestation.
pub fn verify_pruned_application_receipt(
    receipt: &Value,
    sec1_pubkey: &[u8],
    sequencer_did: &str,
    conversation_id: &str,
    group_id: &[u8],
    entry_id: &str,
    entry_seq: i64,
) -> Result<PrunedApplicationReceipt, MLSError> {
    let epoch = receipt
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing epoch".into()))?;
    let commitment: [u8; 32] = json_bytes(receipt.get("archiveCommitment").ok_or_else(|| {
        MLSError::Cryptography("sequencerReceipt missing archiveCommitment".into())
    })?)?
    .try_into()
    .map_err(|_| {
        MLSError::Cryptography("sequencerReceipt archiveCommitment must be 32 bytes".into())
    })?;
    // The message id only binds a sender attestation, which a pruned entry no longer has.
    let (seq, generation, _) = parse_and_verify_i13_sequencer_receipt(
        receipt,
        sec1_pubkey,
        sequencer_did,
        conversation_id,
        group_id,
        epoch,
        entry_id,
        entry_id,
        &commitment,
        None,
    )?;
    if i64::try_from(seq).ok() != Some(entry_seq) {
        return Err(MLSError::Cryptography(format!(
            "I13: pruned entry receipt seq {seq} != entry seq {entry_seq}"
        )));
    }
    let sender_did = receipt["senderDid"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDid".into()))?;
    let sender_device_id = receipt["senderDeviceId"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("sequencerReceipt missing senderDeviceId".into()))?;
    Ok(PrunedApplicationReceipt {
        generation: i64::try_from(generation)
            .map_err(|_| MLSError::Cryptography("receipt generation overflow".into()))?,
        epoch: i64::try_from(epoch)
            .map_err(|_| MLSError::Cryptography("receipt epoch overflow".into()))?,
        sender_did: sender_did.to_owned(),
        sender_device_id: sender_device_id.to_owned(),
    })
}

/// JSON-serializable persistence wrapper for a verified `I13` `ArchivedReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredArchivedReceipt {
    pub sequencer_did: String,
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_did_url: String,
    pub entry_id: String,
    pub archive_commitment: Vec<u8>,
    pub seq: u64,
    pub issued_at_ms: i64,
    pub key_id: String,
    pub signature: Vec<u8>,
    pub generation: u64,
    pub original_sender_attestation:
        Option<crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope>,
}

impl StoredArchivedReceipt {
    #[cfg(feature = "labyrinth")]
    pub fn to_labyrinth_archived(&self) -> Result<labyrinth::message::ArchivedReceipt, MLSError> {
        let archive_commitment: [u8; 32] =
            self.archive_commitment.as_slice().try_into().map_err(|_| {
                MLSError::Internal("invalid stored archive_commitment length".into())
            })?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MLSError::Internal("invalid stored signature length".into()))?;
        Ok(labyrinth::message::ArchivedReceipt {
            signed: labyrinth_protocol::receipt::SignedSequencerReceipt {
                payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
                    sequencer_did: self.sequencer_did.clone(),
                    conversation_id: self.conversation_id.clone(),
                    group_id: self.group_id.clone(),
                    epoch: self.epoch,
                    sender_device_did_url: self.sender_device_did_url.clone(),
                    entry_id: self.entry_id.clone(),
                    archive_commitment,
                    seq: self.seq,
                    issued_at_ms: self.issued_at_ms,
                },
                key_id: self.key_id.clone(),
                signature,
            },
            generation: self.generation,
            original_sender_attestation: self
                .original_sender_attestation
                .as_ref()
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "stored archive receipt lacks original sender attestation".into(),
                    )
                })?
                .to_labyrinth()?,
        })
    }
}

/// Extract `(group_context_hash_32, confirmation_tag_raw_32)` for an `MlsGroup`.
pub fn compute_group_context_hash_and_tag<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
) -> Result<([u8; 32], Vec<u8>), MLSError> {
    let context: GroupContext = provider
        .storage()
        .group_context(group.group_id())
        .map_err(|e| MLSError::OpenMLS(format!("load group_context: {e:?}")))?
        .ok_or(MLSError::StorageFailed)?;
    let context_bytes = context
        .tls_serialize_detached()
        .map_err(|e| MLSError::OpenMLS(format!("serialize group_context: {e:?}")))?;
    let gch: [u8; 32] = Sha256::digest(&context_bytes).into();
    let tag_tls = group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|e| MLSError::OpenMLS(format!("serialize confirmation_tag: {e:?}")))?;
    let tag = if tag_tls.len() == 33 && tag_tls[0] == 32 {
        tag_tls[1..].to_vec()
    } else {
        tag_tls
    };
    Ok((gch, tag))
}

/// Extract a [`SpaceAvatarPointer`](crate::groups::metadata_v1::SpaceAvatarPointer) from a stored [`GroupMetadataRow`](crate::storage::GroupMetadataRow).
pub fn space_avatar_from_metadata_row(
    row: &crate::storage::GroupMetadataRow,
) -> Option<crate::groups::metadata_v1::SpaceAvatarPointer> {
    if let (Some(setter_did), Some(space_blob_cid), Some(sym_key), Some(sha256)) = (
        row.avatar_setter_did.as_ref(),
        row.avatar_blob_cid.as_ref(),
        row.avatar_sym_key.as_ref(),
        row.avatar_sha256.as_ref(),
    ) {
        return Some(crate::groups::metadata_v1::SpaceAvatarPointer {
            setter_did: setter_did.clone(),
            space_blob_cid: space_blob_cid.clone(),
            sym_key: sym_key.clone(),
            sha256: sha256.clone(),
            mime_type: row.avatar_mime_type.clone(),
        });
    }
    serde_json::from_str::<GroupMetadataV1>(&row.metadata_json)
        .ok()
        .and_then(|m| m.space_avatar)
}

/// Convert a decrypted [`GroupMetadataV1`] into a [`GroupMetadataRow`](crate::storage::GroupMetadataRow),
/// preserving all `SpaceAvatarPointer` columns (`1A`).
pub fn group_metadata_row_from_v1(
    conversation_id: &str,
    metadata_version: i64,
    epoch: i64,
    meta: &GroupMetadataV1,
    updated_at_ms: i64,
) -> Result<crate::storage::GroupMetadataRow, MLSError> {
    let avatar = meta.space_avatar.as_ref();
    Ok(crate::storage::GroupMetadataRow {
        conversation_id: conversation_id.to_string(),
        metadata_version,
        epoch,
        title: (!meta.title.is_empty()).then(|| meta.title.clone()),
        description: (!meta.description.is_empty()).then(|| meta.description.clone()),
        avatar_setter_did: avatar.map(|a| a.setter_did.clone()),
        avatar_blob_cid: avatar.map(|a| a.space_blob_cid.clone()),
        avatar_sym_key: avatar.map(|a| a.sym_key.clone()),
        avatar_sha256: avatar.map(|a| a.sha256.clone()),
        avatar_mime_type: avatar
            .and_then(|a| a.mime_type.clone())
            .or_else(|| meta.avatar_content_type.clone()),
        metadata_json: serde_json::to_string(meta)
            .map_err(|e| MLSError::Internal(e.to_string()))?,
        updated_at_ms,
    })
}

/// Build an encrypted `metadataSnapshot` JSON object for `creationBody`, `metadataTransitionBody`,
/// `commitTransitionBody`, or `leafRecoveryFulfillmentBody`.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_metadata_snapshot_json(
    metadata_key: &[u8; 32],
    group_id: &[u8],
    convo_uuid: &uuid::Uuid,
    generation: i64,
    target_epoch: u64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: &str,
    metadata_version: u64,
    origin_seq: u64,
    actor_did: &str,
    actor_device_id: &str,
    auth_generation: i64,
    public_key: &[u8],
    title: &str,
    description: &str,
    space_avatar: Option<crate::groups::metadata_v1::SpaceAvatarPointer>,
) -> Result<Value, MLSError> {
    let nonce: [u8; 12] = rand::random();
    build_encrypted_metadata_snapshot_json_with_nonce(
        metadata_key,
        group_id,
        convo_uuid,
        generation,
        target_epoch,
        group_context_hash,
        confirmation_tag,
        transition_id,
        metadata_version,
        origin_seq,
        actor_did,
        actor_device_id,
        auth_generation,
        public_key,
        title,
        description,
        space_avatar,
        nonce,
    )
}

/// Build an encrypted `metadataSnapshot` JSON object using an explicit 12-byte AEAD `nonce`.
#[allow(clippy::too_many_arguments)]
pub fn build_encrypted_metadata_snapshot_json_with_nonce(
    metadata_key: &[u8; 32],
    group_id: &[u8],
    convo_uuid: &uuid::Uuid,
    generation: i64,
    target_epoch: u64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: &str,
    metadata_version: u64,
    origin_seq: u64,
    actor_did: &str,
    actor_device_id: &str,
    auth_generation: i64,
    public_key: &[u8],
    title: &str,
    description: &str,
    space_avatar: Option<crate::groups::metadata_v1::SpaceAvatarPointer>,
    nonce: [u8; 12],
) -> Result<Value, MLSError> {
    let payload = GroupMetadataV1 {
        version: 1,
        title: title.to_string(),
        description: description.to_string(),
        avatar_blob_locator: None,
        avatar_content_type: space_avatar.as_ref().and_then(|a| a.mime_type.clone()),
        space_avatar,
    };
    let ciphertext = encrypt_metadata_snapshot_with_nonce(
        metadata_key,
        group_id,
        target_epoch,
        metadata_version,
        &nonce,
        &payload,
    )?;
    let key_id = derive_key_id(public_key);
    Ok(json!({
        "authorProof": {
            "authGenerationAtOrigin": auth_generation,
            "authorDeviceId": actor_device_id,
            "authorDid": actor_did,
            "authorKeyId": key_id,
            "deviceStatusAtOrigin": "active",
            "originSeq": origin_seq,
            "originTransitionId": transition_id,
            "roleAtOrigin": "admin",
            "signaturePublicKey": { "$bytes": STANDARD.encode(public_key) }
        },
        "ciphertext": { "$bytes": STANDARD.encode(&ciphertext) },
        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
        "ciphertextSize": ciphertext.len(),
        "coordinate": {
            "confirmationTag": { "$bytes": STANDARD.encode(confirmation_tag) },
            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
            "epoch": target_epoch,
            "generation": generation,
            "groupContextHash": { "$bytes": STANDARD.encode(group_context_hash) },
            "groupId": { "$bytes": STANDARD.encode(group_id) }
        },
        "metadataVersion": metadata_version,
        "nonce": { "$bytes": STANDARD.encode(nonce) },
        "originTransitionId": transition_id
    }))
}

/// Try decrypting a server `metadataSnapshot` JSON object at the current `MlsGroup` epoch.
pub fn try_decrypt_group_metadata_snapshot<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    snapshot_json: &Value,
) -> Option<(i64, i64, GroupMetadataV1)> {
    let coord = snapshot_json.get("coordinate")?;
    let snap_epoch = coord.get("epoch")?.as_u64()?;
    if group.epoch().as_u64() != snap_epoch {
        return None;
    }
    let metadata_version = snapshot_json.get("metadataVersion")?.as_u64()?;
    let nonce_vec = json_bytes(snapshot_json.get("nonce")?).ok()?;
    let nonce_12: [u8; 12] = nonce_vec.as_slice().try_into().ok()?;
    let ciphertext = json_bytes(snapshot_json.get("ciphertext")?).ok()?;
    let group_id = group.group_id().as_slice().to_vec();
    let meta_key = derive_metadata_key_from_group(
        group,
        provider.crypto(),
        provider.storage(),
        &group_id,
        snap_epoch,
    )
    .ok()?;
    let meta = decrypt_metadata_snapshot(
        &meta_key,
        &group_id,
        snap_epoch,
        metadata_version,
        &nonce_12,
        &ciphertext,
    )
    .ok()?;
    Some((snap_epoch as i64, metadata_version as i64, meta))
}

/// Sign a canonical `blue.catbird.chat.*` request body using `prepare_signed_request_with_signer`.
pub fn sign_clean_chat_mutation(
    actor_did: &str,
    device_id: &str,
    auth_generation: Option<i64>,
    operation: CanonicalOperation,
    body_value: &Value,
    signer: &SignatureKeyPair,
) -> Result<PreparedRequest, MLSError> {
    let binding = CleanChatSigningContext {
        actor_did: actor_did.to_string(),
        device_id: device_id.to_string(),
        auth_generation,
    };
    let raw_body = serde_json::to_vec(body_value)
        .map_err(|e| MLSError::Internal(format!("serialize signed body JSON: {e}")))?;
    crate::orchestrator::canonical_transport::prepare_signed_request_with_signer(
        &binding, operation, raw_body, signer,
    )
    .map_err(|e| {
        MLSError::Cryptography(format!(
            "prepare_signed_request_with_signer({operation:?}): {e}"
        ))
    })
}

/// Sign a `C33` direct-request body (`Prepare`, `Publish`, `Accept`, `Cancel`, `Keys`) and return
/// the signed wrapper JSON bytes (`{"body": ..., "signature": "..."}`).
pub fn sign_direct_request_wrapper(
    kind: DirectRequestKind,
    body_value: Value,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, MLSError> {
    let raw_body = serde_json::to_vec(&body_value)
        .map_err(|e| MLSError::Internal(format!("serialize direct-request body: {e}")))?;
    let signing_bytes =
        dr_transcript::direct_request_signing_bytes(kind, &raw_body).map_err(|e| {
            MLSError::Cryptography(format!("direct_request_signing_bytes({kind:?}): {e}"))
        })?;
    let signature = signer
        .sign(&signing_bytes)
        .map_err(|e| MLSError::Cryptography(format!("sign direct-request ({kind:?}): {e:?}")))?;
    let wrapper = serde_json::to_vec(&json!({
        "body": body_value,
        "signature": STANDARD.encode(&signature),
    }))
    .map_err(|e| MLSError::Internal(format!("serialize direct-request wrapper: {e}")))?;
    dr_transcript::verify_signed_request(kind, &wrapper, signer.public()).map_err(|e| {
        MLSError::Cryptography(format!("verify self-signed direct-request ({kind:?}): {e}"))
    })?;
    Ok(wrapper)
}

/// Verify a signed `C33` outcome under the coordinator's receipt key; returns its receipt.
pub fn verify_c33_outcome(
    outcome: &Value,
    authority_did: &str,
    authority_key: &[u8],
) -> Result<Value, MLSError> {
    let outcome = dr_transcript::normalize_read_presentation(
        &serde_json::to_vec(outcome)?,
        "signedDirectRequestReceipt",
        outcome.get("$type").is_some(),
    )
    .map_err(|e| MLSError::Cryptography(format!("C33 outcome: {e}")))?;
    let verified = dr_transcript::verify_signed_request_for_authority(
        authority_did,
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&outcome)?,
        authority_key,
    )
    .map_err(|e| MLSError::Cryptography(format!("C33 outcome signature: {e}")))?;
    Ok(verified.body()["receipt"].clone())
}

/// The error code of a verified receipt that ends this attempt without publication, bound like
/// a publication receipt: the journaled request and its preparation digest, its actor, and the
/// digest of the journaled prepare (or sent publication) that triggered it. `None` for a
/// publication receipt; any other kind or binding fails closed.
pub fn c33_terminal_receipt_code(
    receipt: &Value,
    prepare: &dr_transcript::VerifiedDirectRequest,
    publication: Option<&dr_transcript::VerifiedDirectRequest>,
) -> Result<Option<String>, MLSError> {
    let code = match receipt["$type"].as_str() {
        Some("blue.catbird.chat.defs#directRequestPublishedReceipt") => return Ok(None),
        Some("blue.catbird.chat.defs#directRequestRejectedReceipt") => receipt["code"].as_str(),
        Some("blue.catbird.chat.defs#directRequestExpiredReceipt") => Some("PreparationExpired"),
        Some("blue.catbird.chat.defs#directRequestExistingDirectReceipt") => Some("ExistingDirect"),
        _ => None,
    };
    let digest =
        |request: &dr_transcript::VerifiedDirectRequest| STANDARD.encode(request.request_digest());
    let trigger = match receipt["requestKind"].as_str() {
        Some("prepare") => Some(prepare),
        Some("publish") => publication,
        // A lease expiry is bound to the prepare, a published request's expiry to its publication.
        Some("expiry") => [Some(prepare), publication]
            .into_iter()
            .flatten()
            .find(|&request| receipt["requestDigest"] == digest(request)),
        _ => None,
    };
    let p = prepare.body();
    let bound = trigger.is_some_and(|request| receipt["requestDigest"] == digest(request))
        && receipt["requestId"] == p["requestId"]
        && receipt["preparationRequestDigest"] == digest(prepare)
        && receipt["actorDid"] == p["actorDid"]
        && receipt["actorDeviceId"] == p["actorDeviceId"]
        && receipt["actorKeyId"] == p["keyId"]
        && receipt["authGeneration"] == p["authGeneration"];
    match code {
        Some(code) if bound => Ok(Some(code.to_owned())),
        _ => Err(MLSError::Cryptography(
            "C33 outcome binding mismatch".into(),
        )),
    }
}

/// Normalize a JSON coordinate object so `$bytes` fields are consistently formatted for canonical
/// mutations (`prior` / `next` in `submitTransition` and `sendMessage`).
pub fn canonicalize_wire_coordinate(
    coord: &Value,
    convo_id_override: Option<&str>,
) -> Result<Value, MLSError> {
    let gch = json_bytes(
        coord
            .get("groupContextHash")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing groupContextHash"))?,
    )?;
    let tag = json_bytes(
        coord
            .get("confirmationTag")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing confirmationTag"))?,
    )?;
    let gid = json_bytes(
        coord
            .get("groupId")
            .ok_or_else(|| MLSError::invalid_input("coordinate missing groupId"))?,
    )?;
    let convo_id = convo_id_override
        .or_else(|| coord.get("conversationId").and_then(|v| v.as_str()))
        .ok_or_else(|| MLSError::invalid_input("coordinate missing conversationId"))?;
    let epoch = coord
        .get("epoch")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| MLSError::invalid_input("coordinate missing epoch"))?;
    let generation = coord
        .get("generation")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let state_version = coord
        .get("stateVersion")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let lifecycle = coord
        .get("lifecycle")
        .and_then(|v| v.as_str())
        .unwrap_or("active");
    Ok(json!({
        "confirmationTag": { "$bytes": STANDARD.encode(tag) },
        "conversationId": convo_id,
        "epoch": epoch,
        "generation": generation,
        "groupContextHash": { "$bytes": STANDARD.encode(gch) },
        "groupId": { "$bytes": STANDARD.encode(gid) },
        "lifecycle": lifecycle,
        "stateVersion": state_version,
    }))
}

/// Build the `aad.prior` coordinate object (with base64-encoded 16-byte UUID `conversationId`)
/// required inside `commitAad` and `applicationAad`.
pub fn build_aad_prior_coordinate(
    convo_uuid: &uuid::Uuid,
    group_id: &[u8],
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
) -> Value {
    json!({
        "confirmationTag": { "$bytes": STANDARD.encode(confirmation_tag) },
        "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
        "epoch": epoch,
        "generation": generation,
        "groupContextHash": { "$bytes": STANDARD.encode(group_context_hash) },
        "groupId": { "$bytes": STANDARD.encode(group_id) },
        "lifecycle": "active",
        "stateVersion": state_version,
    })
}

/// Extract unique participant `did:...` roots from a JSON value tree so `I4` PDS device keys
/// can be prefetched outside SQLite `write_tx` without contacting peer DS authorities (`D1`).
pub fn collect_dids_from_json(val: &Value, out: &mut BTreeMap<String, ()>) {
    match val {
        Value::String(s) => {
            if s.contains("#mls-receipt") || s.contains("#atproto_mls") {
                return;
            }
            let root = s.split('#').next().unwrap_or("").trim();
            if root.starts_with("did:plc:") || root.starts_with("did:web:") {
                out.insert(root.to_string(), ());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_dids_from_json(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                if matches!(
                    k.as_str(),
                    "sequencerReceipt"
                        | "sequencerDid"
                        | "authorityDid"
                        | "serviceDid"
                        | "coordinatorDid"
                        | "deliveryService"
                        | "homeDsDid"
                        | "recipientServiceDid"
                        | "senderServiceDid"
                        | "kid"
                        | "receiptKeyId"
                ) {
                    continue;
                }
                collect_dids_from_json(v, out);
            }
        }
        _ => {}
    }
}

/// Parse `<did>#<device_id>` (or `<did>`) from MLS `BasicCredential` bytes.
pub fn parse_scoped_credential_did_device(
    identity_bytes: &[u8],
) -> Result<(String, String), MLSError> {
    let raw = std::str::from_utf8(identity_bytes).map_err(|_| {
        MLSError::Cryptography("I4: MLS leaf credential is not valid UTF-8".to_string())
    })?;
    let trimmed = raw.trim();
    let (did, device_id) = match trimmed.split_once('#') {
        Some((d, dev)) => (d.trim(), dev.trim()),
        None => (trimmed, ""),
    };
    if !(did.starts_with("did:plc:") || did.starts_with("did:web:")) {
        return Err(MLSError::Cryptography(format!(
            "I4: invalid DID `{did}` in MLS leaf credential"
        )));
    }
    Ok((did.to_string(), device_id.to_string()))
}

/// Universal (native + WASM) `I4` verifier over `(did -> Vec<(device_id, pubkey_32)>)`.
pub fn verify_leaf_pds_map_i4(
    identity_bytes: &[u8],
    signature_key: &[u8],
    authorized_by_did: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Result<(String, String), MLSError> {
    let (root_did, device_id) = parse_scoped_credential_did_device(identity_bytes)?;
    let Some(pairs) = authorized_by_did.get(&root_did) else {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: no verified ATProto device keys found for sender DID `{root_did}`"
        )));
    };
    let matched = pairs.iter().any(|(dev_id, pk)| {
        pk.as_slice() == signature_key
            && (device_id.is_empty() || dev_id.is_empty() || dev_id == &device_id)
    });
    if !matched {
        return Err(MLSError::insufficient_permissions(format!(
            "I4/F-02: unverified MLS leaf signature key for `{root_did}#{device_id}`"
        )));
    }
    Ok((root_did, device_id))
}

/// Universal (native + WASM) `I4` verifier for a `StagedCommit`, checking the Commit sender leaf,
/// all `AddProposal` leaves, and all `UpdateProposal` leaves against PDS `blue.catbird.chat.device` keys.
pub fn verify_staged_commit_pds_map_i4(
    group: &openmls::prelude::MlsGroup,
    sender: &openmls::prelude::Sender,
    staged: &openmls::prelude::StagedCommit,
    authorized_by_did: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
) -> Result<(), MLSError> {
    if let openmls::prelude::Sender::Member(leaf_idx) = sender {
        let sender_member = group
            .members()
            .find(|m| m.index == *leaf_idx)
            .ok_or_else(|| {
                MLSError::insufficient_permissions("I4/F-02: Commit sender leaf missing from group")
            })?;
        verify_leaf_pds_map_i4(
            sender_member.credential.serialized_content(),
            &sender_member.signature_key,
            authorized_by_did,
        )?;
    } else {
        return Err(MLSError::insufficient_permissions(
            "I4/F-02: external/non-member Commit rejected",
        ));
    }

    for queued in staged.add_proposals() {
        let ln = queued.add_proposal().key_package().leaf_node();
        verify_leaf_pds_map_i4(
            ln.credential().serialized_content(),
            ln.signature_key().as_slice(),
            authorized_by_did,
        )?;
    }

    for queued in staged.update_proposals() {
        let ln = queued.update_proposal().leaf_node();
        let new_id = ln.credential().serialized_content();
        if let openmls::prelude::Sender::Member(leaf_idx) = queued.sender() {
            let old_member = group
                .members()
                .find(|m| m.index == *leaf_idx)
                .ok_or(MLSError::InvalidCommit)?;
            if old_member.credential.serialized_content() != new_id {
                return Err(MLSError::InvalidCommit);
            }
        } else {
            return Err(MLSError::InvalidCommit);
        }
        verify_leaf_pds_map_i4(new_id, ln.signature_key().as_slice(), authorized_by_did)?;
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_leaf_slice_i4(
    identity_bytes: &[u8],
    signature_key: &[u8],
    keys: &[crate::push::AuthorizedPeerDeviceKey],
) -> Result<(String, String), MLSError> {
    if keys.is_empty()
        && crate::planted::is_planted_bug_active(
            crate::planted::PlantedBug::P14TofuOnDeviceDirectory503,
        )
    {
        return crate::push::root_did_from_credential_bytes(identity_bytes);
    }
    let mut map: std::collections::HashMap<String, Vec<crate::push::AuthorizedPeerDeviceKey>> =
        std::collections::HashMap::new();
    for k in keys {
        map.entry(k.did.clone()).or_default().push(k.clone());
    }
    crate::push::verify_leaf_binding_i4(identity_bytes, signature_key, None, &map)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_staged_commit_slice_i4(
    group: &openmls::prelude::MlsGroup,
    sender: &openmls::prelude::Sender,
    staged: &openmls::prelude::StagedCommit,
    keys: &[crate::push::AuthorizedPeerDeviceKey],
) -> Result<(), MLSError> {
    let mut map: std::collections::HashMap<String, Vec<crate::push::AuthorizedPeerDeviceKey>> =
        std::collections::HashMap::new();
    for k in keys {
        map.entry(k.did.clone()).or_default().push(k.clone());
    }
    crate::push::verify_staged_commit_i4(group, sender, staged, None, &map)
}

/// Normalize plaintext JSON to canonical `MLSMessagePayload` JSON for Labyrinth archival.
pub fn canonical_labyrinth_frame_json(plaintext_json: &str) -> String {
    if serde_json::from_str::<crate::orchestrator::MLSMessagePayload>(plaintext_json).is_ok() {
        return plaintext_json.to_string();
    }
    if let Ok(val) = serde_json::from_str::<Value>(plaintext_json) {
        if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
            if let Ok(encoded) =
                serde_json::to_string(&crate::orchestrator::MLSMessagePayload::text(text))
            {
                return encoded;
            }
        }
    }
    plaintext_json.to_string()
}

fn deterministic_tid_wire(timestamp_ms: i64, sub_seq: u64, discriminator: &str) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let micros = (timestamp_ms.max(0) as u64)
        .saturating_mul(1_000)
        .saturating_add(sub_seq)
        & ((1u64 << 53) - 1);
    let digest = Sha256::digest(discriminator.as_bytes());
    let clock_id = (u16::from_be_bytes([digest[0], digest[1]]) as u64) & 0x3ff;
    let v = (micros << 10) | clock_id;
    (0..13)
        .rev()
        .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

/// Build `(convo_space_uri, apply_writes_json_bytes)` for `com.atproto.space.applyWrites`: one
/// `labyrinth::message::seal_sender_committed` frame under `mek`, written into the conversation
/// Space as `repo_did` (the writing account, not necessarily the message's sender). The payload
/// must carry its 32-byte frame nonce, verified I13 receipt and original sender attestation, and
/// the receipt must retain that exact attestation (`I13`, `D4`); anything else is not archivable.
#[cfg(feature = "labyrinth")]
pub fn build_space_apply_writes_for_queue_payload(
    payload: &crate::client::QueuedLabyrinthArchivePayload,
    mek: &labyrinth::mek::Mek,
    signer: &SignatureKeyPair,
    repo_did: &str,
) -> Result<(String, Vec<u8>), MLSError> {
    struct WireTransportSigner<'a>(&'a SignatureKeyPair, [u8; 32]);
    impl labyrinth::sign::TransportSigner for WireTransportSigner<'_> {
        fn transport_public_key(&self) -> [u8; 32] {
            self.1
        }
        fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
            let sig = self.0.sign(msg).unwrap_or_else(|_| vec![0u8; 64]);
            <[u8; 64]>::try_from(sig.as_slice()).unwrap_or([0u8; 64])
        }
    }

    let pub_key_32: [u8; 32] = signer
        .public()
        .try_into()
        .map_err(|_| MLSError::Cryptography("device signer pubkey must be 32 bytes".to_string()))?;
    let transport_signer = WireTransportSigner(signer, pub_key_32);

    let ts_ms = payload.created_at_ms.max(0) as u64;
    let item_seq_u64 = payload.seq.max(0) as u64;
    let item_sub_seq = item_seq_u64 % 1_000;
    let nonce_32: [u8; 32] =
        STANDARD
            .decode(payload.frame_nonce_b64.as_deref().ok_or_else(|| {
                MLSError::Cryptography("archive payload missing frame nonce".into())
            })?)
            .map_err(|e| MLSError::Cryptography(format!("archive frame nonce: {e}")))?
            .try_into()
            .map_err(|_| MLSError::Cryptography("archive frame nonce must be 32 bytes".into()))?;
    let stored_receipt: StoredArchivedReceipt =
        serde_json::from_str(payload.sequencer_receipt_json.as_deref().ok_or_else(|| {
            MLSError::Cryptography("archive payload missing verified I13 receipt".into())
        })?)
        .map_err(|e| MLSError::Cryptography(format!("archive I13 receipt: {e}")))?;
    let attestation: crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope =
        serde_json::from_str(
            payload
                .original_sender_attestation_json
                .as_deref()
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "archive payload missing original sender attestation".into(),
                    )
                })?,
        )
        .map_err(|e| MLSError::Cryptography(format!("archive original sender attestation: {e}")))?;
    if stored_receipt.original_sender_attestation.as_ref() != Some(&attestation) {
        return Err(MLSError::Cryptography(
            "archive receipt does not retain the payload's original sender attestation".into(),
        ));
    }
    let archived = stored_receipt.to_labyrinth_archived()?;
    let sealed_msg = labyrinth::message::seal_sender_committed(
        mek,
        &payload.conversation_id,
        &payload.message_id,
        ts_ms,
        &nonce_32,
        payload.labyrinth_frame_json.as_bytes(),
        &archived,
        &transport_signer,
    )
    .map_err(|e| MLSError::Cryptography(format!("seal_sender_committed: {e}")))?;

    let sender_batch = labyrinth::records::Batch::from_messages(
        &payload.conversation_id,
        &[sealed_msg],
        labyrinth::records::datetime_from_ms(ts_ms),
    )
    .map_err(|e| MLSError::Internal(format!("Batch::from_messages: {e}")))?;
    let batch_val = serde_json::to_value(&sender_batch)
        .map_err(|e| MLSError::Internal(format!("serialize Batch: {e}")))?;
    let tid = deterministic_tid_wire(
        payload.created_at_ms,
        item_sub_seq,
        &format!("batch:{}:{}", payload.conversation_id, payload.message_id),
    );
    let rkey = format!("{item_seq_u64:016x}-{tid}");
    let convo_space = match payload.space_uri.clone() {
        Some(uri) => uri,
        None => atproto_spaces::SpaceUri::new(
            &payload.sequencer_did,
            "blue.catbird.labyrinth.conversation",
            &format!("{}-0", payload.conversation_id),
        )
        .map(|u| u.as_str().to_owned())
        .map_err(|e| MLSError::invalid_input(format!("invalid conversation Space URI: {e}")))?,
    };
    let apply_body = serde_json::to_vec(&json!({
        "space": convo_space,
        "repo": repo_did,
        "validate": false,
        "writes": [{
            "$type": "com.atproto.space.applyWrites#create",
            "collection": labyrinth::records::nsid::BATCH,
            "rkey": rkey,
            "value": batch_val,
        }],
    }))
    .map_err(|e| MLSError::Internal(format!("serialize applyWrites JSON: {e}")))?;
    Ok((convo_space, apply_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQUENCER: &str = "did:web:sequencer.example.com";
    const CONVERSATION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ENTRY: &str = "33333333-3333-4333-8333-333333333333";

    fn receipt_signer(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn sec1(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn signed_receipt(key: &p256::ecdsa::SigningKey, kid: &str, seq: u64) -> Value {
        let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did: SEQUENCER.into(),
            conversation_id: CONVERSATION.into(),
            group_id: vec![7; 32],
            epoch: 3,
            sender_device_did_url: "did:plc:sender#device".into(),
            entry_id: ENTRY.into(),
            archive_commitment: [9; 32],
            seq,
            issued_at_ms: 1_762_000_000_000,
        };
        let signed =
            labyrinth_protocol::receipt::sign_sequencer_receipt(key, kid, &payload).unwrap();
        json!({
            "kid": signed.key_id,
            "sequencerDid": SEQUENCER,
            "conversationId": CONVERSATION,
            "generation": 0,
            "groupId": { "$bytes": STANDARD.encode([7u8; 32]) },
            "epoch": 3,
            "seq": seq,
            "entryId": ENTRY,
            "senderDid": "did:plc:sender",
            "senderDeviceId": "device",
            "archiveCommitment": { "$bytes": STANDARD.encode([9u8; 32]) },
            "issuedAtMs": 1_762_000_000_000i64,
            "signature": { "$bytes": STANDARD.encode(signed.signature) },
        })
    }

    #[test]
    fn receipt_kid_is_required_exact_and_versioned() {
        let rotated = format!("{SEQUENCER}#mls-receipt-2");
        let receipt = signed_receipt(&receipt_signer(1), &rotated, 4);
        assert_eq!(sequencer_receipt_kid(SEQUENCER, &receipt).unwrap(), rotated);
        for kid in [
            Value::Null,
            json!("#mls-receipt-1"),
            json!("did:web:other.example.com#mls-receipt-1"),
            json!(format!("{SEQUENCER}#mls-receipt-01")),
            json!(format!("{SEQUENCER}#atproto")),
        ] {
            let mut forged = receipt.clone();
            forged["kid"] = kid;
            assert!(
                sequencer_receipt_kid(SEQUENCER, &forged).is_err(),
                "{forged}"
            );
        }
    }

    #[test]
    fn current_receipt_key_is_the_highest_generation_and_history_still_verifies() {
        let method = |generation: u8, key: &p256::ecdsa::SigningKey| {
            json!({
                "id": format!("{SEQUENCER}#mls-receipt-{generation}"),
                "type": "Multikey",
                "controller": SEQUENCER,
                "publicKeyMultibase": multibase::encode(
                    multibase::Base::Base58Btc,
                    [&[0x80u8, 0x24][..], sec1(key).as_slice()].concat(),
                ),
            })
        };
        let (first, second) = (receipt_signer(1), receipt_signer(2));
        let doc = serde_json::to_vec(&json!({
            "id": SEQUENCER,
            "verificationMethod": [method(2, &second), method(1, &first)],
        }))
        .unwrap();
        assert_eq!(
            current_sequencer_receipt_key(&doc, SEQUENCER).unwrap(),
            sec1(&second)
        );
        // A retained generation-1 receipt verifies under its own method after rotation.
        let receipt = signed_receipt(&first, &format!("{SEQUENCER}#mls-receipt-1"), 4);
        let key = decode_p256_sec1_from_did_doc(
            &doc,
            SEQUENCER,
            sequencer_receipt_kid(SEQUENCER, &receipt).unwrap(),
        )
        .unwrap();
        assert_eq!(key, sec1(&first));
        verify_pruned_application_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            &[7; 32],
            ENTRY,
            4,
        )
        .unwrap();
    }

    #[test]
    fn pruned_receipt_must_sequence_exactly_this_entry() {
        let signer = receipt_signer(1);
        let receipt = signed_receipt(&signer, &format!("{SEQUENCER}#mls-receipt-1"), 4);
        let key = sec1(&signer);
        let verify = |receipt: &Value, key: &[u8], sequencer, cid, group: &[u8], entry, seq| {
            verify_pruned_application_receipt(receipt, key, sequencer, cid, group, entry, seq)
        };
        verify(&receipt, &key, SEQUENCER, CONVERSATION, &[7; 32], ENTRY, 4).unwrap();
        let other_entry = "44444444-4444-4444-8444-444444444444";
        let other_cid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        for (sequencer, cid, group, entry, seq) in [
            (SEQUENCER, CONVERSATION, [7u8; 32], ENTRY, 5),
            (SEQUENCER, CONVERSATION, [7u8; 32], other_entry, 4),
            (SEQUENCER, CONVERSATION, [8u8; 32], ENTRY, 4),
            (SEQUENCER, other_cid, [7u8; 32], ENTRY, 4),
            (
                "did:web:other.example.com",
                CONVERSATION,
                [7u8; 32],
                ENTRY,
                4,
            ),
        ] {
            assert!(verify(&receipt, &key, sequencer, cid, &group, entry, seq).is_err());
        }
        assert!(verify(
            &receipt,
            &sec1(&receipt_signer(2)),
            SEQUENCER,
            CONVERSATION,
            &[7; 32],
            ENTRY,
            4
        )
        .is_err());
        let mut forged = receipt.clone();
        forged["seq"] = json!(5);
        assert!(verify(&forged, &key, SEQUENCER, CONVERSATION, &[7; 32], ENTRY, 5).is_err());
        let mut unsigned = receipt;
        unsigned.as_object_mut().unwrap().remove("signature");
        assert!(verify(&unsigned, &key, SEQUENCER, CONVERSATION, &[7; 32], ENTRY, 4).is_err());
    }

    #[test]
    fn account_deletion_v2_matches_server_vector_and_rejects_downgrades_and_mutations() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::{Signature, SigningKey};

        const SEQUENCER: &str = "did:web:sequencer.example.com";
        const CONVERSATION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const DELETED: &str = "did:web:deleted.example.com";
        const ENTRY: &str = "33333333-3333-4333-8333-333333333333";
        const RECEIVED_AT: &str = "2026-11-03T12:00:00.123Z";
        const KEY_ID: &str = "did:web:sequencer.example.com#mls-receipt-1";
        let fields = [SEQUENCER, CONVERSATION, DELETED, "12", ENTRY, RECEIVED_AT];
        let transcript = account_deletion_authority_signing_bytes(KEY_ID, &fields).unwrap();
        assert_eq!(
            hex::encode(&transcript),
            concat!(
                "636174626972642d6d6c732d6163636f756e742d64656c6574696f6e2d61757468",
                "6f726974792d7632000000002b6469643a7765623a73657175656e6365722e6578",
                "616d706c652e636f6d236d6c732d726563656970742d31636174626972642d6d6c",
                "732d6163636f756e742d64656c6574696f6e2d7631000000001d6469643a776562",
                "3a73657175656e6365722e6578616d706c652e636f6d000000246161616161616161",
                "2d616161612d346161612d386161612d6161616161616161616161610000001b64",
                "69643a7765623a64656c657465642e6578616d706c652e636f6d00000002313200",
                "00002433333333333333332d333333332d343333332d383333332d333333333333",
                "33333333333300000018323032362d31312d30335431323a30303a30302e3132335a"
            )
        );

        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let sign = |message: &[u8]| {
            let signature: Signature = key.sign(message);
            signature
                .normalize_s()
                .unwrap_or(signature)
                .to_bytes()
                .to_vec()
        };
        let signature = sign(&transcript);
        let public_key = key.verifying_key().to_encoded_point(true);
        assert!(account_deletion_signature_valid(
            public_key.as_bytes(),
            &signature,
            KEY_ID,
            &fields,
        ));

        // The server's former v1-only signature is a downgrade, not a v2 authority.
        let inner_offset = ACCOUNT_DELETION_AUTHORITY_DOMAIN.len() + 4 + KEY_ID.len();
        let legacy_signature = sign(&transcript[inner_offset..]);
        assert!(!account_deletion_signature_valid(
            public_key.as_bytes(),
            &legacy_signature,
            KEY_ID,
            &fields,
        ));

        for changed in [
            [
                "did:web:other.example.com",
                CONVERSATION,
                DELETED,
                "12",
                ENTRY,
                RECEIVED_AT,
            ],
            [
                SEQUENCER,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                DELETED,
                "12",
                ENTRY,
                RECEIVED_AT,
            ],
            [
                SEQUENCER,
                CONVERSATION,
                "did:web:other.example.com",
                "12",
                ENTRY,
                RECEIVED_AT,
            ],
            [SEQUENCER, CONVERSATION, DELETED, "13", ENTRY, RECEIVED_AT],
            [
                SEQUENCER,
                CONVERSATION,
                DELETED,
                "12",
                "44444444-4444-4444-8444-444444444444",
                RECEIVED_AT,
            ],
            [
                SEQUENCER,
                CONVERSATION,
                DELETED,
                "12",
                ENTRY,
                "2026-11-03T12:00:00.124Z",
            ],
        ] {
            assert!(!account_deletion_signature_valid(
                public_key.as_bytes(),
                &signature,
                KEY_ID,
                &changed,
            ));
        }
        for key_id in [
            "did:web:sequencer.example.com#atproto",
            "did:web:sequencer.example.com#mls-receipt-01",
            "did:web:sequencer.example.com#mls-receipt-2",
        ] {
            assert!(!account_deletion_signature_valid(
                public_key.as_bytes(),
                &signature,
                key_id,
                &fields,
            ));
        }
        let wrong_key = SigningKey::from_slice(&[8; 32]).unwrap();
        let wrong_signature: Signature = wrong_key.sign(&transcript);
        assert!(!account_deletion_signature_valid(
            public_key.as_bytes(),
            &wrong_signature
                .normalize_s()
                .unwrap_or(wrong_signature)
                .to_bytes(),
            KEY_ID,
            &fields,
        ));
    }

    #[test]
    fn recovery_entitlement_roster_and_attestation_fail_closed() {
        let (alice, bob, carol) = ("did:plc:alice", "did:plc:bob", "did:plc:carol");
        let leaves = vec![
            (alice.to_owned(), "a1".to_owned()),
            (bob.to_owned(), "b1".to_owned()),
        ];
        let auth = |did: &str, device: &str, kind: &str| json!({ "requesterDid": did, "requesterDeviceId": device, "recoveryKind": kind });
        let mut roster = roster_from_participants(&json!([
            { "userDid": alice, "role": "admin", "status": "active" },
            { "userDid": bob, "role": "member", "status": "active" },
            { "userDid": carol, "role": "member", "status": "pending" },
        ]))
        .unwrap();
        let entitled = |a: &Value, roster: Option<&Value>, verified_admission: bool| {
            recovery_request_entitled(a, &leaves, roster, verified_admission, alice, "a1")
        };
        assert!(
            entitled(&auth(bob, "b2", "add"), None, false),
            "a member's new device"
        );
        assert!(
            entitled(&auth(bob, "b1", "replace"), None, false),
            "a member's exact leaf"
        );
        assert!(
            !entitled(&auth(alice, "a2", "replace"), None, false),
            "replace requires holding a leaf"
        );
        let mut sibling_leaves = leaves.clone();
        sibling_leaves.push((alice.to_owned(), "a2".to_owned()));
        assert!(
            recovery_request_entitled(
                &auth(alice, "a2", "replace"),
                &sibling_leaves,
                None,
                false,
                alice,
                "a1",
            ),
            "sibling device may fulfill a held-leaf replace"
        );
        assert!(
            !recovery_request_entitled(
                &auth(alice, "a1", "replace"),
                &sibling_leaves,
                None,
                false,
                alice,
                "a1",
            ),
            "own device never fulfills its own replace"
        );
        assert!(
            !entitled(&auth(alice, "a1", "add"), Some(&roster), true),
            "never its own"
        );
        assert!(
            !entitled(&auth(bob, "b1", "add"), None, false),
            "add of a held leaf"
        );
        assert!(
            !entitled(&auth(carol, "c1", "add"), None, true),
            "zero-leaf without a roster"
        );
        assert!(
            !entitled(&auth(carol, "c1", "add"), Some(&roster), true),
            "pending"
        );
        apply_roster_effects(
            &mut roster,
            SignedMutationKind::ParticipantAcceptance,
            &json!({ "actorDid": carol }),
        );
        assert!(
            !entitled(&auth(carol, "c1", "add"), Some(&roster), false),
            "active roster state alone"
        );
        assert!(
            entitled(&auth(carol, "c1", "add"), Some(&roster), true),
            "verified accepted zero-leaf"
        );

        assert!(matches!(
            require_active_admin(None, alice, CONVERSATION),
            Err(MLSError::RosterUnverified { .. })
        ));
        assert!(require_active_admin(Some(&roster), alice, CONVERSATION).is_ok());
        assert!(matches!(
            require_active_admin(Some(&roster), bob, CONVERSATION),
            Err(MLSError::InsufficientPermissions { .. })
        ));
        apply_roster_effects(
            &mut roster,
            SignedMutationKind::PolicyTransition,
            &json!({ "participantChanges": [
                { "$type": "blue.catbird.chat.defs#changeParticipantRole", "userDid": alice, "role": "member" },
                { "$type": "blue.catbird.chat.defs#changeParticipantRole", "userDid": bob, "role": "admin" },
                { "$type": "blue.catbird.chat.defs#removeParticipant", "userDid": carol },
            ]}),
        );
        assert!(require_active_admin(Some(&roster), alice, CONVERSATION).is_err());
        assert!(require_active_admin(Some(&roster), bob, CONVERSATION).is_ok());
        assert!(!roster_active(Some(&roster), carol));

        let Extension::Unknown(kind, UnknownExtension(bytes)) =
            roster_attestation_extension(CONVERSATION, 2, &roster).unwrap()
        else {
            panic!("roster attestation is a private-use extension");
        };
        assert_eq!(kind, ROSTER_ATTESTATION_EXTENSION_TYPE);
        let leaf_dids = [alice.to_owned()];
        assert_eq!(
            attested_roster(&bytes, CONVERSATION, 2, bob, &leaf_dids).unwrap(),
            roster
        );
        assert!(attested_roster(&bytes, CONVERSATION, 3, bob, &leaf_dids).is_err());
        assert!(attested_roster(&bytes, CONVERSATION, 2, carol, &leaf_dids).is_err());

        let coordinate = |version: i64| {
            json!({
                "conversationId": CONVERSATION, "generation": 1, "stateVersion": version,
                "groupId": { "$bytes": STANDARD.encode([1u8; 32]) }, "epoch": 4,
                "groupContextHash": { "$bytes": STANDARD.encode([2u8; 32]) },
                "confirmationTag": { "$bytes": STANDARD.encode([3u8; 32]) }, "lifecycle": "active",
            })
        };
        let view = json!({
            "recoveryRequestId": ENTRY, "conversationId": CONVERSATION, "requesterDid": bob,
            "requesterDeviceId": "b2", "status": "open", "boundCoordinate": coordinate(5),
            "expiresAt": "2026-11-07T00:05:00.000Z",
        });
        assert!(own_leaf_recovery_record(&view, CONVERSATION, carol, "b2").is_err());
        let record = own_leaf_recovery_record(&view, CONVERSATION, bob, "b2").unwrap();
        let expires = record["expiresAtMs"].as_i64().unwrap();
        assert!(own_leaf_recovery_open(
            &record,
            &coordinate(5),
            CONVERSATION,
            expires - 1
        ));
        assert!(!own_leaf_recovery_open(
            &record,
            &coordinate(5),
            CONVERSATION,
            expires
        ));
        assert!(!own_leaf_recovery_open(
            &record,
            &coordinate(6),
            CONVERSATION,
            expires - 1
        ));
    }

    #[test]
    fn pending_invitation_round_trips_only_in_its_member_attested_generation() {
        let provenance = json!({
            "$type": "blue.catbird.chat.defs#invitationProvenance",
            "invitationTransitionId": "00000000-0000-4000-8000-0000000000aa",
            "invitedByDid": "did:plc:alice",
            "invitedByDeviceId": "00000000-0000-4000-8000-0000000000a1",
        });
        let roster = roster_from_participants(&json!([
            { "userDid": "did:plc:alice", "role": "admin", "status": "active" },
            {
                "userDid": "did:plc:carol",
                "role": "member",
                "status": "pending",
                "invitationProvenance": provenance,
            },
        ]))
        .unwrap();
        assert!(roster_has_pending_invitation(
            Some(&roster),
            "did:plc:carol",
            &provenance
        ));
        let Extension::Unknown(_, UnknownExtension(bytes)) =
            roster_attestation_extension(CONVERSATION, 7, &roster).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            attested_roster(
                &bytes,
                CONVERSATION,
                7,
                "did:plc:alice",
                &["did:plc:alice".into()]
            )
            .unwrap(),
            roster
        );
        assert!(attested_roster(
            &bytes,
            "00000000-0000-4000-8000-0000000000ff",
            7,
            "did:plc:alice",
            &["did:plc:alice".into()]
        )
        .is_err());
        assert!(attested_roster(
            &bytes,
            CONVERSATION,
            8,
            "did:plc:alice",
            &["did:plc:alice".into()]
        )
        .is_err());
    }

    #[test]
    fn peer_send_counter_boundaries_reject_replay_rollback_corruption_and_safe_int_overflow() {
        const MAX_SAFE: u64 = 9_007_199_254_740_991;
        verify_next_peer_send_counter(None, 0).unwrap();
        verify_next_peer_send_counter(None, 1).unwrap();
        verify_next_peer_send_counter(None, MAX_SAFE).unwrap();
        assert!(matches!(
            verify_next_peer_send_counter(None, MAX_SAFE + 1),
            Err(MLSError::Cryptography(_))
        ));

        verify_next_peer_send_counter(Some("5"), 6).unwrap();
        verify_next_peer_send_counter(Some("5"), MAX_SAFE).unwrap();
        assert!(matches!(
            verify_next_peer_send_counter(Some("5"), 5),
            Err(MLSError::Cryptography(_))
        ));
        assert!(matches!(
            verify_next_peer_send_counter(Some("5"), 4),
            Err(MLSError::Cryptography(_))
        ));
        assert!(matches!(
            verify_next_peer_send_counter(Some("5"), MAX_SAFE + 1),
            Err(MLSError::Cryptography(_))
        ));
        assert!(matches!(
            verify_next_peer_send_counter(Some("corrupt"), 6),
            Err(MLSError::Internal(_))
        ));
    }

    #[test]
    fn control_sequencer_receipt_rejects_every_field_and_signature_mismatch() {
        let signer = receipt_signer(3);
        let key = sec1(&signer);
        let actor_did = "did:plc:sender";
        let actor_dev = "device";
        let request_digest = [9u8; 32];
        let receipt = signed_receipt(&signer, &format!("{SEQUENCER}#mls-receipt-1"), 4);
        let coord = json!({
            "conversationId": CONVERSATION,
            "generation": 0,
            "stateVersion": 1,
            "groupId": { "$bytes": STANDARD.encode([7u8; 32]) },
            "epoch": 3,
            "groupContextHash": { "$bytes": STANDARD.encode([2u8; 32]) },
            "confirmationTag": { "$bytes": STANDARD.encode([3u8; 32]) },
            "lifecycle": "active",
        });

        verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .unwrap();

        // Wrong sequencer, conversation, entry_id, entry_seq, actor_did, actor_device_id, digest.
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            "did:web:other.example.com",
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            "44444444-4444-4444-8444-444444444444",
            4,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            5,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            "did:plc:other",
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            "other-device",
            &coord,
            &request_digest,
        )
        .is_err());
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &coord,
            &[8u8; 32],
        )
        .is_err());

        // Coordinate generation, epoch, and groupId mismatches fail closed.
        let mut wrong_gen = coord.clone();
        wrong_gen["generation"] = json!(1);
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &wrong_gen,
            &request_digest,
        )
        .is_err());

        let mut wrong_epoch = coord.clone();
        wrong_epoch["epoch"] = json!(4);
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &wrong_epoch,
            &request_digest,
        )
        .is_err());

        let mut wrong_group = coord.clone();
        wrong_group["groupId"] = json!({ "$bytes": STANDARD.encode([6u8; 32]) });
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &key,
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &wrong_group,
            &request_digest,
        )
        .is_err());

        // Wrong P-256 verifying key fails closed.
        assert!(verify_control_sequencer_receipt(
            &receipt,
            &sec1(&receipt_signer(9)),
            SEQUENCER,
            CONVERSATION,
            ENTRY,
            4,
            actor_did,
            actor_dev,
            &coord,
            &request_digest,
        )
        .is_err());
    }

    #[test]
    fn own_commit_body_verification_rejects_wrong_signer_missing_kind_and_tampered_fields() {
        use openmls_traits::types::SignatureScheme;

        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let other_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let cid = "00000000-0000-4000-8000-00000000c501";
        let dev = "00000000-0000-4000-8000-00000000d501";
        let op_id = "00000000-0000-4000-8000-00000000e501";
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
        let prepared = sign_clean_chat_mutation(
            did,
            dev,
            Some(1),
            CanonicalOperation::CreateConversation,
            &body,
            &signer,
        )
        .unwrap();
        let submitted: Value = serde_json::from_slice(&prepared.body.unwrap()).unwrap();
        let signed = &submitted["signedRequest"];

        let verified = verify_own_commit_body(signed, signer.public()).unwrap();
        assert_eq!(verified["conversationId"], cid);
        assert_eq!(verified["actorDid"], did);
        assert_eq!(verified["actorDeviceId"], dev);

        assert!(verify_own_commit_body(signed, other_signer.public()).is_err());

        let mut missing_kind = signed.clone();
        missing_kind["body"]
            .as_object_mut()
            .unwrap()
            .remove("$type");
        assert!(verify_own_commit_body(&missing_kind, signer.public()).is_err());

        let mut unknown_kind = signed.clone();
        unknown_kind["body"]["$type"] = json!("blue.catbird.chat.defs#unknownKind");
        assert!(verify_own_commit_body(&unknown_kind, signer.public()).is_err());

        let mut tampered_actor = signed.clone();
        tampered_actor["body"]["actorDeviceId"] = json!("00000000-0000-4000-8000-00000000d999");
        assert!(verify_own_commit_body(&tampered_actor, signer.public()).is_err());

        let mut tampered_epoch = signed.clone();
        tampered_epoch["body"]["next"]["epoch"] = json!(1);
        assert!(verify_own_commit_body(&tampered_epoch, signer.public()).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn leaf_slice_verification_requires_exact_authorized_did_device_and_key() {
        let did = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        let dev = "11111111-1111-4111-8111-111111111111";
        let key = vec![0x42u8; 32];
        let cred = format!("{did}#{dev}");
        let authorized = vec![crate::push::AuthorizedPeerDeviceKey {
            did: did.to_owned(),
            device_id: dev.to_owned(),
            signature_public_key: key.clone(),
        }];

        let (out_did, out_dev) = verify_leaf_slice_i4(cred.as_bytes(), &key, &authorized).unwrap();
        assert_eq!(out_did, did);
        assert_eq!(out_dev, dev);

        // Empty authorized list fails closed when TOFU calibration bug is not enabled.
        assert!(verify_leaf_slice_i4(cred.as_bytes(), &key, &[]).is_err());
        // Wrong key, wrong device, wrong DID, and un-scoped credential all fail closed.
        assert!(verify_leaf_slice_i4(cred.as_bytes(), &[0x99u8; 32], &authorized).is_err());
        assert!(verify_leaf_slice_i4(
            format!("{did}#22222222-2222-4222-8222-222222222222").as_bytes(),
            &key,
            &authorized
        )
        .is_err());
        assert!(verify_leaf_slice_i4(
            format!("did:plc:bobbbbbbbbbbbbbbbbbbbbbb#{dev}").as_bytes(),
            &key,
            &authorized
        )
        .is_err());
        assert_eq!(
            verify_leaf_slice_i4(did.as_bytes(), &key, &authorized).unwrap(),
            (did.to_string(), String::new())
        );
        assert!(verify_leaf_slice_i4(b"not-a-did", &key, &authorized).is_err());
        assert!(verify_leaf_slice_i4(&[0xff, 0xfe], &key, &authorized).is_err());
    }

    #[test]
    fn account_deleted_entry_key_id_and_signature_reject_all_boundary_mutations() {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::{Signature, SigningKey};

        let key = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let pub_sec1 = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let other_sec1 = SigningKey::from_slice(&[6u8; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let deleted = "did:plc:deleteduseraaaaaaaaaaaaa";
        let received_at = "2026-11-15T00:00:00.000Z";
        let key_id = format!("{SEQUENCER}#mls-receipt-1");
        let fields = [SEQUENCER, CONVERSATION, deleted, "1", ENTRY, received_at];
        let transcript = account_deletion_authority_signing_bytes(&key_id, &fields).unwrap();
        let sig: Signature = key.sign(&transcript);
        let sig_bytes = sig.normalize_s().unwrap_or(sig).to_bytes().to_vec();

        let valid = json!({
            "$type": crate::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND,
            "conversationId": CONVERSATION,
            "sequencerDid": SEQUENCER,
            "seq": 1,
            "deletedDid": deleted,
            "entryId": ENTRY,
            "receivedAt": received_at,
            "sequencerAuthority": {
                "sequencerDid": SEQUENCER,
                "keyId": key_id,
                "signature": { "$bytes": STANDARD.encode(&sig_bytes) },
            }
        });

        assert_eq!(
            account_deleted_entry_key_id(CONVERSATION, SEQUENCER, &valid),
            Some(key_id.as_str())
        );
        assert_eq!(
            verify_account_deleted_entry_signature(
                CONVERSATION,
                &format!("{SEQUENCER}#atproto_mls"),
                &valid,
                &pub_sec1,
            ),
            Some((deleted.to_owned(), 1))
        );

        let mut without_type = valid.clone();
        without_type.as_object_mut().unwrap().remove("$type");
        assert_eq!(
            verify_account_deleted_entry_signature(
                CONVERSATION,
                SEQUENCER,
                &without_type,
                &pub_sec1
            ),
            Some((deleted.to_owned(), 1))
        );

        for invalid_seq in [json!(0), json!(-1)] {
            let mut bad = valid.clone();
            bad["seq"] = invalid_seq;
            assert!(account_deleted_entry_key_id(CONVERSATION, SEQUENCER, &bad).is_none());
            assert!(verify_account_deleted_entry_signature(
                CONVERSATION,
                SEQUENCER,
                &bad,
                &pub_sec1
            )
            .is_none());
        }

        let mut wrong_type = valid.clone();
        wrong_type["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
        assert!(account_deleted_entry_key_id(CONVERSATION, SEQUENCER, &wrong_type).is_none());

        for field in ["deletedDid", "entryId", "receivedAt"] {
            let mut empty_field = valid.clone();
            empty_field[field] = json!("");
            assert!(account_deleted_entry_key_id(CONVERSATION, SEQUENCER, &empty_field).is_none());
        }

        let mut wrong_auth_seq = valid.clone();
        wrong_auth_seq["sequencerAuthority"]["sequencerDid"] = json!("did:web:other.example.com");
        assert!(account_deleted_entry_key_id(CONVERSATION, SEQUENCER, &wrong_auth_seq).is_none());

        assert!(verify_account_deleted_entry_signature(
            CONVERSATION,
            SEQUENCER,
            &valid,
            &other_sec1
        )
        .is_none());
    }

    #[test]
    fn pds_device_revocation_record_signs_canonical_dagcbor_and_verifies_enrolled_actors() {
        use openmls_traits::types::SignatureScheme;

        let repo_did = "did:plc:aliceaaaaaaaaaaaaaaaaaaa";
        let dev1 = "11111111-1111-4111-8111-111111111111";
        let dev2 = "22222222-2222-4222-8222-222222222222";
        let signer1 = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let signer2 = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let rogue_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();

        let mut enrolled = BTreeMap::new();
        enrolled.insert(dev1.to_owned(), signer1.public().to_vec());
        enrolled.insert(dev2.to_owned(), signer2.public().to_vec());

        // Sibling revocation (dev1 revoking dev2) verifies cleanly.
        let body_bytes = build_pds_device_revocation_create_record_body_at(
            repo_did,
            dev1,
            dev2,
            "2026-11-15T00:00:00.000Z",
            &signer1,
            Some("revoked_by_sibling"),
        )
        .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body_json["collection"],
            "blue.catbird.chat.deviceRevocation"
        );
        assert_eq!(body_json["rkey"], dev2);
        let record_val = &body_json["record"];
        assert_eq!(
            verify_pds_device_revocation_record(repo_did, dev2, record_val, &enrolled).unwrap(),
            dev2
        );

        // Self-retirement (dev2 retiring dev2) also verifies cleanly.
        let self_bytes = build_pds_device_revocation_create_record_body_at(
            repo_did,
            dev2,
            dev2,
            "2026-11-15T00:01:00.000Z",
            &signer2,
            Some("retired"),
        )
        .unwrap();
        let self_json: Value = serde_json::from_slice(&self_bytes).unwrap();
        assert_eq!(
            verify_pds_device_revocation_record(repo_did, dev2, &self_json["record"], &enrolled)
                .unwrap(),
            dev2
        );

        // Wrong rkey, wrong repo_did, rogue signer, or tampered createdAt all fail closed.
        assert!(
            verify_pds_device_revocation_record(repo_did, dev1, record_val, &enrolled).is_err()
        );
        assert!(verify_pds_device_revocation_record(
            "did:plc:bobbbbbbbbbbbbbbbbbbbbbb",
            dev2,
            record_val,
            &enrolled
        )
        .is_err());

        let rogue_bytes = build_pds_device_revocation_create_record_body_at(
            repo_did,
            dev1,
            dev2,
            "2026-11-15T00:00:00.000Z",
            &rogue_signer,
            None,
        )
        .unwrap();
        let rogue_json: Value = serde_json::from_slice(&rogue_bytes).unwrap();
        assert!(verify_pds_device_revocation_record(
            repo_did,
            dev2,
            &rogue_json["record"],
            &enrolled
        )
        .is_err());

        let mut tampered_ts = record_val.clone();
        tampered_ts["createdAt"] = json!("2026-11-15T00:00:01.000Z");
        assert!(
            verify_pds_device_revocation_record(repo_did, dev2, &tampered_ts, &enrolled).is_err()
        );
    }
}

#[cfg(test)]
#[path = "chat_wire_unit_tests.rs"]
mod chat_wire_unit_tests;
