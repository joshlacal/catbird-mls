//! Durable pairing of a staged MLS Commit and its exact signed request.
//!
//! A journal row means transmission may have happened. Neither a timeout nor a
//! later 4xx authorizes discarding its pending crypto. Confirmed replies are
//! persisted before merging, so restart can finish a partially applied Commit.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::canonical_transport::{CanonicalOperation, PreparedRequest};
use super::error::{OrchestratorError, Result};
use super::types::GroupState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedControlRecord {
    pub conversation_id: String,
    pub group_id: String,
    pub actor_did: String,
    pub actor_device_id: String,
    pub transition_id: String,
    pub prior: Value,
    pub prior_snapshot_seq: Option<u64>,
    pub next: Value,
    pub projection: GroupState,
    pub request_body: Vec<u8>,
    pub request_sha256: [u8; 32],
    pub commit_sha256: Vec<u8>,
    #[serde(deserialize_with = "read_expected_entry_type")]
    pub expected_entry_type: String,
    /// Exact validated HTTP response, persisted before local merge.
    pub confirmed_response: Option<Vec<u8>>,
    /// An actual canonical entry read from GetEntries, distinct from an HTTP ACK.
    pub confirmed_entry: Option<Vec<u8>>,
    /// Fresh state plus every contiguous entry since the original snapshot.
    pub nonacceptance_proof: Option<Value>,
    /// Set durably before the first transport call; restart must assume ambiguity.
    pub attempted: bool,
    /// Earlier v1 records stored a visible first 4xx here. A transport call may
    /// hide HTTP retries, so this field has no authority: accept and discard it
    /// while decoding, and omit it from canonical comparison and future writes.
    #[serde(
        default,
        rename = "definitive_rejection",
        skip_serializing,
        deserialize_with = "ignore_legacy_rejection"
    )]
    legacy_rejection: (),
    /// Applied records remain as durable own-Commit proof after pending removal.
    /// Retain until a durable server-cursor contract can prove echoes will never
    /// replay; a wall-clock TTL would erase restart authority prematurely.
    pub completed: bool,
}

fn ignore_legacy_rejection<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<(), D::Error> {
    let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(())
}

fn read_expected_entry_type<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    // Correct only the old internal label. Retained signed requests and any
    // acceptance proofs remain byte-for-byte intact and are revalidated below.
    Ok(if value == "blue.catbird.chat.defs#commitTransitionEntry" {
        "blue.catbird.chat.defs#commitEntry".into()
    } else {
        value
    })
}

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::Storage(format!("prepared control journal: {message}"))
}
fn text(value: &Value, name: &str) -> Result<String> {
    value[name]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("missing {name}")))
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    value
        .as_str()
        .or_else(|| value["$bytes"].as_str())
        .and_then(|s| STANDARD.decode(s).ok())
        .ok_or_else(|| invalid("invalid encoded bytes"))
}

impl PreparedControlRecord {
    pub fn new(prepared: PreparedRequest, projection: GroupState) -> Result<Self> {
        if prepared.operation != CanonicalOperation::SubmitTransition
            || prepared.method != "POST"
            || prepared.path != CanonicalOperation::SubmitTransition.path()
        {
            return Err(invalid("unsupported prepared control route"));
        }
        let request_body = prepared
            .body
            .ok_or_else(|| invalid("missing prepared body"))?;
        let request: Value = serde_json::from_slice(&request_body)
            .map_err(|_| invalid("malformed prepared request"))?;
        let body = &request["signedRequest"]["body"];
        // The pinned bytes retain the endpoint, signature, and idempotency key;
        // extracting coordinates here never serializes or signs a replacement.
        let expected_entry_type = match body["$type"].as_str() {
            Some("blue.catbird.chat.defs#leaveCommitFulfillmentBody") => {
                "blue.catbird.chat.defs#leaveCommitFulfillmentEntry"
            }
            Some("blue.catbird.chat.defs#leafRecoveryFulfillmentBody") => {
                "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
            }
            Some("blue.catbird.chat.defs#commitTransitionBody")
                if body["manifest"]["participantChanges"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                    && body["manifest"].get("welcomeBundle").is_none()
                    && body["manifest"]["leafChanges"]
                        .as_array()
                        .is_some_and(|changes| {
                            !changes.is_empty()
                                && changes.iter().all(|change| {
                                    change["$type"] == "blue.catbird.chat.defs#removeLeaf"
                                })
                        }) =>
            {
                "blue.catbird.chat.defs#commitEntry"
            }
            _ => return Err(invalid("unsupported control body")),
        }
        .to_owned();
        let conversation_id = text(&body["prior"], "conversationId")?;
        let prior = super::lifecycle::lifecycle_coordinates(&body["prior"], &conversation_id)?;
        let next = super::lifecycle::lifecycle_coordinates(&body["next"], &conversation_id)?;
        let group_id = hex::encode(bytes(&prior["groupId"])?);
        let transition_id = text(body, "transitionId")?;
        uuid::Uuid::parse_str(&transition_id).map_err(|_| invalid("invalid transition id"))?;
        if body["idempotencyKey"] != transition_id
            || prior["generation"] != next["generation"]
            || prior["groupId"] != next["groupId"]
            || prior["lifecycle"] != "active"
            || next["lifecycle"] != "active"
            || prior["epoch"].as_u64().and_then(|n| n.checked_add(1)) != next["epoch"].as_u64()
            || prior["stateVersion"]
                .as_u64()
                .and_then(|n| n.checked_add(1))
                != next["stateVersion"].as_u64()
            || projection.conversation_id != conversation_id
            || projection.group_id != group_id
            || Some(projection.epoch) != next["epoch"].as_u64()
        {
            return Err(invalid("projection does not bind the exact successor"));
        }
        let commit = bytes(&body["commit"]["bytes"])?;
        let commit_sha256 = bytes(&body["commit"]["sha256"])?;
        if Sha256::digest(&commit).as_slice() != commit_sha256
            || bytes(&request["signedRequest"]["signature"])?.len() != 64
        {
            return Err(invalid("commit or signature binding is invalid"));
        }
        Ok(Self {
            actor_did: text(body, "actorDid")?,
            actor_device_id: text(body, "actorDeviceId")?,
            conversation_id,
            group_id,
            transition_id,
            prior,
            prior_snapshot_seq: None,
            next,
            projection,
            request_sha256: Sha256::digest(&request_body).into(),
            request_body,
            commit_sha256,
            expected_entry_type,
            confirmed_response: None,
            confirmed_entry: None,
            nonacceptance_proof: None,
            attempted: false,
            legacy_rejection: (),
            completed: false,
        })
    }

    pub fn prepared_request(&self) -> PreparedRequest {
        PreparedRequest {
            operation: CanonicalOperation::SubmitTransition,
            method: "POST".into(),
            path: CanonicalOperation::SubmitTransition.path().into(),
            body: Some(self.request_body.clone()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let mut rebuilt = Self::new(self.prepared_request(), self.projection.clone())?;
        if self
            .prior_snapshot_seq
            .is_some_and(|seq| seq > 9_007_199_254_740_991)
        {
            return Err(invalid("invalid prior snapshot sequence"));
        }
        rebuilt.prior_snapshot_seq = self.prior_snapshot_seq;
        if self.immutable_bytes()? != rebuilt.immutable_bytes()? {
            return Err(invalid("stored request binding changed"));
        }
        if let Some(response) = &self.confirmed_response {
            self.validate_response(response)?;
        }
        if let Some(entry) = &self.confirmed_entry {
            self.validate_entry(entry)?;
        }
        if let Some(proof) = &self.nonacceptance_proof {
            self.validate_nonacceptance(proof)?;
        }
        if (self.has_acceptance() || self.nonacceptance_proof.is_some()) && !self.attempted {
            return Err(invalid("outcome without attempted marker"));
        }
        if self.nonacceptance_proof.is_some() && (self.has_acceptance() || self.completed) {
            return Err(invalid("invalid rejected phase"));
        }
        if self.completed && !self.has_acceptance() {
            return Err(invalid("completed without confirmed response"));
        }
        Ok(())
    }

    fn immutable_bytes(&self) -> Result<Vec<u8>> {
        let mut copy = self.clone();
        copy.confirmed_response = None;
        copy.confirmed_entry = None;
        copy.nonacceptance_proof = None;
        copy.completed = false;
        copy.attempted = false;
        serde_json::to_vec(&copy).map_err(|_| invalid("cannot serialize record"))
    }

    fn has_acceptance(&self) -> bool {
        self.confirmed_response.is_some() || self.confirmed_entry.is_some()
    }

    fn validate_entry(&self, entry: &[u8]) -> Result<Value> {
        let entry: Value = serde_json::from_slice(entry)
            .map_err(|_| invalid("malformed retained canonical entry"))?;
        let coordinates = super::lifecycle::lifecycle_coordinates(
            &entry["signedRequest"]["body"]["next"],
            &self.conversation_id,
        )?;
        let output = serde_json::json!({"coordinates":coordinates,"entry":entry});
        self.validate_response(
            &serde_json::to_vec(&output).map_err(|_| invalid("entry projection failed"))?,
        )
    }

    fn validate_nonacceptance(&self, proof: &Value) -> Result<()> {
        if let Some(terminal) = proof.get("terminalError") {
            let status = terminal["status"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| invalid("invalid terminal status"))?;
            let body: Vec<u8> = serde_json::from_value(terminal["body"].clone())
                .map_err(|_| invalid("invalid retained terminal response"))?;
            if !self.terminal_error_proves_nonacceptance(status, &body)
                || super::lifecycle::lifecycle_coordinates(
                    &proof["state"]["state"]["coordinates"],
                    &self.conversation_id,
                )? != self.prior
            {
                return Err(invalid(
                    "terminal response does not prove unchanged-coordinate nonacceptance",
                ));
            }
            return Ok(());
        }
        let after = self
            .prior_snapshot_seq
            .ok_or_else(|| invalid("missing original snapshot sequence"))?;
        let state = &proof["state"]["state"];
        let coordinate =
            super::lifecycle::lifecycle_coordinates(&state["coordinates"], &self.conversation_id)?;
        let snapshot = state["snapshotSeq"]
            .as_u64()
            .filter(|seq| *seq <= 9_007_199_254_740_991)
            .ok_or_else(|| invalid("invalid fresh snapshot sequence"))?;
        if coordinate["groupId"] != self.prior["groupId"]
            || coordinate["generation"] != self.prior["generation"]
            || coordinate["stateVersion"].as_u64() <= self.prior["stateVersion"].as_u64()
            || coordinate["epoch"].as_u64() < self.prior["epoch"].as_u64()
            || snapshot <= after
        {
            return Err(invalid(
                "fresh state does not make original coordinate obsolete",
            ));
        }
        let entries = proof["entries"]
            .as_array()
            .ok_or_else(|| invalid("missing contiguous entry proof"))?;
        if entries.len() > super::pagination::MAX_MESSAGE_ITEMS {
            return Err(invalid("entry proof exceeds bound"));
        }
        let mut seq = after;
        for entry in entries {
            seq = seq
                .checked_add(1)
                .ok_or_else(|| invalid("entry sequence overflow"))?;
            if entry["seq"].as_u64() != Some(seq)
                || entry["conversationId"] != self.conversation_id
                || entry["signedRequest"]["body"]["transitionId"] == self.transition_id
                || entry["signedRequest"]["body"]["idempotencyKey"] == self.transition_id
            {
                return Err(invalid(
                    "entry proof has a gap or includes the attempted transition",
                ));
            }
        }
        if seq != snapshot {
            return Err(invalid("entry proof does not reach fresh snapshot"));
        }
        Ok(())
    }

    fn terminal_error_proves_nonacceptance(&self, status: u16, body: &[u8]) -> bool {
        if !(400..500).contains(&status) {
            return false;
        }
        let Ok(error) = serde_json::from_slice::<Value>(body) else {
            return false;
        };
        // These codes can only originate after exact global operation
        // arbitration. Accepted replay returns its retained success before
        // work expiry checks. NotFound is intentionally excluded: missing
        // replay graph rows can produce it and do not prove nonacceptance.
        if error["error"].as_str() == Some("SignedOperationExpired") {
            return true;
        }
        match (self.expected_entry_type.as_str(), error["error"].as_str()) {
            (
                "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
                Some("LeafRecoveryExpired" | "LeafRecoverySuperseded"),
            )
            | ("blue.catbird.chat.defs#leaveCommitFulfillmentEntry", Some("LeaveRequestExpired")) => {
                true
            }
            _ => false,
        }
    }

    pub fn validate_response(&self, bytes: &[u8]) -> Result<Value> {
        let output: Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed control ACK"))?;
        if super::lifecycle::lifecycle_coordinates(&output["coordinates"], &self.conversation_id)?
            != self.next
            || output["entry"]["conversationId"] != self.conversation_id
            || output["entry"]["$type"] != self.expected_entry_type
        {
            return Err(invalid("ACK does not confirm the exact transition"));
        }
        // The row identity is independent of the signed operation identity.
        // Exact signed-request equality below supplies operation correlation.
        let entry_id = text(&output["entry"], "entryId")?;
        super::canonical_transport::validate_uuid(&entry_id, "entryId")
            .map_err(|_| invalid("invalid canonical entry id"))?;
        if !output["entry"]["seq"]
            .as_u64()
            .is_some_and(|seq| (1..=9_007_199_254_740_991).contains(&seq))
        {
            return Err(invalid("invalid canonical entry sequence"));
        }
        let submitted: Value = serde_json::from_slice(&self.request_body)
            .map_err(|_| invalid("malformed retained request"))?;
        let normalize = |mut signed: Value| -> Value {
            if let Some(object) = signed.as_object_mut() {
                object.remove("$type");
            }
            // Simple-ref generated DTOs omit a redundant body type; the signed
            // body schema is already fixed by the retained entry kind.
            if signed["body"]["$type"].is_null() {
                signed["body"]["$type"] = submitted["signedRequest"]["body"]["$type"].clone();
            }
            normalize_bytes(signed)
        };
        if output["entry"]["signedRequest"].is_null()
            || normalize(output["entry"]["signedRequest"].clone())
                != normalize(submitted["signedRequest"].clone())
        {
            return Err(invalid("ACK signed request differs from retained envelope"));
        }
        Ok(output)
    }
}

fn normalize_bytes(value: Value) -> Value {
    match value {
        Value::Object(mut map)
            if map.len() == 1 && map.get("$bytes").is_some_and(Value::is_string) =>
        {
            map.remove("$bytes").unwrap()
        }
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, normalize_bytes(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_bytes).collect()),
        value => value,
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use super::*;
    use crate::{error::MLSError, mls_context::ManifestStorage};
    use std::collections::BTreeMap;
    const KEY: &str = "prepared_control_journal_v1";
    #[derive(Default, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        pending: BTreeMap<String, PreparedControlRecord>,
        completed: BTreeMap<String, PreparedControlRecord>,
    }
    fn checked(
        storage: &ManifestStorage,
    ) -> std::result::Result<(Option<String>, Journal), MLSError> {
        let raw: Option<Value> = storage.read_manifest(KEY)?;
        let old = raw
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| MLSError::SerializationError)?;
        let journal: Journal = raw
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| MLSError::SerializationError)?
            .unwrap_or_default();
        for (group, record) in &journal.pending {
            if record.completed || &record.group_id != group {
                return Err(MLSError::StorageFailed);
            }
            record.validate().map_err(|_| MLSError::StorageFailed)?;
        }
        for (id, record) in &journal.completed {
            if !record.completed || &record.transition_id != id {
                return Err(MLSError::StorageFailed);
            }
            record.validate().map_err(|_| MLSError::StorageFailed)?;
        }
        Ok((old, journal))
    }
    pub(crate) fn put(
        storage: &ManifestStorage,
        record: &PreparedControlRecord,
    ) -> std::result::Result<(), MLSError> {
        record.validate().map_err(|_| MLSError::StorageFailed)?;
        for _ in 0..8 {
            let (old, mut journal) = checked(storage)?;
            if let Some(existing) = journal
                .completed
                .get(&record.transition_id)
                .or_else(|| journal.pending.get(&record.group_id))
            {
                if existing
                    .immutable_bytes()
                    .map_err(|_| MLSError::StorageFailed)?
                    != record
                        .immutable_bytes()
                        .map_err(|_| MLSError::StorageFailed)?
                    || existing
                        .confirmed_entry
                        .as_ref()
                        .is_some_and(|entry| Some(entry) != record.confirmed_entry.as_ref())
                    || existing
                        .nonacceptance_proof
                        .as_ref()
                        .is_some_and(|proof| Some(proof) != record.nonacceptance_proof.as_ref())
                    || existing.completed && !record.completed
                    || existing.attempted && !record.attempted
                    || existing
                        .confirmed_response
                        .as_ref()
                        .is_some_and(|ack| Some(ack) != record.confirmed_response.as_ref())
                {
                    return Err(MLSError::StorageFailed);
                }
            } else if record.completed
                || record.has_acceptance()
                || record.nonacceptance_proof.is_some()
            {
                return Err(MLSError::StorageFailed);
            }
            if record.completed && journal.completed.contains_key(&record.transition_id) {
                // An old completion retry must never remove a newer pending
                // operation on the same group.
                return storage.flush_database();
            }
            if record.completed {
                journal.pending.remove(&record.group_id);
                journal
                    .completed
                    .insert(record.transition_id.clone(), record.clone());
            } else {
                journal
                    .pending
                    .insert(record.group_id.clone(), record.clone());
            }
            // Serialize through Value so CAS uses the same canonical key order
            // as the read path. The stored payload itself retains raw request bytes.
            let next = serde_json::to_value(&journal).map_err(|_| MLSError::SerializationError)?;
            if storage.compare_exchange_manifest(KEY, old.as_deref(), &next)? {
                return storage.flush_database();
            }
        }
        Err(MLSError::StorageFailed)
    }
    pub(crate) fn remove_rejected(
        storage: &ManifestStorage,
        group: &str,
        transition: &str,
    ) -> std::result::Result<(), MLSError> {
        for _ in 0..8 {
            let (old, mut journal) = checked(storage)?;
            let Some(record) = journal.pending.get(group) else {
                return Ok(());
            };
            if record.transition_id != transition || record.nonacceptance_proof.is_none() {
                return Err(MLSError::StorageFailed);
            }
            journal.pending.remove(group);
            let next = serde_json::to_value(&journal).map_err(|_| MLSError::SerializationError)?;
            if storage.compare_exchange_manifest(KEY, old.as_deref(), &next)? {
                return storage.flush_database();
            }
        }
        Err(MLSError::StorageFailed)
    }
    pub(crate) fn get(
        storage: &ManifestStorage,
        group: &str,
    ) -> std::result::Result<Option<PreparedControlRecord>, MLSError> {
        Ok(checked(storage)?.1.pending.remove(group))
    }
    pub(crate) fn list(
        storage: &ManifestStorage,
    ) -> std::result::Result<Vec<PreparedControlRecord>, MLSError> {
        let (_, journal) = checked(storage)?;
        Ok(journal
            .pending
            .into_values()
            .chain(journal.completed.into_values())
            .collect())
    }
}

use super::{
    api_client::MLSAPIClient,
    credentials::CredentialStore,
    mls_provider::MlsCryptoContext,
    orchestrator::{
        MLSOrchestrator, OwnCommitExpectation, PendingCommitMeta, StagedCommitKindSummary,
    },
    storage::MLSStorageBackend,
};
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Offline initialization, before public APIs become Ready. Only records
    /// for this actor and the currently stored group restore authority or a
    /// staging blocker. Retired-group evidence remains durable without fencing
    /// the successor conversation after reset/account-device rotation.
    pub(crate) async fn hydrate_prepared_control_journal(&self, user_did: &str) -> Result<()> {
        let records = self.mls_context().list_prepared_controls()?;
        if records.is_empty() {
            return Ok(());
        }
        let device = self.credentials().get_device_uuid(user_did).await?;
        for record in records {
            record.validate()?;
            if record.actor_did != user_did || Some(&record.actor_device_id) != device.as_ref() {
                continue;
            }
            let state = self
                .storage()
                .get_conversation_state(&record.conversation_id)
                .await?;
            if matches!(
                state,
                Some(
                    super::types::ConversationState::DeviceRemoved
                        | super::types::ConversationState::Closed
                )
            ) || (record.completed
                && matches!(
                    state,
                    Some(super::types::ConversationState::ResetPending { .. })
                ))
            {
                continue;
            }
            let binding = self
                .storage()
                .get_conversation(user_did, &record.conversation_id)
                .await?;
            if !binding
                .as_ref()
                .is_some_and(|view| view.group_id == record.group_id)
            {
                continue;
            }
            if !record.completed {
                self.restore_control_blocker(&record).await;
                continue;
            }
            self.track_epoch_changing_own_commit(
                record.commit_sha256.clone(),
                OwnCommitExpectation {
                    conversation_id: record.conversation_id.clone(),
                    group_id: record.group_id.clone(),
                    target_epoch: record.projection.epoch,
                },
            )
            .await;
        }
        Ok(())
    }

    /// Caller owns inbound-processing then rejoin locks. On any storage error
    /// preserve pending crypto: the journal write may already have committed.
    pub(crate) async fn journal_prepared_control(
        &self,
        prepared: PreparedRequest,
        projection: GroupState,
    ) -> Result<()> {
        self.journal_prepared_control_at_snapshot(prepared, projection, None)
            .await
    }

    pub(crate) async fn journal_prepared_control_with_snapshot(
        &self,
        prepared: PreparedRequest,
        projection: GroupState,
        prior_snapshot_seq: u64,
    ) -> Result<()> {
        self.journal_prepared_control_at_snapshot(prepared, projection, Some(prior_snapshot_seq))
            .await
    }

    async fn journal_prepared_control_at_snapshot(
        &self,
        prepared: PreparedRequest,
        projection: GroupState,
        snapshot: Option<u64>,
    ) -> Result<()> {
        let mut record = PreparedControlRecord::new(prepared, projection)?;
        record.prior_snapshot_seq = snapshot;
        self.restore_control_blocker(&record).await;
        self.check_control_journal_binding(&record).await?;
        self.mls_context().ensure_storage_durable()?;
        self.mls_context().put_prepared_control(&record)?;
        Ok(())
    }

    async fn check_control_journal_binding(&self, record: &PreparedControlRecord) -> Result<()> {
        record.validate()?;
        if record.actor_did != self.require_user_did().await?
            || record.actor_device_id != self.require_actor_device_id().await?
            || self
                .reset_pending_payload_result(&record.conversation_id)
                .await?
                .is_some()
            || self
                .is_local_device_removed(&record.conversation_id)
                .await?
            || self
                .is_local_conversation_closed(&record.conversation_id)
                .await?
            || self
                .resolve_conversation_context(&record.conversation_id)
                .await?
                .group_id
                != record.group_id
        {
            return Err(invalid("current identity, reset, or group binding changed"));
        }
        Ok(())
    }

    async fn restore_control_blocker(&self, record: &PreparedControlRecord) {
        let nonce = self.next_staged_commit_nonce().await;
        self.pending_staged_commits()
            .lock()
            .await
            .entry(record.group_id.clone())
            .or_insert(PendingCommitMeta {
                conversation_id: record.conversation_id.clone(),
                nonce,
                source_epoch: record.prior["epoch"].as_u64().unwrap(),
                target_epoch: record.projection.epoch,
                kind: StagedCommitKindSummary::AddMembers {
                    member_dids: vec![],
                },
            });
    }

    /// Restore the own-Commit hash/epoch fence from an applied native record.
    pub(crate) async fn restore_completed_control_proof(
        &self,
        record: &PreparedControlRecord,
    ) -> Result<()> {
        self.check_control_journal_binding(record).await?;
        if !record.completed {
            return Err(invalid("own proof is not completed"));
        }
        self.track_epoch_changing_own_commit(
            record.commit_sha256.clone(),
            OwnCommitExpectation {
                conversation_id: record.conversation_id.clone(),
                group_id: record.group_id.clone(),
                target_epoch: record.projection.epoch,
            },
        )
        .await;
        Ok(())
    }

    /// Read a finite, gap-free interval bounded by a fresh state snapshot.
    /// GetEntries may legally hide gaps: any such gap prevents absence proof.
    /// Finding our exact signed canonical entry proves acceptance independently
    /// of the HTTP response; it is stored as an entry proof, never as a fake ACK.
    async fn reconcile_prepared_control_outcome(
        &self,
        record: &mut PreparedControlRecord,
    ) -> Result<bool> {
        let Some(mut after) = record.prior_snapshot_seq else {
            return Ok(false);
        };
        let fresh = self
            .fetch_conversation_lifecycle(&record.conversation_id)
            .await?;
        let current = super::lifecycle::lifecycle_coordinates(
            &fresh["state"]["coordinates"],
            &record.conversation_id,
        )?;
        if current["groupId"] != record.prior["groupId"]
            || current["generation"] != record.prior["generation"]
            || current["stateVersion"].as_u64() <= record.prior["stateVersion"].as_u64()
        {
            return Ok(false);
        }
        let snapshot = fresh["state"]["snapshotSeq"]
            .as_u64()
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or_else(|| invalid("fresh state lacks bounded snapshot sequence"))?;
        if snapshot <= after {
            return Err(invalid("fresh state snapshot did not advance"));
        }
        let auth =
            super::canonical_transport::CleanChatAuthContext::new(record.actor_device_id.clone());
        let mut entries = Vec::new();
        let mut contiguous = true;
        for _ in 0..super::pagination::MAX_MESSAGE_PAGES {
            let request = super::canonical_transport::prepare_get_entries(
                &auth,
                &record.conversation_id,
                after as i64,
                100,
            )
            .map_err(|e| invalid(&format!("prepare entry proof: {e}")))?;
            let response = self.api_client().submit_prepared_request(request).await?;
            if response.status != 200 {
                return Err(invalid(
                    "cannot read canonical entry proof; control remains pending",
                ));
            }
            let page: Value = serde_json::from_slice(&response.body)
                .map_err(|_| invalid("malformed entry proof page"))?;
            let rows = page["entries"]
                .as_array()
                .filter(|rows| rows.len() <= 100)
                .ok_or_else(|| invalid("invalid entry proof page size"))?;
            let mut greatest = after;
            for entry in rows {
                let seq = entry["seq"]
                    .as_u64()
                    .filter(|n| *n <= 9_007_199_254_740_991)
                    .ok_or_else(|| invalid("invalid proof entry sequence"))?;
                if seq <= greatest || entry["conversationId"] != record.conversation_id {
                    return Err(invalid("nonmonotonic or foreign proof entry"));
                }
                if seq <= snapshot {
                    if seq != greatest + 1 {
                        contiguous = false;
                    }
                    if entry["signedRequest"]["body"]["transitionId"] == record.transition_id
                        || entry["signedRequest"]["body"]["idempotencyKey"] == record.transition_id
                    {
                        let actual = serde_json::to_vec(entry)
                            .map_err(|_| invalid("cannot retain canonical entry"))?;
                        record.validate_entry(&actual)?;
                        record.confirmed_entry = Some(actual);
                        self.mls_context().put_prepared_control(record)?;
                        return Ok(false);
                    }
                    entries.push(entry.clone());
                    if entries.len() > super::pagination::MAX_MESSAGE_ITEMS {
                        return Err(invalid("entry proof item bound exceeded"));
                    }
                }
                greatest = seq;
            }
            if page["nextAfterSeq"].as_u64() != Some(greatest) {
                return Err(invalid(
                    "entry proof continuation differs from returned entries",
                ));
            }
            if greatest >= snapshot {
                if !contiguous {
                    return Err(invalid("visibility gap prevents proving nonacceptance"));
                }
                let proof = serde_json::json!({"state":fresh,"entries":entries});
                record.validate_nonacceptance(&proof)?;
                record.nonacceptance_proof = Some(proof);
                self.mls_context().put_prepared_control(record)?;
                return Ok(true);
            }
            if greatest == after || page["hasMore"].as_bool() != Some(true) {
                return Err(invalid("entry proof ends before fresh snapshot"));
            }
            after = greatest;
        }
        Err(invalid(
            "entry proof page bound exceeded; control remains pending",
        ))
    }

    async fn discard_rejected_control(&self, record: &PreparedControlRecord) -> Result<()> {
        let group = hex::decode(&record.group_id).map_err(|_| invalid("invalid group id"))?;
        if self.mls_context().get_epoch(group.clone())?
            != record.prior["epoch"]
                .as_u64()
                .ok_or_else(|| invalid("invalid prior epoch"))?
        {
            return Err(invalid(
                "cannot discard rejected control after epoch changed",
            ));
        }
        self.mls_context().clear_pending_commit(group)?;
        self.mls_context().ensure_storage_durable()?;
        self.mls_context()
            .remove_prepared_control(&record.group_id, &record.transition_id)?;
        self.pending_staged_commits()
            .lock()
            .await
            .remove(&record.group_id);
        Ok(())
    }

    /// Replay a retained operation, never resigning it. Caller owns the inbound
    /// then rejoin locks. All failures retain both pending crypto and journal.
    pub(crate) async fn replay_prepared_control_locked(
        &self,
        group: &str,
    ) -> Result<Option<Value>> {
        let Some(mut record) = self.mls_context().get_prepared_control(group)? else {
            return Ok(None);
        };
        self.check_control_journal_binding(&record).await?;
        self.restore_control_blocker(&record).await;
        if record.nonacceptance_proof.is_some() {
            self.discard_rejected_control(&record).await?;
            return Err(invalid(
                "original control was superseded before acceptance; synchronize before retrying",
            ));
        }
        if !record.has_acceptance() {
            // A single provider call may internally retry HTTP. Even its first
            // visible 4xx cannot prove the signed operation was never accepted.
            record.attempted = true;
            self.mls_context().put_prepared_control(&record)?;
            let mut last = invalid("control outcome remains uncertain");
            for _ in 0..3 {
                match self
                    .api_client()
                    .submit_prepared_request(record.prepared_request())
                    .await
                {
                    Ok(response) if response.status == 200 => {
                        match record.validate_response(&response.body) {
                            Ok(_) => {
                                record.confirmed_response = Some(response.body);
                                self.mls_context().put_prepared_control(&record)?;
                                break;
                            }
                            Err(error) => last = error,
                        }
                    }
                    Ok(response)
                        if record.terminal_error_proves_nonacceptance(
                            response.status,
                            &response.body,
                        ) =>
                    {
                        let fresh = self
                            .fetch_conversation_lifecycle(&record.conversation_id)
                            .await?;
                        let proof = serde_json::json!({"state":fresh,"terminalError":{"status":response.status,"body":response.body}});
                        if record.validate_nonacceptance(&proof).is_ok() {
                            record.nonacceptance_proof = Some(proof);
                            self.mls_context().put_prepared_control(&record)?;
                            self.discard_rejected_control(&record).await?;
                            return Err(invalid(
                                "server confirmed terminal unaccepted control; request fresh work",
                            ));
                        }
                        last = invalid("terminal work reply requires coordinate reconciliation");
                    }
                    Ok(response) => {
                        last = OrchestratorError::ServerError {
                            status: response.status,
                            body: String::from_utf8_lossy(&response.body).into_owned(),
                        }
                    }
                    Err(error) => last = error,
                }
            }
            if !record.has_acceptance() {
                if self.reconcile_prepared_control_outcome(&mut record).await? {
                    self.discard_rejected_control(&record).await?;
                    return Err(invalid("original control was superseded before acceptance; synchronize before retrying"));
                }
                if !record.has_acceptance() {
                    return Err(last);
                }
            }
        }
        let output = if let Some(response) = &record.confirmed_response {
            record.validate_response(response)?
        } else {
            record.validate_entry(
                record
                    .confirmed_entry
                    .as_ref()
                    .ok_or_else(|| invalid("missing acceptance proof"))?,
            )?
        };
        let gid = hex::decode(group).map_err(|_| invalid("invalid group id"))?;
        let local_epoch = self.mls_context().get_epoch(gid.clone())?;
        let local_matches = |coordinate: &Value| -> Result<bool> {
            Ok(Some(local_epoch) == coordinate["epoch"].as_u64()
                && self.mls_context().get_confirmation_tag(gid.clone())?
                    == bytes(&coordinate["confirmationTag"])?
                && self.mls_context().get_group_context_hash(gid.clone())?
                    == bytes(&coordinate["groupContextHash"])?)
        };
        if local_matches(&record.prior)? {
            if self.mls_context().merge_pending_commit(gid.clone())? != record.projection.epoch {
                return Err(invalid("merged unexpected epoch"));
            }
        } else if !local_matches(&record.next)? {
            return Err(invalid("local crypto matches neither journal coordinate"));
        }
        // Verify the actual successor even when retry resumed after a partial merge.
        if self.mls_context().get_epoch(gid.clone())? != record.projection.epoch
            || self.mls_context().get_confirmation_tag(gid.clone())?
                != bytes(&record.next["confirmationTag"])?
            || self.mls_context().get_group_context_hash(gid.clone())?
                != bytes(&record.next["groupContextHash"])?
        {
            return Err(invalid("merged crypto differs from accepted successor"));
        }
        self.mls_context().ensure_storage_durable()?;
        // Keep the intended projection immutable in the journal; derive the
        // durable leaf-level membership from the landed MLS tree.
        let mut landed = record.projection.clone();
        landed.members = self
            .mls_context()
            .group_member_identities(gid)?
            .into_iter()
            .map(|id| String::from_utf8(id).map_err(|_| invalid("invalid landed member identity")))
            .collect::<Result<Vec<_>>>()?;
        self.storage().set_group_state(&landed).await?;
        let members = landed.members.clone();
        {
            let mut states = self.group_states().lock().await;
            super::types::normalize_group_state(&mut states, landed);
        }
        if let Some(conversation) = self
            .conversations()
            .lock()
            .await
            .get_mut(&record.conversation_id)
        {
            conversation.epoch = record.projection.epoch;
            // A generic Remove only changes device membership. Its account
            // policy step may still be pending, so retain the account roster.
            if record.expected_entry_type != "blue.catbird.chat.defs#commitEntry" {
                conversation.members.retain(|member| {
                    members.iter().any(|id| {
                        super::credential_binding::credential_root_did(id)
                            == super::credential_binding::credential_root_did(&member.did)
                    })
                });
            }
        }
        self.storage()
            .clear_rejoin_flag(&record.conversation_id)
            .await?;
        if !self
            .project_non_reset_state_locked(
                &record.conversation_id,
                super::types::ConversationState::Active,
            )
            .await?
        {
            return Err(invalid(
                "terminal or reset authority prevents Active projection",
            ));
        }
        record.completed = true;
        self.mls_context().put_prepared_control(&record)?;
        self.restore_completed_control_proof(&record).await?;
        self.pending_staged_commits().lock().await.remove(group);
        self.cleanup_epoch_secrets_if_needed(
            &record.conversation_id,
            group,
            record.projection.epoch,
        )
        .await;
        Ok(Some(output))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{KeychainAccess, MLSError};
    use serde_json::json;
    struct Keys;
    #[async_trait::async_trait]
    impl KeychainAccess for Keys {
        async fn read(&self, _: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _: String, _: Vec<u8>) -> std::result::Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _: String) -> std::result::Result<(), MLSError> {
            Ok(())
        }
    }
    fn fixture() -> PreparedControlRecord {
        let cid = uuid::Uuid::new_v4().to_string();
        let transition = uuid::Uuid::new_v4().to_string();
        let group = vec![4u8; 32];
        let prior = json!({"conversationId":cid,"generation":0,"groupId":STANDARD.encode(&group),"epoch":0,"stateVersion":0,"groupContextHash":STANDARD.encode([1;32]),"confirmationTag":STANDARD.encode([2;32]),"lifecycle":"active"});
        let mut next = prior.clone();
        next["epoch"] = json!(1);
        next["stateVersion"] = json!(1);
        let commit = vec![1, 2, 3];
        let request = json!({"signedRequest":{"signature":STANDARD.encode([5;64]),"body":{
            "$type":"blue.catbird.chat.defs#leaveCommitFulfillmentBody", "prior":prior,"next":next,
            "actorDid":"did:plc:journaltest", "actorDeviceId":uuid::Uuid::new_v4().to_string(),
            "transitionId":transition,"idempotencyKey":transition,
            "commit":{"bytes":STANDARD.encode(&commit),"sha256":STANDARD.encode(Sha256::digest(&commit))}
        }}});
        PreparedControlRecord::new(
            PreparedRequest {
                operation: CanonicalOperation::SubmitTransition,
                method: "POST".into(),
                path: CanonicalOperation::SubmitTransition.path().into(),
                body: Some(serde_json::to_vec(&request).unwrap()),
            },
            GroupState {
                conversation_id: cid,
                group_id: hex::encode(group),
                epoch: 1,
                members: vec![],
            },
        )
        .unwrap()
    }
    #[test]
    fn generic_removal_constructor_accepts_only_device_removals() {
        let base = fixture();
        let remove = json!({"$type":"blue.catbird.chat.defs#removeLeaf","userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","deviceId":uuid::Uuid::new_v4().to_string()});
        let valid = json!({"participantChanges":[],"leafChanges":[remove.clone()]});
        let build = |manifest: Value| {
            let mut prepared = base.prepared_request();
            let mut request: Value =
                serde_json::from_slice(prepared.body.as_ref().unwrap()).unwrap();
            request["signedRequest"]["body"]["$type"] =
                json!("blue.catbird.chat.defs#commitTransitionBody");
            request["signedRequest"]["body"]["manifest"] = manifest;
            prepared.body = Some(serde_json::to_vec(&request).unwrap());
            PreparedControlRecord::new(prepared, base.projection.clone())
        };
        let accepted = build(valid.clone()).unwrap();
        assert_eq!(
            accepted.expected_entry_type,
            "blue.catbird.chat.defs#commitEntry"
        );
        accepted.validate().unwrap();
        let mut empty = valid.clone();
        empty["leafChanges"] = json!([]);
        let mut mixed = valid.clone();
        mixed["leafChanges"].as_array_mut().unwrap().push(json!({"$type":"blue.catbird.chat.defs#addLeafByRecovery","userDid":"did:plc:cccccccccccccccccccccccc"}));
        let mut participant = valid.clone();
        participant["participantChanges"] = json!([{"$type":"blue.catbird.chat.defs#removeParticipant","userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}]);
        let mut welcome = valid.clone();
        welcome["welcomeBundle"] = json!({"opaqueWelcome":"AA=="});
        let mut null_welcome = valid;
        null_welcome["welcomeBundle"] = Value::Null;
        for (label, manifest) in [
            ("empty", empty),
            ("mixed Add", mixed),
            ("account change", participant),
            ("Welcome", welcome),
            ("null Welcome", null_welcome),
        ] {
            assert!(
                build(manifest).is_err(),
                "generic journal must reject {label}"
            );
        }
    }

    #[test]
    fn legacy_generic_entry_label_reopens_without_changing_signed_request() {
        let base = fixture();
        let mut prepared = base.prepared_request();
        let mut request: Value = serde_json::from_slice(prepared.body.as_ref().unwrap()).unwrap();
        request["signedRequest"]["body"]["$type"] =
            json!("blue.catbird.chat.defs#commitTransitionBody");
        request["signedRequest"]["body"]["manifest"] = json!({"participantChanges":[],"leafChanges":[{"$type":"blue.catbird.chat.defs#removeLeaf","userDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","deviceId":uuid::Uuid::new_v4().to_string()}]});
        prepared.body = Some(serde_json::to_vec(&request).unwrap());
        let mut record = PreparedControlRecord::new(prepared, base.projection).unwrap();
        record.attempted = true;
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy["expected_entry_type"] = json!("blue.catbird.chat.defs#commitTransitionEntry");
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("legacy-generic.db")
            .to_string_lossy()
            .into_owned();
        {
            let (context, _) = crate::mls_context::MLSContext::new(
                path.clone(),
                "legacy-generic-key".into(),
                Box::new(Keys),
            )
            .unwrap();
            context
                .manifest_storage
                .write_manifest(
                    "prepared_control_journal_v1",
                    &json!({"pending":{record.group_id.clone():legacy},"completed":{}}),
                )
                .unwrap();
        }
        let reopened =
            crate::MLSContext::new(path, "legacy-generic-key".into(), Box::new(Keys)).unwrap();
        let restored = reopened
            .get_prepared_control(&record.group_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            restored.expected_entry_type,
            "blue.catbird.chat.defs#commitEntry"
        );
        assert_eq!(restored.request_body, record.request_body);
        assert_eq!(restored.request_sha256, record.request_sha256);
        assert!(restored.attempted);
        assert!(!restored.has_acceptance());
        reopened.put_prepared_control(&restored).unwrap();
        assert_eq!(
            reopened
                .get_prepared_control(&record.group_id)
                .unwrap()
                .unwrap()
                .request_body,
            record.request_body
        );
        assert!(reopened
            .remove_prepared_control(&record.group_id, &record.transition_id)
            .is_err());
    }

    #[test]
    fn nonacceptance_requires_complete_same_generation_interval_without_own_transition() {
        let mut record = fixture();
        record.prior_snapshot_seq = Some(10);
        let make_entry = |seq| json!({"conversationId":record.conversation_id,"entryId":uuid::Uuid::new_v4().to_string(),"seq":seq});
        let proof = json!({"state":{"state":{"coordinates":record.next,"snapshotSeq":12}},"entries":[make_entry(11),make_entry(12)]});
        record.validate_nonacceptance(&proof).unwrap();
        let mut gap = proof.clone();
        gap["entries"][0]["seq"] = json!(12);
        assert!(record.validate_nonacceptance(&gap).is_err());
        let mut truncated = proof.clone();
        truncated["entries"].as_array_mut().unwrap().pop();
        assert!(record.validate_nonacceptance(&truncated).is_err());
        let mut own = proof.clone();
        own["entries"][0]["signedRequest"] = json!({"body":{"transitionId":record.transition_id}});
        assert!(record.validate_nonacceptance(&own).is_err());
        let mut reset = proof.clone();
        reset["state"]["state"]["coordinates"]["generation"] = json!(1);
        assert!(record.validate_nonacceptance(&reset).is_err());
        let mut unchanged = proof;
        unchanged["state"]["state"]["coordinates"] = record.prior.clone();
        assert!(record.validate_nonacceptance(&unchanged).is_err());
    }

    #[test]
    fn resumed_terminal_response_must_be_post_arbitration_and_exact_prior() {
        let record = fixture();
        for code in ["LeaveRequestExpired", "SignedOperationExpired"] {
            let body = serde_json::to_vec(&json!({"error":code})).unwrap();
            let proof = json!({"state":{"state":{"coordinates":record.prior}},"terminalError":{"status":400,"body":body}});
            record.validate_nonacceptance(&proof).unwrap();
            let mut advanced = proof;
            advanced["state"]["state"]["coordinates"] = record.next.clone();
            assert!(record.validate_nonacceptance(&advanced).is_err());
        }
        for code in [
            "InvalidSignature",
            "LeafRecoveryNotFound",
            "LeaveRequestNotFound",
            "InvalidRequest",
            "NotAuthorized",
            "LeafRecoveryExpired",
        ] {
            assert!(!record.terminal_error_proves_nonacceptance(
                400,
                &serde_json::to_vec(&json!({"error":code})).unwrap()
            ));
        }
    }

    #[test]
    fn acceptance_proof_requires_the_exact_retained_signature_and_body() {
        let record = fixture();
        let signed =
            serde_json::from_slice::<Value>(&record.request_body).unwrap()["signedRequest"].clone();
        let output = json!({"coordinates":record.next,"entry":{"conversationId":record.conversation_id,"entryId":uuid::Uuid::new_v4().to_string(),"seq":1,"$type":record.expected_entry_type,"signedRequest":signed}});
        record
            .validate_response(&serde_json::to_vec(&output).unwrap())
            .unwrap();
        let mut substituted = output.clone();
        substituted["entry"]["signedRequest"]["signature"] = json!(STANDARD.encode([6; 64]));
        assert!(record
            .validate_response(&serde_json::to_vec(&substituted).unwrap())
            .is_err());
        let mut body = output;
        body["entry"]["signedRequest"]["body"]["actorDid"] = json!("did:plc:another");
        assert!(record
            .validate_response(&serde_json::to_vec(&body).unwrap())
            .is_err());
    }

    #[test]
    fn accepted_entry_identity_is_independent_but_must_be_well_formed() {
        let record = fixture();
        let signed =
            serde_json::from_slice::<Value>(&record.request_body).unwrap()["signedRequest"].clone();
        let entry = json!({"conversationId":record.conversation_id,"entryId":uuid::Uuid::new_v4().to_string(),"seq":1,"$type":record.expected_entry_type,"signedRequest":signed});
        assert_ne!(
            entry["entryId"],
            entry["signedRequest"]["body"]["transitionId"]
        );
        record
            .validate_entry(&serde_json::to_vec(&entry).unwrap())
            .unwrap();
        for (field, value) in [
            ("entryId", json!("not-a-uuid")),
            ("entryId", json!(uuid::Uuid::nil().to_string())),
            ("seq", json!(0)),
            ("seq", json!(9_007_199_254_740_992u64)),
        ] {
            let mut invalid = entry.clone();
            invalid[field] = value;
            assert!(record
                .validate_entry(&serde_json::to_vec(&invalid).unwrap())
                .is_err());
        }
        let mut wrong_signed_id = entry.clone();
        wrong_signed_id["signedRequest"]["body"]["transitionId"] =
            json!(uuid::Uuid::new_v4().to_string());
        assert!(record
            .validate_entry(&serde_json::to_vec(&wrong_signed_id).unwrap())
            .is_err());
    }

    #[test]
    fn legacy_v1_rejections_remain_readable_and_cannot_authorize_removal() {
        for legacy in [Value::Null, json!([403, b"forbidden".to_vec()])] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.db").to_string_lossy().into_owned();
            let mut record = fixture();
            record.attempted = true;
            let mut old = serde_json::to_value(&record).unwrap();
            old["definitive_rejection"] = legacy;
            {
                let (context, _) = crate::mls_context::MLSContext::new(
                    path.clone(),
                    "legacy-journal-key".into(),
                    Box::new(Keys),
                )
                .unwrap();
                context
                    .manifest_storage
                    .write_manifest(
                        "prepared_control_journal_v1",
                        &json!({"pending":{record.group_id.clone():old},"completed":{}}),
                    )
                    .unwrap();
            }
            let reopened =
                crate::MLSContext::new(path, "legacy-journal-key".into(), Box::new(Keys)).unwrap();
            let restored = reopened
                .get_prepared_control(&record.group_id)
                .expect("legacy v1 field must be readable")
                .unwrap();
            assert_eq!(restored.prepared_request(), record.prepared_request());
            assert!(restored.nonacceptance_proof.is_none());
            assert!(!restored.has_acceptance());
            assert!(
                reopened
                    .remove_prepared_control(&record.group_id, &record.transition_id)
                    .is_err(),
                "legacy 4xx is ambiguous even when persisted before restart"
            );
            // A normal write migrates away only the ignored legacy field.
            reopened.put_prepared_control(&restored).unwrap();
            assert_eq!(reopened.list_prepared_controls().unwrap().len(), 1);
            assert!(serde_json::to_value(&restored)
                .unwrap()
                .get("definitive_rejection")
                .is_none());
        }
    }

    #[test]
    fn encrypted_native_journal_survives_context_recreation_and_rejects_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db").to_string_lossy().into_owned();
        let record = fixture();
        {
            let context =
                crate::MLSContext::new(path.clone(), "journal-test-key".into(), Box::new(Keys))
                    .unwrap();
            context
                .put_prepared_control(&record)
                .expect("must durably journal exact request before transport");
            context.flush_storage().unwrap();
        }
        let reopened =
            crate::MLSContext::new(path, "journal-test-key".into(), Box::new(Keys)).unwrap();
        let restored = reopened
            .get_prepared_control(&record.group_id)
            .unwrap()
            .unwrap();
        assert_eq!(restored.prepared_request(), record.prepared_request());
        let mut replacement = fixture();
        replacement.group_id = record.group_id.clone();
        assert!(reopened.put_prepared_control(&replacement).is_err());
        let mut confirmed = record.clone();
        confirmed.attempted = true;
        confirmed.confirmed_response=Some(serde_json::to_vec(&json!({"coordinates":record.next,"entry":{"conversationId":record.conversation_id,"entryId":record.transition_id,"seq":1,"$type":record.expected_entry_type,"signedRequest":serde_json::from_slice::<Value>(&record.request_body).unwrap()["signedRequest"]}})).unwrap());
        reopened.put_prepared_control(&confirmed).unwrap();
        assert!(
            reopened.put_prepared_control(&record).is_err(),
            "cannot erase known acceptance"
        );
        confirmed.completed = true;
        reopened.put_prepared_control(&confirmed).unwrap();
        assert!(reopened
            .get_prepared_control(&record.group_id)
            .unwrap()
            .is_none());
        let proofs = reopened.list_prepared_controls().unwrap();
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].completed);
        assert_eq!(proofs[0].confirmed_response, confirmed.confirmed_response);
        let newer = fixture();
        reopened.put_prepared_control(&newer).unwrap();
        reopened.put_prepared_control(&confirmed).unwrap();
        assert_eq!(
            reopened
                .get_prepared_control(&newer.group_id)
                .unwrap()
                .unwrap()
                .transition_id,
            newer.transition_id,
            "replaying an old completion must not remove a newer pending request"
        );
        assert!(
            reopened
                .remove_prepared_control(&newer.group_id, &newer.transition_id)
                .is_err(),
            "ambiguous requests cannot be removed"
        );
        let mut rejected = newer;
        rejected.attempted = true;
        let body = serde_json::to_vec(&json!({"error":"SignedOperationExpired"})).unwrap();
        rejected.nonacceptance_proof = Some(
            json!({"state":{"state":{"coordinates":rejected.prior}},"terminalError":{"status":400,"body":body}}),
        );
        reopened.put_prepared_control(&rejected).unwrap();
        reopened
            .remove_prepared_control(&rejected.group_id, &rejected.transition_id)
            .unwrap();
        assert!(reopened
            .get_prepared_control(&rejected.group_id)
            .unwrap()
            .is_none());
        assert_eq!(
            reopened.list_prepared_controls().unwrap().len(),
            1,
            "rejection must preserve completed proof archive"
        );
    }
}
