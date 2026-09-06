//! Exact account-exit intent and accepted proof, independent of MLS Commit journals.
use catbird_atproto::blue_catbird::chat::get_conversation_state::GetConversationStateError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    CanonicalOperation, ConversationState, CredentialStore, MLSAPIClient, MLSOrchestrator,
    MLSStorageBackend, MlsCryptoContext, OrchestratorError, PreparedRequest, Result,
};

fn invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Conversation exit: {message}"))
}
fn valid_id(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|id| crate::chat_v2::ids::uuid::ConversationId::parse(id).is_ok())
}
fn canonical_time(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        chrono::DateTime::parse_from_rfc3339(text)
            .is_ok_and(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true) == text)
    })
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

/// The signed wrapper is durable before transport. The accepted response is
/// durable before any terminal UI projection; neither field is regenerated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountExitResetEvidence {
    pub new_group_id: String,
    pub reset_generation: i32,
    pub notified_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountExitRecord {
    pub request_body: Vec<u8>,
    pub accepted_response: Option<Value>,
    pub local_completion: bool,
    pub replaces_operation: Option<String>,
    pub reset_evidence: Option<AccountExitResetEvidence>,
}

impl AccountExitRecord {
    pub(crate) fn wrapper(&self) -> Result<Value> {
        serde_json::from_slice(&self.request_body).map_err(|_| invalid("invalid saved request"))
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let wrapper = self.wrapper()?;
        if self.local_completion && self.accepted_response.is_none() {
            return Err(invalid("local completion has no accepted proof"));
        }
        let body = &wrapper["signedRequest"]["body"];
        if self
            .replaces_operation
            .as_ref()
            .is_some_and(|id| !valid_id(&Value::String(id.clone())) || body["transitionId"] == *id)
        {
            return Err(invalid("invalid replaced operation"));
        }
        let cid = body["prior"]["conversationId"]
            .as_str()
            .ok_or_else(|| invalid("missing conversation"))?;
        let prior = super::lifecycle::lifecycle_coordinates(&body["prior"], cid)?;
        if let Some(reset) = &self.reset_evidence {
            if self.accepted_response.is_none()
                || reset.reset_generation <= 0
                || prior["generation"].as_u64() != Some(reset.reset_generation as u64)
                || hex::encode(super::welcome_ack::bytes(&prior["groupId"])?) != reset.new_group_id
            {
                return Err(invalid(
                    "archived reset does not match the accepted terminal generation",
                ));
            }
        }
        let close = body["$type"] == "blue.catbird.chat.defs#conversationCloseBody";
        if (!close && body["$type"] != "blue.catbird.chat.defs#zeroLeafLeaveBody")
            || body["signatureDomain"]
                != if close {
                    "CATBIRD-CHAT-CLOSE\0"
                } else {
                    "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0"
                }
            || !valid_id(&body["transitionId"])
            || !valid_id(&body["idempotencyKey"])
            || !valid_id(&body["actorDeviceId"])
            || !canonical_time(&body["signedAt"])
            || body["actorDid"].as_str().is_none()
            || prior["lifecycle"] != "active"
            || !body["authGeneration"].as_u64().is_some_and(|n| n > 0)
            || super::welcome_ack::bytes(&wrapper["signedRequest"]["signature"])?.len() != 64
        {
            return Err(invalid("saved request has an invalid binding"));
        }
        let next = super::lifecycle::lifecycle_coordinates(
            &body[if close { "retired" } else { "next" }],
            cid,
        )?;
        let mut expected = prior;
        expected["stateVersion"] = serde_json::json!(expected["stateVersion"]
            .as_u64()
            .unwrap()
            .checked_add(1)
            .ok_or_else(|| invalid("state version overflow"))?);
        if close {
            expected["lifecycle"] = serde_json::json!("superseded");
        }
        if next != expected {
            return Err(invalid("saved request changes unrelated coordinates"));
        }
        if let Some(response) = &self.accepted_response {
            let result = &response["result"];
            let entry = &result["entry"];
            let expected_kind = if close {
                "blue.catbird.chat.defs#conversationCloseEntry"
            } else {
                "blue.catbird.chat.defs#zeroLeafLeaveEntry"
            };
            if entry.get("$type").is_some_and(|kind| kind != expected_kind) {
                return Err(invalid("accepted entry has the wrong kind"));
            }
            let normalize_signed = |mut signed: Value| {
                if let Some(object) = signed.as_object_mut() {
                    object.remove("$type");
                }
                if signed["body"].get("$type").is_none() {
                    signed["body"]["$type"] = body["$type"].clone();
                }
                normalize_bytes(signed)
            };
            // An entry ID belongs to the server's immutable row, and need not
            // equal the transition ID inside the exact signed request.
            if entry["signedRequest"].is_null()
                || normalize_signed(entry["signedRequest"].clone())
                    != normalize_signed(wrapper["signedRequest"].clone())
                || entry["conversationId"].as_str() != Some(cid)
                || !valid_id(&entry["entryId"])
                || !entry["seq"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991)
                || !canonical_time(&entry["receivedAt"])
            {
                return Err(invalid(
                    "accepted entry does not match the saved signed request",
                ));
            }
            if close {
                let tombstone = &result["tombstone"];
                let normalize_tombstone = |mut value: Value| {
                    if let Some(object) = value.as_object_mut() {
                        object.remove("$type");
                    }
                    normalize_bytes(value)
                };
                if normalize_tombstone(entry["tombstone"].clone())
                    != normalize_tombstone(tombstone.clone())
                    || entry["tombstone"].get("$type").is_some_and(|kind| {
                        kind != "blue.catbird.chat.defs#conversationCloseTombstone"
                    })
                    || tombstone.get("$type").is_some_and(|kind| {
                        kind != "blue.catbird.chat.defs#conversationCloseTombstone"
                    })
                    || tombstone["conversationId"].as_str() != Some(cid)
                    || tombstone["closedByDid"] != body["actorDid"]
                    || tombstone["closedByDeviceId"] != body["actorDeviceId"]
                    || tombstone["conversationKind"] != body["conversationKind"]
                    || tombstone["terminalSeq"] != entry["seq"]
                    || tombstone["closedAt"] != entry["receivedAt"]
                    || super::lifecycle::lifecycle_coordinates(&tombstone["retired"], cid)? != next
                {
                    return Err(invalid("accepted close proof is inconsistent"));
                }
            } else if result["$type"] != "blue.catbird.chat.defs#zeroLeafLeaveResult"
                || super::lifecycle::lifecycle_coordinates(&result["coordinates"], cid)? != next
            {
                return Err(invalid("accepted account-leave proof is inconsistent"));
            }
        }
        Ok(())
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Caller holds the conversation transition lock. Completed old exits are
    /// inert once an explicit fresh Welcome restored Active membership.
    pub(crate) async fn current_account_exit_locked(
        &self,
        cid: &str,
    ) -> Result<Option<AccountExitRecord>> {
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let mut records = self.mls_context().list_account_exits()?;
        records.reverse();
        for record in records {
            let wrapper = record.wrapper()?;
            let body = &wrapper["signedRequest"]["body"];
            if body["prior"]["conversationId"] != cid
                || body["actorDid"] != did
                || body["actorDeviceId"] != device
            {
                continue;
            }
            return Ok(Some(record));
        }
        Ok(None)
    }

    pub(crate) async fn finish_account_exit_locked(
        &self,
        mut record: AccountExitRecord,
    ) -> Result<bool> {
        record.validate()?;
        let wrapper = record.wrapper()?;
        let body = &wrapper["signedRequest"]["body"];
        let cid = body["prior"]["conversationId"].as_str().unwrap();
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        if body["actorDid"] != did || body["actorDeviceId"] != device {
            return Err(invalid("exit belongs to another device"));
        }
        if !self.account_exit_scope_is_current(body).await? {
            return Ok(false);
        }
        let close = body["$type"] == "blue.catbird.chat.defs#conversationCloseBody";
        if record.accepted_response.is_none() {
            let operation = if close {
                CanonicalOperation::CloseConversation
            } else {
                CanonicalOperation::RequestLeave
            };
            let response = self
                .api_client()
                .submit_prepared_request(PreparedRequest {
                    operation,
                    path: super::canonical_transport::canonical_route(operation)
                        .path
                        .into(),
                    method: "POST".into(),
                    body: Some(record.request_body.clone()),
                })
                .await?;
            if response.status != 200 {
                return Err(OrchestratorError::ServerError {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                });
            }
            record.accepted_response = Some(
                serde_json::from_slice(&response.body)
                    .map_err(|_| invalid("invalid accepted response"))?,
            );
            record.validate()?;
            self.mls_context().put_account_exit(&record)?;
        }
        self.retain_verified_departure_coordinate(
            cid,
            &body[if close { "retired" } else { "next" }],
        )
        .await?;
        let prior_group = super::welcome_ack::bytes(&body["prior"]["groupId"])?;
        let newer_native = match self.mls_context().group_is_active(prior_group.clone()) {
            Ok(true) => {
                self.mls_context().get_epoch(prior_group)?
                    > body["prior"]["epoch"].as_u64().unwrap()
            }
            Ok(false) | Err(crate::error::MLSError::GroupNotFound { .. }) => false,
            Err(error) => return Err(error.into()),
        };
        if newer_native {
            // A later authenticated Welcome/Commit already established a newer
            // native incarnation. An offline replay must not retire it again.
            record.local_completion = true;
            self.mls_context().put_account_exit(&record)?;
            return Ok(false);
        }
        // A later re-invitation (including pending consent) can reuse the
        // same group. Old accepted exit evidence must remain historical.
        match self.fetch_conversation_lifecycle(cid).await {
            Ok(current) => {
                let state = &current["state"];
                let present_again = state["participants"].as_array().is_some_and(|items| {
                    items
                        .iter()
                        .any(|participant| participant["userDid"] == did)
                });
                let old = super::lifecycle::lifecycle_coordinates(&body["prior"], cid)?;
                let current = super::lifecycle::lifecycle_coordinates(&state["coordinates"], cid)?;
                if present_again
                    && (current["groupId"] != old["groupId"]
                        || current["generation"] != old["generation"]
                        || current["stateVersion"].as_u64()
                            > old["stateVersion"]
                                .as_u64()
                                .and_then(|version| version.checked_add(1)))
                {
                    record.local_completion = true;
                    self.mls_context().put_account_exit(&record)?;
                    return Ok(false);
                }
            }
            // The saved accepted entry is the authority, not the read denial.
            // A closed CID cannot be re-invited. After zero-leaf leave, an
            // outside-interval denial can still hide newer sibling membership.
            Err(OrchestratorError::ServerError { status: 400, body })
                if match serde_json::from_str::<GetConversationStateError>(&body) {
                    Ok(GetConversationStateError::NotEntitled(_)) => true,
                    Ok(GetConversationStateError::AccessOutsideMembershipInterval(_)) => close,
                    _ => false,
                } => {}
            Err(OrchestratorError::ServerError {
                status: 403 | 404, ..
            }) => {}
            Err(error) => return Err(error),
        }
        let group_id = hex::encode(super::welcome_ack::bytes(&body["prior"]["groupId"])?);
        let stored = self.storage().get_conversation(&did, cid).await?;
        let cached = self.conversations().lock().await.get(cid).cloned();
        let durable_state = self.storage().get_conversation_state(cid).await?;
        let pending = self.reset_pending_payload_result(cid).await?;
        let matching_reset = pending.as_ref().is_some_and(|reset| {
            reset.new_group_id == group_id
                && body["prior"]["generation"].as_u64()
                    == u64::try_from(reset.reset_generation).ok()
        });
        if pending.is_some() && !matching_reset
            || (!matching_reset
                && stored
                    .iter()
                    .chain(cached.iter())
                    .any(|view| view.group_id != group_id))
        {
            return Err(invalid(
                "accepted exit belongs to another conversation generation",
            ));
        }
        if let Some(reset) = pending {
            let evidence = AccountExitResetEvidence {
                new_group_id: reset.new_group_id,
                reset_generation: reset.reset_generation,
                notified_at_ms: reset.notified_at_ms,
            };
            if record
                .reset_evidence
                .as_ref()
                .is_some_and(|old| old != &evidence)
            {
                return Err(invalid(
                    "reset authority changed during terminal completion",
                ));
            }
            match durable_state {
                Some(ConversationState::ResetPending {
                    new_group_id,
                    reset_generation,
                    notified_at_ms,
                }) if evidence.new_group_id == new_group_id
                    && evidence.reset_generation == reset_generation
                    && evidence.notified_at_ms == notified_at_ms =>
                {
                    record.reset_evidence = Some(evidence);
                    self.mls_context().put_account_exit(&record)?;
                }
                // A committed host CAS can lose its reply while the runtime
                // still retains ResetPending. Only the original operation may
                // reuse its archive for the exact terminal retry. A newly
                // accepted exit from durable DeviceRemoved has no live reset
                // to retire and must use the ordinary (None) CAS contract.
                Some(ConversationState::DeviceRemoved)
                    if record.reset_evidence.is_none()
                        && stored
                            .as_ref()
                            .is_some_and(|view| view.group_id == group_id) => {}
                Some(ConversationState::DeviceRemoved | ConversationState::Closed)
                    if record.reset_evidence.as_ref() == Some(&evidence) => {}
                _ => {
                    return Err(invalid(
                        "durable reset authority changed during terminal completion",
                    ))
                }
            }
        }
        self.mls_context().ensure_storage_durable()?;
        if stored.is_none() {
            self.storage()
                .ensure_conversation_exists(&did, cid, &group_id)
                .await?;
        }
        let terminal_state = if close {
            ConversationState::Closed
        } else {
            ConversationState::DeviceRemoved
        };
        let terminal_epoch = body["prior"]["epoch"].as_u64().unwrap();
        if !self
            .storage()
            .complete_account_exit(
                cid,
                &group_id,
                record
                    .reset_evidence
                    .as_ref()
                    .map(|reset| reset.reset_generation),
                terminal_epoch,
                terminal_state.clone(),
            )
            .await?
        {
            return Err(invalid(
                "newer local lifecycle authority prevents this terminal projection",
            ));
        }
        self.conversation_states()
            .lock()
            .await
            .insert(cid.into(), terminal_state);
        if let Some(view) = self.conversations().lock().await.get_mut(cid) {
            view.group_id = group_id.clone();
            view.epoch = terminal_epoch;
        }
        let entry = &record.accepted_response.as_ref().unwrap()["result"]["entry"];
        let marker = if close {
            format!("conversation-closed:{}", entry["entryId"].as_str().unwrap())
        } else {
            format!(
                "membership-left:{}:{device}",
                entry["entryId"].as_str().unwrap()
            )
        };
        if !self.storage().message_exists(&marker).await? {
            let payload = super::MLSMessagePayload::system(if close {
                "conversation.closed"
            } else {
                "membership.left"
            });
            self.storage()
                .store_message(&super::Message {
                    id: marker,
                    conversation_id: cid.into(),
                    sender_did: did,
                    is_own: true,
                    text: if close {
                        "This conversation has ended."
                    } else {
                        "You left this conversation."
                    }
                    .into(),
                    timestamp: chrono::DateTime::parse_from_rfc3339(
                        entry["receivedAt"].as_str().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                    epoch: body["prior"]["epoch"].as_u64().unwrap(),
                    sequence_number: 0,
                    delivery_status: None,
                    payload_json: Some(
                        serde_json::to_string(&payload)
                            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
                    ),
                })
                .await?;
        }
        record.local_completion = true;
        self.mls_context().put_account_exit(&record)?;
        Ok(true)
    }

    pub(crate) async fn resume_account_exits(
        &self,
        blocked_controls: &std::collections::HashSet<String>,
    ) -> Result<std::collections::HashSet<String>> {
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let mut blocked = std::collections::HashSet::new();
        let mut current = std::collections::HashSet::new();
        let mut records = self.mls_context().list_account_exits()?;
        records.reverse();
        for record in records {
            let wrapper = record.wrapper()?;
            let body = &wrapper["signedRequest"]["body"];
            if body["actorDid"] != did || body["actorDeviceId"] != device {
                continue;
            }
            let cid = body["prior"]["conversationId"].as_str().unwrap();
            // New explicit intents supersede older intent retries, while all
            // signed evidence remains durable in its own immutable row.
            if !current.insert(cid.to_owned()) || record.local_completion {
                continue;
            }
            if blocked_controls.contains(cid) {
                continue;
            }
            let lock = self.rejoin_lock(cid).await;
            let _guard = lock.lock().await;
            if !self.account_exit_scope_is_current(body).await? {
                continue;
            }
            if let Err(error) = self.finish_account_exit_locked(record.clone()).await {
                tracing::warn!(conversation_id=cid, %error, "Account exit remains queued");
                blocked.insert(cid.to_owned());
            }
        }
        Ok(blocked)
    }

    async fn account_exit_scope_is_current(&self, body: &Value) -> Result<bool> {
        let cid = body["prior"]["conversationId"].as_str().unwrap();
        let group = super::welcome_ack::bytes(&body["prior"]["groupId"])?;
        let group_hex = hex::encode(&group);
        if let Some(reset) = self.reset_pending_payload_result(cid).await? {
            return Ok(reset.new_group_id == group_hex
                && body["prior"]["generation"].as_u64()
                    == u64::try_from(reset.reset_generation).ok());
        }
        let did = self.require_user_did().await?;
        let stored = self.storage().get_conversation(&did, cid).await?;
        let cached = self.conversations().lock().await.get(cid).cloned();
        if stored
            .iter()
            .chain(cached.iter())
            .any(|view| view.group_id != group_hex)
        {
            return Ok(false);
        }
        match self.mls_context().group_is_active(group.clone()) {
            Ok(true) => Ok(
                self.mls_context().get_epoch(group)? <= body["prior"]["epoch"].as_u64().unwrap()
            ),
            Ok(false) | Err(crate::error::MLSError::GroupNotFound { .. }) => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use super::AccountExitRecord;
    use crate::{error::MLSError, mls_context::ManifestStorage};
    fn failed<E>(_: E) -> MLSError {
        MLSError::StorageFailed
    }
    pub(crate) fn list(storage: &ManifestStorage) -> Result<Vec<AccountExitRecord>, MLSError> {
        let mut query = storage
            .welcome_ack_connection()
            .prepare(
                "SELECT value FROM mls_manifests WHERE key LIKE 'account_exit_v1:%' ORDER BY rowid",
            )
            .map_err(failed)?;
        let rows = query
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(failed)?;
        rows.map(|row| {
            let record: AccountExitRecord =
                serde_json::from_str(&row.map_err(failed)?).map_err(failed)?;
            record.validate().map_err(failed)?;
            Ok(record)
        })
        .collect()
    }
    pub(crate) fn put(
        storage: &ManifestStorage,
        record: &AccountExitRecord,
    ) -> Result<(), MLSError> {
        record.validate().map_err(failed)?;
        let wrapper = record.wrapper().map_err(failed)?;
        let key = format!(
            "account_exit_v1:{}",
            wrapper["signedRequest"]["body"]["transitionId"]
                .as_str()
                .unwrap()
        );
        // Serialize immutable lineage selection and insertion across native
        // contexts opening the same encrypted database.
        use rusqlite::{OptionalExtension as _, TransactionBehavior};
        let tx = rusqlite::Transaction::new_unchecked(
            storage.welcome_ack_connection(),
            TransactionBehavior::Immediate,
        )
        .map_err(failed)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM mls_manifests WHERE key=?1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)?;
        let old: Option<AccountExitRecord> = raw
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(failed)?;
        if let Some(old) = old {
            old.validate().map_err(failed)?;
            if old.request_body != record.request_body
                || old.replaces_operation != record.replaces_operation
                || old
                    .reset_evidence
                    .as_ref()
                    .is_some_and(|reset| Some(reset) != record.reset_evidence.as_ref())
                || old.local_completion && old.reset_evidence != record.reset_evidence
                || old.local_completion && !record.local_completion
                || old
                    .accepted_response
                    .as_ref()
                    .is_some_and(|response| Some(response) != record.accepted_response.as_ref())
            {
                return Err(MLSError::StorageFailed);
            }
        } else {
            if record.accepted_response.is_some() || record.local_completion {
                return Err(MLSError::StorageFailed);
            }
            let body = &wrapper["signedRequest"]["body"];
            let mut latest = None;
            let mut query = tx.prepare("SELECT value FROM mls_manifests WHERE key LIKE 'account_exit_v1:%' ORDER BY rowid DESC").map_err(failed)?;
            let rows = query
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(failed)?;
            for raw in rows {
                let previous: AccountExitRecord =
                    serde_json::from_str(&raw.map_err(failed)?).map_err(failed)?;
                previous.validate().map_err(failed)?;
                let previous_wrapper = previous.wrapper().map_err(failed)?;
                let previous_body = &previous_wrapper["signedRequest"]["body"];
                if previous_body["prior"]["conversationId"] == body["prior"]["conversationId"]
                    && previous_body["actorDid"] == body["actorDid"]
                    && previous_body["actorDeviceId"] == body["actorDeviceId"]
                {
                    latest = previous_body["transitionId"].as_str().map(str::to_owned);
                    break;
                }
            }
            // The predecessor must be the already durable latest operation in
            // this exact device/account/CID scope. A new ID cannot form a cycle.
            if record.replaces_operation != latest {
                return Err(MLSError::StorageFailed);
            }
        }
        tx.execute("INSERT INTO mls_manifests(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [&key, &serde_json::to_string(record).map_err(failed)?]).map_err(failed)?;
        tx.commit().map_err(failed)?;
        storage.flush_database()
    }
}
