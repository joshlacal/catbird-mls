//! Preserve terminal local device membership without turning a server inventory
//! hint into permission to erase history or rejoin an account that left.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use openmls::prelude::{ContentType, MlsMessageIn};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tls_codec::Deserialize as _;

use super::canonical_transport::{CanonicalOperation, PreparedRequest};
use super::pagination::PaginationGuard;
use super::{
    ConversationState, CredentialStore, MLSAPIClient, MLSOrchestrator, MLSStorageBackend,
    MlsCryptoContext, OrchestratorError, Result,
};

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Persisted state wins over a stale runtime projection. A storage failure
    /// fails closed at callers that could otherwise recover or send.
    pub(crate) async fn is_local_device_removed(&self, conversation_id: &str) -> Result<bool> {
        if matches!(
            self.storage()
                .get_conversation_state(conversation_id)
                .await?,
            Some(ConversationState::DeviceRemoved)
        ) {
            return Ok(true);
        }
        Ok(matches!(
            self.conversation_states().lock().await.get(conversation_id),
            Some(ConversationState::DeviceRemoved)
        ))
    }

    pub(crate) async fn is_local_conversation_closed(&self, conversation_id: &str) -> Result<bool> {
        if matches!(
            self.storage()
                .get_conversation_state(conversation_id)
                .await?,
            Some(ConversationState::Closed)
        ) {
            return Ok(true);
        }
        Ok(matches!(
            self.conversation_states().lock().await.get(conversation_id),
            Some(ConversationState::Closed)
        ))
    }

    pub(crate) async fn is_local_conversation_terminal(
        &self,
        conversation_id: &str,
    ) -> Result<bool> {
        Ok(self.is_local_device_removed(conversation_id).await?
            || self.is_local_conversation_closed(conversation_id).await?)
    }

    /// Called after process_welcome and durable application projection, never
    /// from roster presence or a server notification alone.
    pub(crate) async fn restore_device_after_verified_welcome(
        &self,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        let resolved = self.resolve_conversation_context(conversation_id).await?;
        if resolved.group_id != group_id {
            return Err(terminal_invalid("Welcome generation changed."));
        }
        self.finish_available_welcome_adoption(conversation_id)
            .await?;
        Ok(())
    }

    pub(crate) async fn reject_automatic_rejoin_after_device_removal(
        &self,
        conversation_id: &str,
    ) -> Result<()> {
        if self.is_local_conversation_terminal(conversation_id).await? {
            return Err(OrchestratorError::InvalidInput(
                "This device was removed from the conversation. Its saved history is still available. Accept a new invitation to join again.".into(),
            ));
        }
        Ok(())
    }

    /// Called only after an authenticated native MLS Remove outcome has crossed
    /// its durability barrier. Inventory tombstones alone must never call this.
    /// The epoch is the target wire epoch, not an assertion that a removed leaf
    /// has access to the next epoch's secrets.
    pub(crate) async fn record_local_device_removal(
        &self,
        conversation_id: &str,
        expected_group_id: &str,
        wire_epoch: u64,
    ) -> Result<()> {
        let transition_lock = self.rejoin_lock(conversation_id).await;
        let _guard = transition_lock.lock().await;
        let resolved = self.resolve_conversation_context(conversation_id).await?;
        if resolved.group_id != expected_group_id || wire_epoch == 0 {
            return Err(OrchestratorError::InvalidInput(
                "The removed device belongs to a different conversation generation.".into(),
            ));
        }
        if self
            .reset_blocks_non_reset_transition_locked(conversation_id)
            .await?
        {
            return Ok(());
        }
        self.project_non_reset_state_locked(conversation_id, ConversationState::DeviceRemoved)
            .await?;
        // Persist terminal authority before clearing the retry hint. A failure
        // here remains safely unsendable across restart and may be retried.
        self.storage().clear_rejoin_flag(conversation_id).await?;
        tracing::info!(
            conversation_id,
            group_id = expected_group_id,
            wire_epoch,
            "Authenticated MLS removal retained local history and disabled automatic recovery"
        );
        Ok(())
    }
}

fn terminal_invalid(message: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(message.into())
}

fn terminal_bytes(value: &Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .or_else(|| value["$bytes"].as_str())
        .ok_or_else(|| terminal_invalid("Terminal entry is missing canonical bytes."))?;
    STANDARD
        .decode(encoded)
        .map_err(|_| terminal_invalid("Terminal entry contains invalid bytes."))
}

fn normalize_response_bytes(value: &mut Value) {
    match value {
        Value::Object(fields)
            if fields.len() == 1 && fields.get("$bytes").is_some_and(Value::is_string) =>
        {
            *value = fields["$bytes"].clone();
        }
        Value::Object(fields) => fields.values_mut().for_each(normalize_response_bytes),
        Value::Array(items) => items.iter_mut().for_each(normalize_response_bytes),
        _ => {}
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod repository_signature_tests {
    use super::*;
    use crate::orchestrator::credential_binding::{DeviceKeyCacheEntry, DeviceKeyLookup};
    use crate::recovery_e2e_harness::TestWorld;
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn terminal_signature_requires_repository_authority_and_refreshes_new_published_key() {
        let mut world = TestWorld::new();
        world
            .add_client_with_did("Alice", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
            .await;
        world.register_device("Alice").await.unwrap();
        let alice = world.client("Alice");
        let created = alice
            .orchestrator
            .create_group("", None, None)
            .await
            .unwrap();
        let device_id = alice.orchestrator.require_actor_device_id().await.unwrap();
        let key = alice
            .orchestrator
            .mls_context()
            .identity_public_key(format!("{}#{}", alice.did, device_id))
            .unwrap();
        alice
            .orchestrator
            .leave_conversation(&created.conversation_id)
            .await
            .unwrap();
        let mut entry = world
            .delivery_service()
            .terminal_entries_for_test()
            .into_iter()
            .find(|entry| entry["$type"] == "blue.catbird.chat.defs#conversationCloseEntry")
            .unwrap();
        entry["entryId"] = json!(uuid::Uuid::new_v4().to_string());

        // A real valid signature and the DS's exact device/key row cannot
        // replace the root DID's repository authorization.
        alice.credentials.clear_authorized_device_keys(&alice.did);
        alice.orchestrator.device_key_cache().lock().await.clear();
        world.delivery_service().queue_device_directory_response(200, json!({"devices":[{
            "userDid":alice.did,"deviceId":device_id,
            "keyId":super::super::canonical_transport::derive_key_id(&key),
            "signaturePublicKey":{"$bytes":base64::engine::general_purpose::STANDARD.encode(&key)}
        }]}));
        assert!(
            alice
                .orchestrator
                .verify_terminal_signed_body(&entry)
                .await
                .is_err(),
            "DS-only key must not authorize a terminal signature without repo capability"
        );
        for keys in [vec![], vec![vec![4; 32]]] {
            alice
                .credentials
                .set_authorized_device_keys(&alice.did, keys);
            alice.orchestrator.device_key_cache().lock().await.clear();
            let before = alice.credentials.device_key_lookup_count(&alice.did);
            assert!(alice
                .orchestrator
                .verify_terminal_signed_body(&entry)
                .await
                .is_err());
            assert_eq!(
                alice.credentials.device_key_lookup_count(&alice.did),
                before + 1,
                "a fresh repo miss must not refresh in a loop"
            );
        }

        alice.orchestrator.device_key_cache().lock().await.clear();
        alice
            .credentials
            .set_authorized_device_key_resolution_failure(&alice.did, true);
        let before = alice.credentials.device_key_lookup_count(&alice.did);
        for _ in 0..2 {
            assert!(alice
                .orchestrator
                .verify_terminal_signed_body(&entry)
                .await
                .is_err());
        }
        assert_eq!(
            alice.credentials.device_key_lookup_count(&alice.did),
            before + 2,
            "repository failures must remain uncached"
        );
        alice
            .credentials
            .set_authorized_device_key_resolution_failure(&alice.did, false);

        // A published sibling key bypasses an older positive snapshot once.
        alice.orchestrator.device_key_cache().lock().await.insert(
            alice.did.clone(),
            DeviceKeyCacheEntry {
                resolved_at: web_time::Instant::now(),
                lookup: DeviceKeyLookup::Keys(Arc::new(vec![vec![4; 32]])),
            },
        );
        alice
            .credentials
            .set_authorized_device_keys(&alice.did, vec![key]);
        let before = alice.credentials.device_key_lookup_count(&alice.did);
        alice
            .orchestrator
            .verify_terminal_signed_body(&entry)
            .await
            .expect("new repo-published signer refreshes once");
        assert_eq!(
            alice.credentials.device_key_lookup_count(&alice.did),
            before + 1
        );
        let before = alice.credentials.device_key_lookup_count(&alice.did);
        entry["signedRequest"]["signature"] =
            json!(base64::engine::general_purpose::STANDARD.encode([0; 64]));
        assert!(alice
            .orchestrator
            .verify_terminal_signed_body(&entry)
            .await
            .is_err());
        assert_eq!(
            alice.credentials.device_key_lookup_count(&alice.did),
            before,
            "bad signature with an authorized cached key must not refresh"
        );
        assert!(
            !world
                .delivery_service()
                .submitted_prepared_requests()
                .iter()
                .any(|request| request.operation
                    == super::super::canonical_transport::CanonicalOperation::GetDevices),
            "DS directory is never consulted as repository signing authority"
        );
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Server notifications are hints: this performs a fresh authorized inventory
    /// traversal and only mutates the named conversation after terminal proof.
    pub async fn reconcile_terminal_conversation(&self, conversation_id: &str) -> Result<bool> {
        Ok(self
            .reconcile_terminal_inventory(Some(conversation_id))
            .await?
            > 0)
    }

    /// A terminal notification can arrive after an explicit local leave already
    /// removed its projection. A fresh exact admitted hint then acknowledges
    /// the event without recreating data or claiming cryptographic completion.
    pub async fn reconcile_terminal_conversation_hint(
        &self,
        conversation_id: &str,
        terminal_seq: u64,
        closed: bool,
    ) -> Result<bool> {
        let did = self.require_user_did().await?;
        if self
            .storage()
            .get_conversation(&did, conversation_id)
            .await?
            .is_some()
        {
            return self.reconcile_terminal_conversation(conversation_id).await;
        }
        if !(1..=9_007_199_254_740_991).contains(&terminal_seq) {
            return Ok(false);
        }
        let device = self.require_actor_device_id().await?;
        let mut cursor: Option<String> = None;
        let mut pages = PaginationGuard::for_conversations("terminal event acknowledgement");
        let mut found = false;
        loop {
            let mut path = format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={device}&limit=100"
            );
            if let Some(cursor) = &cursor {
                path.push_str("&pageCursor=");
                path.push_str(cursor);
            }
            let page = self
                .terminal_read_json(CanonicalOperation::GetConversations, path)
                .await?;
            let items = page["items"]
                .as_array()
                .ok_or_else(|| terminal_invalid("Terminal inventory is missing items."))?;
            let next = page["nextPageCursor"].as_str().map(str::to_owned);
            pages.observe_page(items.len(), next.as_deref())?;
            for item in items {
                let state = item.get("state").unwrap_or(item);
                if state["coordinates"]["conversationId"].as_str() == Some(conversation_id)
                    && state["coordinates"]["lifecycle"] == "active"
                {
                    return Ok(false);
                }
                if item["conversationId"].as_str() != Some(conversation_id)
                    || item["terminalSeq"].as_u64() != Some(terminal_seq)
                {
                    continue;
                }
                if closed && item["$type"] == "blue.catbird.chat.defs#conversationCloseTombstone" {
                    let retired =
                        super::lifecycle::lifecycle_coordinates(&item["retired"], conversation_id)?;
                    found |= retired["lifecycle"] == "superseded"
                        && item["closedAt"]
                            .as_str()
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .is_some();
                } else if !closed
                    && item["$type"] == "blue.catbird.chat.defs#conversationRemovalTombstone"
                {
                    found |= item["userDid"].as_str() == Some(&did)
                        && item["deviceId"].as_str() == Some(&device)
                        && item["membershipIntervalId"]
                            .as_str()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok())
                            .is_some()
                        && item["removedAt"]
                            .as_str()
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .is_some();
                }
            }
            if page["hasMore"] == true && next.is_none() {
                return Err(terminal_invalid(
                    "Terminal inventory has no continuation cursor.",
                ));
            }
            cursor = next;
            if cursor.is_none() {
                return Ok(found);
            }
        }
    }

    pub async fn reconcile_terminal_conversations(&self) -> Result<usize> {
        self.reconcile_terminal_inventory(None).await
    }

    async fn terminal_read_json(
        &self,
        operation: CanonicalOperation,
        path: String,
    ) -> Result<Value> {
        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation,
                path,
                method: "GET".into(),
                body: None,
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))
    }

    async fn reconcile_terminal_inventory(&self, target: Option<&str>) -> Result<usize> {
        self.check_shutdown().await?;
        let did = self.require_user_did().await?;
        let device = self.require_actor_device_id().await?;
        let mut page_cursor: Option<String> = None;
        let mut pagination = PaginationGuard::for_conversations("terminal conversation inventory");
        let mut inventory_items = Vec::new();
        loop {
            let mut path = format!(
                "/xrpc/blue.catbird.chat.getConversations?actorDeviceId={device}&limit=100"
            );
            if let Some(cursor) = &page_cursor {
                path.push_str("&pageCursor=");
                path.push_str(cursor);
            }
            let page = self
                .terminal_read_json(CanonicalOperation::GetConversations, path)
                .await?;
            let items = page["items"]
                .as_array()
                .ok_or_else(|| terminal_invalid("Conversation inventory is missing items."))?;
            let next = page["nextPageCursor"].as_str().map(str::to_owned);
            pagination.observe_page(items.len(), next.as_deref())?;
            inventory_items.extend(items.iter().cloned());
            if page["hasMore"] == true && next.is_none() {
                return Err(terminal_invalid(
                    "Terminal inventory has no continuation cursor.",
                ));
            }
            page_cursor = next;
            if page_cursor.is_none() {
                break;
            }
        }
        let active_ids: std::collections::HashSet<&str> = inventory_items
            .iter()
            .filter_map(|item| {
                let state = item.get("state").unwrap_or(item);
                (state["coordinates"]["lifecycle"] == "active")
                    .then(|| state["coordinates"]["conversationId"].as_str())
                    .flatten()
            })
            .collect();
        let mut completed = 0;
        for item in &inventory_items {
            let Some(cid) = item["conversationId"].as_str() else {
                continue;
            };
            if target.is_some_and(|target| target != cid) {
                continue;
            }
            let is_close = item["$type"] == "blue.catbird.chat.defs#conversationCloseTombstone";
            // An active successor wins over a retained historical tombstone
            // when acknowledging a generic Changed event. It still needs
            // its own current-device/Welcome handling.
            if is_close && active_ids.contains(cid) {
                continue;
            }
            if !is_close && item["$type"] != "blue.catbird.chat.defs#conversationRemovalTombstone" {
                continue;
            }
            if !is_close
                && (item["userDid"].as_str() != Some(&did)
                    || item["deviceId"].as_str() != Some(&device)
                    || item["membershipIntervalId"]
                        .as_str()
                        .and_then(|id| uuid::Uuid::parse_str(id).ok())
                        .is_none()
                    || item["removedAt"]
                        .as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .is_none())
            {
                continue;
            }
            let Some(terminal_seq) = item["terminalSeq"]
                .as_u64()
                .filter(|s| (1..=9_007_199_254_740_991).contains(s))
            else {
                continue;
            };
            // Old/unknown intervals may be present beside active inventory.
            // Only the actual current-group Commit can end this device.
            let local = self.storage().get_conversation(&did, cid).await?;
            if local.is_none() {
                continue;
            }
            match self
                .consume_terminal_entries(cid, terminal_seq, item, None)
                .await
            {
                Ok(true) if !active_ids.contains(cid) => completed += 1,
                Ok(true) => {}
                Ok(false) => {}
                Err(error) if target.is_some() => return Err(error),
                Err(error) => {
                    tracing::warn!(conversation_id = cid, %error, "Terminal reconciliation preserved local state; retrying on a later sync")
                }
            }
        }
        Ok(completed)
    }

    async fn verify_terminal_signed_body(&self, entry: &Value) -> Result<()> {
        use crate::chat_v2::transcript::{
            decode_strict_json, project_signed_body, SignedMutationKind, VerifiedMutation,
        };
        let entry_id = entry["entryId"]
            .as_str()
            .ok_or_else(|| terminal_invalid("Terminal entry is missing its entry ID."))?;
        super::canonical_transport::validate_uuid(entry_id, "entryId")
            .map_err(|_| terminal_invalid("Terminal entry ID is not a canonical UUID."))?;
        if !entry["seq"]
            .as_u64()
            .is_some_and(|seq| (1..=9_007_199_254_740_991).contains(&seq))
        {
            return Err(terminal_invalid("Terminal entry sequence is invalid."));
        }
        let mut body = entry["signedRequest"]["body"].clone();
        normalize_response_bytes(&mut body);
        let kind = SignedMutationKind::ALL
            .iter()
            .copied()
            .find(|kind| body["$type"].as_str() == Some(kind.type_id()))
            .ok_or_else(|| terminal_invalid("Unknown terminal signed operation."))?;
        let expected_entry = match kind {
            SignedMutationKind::CommitTransition => "blue.catbird.chat.defs#commitEntry",
            SignedMutationKind::LeafRecoveryFulfillment => {
                "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
            }
            SignedMutationKind::LeaveCommitFulfillment => {
                "blue.catbird.chat.defs#leaveCommitFulfillmentEntry"
            }
            SignedMutationKind::ConversationClose => {
                "blue.catbird.chat.defs#conversationCloseEntry"
            }
            _ => return Err(terminal_invalid("Unsupported terminal signed operation.")),
        };
        if entry["$type"].as_str() != Some(expected_entry)
            || entry["conversationId"] != body["prior"]["conversationId"]
        {
            return Err(terminal_invalid(
                "Terminal entry variant or conversation differs from its signed body.",
            ));
        }
        let strict = decode_strict_json(
            &serde_json::to_vec(&body)
                .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
        )
        .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let projected = project_signed_body(kind, &strict)
            .map_err(|e| OrchestratorError::Serialization(e.to_string()))?;
        let signature: [u8; 64] = terminal_bytes(&entry["signedRequest"]["signature"])?
            .try_into()
            .map_err(|_| terminal_invalid("Terminal signature has invalid length."))?;
        let actor = body["actorDid"]
            .as_str()
            .ok_or_else(|| terminal_invalid("Terminal entry has no actor."))?;
        let (mut lookup, cached) = self
            .lookup_authorized_device_keys_with_origin(actor, false)
            .await?;
        // The claimed thumbprint only selects a repository-authorized raw key.
        // A missing key in an older snapshot may be a newly published sibling;
        // refresh once, while a fresh miss and an invalid signature still fail.
        if cached
            && matches!(&lookup,
            super::credential_binding::DeviceKeyLookup::Keys(keys)
            if !keys.iter().any(|key|
                body["keyId"].as_str() == Some(super::canonical_transport::derive_key_id(key).as_str())))
        {
            lookup = self.refresh_authorized_device_keys(actor).await?;
        }
        let valid = match lookup {
            super::credential_binding::DeviceKeyLookup::Keys(keys) => keys
                .iter()
                .any(|key| VerifiedMutation::verify(projected.clone(), signature, key).is_ok()),
            super::credential_binding::DeviceKeyLookup::Unsupported => false,
        };
        if !valid {
            return Err(terminal_invalid(
                "Terminal conversation signature is not authorized.",
            ));
        }
        Ok(())
    }

    async fn consume_verified_conversation_close(
        &self,
        conversation_id: &str,
        group_id: &str,
        tombstone: &Value,
        entry: &Value,
    ) -> Result<bool> {
        let body = &entry["signedRequest"]["body"];
        if entry["$type"] != "blue.catbird.chat.defs#conversationCloseEntry"
            || body["$type"] != "blue.catbird.chat.defs#conversationCloseBody"
            || entry["seq"] != tombstone["terminalSeq"]
            || body["actorDid"] != tombstone["closedByDid"]
            || body["actorDeviceId"] != tombstone["closedByDeviceId"]
            || body["conversationKind"] != tombstone["conversationKind"]
        {
            return Err(terminal_invalid(
                "The close tombstone does not match its signed terminal entry.",
            ));
        }
        let prior = super::lifecycle::lifecycle_coordinates(&body["prior"], conversation_id)?;
        let retired = super::lifecycle::lifecycle_coordinates(&body["retired"], conversation_id)?;
        if retired
            != super::lifecycle::lifecycle_coordinates(&tombstone["retired"], conversation_id)?
            || prior["lifecycle"] != "active"
            || retired["lifecycle"] != "superseded"
            || retired["groupId"] != prior["groupId"]
            || retired["generation"] != prior["generation"]
            || retired["epoch"] != prior["epoch"]
            || retired["confirmationTag"] != prior["confirmationTag"]
            || retired["groupContextHash"] != prior["groupContextHash"]
            || retired["stateVersion"].as_u64()
                != prior["stateVersion"]
                    .as_u64()
                    .and_then(|n| n.checked_add(1))
            || hex::encode(terminal_bytes(&prior["groupId"])?) != group_id
        {
            return Err(terminal_invalid(
                "The signed close does not retire this exact conversation generation.",
            ));
        }
        self.verify_terminal_signed_body(entry).await?;
        let actor = body["actorDid"]
            .as_str()
            .ok_or_else(|| terminal_invalid("Signed close actor is missing."))?;
        let group = terminal_bytes(&prior["groupId"])?;
        let identities = self.mls_context().group_member_identities(group.clone())?;
        // Closing is account authority; a newly enrolled leafless device may
        // close a direct chat using its currently authorized signing key.
        if !identities.iter().any(|id| {
            std::str::from_utf8(id)
                .is_ok_and(|id| super::credential_binding::credential_root_did(id) == actor)
        }) {
            return Err(terminal_invalid(
                "The closing account is not a member of the retained MLS group.",
            ));
        }
        if body["conversationKind"] == "group"
            && identities.iter().any(|id| {
                std::str::from_utf8(id)
                    .map(|id| super::credential_binding::credential_root_did(id) != actor)
                    .unwrap_or(true)
            })
        {
            return Err(terminal_invalid(
                "A group with other participants cannot be closed by this device.",
            ));
        }
        if !matches!(body["conversationKind"].as_str(), Some("direct" | "group")) {
            return Err(terminal_invalid(
                "Signed close conversation kind is invalid.",
            ));
        }
        let transition_lock = self.rejoin_lock(conversation_id).await;
        let _guard = transition_lock.lock().await;
        let current = self.resolve_conversation_context(conversation_id).await?;
        if current.group_id != group_id
            || self
                .reset_blocks_non_reset_transition_locked(conversation_id)
                .await?
        {
            return Ok(false);
        }
        if self.mls_context().get_epoch(group.clone())? != prior["epoch"].as_u64().unwrap()
            || self.mls_context().get_confirmation_tag(group.clone())?
                != terminal_bytes(&prior["confirmationTag"])?
            || self.mls_context().get_group_context_hash(group)?
                != terminal_bytes(&prior["groupContextHash"])?
        {
            return Err(terminal_invalid(
                "Sync the preceding conversation Commits before applying its signed close.",
            ));
        }
        let timestamp = entry["receivedAt"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .ok_or_else(|| terminal_invalid("Close entry timestamp is invalid."))?
            .with_timezone(&Utc);
        self.project_non_reset_state_locked(conversation_id, ConversationState::Closed)
            .await?;
        self.storage().clear_rejoin_flag(conversation_id).await?;
        let entry_id = entry["entryId"]
            .as_str()
            .ok_or_else(|| terminal_invalid("Close entry ID is invalid."))?;
        let marker_id = format!("conversation-closed:{entry_id}");
        if self.storage().message_exists(&marker_id).await? {
            return Ok(true);
        }
        let payload = super::MLSMessagePayload::system("conversation.closed");
        self.storage()
            .store_message(&super::Message {
                id: marker_id,
                conversation_id: conversation_id.into(),
                sender_did: actor.into(),
                text: "This conversation has ended.".into(),
                timestamp,
                epoch: prior["epoch"].as_u64().unwrap(),
                sequence_number: 0,
                is_own: actor == self.require_user_did().await?,
                delivery_status: None,
                payload_json: Some(
                    serde_json::to_string(&payload)
                        .map_err(|e| OrchestratorError::Serialization(e.to_string()))?,
                ),
            })
            .await?;
        Ok(true)
    }

    pub(crate) async fn catch_up_available_welcome(
        &self,
        conversation_id: &str,
        target_epoch: u64,
    ) -> Result<()> {
        let resolved = self.resolve_conversation_context(conversation_id).await?;
        if self.mls_context().get_epoch(resolved.group_id_bytes()?)? >= target_epoch {
            return Ok(());
        }
        self.consume_terminal_entries(
            conversation_id,
            9_007_199_254_740_991,
            &Value::Null,
            Some(target_epoch),
        )
        .await?;
        Ok(())
    }

    async fn consume_terminal_entries(
        &self,
        conversation_id: &str,
        terminal_seq: u64,
        tombstone: &Value,
        max_epoch: Option<u64>,
    ) -> Result<bool> {
        let device = self.require_actor_device_id().await?;
        let resolved = self.resolve_conversation_context(conversation_id).await?;
        let group = resolved.group_id_bytes()?;
        if self
            .mls_context()
            .get_prepared_control(&resolved.group_id)?
            .is_some()
        {
            return Ok(false);
        }
        let mut after = 0u64;
        let mut pagination = PaginationGuard::for_messages("terminal conversation entries");
        loop {
            self.check_shutdown().await?;
            let page = self.terminal_read_json(CanonicalOperation::GetEntries, format!(
                "/xrpc/blue.catbird.chat.getEntries?actorDeviceId={device}&conversationId={conversation_id}&afterSeq={after}&limit=100"
            )).await?;
            let entries = page["entries"]
                .as_array()
                .ok_or_else(|| terminal_invalid("Terminal entry response is missing entries."))?;
            let more = page["hasMore"] == true;
            let next = page["nextAfterSeq"].as_u64();
            let cursor = more.then(|| next.unwrap_or(after).to_string());
            pagination.observe_page(entries.len(), cursor.as_deref())?;
            let mut scanned = after;
            for entry in entries {
                let seq = entry["seq"]
                    .as_u64()
                    .filter(|seq| *seq > scanned && *seq <= 9_007_199_254_740_991)
                    .ok_or_else(|| {
                        terminal_invalid("Terminal entry sequence is not increasing.")
                    })?;
                scanned = seq;
                if seq > terminal_seq {
                    break;
                }
                if entry["conversationId"].as_str() != Some(conversation_id) {
                    return Err(terminal_invalid(
                        "Terminal entry belongs to another conversation.",
                    ));
                }
                let body = &entry["signedRequest"]["body"];
                if body.get("commit").is_none() {
                    if seq == terminal_seq
                        && tombstone["$type"] == "blue.catbird.chat.defs#conversationCloseTombstone"
                    {
                        return self
                            .consume_verified_conversation_close(
                                conversation_id,
                                &resolved.group_id,
                                tombstone,
                                entry,
                            )
                            .await;
                    }
                    continue;
                }
                let prior =
                    super::lifecycle::lifecycle_coordinates(&body["prior"], conversation_id)?;
                let next = super::lifecycle::lifecycle_coordinates(&body["next"], conversation_id)?;
                if terminal_bytes(&prior["groupId"])? != group {
                    continue;
                }
                if next["groupId"] != prior["groupId"]
                    || next["generation"] != prior["generation"]
                    || next["epoch"].as_u64()
                        != prior["epoch"].as_u64().and_then(|e| e.checked_add(1))
                {
                    return Err(terminal_invalid(
                        "Terminal Commit coordinates do not match.",
                    ));
                }
                if max_epoch.is_some_and(|max| next["epoch"].as_u64().unwrap() > max) {
                    return Ok(false);
                }
                let commit = terminal_bytes(&body["commit"]["bytes"])?;
                if terminal_bytes(&body["commit"]["sha256"])? != Sha256::digest(&commit).as_slice()
                {
                    return Err(terminal_invalid("Terminal Commit digest does not match."));
                }
                let protocol = MlsMessageIn::tls_deserialize_exact(&commit)
                    .map_err(|_| terminal_invalid("Terminal Commit framing is invalid."))?
                    .try_into_protocol_message()
                    .map_err(|_| {
                        terminal_invalid("Terminal entry does not contain an MLS message.")
                    })?;
                if protocol.group_id().as_slice() != group
                    || protocol.content_type() != ContentType::Commit
                    || protocol.epoch().as_u64() != prior["epoch"].as_u64().unwrap()
                {
                    return Err(terminal_invalid(
                        "Terminal MLS Commit does not match its conversation and epoch.",
                    ));
                }
                let removed_proof = self
                    .mls_context()
                    .verified_incoming_removal(group.clone(), commit.clone())?;
                let local_epoch = self.mls_context().get_epoch(group.clone())?;
                if protocol.epoch().as_u64() < local_epoch && removed_proof.is_none() {
                    continue;
                }
                if protocol.epoch().as_u64() != local_epoch && removed_proof.is_none() {
                    return Err(terminal_invalid("Earlier conversation Commits must be synchronized before its terminal entry."));
                }
                // The signature binds the manifest to these exact Commit bytes.
                // MLS processing independently authenticates its actual sender
                // and Remove operation before projecting DeviceRemoved.
                self.verify_terminal_signed_body(entry).await?;
                let actor = body["actorDid"]
                    .as_str()
                    .ok_or_else(|| terminal_invalid("Terminal entry is missing its actor."))?;
                let entry_id = entry["entryId"]
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .ok_or_else(|| terminal_invalid("Terminal entry ID is invalid."))?;
                let timestamp = entry["receivedAt"]
                    .as_str()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .ok_or_else(|| terminal_invalid("Terminal entry timestamp is invalid."))?
                    .with_timezone(&Utc);
                self.process_incoming(&super::IncomingEnvelope {
                    conversation_id: conversation_id.into(),
                    sender_did: actor.into(),
                    ciphertext: commit,
                    timestamp,
                    server_message_id: Some(entry_id.into()),
                    server_epoch: prior["epoch"].as_u64(),
                    server_sequence: None,
                })
                .await?;
                if self.is_local_device_removed(conversation_id).await?
                    && (max_epoch.is_none()
                        || !self.mls_context().group_is_active(group.clone())?)
                {
                    let did = self.require_user_did().await?;
                    self.retain_verified_departure_coordinate(conversation_id, &next)
                        .await?;
                    let account_left = seq == terminal_seq
                        && entry["$type"] == "blue.catbird.chat.defs#leaveCommitFulfillmentEntry"
                        && body["$type"] == "blue.catbird.chat.defs#leaveCommitFulfillmentBody"
                        && body["manifest"]["participantChanges"]
                            .as_array()
                            .is_some_and(|changes| {
                                changes.iter().any(|c| {
                                    c["$type"] == "blue.catbird.chat.defs#removeParticipant"
                                        && c["userDid"].as_str() == Some(&did)
                                })
                            })
                        && body["manifest"]["leafChanges"]
                            .as_array()
                            .is_some_and(|changes| {
                                changes.iter().any(|c| {
                                    c["$type"] == "blue.catbird.chat.defs#removeLeaf"
                                        && c["userDid"].as_str() == Some(&did)
                                        && c["deviceId"].as_str() == Some(&device)
                                })
                            });
                    if account_left {
                        let marker_lock = self.rejoin_lock(conversation_id).await;
                        let _marker_guard = marker_lock.lock().await;
                        let marker_id = format!("membership-left:{entry_id}:{device}");
                        if self.storage().message_exists(&marker_id).await? {
                            return Ok(true);
                        }
                        let payload = super::MLSMessagePayload::system("membership.left");
                        self.storage()
                            .store_message(&super::Message {
                                id: marker_id,
                                conversation_id: conversation_id.into(),
                                sender_did: did,
                                text: "You left this conversation.".into(),
                                timestamp,
                                epoch: prior["epoch"].as_u64().unwrap(),
                                sequence_number: 0,
                                is_own: true,
                                delivery_status: None,
                                payload_json: Some(serde_json::to_string(&payload).map_err(
                                    |e| OrchestratorError::Serialization(e.to_string()),
                                )?),
                            })
                            .await?;
                    }
                    return Ok(true);
                }
            }
            if scanned >= terminal_seq || !more {
                return Ok(false);
            }
            let next = next
                .filter(|next| *next == scanned && *next > after)
                .ok_or_else(|| terminal_invalid("Terminal entry pagination did not advance."))?;
            after = next;
        }
    }
}
