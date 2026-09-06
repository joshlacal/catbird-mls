// UniFFI bridge for CatbirdClient
//
// Exposes the high-level CatbirdClient to Swift/Kotlin via UniFFI.
// Uses the same callback-based pattern as orchestrator_bridge.rs:
// Swift/Kotlin provides storage, API, and credential backends via callbacks.

use std::sync::Arc;
use std::collections::HashMap;
use crate::orchestrator::credentials::CleanChatSigningAuthority;

use crate::api::MLSContext;
use crate::client::{CatbirdClient, ChatMessage, Conversation};
use crate::orchestrator::OrchestratorConfig;
use crate::orchestrator_bridge::{
    FFIOrchestratorConfig, OrchestratorAPICallback, OrchestratorBridgeError,
    OrchestratorCredentialCallback, OrchestratorStorageCallback,
};

// Re-use the existing adapter types from orchestrator_bridge.
// Since they are private in that module, we re-define thin wrappers here
// that delegate to the same callbacks. An alternative would be to make the
// adapters pub(crate) in orchestrator_bridge — but creating them here keeps
// the two bridges independently evolvable.

use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::*;

// ═══════════════════════════════════════════════════════════════════════════
// Adapter types — identical to orchestrator_bridge but pub(crate)
// We import the conversion helpers from orchestrator_bridge where possible,
// but since those are private, we replicate the minimal set needed.
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) struct ClientStorageAdapter(pub(crate) Arc<dyn OrchestratorStorageCallback>);
pub(crate) struct ClientAPIAdapter(pub(crate) Arc<dyn OrchestratorAPICallback>);
pub(crate) struct ClientCredentialAdapter(
    pub(crate) Arc<dyn OrchestratorCredentialCallback>,
    pub(crate) Arc<std::sync::RwLock<HashMap<String, i64>>>,
);

impl ClientCredentialAdapter {
    pub(crate) fn new(callback: Arc<dyn OrchestratorCredentialCallback>) -> Self {
        Self(callback, Arc::new(std::sync::RwLock::new(HashMap::new())))
    }
}

// -- Conversion helpers (duplicated from orchestrator_bridge for independence) --

fn bridge_err(e: OrchestratorBridgeError) -> crate::orchestrator::error::OrchestratorError {
    crate::orchestrator_bridge::bridge_mappers::bridge_error_to_internal(e)
}

fn ffi_to_convo_view(ffi: &crate::orchestrator_bridge::FFIConversationView) -> crate::orchestrator::Result<ConversationView> {
    let canonical_state = ffi.canonical_state_json.as_ref().map(|json|
        crate::orchestrator::canonical_transport::decode_conversation_state(json.as_bytes())
            .map_err(|error| crate::orchestrator::OrchestratorError::InvalidInput(error.to_string()))
    ).transpose()?;
    let view = ConversationView {
        canonical_state,
        group_id: ffi.group_id.clone(),
        conversation_id: ffi.conversation_id.clone(),
        epoch: ffi.epoch,
        members: ffi
            .members
            .iter()
            .map(|m| MemberView {
                did: m.did.clone(),
                role: if m.role == "admin" {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: if ffi.name.is_some() || ffi.description.is_some() || ffi.avatar_url.is_some() {
            Some(ConversationMetadata {
                name: ffi.name.clone(),
                description: ffi.description.clone(),
                avatar_url: ffi.avatar_url.clone(),
            })
        } else {
            None
        },
        created_at: ffi
            .created_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        updated_at: ffi
            .updated_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        // FFIConversationView does not carry sequencerDid yet (WS-4 rung 3,
        // ADR-010 A6): UniFFI record shapes are deliberately unchanged in
        // rung 2.
        sequencer_did: None,
    };
    crate::orchestrator::admission::validate_conversation_view(&view)?;
    Ok(view)
}

fn ffi_to_message(ffi: &crate::orchestrator_bridge::FFIMessage) -> Message {
    use crate::orchestrator::types::DeliveryStatus;
    use crate::orchestrator_bridge::FFIDeliveryStatus;
    Message {
        id: ffi.id.clone(),
        conversation_id: ffi.conversation_id.clone(),
        sender_did: ffi.sender_did.clone(),
        text: ffi.text.clone(),
        timestamp: ffi
            .timestamp
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|_| chrono::Utc::now()),
        epoch: ffi.epoch,
        sequence_number: ffi.sequence_number,
        is_own: ffi.is_own,
        delivery_status: ffi.delivery_status.as_ref().map(|s| match s {
            FFIDeliveryStatus::DeliveredToAll => DeliveryStatus::DeliveredToAll,
            FFIDeliveryStatus::Partial {
                acked_count,
                total_count,
            } => DeliveryStatus::Partial {
                acked_count: *acked_count,
                total_count: *total_count,
            },
            FFIDeliveryStatus::Pending => DeliveryStatus::Pending,
            FFIDeliveryStatus::LocalOnly => DeliveryStatus::LocalOnly,
        }),
        payload_json: ffi.payload_json.clone(),
    }
}

fn message_to_ffi(msg: &Message) -> crate::orchestrator_bridge::FFIMessage {
    use crate::orchestrator::types::DeliveryStatus;
    use crate::orchestrator_bridge::FFIDeliveryStatus;
    crate::orchestrator_bridge::FFIMessage {
        id: msg.id.clone(),
        conversation_id: msg.conversation_id.clone(),
        sender_did: msg.sender_did.clone(),
        text: msg.text.clone(),
        timestamp: msg.timestamp.to_rfc3339(),
        epoch: msg.epoch,
        sequence_number: msg.sequence_number,
        is_own: msg.is_own,
        delivery_status: msg.delivery_status.as_ref().map(|s| match s {
            DeliveryStatus::DeliveredToAll => FFIDeliveryStatus::DeliveredToAll,
            DeliveryStatus::Partial {
                acked_count,
                total_count,
            } => FFIDeliveryStatus::Partial {
                acked_count: *acked_count,
                total_count: *total_count,
            },
            DeliveryStatus::Pending => FFIDeliveryStatus::Pending,
            DeliveryStatus::LocalOnly => FFIDeliveryStatus::LocalOnly,
        }),
        payload_json: msg.payload_json.clone(),
    }
}

fn join_method_to_string(jm: JoinMethod) -> String {
    match jm {
        JoinMethod::Creator => "creator".to_string(),
        JoinMethod::Welcome => "welcome".to_string(),
        JoinMethod::ExternalCommit => "external_commit".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MLSStorageBackend impl for ClientStorageAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSStorageBackend for ClientStorageAdapter {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .ensure_conversation_exists(
                user_did.to_string(),
                conversation_id.to_string(),
                group_id.to_string(),
            )
            .map_err(bridge_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .update_join_info(
                conversation_id.to_string(),
                user_did.to_string(),
                join_method_to_string(join_method),
                join_epoch,
            )
            .map_err(bridge_err)
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<Option<ConversationView>> {
        self.0
            .get_conversation(user_did.to_string(), conversation_id.to_string())
            .map_err(bridge_err)?
            .as_ref().map(ffi_to_convo_view).transpose()
    }

    async fn list_conversations(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Vec<ConversationView>> {
        self.0
            .list_conversations(user_did.to_string())
            .map_err(bridge_err)?
            .iter().map(ffi_to_convo_view).collect()
    }

    async fn delete_conversations(
        &self,
        user_did: &str,
        ids: &[&str],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .delete_conversations(
                user_did.to_string(),
                ids.iter().map(|s| s.to_string()).collect(),
            )
            .map_err(bridge_err)
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> crate::orchestrator::Result<()> {
        // ResetPending's payload is persisted separately via set_group_state;
        // the client callback only carries the tag.
        self.0
            .set_conversation_state(conversation_id.to_string(), state.tag().to_string())
            .map_err(bridge_err)
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<Option<ConversationState>> {
        self.0
            .get_conversation_state(conversation_id.to_string())
            .map_err(bridge_err)?
            .map(crate::orchestrator_bridge::bridge_mappers::ffi_conversation_state_to_internal)
            .transpose()
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_reset_pending(
                conversation_id.to_string(),
                new_group_id_hex.to_string(),
                reset_generation,
                notified_at_ms,
            )
            .map_err(bridge_err)
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .adopt_reset_pending_target(
                conversation_id.to_string(),
                expected_generation,
                expected_old_target.to_string(),
                authoritative_new_target.to_string(),
            )
            .map_err(bridge_err)
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .complete_reset_pending(
                conversation_id.to_string(),
                expected_generation,
                expected_new_group_id_hex.to_string(),
                landed_epoch,
            )
            .map_err(bridge_err)
    }

    async fn complete_account_exit(&self, conversation_id: &str, expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>, terminal_epoch: u64, terminal_state: ConversationState) -> crate::orchestrator::Result<bool> {
        if !matches!(terminal_state, ConversationState::Closed | ConversationState::DeviceRemoved) {
            return Err(crate::orchestrator::OrchestratorError::Storage("invalid account exit state".into()));
        }
        self.0.complete_account_exit(conversation_id.into(), expected_group_id_hex.into(),
            expected_reset_generation, terminal_epoch, terminal_state.tag().into()).map_err(bridge_err)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> crate::orchestrator::Result<bool> {
        self.0
            .clear_reset_pending_for_delete(conversation_id.to_string(), expected_generation)
            .map_err(bridge_err)
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_quarantined(
                conversation_id.to_string(),
                reason_tag.to_string(),
                since_ms,
            )
            .map_err(bridge_err)
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .clear_quarantine(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .mark_needs_rejoin(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .needs_rejoin(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .clear_rejoin_flag(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn store_message(&self, message: &Message) -> crate::orchestrator::Result<()> {
        self.0
            .store_message(message_to_ffi(message))
            .map_err(bridge_err)
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> crate::orchestrator::Result<Vec<Message>> {
        self.0
            .get_messages(conversation_id.to_string(), limit, before_sequence)
            .map(|v| v.iter().map(ffi_to_message).collect())
            .map_err(bridge_err)
    }

    async fn message_exists(&self, message_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .message_exists(message_id.to_string())
            .map_err(bridge_err)
    }

    async fn store_pending_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_pending_message(conversation_id.to_string(), message_id.to_string())
            .map_err(bridge_err)
    }

    async fn remove_pending_message(&self, message_id: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .remove_pending_message(message_id.to_string())
            .map_err(bridge_err)
    }

    async fn store_sequencer_receipt(
        &self,
        receipt: &SequencerReceipt,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_sequencer_receipt(crate::orchestrator_bridge::bridge_mappers::receipt_to_ffi(
                receipt.clone(),
            ))
            .map_err(bridge_err)
    }

    async fn get_sequencer_receipts(
        &self,
        convo_id: &str,
        since_epoch: Option<i32>,
    ) -> crate::orchestrator::Result<Vec<SequencerReceipt>> {
        self.0
            .get_sequencer_receipts(convo_id.to_string(), since_epoch)
            .map(|receipts| {
                receipts
                    .into_iter()
                    .map(crate::orchestrator_bridge::bridge_mappers::ffi_receipt_to_internal)
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn clear_sequencer_receipts(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_sequencer_receipts(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn get_recovery_state(&self) -> crate::orchestrator::Result<PersistedRecoveryState> {
        self.0
            .get_recovery_state()
            .map(|ffi| PersistedRecoveryState {
                entries: ffi
                    .entries
                    .into_iter()
                    .map(|entry| PersistedRecoveryBackoff {
                        conversation_id: entry.conversation_id,
                        failed_rejoin_count: entry.failed_rejoin_count,
                        last_attempt_at_ms: entry.last_attempt_at_ms,
                        quarantined_until_ms: entry.quarantined_until_ms,
                    })
                    .collect(),
                last_global_rejoin_attempt_at_ms: ffi.last_global_rejoin_attempt_at_ms,
            })
            .map_err(bridge_err)
    }

    async fn set_recovery_backoff(
        &self,
        entry: &PersistedRecoveryBackoff,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_recovery_backoff(crate::orchestrator_bridge::FFIPersistedRecoveryBackoff {
                conversation_id: entry.conversation_id.clone(),
                failed_rejoin_count: entry.failed_rejoin_count,
                last_attempt_at_ms: entry.last_attempt_at_ms,
                quarantined_until_ms: entry.quarantined_until_ms,
            })
            .map_err(bridge_err)
    }

    async fn clear_recovery_backoff(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_recovery_backoff(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn set_last_global_rejoin_attempt_at(
        &self,
        at_ms: i64,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_last_global_rejoin_attempt_at(at_ms)
            .map_err(bridge_err)
    }

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .mark_pending_local_delete(
                conversation_id.to_string(),
                group_id_hex.map(str::to_string),
            )
            .map_err(bridge_err)
    }

    async fn clear_pending_local_delete(
        &self,
        conversation_id: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .clear_pending_local_delete(conversation_id.to_string())
            .map_err(bridge_err)
    }

    async fn list_pending_local_deletes(
        &self,
    ) -> crate::orchestrator::Result<Vec<PendingLocalDelete>> {
        self.0
            .list_pending_local_deletes()
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| PendingLocalDelete {
                        conversation_id: record.conversation_id,
                        group_id_hex: record.group_id_hex,
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "mark_quarantined",
            "clear_quarantine",
            "store_pending_message",
            "remove_pending_message",
            "store_sequencer_receipt",
            "get_sequencer_receipts",
            "clear_sequencer_receipts",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
        ]
    }

    async fn get_sync_cursor(&self, user_did: &str) -> crate::orchestrator::Result<SyncCursor> {
        self.0
            .get_sync_cursor(user_did.to_string())
            .map(|ffi| SyncCursor {
                conversations_cursor: ffi.conversations_cursor,
                messages_cursor: ffi.messages_cursor,
            })
            .map_err(bridge_err)
    }

    async fn set_sync_cursor(
        &self,
        user_did: &str,
        cursor: &SyncCursor,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .set_sync_cursor(
                user_did.to_string(),
                crate::orchestrator_bridge::FFISyncCursor {
                    conversations_cursor: cursor.conversations_cursor.clone(),
                    messages_cursor: cursor.messages_cursor.clone(),
                },
            )
            .map_err(bridge_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> crate::orchestrator::Result<()> {
        self.0
            .set_group_state(crate::orchestrator_bridge::FFIGroupState {
                group_id: state.group_id.clone(),
                conversation_id: state.conversation_id.clone(),
                epoch: state.epoch,
                members: state.members.clone(),
            })
            .map_err(bridge_err)
    }

    async fn get_group_state(
        &self,
        group_id: &str,
    ) -> crate::orchestrator::Result<Option<GroupState>> {
        self.0
            .get_group_state(group_id.to_string())
            .map(|opt| {
                opt.map(|ffi| GroupState {
                    group_id: ffi.group_id,
                    conversation_id: ffi.conversation_id,
                    epoch: ffi.epoch,
                    members: ffi.members,
                })
            })
            .map_err(bridge_err)
    }

    async fn delete_group_state(&self, group_id: &str) -> crate::orchestrator::Result<()> {
        self.0
            .delete_group_state(group_id.to_string())
            .map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MLSAPIClient impl for ClientAPIAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl MLSAPIClient for ClientAPIAdapter {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.0.is_authenticated_as(did.to_string())
    }

    async fn current_did(&self) -> Option<String> {
        self.0.current_did()
    }

    async fn submit_prepared_request(
        &self,
        request: crate::orchestrator::canonical_transport::PreparedRequest,
    ) -> crate::orchestrator::Result<crate::orchestrator::canonical_transport::GatewayResponse>
    {
        let route = request.operation.route();
        let query_bytes = if request.method == "GET" && request.path.contains('?') {
            request
                .path
                .split_once('?')
                .map(|(_, q)| q.as_bytes().to_vec())
        } else {
            None
        };
        let ffi_res = self
            .0
            .submit_prepared_request(
                request.method,
                route.nsid.to_string(),
                request.body,
                query_bytes,
            )
            .map_err(bridge_err)?;
        Ok(crate::orchestrator::canonical_transport::GatewayResponse {
            status: ffi_res.status,
            content_type: ffi_res.content_type,
            body: ffi_res.body,
        })
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> crate::orchestrator::Result<ConversationListPage> {
        let ffi = self.0.get_conversations(limit, cursor.map(str::to_string)).map_err(bridge_err)?;
        Ok(ConversationListPage {
            conversations: ffi.conversations.iter().map(ffi_to_convo_view).collect::<crate::orchestrator::Result<Vec<_>>>()?,
            cursor: ffi.cursor,
        })
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> crate::orchestrator::Result<(Vec<IncomingEnvelope>, Option<String>)> {
        self.0
            .get_messages(
                convo_id.to_string(),
                cursor.map(|s| s.to_string()),
                limit,
                message_type.map(|s| s.to_string()),
                from_epoch,
                to_epoch,
            )
            .map_err(bridge_err)
            .and_then(|ffi| {
                let envelopes = ffi.envelopes.into_iter()
                    .map(|m| crate::orchestrator_bridge::ffi_incoming_envelope_to_internal(m, None))
                    .collect::<crate::orchestrator::Result<Vec<_>>>()?;
                Ok((envelopes, ffi.cursor))
            })
    }

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> crate::orchestrator::Result<Vec<KeyPackageRef>> {
        self.0
            .get_key_packages(actor_device_id.to_string(), dids.to_vec())
            .map(|refs| {
                refs.into_iter()
                    .map(|r| KeyPackageRef {
                        did: r.did,
                        key_package_data: r.key_package_data,
                        hash: r.hash,
                        cipher_suite: r.cipher_suite,
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_key_package_stats(&self) -> crate::orchestrator::Result<KeyPackageStats> {
        self.0
            .get_key_package_stats()
            .map(|ffi| KeyPackageStats {
                available: ffi.available,
                total: ffi.total,
            })
            .map_err(bridge_err)
    }

    async fn sync_key_packages(
        &self,
        local_hashes: &[String],
        device_id: &str,
    ) -> crate::orchestrator::Result<KeyPackageSyncResult> {
        self.0
            .sync_key_packages(local_hashes.to_vec(), device_id.to_string())
            .map(|ffi| KeyPackageSyncResult {
                orphaned_count: ffi.orphaned_count,
                deleted_count: ffi.deleted_count,
            })
            .map_err(bridge_err)
    }

    async fn list_devices(
        &self,
        actor_device_id: &str,
    ) -> crate::orchestrator::Result<Vec<DeviceInfo>> {
        self.0
            .list_devices(actor_device_id.to_string())
            .map(|devices| {
                devices
                    .into_iter()
                    .map(|d| DeviceInfo {
                        device_id: d.device_id,
                        mls_did: d.mls_did,
                        device_uuid: d.device_uuid,
                        created_at: d
                            .created_at
                            .as_ref()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc)),
                        key_id: d.key_id,
                        signature_public_key: d.signature_public_key,
                        auth_generation: d.auth_generation,
                        status: d.status,
                        available_package_count: d.available_package_count,
                        reserved_package_count: d.reserved_package_count,
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_group_info(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0
            .get_group_info(convo_id.to_string())
            .map_err(bridge_err)
    }

    async fn get_welcome(&self, convo_id: &str) -> crate::orchestrator::Result<Vec<u8>> {
        self.0.get_welcome(convo_id.to_string()).map_err(bridge_err)
    }

    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> crate::orchestrator::Result<Vec<(String, DeliveryStatus)>> {
        self.0
            .get_delivery_status(convo_id.to_string(), message_ids.to_vec())
            .map(|list| {
                list.into_iter()
                    .map(|pair| {
                        let status = match pair.status {
                            crate::orchestrator_bridge::FFIDeliveryStatus::DeliveredToAll => {
                                DeliveryStatus::DeliveredToAll
                            }
                            crate::orchestrator_bridge::FFIDeliveryStatus::Partial {
                                acked_count,
                                total_count,
                            } => DeliveryStatus::Partial {
                                acked_count,
                                total_count,
                            },
                            crate::orchestrator_bridge::FFIDeliveryStatus::Pending => {
                                DeliveryStatus::Pending
                            }
                            crate::orchestrator_bridge::FFIDeliveryStatus::LocalOnly => {
                                DeliveryStatus::LocalOnly
                            }
                        };
                        (pair.message_id, status)
                    })
                    .collect()
            })
            .map_err(bridge_err)
    }

    async fn get_group_metadata_blob(
        &self,
        convo_id: &str,
        group_id_hex: &str,
        blob_locator: &str,
    ) -> crate::orchestrator::Result<Vec<u8>> {
        self.0
            .get_group_metadata_blob(
                convo_id.to_string(),
                group_id_hex.to_string(),
                blob_locator.to_string(),
            )
            .map_err(bridge_err)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CredentialStore impl for ClientCredentialAdapter
// ═══════════════════════════════════════════════════════════════════════════

#[async_trait::async_trait]
impl CredentialStore for ClientCredentialAdapter {
    async fn store_signing_key(
        &self,
        user_did: &str,
        key_data: &[u8],
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_signing_key(user_did.to_string(), key_data.to_vec())
            .map_err(bridge_err)
    }

    async fn get_signing_key(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Option<Vec<u8>>> {
        self.0
            .get_signing_key(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn delete_signing_key(&self, user_did: &str) -> crate::orchestrator::Result<()> {
        self.0
            .delete_signing_key(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn store_mls_did(
        &self,
        user_did: &str,
        mls_did: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_mls_did(user_did.to_string(), mls_did.to_string())
            .map_err(bridge_err)
    }

    async fn get_mls_did(&self, user_did: &str) -> crate::orchestrator::Result<Option<String>> {
        self.0.get_mls_did(user_did.to_string()).map_err(bridge_err)
    }

    async fn store_device_uuid(
        &self,
        user_did: &str,
        uuid: &str,
    ) -> crate::orchestrator::Result<()> {
        self.0
            .store_device_uuid(user_did.to_string(), uuid.to_string())
            .map_err(bridge_err)
    }

    async fn get_device_uuid(&self, user_did: &str) -> crate::orchestrator::Result<Option<String>> {
        self.0
            .get_device_uuid(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn has_credentials(&self, user_did: &str) -> crate::orchestrator::Result<bool> {
        self.0
            .has_credentials(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn clear_all(&self, user_did: &str) -> crate::orchestrator::Result<()> {
        self.0.clear_all(user_did.to_string()).map_err(bridge_err)
    }

    async fn get_authorized_device_keys(
        &self,
        user_did: &str,
    ) -> crate::orchestrator::Result<Option<Vec<Vec<u8>>>> {
        self.0
            .get_authorized_device_keys(user_did.to_string())
            .map_err(bridge_err)
    }

    async fn sign_clean_chat_transcript(
        &self,
        user_did: &str,
        transcript: &[u8],
        key_id: &str,
    ) -> crate::orchestrator::Result<Option<CleanChatSigningAuthority>> {
        let authority = self
            .0
            .sign_clean_chat_transcript(
                user_did.to_string(),
                transcript.to_vec(),
                key_id.to_string(),
            )
            .map_err(bridge_err)?
            .map(|authority| {
                if let Some(gen) = authority.auth_generation {
                    if let Ok(mut lock) = self.1.write() {
                        lock.insert(user_did.to_string(), gen);
                    }
                }
                CleanChatSigningAuthority {
                    public_key: authority.public_key,
                    signature: authority.signature,
                    device_id: authority.device_id,
                    auth_generation: authority.auth_generation,
                }
            });
        Ok(authority)
    }

    async fn get_auth_generation(&self, user_did: &str) -> crate::orchestrator::Result<Option<i64>> {
        if let Ok(lock) = self.1.read() {
            if let Some(&gen) = lock.get(user_did) {
                return Ok(Some(gen));
            }
        }
        Ok(Some(1))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Concrete type alias
// ═══════════════════════════════════════════════════════════════════════════

type ConcreteCatbirdClient = CatbirdClient<
    ClientStorageAdapter,
    ClientAPIAdapter,
    ClientCredentialAdapter,
    crate::MLSContext,
>;

// ═══════════════════════════════════════════════════════════════════════════
// UniFFI-exported CatbirdClientBridge
// ═══════════════════════════════════════════════════════════════════════════

/// UniFFI-exported CatbirdClient — the simple chat API for Swift/Kotlin.
///
/// Provides conversations, messages, and sync without exposing any MLS internals.
/// Swift/Kotlin provides the platform-specific storage, API, and credential backends
/// via the same callback interfaces used by OrchestratorBridge.
#[derive(uniffi::Object)]
pub struct CatbirdClientBridge {
    inner: ConcreteCatbirdClient,
}

#[uniffi::export]
impl CatbirdClientBridge {
    /// Create and initialize a new CatbirdClient.
    ///
    /// - `user_did`: The authenticated user's DID
    /// - `mls_context`: The low-level MLS FFI context
    /// - `storage`: Platform storage callback (same as OrchestratorBridge)
    /// - `api_client`: Platform API client callback (same as OrchestratorBridge)
    /// - `credentials`: Platform credential store callback (same as OrchestratorBridge)
    /// - `config`: Orchestrator configuration
    #[uniffi::constructor]
    pub fn new(
        user_did: String,
        mls_context: Arc<MLSContext>,
        storage: Box<dyn OrchestratorStorageCallback>,
        api_client: Box<dyn OrchestratorAPICallback>,
        credentials: Box<dyn OrchestratorCredentialCallback>,
        capabilities: crate::orchestrator_bridge::SecurityStorageCapabilities,
        config: FFIOrchestratorConfig,
    ) -> Result<Arc<Self>, OrchestratorBridgeError> {
        crate::orchestrator_bridge::bridge_mappers::validate_security_capabilities(&capabilities)?;
        let orch_config = OrchestratorConfig {
            max_devices: config.max_devices,
            target_key_package_count: config.target_key_package_count,
            key_package_replenish_threshold: config.key_package_replenish_threshold,
            sync_cooldown_seconds: config.sync_cooldown_seconds,
            max_consecutive_sync_failures: config.max_consecutive_sync_failures,
            sync_pause_duration_seconds: config.sync_pause_duration_seconds,
            rejoin_cooldown_seconds: config.rejoin_cooldown_seconds,
            max_rejoin_attempts: config.max_rejoin_attempts,
            group_config: crate::GroupConfig::default(),
        };

        let client = crate::async_runtime::block_on(CatbirdClient::create(
            user_did,
            mls_context,
            Arc::new(ClientStorageAdapter(Arc::from(storage))),
            Arc::new(ClientAPIAdapter(Arc::from(api_client))),
            Arc::new(ClientCredentialAdapter::new(Arc::from(credentials))),
            orch_config,
        ))
        .map_err(OrchestratorBridgeError::from)?;

        Ok(Arc::new(Self { inner: client }))
    }

    // -- Conversations --

    /// List all conversations.
    pub fn conversations(&self) -> Result<Vec<Conversation>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.conversations())
            .map_err(OrchestratorBridgeError::from)
    }

    /// Create a new conversation.
    pub fn create_conversation(
        &self,
        name: Option<String>,
        participant_dids: Vec<String>,
    ) -> Result<Conversation, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.create_conversation(name, participant_dids))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Messaging --

    /// Send a text message to a conversation.
    pub fn send_message(
        &self,
        conversation_id: String,
        text: String,
    ) -> Result<ChatMessage, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.send_message(&conversation_id, &text))
            .map_err(OrchestratorBridgeError::from)
    }

    /// Get message history for a conversation.
    pub fn messages(
        &self,
        conversation_id: String,
        limit: Option<i32>,
        before_sequence: Option<u64>,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.messages(
            &conversation_id,
            limit,
            before_sequence,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    /// Fetch new messages from the server for a conversation.
    pub fn fetch_new_messages(
        &self,
        conversation_id: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<Vec<ChatMessage>, OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.fetch_new_messages(
            &conversation_id,
            cursor.as_deref(),
            limit,
        ))
        .map_err(OrchestratorBridgeError::from)
    }

    // -- Participants --

    /// Add participants to an existing conversation.
    pub fn add_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.inner
                .add_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    /// Remove participants from a conversation.
    pub fn remove_participants(
        &self,
        conversation_id: String,
        participant_dids: Vec<String>,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(
            self.inner
                .remove_participants(&conversation_id, participant_dids),
        )
        .map_err(OrchestratorBridgeError::from)
    }

    /// Leave a conversation.
    pub fn leave_conversation(
        &self,
        conversation_id: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.leave_conversation(&conversation_id))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Sync --

    /// Sync conversations and messages with the server.
    pub fn sync(&self, full_sync: bool) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.sync(full_sync))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Recovery --
    //
    // Task #43: `rejoin_conversation` was removed from the UniFFI surface. External
    // Commit rejoin is no longer a platform-callable action. Platforms observing
    // unrecoverable local state should call `report_unrecoverable_local(convo_id,
    // reason)` (on `MLSOrchestrator`) so the A7 server-reset pyramid can take over.

    // -- Read state --

    /// Update the read cursor for a conversation.
    pub fn update_cursor(
        &self,
        conversation_id: String,
        cursor: String,
    ) -> Result<(), OrchestratorBridgeError> {
        crate::async_runtime::block_on(self.inner.update_cursor(&conversation_id, &cursor))
            .map_err(OrchestratorBridgeError::from)
    }

    // -- Lifecycle --

    /// Shut down the client, releasing all resources.
    pub fn shutdown(&self) {
        crate::async_runtime::block_on(self.inner.shutdown());
    }

    /// Get the current user's DID.
    pub fn user_did(&self) -> String {
        self.inner.user_did().to_string()
    }
}
