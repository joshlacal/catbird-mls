use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::orchestrator::pagination::PaginationGuard;
use crate::orchestrator::{
    normalize_group_state, ConversationReadyResult, ConversationRecoveryState, ConversationState,
    ConversationView, CredentialStore, DebugWipeLocalGroupResult, DeferredRecoveryReport,
    EngineEvent, GroupState, IncomingEnvelope, MLSAPIClient, MLSOrchestrator, MLSStorageBackend,
    MlsCryptoContext, OrchestratorConfig, OrchestratorError, ResetRecordOutcome, Result,
    StartupReconcileReport,
};
use crate::platform_lifecycle::{PlatformLifecycle, SuspendResult};
use crate::{StorageLifecycleState, StorageLifecycleStatus};
use serde::Deserialize;

pub use crate::orchestrator::MessageProcessingResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    AppSuspend,
    ProcessExit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSyncResult {
    pub full_sync: bool,
    pub performed_sync: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnginePhase {
    New,
    Initialized,
    Suspended,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EngineState {
    phase: EnginePhase,
    initialized_user_did: Option<String>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            phase: EnginePhase::New,
            initialized_user_did: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct EngineLifecycle {
    last_shutdown_reason: Mutex<Option<ShutdownReason>>,
    last_storage_operation_label: Mutex<Option<String>>,
    platform: PlatformLifecycle,
}

#[derive(Debug, Clone)]
pub struct SendResult {
    pub message: crate::orchestrator::Message,
    pub events: Vec<EngineEvent>,
}

#[derive(Debug, Clone)]
pub struct CreateConversationRequest {
    pub name: String,
    pub member_dids: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupMutationResult {
    pub conversation: ConversationView,
}

#[derive(Debug, Clone)]
pub struct LeaveResult {
    pub conversation_id: String,
    pub group_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ServerEventEnvelope {
    GroupReset {
        #[serde(alias = "convoId")]
        convo_id: String,
        #[serde(alias = "newGroupId")]
        new_group_id: String,
        #[serde(alias = "resetGeneration")]
        reset_generation: i32,
    },
    ResetRequested {
        #[serde(alias = "convoId")]
        convo_id: String,
        #[serde(alias = "cryptoSessionId")]
        crypto_session_id: String,
        #[serde(alias = "resetGeneration")]
        reset_generation: i32,
        trigger: String,
        #[serde(alias = "requestEventId")]
        request_event_id: String,
        #[serde(alias = "expectedNewMlsGroupIdHex")]
        expected_new_mls_group_id_hex: Option<String>,
    },
}

impl EngineLifecycle {
    fn record_shutdown(&self, reason: ShutdownReason) -> Result<()> {
        *self.lock_last_shutdown_reason()? = Some(reason);
        Ok(())
    }

    fn lock_last_shutdown_reason(&self) -> Result<MutexGuard<'_, Option<ShutdownReason>>> {
        self.last_shutdown_reason.lock().map_err(|_| {
            OrchestratorError::InvalidInput("engine lifecycle lock poisoned".to_string())
        })
    }

    fn platform(&self) -> &PlatformLifecycle {
        &self.platform
    }

    fn record_storage_operation(&self, label: impl Into<String>) -> Result<()> {
        *self.lock_last_storage_operation_label()? = Some(label.into());
        Ok(())
    }

    fn lock_last_storage_operation_label(&self) -> Result<MutexGuard<'_, Option<String>>> {
        self.last_storage_operation_label.lock().map_err(|_| {
            OrchestratorError::InvalidInput("engine lifecycle lock poisoned".to_string())
        })
    }
}

pub struct MlsEngine<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    orchestrator: Arc<MLSOrchestrator<S, A, C, M>>,
    lifecycle: Arc<EngineLifecycle>,
    state: Mutex<EngineState>,
}

impl<S, A, C, M> MlsEngine<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub fn new(
        context: Arc<M>,
        storage: Arc<S>,
        api: Arc<A>,
        credentials: Arc<C>,
        lifecycle: Arc<EngineLifecycle>,
        config: OrchestratorConfig,
    ) -> Self {
        Self {
            orchestrator: Arc::new(MLSOrchestrator::new(
                context,
                storage,
                api,
                credentials,
                config,
            )),
            lifecycle,
            state: Mutex::new(EngineState::default()),
        }
    }

    pub(crate) fn orchestrator(&self) -> Arc<MLSOrchestrator<S, A, C, M>> {
        Arc::clone(&self.orchestrator)
    }

    pub fn initialize_user(&self, user_did: &str) -> Result<()> {
        let actual_user_did = self.current_orchestrator_user_did()?;
        if actual_user_did.as_deref() == Some(user_did) {
            match crate::async_runtime::block_on(self.orchestrator.check_shutdown()) {
                Ok(()) => {
                    *self.lock_state()? = EngineState {
                        phase: EnginePhase::Initialized,
                        initialized_user_did: Some(user_did.to_string()),
                    };
                    return Ok(());
                }
                Err(OrchestratorError::ShuttingDown) => {}
                Err(err) => return Err(err),
            }
        }

        if actual_user_did
            .as_deref()
            .is_some_and(|did| did != user_did)
        {
            crate::async_runtime::block_on(self.orchestrator.shutdown());
        }

        crate::async_runtime::block_on(self.orchestrator.initialize(user_did))?;
        *self.lock_state()? = EngineState {
            phase: EnginePhase::Initialized,
            initialized_user_did: Some(user_did.to_string()),
        };
        self.lifecycle.record_storage_operation("initialized")?;
        Ok(())
    }

    pub fn sync(&self, full_sync: bool) -> Result<EngineSyncResult> {
        let state = self.lock_state()?.clone();
        if state.phase != EnginePhase::Initialized {
            return Ok(EngineSyncResult {
                full_sync,
                performed_sync: false,
            });
        }

        crate::async_runtime::block_on(self.orchestrator.sync_with_server(full_sync))?;
        Ok(EngineSyncResult {
            full_sync,
            performed_sync: true,
        })
    }

    pub fn startup_reconcile(&self) -> Result<StartupReconcileReport> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.startup_reconcile())
    }

    pub fn run_deferred_recovery(&self, reason: &str) -> Result<DeferredRecoveryReport> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.run_deferred_recovery(reason))
    }

    pub fn ensure_conversation_ready(&self, convo_id: &str) -> Result<ConversationReadyResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.ensure_conversation_ready(convo_id))
    }

    pub fn debug_wipe_local_group_for_recovery(
        &self,
        convo_id: &str,
    ) -> Result<DebugWipeLocalGroupResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(
            self.orchestrator
                .debug_wipe_local_group_for_recovery(convo_id),
        )
    }

    pub fn send_payload(&self, convo_id: &str, payload_json: &str) -> Result<SendResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let message = crate::async_runtime::block_on(
            self.orchestrator.send_payload_json(convo_id, payload_json),
        )?;
        let events = vec![EngineEvent::MessageInserted {
            message_id: message.id.clone(),
            convo_id: message.conversation_id.clone(),
        }];
        Ok(SendResult { message, events })
    }

    pub fn create_conversation(
        &self,
        request: CreateConversationRequest,
    ) -> Result<crate::orchestrator::CreateConversationResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let members = if request.member_dids.is_empty() {
            None
        } else {
            Some(request.member_dids.as_slice())
        };
        let conversation = crate::async_runtime::block_on(self.orchestrator.create_group(
            &request.name,
            members,
            request.description.as_deref(),
        ))?;
        self.store_conversation_snapshot(&conversation)?;
        Ok(crate::orchestrator::CreateConversationResult {
            conversation,
            commit_data: None,
            welcome_data: None,
        })
    }

    pub fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
    ) -> Result<GroupMutationResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.add_members(convo_id, member_dids))?;
        let conversation = self.refresh_conversation_snapshot(convo_id)?;
        Ok(GroupMutationResult { conversation })
    }

    pub fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
    ) -> Result<GroupMutationResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.remove_members(convo_id, member_dids))?;
        let conversation = self.refresh_conversation_snapshot(convo_id)?;
        Ok(GroupMutationResult { conversation })
    }

    pub fn leave_conversation(&self, convo_id: &str) -> Result<LeaveResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let group_id = self.current_conversation_group_id(convo_id)?;
        crate::async_runtime::block_on(self.orchestrator.leave_group(convo_id))?;
        Ok(LeaveResult {
            conversation_id: convo_id.to_string(),
            group_id,
        })
    }

    pub fn process_server_event(&self, event_json: &str) -> Result<Vec<EngineEvent>> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        let event: ServerEventEnvelope = serde_json::from_str(event_json).map_err(|err| {
            OrchestratorError::InvalidInput(format!("Failed to decode server event JSON: {err}"))
        })?;

        match event {
            ServerEventEnvelope::GroupReset {
                convo_id,
                new_group_id,
                reset_generation,
            } => {
                let new_group_id = hex::decode(&new_group_id).map_err(|err| {
                    OrchestratorError::InvalidInput(format!(
                        "groupReset newGroupId was not valid hex: {err}"
                    ))
                })?;
                let outcome = crate::async_runtime::block_on(
                    self.orchestrator.record_group_reset_with_outcome(
                        &convo_id,
                        new_group_id,
                        reset_generation,
                    ),
                )?;
                Ok(events_for_reset_outcome(&convo_id, outcome))
            }
            ServerEventEnvelope::ResetRequested {
                convo_id,
                crypto_session_id,
                reset_generation,
                trigger,
                request_event_id,
                expected_new_mls_group_id_hex,
            } => {
                let outcome = crate::async_runtime::block_on(
                    self.orchestrator.record_reset_requested_with_outcome(
                        &convo_id,
                        &crypto_session_id,
                        reset_generation,
                        &trigger,
                        &request_event_id,
                        expected_new_mls_group_id_hex,
                    ),
                )?;
                Ok(events_for_reset_outcome(&convo_id, outcome))
            }
        }
    }

    pub fn process_incoming_message(
        &self,
        envelope: IncomingEnvelope,
    ) -> Result<MessageProcessingResult> {
        self.current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;
        crate::async_runtime::block_on(self.orchestrator.process_incoming_message(&envelope))
    }

    pub fn shutdown(&self, reason: ShutdownReason) -> Result<()> {
        let next_phase = match reason {
            ShutdownReason::AppSuspend => EnginePhase::Suspended,
            ShutdownReason::ProcessExit => EnginePhase::Shutdown,
        };
        let state = self.lock_state()?.clone();
        let preserved_user_did = if reason == ShutdownReason::AppSuspend {
            state
                .initialized_user_did
                .clone()
                .or(self.current_orchestrator_user_did()?)
        } else {
            None
        };

        if state.phase == next_phase {
            self.lifecycle.record_shutdown(reason)?;
            return Ok(());
        }

        match reason {
            ShutdownReason::AppSuspend => {
                crate::async_runtime::block_on(self.orchestrator.suspend())?
            }
            ShutdownReason::ProcessExit => {
                crate::async_runtime::block_on(self.orchestrator.shutdown())
            }
        }
        self.lifecycle.record_shutdown(reason)?;
        *self.lock_state()? = EngineState {
            phase: next_phase,
            initialized_user_did: preserved_user_did,
        };
        Ok(())
    }

    pub fn prepare_for_suspend(&self, reason: &str, deadline: Duration) -> Result<SuspendResult> {
        self.lifecycle
            .record_storage_operation(format!("prepare_for_suspend: {reason}"))?;
        let result = self.lifecycle.platform().begin_suspend(
            self.orchestrator.mls_context().as_ref(),
            reason,
            deadline,
        )?;
        self.shutdown(ShutdownReason::AppSuspend)?;
        Ok(result)
    }

    pub fn resume_from_suspend(&self, reason: &str) -> Result<()> {
        let user_did = {
            let state = self.lock_state()?.clone();
            match state.phase {
                EnginePhase::Suspended | EnginePhase::Initialized => state
                    .initialized_user_did
                    .ok_or(OrchestratorError::NotAuthenticated)?,
                EnginePhase::New | EnginePhase::Shutdown => {
                    return Err(OrchestratorError::NotAuthenticated)
                }
            }
        };

        self.lifecycle
            .platform()
            .resume(self.orchestrator.mls_context().as_ref(), reason);
        self.lifecycle
            .record_storage_operation(format!("resume_from_suspend: {reason}"))?;
        crate::async_runtime::block_on(self.orchestrator.resume_after_suspend(&user_did))?;
        *self.lock_state()? = EngineState {
            phase: EnginePhase::Initialized,
            initialized_user_did: Some(user_did),
        };
        Ok(())
    }

    pub fn reattach_after_suspend(&self, user_did: &str, reason: &str) -> Result<()> {
        if self
            .current_orchestrator_user_did()?
            .as_deref()
            .is_some_and(|did| did != user_did)
        {
            crate::async_runtime::block_on(self.orchestrator.shutdown());
        }

        self.lifecycle
            .platform()
            .resume(self.orchestrator.mls_context().as_ref(), reason);
        self.lifecycle
            .record_storage_operation(format!("reattach_after_suspend: {reason}"))?;
        crate::async_runtime::block_on(self.orchestrator.reattach_after_suspend(user_did))?;
        *self.lock_state()? = EngineState {
            phase: EnginePhase::Initialized,
            initialized_user_did: Some(user_did.to_string()),
        };
        Ok(())
    }

    pub fn interrupt_storage(&self, reason: &str) -> Result<usize> {
        self.lifecycle
            .record_storage_operation(format!("interrupt: {reason}"))?;
        Ok(self
            .lifecycle
            .platform()
            .interrupt_storage(self.orchestrator.mls_context().as_ref(), reason))
    }

    pub fn emergency_close(&self, reason: &str) -> Result<()> {
        self.lifecycle
            .record_storage_operation(format!("emergency_close: {reason}"))?;
        self.lifecycle
            .platform()
            .emergency_close(self.orchestrator.mls_context().as_ref(), reason)?;
        *self.lock_state()? = EngineState {
            phase: EnginePhase::Shutdown,
            initialized_user_did: None,
        };
        self.lifecycle
            .record_shutdown(ShutdownReason::ProcessExit)?;
        Ok(())
    }

    pub fn is_suspended(&self) -> bool {
        self.lock_state()
            .map(|state| state.phase == EnginePhase::Suspended)
            .unwrap_or_else(|_| self.lifecycle.platform().is_suspending())
    }

    pub fn storage_lifecycle_status(&self) -> StorageLifecycleStatus {
        let mut status = self.orchestrator.mls_context().storage_lifecycle_status();
        if status.state != StorageLifecycleState::Closed && self.is_suspended() {
            status.state = StorageLifecycleState::Suspended;
        }
        status
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, EngineState>> {
        self.state
            .lock()
            .map_err(|_| OrchestratorError::InvalidInput("engine state lock poisoned".to_string()))
    }

    fn current_orchestrator_user_did(&self) -> Result<Option<String>> {
        match crate::async_runtime::block_on(self.orchestrator.require_user_did()) {
            Ok(user_did) => Ok(Some(user_did)),
            Err(OrchestratorError::NotAuthenticated) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn current_conversation_group_id(&self, convo_id: &str) -> Result<Option<String>> {
        let user_did = self
            .current_orchestrator_user_did()?
            .ok_or(OrchestratorError::NotAuthenticated)?;

        if let Some(conversation) = crate::async_runtime::block_on(
            self.orchestrator
                .storage()
                .get_conversation(&user_did, convo_id),
        )? {
            return Ok(Some(conversation.group_id));
        }

        Ok(crate::async_runtime::block_on(async {
            self.orchestrator
                .conversations()
                .lock()
                .await
                .get(convo_id)
                .map(|conversation| conversation.group_id.clone())
        }))
    }

    fn refresh_conversation_snapshot(&self, convo_id: &str) -> Result<ConversationView> {
        let snapshot = crate::async_runtime::block_on(async {
            let mut cursor: Option<String> = None;
            let mut pagination = PaginationGuard::for_conversations("engine conversation refresh");
            loop {
                let page = self
                    .orchestrator
                    .api_client()
                    .get_conversations(100, cursor.as_deref())
                    .await?;
                pagination.observe_page(page.conversations.len(), page.cursor.as_deref())?;
                if let Some(conversation) = page
                    .conversations
                    .into_iter()
                    .find(|conversation| conversation.conversation_id == convo_id)
                {
                    return Ok(conversation);
                }
                cursor = page.cursor;
                if cursor.is_none() {
                    break;
                }
            }

            self.orchestrator
                .conversations()
                .lock()
                .await
                .get(convo_id)
                .cloned()
                .ok_or_else(|| OrchestratorError::ConversationNotFound(convo_id.to_string()))
        })?;
        self.store_conversation_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    fn store_conversation_snapshot(&self, conversation: &ConversationView) -> Result<()> {
        let state = GroupState {
            group_id: conversation.group_id.clone(),
            conversation_id: conversation.conversation_id.clone(),
            epoch: conversation.epoch,
            members: conversation
                .members
                .iter()
                .map(|member| member.did.clone())
                .collect(),
        };

        crate::async_runtime::block_on(async {
            self.orchestrator
                .conversations()
                .lock()
                .await
                .insert(conversation.conversation_id.clone(), conversation.clone());
            {
                let mut states = self.orchestrator.group_states().lock().await;
                normalize_group_state(&mut states, state.clone());
            }
            self.orchestrator.storage().set_group_state(&state).await?;
            // A server snapshot is a NON-reset projection: it must never
            // overwrite a committed RESET_PENDING authority (durable payload
            // or cached state), or a backend that clears the reset tuple on
            // an "active" write silently loses the reset. Take the transition
            // lock and route through the same reset-aware projection every
            // other non-reset transition uses; ResetPending always wins.
            let transition_lock = self
                .orchestrator
                .rejoin_lock(&conversation.conversation_id)
                .await;
            let _transition_guard = transition_lock.lock().await;
            let projected = self
                .orchestrator
                .project_non_reset_state_locked(
                    &conversation.conversation_id,
                    ConversationState::Active,
                )
                .await?;
            if !projected {
                tracing::info!(
                    convo_id = %conversation.conversation_id,
                    "conversation snapshot stored; Active projection skipped — reset authority is pending"
                );
            }
            Ok(())
        })
    }
}

fn events_for_reset_outcome(convo_id: &str, outcome: ResetRecordOutcome) -> Vec<EngineEvent> {
    if outcome != ResetRecordOutcome::Recorded {
        return Vec::new();
    }

    vec![
        EngineEvent::RecoveryStateChanged {
            convo_id: convo_id.to_string(),
            state: ConversationRecoveryState::ResetPending,
        },
        EngineEvent::NeedsUiRefresh {
            convo_id: convo_id.to_string(),
        },
    ]
}

#[cfg(test)]
mod reset_aware_snapshot_tests {
    //! `store_conversation_snapshot` is a NON-reset projection. It used to
    //! write `ConversationState::Active` straight to storage and the state
    //! cache with no reset guard, bypassing `project_non_reset_state_locked`
    //! — so an ordinary server refresh (create/add/remove members) could
    //! erase a committed RESET_PENDING authority on any backend that clears
    //! the reset tuple on an "active" write. Found by the 2026-08-15 Android
    //! reset-lineage analysis; fixed by routing the projection through the
    //! reset-aware path under the transition lock.

    use std::sync::Arc;

    use crate::orchestrator::{ConversationState, OrchestratorConfig};
    use crate::recovery_e2e_harness::TestWorld;
    use crate::MlsEngine;

    #[test]
    fn server_snapshot_never_overwrites_committed_reset_authority() {
        crate::async_runtime::block_on(async {
            let mut world = TestWorld::new();
            world.add_client("Alice").await;
            world.register_device("Alice").await.expect("register");
            let alice = world.client("Alice");
            let convo = alice
                .orchestrator
                .create_group("snapshot vs reset", None, None)
                .await
                .expect("create group");
            let convo_id = convo.conversation_id.clone();

            // Server-pushed reset: durable authority is committed.
            let new_group_id = hex::decode("aabbccddeeff00112233445566778899").unwrap();
            alice
                .orchestrator
                .record_group_reset(&convo_id, new_group_id, 7)
                .await
                .expect("record reset");
            let pending_before = alice
                .storage
                .get_persisted_reset_pending(&convo_id)
                .expect("reset authority persisted");
            assert_eq!(pending_before.reset_generation, 7);

            // An engine over the SAME storage handle refreshes the snapshot —
            // the exact path create_conversation / add_members / remove_members
            // take after every server round-trip.
            let engine = MlsEngine::new(
                alice.orchestrator.mls_context().clone(),
                Arc::new(alice.storage.clone()),
                Arc::new(world.delivery_service().clone_as(&alice.did)),
                Arc::new(alice.credentials.clone()),
                Arc::new(crate::EngineLifecycle::default()),
                OrchestratorConfig::default(),
            );
            engine
                .orchestrator()
                .initialize(&alice.did)
                .await
                .expect("engine init");
            engine
                .store_conversation_snapshot(&convo)
                .expect("snapshot store must succeed even when projection is skipped");

            // Durable authority is intact — the Active projection was skipped,
            // not applied over the reset.
            let pending_after = alice
                .storage
                .get_persisted_reset_pending(&convo_id)
                .expect("REGRESSION: a server snapshot erased committed reset authority");
            assert_eq!(pending_after.reset_generation, 7);
            assert!(
                !matches!(
                    alice.storage.get_current_state(&convo_id),
                    Some(ConversationState::Active)
                ),
                "REGRESSION: a server snapshot projected Active over a pending reset"
            );
            // And the engine's own orchestrator cache did not learn a lie.
            assert!(matches!(
                engine
                    .orchestrator()
                    .conversation_states()
                    .lock()
                    .await
                    .get(&convo_id),
                None | Some(ConversationState::ResetPending { .. })
            ));
        });
    }
}
