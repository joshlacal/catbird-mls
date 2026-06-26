use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::orchestrator::{
    ConversationReadyResult, ConversationRecoveryState, CredentialStore, DeferredRecoveryReport,
    EngineEvent, IncomingEnvelope, MLSAPIClient, MLSOrchestrator, MLSStorageBackend,
    MlsCryptoContext, OrchestratorConfig, OrchestratorError, ResetRecordOutcome, Result,
    StartupReconcileReport,
};
use crate::platform_lifecycle::{PlatformLifecycle, SuspendResult};
use serde::Deserialize;

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
    platform: PlatformLifecycle,
}

#[derive(Debug, Clone)]
pub struct SendResult {
    pub message: crate::orchestrator::Message,
    pub events: Vec<EngineEvent>,
}

#[derive(Debug, Clone)]
pub struct MessageProcessingResult {
    pub message: Option<crate::orchestrator::Message>,
    pub events: Vec<EngineEvent>,
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
        let message =
            crate::async_runtime::block_on(self.orchestrator.process_incoming(&envelope))?;
        let events = message
            .as_ref()
            .map(|message| {
                vec![EngineEvent::MessageInserted {
                    message_id: message.id.clone(),
                    convo_id: message.conversation_id.clone(),
                }]
            })
            .unwrap_or_default();
        Ok(MessageProcessingResult { message, events })
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

        crate::async_runtime::block_on(self.orchestrator.shutdown());
        self.lifecycle.record_shutdown(reason)?;
        *self.lock_state()? = EngineState {
            phase: next_phase,
            initialized_user_did: preserved_user_did,
        };
        Ok(())
    }

    pub fn prepare_for_suspend(&self, reason: &str, deadline: Duration) -> Result<SuspendResult> {
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
        crate::async_runtime::block_on(self.orchestrator.resume_after_suspend(&user_did));
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
        crate::async_runtime::block_on(self.orchestrator.resume_after_suspend(user_did));
        *self.lock_state()? = EngineState {
            phase: EnginePhase::Initialized,
            initialized_user_did: Some(user_did.to_string()),
        };
        Ok(())
    }

    pub fn interrupt_storage(&self, reason: &str) -> Result<usize> {
        Ok(self
            .lifecycle
            .platform()
            .interrupt_storage(self.orchestrator.mls_context().as_ref(), reason))
    }

    pub fn emergency_close(&self, reason: &str) -> Result<()> {
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
