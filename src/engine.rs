use std::sync::{Arc, Mutex, MutexGuard};

use crate::orchestrator::{
    CredentialStore, MLSAPIClient, MLSOrchestrator, MLSStorageBackend, MlsCryptoContext,
    OrchestratorConfig, OrchestratorError, Result,
};

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

    pub fn orchestrator(&self) -> Arc<MLSOrchestrator<S, A, C, M>> {
        Arc::clone(&self.orchestrator)
    }

    pub fn initialize_user(&self, user_did: &str) -> Result<()> {
        let state = self.lock_state()?.clone();
        let same_initialized_did = state.phase == EnginePhase::Initialized
            && state.initialized_user_did.as_deref() == Some(user_did);
        if same_initialized_did {
            match crate::async_runtime::block_on(self.orchestrator.check_shutdown()) {
                Ok(()) => return Ok(()),
                Err(OrchestratorError::ShuttingDown) => {}
                Err(err) => return Err(err),
            }
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

    pub fn shutdown(&self, reason: ShutdownReason) -> Result<()> {
        let next_phase = match reason {
            ShutdownReason::AppSuspend => EnginePhase::Suspended,
            ShutdownReason::ProcessExit => EnginePhase::Shutdown,
        };
        let state = self.lock_state()?.clone();

        if state.phase == next_phase {
            self.lifecycle.record_shutdown(reason)?;
            return Ok(());
        }

        crate::async_runtime::block_on(self.orchestrator.shutdown());
        self.lifecycle.record_shutdown(reason)?;
        *self.lock_state()? = EngineState {
            phase: next_phase,
            initialized_user_did: None,
        };
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, EngineState>> {
        self.state
            .lock()
            .map_err(|_| OrchestratorError::InvalidInput("engine state lock poisoned".to_string()))
    }
}
