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
enum EngineState {
    New,
    Initialized,
    Suspended,
    Shutdown,
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
            state: Mutex::new(EngineState::New),
        }
    }

    pub fn orchestrator(&self) -> Arc<MLSOrchestrator<S, A, C, M>> {
        Arc::clone(&self.orchestrator)
    }

    pub fn initialize_user(&self, user_did: &str) -> Result<()> {
        let mut state = self.lock_state()?;
        if *state == EngineState::Initialized {
            return Ok(());
        }

        crate::async_runtime::block_on(self.orchestrator.initialize(user_did))?;
        *state = EngineState::Initialized;
        Ok(())
    }

    pub fn sync(&self, full_sync: bool) -> Result<EngineSyncResult> {
        let state = *self.lock_state()?;
        if state != EngineState::Initialized {
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
        let mut state = self.lock_state()?;
        let next_state = match reason {
            ShutdownReason::AppSuspend => EngineState::Suspended,
            ShutdownReason::ProcessExit => EngineState::Shutdown,
        };

        if *state == next_state {
            self.lifecycle.record_shutdown(reason)?;
            return Ok(());
        }

        crate::async_runtime::block_on(self.orchestrator.shutdown());
        self.lifecycle.record_shutdown(reason)?;
        *state = next_state;
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, EngineState>> {
        self.state
            .lock()
            .map_err(|_| OrchestratorError::InvalidInput("engine state lock poisoned".to_string()))
    }
}
