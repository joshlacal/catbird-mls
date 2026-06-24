use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::orchestrator::{OrchestratorError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspendResult {
    pub accepting_new_work: bool,
    pub interrupted_contexts: u32,
}

#[derive(Debug, Default)]
pub struct PlatformLifecycle {
    suspending: AtomicBool,
}

impl PlatformLifecycle {
    pub fn begin_suspend<M: MlsCryptoContext>(
        &self,
        context: &M,
        _reason: &str,
        _deadline: Duration,
    ) -> Result<SuspendResult> {
        self.suspending.store(true, Ordering::Release);
        context.set_suspended(true);
        let interrupted_contexts = context.interrupt_storage() as u32;
        Ok(SuspendResult {
            accepting_new_work: false,
            interrupted_contexts,
        })
    }

    pub fn resume<M: MlsCryptoContext>(&self, context: &M, _reason: &str) {
        context.set_suspended(false);
        self.suspending.store(false, Ordering::Release);
    }

    pub fn interrupt_storage<M: MlsCryptoContext>(&self, context: &M, _reason: &str) -> usize {
        context.interrupt_storage()
    }

    pub fn emergency_close<M: MlsCryptoContext>(&self, context: &M, _reason: &str) -> Result<()> {
        self.suspending.store(true, Ordering::Release);
        context.set_suspended(true);
        context
            .flush_and_prepare_close()
            .map_err(OrchestratorError::from)
    }

    pub fn is_suspending(&self) -> bool {
        self.suspending.load(Ordering::Acquire)
    }
}
