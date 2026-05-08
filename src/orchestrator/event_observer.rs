//! Layer 3 quarantine event observer trait.
//!
//! The orchestrator emits quarantine entry/exit events to platform layers
//! (Android, catmos Tauri, catmos-cli, web) so they can show banners,
//! disable composers, and offer a manual reset CTA. The trait is defined
//! here in the platform-agnostic orchestrator module; the UniFFI bridge
//! adapts it to a callback_interface in .
//!
//! Methods are sync to keep callbacks fast (they may be called while holding
//! orchestrator mutexes); platforms should dispatch heavy work to a runtime.

use super::types::{QuarantineExitReason, QuarantineReason};

/// Platform-agnostic observer for orchestrator events. Currently only carries
/// Layer 3 quarantine events; can be extended in future for other event
/// classes without breaking the existing surface (each method has a default).
#[cfg(not(target_arch = "wasm32"))]
pub trait OrchestratorEventObserver: Send + Sync {
    /// Conversation entered quarantine. Called from .
    fn on_conversation_quarantined(
        &self,
        _convo_id: &str,
        _reason: QuarantineReason,
        _suspected_dids: Vec<String>,
    ) {
    }

    /// Conversation exited quarantine. Called from .
    fn on_conversation_quarantine_cleared(&self, _convo_id: &str, _via: QuarantineExitReason) {}
}

#[cfg(target_arch = "wasm32")]
pub trait OrchestratorEventObserver {
    fn on_conversation_quarantined(
        &self,
        _convo_id: &str,
        _reason: QuarantineReason,
        _suspected_dids: Vec<String>,
    ) {
    }
    fn on_conversation_quarantine_cleared(&self, _convo_id: &str, _via: QuarantineExitReason) {}
}
