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

    /// A recovery-critical storage write failed (WS-5.2). `operation` is the
    /// storage-trait method name (e.g. `mark_needs_rejoin`). Failing such a
    /// write silently cancels deferred recovery across restart, so platforms
    /// should surface it (diagnostics, error UI) rather than ignore it.
    fn on_recovery_storage_write_failed(&self, _convo_id: &str, _operation: &str, _error: &str) {}

    /// A credential-binding check failed in warn-and-allow mode (WS-3 stage 1,
    /// ADR-009 D5). The operation continued; platforms should surface this in
    /// diagnostics/telemetry — a clean week of field data gates the enforce
    /// flip. `operation` is the ADR-009 D5 operation tag (`fetch`, `message`,
    /// ...). `convo_id` is `"<none>"` when no conversation is in scope yet
    /// (e.g. key-package fetch during group creation).
    fn on_credential_binding_warning(
        &self,
        _convo_id: &str,
        _operation: &str,
        _expected_did: &str,
        _claimed_identity: &str,
        _reason: &str,
    ) {
    }

    /// Sequencer equivocation detected (WS-3 stage 1, ADR-009 D8 / E3): two
    /// receipts for the same `(conversation, epoch)` carry different commit
    /// hashes. Stage 1 is detection-only — the triggering operation
    /// continued. Hashes are hex-encoded.
    fn on_sequencer_equivocation(
        &self,
        _convo_id: &str,
        _epoch: i32,
        _stored_commit_hash_hex: &str,
        _new_commit_hash_hex: &str,
        _sequencer_did: &str,
    ) {
    }
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
    fn on_recovery_storage_write_failed(&self, _convo_id: &str, _operation: &str, _error: &str) {}
    fn on_credential_binding_warning(
        &self,
        _convo_id: &str,
        _operation: &str,
        _expected_did: &str,
        _claimed_identity: &str,
        _reason: &str,
    ) {
    }
    fn on_sequencer_equivocation(
        &self,
        _convo_id: &str,
        _epoch: i32,
        _stored_commit_hash_hex: &str,
        _new_commit_hash_hex: &str,
        _sequencer_did: &str,
    ) {
    }
}
