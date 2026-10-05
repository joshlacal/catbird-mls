//! UniFFI surface for Labyrinth history backup (feature `labyrinth`).
//!
//! Declared as a child module of `orchestrator_bridge` so it can reach the
//! bridge's inner orchestrator. Bindings are NOT regenerated in this change;
//! run the `ffi-propagate` workflow before any platform uses these methods,
//! and add `submit_labyrinth_request` to `OrchestratorAPICallback` first
//! (without it every call below fails with an `Api` error).

use super::{OrchestratorBridge, OrchestratorBridgeError};
use crate::labyrinth::{HistoryPage, ImportReport};
use labyrinth::client::MessageSource;

/// One decrypted history message.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthMessage {
    pub message_id: String,
    /// Absent for owner-archive copies, which carry no sender.
    pub sender_did: Option<String>,
    pub timestamp_ms: u64,
    /// The archived frame: the sent `MLSMessagePayload` JSON.
    pub frame: Vec<u8>,
    /// True for a copy from this account's own re-archive.
    pub from_owner_archive: bool,
    /// Another copy shares this message id ([CB-31]); show both.
    pub conflict: bool,
}

/// One page of decrypted history.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthHistory {
    pub messages: Vec<FfiLabyrinthMessage>,
    pub undecryptable_count: u64,
    pub space_readable: bool,
}

/// What importing a conversation's history stored.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiLabyrinthImport {
    pub imported: u64,
    pub already_present: u64,
    pub skipped: u64,
    pub undecryptable: u64,
}

fn history_to_ffi(page: HistoryPage) -> FfiLabyrinthHistory {
    FfiLabyrinthHistory {
        undecryptable_count: page.undecryptable as u64,
        space_readable: page.space_readable,
        messages: page
            .messages
            .into_iter()
            .map(|m| FfiLabyrinthMessage {
                message_id: m.message_id,
                sender_did: m.sender,
                timestamp_ms: m.timestamp,
                frame: m.frame,
                from_owner_archive: m.source == MessageSource::Owner,
                conflict: m.conflict,
            })
            .collect(),
    }
}

fn import_to_ffi(r: ImportReport) -> FfiLabyrinthImport {
    FfiLabyrinthImport {
        imported: r.imported as u64,
        already_present: r.already_present as u64,
        skipped: (r.skipped_conflicts + r.skipped_unattributed + r.skipped_undecodable) as u64,
        undecryptable: r.undecryptable as u64,
    }
}

#[uniffi::export]
impl OrchestratorBridge {
    /// Turn on encrypted history backup for the signed-in account on this
    /// device. Returns this device's Labyrinth device key (hex).
    pub fn labyrinth_enable_backup(&self) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_enable(),
        )?)
    }

    /// Create a recovery code. Show it to the user once; it is not stored.
    pub fn labyrinth_create_recovery_code(&self) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_create_recovery_code(),
        )?)
    }

    /// Enroll this device into the account's backup with a recovery code.
    /// Returns this device's Labyrinth device key (hex).
    pub fn labyrinth_restore_with_recovery_code(
        &self,
        code: String,
    ) -> Result<String, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_restore_with_recovery_code(&code),
        )?)
    }

    /// Decrypted history of a conversation in `[from_ms, until_ms)`.
    pub fn labyrinth_load_history_page(
        &self,
        conversation_id: String,
        from_ms: Option<u64>,
        until_ms: Option<u64>,
    ) -> Result<FfiLabyrinthHistory, OrchestratorBridgeError> {
        let page = crate::async_runtime::block_on(self.inner.labyrinth_load_history(
            &conversation_id,
            from_ms,
            until_ms,
        ))?;
        Ok(history_to_ffi(page))
    }

    /// Store a conversation's archived history locally (new device).
    pub fn labyrinth_import_history(
        &self,
        conversation_id: String,
    ) -> Result<FfiLabyrinthImport, OrchestratorBridgeError> {
        let report =
            crate::async_runtime::block_on(self.inner.labyrinth_import_history(&conversation_id))?;
        Ok(import_to_ffi(report))
    }

    /// Revoke another device of this account from the backup.
    pub fn labyrinth_revoke_device(
        &self,
        device_key_hex: String,
    ) -> Result<u64, OrchestratorBridgeError> {
        Ok(crate::async_runtime::block_on(
            self.inner.labyrinth_revoke_device(&device_key_hex),
        )?)
    }
}
