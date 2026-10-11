//! Labyrinth 1.1 encrypted chat history over mls-ds (feature `labyrinth`).
//! Plan and decisions: `docs/plans/2026-10-05-labyrinth-history-backup.md`.
//!
//! MLS keeps messages end-to-end encrypted in transit but gives a new or
//! restored device no history. The `labyrinth` crate (private repo
//! `joshlacal/labyrinth`, bookmark `labyrinth-1.1`) adds an encrypted
//! per-account mailbox of key material and an encrypted per-conversation
//! archive that only the account's enrolled devices, or a recovery code,
//! can open. mls-ds stores both behind its `blue.catbird.labyrinth.*`
//! endpoints and sees only ciphertext.
//!
//! This module is the catbird-mls side of that integration:
//!
//! | Piece | File |
//! |---|---|
//! | The `labyrinthWriteBody` headers mls-ds verifies on every procedure | [`write_auth`] |
//! | [`labyrinth::store::xrpc::XrpcTransport`] over the platform gateway | [`transport`] |
//! | Chat device Ed25519 key as Labyrinth's [`labyrinth::sign::TransportSigner`] | [`signer`] |
//! | Client state persisted in the encrypted MLS database | [`state`] |
//! | One account's synchronous Labyrinth session | [`session`] |
//! | The mailbox in the account's own PDS Space, and where each account's mailbox lives | [`space`] |
//! | Orchestrator hooks (enable, restore, archive, history, revoke, leave, sign-out) | [`hooks`] |
//! | Background archive queue (batched, crash-safe) | [`queue`] |
//! | One flush, conversation by conversation | [`flush`] |
//! | Exclusions, dropped rows, pending remote deletion | [`status`] |
//! | UniFFI methods on `OrchestratorBridge` | `ffi.rs` (a child module of `orchestrator_bridge`) |
//!
//! The crate is synchronous and runtime-free; the orchestrator is async.
//! Every Labyrinth call therefore runs on a Tokio blocking thread
//! (`spawn_blocking`) and the transport and signer block on the captured
//! runtime handle for each network or credential call.
//!
//! Platform gateways must implement
//! [`crate::orchestrator::MLSAPIClient::submit_labyrinth_request`]: attach
//! the atproto service-auth JWT whose `lxm` is [`LabyrinthRequest::nsid`],
//! forward the extra headers verbatim, and return the raw response. The
//! UniFFI `OrchestratorAPICallback::submit_labyrinth_request` forwards it
//! (bindings not yet regenerated), and the `*_labyrinth_mailbox_keys`
//! callback methods give the PDS half of the directory. Gateways that can
//! reach the account's PDS Space also implement
//! `submit_labyrinth_space_request` and `labyrinth_space_enabled`
//! ([`space`]).

pub mod flush;
pub mod hooks;
pub mod hooks_status;
pub mod queue;
pub mod session;
pub mod signer;
pub mod space;
pub mod state;
pub mod status;
pub mod transport;
pub mod write_auth;

#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};

use crate::orchestrator::error::OrchestratorError;

pub use flush::FlushReport;
pub use hooks_status::ArchiveStatusReport;
pub use queue::{ArchiveQueueStore, ArchiveWorker, MlsArchiveQueue, PendingArchive, QueueConfig};
pub use session::{ArchiveBatch, HistoryPage, ImportReport, LabyrinthSession, SessionDeps};
pub use signer::{ChatKeySigner, OrchestratorChatSigner, SignerFault};
pub use space::{
    LabyrinthSpaceGateway, LabyrinthSpaceRequest, MlsPlacementVault, Placement, SpaceXrpcTransport,
    PLACEMENT_NAMESPACE,
};
pub use state::{MlsStateVault, StateVault, STATE_NAMESPACE};
pub use status::ArchiveStatus;
pub use transport::{ApiGateway, GatewayXrpcTransport, LabyrinthGateway};

/// One Labyrinth XRPC, ready for the platform gateway.
///
/// It carries no account credential. The gateway adds the service-auth JWT
/// (`lxm` = [`nsid`](Self::nsid)), exactly as it does for clean-chat
/// requests, and sends `headers` unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabyrinthRequest {
    /// The endpoint NSID; the gateway's service-auth `lxm`.
    pub nsid: String,
    /// `GET` for queries, `POST` for procedures.
    pub method: String,
    /// `/xrpc/{nsid}` plus the URL-encoded query string.
    pub path: String,
    /// JSON body of a procedure.
    pub body: Option<Vec<u8>>,
    /// Extra headers: the signed write body and its signature on procedures.
    pub headers: Vec<(String, String)>,
}

/// The orchestrator's Labyrinth session for its current account. `None`
/// until the account enables history backup or its saved state is loaded.
pub type LabyrinthSlot = Arc<Mutex<Option<LabyrinthSession>>>;

/// Maps a Labyrinth error onto the orchestrator's error type.
pub(crate) fn map_error(error: labyrinth::Error) -> OrchestratorError {
    match error {
        labyrinth::Error::BadRecoveryCode => {
            OrchestratorError::InvalidInput("labyrinth: recovery code is invalid".into())
        }
        labyrinth::Error::Backend(m) if m.contains(transport::SIGNING_FAILED) => {
            OrchestratorError::Credential(format!("labyrinth: {m}"))
        }
        other => OrchestratorError::Api(format!("labyrinth: {other}")),
    }
}
