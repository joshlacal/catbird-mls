//! Clean-slate Spaces-only Labyrinth 1.1 encrypted chat history (`feature = "labyrinth"`).
//!
//! Personal mailboxes live strictly in each account's personal Space on its PDS
//! (`at://{did}/space/blue.catbird.labyrinth.mailbox/self`), and conversation
//! history lives strictly in each conversation's Option A Space on the
//! sequencing `mls-ds` (`at://{authorityDid}/space/blue.catbird.labyrinth.conversation/{conversationId}-{generation}`).
//! `mls-ds` stores zero mailboxes, sender batches, MEKs, attachment manifests,
//! or ORF state (`G6`, `I14`, `2A`).

pub mod flush;
pub mod hooks;
pub mod hooks_status;
pub mod journal;
pub mod mac_gate;
pub mod queue;
pub mod session;
pub mod signer;
pub mod space;
pub mod state;
pub mod status;
pub mod transport;
pub mod write_auth;

pub use mac_gate as mac_guard;
pub use mac_gate as mek_scope;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use crate::orchestrator::error::OrchestratorError;

pub use flush::FlushReport;
pub use hooks_status::ArchiveStatusReport;
pub use queue::{ArchiveQueueStore, ArchiveWorker, MlsArchiveQueue, PendingArchive, QueueConfig};
pub use session::{ArchiveBatch, HistoryPage, ImportReport, LabyrinthSession, SessionDeps};
#[cfg(not(target_arch = "wasm32"))]
pub use signer::OrchestratorChatSigner;
pub use signer::{ChatKeySigner, ContextIdentitySigner, SignerFault};
pub use space::{
    LabyrinthSpaceGateway, LabyrinthSpaceRequest, LabyrinthSpaceResponse, MlsPlacementVault,
    Placement, ResolvingSpaceThreadStore, SpaceMailbox, SpaceResponseMacVerifier,
    SpaceXrpcTransport, ThreadPlacement, PLACEMENT_NAMESPACE,
};
pub use state::{MlsStateVault, StateVault, STATE_NAMESPACE};
pub use status::ArchiveStatus;
pub use transport::{
    ApiGateway, DsDirectoryStore, GatewayXrpcTransport, LabyrinthGateway, XrpcTransportError,
};

/// One `blue.catbird.labyrinth.*` XRPC request ready for the platform gateway.
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
    /// Extra headers: signed `catbird-labyrinth-write*` or `catbird-labyrinth-read*`.
    pub headers: Vec<(String, String)>,
}

/// Async mutex slot holding the current account's Labyrinth session.
pub type LabyrinthSlot = Arc<tokio::sync::Mutex<Option<LabyrinthSession>>>;

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
