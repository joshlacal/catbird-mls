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
pub mod recovery_shares;
pub mod repo_proof;
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

pub use crate::orchestrator::error::OrchestratorError;

pub use flush::FlushReport;
pub use hooks_status::ArchiveStatusReport;
pub use queue::{ArchiveQueueStore, ArchiveWorker, MlsArchiveQueue, PendingArchive, QueueConfig};
pub use session::{
    ArchiveBatch, HistoryPage, ImportReport, LabyrinthSession, PeerEpochTrust, RotationExclusion,
    SessionDeps, SessionRotationReport,
};
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
    ApiGateway, DsDirectoryStore, GatewayXrpcTransport, LabyrinthGateway, PreparedAccountDeletion,
    XrpcTransportError,
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

/// `Malformed` texts that are directory/receipt verification failures.
const TRUST_MALFORMED: &[&str] = &[
    "directory epoch gap too long",
    "directory epoch under the wrong number",
];

fn is_trust_malformed(m: &str) -> bool {
    TRUST_MALFORMED.contains(&m)
        || (m.starts_with("sequencer receipt ") && m.ends_with(" mismatch"))
}

/// Whether `error` means a peer's evidence failed verification (signature,
/// chain, fork, attestation, receipt, tamper), as opposed to I/O, stale
/// state or a missing record. `DirectoryIncomplete` is NOT a trust failure:
/// it is the normal state after a chat-side rotation until the PDS copy is
/// backfilled.
pub(crate) fn is_trust_failure(error: &labyrinth::Error) -> bool {
    use labyrinth::Error as E;
    match error {
        E::Decrypt
        | E::BadSignature
        | E::BadPublicKey
        | E::DeviceTampered
        | E::EpochTruncated { .. }
        | E::EpochRollback { .. }
        | E::DirectoryFork { .. }
        | E::Unattested
        | E::WrongEpoch
        | E::RosterMismatch
        | E::MekMismatch
        | E::EpochSquatted { .. }
        | E::MemberTampered { .. }
        | E::ReceiptCommitmentMismatch
        | E::WriterRollback { .. } => true,
        E::Malformed(m) => is_trust_malformed(m),
        _ => false,
    }
}

/// Whether `error` is operational (reachability, stale or missing evidence,
/// store state): retrying later may succeed. Everything else about a peer's
/// record is treated as untrusted.
pub(crate) fn is_operational_failure(error: &labyrinth::Error) -> bool {
    use labyrinth::Error as E;
    matches!(
        error,
        E::Backend(_)
            | E::DirectoryIncomplete { .. }
            | E::NotFound(_)
            | E::NotSupported(_)
            | E::Forbidden
            | E::Conflict
            | E::Rng
            | E::PendingWrites
    )
}

/// [`is_trust_failure`] for an error already rendered by [`map_error`] into
/// `OrchestratorError::Api`. Matches only the fixed `Display` prefixes of
/// labyrinth's own variants after the `labyrinth: ` tag, so the free text of
/// a `Backend` (remote) error can never classify as a trust failure.
pub(crate) fn is_trust_failure_text(api_message: &str) -> bool {
    const EXACT: &[&str] = &[
        "authentication failed",
        "invalid signature",
        "invalid public key",
        "virtual device record names a non-virtual or active physical device",
        "epoch is not attested by one of the account's chat devices",
        "epoch does not match the one the record names",
        "MEK roster hash does not match its recipients",
        "MEK id does not match the MEK",
        "archived item commitment does not match sequencer receipt",
    ];
    const PREFIX: &[&str] = &[
        "epoch chain truncated: published epoch ",
        "peer epoch rolled back or forked: pinned epoch ",
        "directories disagree on the account's epoch chain: ",
        "a member this device verified in epoch ",
        "space writer revision rolled back for ",
    ];
    let Some(rest) = api_message.strip_prefix("labyrinth: ") else {
        return false;
    };
    if EXACT.contains(&rest) || PREFIX.iter().any(|p| rest.starts_with(p)) {
        return true;
    }
    if let Some(m) = rest.strip_prefix("malformed input: ") {
        return is_trust_malformed(m);
    }
    rest.strip_prefix("epoch ")
        .map(|r| r.trim_start_matches(|c: char| c.is_ascii_digit()))
        .is_some_and(|r| r.starts_with(" is squatted by an invalid record: "))
}

pub(crate) fn map_error(error: labyrinth::Error) -> OrchestratorError {
    match error {
        labyrinth::Error::BadRecoveryCode => {
            OrchestratorError::InvalidInput("labyrinth: recovery code is invalid".into())
        }
        labyrinth::Error::UnsupportedCodeVersion => OrchestratorError::InvalidInput(
            "labyrinth: recovery code version is not supported by this app".into(),
        ),
        labyrinth::Error::Backend(m) if m.contains(transport::SIGNING_FAILED) => {
            OrchestratorError::Credential(format!("labyrinth: {m}"))
        }
        other => OrchestratorError::Api(format!("labyrinth: {other}")),
    }
}
