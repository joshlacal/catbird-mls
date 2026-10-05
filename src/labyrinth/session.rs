//! One account's Labyrinth session: the synchronous client plus its
//! persisted state. Every method blocks; the orchestrator calls them from
//! `spawn_blocking` (see [`super::hooks`]).

use std::sync::Arc;

use labyrinth::client::{Backends, Labyrinth, LoadedMessage, SystemClock};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::xrpc::{
    XrpcDirectory, XrpcMailboxStore, XrpcOrf, XrpcThreadStore, XrpcTransport,
};
use labyrinth::store::TimeRange;
use labyrinth::virtual_device::Mechanism;
use zeroize::Zeroizing;

use super::map_error;
use super::signer::{ChatKeySigner, LatchedTransportSigner, SignerFault};
use super::state::StateVault;
use crate::orchestrator::error::{OrchestratorError, Result};

/// Everything needed to open a session for one account and chat device.
#[derive(Clone)]
pub struct SessionDeps {
    pub did: String,
    pub transport: Arc<dyn XrpcTransport>,
    pub signer: Arc<dyn ChatKeySigner>,
    pub vault: Arc<dyn StateVault>,
}

/// One page of decrypted history (`load_thread` over a time range).
#[derive(Debug, Clone, Default)]
pub struct HistoryPage {
    /// Ordered by `(timestamp, messageId)`.
    pub messages: Vec<LoadedMessage>,
    /// Messages this device can see but not open (e.g. sent before the
    /// account joined).
    pub undecryptable: usize,
    /// False if mls-ds refused the conversation's sender records; only the
    /// owner archive is then included.
    pub space_readable: bool,
}

/// What importing a conversation's history into local storage did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub imported: usize,
    pub already_present: usize,
    /// Copies flagged by [CB-31] (another copy shares the messageId).
    pub skipped_conflicts: usize,
    /// Owner-archive copies, which carry no sender DID.
    pub skipped_unattributed: usize,
    /// Frames that are not an `MLSMessagePayload`.
    pub skipped_undecodable: usize,
    pub undecryptable: usize,
}

/// A recorded signing failure as an error. Checked before the Labyrinth
/// result, so a failed signature is reported as the cause.
fn surface(fault: &SignerFault) -> Result<()> {
    match fault.take() {
        Some(e) => Err(OrchestratorError::Credential(format!("labyrinth: {e}"))),
        None => Ok(()),
    }
}

impl SessionDeps {
    fn backends(&self) -> Backends {
        let t = self.transport.clone();
        Backends {
            mailbox: Box::new(XrpcMailboxStore::new(&self.did, t.clone())),
            threads: Box::new(XrpcThreadStore::new(&self.did, t.clone())),
            // Single directory: mls-ds. The PDS `mailboxKeys` side of a
            // `CompositeDirectory` has no store yet (plan doc, D6).
            directory: Box::new(XrpcDirectory::new(t.clone())),
            orf: Box::new(XrpcOrf::new(t)),
            publishers: Vec::new(),
            clock: Box::new(SystemClock),
        }
    }

    fn transport_signer(&self, fault: &SignerFault) -> Box<LatchedTransportSigner> {
        Box::new(LatchedTransportSigner::new(
            self.signer.clone(),
            fault.clone(),
        ))
    }

    fn session(
        self,
        lab: Labyrinth,
        fault: SignerFault,
        persisted: Option<Vec<u8>>,
    ) -> LabyrinthSession {
        LabyrinthSession {
            did: self.did.clone(),
            transport_key: self.signer.public_key(),
            lab,
            fault,
            vault: self.vault,
            persisted: persisted.map(Zeroizing::new),
        }
    }

    /// The saved session, caught up with the mailbox; `None` if this
    /// device never enabled Labyrinth for the account.
    pub fn open(self) -> Result<Option<LabyrinthSession>> {
        let Some(saved) = self.vault.load(&self.did).map_err(OrchestratorError::Mls)? else {
            return Ok(None);
        };
        let fault = SignerFault::default();
        let lab = Labyrinth::from_state(
            &saved,
            &self.did,
            self.transport_signer(&fault),
            self.backends(),
        );
        surface(&fault)?;
        let lab = lab.map_err(map_error)?;
        let mut s = self.session(lab, fault, Some(saved));
        s.run(|lab| lab.sync_epochs().map(|_| ()))?;
        Ok(Some(s))
    }

    /// Opens the saved session, or creates the account's mailbox. Fails
    /// with a `Conflict` error when another device already created it:
    /// this device must then restore with a recovery code.
    pub fn enable(self) -> Result<LabyrinthSession> {
        if let Some(s) = self.clone().open()? {
            return Ok(s);
        }
        let fault = SignerFault::default();
        let lab = Labyrinth::initialize(&self.did, self.transport_signer(&fault), self.backends());
        surface(&fault)?;
        let mut s = self.session(lab.map_err(map_error)?, fault, None);
        s.save()?;
        Ok(s)
    }

    /// Enrolls this device from a recovery code (typos are corrected) and
    /// replaces any saved state for the account.
    pub fn restore_with_recovery_code(self, code: &str) -> Result<LabyrinthSession> {
        let fault = SignerFault::default();
        let restored = Labyrinth::restore_with_recovery_code(
            &self.did,
            code,
            self.transport_signer(&fault),
            self.backends(),
        );
        surface(&fault)?;
        let (lab, _enrollment) = restored.map_err(map_error)?;
        let existing = self.vault.load(&self.did).map_err(OrchestratorError::Mls)?;
        let mut s = self.session(lab, fault, existing);
        s.save()?;
        Ok(s)
    }
}

/// An enabled account on this device.
pub struct LabyrinthSession {
    did: String,
    transport_key: [u8; 32],
    lab: Labyrinth,
    fault: SignerFault,
    vault: Arc<dyn StateVault>,
    /// The bytes last read from or written to the vault.
    persisted: Option<Zeroizing<Vec<u8>>>,
}

impl LabyrinthSession {
    /// The account DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// True if this session was opened for `did` with chat key `key`.
    pub fn is_for(&self, did: &str, transport_key: &[u8; 32]) -> bool {
        self.did == did && self.transport_key == *transport_key
    }

    /// This device's Labyrinth device key (hex). Other devices of the
    /// account revoke it with [`revoke_device`](Self::revoke_device).
    pub fn device_key_hex(&self) -> String {
        hex::encode(self.lab.device_public().device_key_pub.0)
    }

    /// Runs `f`, surfaces a signing failure, then saves the state.
    fn run<R>(&mut self, f: impl FnOnce(&mut Labyrinth) -> labyrinth::Result<R>) -> Result<R> {
        let out = f(&mut self.lab);
        surface(&self.fault)?;
        let out = out.map_err(map_error)?;
        self.save()?;
        Ok(out)
    }

    /// Writes the exported state if it changed. A concurrent writer (the
    /// stored bytes are no longer the ones this session saw) is an error.
    fn save(&mut self) -> Result<()> {
        let next = self.lab.export_state().map_err(map_error)?;
        if self.persisted.as_ref().map(|p| p.as_slice()) == Some(next.as_slice()) {
            return Ok(());
        }
        let swapped = self
            .vault
            .compare_exchange(
                &self.did,
                self.persisted.as_deref().map(|v| v.as_slice()),
                &next,
            )
            .map_err(OrchestratorError::Mls)?;
        if !swapped {
            return Err(OrchestratorError::Storage(
                "labyrinth: client state changed concurrently; reopen the session".into(),
            ));
        }
        self.persisted = Some(next);
        Ok(())
    }

    /// A new recovery code for the account (show it once, then drop it).
    pub fn create_recovery_code(&mut self) -> Result<String> {
        self.run(|lab| {
            lab.create_recovery_code(Mechanism::Code)
                .map(|setup| setup.code.to_string())
        })
    }

    /// Archives one sent message for `members` (the conversation's MLS
    /// member DIDs; unenrolled ones are skipped) and writes it at once.
    ///
    /// Flushing per message trades batching for durability: the state blob
    /// does not include unflushed batches, so a killed app would otherwise
    /// lose them (docs/plans/2026-10-05-labyrinth-history-backup.md, D7).
    pub fn archive_sent(
        &mut self,
        conversation_id: &str,
        members: &[String],
        message_id: &str,
        timestamp_ms: u64,
        frame: &[u8],
    ) -> Result<()> {
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        self.run(|lab| {
            let roster = lab.resolve_roster(&members)?;
            lab.archive_outgoing(conversation_id, &roster, message_id, timestamp_ms, frame)?;
            lab.flush().map(|_| ())
        })
    }

    /// Decrypts the conversation's history in `range`.
    pub fn load_history(&mut self, conversation_id: &str, range: TimeRange) -> Result<HistoryPage> {
        let h = self.run(|lab| {
            lab.sync_epochs()?;
            lab.load_thread(conversation_id, range)
        })?;
        Ok(HistoryPage {
            undecryptable: h.undecryptable.len(),
            space_readable: h.space_readable,
            messages: h.messages,
        })
    }

    /// Revokes another device of the account by its Labyrinth device key
    /// and opens a new epoch without it ([CB-11]).
    pub fn revoke_device(&mut self, device_key: [u8; 32]) -> Result<u64> {
        self.run(|lab| {
            lab.revoke_device(&XVerifyingKey(device_key))
                .map(|r| r.new_epoch)
        })
    }

    /// [CB-22]: copies every readable message of the conversation into the
    /// account's own mailbox before leaving. Returns how many were copied.
    pub fn rearchive_before_leave(&mut self, conversation_id: &str) -> Result<usize> {
        self.run(|lab| lab.rearchive_thread_before_leave(conversation_id))
    }
}
