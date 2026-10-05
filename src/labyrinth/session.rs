//! One account's Labyrinth session: the synchronous client plus its
//! persisted state. Every method blocks; the orchestrator calls them from
//! `spawn_blocking` (see [`super::hooks`]).

use std::sync::Arc;

use labyrinth::client::{
    Backends, CompositeDirectory, Labyrinth, LoadedMessage, PurgeReport, SystemClock,
};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PdsRecords};
use labyrinth::store::xrpc::{
    XrpcDirectory, XrpcMailboxStore, XrpcOrf, XrpcThreadStore, XrpcTransport,
};
use labyrinth::store::{KeyPublisher, MailboxDirectory, TimeRange};
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
    /// The PDS `mailboxKeys` records, when the platform implements them
    /// (`OrchestratorAPICallback::labyrinth_pds_enabled`). With it, every
    /// epoch is also published to the account's PDS and peers' heads are
    /// cross-checked between PDS and mls-ds ([CB-28], [CB-29]); without
    /// it mls-ds is the only directory (plan doc, D6).
    pub pds: Option<Arc<dyn PdsRecords>>,
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
        let ds = Box::new(XrpcDirectory::new(t.clone()));
        let (directory, publishers): (Box<dyn MailboxDirectory + Send>, Vec<_>) = match &self.pds
        {
            Some(pds) => (
                Box::new(CompositeDirectory::new(
                    Box::new(PdsDirectory::new(pds.clone())),
                    ds,
                )),
                vec![Box::new(PdsPublisher::new(&self.did, pds.clone()))
                    as Box<dyn KeyPublisher + Send>],
            ),
            None => (ds, Vec::new()),
        };
        Backends {
            mailbox: Box::new(XrpcMailboxStore::new(&self.did, t.clone())),
            threads: Box::new(XrpcThreadStore::new(&self.did, t.clone())),
            directory,
            orf: Box::new(XrpcOrf::new(t)),
            publishers,
            clock: Box::new(SystemClock),
        }
    }

    /// With a PDS directory: makes sure the account's PDS carries its
    /// latest epoch (an account enabled before PDS publication, or a
    /// publish that failed after its epoch was created).
    fn backfill_pds(&self, s: &mut LabyrinthSession) -> Result<()> {
        let Some(pds) = &self.pds else {
            return Ok(());
        };
        let latest = s.lab.latest_public().map_err(map_error)?;
        let published = PdsDirectory::new(pds.clone())
            .latest(&self.did)
            .map_err(map_error)?;
        if published.is_none_or(|p| p.seq < latest.seq) {
            s.run(|lab| lab.publish_latest_keys())?;
        }
        Ok(())
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
        let mut s = self.clone().session(lab, fault, Some(saved));
        s.run(|lab| lab.sync_epochs().map(|_| ()))?;
        self.backfill_pds(&mut s)?;
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

/// One conversation's messages for [`LabyrinthSession::archive_many`]:
/// `(conversationId, member DIDs, [(messageId, timestampMs, frame)])`.
pub type ArchiveBatch = (String, Vec<String>, Vec<(String, u64, Vec<u8>)>);

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

    /// Erases this account's saved state on this device (sign-out or
    /// account removal). The session must be dropped afterwards; the
    /// server-side mailbox is untouched.
    pub fn forget(&mut self) -> Result<()> {
        self.vault.delete(&self.did).map_err(OrchestratorError::Mls)?;
        self.persisted = None;
        Ok(())
    }

    /// Deletes the account's Labyrinth data everywhere: the server-side
    /// account deletion (`deleteAccountData`: mailbox purge plus an
    /// unsigned redaction of every item the account wrote), the PDS
    /// `mailboxKeys` records, then this device's saved state. Drop the
    /// session afterwards.
    pub fn purge_account(&mut self) -> Result<PurgeReport> {
        let out = self.lab.purge_account();
        surface(&self.fault)?;
        let report = out.map_err(map_error)?;
        self.forget()?;
        Ok(report)
    }

    /// [CB-36] After chat device `chat_key` was revoked, revokes the
    /// Labyrinth device(s) it enrolled (found by their verified chat
    /// bindings) and opens a new epoch for each. Returns the new epochs;
    /// empty when that chat device enrolled none.
    pub fn revoke_chat_device(&mut self, chat_key: [u8; 32]) -> Result<Vec<u64>> {
        self.run(|lab| {
            lab.revoke_chat_device(&chat_key)
                .map(|v| v.into_iter().map(|r| r.new_epoch).collect())
        })
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
    /// The send path uses the background queue instead ([`super::queue`]).
    pub fn archive_sent(
        &mut self,
        conversation_id: &str,
        members: &[String],
        message_id: &str,
        timestamp_ms: u64,
        frame: &[u8],
    ) -> Result<()> {
        self.archive_many(&[(
            conversation_id.to_owned(),
            members.to_vec(),
            vec![(message_id.to_owned(), timestamp_ms, frame.to_vec())],
        )])
    }

    /// Archives sent messages of several conversations, each item
    /// `(messageId, timestampMs, frame)`, then writes everything with one
    /// flush (one `appendBatch` per conversation and MEK, [CB-20]).
    pub fn archive_many(&mut self, batches: &[ArchiveBatch]) -> Result<()> {
        self.run(|lab| {
            for (conversation_id, members, items) in batches {
                let members: Vec<&str> = members.iter().map(String::as_str).collect();
                let roster = lab.resolve_roster(&members)?;
                for (message_id, ts, frame) in items {
                    lab.archive_outgoing(conversation_id, &roster, message_id, *ts, frame)?;
                }
            }
            lab.flush().map(|_| ())
        })
    }

    /// Whether this account's copy of `message_id` is already stored in the
    /// conversation (live or since unsent): the archive queue's duplicate
    /// check after a crash.
    pub fn has_archived(&mut self, conversation_id: &str, message_id: &str) -> Result<bool> {
        let did = self.did.clone();
        let h = self.run(|lab| lab.load_message(conversation_id, message_id))?;
        Ok(h.messages
            .iter()
            .any(|m| m.message_id == message_id && m.sender.as_deref() == Some(did.as_str()))
            || h.redacted
                .iter()
                .any(|r| r.message_id == message_id && r.sender == did))
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
