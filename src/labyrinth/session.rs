//! One account's async Spaces-only Labyrinth session plus persisted state.

use std::sync::Arc;

use labyrinth::client::{
    delete_account_remote, Backends, CompositeDirectory, Labyrinth, LoadedMessage, PurgeReport,
    RedactedMessage, RepinProposal, RosterExclusion, SystemClock, ThreadCursor, ThreadList,
};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PublicRepoBackend};
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceRpc};
use labyrinth::store::{
    KeyPublisher, MailboxDirectory, MailboxStore, MaybeSend, MaybeSync, SequencerKey,
    SequencerReceiptKey, TimeRange,
};
use labyrinth::virtual_device::Mechanism;
use zeroize::Zeroizing;

use super::map_error;
use super::signer::{ChatKeySigner, LatchedTransportSigner, SignerFault};
use super::space::{
    thread_placement_key, Placement, ResolvingSpaceThreadStore, SpaceMailbox, ThreadPlacement,
};
use super::state::StateVault;
use super::transport::{DsDirectoryStore, GatewayXrpcTransport};
use crate::orchestrator::error::{OrchestratorError, Result};

/// Authenticated local OpenMLS snapshot of a conversation's group state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGroupSnapshot {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_dids: Vec<String>,
}

/// Local OpenMLS / storage authority consulted during archive flushes.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait LocalConversationAuthority: MaybeSend + MaybeSync {
    /// Returns `Ok(Some(snapshot))` when the conversation still exists in local
    /// OpenMLS or durable conversation storage, or `Ok(None)` when locally gone.
    async fn current_group_snapshot(
        &self,
        conversation_id: &str,
        queued_group_id_hex: Option<&str>,
    ) -> Result<Option<LocalGroupSnapshot>>;
}

/// Everything needed to open a Spaces-only Labyrinth session for one account and chat device.
#[derive(Clone)]
pub struct SessionDeps {
    pub did: String,
    pub transport: Arc<GatewayXrpcTransport>,
    pub signer: Arc<dyn ChatKeySigner>,
    pub vault: Arc<dyn StateVault>,
    /// Public repo `mailboxKeys` CAS backend (`com.atproto.repo.*`), when enabled.
    pub pds: Option<Arc<dyn PublicRepoBackend>>,
    /// Personal & conversation Space RPC transport (`com.atproto.space.*`).
    pub space: Option<Arc<dyn SpaceRpc>>,
    /// Saved mailbox placement & conversation Space pins.
    pub placements: Arc<dyn StateVault>,
    /// Local OpenMLS/storage authority for cross-checking `mls-ds` state.
    pub local_authority: Option<Arc<dyn LocalConversationAuthority>>,
    /// Sequencer DS DID and Ed25519 verifying key (`[CB-38]`).
    pub sequencer_key: Option<SequencerKey>,
    /// Sequencer ES256 receipt verifying key (`I13`, Gate 1).
    pub sequencer_receipt_key: Option<SequencerReceiptKey>,
    /// Optional fallback authority DID for conversation Space resolution in tests.
    pub default_conversation_authority_did: Option<String>,
}

/// One page of decrypted history (`load_thread` over a time range).
#[derive(Debug, Clone, Default)]
pub struct HistoryPage {
    /// Ordered by `(timestamp, messageId)`.
    pub messages: Vec<LoadedMessage>,
    /// Messages this device can see but not open (e.g. sent before the account joined).
    pub undecryptable: usize,
    /// False if the Space refused the conversation's sender records; only the owner archive is included.
    pub space_readable: bool,
    /// Redacted messages (`by_author`, `account_deleted`, or `removed_by_server`).
    pub redacted: Vec<RedactedMessage>,
}

/// What importing a conversation's history into local storage did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub imported: usize,
    pub already_present: usize,
    /// Copies flagged by `[CB-31]` (another copy shares the messageId).
    pub skipped_conflicts: usize,
    /// Owner-archive copies, which carry no sender DID.
    pub skipped_unattributed: usize,
    /// Frames that are not a displayable `MLSMessagePayload`.
    pub skipped_undecodable: usize,
    pub undecryptable: usize,
}

fn surface(fault: &SignerFault) -> Result<()> {
    match fault.take() {
        Some(e) => Err(OrchestratorError::Credential(format!("labyrinth: {e}"))),
        None => Ok(()),
    }
}

fn space_unreachable() -> OrchestratorError {
    OrchestratorError::Api(
        "labyrinth: this account's history mailbox requires ATProto Spaces (`com.atproto.space.*`), \
         which is not reachable on this session"
            .into(),
    )
}

impl SessionDeps {
    fn ds_directory(&self) -> DsDirectoryStore {
        DsDirectoryStore::new(
            self.transport.clone(),
            self.sequencer_key.clone(),
            self.sequencer_receipt_key.clone(),
        )
    }

    fn space_store(&self) -> Option<SpaceMailboxStore> {
        let space = self.space.as_ref()?.clone();
        let publisher: Box<dyn KeyPublisher> = match &self.pds {
            Some(pds) => Box::new(PdsPublisher::new(pds.clone(), &self.did)),
            None => Box::new(self.ds_directory()),
        };
        Some(SpaceMailboxStore::for_owner(&self.did, space, publisher))
    }

    fn backends(&self, _placement: Placement) -> Result<Backends> {
        let space_rpc = self.space.clone().ok_or_else(space_unreachable)?;
        let space_mb = self.space_store().ok_or_else(space_unreachable)?;
        let ds_arc = Arc::new(self.ds_directory());

        let (directory, publishers): (Box<dyn MailboxDirectory>, Vec<Box<dyn KeyPublisher>>) =
            match &self.pds {
                Some(pds) => (
                    Box::new(CompositeDirectory::new(
                        Box::new(PdsDirectory::new(pds.clone())),
                        Box::new(self.ds_directory()),
                    )),
                    vec![Box::new(self.ds_directory())],
                ),
                None => (Box::new(self.ds_directory()), Vec::new()),
            };

        let mailbox: Box<dyn MailboxStore> = Box::new(SpaceMailbox::new(space_mb, Some(ds_arc)));
        let threads = Box::new(ResolvingSpaceThreadStore::new(
            &self.did,
            space_rpc,
            Some(self.transport.clone()),
            self.placements.clone(),
            self.default_conversation_authority_did.clone(),
        ));

        Ok(Backends {
            mailbox,
            threads,
            directory,
            publishers,
            clock: Box::new(SystemClock),
        })
    }

    fn saved_placement(&self) -> Result<Placement> {
        let saved = self
            .placements
            .load(&self.did)
            .map_err(OrchestratorError::Mls)?;
        match saved {
            None => Ok(Placement::Space),
            Some(b) => Placement::parse(&b).ok_or_else(|| {
                OrchestratorError::Storage("labyrinth: unsupported non-Space mailbox placement".into())
            }),
        }
    }

    fn save_placement(&self, placement: Placement) -> Result<()> {
        let current = self
            .placements
            .load(&self.did)
            .map_err(OrchestratorError::Mls)?;
        let next = placement.as_str().as_bytes();
        if current.as_deref() == Some(next) {
            return Ok(());
        }
        let swapped = self
            .placements
            .compare_exchange(&self.did, current.as_deref(), next)
            .map_err(OrchestratorError::Mls)?;
        if !swapped {
            return Err(OrchestratorError::Storage(
                "labyrinth: mailbox placement changed concurrently; reopen the session".into(),
            ));
        }
        Ok(())
    }

    /// Spaces-only mailbox probe (`G6`, `I14`, `I15`): requires reachable `com.atproto.space.*`.
    pub async fn probe_placement(&self) -> Result<Placement> {
        let space = self.space_store().ok_or_else(space_unreachable)?;
        match space.get_epoch(0).await {
            Ok(_) | Err(labyrinth::Error::NotFound("space" | "record" | "repo")) => {
                Ok(Placement::Space)
            }
            Err(e) => Err(map_error(e)),
        }
    }

    /// Remote half of account deletion without client state.
    pub async fn delete_account_remote(&self) -> labyrinth::Result<()> {
        let spaces = self.conversation_spaces()?;
        self.delete_account_remote_at(Some(Placement::Space))
            .await?;
        self.delete_conversation_records(&spaces, self.space.is_some())
            .await
    }

    pub(crate) fn conversation_spaces(&self) -> labyrinth::Result<Vec<String>> {
        let key = thread_placement_key(&self.did);
        let Some(raw) = self
            .placements
            .load(&key)
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
        else {
            return Ok(vec![]);
        };
        let pins: std::collections::BTreeMap<String, ThreadPlacement> = serde_json::from_slice(&raw)
            .map_err(|_| labyrinth::Error::Malformed("saved conversation placements"))?;
        let mut spaces = std::collections::BTreeSet::new();
        for placement in pins.into_values() {
            placement.validate()?;
            if let Some(space) = placement.space {
                spaces.insert(space);
            }
        }
        Ok(spaces.into_iter().collect())
    }

    pub(crate) async fn delete_conversation_records(
        &self,
        spaces: &[String],
        required: bool,
    ) -> labyrinth::Result<()> {
        if spaces.is_empty() && !required {
            return Ok(());
        }
        let transport = self.space.as_ref().ok_or(labyrinth::Error::NotSupported(
            "conversation Space account deletion",
        ))?;
        let mut owned =
            ResolvingSpaceThreadStore::owned_conversation_spaces(transport.as_ref()).await?;
        owned.extend(spaces.iter().cloned());
        owned.sort();
        owned.dedup();
        for space in owned {
            ResolvingSpaceThreadStore::purge_owned_records(&self.did, transport.clone(), &space)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_account_remote_at(
        &self,
        placement: Option<Placement>,
    ) -> labyrinth::Result<()> {
        let _ = placement;
        let space_mb = self.space_store().ok_or_else(|| {
            labyrinth::Error::Backend(
                "personal Space deletion requires the account's Space connection".into(),
            )
        })?;
        let mailbox = SpaceMailbox::new(space_mb, Some(Arc::new(self.ds_directory())));
        let pds = self
            .pds
            .as_ref()
            .map(|p| PdsPublisher::new(p.clone(), &self.did));
        let publishers: Vec<&dyn KeyPublisher> =
            pds.iter().map(|p| p as &dyn KeyPublisher).collect();
        match delete_account_remote(&mailbox, &publishers).await {
            Ok(()) => Ok(()),
            Err(labyrinth::Error::NotFound("space")) => self.verify_mailbox_space_absent().await,
            Err(e) => Err(e),
        }
    }

    async fn verify_mailbox_space_absent(&self) -> labyrinth::Result<()> {
        let Some(space) = self.space.as_ref() else {
            return Ok(());
        };
        let body = space
            .query("com.atproto.space.listSpaces", &[])
            .await
            .map_err(|e| {
                let detail = match (&e.error, &e.message) {
                    (Some(err), Some(msg)) => format!("{err}: {msg}"),
                    (Some(err), None) => err.clone(),
                    (None, Some(msg)) => msg.clone(),
                    (None, None) => "listSpaces failed".into(),
                };
                labyrinth::Error::Backend(format!("space {}: {detail}", e.status))
            })?;
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| labyrinth::Error::Malformed("listSpaces response is not JSON"))?;
        let spaces = parsed["spaces"]
            .as_array()
            .ok_or(labyrinth::Error::Malformed(
                "listSpaces spaces array is missing",
            ))?;
        let expected_mailbox = SpaceRef::mailbox(&self.did).to_string();
        let still_present = spaces.iter().any(|entry| {
            let uri = entry
                .as_str()
                .or_else(|| entry["uri"].as_str())
                .or_else(|| entry["space"].as_str());
            uri.is_some_and(|u| {
                u == expected_mailbox || u.contains("/space/blue.catbird.labyrinth.mailbox")
            })
        });
        if still_present {
            return Err(labyrinth::Error::Backend(
                "space mailbox still present in listSpaces after SpaceNotFound".into(),
            ));
        }
        Ok(())
    }

    async fn backfill_pds(&self, s: &mut LabyrinthSession) -> Result<()> {
        let Some(pds) = &self.pds else {
            return Ok(());
        };
        let latest = s.lab.latest_public().map_err(map_error)?;
        let published = PdsDirectory::new(pds.clone())
            .latest(&self.did)
            .await
            .map_err(map_error)?;
        if published.is_none_or(|p| p.seq < latest.seq) {
            let ds_latest = self
                .ds_directory()
                .latest(&self.did)
                .await
                .map_err(map_error)?;
            if ds_latest.as_ref().is_none_or(|d| d.seq <= latest.seq) {
                let out = s.lab.publish_latest_keys().await;
                s.finish(out)?;
            }
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
        persisted: Option<Zeroizing<Vec<u8>>>,
    ) -> LabyrinthSession {
        LabyrinthSession {
            did: self.did.clone(),
            transport_key: self.signer.public_key(),
            lab,
            fault,
            vault: self.vault,
            placements: self.placements,
            persisted,
        }
    }

    /// Opens the saved session and catches up with the mailbox; `None` if never enabled here.
    pub async fn open(self) -> Result<Option<LabyrinthSession>> {
        let Some(saved) = self
            .vault
            .load_zeroizing(&self.did)
            .map_err(OrchestratorError::Mls)?
        else {
            return Ok(None);
        };
        let placement = self.saved_placement()?;
        let fault = SignerFault::default();
        let lab = Labyrinth::from_state(
            &saved,
            &self.did,
            self.transport_signer(&fault),
            self.backends(placement)?,
        )
        .await;
        surface(&fault)?;
        let lab = lab.map_err(map_error)?;
        let mut s = self.clone().session(lab, fault, Some(saved));
        self.backfill_pds(&mut s).await?;
        let sync_res = s.lab.sync_epochs().await.map(|_| ());
        s.finish(sync_res)?;
        self.backfill_pds(&mut s).await?;
        Ok(Some(s))
    }

    /// Opens the saved session, or initializes the account's Space mailbox (`D4` auto-enrollment).
    pub async fn enable(self) -> Result<LabyrinthSession> {
        if let Some(s) = self.clone().open().await? {
            return Ok(s);
        }
        let placement = self.probe_placement().await?;
        let fault = SignerFault::default();
        let lab = Labyrinth::initialize(
            &self.did,
            self.transport_signer(&fault),
            self.backends(placement)?,
        )
        .await;
        surface(&fault)?;
        let lab = lab.map_err(map_error)?;
        self.save_placement(placement)?;
        let mut s = self.session(lab, fault, None);
        s.save()?;
        Ok(s)
    }

    /// Enrolls this device from a 40-char recovery code (`Gate 3` atomic enrollment).
    pub async fn restore_with_recovery_code(self, code: &str) -> Result<LabyrinthSession> {
        let placement = self.probe_placement().await?;
        let fault = SignerFault::default();
        let restored = Labyrinth::restore_with_recovery_code(
            &self.did,
            code,
            self.transport_signer(&fault),
            self.backends(placement)?,
        )
        .await;
        surface(&fault)?;
        let (lab, _enrollment) = restored.map_err(map_error)?;
        self.save_placement(placement)?;
        let existing = self
            .vault
            .load_zeroizing(&self.did)
            .map_err(OrchestratorError::Mls)?;
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
    placements: Arc<dyn StateVault>,
    persisted: Option<Zeroizing<Vec<u8>>>,
}

impl LabyrinthSession {
    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn is_for(&self, did: &str, transport_key: &[u8; 32]) -> bool {
        self.did == did && self.transport_key == *transport_key
    }

    pub fn forget(&mut self) -> Result<()> {
        self.vault
            .delete(&self.did)
            .map_err(OrchestratorError::Mls)?;
        self.placements
            .delete(&self.did)
            .map_err(OrchestratorError::Mls)?;
        self.placements
            .delete(&thread_placement_key(&self.did))
            .map_err(OrchestratorError::Mls)?;
        self.persisted = None;
        Ok(())
    }

    pub async fn purge_account(&mut self) -> Result<PurgeReport> {
        let out = self.lab.purge_account().await;
        let fault = self.fault.take();
        self.forget()?;
        let mut report = out.unwrap_or_else(|e| PurgeReport {
            remote_pending: Some(e),
            ..PurgeReport::default()
        });
        if let Some(e) = fault {
            report
                .remote_pending
                .get_or_insert(labyrinth::Error::Backend(format!("chat key signer: {e}")));
        }
        Ok(report)
    }

    pub async fn propose_repin(&mut self, did: &str) -> Result<RepinProposal> {
        let out = self.lab.propose_repin(did).await;
        self.finish(out)
    }

    pub async fn repin_peer(&mut self, did: &str, confirmed_head: [u8; 32]) -> Result<()> {
        let out = self.lab.repin_peer(did, &confirmed_head).await.map(|_| ());
        self.finish(out)
    }

    pub async fn list_threads(&mut self) -> Result<ThreadList> {
        let out = self.lab.list_threads_report().await;
        self.finish(out)
    }

    pub async fn revoke_chat_device(&mut self, chat_key: [u8; 32]) -> Result<Vec<u64>> {
        let out = self
            .lab
            .revoke_chat_device(&chat_key)
            .await
            .map(|v| v.into_iter().map(|r| r.new_epoch).collect());
        self.finish(out)
    }

    pub fn device_key_hex(&self) -> String {
        hex::encode(self.lab.device_public().device_key_pub.0)
    }

    fn try_finish<R>(&mut self, out: labyrinth::Result<R>) -> Result<labyrinth::Result<R>> {
        surface(&self.fault)?;
        self.save()?;
        Ok(out)
    }

    fn finish<R>(&mut self, out: labyrinth::Result<R>) -> Result<R> {
        surface(&self.fault)?;
        let out = out.map_err(map_error)?;
        self.save()?;
        Ok(out)
    }

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

    pub async fn create_recovery_code(&mut self) -> Result<String> {
        let out = self
            .lab
            .create_recovery_code(Mechanism::Code)
            .await
            .map(|setup| setup.code.to_string());
        self.finish(out)
    }

    pub async fn archive_sent(
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
        .await
    }

    pub async fn archive_many(&mut self, batches: &[ArchiveBatch]) -> Result<()> {
        let out = async {
            for (conversation_id, members, items) in batches {
                let members: Vec<&str> = members.iter().map(String::as_str).collect();
                let roster = self.lab.resolve_roster(&members).await?;
                for (message_id, ts, frame) in items {
                    self.lab
                        .archive_outgoing(conversation_id, &roster, message_id, *ts, frame)
                        .await?;
                }
            }
            self.lab.flush().await.map(|_| ())
        }
        .await;
        self.finish(out)
    }

    pub async fn has_archived(
        &mut self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<labyrinth::Result<bool>> {
        let did = self.did.clone();
        let raw = self.lab.load_message(conversation_id, message_id).await;
        let h = self.try_finish(raw)?;
        Ok(h.map(|h| {
            h.messages
                .iter()
                .any(|m| m.message_id == message_id && m.sender.as_deref() == Some(did.as_str()))
                || h.redacted
                    .iter()
                    .any(|r| r.message_id == message_id && r.sender == did)
        }))
    }

    pub async fn archive_conversation(
        &mut self,
        conversation_id: &str,
        members: &[String],
        items: &[(String, u64, Vec<u8>)],
    ) -> Result<labyrinth::Result<Vec<RosterExclusion>>> {
        let raw = async {
            let members: Vec<&str> = members.iter().map(String::as_str).collect();
            let r = self.lab.resolve_roster_report(&members).await?;
            for (message_id, ts, frame) in items {
                self.lab
                    .archive_outgoing(conversation_id, &r.roster, message_id, *ts, frame)
                    .await?;
            }
            self.lab.flush_thread(conversation_id).await?;
            Ok(r.excluded)
        }
        .await;
        let out = self.try_finish(raw);
        if !matches!(out, Ok(Ok(_))) {
            self.lab.discard_pending(conversation_id);
        }
        out
    }

    pub fn discard_pending(&mut self, conversation_id: &str) {
        self.lab.discard_pending(conversation_id);
    }

    pub async fn load_history(&mut self, conversation_id: &str, range: TimeRange) -> Result<HistoryPage> {
        let raw = async {
            self.lab.sync_epochs().await?;
            self.lab.load_thread(conversation_id, range).await
        }
        .await;
        let h = self.finish(raw)?;
        Ok(HistoryPage {
            undecryptable: h.undecryptable.len(),
            space_readable: h.space_readable,
            messages: h.messages,
            redacted: h.redacted,
        })
    }

    pub async fn load_history_page(
        &mut self,
        conversation_id: &str,
        before: Option<&ThreadCursor>,
        limit: usize,
        sync: bool,
    ) -> Result<(HistoryPage, Option<ThreadCursor>)> {
        let raw = async {
            if sync {
                self.lab.sync_epochs().await?;
            }
            self.lab.load_thread_page(conversation_id, before, limit).await
        }
        .await;
        let p = self.finish(raw)?;
        Ok((
            HistoryPage {
                undecryptable: p.history.undecryptable.len(),
                space_readable: p.history.space_readable,
                messages: p.history.messages,
                redacted: p.history.redacted,
            },
            p.next,
        ))
    }

    pub async fn revoke_device(&mut self, device_key: [u8; 32]) -> Result<u64> {
        let out = self
            .lab
            .revoke_device(&XVerifyingKey(device_key))
            .await
            .map(|r| r.new_epoch);
        self.finish(out)
    }

    /// `[CB-22]` / `Gate 5`: copies every readable message and own encrypted
    /// attachment of `conversation_id` into the personal mailbox Space and
    /// clears this caller's repo in the conversation Space before leaving.
    pub async fn rearchive_before_leave(&mut self, conversation_id: &str) -> Result<usize> {
        let out = self
            .lab
            .rearchive_and_clear_before_leave(conversation_id)
            .await
            .map(|r| r.messages_archived);
        self.finish(out)
    }
}
