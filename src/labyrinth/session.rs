//! One account's async Spaces-only Labyrinth session plus persisted state.

use std::sync::Arc;

use labyrinth::client::{
    delete_account_remote, Backends, CompositeDirectory, Labyrinth, LoadedMessage, PurgeReport,
    RecoveryMethod, RedactedMessage, RepinProposal, RosterExclusion, RotationReport, ThreadCursor,
    ThreadList,
};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PublicRepoBackend};
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceRpc};
use labyrinth::store::{
    ChatDeviceKey, KeyPublisher, MailboxDirectory, MailboxStore, MaybeSend, MaybeSync,
    MemberDeviceKey, SequencerReceiptKey, TimeRange,
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
/// One member dropped during a mailbox epoch rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationExclusion {
    pub device_key: Option<[u8; 32]>,
    pub reason: String,
    pub recovery_method: Option<Mechanism>,
}

/// A rotation result whose exclusions remain visible to native clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRotationReport {
    pub new_epoch: u64,
    pub exclusions: Vec<RotationExclusion>,
}

fn rotation_report(
    report: RotationReport,
    recovery_methods: &[RecoveryMethod],
) -> SessionRotationReport {
    let exclusions = report
        .excluded
        .into_iter()
        .map(|excluded| {
            let recovery_method = excluded.device_key.and_then(|key| {
                recovery_methods
                    .iter()
                    .find(|method| method.device_key == key)
                    .map(|method| method.mechanism)
            });
            RotationExclusion {
                device_key: excluded.device_key.map(|key| key.0),
                reason: match excluded.reason {
                    labyrinth::client::ExclusionReason::MalformedMember => "malformed-member",
                    labyrinth::client::ExclusionReason::MissingDeviceRecord => {
                        "missing-device-record"
                    }
                    labyrinth::client::ExclusionReason::InvalidDeviceRecord => {
                        "invalid-device-record"
                    }
                    labyrinth::client::ExclusionReason::InvalidMac => "invalid-membership",
                    labyrinth::client::ExclusionReason::Unbound => "unbound-device",
                    labyrinth::client::ExclusionReason::ChatDeviceNotCurrent => {
                        "chat-device-not-current"
                    }
                    labyrinth::client::ExclusionReason::RecoveryExpired => "recovery-expired",
                }
                .into(),
                recovery_method,
            }
        })
        .collect();
    SessionRotationReport {
        new_epoch: report.new_epoch,
        exclusions,
    }
}

/// Authenticated local OpenMLS snapshot of a conversation's group state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGroupSnapshot {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_dids: Vec<String>,
}

/// One DID's leaves in this device's MLS group for a conversation, as of the
/// last conversation entry the group applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLeafKeys {
    pub applied_chat_seq: u64,
    pub keys: Vec<[u8; 32]>,
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

    /// `did`'s leaf signing keys in this device's live MLS group for
    /// `conversation_id`. `None` when the authority holds no such group view
    /// anchored at an applied conversation entry.
    async fn leaf_keys(&self, conversation_id: &str, did: &str) -> Result<Option<LocalLeafKeys>> {
        let _ = (conversation_id, did);
        Ok(None)
    }
}

/// `mls-ds` reports which devices are conversation members; this device's MLS
/// group authenticates them independently. The devices the DS reports active
/// at the last entry the local group applied must be exactly that group's
/// leaves for the DID, so the DS can neither add a writer or sender
/// attestation key nor hide one.
/// ponytail: devices active only outside the local view (before this device
/// joined, after a removal it applied) stay DS-attested; a durable local leaf
/// log would cover them.
struct LocallyCheckedDirectory {
    inner: Box<dyn MailboxDirectory>,
    authority: Arc<dyn LocalConversationAuthority>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for LocallyCheckedDirectory {
    async fn latest(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.inner.latest(did).await
    }

    async fn latest_two_source(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.inner.latest_two_source(did).await
    }

    async fn epoch(
        &self,
        did: &str,
        seq: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.inner.epoch(did, seq).await
    }

    async fn epoch_chain(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        self.inner.epoch_chain(did).await
    }

    async fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.inner.device_transport_keys(did).await
    }

    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> labyrinth::Result<Option<Vec<MemberDeviceKey>>> {
        let reported = self.inner.member_device_keys(thread_id, did).await?;
        let local = self
            .authority
            .leaf_keys(thread_id, did)
            .await
            .map_err(|error| labyrinth::Error::Backend(format!("local MLS group: {error}")))?;
        if let Some(local) = local {
            let active: std::collections::BTreeSet<[u8; 32]> = reported
                .iter()
                .flatten()
                .filter(|device| device.active_at(local.applied_chat_seq))
                .map(|device| device.key)
                .collect();
            if active != local.keys.into_iter().collect() {
                return Err(labyrinth::Error::Backend(
                    "mls-ds member devices disagree with the local MLS group".into(),
                ));
            }
        }
        Ok(reported)
    }

    async fn sequencer_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.inner.sequencer_receipt_key(thread_id).await
    }

    async fn sequencer_receipt_key_for_authority(
        &self,
        thread_id: &str,
        expected_authority: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.inner
            .sequencer_receipt_key_for_authority(thread_id, expected_authority)
            .await
    }

    async fn sequencer_receipt_key_by_id(
        &self,
        thread_id: &str,
        expected_authority: &str,
        key_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.inner
            .sequencer_receipt_key_by_id(thread_id, expected_authority, key_id)
            .await
    }
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
    /// Corrupt or unauthenticated records that could not be opened.
    pub undecryptable: usize,
    /// Authenticated records whose MEK was not addressed to this account,
    /// as expected for history outside its membership interval.
    pub not_recipient: usize,
    /// Witness copies Labyrinth rejected because they contradict an accepted copy (ruling 3).
    pub rejected: usize,
    /// False if the Space refused the conversation's sender records; only the owner archive is included.
    pub space_readable: bool,
    /// Messages their authors unsent (verified author redactions only).
    pub redacted: Vec<RedactedMessage>,
}

fn history_error_counts(items: &[labyrinth::client::Undecryptable]) -> (usize, usize) {
    let not_recipient = items
        .iter()
        .filter(|item| item.error == labyrinth::Error::NotRecipient)
        .count();
    (items.len() - not_recipient, not_recipient)
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

struct TransportClock(Arc<GatewayXrpcTransport>);

impl labyrinth::client::Clock for TransportClock {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}

impl SessionDeps {
    pub(crate) fn ds_directory(&self) -> DsDirectoryStore {
        DsDirectoryStore::new(self.transport.clone(), self.sequencer_receipt_key.clone())
            .with_placements(self.did.clone(), self.placements.clone())
    }

    fn space_store(&self) -> Option<SpaceMailboxStore> {
        let space = self.space.as_ref()?.clone();
        let publisher: Box<dyn KeyPublisher> = match &self.pds {
            Some(pds) => Box::new(PdsPublisher::new(pds.clone(), &self.did)),
            None => Box::new(self.ds_directory()),
        };
        let transport = self.transport.clone();
        Some(
            SpaceMailboxStore::for_owner(&self.did, space, publisher)
                .with_clock(Arc::new(move || transport.now_ms())),
        )
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
        let directory: Box<dyn MailboxDirectory> = match &self.local_authority {
            Some(authority) => Box::new(LocallyCheckedDirectory {
                inner: directory,
                authority: authority.clone(),
            }),
            None => directory,
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
            clock: Box::new(TransportClock(self.transport.clone())),
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
                OrchestratorError::Storage(
                    "labyrinth: unsupported non-Space mailbox placement".into(),
                )
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
        let pins: std::collections::BTreeMap<String, ThreadPlacement> =
            serde_json::from_slice(&raw)
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

    async fn reconcile_directory_publication(
        &self,
        session: &mut LabyrinthSession,
    ) -> labyrinth::Result<()> {
        if session.lab.pending_directory_epoch().is_some() {
            session.lab.retry_pending_directory_publication().await?;
        }
        let Some(pds) = &self.pds else {
            return Ok(());
        };
        let local = session.lab.latest_public()?;
        let pds_latest = PdsDirectory::new(pds.clone()).latest(&self.did).await?;
        let ds_latest = self.ds_directory().latest(&self.did).await?;
        let agrees = |head: &Option<labyrinth::mailbox::EpochPublic>| {
            head.as_ref()
                .is_some_and(|head| head.seq == local.seq && head.head == local.head)
        };
        if (!agrees(&pds_latest) || !agrees(&ds_latest))
            && local.attestation.transport_public_key == self.signer.public_key()
        {
            session.lab.publish_latest_keys().await?;
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
        mut lab: Labyrinth,
        fault: SignerFault,
        persisted: Option<Zeroizing<Vec<u8>>>,
    ) -> LabyrinthSession {
        let persisted = Arc::new(std::sync::Mutex::new(persisted));
        lab.set_state_sink(Box::new(VaultStateSink {
            did: self.did.clone(),
            vault: self.vault.clone(),
            persisted: persisted.clone(),
        }));
        LabyrinthSession {
            did: self.did.clone(),
            transport_key: self.signer.public_key(),
            lab,
            fault,
            vault: self.vault,
            placements: self.placements,
            persisted,
            recovery_method_stale: false,
            directory_publish_attempted: false,
            directory_publish_error: None,
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
        let publication = self.reconcile_directory_publication(&mut s).await;
        s.note_directory_publication(&publication);
        if publication.is_ok() {
            let sync_res = s.sync_epochs_healing_squats().await;
            s.finish(sync_res)?;
        } else {
            s.save()?;
        }
        Ok(Some(s))
    }

    /// Opens the saved session, or initializes the account's Space mailbox (`D4` auto-enrollment).
    pub async fn enable(self) -> Result<LabyrinthSession> {
        if let Some(s) = self.clone().open().await? {
            return Ok(s);
        }
        let placement = self.probe_placement().await?;
        let fault = SignerFault::default();
        let initialized = Labyrinth::initialize_with_report(
            &self.did,
            self.transport_signer(&fault),
            self.backends(placement)?,
        )
        .await;
        surface(&fault)?;
        let (lab, unfinished) = initialized.map_err(map_error)?;
        self.save_placement(placement)?;
        let mut s = self.session(lab, fault, None);
        if let Some(error) = unfinished {
            let failed: labyrinth::Result<()> = Err(error);
            s.note_directory_publication(&failed);
        }
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
        let (lab, enrollment) = restored.map_err(map_error)?;
        self.save_placement(placement)?;
        let existing = self
            .vault
            .load_zeroizing(&self.did)
            .map_err(OrchestratorError::Mls)?;
        let mut s = self.session(lab, fault, existing);
        s.recovery_method_stale = enrollment.stale_recovery_method;
        // The enrolled head may still be pending; saving the state keeps the
        // marker so `open` retries the publication (G15).
        if let Some(error) = enrollment.unfinished {
            s.note_directory_publication(&Err(error));
        }
        s.save()?;
        Ok(s)
    }
}

struct VaultStateSink {
    did: String,
    vault: Arc<dyn StateVault>,
    persisted: Arc<std::sync::Mutex<Option<Zeroizing<Vec<u8>>>>>,
}

impl labyrinth::client::StateSink for VaultStateSink {
    fn save_state(&self, state: &[u8]) -> labyrinth::Result<()> {
        let mut guard = self.persisted.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref().map(|p| p.as_slice()) == Some(state) {
            return Ok(());
        }
        let swapped = self
            .vault
            .compare_exchange(&self.did, guard.as_deref().map(|v| v.as_slice()), state)
            .map_err(|e| labyrinth::Error::Backend(format!("state vault: {e}")))?;
        if !swapped {
            return Err(labyrinth::Error::Backend(
                "labyrinth: client state changed concurrently; reopen the session".into(),
            ));
        }
        *guard = Some(Zeroizing::new(state.to_vec()));
        Ok(())
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
    persisted: Arc<std::sync::Mutex<Option<Zeroizing<Vec<u8>>>>>,
    recovery_method_stale: bool,
    directory_publish_attempted: bool,
    directory_publish_error: Option<String>,
}

impl LabyrinthSession {
    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn latest_epoch(&self) -> u64 {
        self.lab.latest_epoch()
    }

    pub fn recovery_method_stale(&self) -> bool {
        self.recovery_method_stale
    }

    pub fn pending_directory_epoch(&self) -> Option<u64> {
        self.lab.pending_directory_epoch()
    }

    pub fn directory_publish_attempted(&self) -> bool {
        self.directory_publish_attempted
    }

    pub fn directory_publish_error(&self) -> Option<&str> {
        self.directory_publish_error.as_deref()
    }

    fn note_directory_publication(&mut self, result: &labyrinth::Result<()>) {
        self.directory_publish_attempted = true;
        self.directory_publish_error = result.as_ref().err().map(ToString::to_string);
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
        *self.persisted.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }

    /// Safely clear an unanchored, unverified squatted epoch record (`[CB-40]`)
    /// from the personal mailbox Space if `seq` is strictly ahead of the
    /// verified local epoch and not anchored in `CompositeDirectory`.
    pub async fn clear_squatted_epoch(&mut self, seq: u64) -> Result<bool> {
        let out = self.lab.clear_squatted_epoch(seq).await;
        self.finish(out)
    }

    async fn try_heal_squat(&mut self, seq: u64) -> bool {
        if seq <= self.lab.latest_epoch() {
            return false;
        }
        matches!(self.lab.clear_squatted_epoch(seq).await, Ok(true))
    }

    async fn sync_epochs_healing_squats(&mut self) -> labyrinth::Result<()> {
        if self.lab.pending_directory_epoch().is_some() {
            let retry = self
                .lab
                .retry_pending_directory_publication()
                .await
                .map(|_| ());
            self.note_directory_publication(&retry);
            retry?;
        }
        for _ in 0..8 {
            match self.lab.sync_epochs().await {
                Ok(_) => return Ok(()),
                Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                    if !self.try_heal_squat(seq).await {
                        return Err(labyrinth::Error::EpochSquatted { seq, reason });
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.lab.sync_epochs().await.map(|_| ())
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
        let out = match self.lab.propose_repin(did).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.propose_repin(did).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        };
        self.finish(out)
    }

    pub async fn repin_peer(&mut self, did: &str, confirmed_head: [u8; 32]) -> Result<()> {
        let out = match self.lab.repin_peer(did, &confirmed_head).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.repin_peer(did, &confirmed_head).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        }
        .map(|_| ());
        self.finish(out)
    }

    pub async fn list_threads(&mut self) -> Result<ThreadList> {
        let out = self.lab.list_threads_report().await;
        self.finish(out)
    }

    pub async fn revoke_chat_device(
        &mut self,
        chat_key: [u8; 32],
    ) -> Result<Vec<SessionRotationReport>> {
        let recovery_methods = self.lab.list_recovery_methods().await.unwrap_or_default();
        let out = match self.lab.revoke_chat_device(&chat_key).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.revoke_chat_device(&chat_key).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        }
        .map(|reports| {
            reports
                .into_iter()
                .map(|report| rotation_report(report, &recovery_methods))
                .collect()
        });
        self.finish(out)
    }

    pub fn device_key_hex(&self) -> String {
        hex::encode(self.lab.device_public().device_key_pub.0)
    }

    pub fn device_key_pub(&self) -> [u8; 32] {
        self.lab.device_public().device_key_pub.0
    }

    fn capture_directory_failure<R>(&mut self, out: &labyrinth::Result<R>) {
        if self.lab.pending_directory_epoch().is_some() {
            if let Err(error) = out {
                self.directory_publish_attempted = true;
                self.directory_publish_error = Some(error.to_string());
            }
        } else if out.is_ok() {
            self.directory_publish_error = None;
        }
    }

    fn try_finish<R>(&mut self, out: labyrinth::Result<R>) -> Result<labyrinth::Result<R>> {
        self.capture_directory_failure(&out);
        let save_res = self.save();
        surface(&self.fault)?;
        save_res?;
        Ok(out)
    }

    fn finish<R>(&mut self, out: labyrinth::Result<R>) -> Result<R> {
        self.capture_directory_failure(&out);
        let save_res = self.save();
        surface(&self.fault)?;
        match out {
            Ok(val) => {
                save_res?;
                Ok(val)
            }
            Err(err) => {
                save_res?;
                Err(map_error(err))
            }
        }
    }

    fn save(&mut self) -> Result<()> {
        let next = self.lab.export_state().map_err(map_error)?;
        let mut guard = self.persisted.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref().map(|p| p.as_slice()) == Some(next.as_slice()) {
            return Ok(());
        }
        let swapped = self
            .vault
            .compare_exchange(&self.did, guard.as_deref().map(|v| v.as_slice()), &next)
            .map_err(OrchestratorError::Mls)?;
        if !swapped {
            return Err(OrchestratorError::Storage(
                "labyrinth: client state changed concurrently; reopen the session".into(),
            ));
        }
        *guard = Some(next);
        Ok(())
    }

    pub async fn create_recovery_code(&mut self) -> Result<String> {
        let out = match self.lab.create_recovery_code(Mechanism::Code).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.create_recovery_code(Mechanism::Code).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        }
        .map(|setup| setup.code.to_string());
        self.finish(out)
    }

    pub async fn create_passkey_recovery(
        &mut self,
        prf_output: &[u8],
        credential_id: &[u8],
    ) -> Result<()> {
        let out = match self
            .lab
            .create_passkey_recovery(prf_output, credential_id)
            .await
        {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab
                        .create_passkey_recovery(prf_output, credential_id)
                        .await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        }
        .map(|_| ());
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
            self.sync_epochs_healing_squats().await?;
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
        if out.is_err() {
            for (conversation_id, _, _) in batches {
                self.lab.discard_pending(conversation_id);
            }
        }
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
        // Another member's witness copy of my message is not my own archive write.
        Ok(h.map(|h| {
            h.messages.iter().any(|m| {
                m.message_id == message_id
                    && m.source != labyrinth::client::MessageSource::Witness
                    && m.sender.as_deref() == Some(did.as_str())
            }) || h
                .redacted
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
            self.sync_epochs_healing_squats().await?;
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

    /// `[CB-22]` / `[CB-37]` owner-mode (`v5`, `KIND_ATTRIBUTED_FRAME = 0x03`)
    /// fallback used when this account has been involuntarily removed (kicked)
    /// from `conversation_id` and can no longer write to or read from the
    /// conversation Space. Seals `(message_id, timestamp_ms, sender_did, frame)`
    /// items into the personal mailbox Space while preserving `sender_did`.
    pub async fn archive_owner_fallback(
        &mut self,
        conversation_id: &str,
        items: &[(String, u64, String, Vec<u8>)],
    ) -> Result<labyrinth::Result<usize>> {
        if items.is_empty() {
            return Ok(Ok(0));
        }
        self.lab.discard_pending(conversation_id);
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            let mut count = 0usize;
            for (message_id, ts, sender_did, frame) in items {
                self.lab
                    .archive_owner_attributed(conversation_id, message_id, *ts, sender_did, frame)
                    .await?;
                count += 1;
            }
            self.lab.flush_owner(conversation_id).await?;
            Ok(count)
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

    /// Publish the author's immutable message-scoped redaction through the
    /// same Conversation Space used by native send/archive.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn unsend_native_message(
        &mut self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<labyrinth::Result<usize>> {
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            self.lab.unsend(conversation_id, message_id).await
        }
        .await;
        self.try_finish(raw)
    }

    /// Native queue entries keep the verified receipt and blinded frame nonce;
    /// delegate MEK verification/distribution and sender sealing to Labyrinth.
    ///
    /// `Ok(true)` is narrowly an established Conversation Space write denial:
    /// roster/directory and mailbox preparation have already succeeded. A
    /// `Forbidden` from those prerequisite stages remains an error so callers
    /// retain their durable queue rather than misclassifying it as a kick.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn archive_native_sender(
        &mut self,
        conversation_id: &str,
        members: &[String],
        items: &[crate::client::QueuedLabyrinthArchivePayload],
    ) -> Result<labyrinth::Result<bool>> {
        use base64::Engine as _;
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            let members: Vec<&str> = members.iter().map(String::as_str).collect();
            let resolved = self.lab.resolve_roster_report(&members).await?;
            for excluded in &resolved.excluded {
                tracing::warn!(conversation_id, did = %excluded.did, error = %excluded.error,
                    "labyrinth: member excluded from the native archive roster");
            }
            let roster = resolved.roster;
            for item in items {
                let write = match (&item.frame_nonce_b64, &item.sequencer_receipt_json) {
                    (Some(nonce), Some(receipt)) => {
                        let nonce: [u8; 32] = base64::engine::general_purpose::STANDARD
                            .decode(nonce)
                            .map_err(|_| labyrinth::Error::Malformed("archive nonce"))?
                            .try_into()
                            .map_err(|_| labyrinth::Error::Malformed("archive nonce length"))?;
                        let receipt: crate::client::chat_wire::StoredArchivedReceipt =
                            serde_json::from_str(receipt)
                                .map_err(|_| labyrinth::Error::Malformed("archive receipt"))?;
                        let attestation: crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope =
                            serde_json::from_str(
                                item.original_sender_attestation_json
                                    .as_ref()
                                    .ok_or(labyrinth::Error::ReceiptCommitmentMismatch)?,
                            )
                            .map_err(|_| {
                                labyrinth::Error::Malformed(
                                    "archive original sender attestation",
                                )
                            })?;
                        if receipt.original_sender_attestation.as_ref() != Some(&attestation) {
                            return Err(labyrinth::Error::ReceiptCommitmentMismatch);
                        }
                        let archived = receipt
                            .to_labyrinth_archived()
                            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
                        self.lab
                            .archive_outgoing_committed(
                                conversation_id,
                                &roster,
                                &item.message_id,
                                item.created_at_ms.max(0) as u64,
                                &nonce,
                                item.labyrinth_frame_json.as_bytes(),
                                &archived,
                            )
                            .await
                    }
                    _ => return Err(labyrinth::Error::ReceiptCommitmentMismatch),
                };
                match write {
                    Ok(_) => {}
                    Err(labyrinth::Error::Forbidden) => return Ok(true),
                    Err(error) => return Err(error),
                }
            }
            match self.lab.flush_thread(conversation_id).await {
                Ok(_) => Ok(false),
                Err(labyrinth::Error::Forbidden) => Ok(true),
                Err(error) => Err(error),
            }
        }
        .await;
        let out = self.try_finish(raw);
        if !matches!(out, Ok(Ok(false))) {
            self.lab.discard_pending(conversation_id);
        }
        out
    }

    /// Kick/leave fallback preserves the same canonical frame and I13 evidence as sender batches.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn archive_native_owner(
        &mut self,
        conversation_id: &str,
        items: &[&crate::client::native_client::NativeArchiveEvidence],
    ) -> Result<labyrinth::Result<()>> {
        use base64::Engine as _;
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            for item in items {
                let nonce: [u8; 32] = base64::engine::general_purpose::STANDARD
                    .decode(
                        item.frame_nonce_b64
                            .as_ref()
                            .ok_or(labyrinth::Error::ReceiptCommitmentMismatch)?,
                    )
                    .map_err(|_| labyrinth::Error::Malformed("archive nonce"))?
                    .try_into()
                    .map_err(|_| labyrinth::Error::Malformed("archive nonce length"))?;
                let receipt: crate::client::chat_wire::StoredArchivedReceipt =
                    serde_json::from_str(
                        item.sequencer_receipt_json
                            .as_ref()
                            .ok_or(labyrinth::Error::ReceiptCommitmentMismatch)?,
                    )
                    .map_err(|_| labyrinth::Error::Malformed("archive receipt"))?;
                let attestation: crate::messaging::receive::OriginalSenderArchiveAttestationEnvelope =
                    serde_json::from_str(
                        item.original_sender_attestation_json
                            .as_ref()
                            .ok_or(labyrinth::Error::ReceiptCommitmentMismatch)?,
                    )
                    .map_err(|_| {
                        labyrinth::Error::Malformed("archive original sender attestation")
                    })?;
                if receipt.original_sender_attestation.as_ref() != Some(&attestation) {
                    return Err(labyrinth::Error::ReceiptCommitmentMismatch);
                }
                let archived = receipt
                    .to_labyrinth_archived()
                    .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
                self.lab
                    .archive_owner_committed(
                        conversation_id,
                        &item.message_id,
                        item.created_at_ms.max(0) as u64,
                        &nonce,
                        item.labyrinth_frame_json.as_bytes(),
                        &archived,
                    )
                    .await?;
            }
            self.lab.flush_owner(conversation_id).await?;
            Ok(())
        }
        .await;
        let out = self.try_finish(raw);
        if !matches!(out, Ok(Ok(()))) {
            self.lab.discard_pending(conversation_id);
        }
        out
    }

    pub async fn load_owner_history(
        &mut self,
        conversation_id: &str,
    ) -> Result<Vec<LoadedMessage>> {
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            self.lab.load_owner_thread(conversation_id).await
        }
        .await;
        let history = self.finish(raw)?;
        if !history.undecryptable.is_empty() {
            return Err(OrchestratorError::Api(
                "labyrinth: owner archive contains undecryptable messages".into(),
            ));
        }
        Ok(history.messages)
    }

    pub async fn open_owner_record(
        &mut self,
        batch: labyrinth::records::OwnerBatch,
    ) -> Result<Vec<LoadedMessage>> {
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            self.lab.open_owner_record(batch).await
        }
        .await;
        let history = self.finish(raw)?;
        if !history.undecryptable.is_empty() {
            return Err(OrchestratorError::Api(
                "labyrinth: owner record is undecryptable".into(),
            ));
        }
        Ok(history.messages)
    }

    pub async fn load_history(
        &mut self,
        conversation_id: &str,
        range: TimeRange,
    ) -> Result<HistoryPage> {
        let raw = async {
            self.sync_epochs_healing_squats().await?;
            self.lab.load_thread(conversation_id, range).await
        }
        .await;
        let h = self.finish(raw)?;
        let (undecryptable, not_recipient) = history_error_counts(&h.undecryptable);
        Ok(HistoryPage {
            undecryptable,
            not_recipient,
            rejected: h.rejected.len(),
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
                self.sync_epochs_healing_squats().await?;
            }
            self.lab
                .load_thread_page(conversation_id, before, limit)
                .await
        }
        .await;
        let p = self.finish(raw)?;
        let (undecryptable, not_recipient) = history_error_counts(&p.history.undecryptable);
        Ok((
            HistoryPage {
                undecryptable,
                not_recipient,
                rejected: p.history.rejected.len(),
                space_readable: p.history.space_readable,
                messages: p.history.messages,
                redacted: p.history.redacted,
            },
            p.next,
        ))
    }

    pub async fn rotate_epoch(&mut self) -> Result<SessionRotationReport> {
        let recovery_methods = self.lab.list_recovery_methods().await.unwrap_or_default();
        let out = match self.lab.rotate_epoch().await {
            Err(labyrinth::Error::EpochSquatted { seq, reason: _ })
                if self.try_heal_squat(seq).await =>
            {
                self.lab.rotate_epoch().await
            }
            other => other,
        }
        .map(|report| rotation_report(report, &recovery_methods));
        self.finish(out)
    }

    pub async fn revoke_device(&mut self, device_key: [u8; 32]) -> Result<SessionRotationReport> {
        let recovery_methods = self.lab.list_recovery_methods().await.unwrap_or_default();
        let out = match self.lab.revoke_device(&XVerifyingKey(device_key)).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.revoke_device(&XVerifyingKey(device_key)).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        }
        .map(|report| rotation_report(report, &recovery_methods));
        self.finish(out)
    }

    /// `[CB-22]` / `Gate 5`: copies every readable message and own encrypted
    /// attachment of `conversation_id` into the personal mailbox Space before
    /// leaving. The conversation Space keeps this account's records.
    pub async fn rearchive_before_leave(&mut self, conversation_id: &str) -> Result<usize> {
        let out = self
            .lab
            .rearchive_before_leave(conversation_id)
            .await
            .map(|r| r.messages_archived);
        self.finish(out)
    }
}

#[cfg(test)]
mod history_error_tests {
    use super::history_error_counts;

    #[test]
    fn expected_not_recipient_is_separate_from_corruption() {
        let items = [
            labyrinth::client::Undecryptable {
                message_id: "before-join".into(),
                timestamp: 1,
                sender: Some("did:plc:alice".into()),
                error: labyrinth::Error::NotRecipient,
            },
            labyrinth::client::Undecryptable {
                message_id: "tampered".into(),
                timestamp: 2,
                sender: Some("did:plc:alice".into()),
                error: labyrinth::Error::BadSignature,
            },
        ];
        assert_eq!(history_error_counts(&items), (1, 1));
    }

    #[test]
    fn rotation_exclusions_keep_recovery_method_identity() {
        let key = labyrinth::sign::XVerifyingKey([7; 32]);
        let report = labyrinth::client::RotationReport {
            new_epoch: 9,
            revoked: Some(labyrinth::sign::XVerifyingKey([8; 32])),
            excluded: vec![
                labyrinth::client::ExcludedMember {
                    device_key: Some(key),
                    reason: labyrinth::client::ExclusionReason::InvalidMac,
                },
                labyrinth::client::ExcludedMember {
                    device_key: None,
                    reason: labyrinth::client::ExclusionReason::MalformedMember,
                },
            ],
        };
        let methods = [labyrinth::client::RecoveryMethod {
            vdevice_id: [4; 16],
            mechanism: labyrinth::virtual_device::Mechanism::Passkey,
            device_key: key,
            created_at_ms: 1,
            last_used_at_ms: None,
            stale_at_ms: Some(2),
            revoked: false,
        }];

        let mapped = super::rotation_report(report, &methods);
        assert_eq!(mapped.new_epoch, 9);
        assert_eq!(
            mapped.exclusions[0].recovery_method,
            Some(labyrinth::virtual_device::Mechanism::Passkey)
        );
        assert_eq!(mapped.exclusions[0].reason, "invalid-membership");
        assert_eq!(mapped.exclusions[1].device_key, None);
    }
}
