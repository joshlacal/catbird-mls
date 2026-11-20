//! One account's async Spaces-only Labyrinth session plus persisted state.

use std::sync::Arc;

use labyrinth::client::{
    delete_account_remote, Backends, CompositeDirectory, Labyrinth, LoadedMessage, PurgeReport,
    RecoveryMethod, RedactedMessage, RepinProposal, ResolvedRoster, RosterExclusion,
    RotationReport, ThreadCursor, ThreadList,
};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::recovery_share::RecoveryShares;
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PublicRepoBackend};
use labyrinth::store::space::{
    SpaceMailboxStore, SpaceRef, SpaceRpc, MAILBOX_SKEY, MAILBOX_SPACE_TYPE,
};
use labyrinth::store::{
    keys_valid_for, ChatDeviceKey, KeyPublisher, MailboxDirectory, MailboxStore, MaybeSend,
    MaybeSync, MemberDeviceKey, SequencerReceiptKey, ThreadStore, TimeRange, VouchAt,
};
use labyrinth::virtual_device::Mechanism;
use zeroize::Zeroizing;

use super::map_error;
use super::recovery_shares::GatewayRecoveryShareStore;
use super::signer::{ChatKeySigner, LatchedTransportSigner, SignerFault};
use super::space::{
    thread_placement_key, Placement, ResolvingSpaceThreadStore, SpaceMailbox, ThreadPlacement,
};
use super::state::StateVault;
use super::transport::{DsDirectoryStore, GatewayXrpcTransport, PreparedAccountDeletion};
pub use crate::orchestrator::error::{OrchestratorError, Result as AuthorityResult};
use AuthorityResult as Result;
/// One member dropped during a mailbox epoch rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationExclusion {
    pub device_key: Option<[u8; 32]>,
    pub reason: String,
    pub recovery_method: Option<Mechanism>,
}

/// A rotation result whose exclusions and re-keyed recovery methods remain visible to native clients.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRotationReport {
    pub new_epoch: u64,
    pub exclusions: Vec<RotationExclusion>,
    pub rekeyed_recovery_code: Option<String>,
    pub rekeyed_passkeys: Vec<[u8; 16]>,
}

impl core::fmt::Debug for SessionRotationReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionRotationReport")
            .field("new_epoch", &self.new_epoch)
            .field("exclusions", &self.exclusions)
            .field(
                "rekeyed_recovery_code",
                &self.rekeyed_recovery_code.as_ref().map(|_| "<redacted>"),
            )
            .field("rekeyed_passkeys", &self.rekeyed_passkeys)
            .finish()
    }
}

/// Independent evidence that an account already has an archive. A fresh
/// device must restore from an existing method instead of creating epoch 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPresence {
    pub local_state: bool,
    pub mailbox_epoch: bool,
    pub pds_head: bool,
    pub ds_head: bool,
}

impl RecoveryPresence {
    pub fn requires_recovery(&self) -> bool {
        !self.local_state && (self.mailbox_epoch || self.pds_head || self.ds_head)
    }
}

fn rotation_report(
    report: RotationReport,
    recovery_methods: &[RecoveryMethod],
) -> SessionRotationReport {
    let rekeyed_recovery_code = report.rekeyed_recovery.map(|setup| setup.code.to_string());
    let rekeyed_passkeys = report
        .invalidated_recovery_methods
        .iter()
        .filter(|m| m.mechanism == Mechanism::Passkey)
        .map(|m| m.vdevice_id)
        .collect();
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
                    labyrinth::client::ExclusionReason::MissingRecoveryBundle => {
                        "missing-recovery-bundle"
                    }
                    labyrinth::client::ExclusionReason::InvalidRecoveryBundle => {
                        "invalid-recovery-bundle"
                    }
                    labyrinth::client::ExclusionReason::UnsignedRevocation => "unsigned-revocation",
                }
                .into(),
                recovery_method,
            }
        })
        .collect();
    SessionRotationReport {
        new_epoch: report.new_epoch,
        exclusions,
        rekeyed_recovery_code,
        rekeyed_passkeys,
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

    /// `did`'s Ed25519 chat device signing keys verified against `did`'s PDS
    /// `blue.catbird.chat.device` repository records (`#atproto` commit proof),
    /// excluding any device retired by `blue.catbird.chat.deviceRevocation`.
    /// `None` when PDS device verification is not configured on this authority.
    async fn authorized_chat_device_keys(&self, did: &str) -> Result<Option<Vec<[u8; 32]>>> {
        let _ = did;
        Ok(None)
    }

    /// `did`'s Ed25519 chat device signing keys retired via verified append-only
    /// `blue.catbird.chat.deviceRevocation` records on `did`'s PDS.
    async fn revoked_chat_device_keys(&self, did: &str) -> Result<Vec<[u8; 32]>> {
        let _ = did;
        Ok(Vec::new())
    }

    /// `did`'s Ed25519 chat device signing keys paired with each key's earliest
    /// verified revocation instant (`createdAt` ms) from PDS `deviceRevocation`.
    /// Preserving the real revocation timestamp lets restored clients verify
    /// pre-deletion witness copies while rejecting any post-revocation use.
    async fn revoked_chat_device_keys_with_times(&self, did: &str) -> Result<Vec<([u8; 32], u64)>> {
        Ok(self
            .revoked_chat_device_keys(did)
            .await?
            .into_iter()
            .map(|k| (k, 1))
            .collect())
    }

    /// `did`'s live leaf signing keys across active local MLS groups shared with
    /// this device. Every such leaf must be present and non-revoked in any
    /// device-key directory response for `did`.
    async fn shared_group_leaf_keys(&self, did: &str) -> Result<Option<Vec<[u8; 32]>>> {
        let _ = did;
        Ok(None)
    }

    /// Earliest verified account deletion instant (`signed_at_ms`) recorded for `did`
    /// from an authenticated `accountDeletedEntry`, when known locally.
    async fn verified_deleted_account_ms(&self, did: &str) -> Result<Option<u64>> {
        let _ = did;
        Ok(None)
    }

    /// Whether `did`'s PDS repository returned a terminal tombstone (`RepoNotFound` / `RepoTakendown`).
    async fn is_pds_repo_tombstoned(&self, did: &str) -> Result<bool> {
        let _ = did;
        Ok(false)
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
        let mut reported = self.inner.device_transport_keys(did).await?;
        let verified_deleted_ms = self
            .authority
            .verified_deleted_account_ms(did)
            .await
            .map_err(|error| {
                labyrinth::Error::Backend(format!("verified deleted account: {error}"))
            })?;
        let mut revoked_times = std::collections::BTreeMap::<[u8; 32], u64>::new();
        for (key, at_ms) in self
            .authority
            .revoked_chat_device_keys_with_times(did)
            .await
            .map_err(|error| labyrinth::Error::Backend(format!("revoked PDS devices: {error}")))?
        {
            revoked_times
                .entry(key)
                .and_modify(|prev| *prev = (*prev).min(at_ms))
                .or_insert(at_ms);
        }
        for entry in &mut reported {
            if let Some(&rev_ms) = revoked_times.get(&entry.key) {
                entry.removed_at = Some(entry.removed_at.map_or(rev_ms, |ds| ds.min(rev_ms)));
            }
        }
        let mut had_pds_device_list = false;
        if let Some(allowed) = self
            .authority
            .authorized_chat_device_keys(did)
            .await
            .map_err(|error| {
                labyrinth::Error::Backend(format!("authorized PDS devices: {error}"))
            })?
        {
            had_pds_device_list = true;
            let allowed_set: std::collections::BTreeSet<[u8; 32]> = allowed.into_iter().collect();
            reported.retain(|entry| {
                allowed_set.contains(&entry.key) || revoked_times.contains_key(&entry.key)
            });
            for entry in &mut reported {
                if !allowed_set.contains(&entry.key) {
                    let rev_ms = revoked_times.get(&entry.key).copied().unwrap_or(1);
                    entry.removed_at.get_or_insert(rev_ms);
                }
            }
        }
        let is_tombstoned = self
            .authority
            .is_pds_repo_tombstoned(did)
            .await
            .map_err(|error| {
                labyrinth::Error::Backend(format!("PDS repo tombstone check: {error}"))
            })?;
        if let Some(del_ms) = verified_deleted_ms {
            if !had_pds_device_list {
                let bound =
                    crate::client::deletion_authority::self_deletion_archive_revocation_bound_ms(
                        del_ms,
                    );
                for entry in &mut reported {
                    entry.removed_at = Some(entry.removed_at.map_or(bound, |ds| ds.min(bound)));
                }
            }
        } else if is_tombstoned {
            for entry in &mut reported {
                entry.removed_at.get_or_insert(u64::MAX);
            }
        }
        // An old deletion cannot excuse a missing device after this account returns.
        // A terminal repository plus verified erasure is the only offline-history exception.
        if verified_deleted_ms.is_none() || !is_tombstoned || had_pds_device_list {
            if let Some(shared_leaves) = self
                .authority
                .shared_group_leaf_keys(did)
                .await
                .map_err(|error| labyrinth::Error::Backend(format!("shared MLS leaves: {error}")))?
            {
                if is_tombstoned {
                    for leaf_key in shared_leaves {
                        if !reported.iter().any(|entry| entry.key == leaf_key) {
                            return Err(labyrinth::Error::DirectoryIncomplete {
                                pds_present: false,
                                ds_present: true,
                            });
                        }
                    }
                } else {
                    let active_reported: std::collections::BTreeSet<[u8; 32]> = reported
                        .iter()
                        .filter(|entry| entry.removed_at.is_none())
                        .map(|entry| entry.key)
                        .collect();
                    for leaf_key in shared_leaves {
                        let accounted_as_revoked =
                            reported.iter().any(|entry| entry.key == leaf_key)
                                && revoked_times.contains_key(&leaf_key);
                        if !active_reported.contains(&leaf_key) && !accounted_as_revoked {
                            return Err(labyrinth::Error::Backend(
                                "chat device directory omits or revokes a live shared MLS group leaf"
                                    .into(),
                            ));
                        }
                    }
                }
            }
        }
        Ok(reported)
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

/// The account's public key publisher as the mailbox Space store holds it. The store ends
/// its purge by retracting the published keys and has no way to say "these cannot be
/// retracted". A publisher that answers so (the gateway keeps the public key records
/// create-only) leaves nothing more to remove, so the purge of everything else stands.
struct MailboxSpaceKeyPublisher(PdsPublisher);

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for MailboxSpaceKeyPublisher {
    async fn publish(
        &self,
        record: &labyrinth::records::MailboxKeysRecord,
    ) -> labyrinth::Result<()> {
        self.0.publish(record).await
    }

    async fn retract(&self) -> labyrinth::Result<()> {
        match self.0.retract().await {
            Err(labyrinth::Error::NotSupported(_)) => Ok(()),
            other => other,
        }
    }
}

struct TransportClock(Arc<GatewayXrpcTransport>);

impl labyrinth::client::Clock for TransportClock {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}

impl SessionDeps {
    fn recovery_shares(&self) -> RecoveryShares {
        RecoveryShares::reader(Box::new(GatewayRecoveryShareStore::new(
            self.did.clone(),
            self.transport.clone(),
            self.placements.clone(),
        )))
    }

    /// Check the mailbox and both public head sources independently. A
    /// partial publication still blocks a new genesis, and an unavailable
    /// source propagates an error instead of being treated as absent.
    pub async fn recovery_presence(&self) -> Result<RecoveryPresence> {
        let local_state = self
            .vault
            .has_state(&self.did)
            .map_err(OrchestratorError::Mls)?;
        let mailbox_epoch = self
            .space_store()
            .ok_or_else(space_unreachable)?
            .get_epoch(0)
            .await
            .map_err(map_error)?
            .is_some();
        let pds_head = match &self.pds {
            Some(pds) => PdsDirectory::new(pds.clone())
                .latest(&self.did)
                .await
                .map_err(map_error)?
                .is_some(),
            None => false,
        };
        let ds_head = self
            .ds_directory()
            .latest(&self.did)
            .await
            .map_err(map_error)?
            .is_some();
        Ok(RecoveryPresence {
            local_state,
            mailbox_epoch,
            pds_head,
            ds_head,
        })
    }

    /// Resolve the typo-corrected code against the live bundle inventory
    /// before deciding whether a recovery-share service proof is needed.
    pub async fn recovery_code_requires_share(&self, code: &str) -> Result<bool> {
        let bundles = self
            .space_store()
            .ok_or_else(space_unreachable)?
            .list_virtual_devices()
            .await
            .map_err(map_error)?;
        labyrinth::client::enroll::recovery_code_requires_share(&self.did, code, &bundles)
            .map_err(map_error)
    }

    /// Unwrap and match the passkey's live bundles without exposing the
    /// recovery code, returning only whether version-3 share access is possible.
    pub async fn passkey_recovery_requires_share(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<bool> {
        let bundles = self
            .space_store()
            .ok_or_else(space_unreachable)?
            .list_virtual_devices()
            .await
            .map_err(map_error)?;
        labyrinth::client::enroll::passkey_recovery_requires_share(
            &self.did,
            prf_output_32,
            credential_id,
            &bundles,
        )
        .map_err(map_error)
    }

    pub(crate) fn ds_directory(&self) -> DsDirectoryStore {
        DsDirectoryStore::new(self.transport.clone(), self.sequencer_receipt_key.clone())
            .with_placements(self.did.clone(), self.placements.clone())
    }

    fn space_store(&self) -> Option<SpaceMailboxStore> {
        let space = self.space.as_ref()?.clone();
        let publisher: Box<dyn KeyPublisher> = match &self.pds {
            Some(pds) => Box::new(MailboxSpaceKeyPublisher(PdsPublisher::new(
                pds.clone(),
                &self.did,
            ))),
            None => Box::new(self.ds_directory()),
        };
        let transport = self.transport.clone();
        Some(
            SpaceMailboxStore::for_owner(&self.did, space, publisher)
                .with_clock(Arc::new(move || transport.now_ms())),
        )
    }

    /// The epoch directory: `CompositeDirectory` (PDS `mailboxKeys` cross-checked
    /// against the DS head chain) when a PDS backend is configured, else the DS.
    fn directory(&self) -> Box<dyn MailboxDirectory> {
        let directory: Box<dyn MailboxDirectory> = match &self.pds {
            Some(pds) => Box::new(CompositeDirectory::new(
                Box::new(PdsDirectory::new(pds.clone())),
                Box::new(self.ds_directory()),
            )),
            None => Box::new(self.ds_directory()),
        };
        match &self.local_authority {
            Some(authority) => Box::new(LocallyCheckedDirectory {
                inner: directory,
                authority: authority.clone(),
            }),
            None => directory,
        }
    }

    fn backends(&self, _placement: Placement) -> Result<Backends> {
        let space_rpc = self.space.clone().ok_or_else(space_unreachable)?;
        let space_mb = self.space_store().ok_or_else(space_unreachable)?;
        let ds_arc = Arc::new(self.ds_directory());

        let directory = self.directory();
        let publishers: Vec<Box<dyn KeyPublisher>> = match &self.pds {
            Some(_) => vec![Box::new(self.ds_directory())],
            None => Vec::new(),
        };

        let persisted_floors = Self::load_writer_rev_floors(&*self.placements, &self.did);
        let mailbox: Box<dyn MailboxStore> = Box::new(SpaceMailbox::new(space_mb, Some(ds_arc)));
        mailbox.seed_writer_rev_floors(&persisted_floors);
        let threads = Box::new(ResolvingSpaceThreadStore::new(
            &self.did,
            space_rpc,
            Some(self.transport.clone()),
            self.placements.clone(),
            self.default_conversation_authority_did.clone(),
        ));
        threads.seed_writer_rev_floors(&persisted_floors);

        Ok(Backends {
            mailbox,
            threads,
            directory,
            publishers,
            clock: Box::new(TransportClock(self.transport.clone())),
        })
    }

    pub(crate) fn writer_rev_floors_key(did: &str) -> String {
        format!("writer_rev_floors:{did}")
    }

    pub(crate) fn load_writer_rev_floors(
        placements: &dyn StateVault,
        did: &str,
    ) -> std::collections::BTreeMap<(String, String), String> {
        let key = Self::writer_rev_floors_key(did);
        let Ok(Some(raw)) = placements.load(&key) else {
            return std::collections::BTreeMap::new();
        };
        let Ok(entries) = serde_json::from_slice::<Vec<(String, String, String)>>(&raw) else {
            return std::collections::BTreeMap::new();
        };
        entries
            .into_iter()
            .map(|(space, writer, rev)| ((space, writer), rev))
            .collect()
    }

    pub(crate) fn persist_writer_rev_floors(
        placements: &dyn StateVault,
        did: &str,
        floors: &std::collections::BTreeMap<(String, String), String>,
    ) {
        let key = Self::writer_rev_floors_key(did);
        let mut merged = Self::load_writer_rev_floors(placements, did);
        let mut changed = false;
        for ((space, writer), rev) in floors {
            let entry = merged.entry((space.clone(), writer.clone()));
            match entry {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(rev.clone());
                    changed = true;
                }
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    if rev.as_str() > o.get().as_str() {
                        o.insert(rev.clone());
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return;
        }
        let encoded: Vec<(String, String, String)> =
            merged.into_iter().map(|((s, w), r)| (s, w, r)).collect();
        if let Ok(bytes) = serde_json::to_vec(&encoded) {
            let current = placements.load(&key).ok().flatten();
            let _ = placements.compare_exchange(&key, current.as_deref(), &bytes);
        }
    }

    /// Creates a standalone `ResolvingSpaceThreadStore` seeded with persisted `writer_rev_floors`.
    pub fn resolving_thread_store(&self) -> Result<ResolvingSpaceThreadStore> {
        let space_rpc = self.space.clone().ok_or_else(space_unreachable)?;
        let floors = Self::load_writer_rev_floors(&*self.placements, &self.did);
        let store = ResolvingSpaceThreadStore::new(
            &self.did,
            space_rpc,
            Some(self.transport.clone()),
            self.placements.clone(),
            self.default_conversation_authority_did.clone(),
        );
        store.seed_writer_rev_floors(&floors);
        Ok(store)
    }

    /// Opens a standalone `SpaceMailbox` seeded with persisted `writer_rev_floors`.
    pub fn open_mailbox_store(&self) -> Result<SpaceMailbox> {
        let space_mb = self.space_store().ok_or_else(space_unreachable)?;
        let ds_arc = Arc::new(self.ds_directory());
        let floors = Self::load_writer_rev_floors(&*self.placements, &self.did);
        let mailbox = SpaceMailbox::new(space_mb, Some(ds_arc));
        mailbox.seed_writer_rev_floors(&floors);
        Ok(mailbox)
    }

    /// Lists non-virtual device records currently stored in the account's `OwnerMailbox` Space.
    pub async fn list_mailbox_devices(&self) -> Result<Vec<labyrinth::records::Device>> {
        let space_mb = self.space_store().ok_or_else(space_unreachable)?;
        let ds_arc = Arc::new(self.ds_directory());
        let floors = Self::load_writer_rev_floors(&*self.placements, &self.did);
        let mailbox = SpaceMailbox::new(space_mb, Some(ds_arc));
        mailbox.seed_writer_rev_floors(&floors);
        let devices = mailbox.list_devices().await.map_err(map_error)?;
        Self::persist_writer_rev_floors(
            &*self.placements,
            &self.did,
            &mailbox.export_writer_rev_floors(),
        );
        Ok(devices)
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

    /// Remote half of account deletion carrying pre-published PDS device &
    /// self-revocation CARv1 proofs so peers can verify deletion post-takedown.
    pub async fn delete_account_remote_prepared(
        &self,
        prepared: &PreparedAccountDeletion,
    ) -> labyrinth::Result<()> {
        let spaces = self.conversation_spaces()?;
        self.delete_account_remote_at_with_prepared(Some(Placement::Space), Some(prepared.clone()))
            .await?;
        self.delete_conversation_records(&spaces, self.space.is_some())
            .await
    }

    /// Confirm durable peer erasure before retracting account keys or changing any Space.
    pub async fn confirm_hosted_account_erasure(
        &self,
        prepared: &PreparedAccountDeletion,
    ) -> std::result::Result<(), super::transport::XrpcTransportError> {
        self.ds_directory()
            .submit_account_erasure(prepared, true)
            .await
    }

    pub async fn finish_confirmed_account_erasure(&self) -> labyrinth::Result<()> {
        let spaces = self.conversation_spaces()?;
        self.purge_account_mailbox(None).await?;
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
        self.delete_account_remote_at_with_prepared(placement, None)
            .await
    }

    async fn delete_account_remote_at_with_prepared(
        &self,
        placement: Option<Placement>,
        prepared: Option<PreparedAccountDeletion>,
    ) -> labyrinth::Result<()> {
        let _ = placement;
        let ds = match prepared {
            Some(prepared) => self.ds_directory().with_prepared_deletion(prepared),
            None => self.ds_directory(),
        };
        self.purge_account_mailbox(Some(Arc::new(ds))).await
    }

    async fn purge_account_mailbox(
        &self,
        directory: Option<Arc<DsDirectoryStore>>,
    ) -> labyrinth::Result<()> {
        let space_mb = self.space_store().ok_or_else(|| {
            labyrinth::Error::Backend(
                "personal Space deletion requires the account's Space connection".into(),
            )
        })?;
        let mailbox = SpaceMailbox::new(space_mb, directory);
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
        // Name the authority and the type: the session's grant covers this account's
        // mailbox, and a PDS refuses an unfiltered listing under such a grant.
        let body = space
            .query(
                "com.atproto.space.listSpaces",
                &[
                    ("spaceDid", self.did.clone()),
                    ("spaceType", MAILBOX_SPACE_TYPE.to_owned()),
                ],
            )
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
                u == expected_mailbox
                    || atproto_spaces::SpaceUri::parse_hedged(u).is_ok_and(|parsed| {
                        parsed.authority == self.did
                            && parsed.space_type == "blue.catbird.labyrinth.mailbox"
                            && parsed.rkey == "self"
                    })
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
        // Another enrolled device may have advanced both authenticated sources while this
        // device was dormant. Do not republish this device's stale local head first: that can
        // create the very PDS/DS split that `open` is meant to reconcile. Let the strict
        // CompositeDirectory sync below verify and adopt the remote chain.
        if pds_latest.is_some() && ds_latest.is_some() {
            let anchored = self.directory().latest(&self.did).await?;
            if anchored.as_ref().is_some_and(|head| {
                head.seq > local.seq || (head.seq == local.seq && head.head != local.head)
            }) {
                return Ok(());
            }
        }
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
        lab.set_recovery_shares(Some(self.recovery_shares()));
        let persisted = Arc::new(std::sync::Mutex::new(persisted));
        let directory = Arc::from(self.directory());
        lab.set_state_sink(Box::new(VaultStateSink {
            did: self.did.clone(),
            vault: self.vault.clone(),
            persisted: persisted.clone(),
        }));
        LabyrinthSession {
            did: self.did.clone(),
            transport_key: self.signer.public_key(),
            lab,
            directory,
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

    /// Creates the account's personal mailbox Space on its PDS if it is not there yet.
    ///
    /// A PDS does not create a Space on first use: the Spaces reference PDS and Swan both
    /// answer `SpaceNotFound` for one that was never created, and the first thing `enable`
    /// does is read the mailbox. Without this step no account could ever enable its backup.
    /// The policy is `personalspace`: only the account itself can read or write it. A Space
    /// that already exists (another device, or an earlier attempt, created it) is left as
    /// it is.
    async fn ensure_mailbox_space(&self) -> Result<()> {
        let Some(space) = &self.space else {
            return Ok(());
        };
        let body = serde_json::json!({
            "spaceType": MAILBOX_SPACE_TYPE,
            "skey": MAILBOX_SKEY,
            "policy": { "$type": "com.atproto.personalspace.policy" },
        });
        let body = serde_json::to_vec(&body).map_err(|e| {
            OrchestratorError::InvalidInput(format!("labyrinth: createSpace request: {e}"))
        })?;
        match space
            .procedure("com.atproto.space.createSpace", &body)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.error.as_deref() == Some("SpaceAlreadyExists") => Ok(()),
            Err(e) => Err(OrchestratorError::Api(format!(
                "labyrinth: createSpace for the history mailbox failed: HTTP {} {}{}",
                e.status,
                e.error.as_deref().unwrap_or("no error name"),
                e.message
                    .as_deref()
                    .map(|m| format!(": {m}"))
                    .unwrap_or_default(),
            ))),
        }
    }

    /// Opens the saved session, or initializes the account's Space mailbox (`D4` auto-enrollment).
    pub async fn enable(self) -> Result<LabyrinthSession> {
        if let Some(s) = self.clone().open().await? {
            return Ok(s);
        }
        // Before the first read: a mailbox that does not exist cannot even be found empty.
        self.ensure_mailbox_space().await?;
        if self.recovery_presence().await?.requires_recovery() {
            return Err(OrchestratorError::InvalidInput(
                "labyrinth: this account already has history; restore it with a passkey, another device, or a recovery code".into(),
            ));
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
        let restored = Labyrinth::restore_with_recovery_code_shared(
            &self.did,
            code,
            self.transport_signer(&fault),
            self.backends(placement)?,
            Some(self.recovery_shares()),
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

    /// Enrolls this device from a WebAuthn Passkey PRF secret (`Gate 3` atomic enrollment).
    pub async fn restore_with_passkey_prf(
        self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<LabyrinthSession> {
        let placement = self.probe_placement().await?;
        let fault = SignerFault::default();
        let restored = Labyrinth::restore_with_passkey_shared(
            &self.did,
            prf_output_32,
            credential_id,
            self.transport_signer(&fault),
            self.backends(placement)?,
            Some(self.recovery_shares()),
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
        if let Some(error) = enrollment.unfinished {
            s.note_directory_publication(&Err(error));
        }
        s.save()?;
        Ok(s)
    }

    /// Starts a live 2-device CPace+ML-KEM-768 OTC session as the new device,
    /// writing the initiator offer record to the account's `OwnerMailbox` Space.
    pub async fn start_otc_session(
        &self,
        six_digit_code: &str,
        now_ms: u64,
    ) -> Result<(labyrinth::otc::Initiator, String, u64, u32)> {
        let space_mb = self.space_store().ok_or_else(space_unreachable)?;
        let ds_arc = Arc::new(self.ds_directory());
        let floors = Self::load_writer_rev_floors(&*self.placements, &self.did);
        let mailbox = SpaceMailbox::new(space_mb, Some(ds_arc));
        mailbox.seed_writer_rev_floors(&floors);
        let (initiator, msg) =
            Labyrinth::otc_start(&self.did, six_digit_code).map_err(map_error)?;
        let ek_len = msg.ek_otc.len() as u32;
        let session_id_hex = hex::encode(msg.sid);
        let expires_at_ms = now_ms.saturating_add(5 * 60 * 1000);
        let record = labyrinth::records::OtcSession {
            type_: labyrinth::records::nsid::OTC_SESSION.into(),
            session_id: session_id_hex.clone(),
            initiator_device_key_pubkey: labyrinth::records::Bytes(
                self.signer.public_key().to_vec(),
            ),
            ya: labyrinth::records::Bytes(msg.ya.to_vec()),
            ek_otc: labyrinth::records::Bytes(msg.ek_otc),
            yb: None,
            kem_ct: None,
            sealed_payload: None,
            expires_at: labyrinth::records::datetime_from_ms(expires_at_ms),
            created_at: labyrinth::records::datetime_from_ms(now_ms),
        };
        mailbox.put_otc_session(&record).await.map_err(map_error)?;
        Self::persist_writer_rev_floors(
            &*self.placements,
            &self.did,
            &mailbox.export_writer_rev_floors(),
        );
        Ok((initiator, session_id_hex, expires_at_ms, ek_len))
    }

    /// Completes a live 2-device OTC session on the new device once an already
    /// enrolled device has written the responder half into `OwnerMailbox`.
    pub async fn complete_otc_session(
        self,
        initiator: labyrinth::otc::Initiator,
        session_id_hex: &str,
        now_ms: u64,
    ) -> Result<(LabyrinthSession, u64, u32)> {
        use sha2::{Digest, Sha256};
        let placement = self.probe_placement().await?;
        let backends = self.backends(placement)?;
        let record = backends
            .mailbox
            .get_otc_session(session_id_hex)
            .await
            .map_err(map_error)?
            .ok_or_else(|| {
                OrchestratorError::InvalidInput("OTC session not found in OwnerMailbox".into())
            })?;
        let expires_at_ms = labyrinth::records::ms_from_datetime(&record.expires_at)
            .map_err(|_| OrchestratorError::InvalidInput("Malformed OTC expiresAt".into()))?;
        if now_ms >= expires_at_ms {
            return Err(OrchestratorError::InvalidInput(
                "OTC session expired".into(),
            ));
        }
        let yb_vec = record
            .yb
            .ok_or_else(|| {
                OrchestratorError::InvalidInput(
                    "OTC session awaiting responder completion from enrolled device".into(),
                )
            })?
            .0;
        let yb: [u8; 32] = yb_vec
            .try_into()
            .map_err(|_| OrchestratorError::InvalidInput("Malformed OTC yb".into()))?;
        let kem_ct = record
            .kem_ct
            .ok_or_else(|| OrchestratorError::InvalidInput("Missing OTC kemCt".into()))?
            .0;
        let kem_ct_len = kem_ct.len() as u32;
        let sealed_payload = record
            .sealed_payload
            .ok_or_else(|| OrchestratorError::InvalidInput("Missing OTC sealedPayload".into()))?
            .0;
        let ad = Sha256::digest(&kem_ct).to_vec();
        let responder_msg = labyrinth::otc::ResponderMessage { yb, kem_ct, ad };
        let fault = SignerFault::default();
        let enrolled = Labyrinth::enroll_via_otc_session(
            &self.did,
            initiator,
            &responder_msg,
            &sealed_payload,
            Some(session_id_hex.to_owned()),
            self.transport_signer(&fault),
            backends,
        )
        .await;
        surface(&fault)?;
        let (lab, enrollment) = enrolled.map_err(map_error)?;
        self.save_placement(placement)?;
        let existing = self
            .vault
            .load_zeroizing(&self.did)
            .map_err(OrchestratorError::Mls)?;
        let mut s = self.session(lab, fault, existing);
        if let Some(error) = enrollment.unfinished {
            s.note_directory_publication(&Err(error));
        }
        let new_epoch = s.latest_epoch();
        s.save()?;
        Ok((s, new_epoch, kem_ct_len))
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

/// Outcome of a peer-epoch trust check ([`LabyrinthSession::verify_peer_epoch_chain`],
/// [`LabyrinthSession::check_peer_epoch_attested`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEpochTrust {
    Verified,
    /// The epoch must not be trusted; the reason is safe to show.
    Untrusted(String),
}

/// An enabled account on this device.
pub struct LabyrinthSession {
    did: String,
    transport_key: [u8; 32],
    lab: Labyrinth,
    directory: Arc<dyn MailboxDirectory>,
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

    /// The verified public record of this account's newest epoch.
    pub fn latest_public(&self) -> Result<EpochPublic> {
        self.lab.latest_public().map_err(map_error)
    }

    /// `(seq, head, keys)` for up to `max_epochs` most recent OwnerMailbox epochs.
    ///
    /// The keys are secret: use them only inside the process, never log,
    /// serialize, or pass them across an FFI boundary.
    pub async fn recent_mailbox_keys(
        &mut self,
        max_epochs: usize,
    ) -> Result<Vec<(u64, [u8; 32], MailboxKeys)>> {
        let out = self.lab.recent_mailbox_keys(max_epochs).await;
        self.finish(out)
    }

    /// `(seq, head, keys)` for the latest epoch and the one before it.
    pub async fn mailbox_keys_current_and_previous(
        &mut self,
    ) -> Result<Vec<(u64, [u8; 32], MailboxKeys)>> {
        self.recent_mailbox_keys(2).await
    }

    /// Each member's latest epoch, verified, `[CB-18]`-attested and checked
    /// against its `[CB-29]` pin, plus this account's own latest epoch;
    /// members that fail a trust check are reported in `excluded`.
    pub async fn resolve_roster_report(&mut self, dids: &[&str]) -> Result<ResolvedRoster> {
        let out = self.lab.resolve_roster_report(dids).await;
        self.finish(out)
    }

    /// Whether `offered` is a genuine epoch of `did`: it must chain by
    /// `prev_head`/`prev_sig` links, through epochs fetched from the
    /// directory, to `did`'s latest epoch as [`resolve_roster_report`](Self::resolve_roster_report)
    /// verifies it (pins and `[CB-18]` applied; this account's own verified
    /// latest when `did` is this account).
    pub async fn verify_peer_epoch_chain(
        &mut self,
        did: &str,
        offered: &EpochPublic,
    ) -> Result<PeerEpochTrust> {
        let untrusted = |r: String| Ok(PeerEpochTrust::Untrusted(r));
        let roster = self.resolve_roster_report(&[did]).await?;
        if let Some(x) = roster.excluded.iter().find(|x| x.did == did) {
            if super::is_operational_failure(&x.error) {
                return Err(map_error(x.error.clone()));
            }
            return untrusted(format!("{did} failed directory verification: {}", x.error));
        }
        let Some((_, latest)) = roster.roster.into_iter().find(|(d, _)| d == did) else {
            return untrusted(format!("{did} has no published Labyrinth epoch"));
        };
        if let Err(e) = offered.verify(did, None) {
            return untrusted(format!("epoch failed verification: {e}"));
        }
        if offered.seq > latest.seq {
            return untrusted(format!(
                "epoch {} is newer than the verified latest epoch {}",
                offered.seq, latest.seq
            ));
        }
        if offered.seq == latest.seq {
            return if offered.head == latest.head {
                Ok(PeerEpochTrust::Verified)
            } else {
                untrusted("epoch head differs from the verified latest epoch".into())
            };
        }
        if latest.seq - offered.seq > labyrinth::client::pins::MAX_PIN_ADVANCE {
            return untrusted("epoch is too far behind the verified latest epoch".into());
        }
        let mut prev = labyrinth::client::PeerPin::of(offered);
        for seq in offered.seq + 1..latest.seq {
            let fetched = match self.directory.epoch(did, seq).await {
                Ok(e) => e,
                Err(err) if super::is_trust_failure(&err) => {
                    return untrusted(format!("directory epoch {seq} failed verification: {err}"));
                }
                Err(err) => return Err(map_error(err)),
            };
            let Some(e) = fetched else {
                return untrusted(format!("directory has no epoch {seq} to link the chain"));
            };
            if e.seq != seq {
                return untrusted("directory epoch under the wrong number".into());
            }
            if let Err(err) = e
                .verify(did, None)
                .and_then(|()| e.verify_link(prev.seq, &prev.head, &prev.sig_key))
            {
                return untrusted(format!("epoch chain broken at {seq}: {err}"));
            }
            prev = labyrinth::client::PeerPin::of(&e);
        }
        match latest.verify_link(prev.seq, &prev.head, &prev.sig_key) {
            Ok(()) => Ok(PeerEpochTrust::Verified),
            Err(err) => untrusted(format!("epoch chain broken at {}: {err}", latest.seq)),
        }
    }

    /// `[CB-18]`/`[CB-27]` for a stored record: `epoch` verifies for `did`
    /// and its attestation key is one of `did`'s chat devices that may vouch
    /// at `at`.
    pub async fn check_peer_epoch_attested(
        &self,
        did: &str,
        epoch: &EpochPublic,
        at: VouchAt,
    ) -> Result<PeerEpochTrust> {
        if let Err(e) = epoch.verify(did, None) {
            return Ok(PeerEpochTrust::Untrusted(format!(
                "epoch failed verification: {e}"
            )));
        }
        let keys = match self.directory.device_transport_keys(did).await {
            Ok(keys) => keys,
            Err(err) if super::is_trust_failure(&err) => {
                return Ok(PeerEpochTrust::Untrusted(format!(
                    "chat device keys of {did} failed verification: {err}"
                )));
            }
            Err(err) => return Err(map_error(err)),
        };
        if keys_valid_for(&keys, None, at).contains(&epoch.attestation.transport_public_key) {
            Ok(PeerEpochTrust::Verified)
        } else {
            Ok(PeerEpochTrust::Untrusted(format!(
                "epoch is not attested by a chat device of {did} valid at the record's time"
            )))
        }
    }

    pub fn recovery_method_stale(&self) -> bool {
        self.recovery_method_stale
    }

    pub async fn list_recovery_methods(&self) -> Result<Vec<RecoveryMethod>> {
        self.lab.list_recovery_methods().await.map_err(map_error)
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
        self.placements
            .delete(&SessionDeps::writer_rev_floors_key(&self.did))
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
        match out {
            Err(error @ labyrinth::Error::EpochUnanchored { .. }) => {
                let report = self
                    .lab
                    .last_unanchored_rotation()
                    .cloned()
                    .ok_or_else(|| map_error(error.clone()))?;
                self.note_directory_publication(&Err(error));
                self.finish(Ok(vec![rotation_report(report, &recovery_methods)]))
            }
            other => self.finish(other),
        }
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
        SessionDeps::persist_writer_rev_floors(
            &*self.placements,
            &self.did,
            self.lab.writer_rev_floors(),
        );
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
        let out = async {
            self.sync_epochs_healing_squats().await?;
            match self
                .lab
                .create_passkey_recovery(prf_output, credential_id)
                .await
            {
                Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                    if self.try_heal_squat(seq).await {
                        self.lab.rotate_epoch().await.map(|_| ())
                    } else {
                        Err(labyrinth::Error::EpochSquatted { seq, reason })
                    }
                }
                other => other.map(|_| ()),
            }
        }
        .await;
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
        };
        self.finish_rotation(out, &recovery_methods)
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
        };
        self.finish_rotation(out, &recovery_methods)
    }

    pub async fn remove_recovery_method(
        &mut self,
        vdevice_id: [u8; 16],
    ) -> Result<SessionRotationReport> {
        let recovery_methods = self.lab.list_recovery_methods().await.unwrap_or_default();
        let out = match self.lab.remove_recovery_method(&vdevice_id).await {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab.remove_recovery_method(&vdevice_id).await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        };
        self.finish_rotation(out, &recovery_methods)
    }

    /// A rotation may have committed to the mailbox before directory
    /// publication failed. Labyrinth retains the complete report, including
    /// a newly minted replacement code. Save that report and the pending
    /// publication marker rather than discarding the only visible code.
    fn finish_rotation(
        &mut self,
        out: labyrinth::Result<RotationReport>,
        recovery_methods: &[RecoveryMethod],
    ) -> Result<SessionRotationReport> {
        match out {
            Err(error @ labyrinth::Error::EpochUnanchored { .. }) => {
                let report = self
                    .lab
                    .last_unanchored_rotation()
                    .cloned()
                    .ok_or_else(|| map_error(error.clone()))?;
                self.note_directory_publication(&Err(error));
                self.finish(Ok(rotation_report(report, recovery_methods)))
            }
            other => self.finish(other.map(|report| rotation_report(report, recovery_methods))),
        }
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

    /// Responds to a pending 2-device OTC session in `OwnerMailbox` as an
    /// already enrolled device, sealing the recovery payload under CPace + ML-KEM-768.
    pub async fn respond_otc_session(
        &mut self,
        mailbox: &dyn MailboxStore,
        session_id_hex: &str,
        six_digit_code: &str,
        now_ms: u64,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let mut record = mailbox
            .get_otc_session(session_id_hex)
            .await
            .map_err(map_error)?
            .ok_or_else(|| {
                OrchestratorError::InvalidInput("OTC session not found in OwnerMailbox".into())
            })?;
        let expires_at_ms = labyrinth::records::ms_from_datetime(&record.expires_at)
            .map_err(|_| OrchestratorError::InvalidInput("Malformed OTC expiresAt".into()))?;
        if now_ms >= expires_at_ms {
            return Err(OrchestratorError::InvalidInput(
                "OTC session expired".into(),
            ));
        }
        let sid_bytes = hex::decode(session_id_hex)
            .map_err(|_| OrchestratorError::InvalidInput("Invalid OTC sessionId hex".into()))?;
        let sid: [u8; 16] = sid_bytes.try_into().map_err(|_| {
            OrchestratorError::InvalidInput("OTC sessionId must be 16 bytes".into())
        })?;
        let ya: [u8; 32] = record
            .ya
            .0
            .clone()
            .try_into()
            .map_err(|_| OrchestratorError::InvalidInput("Malformed OTC ya".into()))?;
        let ek_otc = record.ek_otc.0.clone();
        let ad = Sha256::digest(&ek_otc).to_vec();
        let init_msg = labyrinth::otc::InitiatorMessage {
            sid,
            ya,
            ek_otc,
            ad,
        };
        let code = labyrinth::otc::OneTimeCode::parse(six_digit_code).map_err(map_error)?;
        let mut responder = labyrinth::otc::Responder::new(code, &self.did);
        let out = self.lab.otc_respond(&mut responder, &init_msg).await;
        let resp = self.finish(out)?;
        record.yb = Some(labyrinth::records::Bytes(resp.message.yb.to_vec()));
        record.kem_ct = Some(labyrinth::records::Bytes(resp.message.kem_ct));
        record.sealed_payload = Some(labyrinth::records::Bytes(resp.sealed_payload));
        mailbox.put_otc_session(&record).await.map_err(map_error)?;
        SessionDeps::persist_writer_rev_floors(
            &*self.placements,
            &self.did,
            &mailbox.export_writer_rev_floors(),
        );
        Ok(())
    }

    pub async fn get_read_state(
        &mut self,
        conversation_id: &str,
    ) -> Result<Option<labyrinth::client::ReadState>> {
        let out = self.lab.get_read_state(conversation_id).await;
        self.finish(out)
    }

    pub async fn advance_read_state(
        &mut self,
        conversation_id: &str,
        candidate_seq: u64,
    ) -> Result<labyrinth::client::ReadState> {
        let out = match self
            .lab
            .advance_read_state(conversation_id, candidate_seq)
            .await
        {
            Err(labyrinth::Error::EpochSquatted { seq, reason }) => {
                if self.try_heal_squat(seq).await {
                    self.lab
                        .advance_read_state(conversation_id, candidate_seq)
                        .await
                } else {
                    Err(labyrinth::Error::EpochSquatted { seq, reason })
                }
            }
            other => other,
        };
        self.finish(out)
    }

    pub async fn list_read_states(&mut self) -> Result<Vec<labyrinth::client::ReadState>> {
        let out = self.lab.list_read_states().await;
        self.finish(out)
    }

    pub async fn get_circle_owner_state(
        &mut self,
        circle_id: &str,
    ) -> Result<Option<(labyrinth::client::CircleOwnerState, Option<String>)>> {
        let out = self.lab.get_circle_owner_state(circle_id).await;
        self.finish(out)
    }

    pub async fn put_circle_owner_state(
        &mut self,
        state: &labyrinth::client::CircleOwnerState,
        swap_record_cid: Option<&str>,
    ) -> Result<String> {
        let out = self
            .lab
            .put_circle_owner_state(state, swap_record_cid)
            .await;
        self.finish(out)
    }

    pub async fn merge_circle_owner_state(
        &mut self,
        update: &labyrinth::client::CircleOwnerState,
    ) -> Result<(labyrinth::client::CircleOwnerState, String)> {
        let out = self.lab.merge_circle_owner_state(update).await;
        self.finish(out)
    }

    pub async fn clear_circle_acl_tombstone(
        &mut self,
        circle_id: &str,
        member_did: &str,
    ) -> Result<Option<(labyrinth::client::CircleOwnerState, String)>> {
        let out = self
            .lab
            .clear_circle_acl_tombstone(circle_id, member_did)
            .await;
        self.finish(out)
    }

    pub async fn list_circle_owner_states(
        &mut self,
    ) -> Result<Vec<labyrinth::client::CircleOwnerState>> {
        let out = self.lab.list_circle_owner_states().await;
        self.finish(out)
    }
}

#[cfg(test)]
mod history_error_tests {
    use super::history_error_counts;

    #[tokio::test]
    async fn returned_account_still_requires_every_live_shared_leaf() {
        use super::{
            LocalConversationAuthority, LocalGroupSnapshot, LocallyCheckedDirectory, Result,
        };
        use labyrinth::store::{memory::MemoryBackend, MailboxDirectory};

        struct ReturnedAccount;
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl LocalConversationAuthority for ReturnedAccount {
            async fn current_group_snapshot(
                &self,
                _: &str,
                _: Option<&str>,
            ) -> Result<Option<LocalGroupSnapshot>> {
                Ok(None)
            }
            async fn authorized_chat_device_keys(&self, _: &str) -> Result<Option<Vec<[u8; 32]>>> {
                Ok(Some(vec![[1; 32], [2; 32]]))
            }
            async fn shared_group_leaf_keys(&self, _: &str) -> Result<Option<Vec<[u8; 32]>>> {
                Ok(Some(vec![[1; 32], [2; 32]]))
            }
            async fn verified_deleted_account_ms(&self, _: &str) -> Result<Option<u64>> {
                Ok(Some(100))
            }
        }
        let backend = MemoryBackend::new();
        let did = "did:plc:returned";
        backend.register_chat_device(did, [1; 32]);
        let directory = LocallyCheckedDirectory {
            inner: Box::new(backend.directory()),
            authority: std::sync::Arc::new(ReturnedAccount),
        };
        assert!(directory.device_transport_keys(did).await.is_err());
        backend.register_chat_device(did, [2; 32]);
        assert_eq!(directory.device_transport_keys(did).await.unwrap().len(), 2);
    }

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
            evicted_revoked: Vec::new(),
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
            invalidated_recovery_methods: Vec::new(),
            rekeyed_recovery: None,
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
