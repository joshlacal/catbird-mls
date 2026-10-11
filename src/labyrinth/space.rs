//! The personal mailbox in the account's own atproto Space (backend A of
//! the plan; the labyrinth crate's `store::space`, SPEC §9).
//!
//! When the platform can reach the signed-in account's PDS with its OAuth
//! session (`OrchestratorAPICallback::labyrinth_space_enabled`) and also
//! publishes `mailboxKeys` (`labyrinth_pds_enabled`), a new mailbox goes
//! into the account's Space
//! `at://{did}/space/blue.catbird.labyrinth.mailbox/self` instead of mls-ds.
//! Everything else stays on mls-ds: conversation threads, MEKs, the ORF and
//! attachment references, the chat device keys and the epoch-head chain
//! that cross-checks the PDS ([CB-28]: with the mailbox on the PDS, mls-ds
//! is the independent directory).
//!
//! | Piece | Here |
//! |---|---|
//! | `com.atproto.space.*` request the platform sends with OAuth | [`LabyrinthSpaceRequest`] |
//! | Blocking seam to the platform | [`LabyrinthSpaceGateway`] |
//! | [`XrpcTransport`] for the crate's `SpaceMailboxStore` | [`SpaceXrpcTransport`] |
//! | Which backend holds this account's mailbox, saved per device | [`Placement`], [`MlsPlacementVault`] |
//! | Account deletion across both backends | [`SpaceMailbox`] |
//!
//! The placement is chosen once, when this device enables or restores
//! ([`super::session::SessionDeps::probe_placement`]), and saved next to the
//! client state. Saved state from before this module has no placement and
//! is an mls-ds mailbox. Nothing moves a mailbox between backends.

use std::sync::Arc;

use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::space::SpaceMailboxStore;
use labyrinth::store::xrpc::{XrpcError, XrpcMailboxStore, XrpcTransport};
use labyrinth::store::{MailboxStore, Stored, TimeRange};

use super::state::StateVault;
use super::transport::decode_response;
use crate::orchestrator::canonical_transport::{encode_query, GatewayResponse};
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::MLSError;

/// NSID prefix of every request [`SpaceXrpcTransport`] sends.
pub const SPACE_NSID_PREFIX: &str = "com.atproto.space.";

/// One `com.atproto.space.*` XRPC to the signed-in account's own PDS.
///
/// The platform sends it with the account's OAuth (DPoP) session, the way
/// it sends `com.atproto.repo.*` calls. It is not a service-auth request:
/// no `lxm`, no Labyrinth write or read headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabyrinthSpaceRequest {
    /// The endpoint NSID, always under [`SPACE_NSID_PREFIX`].
    pub nsid: String,
    /// `GET` for queries, `POST` for procedures.
    pub method: String,
    /// `/xrpc/{nsid}` plus the URL-encoded query string.
    pub path: String,
    /// JSON body of a procedure.
    pub body: Option<Vec<u8>>,
}

/// Blocking access to the account's PDS for Space requests.
pub trait LabyrinthSpaceGateway: Send + Sync {
    fn submit_space(&self, request: LabyrinthSpaceRequest) -> Result<GatewayResponse, String>;
}

/// The crate's Space store transport over [`LabyrinthSpaceGateway`].
///
/// It sends only `com.atproto.space.*` NSIDs, so a bug elsewhere cannot
/// turn the OAuth session into a general PDS client.
pub struct SpaceXrpcTransport {
    gateway: Arc<dyn LabyrinthSpaceGateway>,
}

impl SpaceXrpcTransport {
    pub fn new(gateway: Arc<dyn LabyrinthSpaceGateway>) -> Self {
        Self { gateway }
    }
}

fn refuse(message: String) -> XrpcError {
    XrpcError {
        status: 0,
        error: None,
        message: Some(message),
    }
}

fn check_nsid(nsid: &str) -> Result<(), XrpcError> {
    if nsid.starts_with(SPACE_NSID_PREFIX) {
        Ok(())
    } else {
        Err(refuse(format!("refusing a non-Space PDS request: {nsid}")))
    }
}

impl XrpcTransport for SpaceXrpcTransport {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcError> {
        check_nsid(nsid)?;
        // The Space store sends none; the gateway has no way to carry them.
        if !headers.is_empty() {
            return Err(refuse(format!("{nsid}: extra headers are not supported")));
        }
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
            .collect();
        let path = if query.is_empty() {
            format!("/xrpc/{nsid}")
        } else {
            format!("/xrpc/{nsid}?{}", query.join("&"))
        };
        decode_response(self.gateway.submit_space(LabyrinthSpaceRequest {
            nsid: nsid.to_owned(),
            method: "GET".into(),
            path,
            body: None,
        }))
    }

    /// Space writes are not idempotent by operation id; the store's
    /// create-if-absent rkeys make a retried write fail with a conflict
    /// instead of applying twice.
    fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        _operation_id: [u8; 16],
    ) -> Result<Vec<u8>, XrpcError> {
        check_nsid(nsid)?;
        decode_response(self.gateway.submit_space(LabyrinthSpaceRequest {
            nsid: nsid.to_owned(),
            method: "POST".into(),
            path: format!("/xrpc/{nsid}"),
            body: Some(payload.to_vec()),
        }))
    }
}

/// Where an account's mailbox lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// mls-ds `blue.catbird.labyrinth.*` (backend B; every account before
    /// Space support).
    MlsDs,
    /// The account's personal Space on its PDS (backend A).
    Space,
}

impl Placement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlsDs => "mlsds",
            Self::Space => "space",
        }
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"mlsds" => Some(Self::MlsDs),
            b"space" => Some(Self::Space),
            _ => None,
        }
    }
}

/// Request-value namespace of the saved [`Placement`], keyed by DID.
pub const PLACEMENT_NAMESPACE: &str = "labyrinthMailboxPlacement";

/// The saved [`Placement`] in the encrypted MLS database, next to the
/// client state ([`super::state::MlsStateVault`]).
pub struct MlsPlacementVault<M>(pub Arc<M>);

impl<M: MlsCryptoContext + 'static> StateVault for MlsPlacementVault<M> {
    fn load(&self, did: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.0.read_request_value(PLACEMENT_NAMESPACE, did)
    }

    fn compare_exchange(
        &self,
        did: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.0
            .compare_exchange_request_value(PLACEMENT_NAMESPACE, did, expected, next)
    }

    fn delete(&self, did: &str) -> Result<(), MLSError> {
        self.0
            .delete_request_value(PLACEMENT_NAMESPACE, did)
            .map(|_| ())
    }
}

/// A Space mailbox whose account deletion also runs mls-ds
/// `deleteAccountData`.
///
/// Every mailbox call goes to the Space. Only
/// [`MailboxStore::delete_account_data`] differs: mls-ds redacts every
/// thread item the account wrote (across delivery services, atomically,
/// which the client's own loop cannot) and drops its ORF states,
/// attachment references and head chain; then the Space records and the
/// PDS `mailboxKeys` go. Both halves are idempotent, so the crate's retry
/// after `remote_pending` reruns the whole thing.
pub struct SpaceMailbox {
    space: SpaceMailboxStore,
    ds: XrpcMailboxStore,
}

impl SpaceMailbox {
    pub fn new(space: SpaceMailboxStore, ds: XrpcMailboxStore) -> Self {
        Self { space, ds }
    }
}

impl MailboxStore for SpaceMailbox {
    fn owner(&self) -> &str {
        self.space.owner()
    }
    fn create_device(&self, device: &Device) -> labyrinth::Result<()> {
        self.space.create_device(device)
    }
    fn set_device_revoked(
        &self,
        device_key: &XVerifyingKey,
        revoked_at: &str,
    ) -> labyrinth::Result<()> {
        self.space.set_device_revoked(device_key, revoked_at)
    }
    fn get_device(&self, device_key: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.space.get_device(device_key)
    }
    fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.space.list_devices()
    }
    fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> labyrinth::Result<String> {
        self.space.create_epoch(epoch, members)
    }
    fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        self.space.get_epoch(seq)
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.space.list_epochs()
    }
    fn create_epoch_member(&self, member: &EpochMember) -> labyrinth::Result<()> {
        self.space.create_epoch_member(member)
    }
    fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.space.list_epoch_members(seq)
    }
    fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> labyrinth::Result<Option<EpochMember>> {
        self.space.get_epoch_member(seq, device_key)
    }
    fn create_virtual_device(&self, vdevice: &VirtualDevice) -> labyrinth::Result<()> {
        self.space.create_virtual_device(vdevice)
    }
    fn get_virtual_device(
        &self,
        vdevice_id: &[u8; 16],
    ) -> labyrinth::Result<Option<VirtualDevice>> {
        self.space.get_virtual_device(vdevice_id)
    }
    fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.space.list_virtual_devices()
    }
    fn append_owner_batch(&self, batch: &OwnerBatch) -> labyrinth::Result<String> {
        self.space.append_owner_batch(batch)
    }
    fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space.list_owner_batches(thread_id, range)
    }
    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.space.publish_mailbox_keys(record)
    }
    fn get_owner_messages(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space.get_owner_messages(thread_id, message_ids)
    }
    fn list_owner_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space
            .list_owner_batches_before(thread_id, before_ms, limit)
    }
    fn list_owner_threads(&self) -> labyrinth::Result<Vec<String>> {
        self.space.list_owner_threads()
    }
    fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> labyrinth::Result<()> {
        self.space.touch_virtual_device(vdevice_id)
    }
    fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> labyrinth::Result<()> {
        self.space.delete_virtual_device(vdevice_id)
    }
    fn purge_mailbox(&self) -> labyrinth::Result<()> {
        self.space.purge_mailbox()
    }
    fn delete_account_data(&self) -> labyrinth::Result<()> {
        self.ds.delete_account_data()?;
        self.space.purge_mailbox()
    }
}
