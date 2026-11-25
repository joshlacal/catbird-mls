//! ATProto Spaces (`com.atproto.space.*`) transport, placement pins, and
//! account deletion wrapper (`SPEC §9`, Gates 1, 3, 5, and 7).

use std::sync::Arc;

use labyrinth::attachment::AttachmentCiphertextMeta;
use labyrinth::records::{
    CircleOwnerStateRecord, Device, Epoch, EpochMember, MailboxKeysRecord, OtcSession, OwnerBatch,
    ReadStateRecord, VirtualDevice,
};
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::space::{SpaceError, SpaceMailboxStore, SpaceRpc};
use labyrinth::store::{
    AtomicEnrollBundle, AuthorQuarantine, MailboxStore, MaybeSend, MaybeSync, Stored,
    ThreadListing, TimeRange,
};
use serde::{Deserialize, Serialize};

use super::state::StateVault;
use super::transport::{decode_response_bounded, validate_nsid, DsDirectoryStore};
use crate::orchestrator::canonical_transport::{encode_query, GatewayResponse};
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::MLSError;

/// NSID prefix of every Space endpoint [`SpaceXrpcTransport`] sends.
pub const SPACE_NSID_PREFIX: &str = "com.atproto.space.";

/// Blob staging endpoint used prior to `applyWrites` commit (`atproto#5187`).
pub const UPLOAD_BLOB_NSID: &str = "com.atproto.repo.uploadBlob";

/// Maximum response payload accepted from a Space XRPC or blob call (16 MiB).
pub const MAX_SPACE_XRPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// One `com.atproto.space.*` (or `com.atproto.repo.uploadBlob`) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabyrinthSpaceRequest {
    pub nsid: String,
    pub method: String,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl LabyrinthSpaceRequest {
    pub fn get(nsid: &str, path: String) -> Self {
        Self {
            nsid: nsid.to_owned(),
            method: "GET".into(),
            path,
            body: None,
            content_type: None,
            headers: Vec::new(),
        }
    }

    pub fn post_json(nsid: &str, body: Vec<u8>) -> Self {
        Self {
            nsid: nsid.to_owned(),
            method: "POST".into(),
            path: format!("/xrpc/{nsid}"),
            body: Some(body),
            content_type: Some("application/json".into()),
            headers: Vec::new(),
        }
    }
}

/// Full HTTP response from a Space host or `mls-ds` `relaySpaceRead`, carrying
/// response headers (such as `Atproto-Space-Mac`) for Gate 7 verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabyrinthSpaceResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl From<GatewayResponse> for LabyrinthSpaceResponse {
    fn from(r: GatewayResponse) -> Self {
        Self {
            status: r.status,
            content_type: r.content_type,
            headers: Vec::new(),
            body: r.body,
        }
    }
}

/// Gate 7 hook verifying `Atproto-Space-Mac` on credentialed Space responses
/// before any `MEK` or record bytes are inspected.
pub trait SpaceResponseMacVerifier: MaybeSend + MaybeSync {
    fn verify_space_response(
        &self,
        request: &LabyrinthSpaceRequest,
        response: &LabyrinthSpaceResponse,
    ) -> Result<(), String>;
}

/// Async access to the account's PDS Space / `relaySpaceRead` transport.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait LabyrinthSpaceGateway: MaybeSend + MaybeSync {
    async fn submit_space(&self, request: LabyrinthSpaceRequest)
        -> Result<GatewayResponse, String>;

    /// True only when the gateway verifies every successful Space read before
    /// returning it (response MAC, STAR, inventory commitment and rollback
    /// floors as applicable).
    fn authenticates_responses(&self) -> bool {
        false
    }

    async fn submit_space_with_headers(
        &self,
        request: LabyrinthSpaceRequest,
    ) -> Result<LabyrinthSpaceResponse, String> {
        self.submit_space(request).await.map(Into::into)
    }
}

/// [`SpaceRpc`] adapter over [`LabyrinthSpaceGateway`] with NSID allowlisting
/// and optional Gate 7 `Atproto-Space-Mac` verification.
pub struct SpaceXrpcTransport {
    gateway: Arc<dyn LabyrinthSpaceGateway>,
    mac_verifier: Option<Arc<dyn SpaceResponseMacVerifier>>,
}

impl SpaceXrpcTransport {
    pub fn new(gateway: Arc<dyn LabyrinthSpaceGateway>) -> Self {
        Self {
            gateway,
            mac_verifier: None,
        }
    }

    pub fn with_mac_verifier(mut self, verifier: Arc<dyn SpaceResponseMacVerifier>) -> Self {
        self.mac_verifier = Some(verifier);
        self
    }

    /// Fetch and Gate-7-MAC-verify a single record via `com.atproto.space.getRecord`.
    pub async fn get_record(
        &self,
        space: &str,
        repo: &str,
        collection: &str,
        rkey: &str,
    ) -> core::result::Result<Option<serde_json::Value>, SpaceError> {
        let res = self
            .query(
                "com.atproto.space.getRecord",
                &[
                    ("space", space.to_owned()),
                    ("repo", repo.to_owned()),
                    ("collection", collection.to_owned()),
                    ("rkey", rkey.to_owned()),
                ],
            )
            .await;
        match res {
            Ok(bytes) => {
                let parsed: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| refuse_space(format!("getRecord invalid JSON: {e}")))?;
                Ok(Some(parsed))
            }
            Err(err)
                if err.status == 404
                    || matches!(err.error.as_deref(), Some("RecordNotFound" | "NotFound")) =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    async fn send_checked_with_headers(
        &self,
        req: LabyrinthSpaceRequest,
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        let resp = self
            .gateway
            .submit_space_with_headers(req.clone())
            .await
            .map_err(|m| SpaceError {
                status: 0,
                error: None,
                message: Some(m),
            })?;
        if let Some(verifier) = &self.mac_verifier {
            if (200..300).contains(&resp.status) {
                verifier
                    .verify_space_response(&req, &resp)
                    .map_err(|msg| SpaceError {
                        status: 0,
                        error: Some("InvalidSpaceMac".into()),
                        message: Some(msg),
                    })?;
            }
        }
        let headers = resp.headers;
        let body = decode_response_bounded(
            Ok(GatewayResponse {
                status: resp.status,
                content_type: resp.content_type,
                body: resp.body,
            }),
            MAX_SPACE_XRPC_RESPONSE_BYTES,
        )
        .map_err(|e| SpaceError {
            status: e.status,
            error: e.error,
            message: e.message,
        })?;
        Ok((headers, body))
    }

    async fn send_checked(&self, req: LabyrinthSpaceRequest) -> Result<Vec<u8>, SpaceError> {
        self.send_checked_with_headers(req)
            .await
            .map(|(_, body)| body)
    }
}

fn refuse_space(message: String) -> SpaceError {
    SpaceError {
        status: 0,
        error: None,
        message: Some(message),
    }
}

fn check_space_nsid(nsid: &str) -> Result<(), SpaceError> {
    validate_nsid(nsid).map_err(|e| SpaceError {
        status: e.status,
        error: e.error,
        message: e.message,
    })?;
    if nsid.starts_with(SPACE_NSID_PREFIX) {
        Ok(())
    } else {
        Err(refuse_space(format!(
            "refusing a non-Space PDS request: {nsid}"
        )))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for SpaceXrpcTransport {
    fn authenticates_responses(&self) -> bool {
        self.gateway.authenticates_responses()
    }
    async fn query(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> core::result::Result<Vec<u8>, SpaceError> {
        self.query_with_headers(nsid, params, &[])
            .await
            .map(|(_, body)| body)
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> core::result::Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        check_space_nsid(nsid)?;
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
            .collect();
        let path = if query.is_empty() {
            format!("/xrpc/{nsid}")
        } else {
            format!("/xrpc/{nsid}?{}", query.join("&"))
        };
        let mut req = LabyrinthSpaceRequest::get(nsid, path);
        req.headers = headers.to_vec();
        self.send_checked_with_headers(req).await
    }

    async fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
    ) -> core::result::Result<Vec<u8>, SpaceError> {
        check_space_nsid(nsid)?;
        self.send_checked(LabyrinthSpaceRequest::post_json(nsid, payload.to_vec()))
            .await
    }

    async fn upload_blob(
        &self,
        bytes: &[u8],
        mime_type: &str,
    ) -> core::result::Result<String, SpaceError> {
        let req = LabyrinthSpaceRequest {
            nsid: UPLOAD_BLOB_NSID.to_owned(),
            method: "POST".into(),
            path: format!("/xrpc/{UPLOAD_BLOB_NSID}"),
            body: Some(bytes.to_vec()),
            content_type: Some(mime_type.to_owned()),
            headers: Vec::new(),
        };
        let body = self.send_checked(req).await?;
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| refuse_space(format!("uploadBlob invalid JSON: {e}")))?;
        parsed["blob"]["ref"]["$link"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| refuse_space("uploadBlob missing blob.ref.$link".into()))
    }

    async fn get_blob(
        &self,
        space: &str,
        did: &str,
        cid: &str,
    ) -> core::result::Result<Vec<u8>, SpaceError> {
        let nsid = "com.atproto.space.getBlob";
        let path = format!(
            "/xrpc/{nsid}?space={}&repo={}&cid={}",
            encode_query(space),
            encode_query(did),
            encode_query(cid)
        );
        self.send_checked(LabyrinthSpaceRequest::get(nsid, path))
            .await
    }
}

/// Clean-slate mailbox placement (`Spaces-only` per Spec §3.2 `G6`, `I14`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Placement {
    /// The account's personal Space on its PDS (`at:space/{did}/blue.catbird.labyrinth.mailbox/self`).
    #[default]
    Space,
}

impl Placement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Space => "space",
        }
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"space" => Some(Self::Space),
            _ => None,
        }
    }
}

/// Request-value namespace of the saved [`Placement`] & conversation Space pins.
pub const PLACEMENT_NAMESPACE: &str = "labyrinthMailboxPlacement";

/// Conversation Space URI + generation pin persisted per account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadPlacement {
    pub space: Option<String>,
    #[serde(default)]
    pub generation: u64,
    /// Lowercase hex MLS group of `generation`, from the verified local roster or a signed owner
    /// receipt. A Space denial is removal proof only for this exact group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

impl ThreadPlacement {
    pub fn validate(&self) -> labyrinth::Result<()> {
        if let Some(ref u) = self.space {
            labyrinth::store::space::SpaceRef::parse(u)?;
        }
        Ok(())
    }
}

pub fn thread_placement_key(did: &str) -> String {
    format!("threads:{did}")
}

/// Saved [`Placement`] and conversation Space URI pins in the encrypted MLS DB.
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

/// Personal Space mailbox whose account deletion also runs `mls-ds`
/// `deleteAccountData` (`L-F01` epoch floor + `accountDeleted` chat entries).
pub struct SpaceMailbox {
    space: SpaceMailboxStore,
    ds: Option<Arc<DsDirectoryStore>>,
}

impl SpaceMailbox {
    pub fn new(space: SpaceMailboxStore, ds: Option<Arc<DsDirectoryStore>>) -> Self {
        Self { space, ds }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for SpaceMailbox {
    fn owner(&self) -> &str {
        self.space.owner()
    }
    async fn create_device(&self, device: &Device) -> labyrinth::Result<()> {
        self.space.create_device(device).await
    }
    async fn set_device_revoked(
        &self,
        device_key: &XVerifyingKey,
        revoked_at: &str,
    ) -> labyrinth::Result<()> {
        self.space.set_device_revoked(device_key, revoked_at).await
    }
    async fn set_device_revocation(
        &self,
        device_key: &XVerifyingKey,
        revoked_at: &str,
        revocation: &labyrinth::records::DeviceRevocationDef,
    ) -> labyrinth::Result<()> {
        self.space
            .set_device_revocation(device_key, revoked_at, revocation)
            .await
    }
    async fn get_device(&self, device_key: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.space.get_device(device_key).await
    }
    async fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.space.list_devices().await
    }
    async fn create_epoch(
        &self,
        epoch: &Epoch,
        members: &[EpochMember],
    ) -> labyrinth::Result<String> {
        self.space.create_epoch(epoch, members).await
    }
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.space.atomic_enroll(bundle).await
    }
    async fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        self.space.get_epoch(seq).await
    }
    async fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.space.list_epochs().await
    }
    async fn create_epoch_member(&self, member: &EpochMember) -> labyrinth::Result<()> {
        self.space.create_epoch_member(member).await
    }
    async fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.space.list_epoch_members(seq).await
    }
    async fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> labyrinth::Result<Option<EpochMember>> {
        self.space.get_epoch_member(seq, device_key).await
    }
    async fn create_virtual_device(&self, vdevice: &VirtualDevice) -> labyrinth::Result<()> {
        self.space.create_virtual_device(vdevice).await
    }
    async fn get_virtual_device(
        &self,
        vdevice_id: &[u8; 16],
    ) -> labyrinth::Result<Option<VirtualDevice>> {
        self.space.get_virtual_device(vdevice_id).await
    }
    async fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.space.list_virtual_devices().await
    }
    async fn list_virtual_device_records(
        &self,
    ) -> labyrinth::Result<Vec<labyrinth::Result<VirtualDevice>>> {
        self.space.list_virtual_device_records().await
    }
    async fn put_otc_session(&self, session: &OtcSession) -> labyrinth::Result<()> {
        self.space.put_otc_session(session).await
    }
    async fn get_otc_session(&self, session_id: &str) -> labyrinth::Result<Option<OtcSession>> {
        self.space.get_otc_session(session_id).await
    }
    async fn get_read_state(
        &self,
        conversation_id: &str,
    ) -> labyrinth::Result<Option<(ReadStateRecord, Option<String>)>> {
        self.space.get_read_state(conversation_id).await
    }
    async fn get_read_state_versioned(
        &self,
        conversation_id: &str,
    ) -> labyrinth::Result<Option<(ReadStateRecord, Option<String>, u64)>> {
        self.space.get_read_state_versioned(conversation_id).await
    }
    async fn put_read_state(
        &self,
        conversation_id: &str,
        record: &ReadStateRecord,
        expected_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        self.space
            .put_read_state(conversation_id, record, expected_cid)
            .await
    }
    async fn list_read_states(
        &self,
    ) -> labyrinth::Result<Vec<(String, ReadStateRecord, Option<String>)>> {
        self.space.list_read_states().await
    }
    async fn list_read_states_versioned(
        &self,
    ) -> labyrinth::Result<Vec<(String, ReadStateRecord, Option<String>, u64)>> {
        self.space.list_read_states_versioned().await
    }
    async fn get_circle_owner_state(
        &self,
        circle_id: &str,
    ) -> labyrinth::Result<Option<(CircleOwnerStateRecord, Option<String>)>> {
        self.space.get_circle_owner_state(circle_id).await
    }
    async fn get_circle_owner_state_versioned(
        &self,
        circle_id: &str,
    ) -> labyrinth::Result<Option<(CircleOwnerStateRecord, Option<String>, u64)>> {
        self.space.get_circle_owner_state_versioned(circle_id).await
    }
    async fn put_circle_owner_state(
        &self,
        circle_id: &str,
        record: &CircleOwnerStateRecord,
        expected_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        self.space
            .put_circle_owner_state(circle_id, record, expected_cid)
            .await
    }
    async fn list_circle_owner_states(
        &self,
    ) -> labyrinth::Result<Vec<(String, CircleOwnerStateRecord, Option<String>)>> {
        self.space.list_circle_owner_states().await
    }
    async fn list_circle_owner_states_versioned(
        &self,
    ) -> labyrinth::Result<Vec<(String, CircleOwnerStateRecord, Option<String>, u64)>> {
        self.space.list_circle_owner_states_versioned().await
    }
    fn seed_owner_state_version_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), u64>,
    ) {
        self.space.seed_owner_state_version_floors(floors);
    }
    fn replace_owner_state_version_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), u64>,
    ) {
        self.space.replace_owner_state_version_floors(floors);
    }
    fn export_owner_state_version_floors(
        &self,
    ) -> std::collections::BTreeMap<(String, String), u64> {
        self.space.export_owner_state_version_floors()
    }
    fn seed_writer_rev_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), String>,
    ) {
        self.space.seed_writer_rev_floors(floors);
    }
    fn replace_writer_rev_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), String>,
    ) {
        self.space.replace_writer_rev_floors(floors);
    }
    fn export_writer_rev_floors(&self) -> std::collections::BTreeMap<(String, String), String> {
        self.space.export_writer_rev_floors()
    }
    async fn append_owner_batch(&self, batch: &OwnerBatch) -> labyrinth::Result<String> {
        self.space.append_owner_batch(batch).await
    }
    async fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space.list_owner_batches(thread_id, range).await
    }
    async fn upload_and_commit_owner_attachment(
        &self,
        rkey: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> labyrinth::Result<String> {
        self.space
            .upload_and_commit_owner_attachment(rkey, ciphertext, meta, created_at)
            .await
    }
    async fn get_owner_attachment_verified(&self, rkey: &str) -> labyrinth::Result<Vec<u8>> {
        self.space.get_owner_attachment_verified(rkey).await
    }
    async fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.space.publish_mailbox_keys(record).await
    }
    async fn get_owner_messages(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space.get_owner_messages(thread_id, message_ids).await
    }
    async fn list_owner_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.space
            .list_owner_batches_before(thread_id, before_ms, limit)
            .await
    }
    async fn list_owner_threads(&self) -> labyrinth::Result<Vec<String>> {
        self.space.list_owner_threads().await
    }
    async fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> labyrinth::Result<()> {
        self.space.touch_virtual_device(vdevice_id).await
    }
    async fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> labyrinth::Result<()> {
        self.space.delete_virtual_device(vdevice_id).await
    }
    async fn purge_mailbox(&self) -> labyrinth::Result<()> {
        self.space.purge_mailbox().await
    }
    async fn delete_account_data(&self) -> labyrinth::Result<()> {
        if let Some(ds) = &self.ds {
            ds.delete_account_data().await?;
        }
        self.space.purge_mailbox().await
    }
    async fn delete_squatted_epoch(&self, seq: u64) -> labyrinth::Result<()> {
        self.space.delete_squatted_epoch(seq).await
    }
}

/// Conversation [`ThreadStore`] backed by [`labyrinth::store::space::SpaceThreadStore`]
/// that resolves and pins each conversation's Option A Space URI
/// (`at:space/{sequencerDid}/blue.catbird.labyrinth.conversation/{conversationId}-{generation}`)
/// from persisted `ThreadPlacement` pins or `blue.catbird.chat.getConversationState`.
pub struct ResolvingSpaceThreadStore {
    did: String,
    inner: labyrinth::store::space::SpaceThreadStore,
    transport: Option<Arc<super::transport::GatewayXrpcTransport>>,
    placements: Arc<dyn StateVault>,
    resolved: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl ResolvingSpaceThreadStore {
    pub fn new(
        did: impl Into<String>,
        space_rpc: Arc<dyn SpaceRpc>,
        transport: Option<Arc<super::transport::GatewayXrpcTransport>>,
        placements: Arc<dyn StateVault>,
        default_authority_did: Option<String>,
    ) -> Self {
        let did = did.into();
        let mut inner = labyrinth::store::space::SpaceThreadStore::new(space_rpc, did.clone());
        if let Some(auth) = default_authority_did {
            inner = inner.with_authority_did(auth);
        }
        if let Some(transport) = &transport {
            let transport = transport.clone();
            inner = inner.with_clock(Arc::new(move || transport.now_ms()));
        }
        Self {
            did,
            inner,
            transport,
            placements,
            resolved: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    pub fn set_thread_space(&self, thread_id: &str, space: labyrinth::store::space::SpaceRef) {
        self.inner.set_thread_space(thread_id, space);
        self.resolved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(thread_id.to_owned());
    }

    fn load_pins(&self) -> labyrinth::Result<std::collections::BTreeMap<String, ThreadPlacement>> {
        let key = thread_placement_key(&self.did);
        let Some(raw) = self
            .placements
            .load(&key)
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
        else {
            return Ok(std::collections::BTreeMap::new());
        };
        serde_json::from_slice(&raw)
            .map_err(|_| labyrinth::Error::Malformed("saved conversation placements"))
    }

    fn save_pin(
        &self,
        thread_id: &str,
        space: &labyrinth::store::space::SpaceRef,
        generation: u64,
    ) {
        let key = thread_placement_key(&self.did);
        let Ok(current) = self.placements.load(&key) else {
            return;
        };
        let mut map: std::collections::BTreeMap<String, ThreadPlacement> = current
            .as_deref()
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();
        let uri = space.to_string();
        if map
            .get(thread_id)
            .is_some_and(|p| p.space.as_deref() == Some(uri.as_str()) && p.generation == generation)
        {
            return;
        }
        map.insert(
            thread_id.to_owned(),
            ThreadPlacement {
                space: Some(uri),
                generation,
                group_id: None,
            },
        );
        if let Ok(encoded) = serde_json::to_vec(&map) {
            let _ = self
                .placements
                .compare_exchange(&key, current.as_deref(), &encoded);
        }
    }

    async fn ensure_thread_space(&self, thread_id: &str) -> labyrinth::Result<()> {
        if self
            .resolved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(thread_id)
        {
            return Ok(());
        }
        let pins = self.load_pins()?;
        if let Some(pin) = pins.get(thread_id) {
            pin.validate()?;
            if let Some(ref uri) = pin.space {
                let parsed = labyrinth::store::space::SpaceRef::parse(uri)?;
                self.set_thread_space(thread_id, parsed);
                return Ok(());
            }
        }
        if let Some(transport) = &self.transport {
            let body = transport
                .query(
                    "blue.catbird.chat.getConversationState",
                    &[("conversationId", thread_id.to_owned())],
                )
                .await
                .map_err(super::transport::map_xrpc_error)?;
            let parsed: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|_| labyrinth::Error::Malformed("getConversationState JSON"))?;
            let generation = parsed["state"]["coordinates"]["generation"]
                .as_u64()
                .unwrap_or(0);
            let space_ref = if let Some(explicit_uri) = parsed["state"]["conversationSpace"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                labyrinth::store::space::SpaceRef::parse(explicit_uri)?
            } else {
                let raw_ds = parsed["state"]["sequencerDid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(labyrinth::Error::Malformed(
                        "conversation sequencerDid is missing",
                    ))?;
                let authority = raw_ds
                    .split('#')
                    .next()
                    .unwrap_or(raw_ds)
                    .trim_end_matches('/');
                labyrinth::store::space::SpaceRef::conversation(
                    authority,
                    &format!("{thread_id}-{generation}"),
                )
            };
            self.save_pin(thread_id, &space_ref, generation);
            self.set_thread_space(thread_id, space_ref);
        }
        Ok(())
    }

    /// Lists conversation Space URIs owned/participated in according to `com.atproto.space.listSpaces`.
    pub async fn owned_conversation_spaces(
        space_rpc: &dyn SpaceRpc,
    ) -> labyrinth::Result<Vec<String>> {
        // Name the type: the session's grant covers conversation Spaces, not every type,
        // and a PDS refuses an unfiltered listing under such a grant.
        let body = space_rpc
            .query(
                "com.atproto.space.listSpaces",
                &[(
                    "spaceType",
                    labyrinth::store::space::CONVERSATION_SPACE_TYPE.to_owned(),
                )],
            )
            .await
            .map_err(labyrinth::store::space::map_space_error)?;
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| labyrinth::Error::Malformed("listSpaces JSON"))?;
        let entries = parsed["spaces"]
            .as_array()
            .ok_or(labyrinth::Error::Malformed("listSpaces spaces missing"))?;
        let mut out = Vec::new();
        for entry in entries {
            let uri = entry
                .as_str()
                .or_else(|| entry["uri"].as_str())
                .or_else(|| entry["space"].as_str());
            if let Some(u) = uri {
                if let Ok(parsed) = atproto_spaces::SpaceUri::parse_hedged(u) {
                    if parsed.space_type == "blue.catbird.labyrinth.conversation" {
                        out.push(parsed.to_string());
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Purges all records authored by `did` inside `space_uri` (`Gate 5`).
    pub async fn purge_owned_records(
        did: &str,
        space_rpc: Arc<dyn SpaceRpc>,
        space_uri: &str,
    ) -> labyrinth::Result<()> {
        use labyrinth::store::ThreadStore as _;
        let space_ref = labyrinth::store::space::SpaceRef::parse(space_uri)?;
        let store = labyrinth::store::space::SpaceThreadStore::new(space_rpc, did);
        store.set_thread_space("__purge__", space_ref);
        store.clear_records("__purge__").await
    }

    /// Resolves and returns the canonical conversation Space URI for `thread_id`.
    pub async fn resolved_space_uri(&self, thread_id: &str) -> labyrinth::Result<String> {
        self.ensure_thread_space(thread_id).await?;
        let pins = self.load_pins()?;
        if let Some(pin) = pins.get(thread_id) {
            pin.validate()?;
            if let Some(ref uri) = pin.space {
                return Ok(uri.clone());
            }
        }
        Err(labyrinth::Error::NotFound("space"))
    }

    /// Uploads encrypted attachment ciphertext into the conversation Space and
    /// commits its `attachmentManifest` record, returning `(space_uri, cid, rkey)`.
    pub async fn upload_conversation_attachment_blob(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> labyrinth::Result<(String, String, String)> {
        use labyrinth::store::ThreadStore as _;
        let space_uri = self.resolved_space_uri(thread_id).await?;
        let rkey = self
            .inner
            .upload_and_commit_attachment(thread_id, ciphertext, meta, created_at)
            .await?;
        let manifest = self
            .inner
            .get_attachment_manifest(thread_id, self.inner.author(), &rkey)
            .await?
            .ok_or(labyrinth::Error::NotFound("attachmentManifest"))?;
        let (cid, _) = manifest.to_meta()?;
        Ok((space_uri, cid, rkey))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl labyrinth::store::ThreadStore for ResolvingSpaceThreadStore {
    fn author(&self) -> &str {
        self.inner.author()
    }

    async fn create_mek(&self, mek: &labyrinth::records::MekDistribution) -> labyrinth::Result<()> {
        self.ensure_thread_space(&mek.thread_id).await?;
        self.inner.create_mek(mek).await
    }

    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::MekDistribution>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner.find_meks(thread_id, mek_id).await
    }

    fn supports_author_mek_fast_path(&self) -> bool {
        self.inner.supports_author_mek_fast_path()
    }

    async fn find_mek_from_author(
        &self,
        thread_id: &str,
        author_did: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Option<Stored<labyrinth::records::MekDistribution>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .find_mek_from_author(thread_id, author_did, mek_id)
            .await
    }

    async fn find_meks_excluding_author(
        &self,
        thread_id: &str,
        excluded_author: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::MekDistribution>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .find_meks_excluding_author(thread_id, excluded_author, mek_id)
            .await
    }

    async fn find_meks_with_hint(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
        preferred_author: Option<&str>,
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::MekDistribution>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .find_meks_with_hint(thread_id, mek_id, preferred_author)
            .await
    }

    async fn append_batch(&self, batch: &labyrinth::records::Batch) -> labyrinth::Result<String> {
        self.ensure_thread_space(&batch.thread_id).await?;
        self.inner.append_batch(batch).await
    }

    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::Batch>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner.list_batches(thread_id, sender, range).await
    }

    async fn list_batches_quarantined(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<(
        Vec<Stored<labyrinth::records::Batch>>,
        Vec<AuthorQuarantine>,
    )> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .list_batches_quarantined(thread_id, sender, range)
            .await
    }

    async fn get_messages(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::Batch>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner.get_messages(thread_id, message_ids).await
    }

    async fn get_messages_quarantined(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> labyrinth::Result<(
        Vec<Stored<labyrinth::records::Batch>>,
        Vec<AuthorQuarantine>,
    )> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .get_messages_quarantined(thread_id, message_ids)
            .await
    }

    async fn list_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::Batch>>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .list_batches_before(thread_id, before_ms, limit)
            .await
    }

    async fn list_batches_before_quarantined(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> labyrinth::Result<(
        Vec<Stored<labyrinth::records::Batch>>,
        Vec<AuthorQuarantine>,
    )> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .list_batches_before_quarantined(thread_id, before_ms, limit)
            .await
    }

    async fn list_threads(&self) -> labyrinth::Result<Vec<String>> {
        let mut set: std::collections::BTreeSet<String> =
            self.inner.list_threads().await?.into_iter().collect();
        for key in self.load_pins()?.into_keys() {
            set.insert(key);
        }
        Ok(set.into_iter().collect())
    }

    async fn list_threads_report(&self) -> labyrinth::Result<ThreadListing> {
        let mut report = self.inner.list_threads_report().await?;
        let mut set: std::collections::BTreeSet<String> = report.threads.into_iter().collect();
        for key in self.load_pins()?.into_keys() {
            set.insert(key);
        }
        report.threads = set.into_iter().collect();
        Ok(report)
    }

    async fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &labyrinth::deletion::Redaction,
    ) -> labyrinth::Result<usize> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .redact_item(thread_id, message_id, redaction)
            .await
    }

    async fn upload_and_commit_attachment(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> labyrinth::Result<String> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .upload_and_commit_attachment(thread_id, ciphertext, meta, created_at)
            .await
    }

    async fn get_attachment_manifest(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<labyrinth::records::AttachmentManifest>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .get_attachment_manifest(thread_id, author_did, rkey)
            .await
    }

    async fn get_attachment_verified(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Vec<u8>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner
            .get_attachment_verified(thread_id, author_did, rkey)
            .await
    }

    async fn list_own_attachment_manifests(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Vec<(String, labyrinth::records::AttachmentManifest)>> {
        self.ensure_thread_space(thread_id).await?;
        self.inner.list_own_attachment_manifests(thread_id).await
    }

    async fn clear_records(&self, thread_id: &str) -> labyrinth::Result<()> {
        self.ensure_thread_space(thread_id).await?;
        self.inner.clear_records(thread_id).await
    }

    fn seed_writer_rev_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), String>,
    ) {
        self.inner.seed_writer_rev_floors(floors);
    }

    fn replace_writer_rev_floors(
        &self,
        floors: &std::collections::BTreeMap<(String, String), String>,
    ) {
        self.inner.replace_writer_rev_floors(floors);
    }

    fn export_writer_rev_floors(&self) -> std::collections::BTreeMap<(String, String), String> {
        self.inner.export_writer_rev_floors()
    }
}
