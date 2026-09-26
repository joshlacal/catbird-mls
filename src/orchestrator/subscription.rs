//! Canonical subscription ticket and event frame processing.
//!
//! Provides:
//! - Exact authenticated inventory sync under one inventory session -> `AppliedInventoryFence`
//! - Subscription ticket preparation via `blue.catbird.chat.getSubscriptionTicket`
//! - Event frame decode, CAS cursor persistence, and message/state dispatch

use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    api_client::MLSAPIClient,
    authenticated_inventory::{AppliedInventoryFence, AuthenticatedInventorySnapshot},
    canonical_transport::{CanonicalOperation, PreparedRequest},
    credentials::CredentialStore,
    error::{OrchestratorError, Result},
    mls_provider::MlsCryptoContext,
    orchestrator::MLSOrchestrator,
    storage::MLSStorageBackend,
    types::Message,
};
use crate::error::MLSError;

pub const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PAGES: usize = 100;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

fn invalid(message: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Api(format!("Subscription: {message}"))
}

fn invalid_err(e: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Serialization(e.to_string())
}

fn storage_err(e: MLSError) -> OrchestratorError {
    OrchestratorError::Storage(e.to_string())
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fresh(value: &str) -> Result<()> {
    let expiry = chrono::DateTime::parse_from_rfc3339(value).map_err(invalid)?;
    if expiry <= chrono::Utc::now() {
        return Err(invalid("snapshot expired"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub supported_protocol_versions: Vec<String>,
    #[serde(deserialize_with = "scope_digest")]
    pub scope_digest: String,
}

fn scope_digest<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bytes {
        #[serde(rename = "$bytes")]
        bytes: String,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Text(String),
        Bytes(Bytes),
    }
    Ok(match Wire::deserialize(deserializer)? {
        Wire::Text(value) => value,
        Wire::Bytes(value) => value.bytes,
    })
}

impl Scope {
    pub fn validate(&self) -> Result<()> {
        let bytes = STANDARD.decode(&self.scope_digest).map_err(invalid)?;
        if self.supported_protocol_versions != ["1", "2"]
            || bytes.len() != 32
            || STANDARD.encode(&bytes) != self.scope_digest
        {
            return Err(invalid("missing or changed protocol scope"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Page {
    pub items: Vec<serde_json::Value>,
    pub inventory_session_id: String,
    pub snapshot_event_cursor: String,
    pub snapshot_expires_at: String,
    pub has_more: bool,
    pub next_page_cursor: Option<String>,
    pub inventory_scope: Scope,
}

#[derive(Default)]
pub(crate) struct Traversal {
    cursors: HashSet<String>,
    pages: usize,
    total_bytes: usize,
}

impl Traversal {
    pub(crate) fn observe(
        &mut self,
        raw: &[u8],
        expected: Option<(&str, &str, &str, &str)>,
    ) -> Result<Page> {
        if raw.is_empty() || raw.len() > MAX_PAGE_BYTES {
            return Err(invalid("page byte bound"));
        }
        let page: Page = serde_json::from_slice(raw).map_err(invalid)?;
        page.inventory_scope.validate()?;
        if !(32..=512).contains(&page.inventory_session_id.len())
            || page.snapshot_event_cursor.is_empty()
            || page.snapshot_event_cursor.len() > 512
            || page.items.len() > 100
        {
            return Err(invalid("invalid page envelope"));
        }
        fresh(&page.snapshot_expires_at)?;
        if let Some((session, cursor, expiry, scope)) = expected {
            if (
                page.inventory_session_id.as_str(),
                page.snapshot_event_cursor.as_str(),
                page.snapshot_expires_at.as_str(),
                page.inventory_scope.scope_digest.as_str(),
            ) != (session, cursor, expiry, scope)
            {
                return Err(invalid("session, event cursor, expiry or scope changed"));
            }
        }
        self.pages += 1;
        self.total_bytes += raw.len();
        if self.pages > MAX_PAGES || self.total_bytes > MAX_TOTAL_BYTES {
            return Err(invalid("pagination bound"));
        }
        match (page.has_more, page.next_page_cursor.as_deref()) {
            (false, None) => {}
            (true, Some(cursor))
                if !cursor.is_empty()
                    && cursor.len() <= 512
                    && self.pages < MAX_PAGES
                    && self.cursors.insert(cursor.to_owned()) => {}
            _ => return Err(invalid("inconsistent or repeated pagination cursor")),
        }
        Ok(page)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
    id: String,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    owner: String,
    actor: String,
    auth_generation: i64,
    attempt: String,
    session: String,
    cursor: String,
    expires_at: String,
    scope: String,
    conversations: Vec<PageRef>,
    welcomes: Vec<PageRef>,
    recovery: Vec<PageRef>,
    snapshot_sha256: String,
    applied_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionTicket {
    pub endpoint: String,
    pub ticket: String,
    pub inventory_session_id: String,
    pub event_cursor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CursorFence {
    pub owner: String,
    pub actor: String,
    pub generation: i64,
    pub session: String,
    pub connection: String,
    pub cursor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubscriptionDispatchOutcome {
    Typing {
        conversation_id: String,
        sender_did: String,
        is_typing: bool,
    },
    MessageAvailable {
        conversation_id: String,
        target_seq: u64,
        messages: Vec<Message>,
        cursor: String,
    },
    Watermark {
        issued_at: String,
        cursor: String,
    },
    AccessEnded {
        user_did: String,
        device_id: String,
        cursor: String,
    },
    OtherEvent {
        event_type: String,
        conversation_id: Option<String>,
        cursor: String,
    },
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_value_read(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
    id: &str,
) -> std::result::Result<Option<Vec<u8>>, MLSError> {
    use rusqlite::OptionalExtension;
    checked_namespace(namespace)?;
    checked_id(id)?;
    let key = format!("direct_request_value_v2:{namespace}:{id}");
    storage
        .welcome_ack_connection()
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| MLSError::StorageFailed)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_value_cas(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
    id: &str,
    expected: Option<&[u8]>,
    next: &[u8],
) -> std::result::Result<bool, MLSError> {
    use rusqlite::OptionalExtension;
    checked_namespace(namespace)?;
    checked_id(id)?;
    if next.is_empty() || next.len() > 16 * 1024 * 1024 {
        return Err(MLSError::invalid_input("Request value exceeds storage bound"));
    }
    let key = format!("direct_request_value_v2:{namespace}:{id}");
    let tx = storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(|_| MLSError::StorageFailed)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| MLSError::StorageFailed)?;
    if old.as_deref() != expected {
        return Ok(false);
    }
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES(?1,?2)",
        rusqlite::params![key, next],
    )
    .map_err(|_| MLSError::StorageFailed)?;
    tx.commit().map_err(|_| MLSError::StorageFailed)?;
    storage.flush_database()?;
    Ok(true)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_values_list(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
) -> std::result::Result<Vec<Vec<u8>>, MLSError> {
    checked_namespace(namespace)?;
    let pattern = format!("direct_request_value_v2:{namespace}:%");
    let mut query = storage
        .welcome_ack_connection()
        .prepare("SELECT CAST(value AS BLOB) FROM mls_manifests WHERE key LIKE ?1 ORDER BY key")
        .map_err(|_| MLSError::StorageFailed)?;
    let rows = query
        .query_map([&pattern], |r| r.get::<_, Vec<u8>>(0))
        .map_err(|_| MLSError::StorageFailed)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| MLSError::StorageFailed)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn request_values_total_bytes(
    storage: &crate::mls_context::ManifestStorage,
    namespace: &str,
) -> std::result::Result<u64, MLSError> {
    checked_namespace(namespace)?;
    let pattern = format!("direct_request_value_v2:{namespace}:%");
    let total: i64 = storage
        .welcome_ack_connection()
        .query_row(
            "SELECT COALESCE(SUM(length(value)),0) FROM mls_manifests WHERE key LIKE ?1",
            [&pattern],
            |r| r.get(0),
        )
        .map_err(|_| MLSError::StorageFailed)?;
    Ok(total.max(0) as u64)
}

pub(crate) fn checked_id(id: &str) -> std::result::Result<(), MLSError> {
    if id.is_empty() || id.len() > 512 {
        return Err(MLSError::invalid_input("Invalid request value identifier"));
    }
    Ok(())
}

pub(crate) fn checked_namespace(namespace: &str) -> std::result::Result<(), MLSError> {
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(MLSError::invalid_input("Invalid request value namespace"));
    }
    Ok(())
}

fn store_pages<M: MlsCryptoContext + ?Sized>(
    ctx: &M,
    namespace: &str,
    pages: &[Vec<u8>],
) -> Result<Vec<PageRef>> {
    pages
        .iter()
        .map(|raw| {
            let sha256 = digest_hex(raw);
            let hash = Sha256::digest(raw);
            let mut locator = [0u8; 16];
            locator.copy_from_slice(&hash[..16]);
            locator[6] = (locator[6] & 0x0f) | 0x40;
            locator[8] = (locator[8] & 0x3f) | 0x80;
            let id = uuid::Uuid::from_bytes(locator).to_string();
            if let Some(existing) = ctx.read_request_value(namespace, &id).map_err(storage_err)? {
                if existing != *raw {
                    return Err(invalid("page locator collision"));
                }
            } else {
                if ctx
                    .request_values_total_bytes(namespace)
                    .map_err(storage_err)?
                    .saturating_add(raw.len() as u64)
                    > 256 * 1024 * 1024
                {
                    return Err(invalid("protected inventory retention quota reached"));
                }
                if !ctx
                    .compare_exchange_request_value(namespace, &id, None, raw)
                    .map_err(storage_err)?
                {
                    return Err(invalid("page custody conflict"));
                }
            }
            Ok(PageRef { id, sha256 })
        })
        .collect()
}

fn load_pages<M: MlsCryptoContext + ?Sized>(
    ctx: &M,
    namespace: &str,
    refs: &[PageRef],
    total: &mut usize,
) -> Result<Vec<Vec<u8>>> {
    if refs.is_empty() || refs.len() > MAX_PAGES {
        return Err(invalid("invalid retained page count"));
    }
    refs.iter()
        .map(|reference| {
            let raw = ctx
                .read_request_value(namespace, &reference.id)
                .map_err(storage_err)?
                .ok_or_else(|| invalid("retained page missing"))?;
            *total += raw.len();
            if raw.len() > MAX_PAGE_BYTES
                || *total > MAX_TOTAL_BYTES
                || digest_hex(&raw) != reference.sha256
            {
                return Err(invalid("retained page binding"));
            }
            Ok(raw)
        })
        .collect()
}

fn restore<M: MlsCryptoContext + ?Sized>(
    ctx: &M,
    namespace: &str,
    journal: &Journal,
) -> Result<AuthenticatedInventorySnapshot> {
    let mut total = 0;
    let snapshot = AuthenticatedInventorySnapshot {
        owner_did: journal.owner.clone(),
        actor_device_id: journal.actor.clone(),
        auth_generation: journal.auth_generation,
        inventory_session_id: journal.session.clone(),
        event_cursor: journal.cursor.clone(),
        expires_at: journal.expires_at.clone(),
        scope_digest: journal.scope.clone(),
        conversation_pages: load_pages(ctx, namespace, &journal.conversations, &mut total)?,
        welcome_pages: load_pages(ctx, namespace, &journal.welcomes, &mut total)?,
        recovery_pages: load_pages(ctx, namespace, &journal.recovery, &mut total)?,
    };
    if snapshot_hash(&snapshot)? != journal.snapshot_sha256 {
        return Err(invalid("retained snapshot binding"));
    }
    Ok(snapshot)
}

fn snapshot_hash(snapshot: &AuthenticatedInventorySnapshot) -> Result<String> {
    Ok(hex::encode(snapshot.digest()?))
}

fn query(
    operation: CanonicalOperation,
    actor: &str,
    session: Option<&str>,
    cursor: Option<&str>,
) -> PreparedRequest {
    let nsid = match operation {
        CanonicalOperation::GetConversations => "getConversations",
        CanonicalOperation::GetPendingWelcomes => "getPendingWelcomes",
        _ => "getLeafRecoveryInbox",
    };
    let mut path = format!("/xrpc/blue.catbird.chat.{nsid}?actorDeviceId=");
    push_query_value(&mut path, actor);
    path.push_str("&limit=100&supportedProtocolVersions=1&supportedProtocolVersions=2");
    if let Some(session) = session {
        path.push_str("&inventorySessionId=");
        push_query_value(&mut path, session);
    }
    if let Some(cursor) = cursor {
        path.push_str("&pageCursor=");
        push_query_value(&mut path, cursor);
    }
    PreparedRequest {
        operation,
        method: "GET".into(),
        path,
        body: None,
    }
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
fn push_query_value(out: &mut String, value: &str) {
    use std::fmt::Write as _;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

/// The only admitted subscription endpoint: the production service on its
/// default port, with no userinfo, query, or fragment.
fn validate_endpoint(endpoint: &str) -> Result<()> {
    const PATH: &str = "/xrpc/blue.catbird.chat.subscribeEvents";
    let authority = endpoint
        .strip_prefix("wss://")
        .and_then(|rest| rest.strip_suffix(PATH))
        .ok_or_else(|| invalid("Endpoint must be wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents"))?;
    if !matches!(authority, "chat.catbird.blue" | "chat.catbird.blue:443") {
        return Err(invalid(format!("Invalid endpoint authority: {authority}")));
    }
    Ok(())
}

/// Decode one `subscriptionMessage` frame under the strict canonical schema:
/// duplicate keys, unknown fields, and unknown union variants are rejected
/// before any state or cursor is touched.
pub fn decode_subscription_frame(raw: &str) -> Result<serde_json::Value> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(invalid("Subscription frame exceeds bound"));
    }
    super::canonical_transport::validate_read_shape("subscriptionMessage", raw.as_bytes())
        .map_err(invalid)
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    async fn verify_actor_identity(&self, owner: &str, actor: &str, generation: i64) -> Result<()> {
        self.check_shutdown().await?;
        if self.require_user_did().await? != owner
            || self.require_actor_device_id().await? != actor
            || !self.api_client().is_authenticated_as(owner).await
            || self.credentials().get_auth_generation(owner).await? != Some(generation)
            || generation <= 0
        {
            return Err(invalid("authenticated actor changed"));
        }
        Ok(())
    }

    async fn fetch_scoped_inventory(
        &self,
        owner: &str,
        actor: &str,
        generation: i64,
    ) -> Result<AuthenticatedInventorySnapshot> {
        let mut snapshot = AuthenticatedInventorySnapshot {
            owner_did: owner.into(),
            actor_device_id: actor.into(),
            auth_generation: generation,
            inventory_session_id: String::new(),
            event_cursor: String::new(),
            expires_at: String::new(),
            scope_digest: String::new(),
            conversation_pages: vec![],
            welcome_pages: vec![],
            recovery_pages: vec![],
        };
        let mut total = 0usize;
        for operation in [
            CanonicalOperation::GetConversations,
            CanonicalOperation::GetPendingWelcomes,
            CanonicalOperation::GetLeafRecoveryInbox,
        ] {
            let mut traversal = Traversal::default();
            let mut cursor = None;
            loop {
                self.verify_actor_identity(owner, actor, generation).await?;
                let session = (operation != CanonicalOperation::GetConversations)
                    .then_some(snapshot.inventory_session_id.as_str());
                let response = self
                    .api_client()
                    .submit_prepared_request(query(operation, actor, session, cursor.as_deref()))
                    .await?;
                self.verify_actor_identity(owner, actor, generation).await?;
                if response.status != 200 {
                    return Err(invalid(format!("inventory HTTP {}", response.status)));
                }
                total = total
                    .checked_add(response.body.len())
                    .ok_or_else(|| invalid("byte overflow"))?;
                if total > MAX_TOTAL_BYTES {
                    return Err(invalid("total byte bound"));
                }
                let expected = (!snapshot.inventory_session_id.is_empty()).then_some((
                    snapshot.inventory_session_id.as_str(),
                    snapshot.event_cursor.as_str(),
                    snapshot.expires_at.as_str(),
                    snapshot.scope_digest.as_str(),
                ));
                super::canonical_transport::validate_authenticated_inventory_page(
                    operation,
                    &response.body,
                )
                .map_err(invalid)?;
                let page = traversal.observe(&response.body, expected)?;
                if snapshot.inventory_session_id.is_empty() {
                    snapshot.inventory_session_id = page.inventory_session_id;
                    snapshot.event_cursor = page.snapshot_event_cursor;
                    snapshot.expires_at = page.snapshot_expires_at;
                    snapshot.scope_digest = page.inventory_scope.scope_digest;
                }
                cursor = page.next_page_cursor;
                match operation {
                    CanonicalOperation::GetConversations => {
                        snapshot.conversation_pages.push(response.body)
                    }
                    CanonicalOperation::GetPendingWelcomes => {
                        snapshot.welcome_pages.push(response.body)
                    }
                    _ => snapshot.recovery_pages.push(response.body),
                }
                if !page.has_more {
                    break;
                }
            }
        }
        Ok(snapshot)
    }

    async fn synchronize_inventory_internal(
        &self,
        force_fresh: bool,
    ) -> Result<(
        AuthenticatedInventorySnapshot,
        AppliedInventoryFence,
        Vec<u8>,
    )> {
        let owner = self.require_user_did().await?;
        let actor = self.require_actor_device_id().await?;
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(|| invalid("actor generation unavailable"))?;
        self.verify_actor_identity(&owner, &actor, generation).await?;

        let namespace = format!("inventory:{owner}");
        let pages_namespace = format!("inventoryPages:{owner}");
        let old = self
            .mls_context()
            .read_request_value(&namespace, &actor)
            .map_err(storage_err)?;
        let prior = old
            .as_deref()
            .map(serde_json::from_slice::<Journal>)
            .transpose()
            .map_err(invalid_err)?;

        let snapshot = if let Some(journal) = prior.as_ref().filter(|j| {
            !force_fresh
                && j.owner == owner
                && j.actor == actor
                && j.auth_generation == generation
                && fresh(&j.expires_at).is_ok()
        }) {
            restore(self.mls_context().as_ref(), &pages_namespace, journal)?
        } else {
            self.fetch_scoped_inventory(&owner, &actor, generation).await?
        };

        self.verify_actor_identity(&owner, &actor, generation).await?;
        fresh(&snapshot.expires_at)?;

        let mut journal = Journal {
            owner: owner.clone(),
            actor: actor.clone(),
            auth_generation: generation,
            attempt: uuid::Uuid::new_v4().to_string(),
            session: snapshot.inventory_session_id.clone(),
            cursor: snapshot.event_cursor.clone(),
            expires_at: snapshot.expires_at.clone(),
            scope: snapshot.scope_digest.clone(),
            conversations: store_pages(
                self.mls_context().as_ref(),
                &pages_namespace,
                &snapshot.conversation_pages,
            )?,
            welcomes: store_pages(
                self.mls_context().as_ref(),
                &pages_namespace,
                &snapshot.welcome_pages,
            )?,
            recovery: store_pages(
                self.mls_context().as_ref(),
                &pages_namespace,
                &snapshot.recovery_pages,
            )?,
            snapshot_sha256: snapshot_hash(&snapshot)?,
            applied_digest: None,
        };

        let prepared = serde_json::to_vec(&journal).map_err(invalid_err)?;
        if !self
            .mls_context()
            .compare_exchange_request_value(&namespace, &actor, old.as_deref(), &prepared)
            .map_err(storage_err)?
        {
            return Err(invalid("concurrent inventory replaced this attempt"));
        }

        let applied = self
            .ingest_authenticated_inventory_snapshot(&snapshot)
            .await?;

        self.verify_actor_identity(&owner, &actor, generation).await?;
        fresh(&snapshot.expires_at)?;
        if !applied.matches_snapshot(&snapshot) {
            return Err(invalid("shared completion does not match exact snapshot"));
        }

        journal.applied_digest = Some(hex::encode(applied.snapshot_digest()));
        let completed = serde_json::to_vec(&journal).map_err(invalid_err)?;
        if !self
            .mls_context()
            .compare_exchange_request_value(&namespace, &actor, Some(&prepared), &completed)
            .map_err(storage_err)?
        {
            return Err(invalid("inventory completion superseded"));
        }

        Ok((snapshot, applied, completed))
    }

    /// Synchronize the three authenticated inventory domains under one session
    /// and ingest them via `ingest_authenticated_inventory_snapshot`.
    pub async fn synchronize_authenticated_inventory(
        &self,
        force_fresh: bool,
    ) -> Result<AppliedInventoryFence> {
        Ok(self.synchronize_inventory_internal(force_fresh).await?.1)
    }

    /// Prepare a subscription ticket using explicit identity parameters. The
    /// ticket's inventory scope must equal the snapshot's `inventory_scope_digest`.
    pub async fn prepare_subscription_ticket(
        &self,
        actor_device_id: &str,
        inventory_session_id: &str,
        event_cursor: &str,
        inventory_scope_digest: &str,
    ) -> Result<SubscriptionTicket> {
        self.check_shutdown().await?;
        let owner = self.require_user_did().await?;
        let current_actor = self.require_actor_device_id().await?;
        if current_actor != actor_device_id {
            return Err(invalid("actor device ID mismatch"));
        }
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(|| invalid("actor generation unavailable"))?;
        self.verify_actor_identity(&owner, actor_device_id, generation).await?;

        let body = serde_json::to_vec(&serde_json::json!({
            "actorDeviceId": actor_device_id,
            "inventorySessionId": inventory_session_id,
            "eventCursor": event_cursor,
            "supportedProtocolVersions": ["1", "2"]
        }))
        .map_err(invalid_err)?;

        let response = self
            .api_client()
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::GetSubscriptionTicket,
                method: "POST".into(),
                path: "/xrpc/blue.catbird.chat.getSubscriptionTicket".into(),
                body: Some(body),
            })
            .await?;

        self.verify_actor_identity(&owner, actor_device_id, generation).await?;
        if response.status != 200 {
            // A rejected ticket names its protocol error only in the body.
            let reason = String::from_utf8_lossy(&response.body[..response.body.len().min(256)]).into_owned();
            return Err(OrchestratorError::Api(format!("ticket HTTP {}: {reason}", response.status)));
        }

        if response.body.len() > 16384 {
            return Err(OrchestratorError::Api("ticket response bound".into()));
        }

        crate::chat_v2::transcript::decode_strict_json(&response.body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawTicket {
            ticket: String,
            endpoint: String,
            expires_at: String,
            inventory_scope: Scope,
        }

        let ticket: RawTicket = serde_json::from_slice(&response.body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        ticket.inventory_scope.validate()?;
        if ticket.inventory_scope.scope_digest != inventory_scope_digest {
            return Err(invalid("ticket inventory scope does not match snapshot"));
        }
        fresh(&ticket.expires_at)?;

        validate_endpoint(&ticket.endpoint)?;

        if !(32..=4096).contains(&ticket.ticket.len()) {
            return Err(OrchestratorError::Api("ticket token length invalid".into()));
        }

        Ok(SubscriptionTicket {
            endpoint: ticket.endpoint,
            ticket: ticket.ticket,
            inventory_session_id: inventory_session_id.to_string(),
            event_cursor: event_cursor.to_string(),
        })
    }

    /// Synchronize a fresh inventory and prepare its subscription ticket in one step.
    ///
    /// Every (re)connect mints from a freshly fetched and applied inventory: the server keeps
    /// one inventory session per device and replaces its capability once newer events exist,
    /// so a session restored from an earlier journal (e.g. the previous launch's) is refused
    /// with InventorySessionMismatch.
    pub async fn prepare_subscription(&self) -> Result<SubscriptionTicket> {
        let (snapshot, _applied, completed) = self.synchronize_inventory_internal(true).await?;
        let actor = self.require_actor_device_id().await?;
        let owner = self.require_user_did().await?;
        let namespace = format!("inventory:{owner}");

        let ticket = self
            .prepare_subscription_ticket(
                &actor,
                &snapshot.inventory_session_id,
                &snapshot.event_cursor,
                &snapshot.scope_digest,
            )
            .await?;

        if self
            .mls_context()
            .read_request_value(&namespace, &actor)
            .map_err(storage_err)?
            .as_deref()
            != Some(&completed)
        {
            return Err(invalid("ticket attempt superseded"));
        }

        Ok(ticket)
    }

    /// Initialize the durable subscription cursor in storage before WebSocket connect.
    pub async fn initialize_subscription_cursor(
        &self,
        ticket: &SubscriptionTicket,
    ) -> Result<CursorFence> {
        self.check_shutdown().await?;
        let owner = self.require_user_did().await?;
        let actor = self.require_actor_device_id().await?;
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(|| invalid("actor generation unavailable"))?;

        let previous = self
            .mls_context()
            .read_request_value("subscriptionCursor", &actor)
            .map_err(storage_err)?;

        let fence = CursorFence {
            owner: owner.clone(),
            actor: actor.clone(),
            generation,
            session: ticket.inventory_session_id.clone(),
            connection: uuid::Uuid::new_v4().to_string(),
            cursor: ticket.event_cursor.clone(),
        };

        let encoded = serde_json::to_vec(&fence).map_err(invalid_err)?;
        if !self
            .mls_context()
            .compare_exchange_request_value("subscriptionCursor", &actor, previous.as_deref(), &encoded)
            .map_err(storage_err)?
        {
            return Err(OrchestratorError::Api("Concurrent subscription installation".into()));
        }

        Ok(fence)
    }

    /// Read the currently durable subscription cursor fence, if any.
    pub async fn current_subscription_cursor(&self) -> Result<Option<CursorFence>> {
        let actor = self.require_actor_device_id().await?;
        let raw = self
            .mls_context()
            .read_request_value("subscriptionCursor", &actor)
            .map_err(storage_err)?;
        raw.as_deref()
            .map(serde_json::from_slice::<CursorFence>)
            .transpose()
            .map_err(invalid_err)
    }

    async fn messages_through(&self, cid: &str, target: u64) -> Result<Vec<Message>> {
        let previous = self
            .mls_context()
            .read_request_value("entryCursor", cid)
            .map_err(storage_err)?;
        let mut cursor = previous
            .as_deref()
            .map(|raw| serde_json::from_slice::<u64>(raw).map_err(invalid_err))
            .transpose()?
            .unwrap_or(0);
        let mut exact = previous;
        let mut output = Vec::new();
        for _ in 0..100 {
            if cursor >= target {
                return Ok(output);
            }
            let (messages, next) = self
                .fetch_messages(cid, Some(&cursor.to_string()), 100, None, None, None)
                .await?;
            let next_str = next.ok_or_else(|| {
                OrchestratorError::Api("Message hint not present in verified entries".into())
            })?;
            let next_u64 = next_str.parse::<u64>().map_err(invalid_err)?;
            if next_u64 <= cursor {
                return Err(OrchestratorError::Api("Message cursor did not advance".into()));
            }
            self.mls_context().ensure_storage_durable().map_err(storage_err)?;
            let raw = serde_json::to_vec(&next_u64).map_err(invalid_err)?;
            if !self
                .mls_context()
                .compare_exchange_request_value("entryCursor", cid, exact.as_deref(), &raw)
                .map_err(storage_err)?
            {
                return Err(OrchestratorError::Api("Entry progress changed concurrently".into()));
            }
            exact = Some(raw);
            cursor = next_u64;
            output.extend(messages.into_iter().filter(|m| m.has_displayable_body()));
        }
        Err(OrchestratorError::Api("Message catch-up exceeded page bound".into()))
    }

    /// Decode a canonical subscribeEvents frame, enforce CAS cursor chain persistence,
    /// reconcile local conversation state/messages, and return the dispatch outcome.
    pub async fn apply_subscription_frame(&self, raw: &str) -> Result<SubscriptionDispatchOutcome> {
        self.check_shutdown().await?;
        let owner = self.require_user_did().await?;
        let actor = self.require_actor_device_id().await?;
        let generation = self
            .credentials()
            .get_auth_generation(&owner)
            .await?
            .ok_or_else(|| invalid("actor generation unavailable"))?;

        let retained = self
            .mls_context()
            .read_request_value("subscriptionCursor", &actor)
            .map_err(storage_err)?
            .ok_or_else(|| OrchestratorError::Api("Subscription cursor missing".into()))?;

        let fence: CursorFence = serde_json::from_slice(&retained).map_err(invalid_err)?;
        if fence.owner != owner || fence.actor != actor || fence.generation != generation {
            return Err(OrchestratorError::Api("Subscription device authority changed".into()));
        }

        let value = decode_subscription_frame(raw)?;

        // The strict decode guarantees every required typingEvent field.
        if value["$type"] == "blue.catbird.chat.defs#typingEvent" {
            return Ok(SubscriptionDispatchOutcome::Typing {
                conversation_id: value["conversationId"].as_str().unwrap_or_default().to_string(),
                sender_did: value["actorDid"].as_str().unwrap_or_default().to_string(),
                is_typing: value["isTyping"] == true,
            });
        }

        let previous_cursor = value
            .get("previousCursor")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid("Missing event previousCursor"))?;
        let next_cursor = value
            .get("cursor")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid("Missing event cursor"))?;

        if previous_cursor != fence.cursor || next_cursor == fence.cursor || next_cursor.is_empty() {
            return Err(OrchestratorError::Api("Subscription cursor chain changed".into()));
        }

        let payload = value
            .get("payload")
            .ok_or_else(|| invalid("Missing event payload"))?;
        let kind = payload
            .get("$type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid("Missing event payload type"))?;

        let outcome = if kind == "blue.catbird.chat.defs#messageAvailableEvent" {
            let cid = payload
                .get("conversationId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("Missing conversation"))?;
            if !self.conversations().lock().await.contains_key(cid) {
                self.synchronize_authenticated_inventory(true).await?;
            }
            let target = payload
                .get("seq")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| invalid("Missing entry sequence"))?;
            let messages = self.messages_through(cid, target).await?;
            SubscriptionDispatchOutcome::MessageAvailable {
                conversation_id: cid.to_string(),
                target_seq: target,
                messages,
                cursor: next_cursor.to_string(),
            }
        } else if kind == "blue.catbird.chat.defs#watermarkEvent" {
            let issued_at = payload
                .get("issuedAt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            SubscriptionDispatchOutcome::Watermark {
                issued_at,
                cursor: next_cursor.to_string(),
            }
        } else if kind == "blue.catbird.chat.defs#accessEndedEvent" {
            let user_did = payload.get("userDid").and_then(|v| v.as_str()).unwrap_or("");
            let device_id = payload.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
            if user_did != owner || device_id != actor {
                return Err(OrchestratorError::Api("Foreign access-ended audience".into()));
            }
            self.synchronize_authenticated_inventory(true).await?;
            SubscriptionDispatchOutcome::AccessEnded {
                user_did: user_did.to_string(),
                device_id: device_id.to_string(),
                cursor: next_cursor.to_string(),
            }
        } else {
            self.synchronize_authenticated_inventory(true).await?;
            let conversation_id = payload
                .get("conversationId")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            SubscriptionDispatchOutcome::OtherEvent {
                event_type: kind.to_string(),
                conversation_id,
                cursor: next_cursor.to_string(),
            }
        };

        // Advance cursor atomically in storage
        self.mls_context().ensure_storage_durable().map_err(storage_err)?;
        let mut new_fence = fence.clone();
        new_fence.cursor = next_cursor.to_string();
        let encoded = serde_json::to_vec(&new_fence).map_err(invalid_err)?;
        if !self
            .mls_context()
            .compare_exchange_request_value(
                "subscriptionCursor",
                &actor,
                Some(&retained),
                &encoded,
            )
            .map_err(storage_err)?
        {
            return Err(OrchestratorError::Api("Subscription progress superseded".into()));
        }

        Ok(outcome)
    }

    /// Process a binary frame (UTF-8 JSON bytes).
    pub async fn apply_subscription_frame_bytes(
        &self,
        raw: &[u8],
    ) -> Result<SubscriptionDispatchOutcome> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| OrchestratorError::InvalidInput(format!("Invalid UTF-8 in subscription frame: {e}")))?;
        self.apply_subscription_frame(text).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::orchestrator::mls_provider::MlsCryptoContext;

    struct NoopKeychain;
    #[async_trait::async_trait]
    impl crate::KeychainAccess for NoopKeychain {
        async fn read(&self, _key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(None)
        }
        async fn write(&self, _key: String, _data: Vec<u8>) -> std::result::Result<(), MLSError> {
            Ok(())
        }
        async fn delete(&self, _key: String) -> std::result::Result<(), MLSError> {
            Ok(())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn request_value_cas_and_bounds_work_as_expected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("request_val_test.db").to_string_lossy().to_string();
        let context = crate::MLSContext::new(
            db_path,
            "test-key-1234567890123456".to_string(),
            Box::new(NoopKeychain),
        )
        .unwrap();

        let ns = "testNamespace";
        let id1 = "id-1";
        let id2 = "id-2";

        assert_eq!(context.read_request_value(ns, id1).unwrap(), None);

        // Insert id1
        let val1 = b"first value payload";
        assert!(context.compare_exchange_request_value(ns, id1, None, val1).unwrap());
        assert_eq!(
            context.read_request_value(ns, id1).unwrap().as_deref(),
            Some(val1.as_slice())
        );

        // CAS with wrong expected fails
        assert!(!context.compare_exchange_request_value(ns, id1, Some(b"wrong"), b"new val").unwrap());
        assert_eq!(
            context.read_request_value(ns, id1).unwrap().as_deref(),
            Some(val1.as_slice())
        );

        // CAS with right expected updates
        let val1_updated = b"second value payload";
        assert!(context.compare_exchange_request_value(ns, id1, Some(val1), val1_updated).unwrap());
        assert_eq!(
            context.read_request_value(ns, id1).unwrap().as_deref(),
            Some(val1_updated.as_slice())
        );

        // Insert id2
        let val2 = b"third payload";
        assert!(context.compare_exchange_request_value(ns, id2, None, val2).unwrap());

        // List
        let list = context.list_request_values(ns).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], val1_updated);
        assert_eq!(list[1], val2);

        // Total bytes
        let total = context.request_values_total_bytes(ns).unwrap();
        assert_eq!(total, (val1_updated.len() + val2.len()) as u64);

        // Bounds check
        assert!(checked_id("").is_err());
        assert!(checked_id(&"x".repeat(513)).is_err());
        assert!(checked_namespace("").is_err());
        assert!(checked_namespace(&"x".repeat(129)).is_err());
    }

    #[test]
    fn subscription_frame_decode_and_cursor_validation() {
        let valid_watermark = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "c1",
            "cursor": "c2",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#watermarkEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        });
        let raw = serde_json::to_string(&valid_watermark).unwrap();
        let decoded = decode_subscription_frame(&raw).unwrap();
        assert_eq!(decoded["previousCursor"], "c1");
        assert_eq!(decoded["cursor"], "c2");

        // Canonical typing event decode
        let raw_typing = typing_frame("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        let decoded_typing = decode_subscription_frame(&raw_typing).unwrap();
        assert_eq!(decoded_typing["$type"], "blue.catbird.chat.defs#typingEvent");

        // subscriptionMessage is the union itself, never a wrapper variant
        let wrapped = serde_json::json!({
            "$type": "blue.catbird.chat.defs#subscriptionMessage",
            "payload": valid_watermark
        });
        assert!(decode_subscription_frame(&serde_json::to_string(&wrapped).unwrap()).is_err());

        // Unknown frame $type rejected
        let invalid_type = serde_json::json!({
            "$type": "blue.catbird.chat.defs#unknownFutureEvent",
            "data": 123
        });
        assert!(decode_subscription_frame(&serde_json::to_string(&invalid_type).unwrap()).is_err());

        // Unknown payload variant, unknown field, and duplicate key rejected
        let unknown_payload = raw.replace("#watermarkEvent", "#unknownEvent");
        assert!(decode_subscription_frame(&unknown_payload).is_err());
        let unknown_field = raw.replace(r#""cursor":"c2""#, r#""cursor":"c2","extra":"x""#);
        assert_ne!(unknown_field, raw);
        assert!(decode_subscription_frame(&unknown_field).is_err());
        let duplicate_key = raw.replace(r#""cursor":"c2""#, r#""cursor":"c2","cursor":"c9""#);
        assert_ne!(duplicate_key, raw);
        assert!(decode_subscription_frame(&duplicate_key).is_err());

        // Oversized frame rejected
        let huge = "x".repeat(MAX_FRAME_BYTES + 1);
        assert!(decode_subscription_frame(&huge).is_err());
    }

    #[test]
    fn scope_validation_rejects_altered_digest_or_versions() {
        let valid = Scope {
            supported_protocol_versions: vec!["1".into(), "2".into()],
            scope_digest: STANDARD.encode([9u8; 32]),
        };
        assert!(valid.validate().is_ok());

        let invalid_versions = Scope {
            supported_protocol_versions: vec!["1".into()],
            scope_digest: STANDARD.encode([9u8; 32]),
        };
        assert!(invalid_versions.validate().is_err());

        let invalid_digest = Scope {
            supported_protocol_versions: vec!["1".into(), "2".into()],
            scope_digest: "not-base64".into(),
        };
        assert!(invalid_digest.validate().is_err());
    }

    #[test]
    fn cursor_fence_serialization_round_trip() {
        let fence = CursorFence {
            owner: "did:plc:alice".into(),
            actor: "00000000-0000-4000-8000-000000000001".into(),
            generation: 3,
            session: "session-xyz".into(),
            connection: "conn-123".into(),
            cursor: "cursor-abc".into(),
        };
        let bytes = serde_json::to_vec(&fence).unwrap();
        let restored: CursorFence = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(fence, restored);
    }

    #[test]
    fn validate_endpoint_scenarios() {
        assert!(validate_endpoint("wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents").is_ok());
        assert!(validate_endpoint("wss://chat.catbird.blue:443/xrpc/blue.catbird.chat.subscribeEvents").is_ok());

        // Fixture hosts and non-default ports are not admitted
        assert!(validate_endpoint("wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents").is_err());
        assert!(validate_endpoint("wss://127.0.0.1:443/xrpc/blue.catbird.chat.subscribeEvents").is_err());
        assert!(validate_endpoint("wss://localhost/xrpc/blue.catbird.chat.subscribeEvents").is_err());
        assert!(validate_endpoint("wss://chat.catbird.blue:8443/xrpc/blue.catbird.chat.subscribeEvents").is_err());

        // Query and fragment rejected
        assert!(validate_endpoint("wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents?x=1").is_err());
        assert!(validate_endpoint("wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents#f").is_err());

        // Scheme must be wss
        assert!(validate_endpoint("ws://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents").is_err());
        assert!(validate_endpoint("https://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents").is_err());

        // Host must be authorized
        assert!(validate_endpoint("wss://evil.attacker.com/xrpc/blue.catbird.chat.subscribeEvents").is_err());

        // Credentials rejected
        assert!(validate_endpoint("wss://user:pass@chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents").is_err());
        assert!(validate_endpoint("wss://evil.test@chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents").is_err());

        // Path must be exact
        assert!(validate_endpoint("wss://chat.catbird.blue/xrpc/other.endpoint").is_err());
        assert!(validate_endpoint("wss://chat.catbird.blue/").is_err());
    }

    #[test]
    fn inventory_query_percent_encodes_untrusted_values() {
        let path = query(
            CanonicalOperation::GetConversations,
            "actor/1",
            Some("session&other"),
            Some("page cursor=+"),
        )
        .path;
        assert!(path.contains("?actorDeviceId=actor%2F1&limit=100&"));
        assert!(path.contains("&inventorySessionId=session%26other"));
        assert!(path.ends_with("&pageCursor=page%20cursor%3D%2B"));
    }

    fn typing_frame(actor_did: &str) -> String {
        serde_json::json!({
            "$type": "blue.catbird.chat.defs#typingEvent",
            "typingId": "00000000-0000-4000-8000-00000000000a",
            "conversationId": "00000000-0000-4000-8000-00000000000b",
            "actorDid": actor_did,
            "actorDeviceId": "00000000-0000-4000-8000-00000000000c",
            "isTyping": true,
            "expiresAt": "2026-09-23T00:00:05.000Z"
        })
        .to_string()
    }

    struct MockStorage;
    #[async_trait::async_trait]
    impl MLSStorageBackend for MockStorage {
        async fn ensure_conversation_exists(&self, _: &str, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn update_join_info(&self, _: &str, _: &str, _: super::super::types::JoinMethod, _: u64) -> Result<()> { Ok(()) }
        async fn get_conversation(&self, _: &str, _: &str) -> Result<Option<super::super::types::ConversationView>> { Ok(None) }
        async fn list_conversations(&self, _: &str) -> Result<Vec<super::super::types::ConversationView>> { Ok(vec![]) }
        async fn delete_conversations(&self, _: &str, _: &[&str]) -> Result<()> { Ok(()) }
        async fn set_conversation_state(&self, _: &str, _: super::super::types::ConversationState) -> Result<()> { Ok(()) }
        async fn mark_needs_rejoin(&self, _: &str) -> Result<()> { Ok(()) }
        async fn needs_rejoin(&self, _: &str) -> Result<bool> { Ok(false) }
        async fn clear_rejoin_flag(&self, _: &str) -> Result<()> { Ok(()) }
        async fn store_message(&self, _: &Message) -> Result<()> { Ok(()) }
        async fn get_messages(&self, _: &str, _: u32, _: Option<u64>) -> Result<Vec<Message>> { Ok(vec![]) }
        async fn message_exists(&self, _: &str) -> Result<bool> { Ok(false) }
        async fn get_sync_cursor(&self, _: &str) -> Result<super::super::types::SyncCursor> { Ok(super::super::types::SyncCursor { conversations_cursor: None, messages_cursor: None }) }
        async fn set_sync_cursor(&self, _: &str, _: &super::super::types::SyncCursor) -> Result<()> { Ok(()) }
        async fn set_group_state(&self, _: &super::super::types::GroupState) -> Result<()> { Ok(()) }
        async fn get_group_state(&self, _: &str) -> Result<Option<super::super::types::GroupState>> { Ok(None) }
        async fn delete_group_state(&self, _: &str) -> Result<()> { Ok(()) }
        async fn get_recovery_state(&self) -> Result<super::super::types::PersistedRecoveryState> { Ok(super::super::types::PersistedRecoveryState::default()) }
        async fn set_recovery_backoff(&self, _: &super::super::types::PersistedRecoveryBackoff) -> Result<()> { Ok(()) }
        async fn clear_recovery_backoff(&self, _: &str) -> Result<()> { Ok(()) }
        async fn set_last_global_rejoin_attempt_at(&self, _: i64) -> Result<()> { Ok(()) }
        async fn get_conversation_state(&self, _: &str) -> Result<Option<super::super::types::ConversationState>> { Ok(None) }
        fn implemented_optional_methods(&self) -> &'static [&'static str] {
            &["get_recovery_state", "set_recovery_backoff", "clear_recovery_backoff", "set_last_global_rejoin_attempt_at", "get_conversation_state"]
        }
    }

    struct MockCreds {
        owner: String,
        actor: String,
        gen: i64,
    }
    #[async_trait::async_trait]
    impl CredentialStore for MockCreds {
        async fn store_signing_key(&self, _: &str, _: &[u8]) -> Result<()> { Ok(()) }
        async fn get_signing_key(&self, _: &str) -> Result<Option<Vec<u8>>> { Ok(None) }
        async fn delete_signing_key(&self, _: &str) -> Result<()> { Ok(()) }
        async fn store_mls_did(&self, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn get_mls_did(&self, _: &str) -> Result<Option<String>> { Ok(Some(self.owner.clone())) }
        async fn store_device_uuid(&self, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn get_device_uuid(&self, _: &str) -> Result<Option<String>> { Ok(Some(self.actor.clone())) }
        async fn get_auth_generation(&self, _: &str) -> Result<Option<i64>> { Ok(Some(self.gen)) }
        async fn has_credentials(&self, _: &str) -> Result<bool> { Ok(true) }
        async fn clear_all(&self, _: &str) -> Result<()> { Ok(()) }
        async fn verify_member_credential(&self, _: &str, _: &str) -> Result<super::super::credential_binding::CredentialVerification> { Ok(super::super::credential_binding::CredentialVerification::Verified) }
    }

    struct MockApi {
        did: String,
    }
    #[async_trait::async_trait]
    impl MLSAPIClient for MockApi {
        async fn is_authenticated_as(&self, did: &str) -> bool { did == self.did }
        async fn current_did(&self) -> Option<String> { Some(self.did.clone()) }
        async fn submit_prepared_request(&self, _: PreparedRequest) -> Result<super::super::canonical_transport::GatewayResponse> {
            Ok(super::super::canonical_transport::GatewayResponse { status: 200, content_type: None, body: vec![] })
        }
        async fn get_conversations(&self, _: u32, _: Option<&str>) -> Result<super::super::types::ConversationListPage> {
            Ok(super::super::types::ConversationListPage { conversations: vec![], cursor: None })
        }
        async fn get_messages(&self, _: &str, _: Option<&str>, _: u32, _: Option<&str>, _: Option<u32>, _: Option<u32>) -> Result<(Vec<super::super::types::IncomingEnvelope>, Option<String>)> {
            Ok((vec![], None))
        }
        async fn get_key_packages(&self, _: &str, _: &[String]) -> Result<Vec<super::super::types::KeyPackageRef>> { Ok(vec![]) }
        async fn get_key_package_stats(&self) -> Result<super::super::types::KeyPackageStats> {
            Ok(super::super::types::KeyPackageStats { available: 10, total: 10 })
        }
        async fn sync_key_packages(&self, _: &[String], _: &str) -> Result<super::super::types::KeyPackageSyncResult> {
            Ok(super::super::types::KeyPackageSyncResult { orphaned_count: 0, deleted_count: 0 })
        }
        async fn list_devices(&self, _: &str) -> Result<Vec<super::super::types::DeviceInfo>> { Ok(vec![]) }
        async fn get_group_info(&self, _: &str) -> Result<Vec<u8>> { Ok(vec![]) }
    }

    /// Serves one inventory snapshot, numbered `snapshot`. Like the server, which keeps one
    /// session per device and replaces its capability once newer events exist, the ticket
    /// endpoint only accepts the current snapshot's session.
    struct MockInventoryApi {
        did: String,
        expires: String,
        snapshot: u8,
    }
    impl MockInventoryApi {
        fn session(&self) -> String {
            format!("session-inv-{}234567890123456789012", self.snapshot)
        }
    }
    #[async_trait::async_trait]
    impl MLSAPIClient for MockInventoryApi {
        async fn is_authenticated_as(&self, did: &str) -> bool { did == self.did }
        async fn current_did(&self) -> Option<String> { Some(self.did.clone()) }
        async fn submit_prepared_request(&self, req: PreparedRequest) -> Result<super::super::canonical_transport::GatewayResponse> {
            let expires = self.expires.as_str();
            let scope_bytes = STANDARD.encode([3u8; 32]);
            if req.operation == CanonicalOperation::GetSubscriptionTicket {
                let asked: serde_json::Value = serde_json::from_slice(req.body.as_deref().unwrap_or_default()).unwrap();
                if asked["inventorySessionId"] != self.session().as_str() {
                    return Ok(super::super::canonical_transport::GatewayResponse {
                        status: 400,
                        content_type: Some("application/json".into()),
                        body: br#"{"error":"InventorySessionMismatch","message":"InventorySessionMismatch"}"#.to_vec(),
                    });
                }
                let body = serde_json::json!({
                    "ticket": "ticket-12345678901234567890123456789012",
                    "endpoint": "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
                    "expiresAt": expires,
                    "inventoryScope": {
                        "supportedProtocolVersions": ["1", "2"],
                        "scopeDigest": scope_bytes,
                    }
                });
                return Ok(super::super::canonical_transport::GatewayResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    body: serde_json::to_vec(&body).unwrap(),
                });
            }
            let page = serde_json::json!({
                "inventorySessionId": self.session(),
                "snapshotEventCursor": format!("cursor-inv-{}", self.snapshot),
                "snapshotExpiresAt": expires,
                "hasMore": false,
                "items": [],
                "inventoryScope": {
                    "supportedProtocolVersions": ["1", "2"],
                    "scopeDigest": { "$bytes": scope_bytes },
                }
            });
            Ok(super::super::canonical_transport::GatewayResponse {
                status: 200,
                content_type: Some("application/json".into()),
                body: serde_json::to_vec(&page).unwrap(),
            })
        }
        async fn get_conversations(&self, _: u32, _: Option<&str>) -> Result<super::super::types::ConversationListPage> {
            Ok(super::super::types::ConversationListPage { conversations: vec![], cursor: None })
        }
        async fn get_messages(&self, _: &str, _: Option<&str>, _: u32, _: Option<&str>, _: Option<u32>, _: Option<u32>) -> Result<(Vec<super::super::types::IncomingEnvelope>, Option<String>)> {
            Ok((vec![], None))
        }
        async fn get_key_packages(&self, _: &str, _: &[String]) -> Result<Vec<super::super::types::KeyPackageRef>> { Ok(vec![]) }
        async fn get_key_package_stats(&self) -> Result<super::super::types::KeyPackageStats> {
            Ok(super::super::types::KeyPackageStats { available: 10, total: 10 })
        }
        async fn sync_key_packages(&self, _: &[String], _: &str) -> Result<super::super::types::KeyPackageSyncResult> {
            Ok(super::super::types::KeyPackageSyncResult { orphaned_count: 0, deleted_count: 0 })
        }
        async fn list_devices(&self, _: &str) -> Result<Vec<super::super::types::DeviceInfo>> { Ok(vec![]) }
        async fn get_group_info(&self, _: &str) -> Result<Vec<u8>> { Ok(vec![]) }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn subscription_orchestrator_cursor_lifecycle_and_cas() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sub_orch_test.db").to_string_lossy().to_string();
        let context = crate::MLSContext::new(
            db_path,
            "test-key-1234567890123456".to_string(),
            Box::new(NoopKeychain),
        )
        .unwrap();

        let owner = "did:plc:alice";
        let actor = "00000000-0000-4000-8000-000000000001";
        let creds = Arc::new(MockCreds {
            owner: owner.into(),
            actor: actor.into(),
            gen: 1,
        });
        let storage = Arc::new(MockStorage);
        let api = Arc::new(MockApi { did: owner.into() });

        let orchestrator = MLSOrchestrator::new(
            context.clone(),
            storage,
            api,
            creds,
            super::super::orchestrator::OrchestratorConfig::default(),
        );
        orchestrator.initialize(owner).await.unwrap();

        let ticket = SubscriptionTicket {
            endpoint: "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents".into(),
            ticket: "ticket-12345678901234567890123456789012".into(),
            inventory_session_id: "session-1".into(),
            event_cursor: "cursor-1".into(),
        };

        // 1. Initialize cursor fence
        let fence = orchestrator.initialize_subscription_cursor(&ticket).await.unwrap();
        assert_eq!(fence.cursor, "cursor-1");
        assert_eq!(fence.session, "session-1");

        let current = orchestrator.current_subscription_cursor().await.unwrap().unwrap();
        assert_eq!(current.cursor, "cursor-1");

        // 2. Apply watermark event: cursor-1 -> cursor-2
        let watermark_frame = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-1",
            "cursor": "cursor-2",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#watermarkEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        }).to_string();

        let outcome = orchestrator.apply_subscription_frame(&watermark_frame).await.unwrap();
        assert!(matches!(outcome, SubscriptionDispatchOutcome::Watermark { ref cursor, .. } if cursor == "cursor-2"));

        let current = orchestrator.current_subscription_cursor().await.unwrap().unwrap();
        assert_eq!(current.cursor, "cursor-2");

        // 3. Gap frame: expected previousCursor cursor-2, but received cursor-1 -> rejected!
        let gap_frame = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-1",
            "cursor": "cursor-3",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#watermarkEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        }).to_string();
        let err = orchestrator.apply_subscription_frame(&gap_frame).await.unwrap_err();
        assert!(err.to_string().contains("Subscription cursor chain changed"));
        // Cursor must remain cursor-2
        assert_eq!(orchestrator.current_subscription_cursor().await.unwrap().unwrap().cursor, "cursor-2");

        // 4. Typing event does NOT advance cursor
        let bob = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
        let outcome = orchestrator.apply_subscription_frame(&typing_frame(bob)).await.unwrap();
        assert!(matches!(outcome, SubscriptionDispatchOutcome::Typing { ref conversation_id, ref sender_did, is_typing: true } if conversation_id == "00000000-0000-4000-8000-00000000000b" && sender_did == bob));
        // Cursor must remain cursor-2
        assert_eq!(orchestrator.current_subscription_cursor().await.unwrap().unwrap().cursor, "cursor-2");

        // 5. Valid advance cursor-2 -> cursor-3
        let advance_frame = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-2",
            "cursor": "cursor-3",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#watermarkEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        }).to_string();
        let outcome = orchestrator.apply_subscription_frame(&advance_frame).await.unwrap();
        assert!(matches!(outcome, SubscriptionDispatchOutcome::Watermark { ref cursor, .. } if cursor == "cursor-3"));
        assert_eq!(orchestrator.current_subscription_cursor().await.unwrap().unwrap().cursor, "cursor-3");

        // 6. Foreign access-ended event is rejected
        let foreign_access_ended = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-3",
            "cursor": "cursor-4",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#accessEndedEvent",
                "conversationId": "00000000-0000-4000-8000-00000000000b",
                "membershipIntervalId": "00000000-0000-4000-8000-00000000000d",
                "userDid": "did:plc:ffffffffffffffffffffffff",
                "deviceId": "00000000-0000-4000-8000-000000000999",
                "terminalSeq": 1
            }
        }).to_string();
        let err = orchestrator.apply_subscription_frame(&foreign_access_ended).await.unwrap_err();
        assert!(err.to_string().contains("Foreign access-ended audience"));
        assert_eq!(orchestrator.current_subscription_cursor().await.unwrap().unwrap().cursor, "cursor-3");

        // 6b. Unknown payload variant is rejected before the cursor moves
        let unknown_variant = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-3",
            "cursor": "cursor-4",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#unknownEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        }).to_string();
        assert!(orchestrator.apply_subscription_frame(&unknown_variant).await.is_err());
        assert_eq!(orchestrator.current_subscription_cursor().await.unwrap().unwrap().cursor, "cursor-3");

        // 7. Concurrent CAS modification: another process updates subscriptionCursor
        let competing_fence = CursorFence {
            owner: owner.into(),
            actor: actor.into(),
            generation: 1,
            session: "session-competing".into(),
            connection: "conn-competing".into(),
            cursor: "cursor-competing".into(),
        };
        let raw_current = context.read_request_value("subscriptionCursor", actor).unwrap().unwrap();
        let competing_bytes = serde_json::to_vec(&competing_fence).unwrap();
        assert!(context.compare_exchange_request_value("subscriptionCursor", actor, Some(&raw_current), &competing_bytes).unwrap());

        // Now apply_subscription_frame fails with authority changed or superseded
        let advance_frame_4 = serde_json::json!({
            "$type": "blue.catbird.chat.defs#eventEnvelope",
            "previousCursor": "cursor-3",
            "cursor": "cursor-4",
            "createdAt": "2026-09-23T00:00:00.000Z",
            "payload": {
                "$type": "blue.catbird.chat.defs#watermarkEvent",
                "issuedAt": "2026-09-23T00:00:00.000Z"
            }
        }).to_string();
        assert!(orchestrator.apply_subscription_frame(&advance_frame_4).await.is_err());
    }

    /// An initialized orchestrator over the mock inventory API serving `snapshot`
    /// (`session-inv-<snapshot>…`, `cursor-inv-<snapshot>`), ticket `ticket-…`. Reusing `dir`
    /// is a relaunch on the same storage.
    #[cfg(not(target_arch = "wasm32"))]
    async fn inventory_orchestrator(
        dir: &tempfile::TempDir,
        snapshot: u8,
    ) -> MLSOrchestrator<MockStorage, MockInventoryApi, MockCreds, crate::MLSContext> {
        let db_path = dir.path().join("sub_inv_test.db").to_string_lossy().to_string();
        let context = crate::MLSContext::new(
            db_path,
            "test-key-1234567890123456".to_string(),
            Box::new(NoopKeychain),
        )
        .unwrap();
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let actor = "00000000-0000-4000-8000-000000000001";
        let creds = Arc::new(MockCreds {
            owner: owner.into(),
            actor: actor.into(),
            gen: 1,
        });
        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let api = Arc::new(MockInventoryApi { did: owner.into(), expires, snapshot });
        let orchestrator = MLSOrchestrator::new(
            context,
            Arc::new(MockStorage),
            api,
            creds,
            super::super::orchestrator::OrchestratorConfig::default(),
        );
        orchestrator.initialize(owner).await.unwrap();
        orchestrator
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn synchronize_inventory_and_prepare_ticket_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let orchestrator = inventory_orchestrator(&dir, 1).await;
        let actor = "00000000-0000-4000-8000-000000000001";

        // 1. Synchronize inventory
        let fence = orchestrator.synchronize_authenticated_inventory(false).await.unwrap();
        assert_eq!(fence.inventory_session_id(), "session-inv-1234567890123456789012");
        assert_eq!(fence.event_cursor(), "cursor-inv-1");

        // 2. Prepare subscription ticket
        let ticket = orchestrator.prepare_subscription().await.unwrap();
        assert_eq!(ticket.inventory_session_id, "session-inv-1234567890123456789012");
        assert_eq!(ticket.event_cursor, "cursor-inv-1");
        assert_eq!(ticket.endpoint, "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents");
        assert_eq!(ticket.ticket, "ticket-12345678901234567890123456789012");

        // 2b. A ticket whose inventory scope differs from the snapshot is refused
        let foreign_scope = STANDARD.encode([4u8; 32]);
        let err = orchestrator
            .prepare_subscription_ticket(actor, &ticket.inventory_session_id, &ticket.event_cursor, &foreign_scope)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ticket inventory scope does not match snapshot"));

        // 3. Second call with force_fresh=false restores from cached journal
        let fence2 = orchestrator.synchronize_authenticated_inventory(false).await.unwrap();
        assert_eq!(fence2.inventory_session_id(), "session-inv-1234567890123456789012");
        assert_eq!(fence2.event_cursor(), "cursor-inv-1");
    }

    /// F71: a subscription requested while a sync pass is running (the 5 s periodic sync or a
    /// UI refresh) waits for that pass and then gets its ticket, instead of failing with
    /// "another sync is in progress" and backing the stream off.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn ticket_requested_during_in_flight_sync_is_prepared_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let orchestrator = inventory_orchestrator(&dir, 1).await;

        *orchestrator.sync_in_progress().lock().await = true;
        let pending = orchestrator.prepare_subscription();
        tokio::pin!(pending);
        let early = tokio::time::timeout(std::time::Duration::from_millis(200), &mut pending).await;
        assert!(early.is_err(), "ticket must wait for the in-flight pass, got {early:?}");

        *orchestrator.sync_in_progress().lock().await = false;
        orchestrator.sync_finished().notify_waiters();
        let ticket = pending.await.expect("ticket after the pass finished");
        assert_eq!(ticket.ticket, "ticket-12345678901234567890123456789012");
        assert!(!*orchestrator.sync_in_progress().lock().await, "ingest released the sync flag");
    }

    /// F71: after any newer event the server replaces the device's inventory session
    /// capability (and its tickets). A relaunched client must mint its ticket from a fresh
    /// applied inventory, not from the session restored out of the previous launch's journal,
    /// which the server now answers with 400 InventorySessionMismatch.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn relaunch_after_server_event_mints_ticket_from_fresh_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let first = inventory_orchestrator(&dir, 1).await;
        let ticket = first.prepare_subscription().await.unwrap();
        assert_eq!(ticket.event_cursor, "cursor-inv-1");
        drop(first);

        let relaunched = inventory_orchestrator(&dir, 2).await;
        let ticket = relaunched
            .prepare_subscription()
            .await
            .expect("ticket minted from the fresh inventory");
        assert_eq!(ticket.inventory_session_id, "session-inv-2234567890123456789012");
        assert_eq!(ticket.event_cursor, "cursor-inv-2");
    }
}
