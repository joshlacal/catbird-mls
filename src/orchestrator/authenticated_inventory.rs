//! Exact account-scoped snapshot ingestion for hosts that own HTTP transport.
//! A completed fence certifies the same three retained inventories were applied;
//! it cannot be constructed from the best-effort background sync result.
use super::canonical_transport::CanonicalOperation;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedInventorySnapshot {
    pub owner_did: String,
    pub actor_device_id: String,
    pub auth_generation: i64,
    pub inventory_session_id: String,
    pub event_cursor: String,
    pub expires_at: String,
    pub scope_digest: String,
    pub conversation_pages: Vec<Vec<u8>>,
    pub welcome_pages: Vec<Vec<u8>>,
    pub recovery_pages: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AppliedInventoryFence {
    snapshot_digest: [u8; 32],
    inventory_session_id: String,
    event_cursor: String,
}
impl AppliedInventoryFence {
    pub fn matches_snapshot(&self, snapshot: &AuthenticatedInventorySnapshot) -> bool {
        snapshot.digest().is_ok_and(|d| d == self.snapshot_digest)
    }
    pub fn inventory_session_id(&self) -> &str {
        &self.inventory_session_id
    }
    pub fn event_cursor(&self) -> &str {
        &self.event_cursor
    }
    pub fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
}
fn invalid(reason: &str) -> OrchestratorError {
    OrchestratorError::InvalidInput(format!("Authenticated inventory: {reason}"))
}
impl AuthenticatedInventorySnapshot {
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|e| invalid(&e.to_string()))?).into())
    }
    fn validate(&self) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>)> {
        crate::chat_v2::ids::BareDid::parse(&self.owner_did).map_err(|_| invalid("owner"))?;
        crate::chat_v2::ids::CanonicalUuid::parse(&self.actor_device_id)
            .map_err(|_| invalid("actor device"))?;
        if self.auth_generation < 1
            || self.inventory_session_id.is_empty()
            || self.inventory_session_id.len() > 512
            || self.event_cursor.is_empty()
            || self.event_cursor.len() > 512
        {
            return Err(invalid("fence identity"));
        }
        let expiry = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| invalid("expiry"))?;
        if expiry <= chrono::Utc::now() {
            return Err(invalid("snapshot expired"));
        }
        let digest = STANDARD
            .decode(&self.scope_digest)
            .map_err(|_| invalid("scope digest"))?;
        if digest.len() != 32 || STANDARD.encode(&digest) != self.scope_digest {
            return Err(invalid("scope digest"));
        }
        let total = self
            .conversation_pages
            .iter()
            .chain(&self.welcome_pages)
            .chain(&self.recovery_pages)
            .try_fold(0usize, |n, p| {
                n.checked_add(p.len())
                    .ok_or_else(|| invalid("size overflow"))
            })?;
        if total > 64 * 1024 * 1024 {
            return Err(invalid("snapshot exceeds 64 MiB"));
        }
        Ok((
            self.pages(
                &self.conversation_pages,
                CanonicalOperation::GetConversations,
            )?,
            self.pages(&self.welcome_pages, CanonicalOperation::GetPendingWelcomes)?,
            self.pages(
                &self.recovery_pages,
                CanonicalOperation::GetLeafRecoveryInbox,
            )?,
        ))
    }
    fn pages(&self, pages: &[Vec<u8>], operation: CanonicalOperation) -> Result<Vec<Value>> {
        if pages.is_empty() {
            return Err(invalid("missing inventory"));
        }
        let mut guard = super::pagination::PaginationGuard::for_conversations("exact snapshot");
        let mut items = Vec::new();
        for (index, raw) in pages.iter().enumerate() {
            if raw.len() > 16 * 1024 * 1024 {
                return Err(invalid("page exceeds 16 MiB"));
            }
            super::canonical_transport::validate_authenticated_inventory_page(operation, raw)
                .map_err(|e| invalid(&e.to_string()))?;
            let page: Value = serde_json::from_slice(raw).map_err(|e| invalid(&e.to_string()))?;
            let scope = &page["inventoryScope"];
            let digest = scope["scopeDigest"]
                .as_str()
                .or_else(|| scope["scopeDigest"]["$bytes"].as_str());
            if page["inventorySessionId"] != self.inventory_session_id
                || page["snapshotEventCursor"] != self.event_cursor
                || page["snapshotExpiresAt"] != self.expires_at
                || scope["supportedProtocolVersions"] != serde_json::json!(["1", "2"])
                || digest != Some(self.scope_digest.as_str())
            {
                return Err(invalid("page changed the bound fence or reader scope"));
            }
            let next = match page.get("nextPageCursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
                _ => return Err(invalid("invalid next cursor")),
            };
            if page["hasMore"].as_bool() != Some(next.is_some())
                || next.is_some() != (index + 1 < pages.len())
            {
                return Err(invalid("incomplete or extra page"));
            }
            let rows = page["items"]
                .as_array()
                .ok_or_else(|| invalid("missing items"))?;
            guard.observe_page(rows.len(), next)?;
            items.extend(rows.iter().cloned());
        }
        Ok(items)
    }
}
static NEXT_EXACT_EXECUTION: AtomicU64 = AtomicU64::new(1);
tokio::task_local! {static EXACT_WELCOME_ITEMS:Arc<Vec<Value>>;}
pub(crate) fn scoped_welcome_items() -> Option<Arc<Vec<Value>>> {
    EXACT_WELCOME_ITEMS.try_with(Clone::clone).ok()
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    async fn require_snapshot_account(
        &self,
        snapshot: &AuthenticatedInventorySnapshot,
    ) -> Result<()> {
        self.check_shutdown().await?;
        if self.require_user_did().await? != snapshot.owner_did
            || self.require_actor_device_id().await? != snapshot.actor_device_id
            || !self
                .api_client()
                .is_authenticated_as(&snapshot.owner_did)
                .await
            || self
                .credentials()
                .get_auth_generation(&snapshot.owner_did)
                .await?
                != Some(snapshot.auth_generation)
        {
            return Err(invalid("account or enrollment changed"));
        }
        Ok(())
    }
    /// The caller retains these exact authenticated response bytes in protected
    /// storage before calling. An error never authorizes ticket/cursor advance.
    pub async fn ingest_authenticated_inventory_snapshot(
        &self,
        snapshot: &AuthenticatedInventorySnapshot,
    ) -> Result<AppliedInventoryFence> {
        self.require_snapshot_account(snapshot).await?;
        let (items, welcomes, recovery) = snapshot.validate()?;
        let mut conversations = HashMap::new();
        let mut terminals = HashSet::new();
        for item in &items {
            if item["$type"] == "blue.catbird.chat.defs#conversationInventoryState" {
                let view = super::admission::conversation_view_from_state_json(&item["state"])
                    .ok_or_else(|| invalid("state projection failed"))?;
                if conversations
                    .insert(view.conversation_id.clone(), view)
                    .is_some()
                {
                    return Err(invalid("duplicate active conversation"));
                }
            } else {
                let cid = item["conversationId"]
                    .as_str()
                    .ok_or_else(|| invalid("terminal identity"))?;
                terminals.insert(cid.to_owned());
            }
        }
        for item in &welcomes {
            if item["recipientDid"] != snapshot.owner_did
                || item["recipientDeviceId"] != snapshot.actor_device_id
            {
                return Err(invalid("Welcome addressed to another device"));
            }
            let cid = item["conversationId"]
                .as_str()
                .ok_or_else(|| invalid("Welcome conversation"))?;
            if !conversations.contains_key(cid) && !terminals.contains(cid) {
                return Err(invalid("Welcome absent from exact conversation inventory"));
            }
        }
        let execution_id = NEXT_EXACT_EXECUTION.fetch_add(1, Ordering::Relaxed);
        let inv = Arc::new(AuthorizedInventorySnapshot {
            owner_instance_id: self.instance_id,
            execution_id,
            session_id: snapshot.inventory_session_id.clone(),
            event_cursor: snapshot.event_cursor.clone(),
            expires_at: Some(snapshot.expires_at.clone()),
            items,
            conversations: conversations.clone(),
            user_did: snapshot.owner_did.clone(),
            device_id: snapshot.actor_device_id.clone(),
        });
        let inbox = Arc::new(AuthorizedRecoveryInboxSnapshot {
            owner_instance_id: self.instance_id,
            execution_id,
            session_id: snapshot.inventory_session_id.clone(),
            event_cursor: snapshot.event_cursor.clone(),
            expires_at: Some(snapshot.expires_at.clone()),
            items: recovery,
            user_did: snapshot.owner_did.clone(),
            device_id: snapshot.actor_device_id.clone(),
        });
        // An ingest that finds a sync pass in flight (the periodic sync, a UI refresh) waits for
        // it and then runs its own snapshot, as sync_with_server callers coalesce in sync.rs.
        // The waiter registers before the flag lock is released, so a completion cannot be
        // missed; a pass that outlives the bound fails closed.
        #[cfg(not(target_arch = "wasm32"))]
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(super::constants::INVENTORY_SYNC_WAIT_SECS);
        loop {
            let mut busy = self.sync_in_progress().lock().await;
            if !*busy {
                *busy = true;
                break;
            }
            let finished = self.sync_finished().notified();
            drop(busy);
            #[cfg(not(target_arch = "wasm32"))]
            if tokio::time::timeout_at(deadline, finished).await.is_err() {
                return Err(invalid("another sync is in progress"));
            }
            #[cfg(target_arch = "wasm32")]
            finished.await;
        }
        let flag = self.sync_in_progress();
        let finished = self.sync_finished();
        let _guard = scopeguard::guard((), |_| {
            if let Ok(mut flag) = flag.try_lock() {
                *flag = false;
            }
            finished.notify_waiters();
        });
        let result = super::with_batch_inventory_scope(
            inv,
            super::with_batch_recovery_inbox_scope(
                inbox,
                EXACT_WELCOME_ITEMS.scope(
                    Arc::new(welcomes),
                    Box::pin(async {
                        let mut blocked = self.resume_prepared_controls().await?;
                        blocked.extend(self.resume_account_exits(&blocked).await?);
                        self.retry_pending_welcome_acknowledgements().await?;
                        blocked.extend(self.pending_welcome_publications().await?);
                        for cid in &terminals {
                            self.reconcile_terminal_conversation(cid).await?;
                        }
                        self.reconcile_server_conversations_batch(
                            &snapshot.owner_did,
                            conversations.into_values().collect(),
                            blocked,
                            true,
                        )
                        .await?;
                        self.mls_context().ensure_storage_durable()?;
                        self.require_snapshot_account(snapshot).await?;
                        // Receipt is minted only while the exact session is still valid.
                        snapshot.validate()?;
                        Ok::<(), OrchestratorError>(())
                    }),
                ),
            ),
        )
        .await;
        *self.sync_in_progress().lock().await = false;
        self.sync_finished().notify_waiters();
        result?;
        Ok(AppliedInventoryFence {
            snapshot_digest: snapshot.digest()?,
            inventory_session_id: snapshot.inventory_session_id.clone(),
            event_cursor: snapshot.event_cursor.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> AuthenticatedInventorySnapshot {
        let expires = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let page = serde_json::json!({"inventorySessionId":"s".repeat(32),"snapshotEventCursor":"e".repeat(32),"snapshotExpiresAt":expires,"hasMore":false,"items":[],"inventoryScope":{"supportedProtocolVersions":["1","2"],"scopeDigest":{"$bytes":STANDARD.encode([3u8;32])}}});
        let raw = serde_json::to_vec(&page).unwrap();
        AuthenticatedInventorySnapshot {
            owner_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            actor_device_id: "00000000-0000-4000-8000-000000000000".into(),
            auth_generation: 7,
            inventory_session_id: "s".repeat(32),
            event_cursor: "e".repeat(32),
            expires_at: expires,
            scope_digest: STANDARD.encode([3u8; 32]),
            conversation_pages: vec![raw.clone()],
            welcome_pages: vec![raw.clone()],
            recovery_pages: vec![raw],
        }
    }
    #[test]
    fn exact_scope_requires_all_three_complete_inventories() {
        let mut s = snapshot();
        assert!(s.validate().is_ok(), "{:?}", s.validate());
        s.welcome_pages.clear();
        assert!(s.validate().is_err());
        let mut s = snapshot();
        let mut page: Value = serde_json::from_slice(&s.recovery_pages[0]).unwrap();
        page["inventoryScope"]["supportedProtocolVersions"] = serde_json::json!(["1"]);
        s.recovery_pages[0] = serde_json::to_vec(&page).unwrap();
        assert!(s.validate().is_err());
        let mut s = snapshot();
        s.conversation_pages.push(s.conversation_pages[0].clone());
        assert!(s.validate().is_err());
    }
    #[test]
    fn applied_receipt_is_bound_to_exact_bytes_and_auth_generation() {
        let mut s = snapshot();
        let fence = AppliedInventoryFence {
            snapshot_digest: s.digest().unwrap(),
            inventory_session_id: s.inventory_session_id.clone(),
            event_cursor: s.event_cursor.clone(),
        };
        assert!(fence.matches_snapshot(&s));
        s.auth_generation += 1;
        assert!(!fence.matches_snapshot(&s));
        let mut s = snapshot();
        s.expires_at = "2000-01-01T00:00:00.000Z".into();
        assert!(s.validate().is_err());
    }
}
