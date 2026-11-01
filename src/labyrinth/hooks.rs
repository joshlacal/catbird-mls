//! Async orchestrator hooks for Spaces-only Labyrinth history backup.

use std::sync::Arc;

use chrono::{TimeZone as _, Utc};
use labyrinth::client::{MessageSource, PurgeReport, ThreadCursor};
use labyrinth::store::pds::PublicRepoBackend;
use labyrinth::store::space::SpaceRpc;
use labyrinth::store::TimeRange;
use serde_json::Value;

use super::queue::{
    enqueue, flush_in_slot, ArchiveQueueStore, MlsArchiveQueue, PendingArchive, QueueConfig,
};
use super::session::{
    HistoryPage, ImportReport, LabyrinthSession, LocalConversationAuthority, LocalGroupSnapshot,
    SessionDeps,
};
use super::signer::ChatKeySigner;
use super::space::{thread_placement_key, MlsPlacementVault, Placement, SpaceXrpcTransport};
use super::state::MlsStateVault;
use super::status::{now_ms, PendingDeletion};
use super::transport::{ApiGateway, GatewayXrpcTransport};
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::error::{OrchestratorError, Result};
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::{MLSMessagePayload, Message};
use crate::orchestrator::MLSOrchestrator;

/// Active MLS member DIDs from `getConversationState` (`[CB-16]`).
pub(crate) fn roster_members(conversation_state: &Value) -> labyrinth::Result<Vec<String>> {
    let participants = conversation_state["state"]["participants"]
        .as_array()
        .ok_or(labyrinth::Error::Malformed(
            "conversation participants are missing",
        ))?;
    let mut active = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for participant in participants {
        let did = participant["userDid"]
            .as_str()
            .ok_or(labyrinth::Error::Malformed("participant DID is missing"))?;
        let status = participant["status"]
            .as_str()
            .ok_or(labyrinth::Error::Malformed("participant status is missing"))?;
        let leaves = participant["leafCount"]
            .as_u64()
            .ok_or(labyrinth::Error::Malformed(
                "participant leaf count is missing",
            ))?;
        if status == "active" && leaves > 0 {
            if !seen.insert(did) {
                return Err(labyrinth::Error::Malformed("duplicate active participant"));
            }
            active.push(did.to_owned());
        }
    }
    Ok(active)
}

struct OrchestratorLocalAuthority<S, M> {
    storage: Arc<S>,
    mls_context: Arc<M>,
    user_did: String,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<S, M> LocalConversationAuthority for OrchestratorLocalAuthority<S, M>
where
    S: MLSStorageBackend + 'static,
    M: MlsCryptoContext + 'static,
{
    async fn current_group_snapshot(
        &self,
        conversation_id: &str,
        queued_group_id_hex: Option<&str>,
    ) -> Result<Option<LocalGroupSnapshot>> {
        let conv_view = self
            .storage
            .get_conversation(&self.user_did, conversation_id)
            .await?;
        let candidate_hex = conv_view
            .as_ref()
            .map(|v| v.group_id.as_str())
            .filter(|s| !s.is_empty())
            .or(queued_group_id_hex);
        let Some(group_id_hex) = candidate_hex else {
            return Ok(None);
        };
        let group_bytes =
            hex::decode(group_id_hex).unwrap_or_else(|_| group_id_hex.as_bytes().to_vec());
        match self.mls_context.get_epoch(group_bytes.clone()) {
            Ok(epoch) => {
                let raw_identities = self
                    .mls_context
                    .group_member_identities(group_bytes)
                    .map_err(OrchestratorError::Mls)?;
                let mut member_dids = Vec::with_capacity(raw_identities.len());
                for raw in raw_identities {
                    let ident = std::str::from_utf8(&raw).map_err(|_| {
                        OrchestratorError::Credential(
                            "MLS leaf credential identity is not valid UTF-8".into(),
                        )
                    })?;
                    let root = crate::orchestrator::credential_binding::credential_root_did(ident);
                    if root.is_empty() {
                        return Err(OrchestratorError::Credential(
                            "MLS leaf credential root DID is empty".into(),
                        ));
                    }
                    member_dids.push(root.to_owned());
                }
                member_dids.sort();
                member_dids.dedup();
                Ok(Some(LocalGroupSnapshot {
                    group_id_hex: group_id_hex.to_owned(),
                    epoch,
                    member_dids,
                }))
            }
            Err(crate::MLSError::GroupNotFound { .. }) => {
                if let Some(view) = conv_view {
                    let mut member_dids: Vec<String> = view
                        .members
                        .iter()
                        .map(|m| {
                            crate::orchestrator::credential_binding::credential_root_did(&m.did)
                                .to_owned()
                        })
                        .filter(|d| !d.is_empty())
                        .collect();
                    member_dids.sort();
                    member_dids.dedup();
                    Ok(Some(LocalGroupSnapshot {
                        group_id_hex: view.group_id,
                        epoch: view.epoch,
                        member_dids,
                    }))
                } else {
                    Ok(None)
                }
            }
            Err(other) => Err(OrchestratorError::Mls(other)),
        }
    }
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub(super) async fn labyrinth_deps(&self) -> Result<SessionDeps> {
        let did = self.require_user_did().await?;
        let device_id = self.require_actor_device_id().await?;
        let public = self
            .mls_context()
            .identity_public_key(format!("{did}#{device_id}").into_bytes())?;
        let public_key: [u8; 32] = public
            .as_slice()
            .try_into()
            .map_err(|_| OrchestratorError::Credential("chat device key is not Ed25519".into()))?;

        #[cfg(not(target_arch = "wasm32"))]
        let signer: Arc<dyn ChatKeySigner> = Arc::new(super::signer::OrchestratorChatSigner {
            credentials: self.credentials().clone(),
            mls_context: self.mls_context().clone(),
            user_did: did.clone(),
            device_id: device_id.clone(),
            key_id: crate::orchestrator::canonical_transport::derive_key_id(&public_key),
            public_key,
        });

        #[cfg(target_arch = "wasm32")]
        let signer: Arc<dyn ChatKeySigner> = Arc::new(super::signer::ContextIdentitySigner {
            mls_context: self.mls_context().clone(),
            user_did: did.clone(),
            device_id: device_id.clone(),
            public_key,
        });

        let local_authority: Arc<dyn LocalConversationAuthority> =
            Arc::new(OrchestratorLocalAuthority {
                storage: self.storage().clone(),
                mls_context: self.mls_context().clone(),
                user_did: did.clone(),
            });
        let gateway = Arc::new(ApiGateway::new(self.api_client().clone()));
        let pds: Option<Arc<dyn PublicRepoBackend>> =
            if self.api_client().labyrinth_pds_enabled().await {
                Some(gateway.clone())
            } else {
                None
            };
        let space: Option<Arc<dyn SpaceRpc>> = if self.api_client().labyrinth_space_enabled().await
        {
            Some(Arc::new(SpaceXrpcTransport::new(gateway.clone())))
        } else {
            None
        };
        let sequencer_key = self
            .api_client()
            .labyrinth_sequencer_key()
            .await
            .map(|(did, key)| labyrinth::store::SequencerKey { did, key });
        Ok(SessionDeps {
            pds,
            space,
            placements: Arc::new(MlsPlacementVault(self.mls_context().clone())),
            transport: Arc::new(GatewayXrpcTransport::new(
                gateway,
                signer.clone(),
                did.clone(),
                device_id,
            )),
            vault: Arc::new(MlsStateVault(self.mls_context().clone())),
            signer,
            did,
            local_authority: Some(local_authority),
            sequencer_key,
            sequencer_receipt_key: None,
            default_conversation_authority_did: None,
        })
    }

    pub fn labyrinth_close(&self) {
        if let Ok(mut guard) = self.labyrinth_slot().try_lock() {
            *guard = None;
        }
    }

    pub async fn labyrinth_close_async(&self) {
        *self.labyrinth_slot().lock().await = None;
    }

    async fn ensure_opened_in_slot(
        guard: &mut Option<LabyrinthSession>,
        deps: SessionDeps,
    ) -> Result<Option<&mut LabyrinthSession>> {
        let key = deps.signer.public_key();
        if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
            *guard = None;
            *guard = deps.open().await?;
        }
        Ok(guard.as_mut())
    }

    pub async fn labyrinth_is_enabled(&self) -> Result<bool> {
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        Ok(Self::ensure_opened_in_slot(&mut guard, deps)
            .await?
            .is_some())
    }

    pub async fn labyrinth_enable(&self) -> Result<String> {
        let deps = self.labyrinth_deps().await?;
        let key = self.labyrinth_enroll_enable(deps.clone()).await?;
        self.labyrinth_start_archive_worker(&deps)?;
        Ok(key)
    }

    pub async fn labyrinth_create_recovery_code(&self) -> Result<String> {
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        let session = Self::ensure_opened_in_slot(&mut guard, deps)
            .await?
            .ok_or_else(not_enabled)?;
        session.create_recovery_code().await
    }

    pub async fn labyrinth_restore_with_recovery_code(&self, code: &str) -> Result<String> {
        let deps = self.labyrinth_deps().await?;
        let store = self.labyrinth_queue_store();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let _lifecycle = lifecycle.lock().await;
        if !super::hooks_status::retry_deletion_async(&deps, store.as_ref()).await? {
            return Err(OrchestratorError::Api(
                "labyrinth: the previous account deletion is still pending on the server; \
                 retry when online"
                    .into(),
            ));
        }
        let mut guard = self.labyrinth_slot().lock().await;
        *guard = None;
        let session = deps.restore_with_recovery_code(code).await?;
        let hex = session.device_key_hex();
        *guard = Some(session);
        Ok(hex)
    }

    async fn labyrinth_enroll_enable(&self, deps: SessionDeps) -> Result<String> {
        let store = self.labyrinth_queue_store();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let _lifecycle = lifecycle.lock().await;
        if !super::hooks_status::retry_deletion_async(&deps, store.as_ref()).await? {
            return Err(OrchestratorError::Api(
                "labyrinth: the previous account deletion is still pending on the server; \
                 retry when online"
                    .into(),
            ));
        }
        let mut guard = self.labyrinth_slot().lock().await;
        if !guard
            .as_ref()
            .is_some_and(|s| s.is_for(&deps.did, &deps.signer.public_key()))
        {
            *guard = None;
            *guard = Some(deps.enable().await?);
        }
        guard
            .as_ref()
            .map(|s| s.device_key_hex())
            .ok_or_else(|| OrchestratorError::Api("labyrinth session missing".into()))
    }

    pub async fn labyrinth_load_history(
        &self,
        conversation_id: &str,
        from_ms: Option<u64>,
        until_ms: Option<u64>,
    ) -> Result<HistoryPage> {
        let deps = self.labyrinth_deps().await?;
        let range = TimeRange { from_ms, until_ms };
        let mut guard = self.labyrinth_slot().lock().await;
        let session = Self::ensure_opened_in_slot(&mut guard, deps)
            .await?
            .ok_or_else(not_enabled)?;
        session.load_history(conversation_id, range).await
    }

    pub async fn labyrinth_import_history(&self, conversation_id: &str) -> Result<ImportReport> {
        const IMPORT_HISTORY_PAGE_SIZE: usize = 200;
        const IMPORT_HISTORY_MAX_PAGES: usize = 500;
        const MAX_IMPORTED_MESSAGE_ID_LEN: usize = 128;

        let user_did = self.require_user_did().await?;
        let receiver_root =
            crate::orchestrator::credential_binding::credential_root_did(&user_did).to_owned();
        let mut report = ImportReport::default();
        let mut before: Option<ThreadCursor> = None;
        let mut seen_cursors = std::collections::HashSet::new();

        for page_idx in 0..IMPORT_HISTORY_MAX_PAGES {
            let deps = self.labyrinth_deps().await?;
            let sync = page_idx == 0;
            let (page, next_cursor) = {
                let mut guard = self.labyrinth_slot().lock().await;
                let session = Self::ensure_opened_in_slot(&mut guard, deps)
                    .await?
                    .ok_or_else(not_enabled)?;
                session
                    .load_history_page(
                        conversation_id,
                        before.as_ref(),
                        IMPORT_HISTORY_PAGE_SIZE,
                        sync,
                    )
                    .await?
            };

            report.undecryptable = report.undecryptable.saturating_add(page.undecryptable);

            for m in page.messages {
                if m.conflict {
                    report.skipped_conflicts += 1;
                    continue;
                }
                let (MessageSource::Sender | MessageSource::Owner, Some(sender)) =
                    (m.source, m.sender.clone())
                else {
                    report.skipped_unattributed += 1;
                    continue;
                };
                if m.message_id.is_empty()
                    || m.message_id.len() > MAX_IMPORTED_MESSAGE_ID_LEN
                    || m.message_id.chars().any(char::is_control)
                {
                    report.skipped_undecodable += 1;
                    continue;
                }
                let Ok(payload) = MLSMessagePayload::decode(&m.frame) else {
                    report.skipped_undecodable += 1;
                    continue;
                };
                if !payload.is_displayable() {
                    report.skipped_undecodable += 1;
                    continue;
                }
                let sender_root =
                    crate::orchestrator::credential_binding::credential_root_did(&sender);
                let is_own = sender_root == receiver_root;
                match payload.checked_group_invitation() {
                    Ok(Some(reference)) => {
                        if reference.invited_by_did != sender_root
                            || (!is_own && reference.recipient_did != receiver_root)
                        {
                            report.skipped_undecodable += 1;
                            continue;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        report.skipped_undecodable += 1;
                        continue;
                    }
                }
                if self
                    .durable_message_exists_in_conversation(conversation_id, &m.message_id)
                    .await?
                    || self.storage().message_exists(&m.message_id).await?
                {
                    report.already_present += 1;
                    continue;
                }
                let timestamp = Utc
                    .timestamp_millis_opt(i64::try_from(m.timestamp).unwrap_or(i64::MAX))
                    .single()
                    .unwrap_or_else(Utc::now);
                let message = Message {
                    id: m.message_id,
                    conversation_id: conversation_id.to_owned(),
                    is_own,
                    sender_did: sender,
                    text: payload.display_text(),
                    timestamp,
                    epoch: 0,
                    sequence_number: 0,
                    delivery_status: None,
                    payload_json: String::from_utf8(m.frame).ok(),
                };
                self.storage().store_message(&message).await?;
                report.imported += 1;
            }

            let Some(next) = next_cursor else {
                break;
            };
            if !seen_cursors.insert((next.timestamp, next.message_id.clone())) {
                return Err(OrchestratorError::Api(
                    "labyrinth history pagination returned a repeated cursor".into(),
                ));
            }
            before = Some(next);
        }
        Ok(report)
    }

    pub async fn labyrinth_revoke_device(&self, device_key_hex: &str) -> Result<u64> {
        let key: [u8; 32] = hex::decode(device_key_hex)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                OrchestratorError::InvalidInput("labyrinth device key must be 32 hex bytes".into())
            })?;
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        let session = Self::ensure_opened_in_slot(&mut guard, deps)
            .await?
            .ok_or_else(not_enabled)?;
        session.revoke_device(key).await
    }

    pub async fn labyrinth_revoke_chat_device(&self, chat_key: [u8; 32]) -> Result<Vec<u64>> {
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        match Self::ensure_opened_in_slot(&mut guard, deps).await? {
            Some(session) => session.revoke_chat_device(chat_key).await,
            None => Ok(Vec::new()),
        }
    }

    pub async fn labyrinth_sign_out(&self) -> Result<bool> {
        let deps = self.labyrinth_deps().await?;
        let did = deps.did.clone();
        self.labyrinth_stop_archive_worker();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let _lifecycle = lifecycle.lock().await;
        *self.labyrinth_slot().lock().await = None;
        let queue = self.labyrinth_queue_store();
        let had = deps.vault.has_state(&did).map_err(OrchestratorError::Mls)?;
        deps.vault.delete(&did).map_err(OrchestratorError::Mls)?;
        deps.placements
            .delete(&did)
            .map_err(OrchestratorError::Mls)?;
        deps.placements
            .delete(&thread_placement_key(&did))
            .map_err(OrchestratorError::Mls)?;
        queue.clear(&did)?;
        queue.clear_status_preserving_deletion(&did)?;
        Ok(had)
    }

    pub async fn labyrinth_delete_account(&self) -> Result<PurgeReport> {
        self.labyrinth_stop_archive_worker();
        let deps = self.labyrinth_deps().await?;
        let queue = self.labyrinth_queue_store();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let _lifecycle = lifecycle.lock().await;
        let mut guard = self.labyrinth_slot().lock().await;

        let saved_placement = deps
            .placements
            .load(&deps.did)
            .map_err(OrchestratorError::Mls)?
            .map(|p| {
                String::from_utf8(p).map_err(|_| {
                    OrchestratorError::Storage("invalid Labyrinth mailbox placement".into())
                })
            })
            .transpose()?;
        let prior = queue.load_status(&deps.did)?.pending_remote_deletion;
        let mailbox_placement = prior
            .as_ref()
            .and_then(|pending| pending.mailbox_placement.clone())
            .or(saved_placement);
        let mut conversation_spaces = deps
            .conversation_spaces()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        if let Some(pending) = &prior {
            conversation_spaces.extend(pending.conversation_spaces.iter().cloned());
        }
        conversation_spaces.sort();
        conversation_spaces.dedup();
        let space_cleanup_required = deps.space.is_some()
            || !conversation_spaces.is_empty()
            || prior.as_ref().is_some_and(|p| p.space_cleanup_required);
        let parsed_placement = mailbox_placement
            .as_deref()
            .map(|p| {
                Placement::parse(p.as_bytes()).ok_or_else(|| {
                    OrchestratorError::Storage("invalid Labyrinth deletion placement".into())
                })
            })
            .transpose()?;

        queue.update_status(&deps.did, &mut |s| {
            if s.pending_remote_deletion.is_none() {
                s.pending_remote_deletion = Some(PendingDeletion {
                    attempts: 0,
                    last_error: "deletion interrupted before completion".into(),
                    since_ms: now_ms(),
                    mailbox_placement: mailbox_placement.clone(),
                    conversation_spaces: conversation_spaces.clone(),
                    space_cleanup_required,
                });
            } else if let Some(pending) = &mut s.pending_remote_deletion {
                pending.mailbox_placement = mailbox_placement.clone();
                pending.conversation_spaces = conversation_spaces.clone();
                pending.space_cleanup_required = space_cleanup_required;
            }
        })?;

        let key = deps.signer.public_key();
        let open = match guard.take() {
            Some(s) if s.is_for(&deps.did, &key) => Ok(Some(s)),
            _ => deps.clone().open().await,
        };
        let had_saved = deps
            .vault
            .has_state(&deps.did)
            .map_err(OrchestratorError::Mls)?;
        let mut report = match open {
            Ok(Some(mut s)) => s.purge_account().await?,
            Ok(None) if !had_saved => PurgeReport {
                remote_pending: deps.delete_account_remote_at(parsed_placement).await.err(),
                ..PurgeReport::default()
            },
            Ok(None) => PurgeReport::default(),
            Err(e) => PurgeReport {
                remote_pending: Some(labyrinth::Error::Backend(format!(
                    "could not open the session: {e}"
                ))),
                ..PurgeReport::default()
            },
        };
        if let Err(error) = deps
            .delete_conversation_records(&conversation_spaces, space_cleanup_required)
            .await
        {
            report.remote_pending.get_or_insert(error);
        }
        deps.vault
            .delete(&deps.did)
            .map_err(OrchestratorError::Mls)?;
        deps.placements
            .delete(&deps.did)
            .map_err(OrchestratorError::Mls)?;
        deps.placements
            .delete(&thread_placement_key(&deps.did))
            .map_err(OrchestratorError::Mls)?;
        queue.clear(&deps.did)?;
        let pending = report.remote_pending.as_ref().map(|e| PendingDeletion {
            attempts: 1,
            last_error: e.to_string(),
            since_ms: now_ms(),
            mailbox_placement,
            conversation_spaces,
            space_cleanup_required,
        });
        queue.update_status(&deps.did, &mut |s| {
            s.pending_remote_deletion = pending.clone();
            s.excluded_members.clear();
            s.dropped.clear();
        })?;
        if pending.is_none() {
            queue.clear_status_preserving_deletion(&deps.did)?;
        }
        if let Some(error) = &report.remote_pending {
            tracing::warn!(%error, "labyrinth: remote account deletion failed; pending retry saved");
        }
        Ok(report)
    }

    pub(crate) fn labyrinth_queue_store(&self) -> Arc<dyn ArchiveQueueStore> {
        Arc::new(MlsArchiveQueue(self.mls_context().clone()))
    }

    pub(crate) fn labyrinth_stop_archive_worker(&self) {
        self.labyrinth_archive().stop();
    }

    fn labyrinth_start_archive_worker(&self, deps: &SessionDeps) -> Result<()> {
        let store = self.labyrinth_queue_store();
        let already = store.list(&deps.did)?.len();
        self.labyrinth_archive().ensure(already);
        Ok(())
    }

    pub fn labyrinth_set_archive_policy(&self, config: QueueConfig) {
        self.labyrinth_archive().set_config(config);
    }

    pub async fn labyrinth_flush_archive(&self) -> Result<usize> {
        if !self.labyrinth_retry_remote_deletion().await? {
            return Ok(0);
        }
        let deps = self.labyrinth_deps().await?;
        let report = flush_in_slot(
            self.labyrinth_slot().clone(),
            deps.clone(),
            self.labyrinth_queue_store(),
        )
        .await?;
        let n = report.left_queue();
        self.labyrinth_archive().flushed(n);
        self.labyrinth_start_archive_worker(&deps)?;
        Ok(n)
    }

    pub(crate) async fn labyrinth_archive_sent(
        &self,
        conversation_id: &str,
        message_id: &str,
        timestamp_ms: u64,
        frame: &[u8],
        mls_snapshot: Option<(String, u64, Vec<String>)>,
    ) {
        let result = async {
            let deps = self.labyrinth_deps().await?;
            let enabled = deps
                .vault
                .has_state(&deps.did)
                .map_err(OrchestratorError::Mls)?;
            if !enabled {
                return Ok(());
            }
            let (group_id_hex, mls_epoch, expected_member_dids) =
                mls_snapshot.ok_or_else(|| {
                    OrchestratorError::Storage(
                    "labyrinth: cannot archive sent message without local OpenMLS roster snapshot"
                        .into(),
                )
                })?;
            if expected_member_dids.is_empty() {
                return Err(OrchestratorError::Storage(
                    "labyrinth: local OpenMLS roster snapshot is empty".into(),
                ));
            }
            let row =
                PendingArchive::new(&deps.did, conversation_id, message_id, timestamp_ms, frame)
                    .with_mls_snapshot(group_id_hex, mls_epoch, expected_member_dids);
            self.labyrinth_start_archive_worker(&deps)?;
            let store = self.labyrinth_queue_store();
            let queued = enqueue(store.as_ref(), &row)?;
            if queued {
                self.labyrinth_archive().enqueued();
                if self.labyrinth_archive().should_auto_flush() {
                    let _ = self.labyrinth_flush_archive().await;
                }
            }
            Ok::<_, OrchestratorError>(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(conversation_id, %error, "labyrinth: queueing a sent message failed");
        }
    }

    /// `[CB-22]` / `[CB-37]` involuntary-removal rescue: archives locally cached
    /// decrypted conversation messages (`storage().get_messages`) and any pending
    /// outbox rows for `conversation_id` into the caller's personal mailbox Space
    /// using owner-mode `v5` (`KIND_ATTRIBUTED_FRAME = 0x03`, preserving each
    /// message's `sender_did`) before local history is deleted or after Space
    /// access is revoked (`Forbidden`).
    pub async fn labyrinth_rescue_cached_history(&self, conversation_id: &str) -> Result<usize> {
        const PAGE_LIMIT: u32 = 500;
        const MAX_PAGES: usize = 20;
        const CHUNK_SIZE: usize = 100;

        let deps = self.labyrinth_deps().await?;
        let enabled = deps
            .vault
            .has_state(&deps.did)
            .map_err(OrchestratorError::Mls)?;
        if !enabled {
            return Ok(0);
        }

        let mut candidates: std::collections::BTreeMap<String, (u64, String, Vec<u8>)> =
            std::collections::BTreeMap::new();
        let mut before_seq: Option<u64> = None;

        for _ in 0..MAX_PAGES {
            let page = match self
                .storage()
                .get_messages(conversation_id, PAGE_LIMIT, before_seq)
                .await
            {
                Ok(msgs) => msgs,
                Err(_) => break,
            };
            if page.is_empty() {
                break;
            }
            let prev_len = candidates.len();
            let mut min_seq: Option<u64> = None;
            for msg in &page {
                if msg.sequence_number > 0 {
                    min_seq = Some(match min_seq {
                        Some(cur) => cur.min(msg.sequence_number),
                        None => msg.sequence_number,
                    });
                }
                if msg.id.is_empty() || msg.id.len() > 128 || msg.id.chars().any(char::is_control) {
                    continue;
                }
                let sender_root =
                    crate::orchestrator::credential_binding::credential_root_did(&msg.sender_did)
                        .to_owned();
                if !sender_root.starts_with("did:") {
                    continue;
                }
                let frame = if let Some(ref pj) = msg.payload_json {
                    if MLSMessagePayload::decode(pj.as_bytes()).is_ok_and(|p| p.is_displayable()) {
                        pj.as_bytes().to_vec()
                    } else if !msg.text.trim().is_empty() {
                        match serde_json::to_vec(&MLSMessagePayload::text(&msg.text)) {
                            Ok(b) => b,
                            Err(_) => continue,
                        }
                    } else {
                        continue;
                    }
                } else if !msg.text.trim().is_empty() {
                    match serde_json::to_vec(&MLSMessagePayload::text(&msg.text)) {
                        Ok(b) => b,
                        Err(_) => continue,
                    }
                } else {
                    continue;
                };
                let ts_ms = u64::try_from(msg.timestamp.timestamp_millis().max(0)).unwrap_or(0);
                candidates
                    .entry(msg.id.clone())
                    .or_insert((ts_ms, sender_root, frame));
            }
            if candidates.len() == prev_len || page.len() < PAGE_LIMIT as usize {
                break;
            }
            match min_seq {
                Some(seq) if before_seq.is_none_or(|b| seq < b) => before_seq = Some(seq),
                _ => break,
            }
        }

        let store = self.labyrinth_queue_store();
        let mut queued_ids = Vec::new();
        for row in store.list(&deps.did)? {
            if row.conversation_id != conversation_id {
                continue;
            }
            if let Ok(frame) = row.frame_bytes() {
                queued_ids.push(row.message_id.clone());
                candidates.entry(row.message_id).or_insert((
                    row.timestamp_ms,
                    deps.did.clone(),
                    frame,
                ));
            }
        }

        if candidates.is_empty() {
            return Ok(0);
        }

        let mut guard = self.labyrinth_slot().lock().await;
        let Some(session) = Self::ensure_opened_in_slot(&mut guard, deps.clone()).await? else {
            return Ok(0);
        };

        let existing_owner_ids: std::collections::HashSet<String> = match session
            .load_history(conversation_id, labyrinth::store::TimeRange::ALL)
            .await
        {
            Ok(h) => h
                .messages
                .into_iter()
                .filter(|m| m.source == MessageSource::Owner)
                .map(|m| m.message_id)
                .collect(),
            Err(_) => std::collections::HashSet::new(),
        };

        let mut to_archive: Vec<(String, u64, String, Vec<u8>)> = candidates
            .into_iter()
            .filter(|(msg_id, _)| !existing_owner_ids.contains(msg_id))
            .map(|(msg_id, (ts, sender, frame))| (ts, msg_id, sender, frame))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(ts, msg_id, sender, frame)| (msg_id, ts, sender, frame))
            .collect();
        to_archive.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));

        let mut total_archived = 0usize;
        for chunk in to_archive.chunks(CHUNK_SIZE) {
            match session
                .archive_owner_fallback(conversation_id, chunk)
                .await?
            {
                Ok(n) => total_archived += n,
                Err(e) => return Err(super::map_error(e)),
            }
        }

        if !queued_ids.is_empty() {
            for msg_id in &queued_ids {
                store.remove(&deps.did, msg_id)?;
            }
            self.labyrinth_archive().flushed(queued_ids.len());
        }

        Ok(total_archived)
    }

    pub(crate) async fn labyrinth_rearchive_on_kick(&self, conversation_id: &str) {
        match self.labyrinth_rescue_cached_history(conversation_id).await {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(
                    conversation_id,
                    n,
                    "labyrinth: rescued cached history into personal mailbox Space after removal"
                );
            }
            Err(error) => {
                tracing::warn!(
                    conversation_id,
                    %error,
                    "labyrinth: rescuing cached history into personal mailbox Space failed"
                );
            }
        }
    }

    pub(crate) async fn labyrinth_rearchive_before_leave(&self, conversation_id: &str) {
        let space_result = async {
            let deps = self.labyrinth_deps().await?;
            let mut guard = self.labyrinth_slot().lock().await;
            match Self::ensure_opened_in_slot(&mut guard, deps).await? {
                Some(session) => session
                    .rearchive_before_leave(conversation_id)
                    .await
                    .map(Some),
                None => Ok(None),
            }
        }
        .await;
        match space_result {
            Ok(Some(n)) => {
                tracing::info!(conversation_id, n, "labyrinth: re-archived before leave")
            }
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    conversation_id,
                    %error,
                    "labyrinth: Space re-archive before leave failed; rescuing local cache via owner fallback"
                )
            }
        }
        // Also rescue any locally cached messages or queued outbox rows not yet in the Space
        // (covers both unsent/unflushed local cache and leave-vs-kick Forbidden races).
        self.labyrinth_rearchive_on_kick(conversation_id).await;
    }
}

pub(super) fn not_enabled() -> OrchestratorError {
    OrchestratorError::InvalidInput(
        "labyrinth: history backup is not enabled on this device".into(),
    )
}
