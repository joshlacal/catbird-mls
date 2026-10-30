//! Orchestrator hooks: the async face of [`super::session`].
//!
//! Explicit operations (enable, recovery code, restore, history, revoke)
//! return errors. The automatic hooks on send and leave are best effort:
//! the MLS operation has already succeeded, so a Labyrinth failure is
//! logged and never fails the send or the leave. Each hook is a no-op
//! until the account has enabled Labyrinth on this device.

use std::sync::Arc;

use chrono::{TimeZone as _, Utc};
use labyrinth::client::{MessageSource, PurgeReport};
use labyrinth::store::TimeRange;
use serde_json::Value;

use super::queue::{
    enqueue, flush_in_slot, ArchiveQueueStore, MlsArchiveQueue, PendingArchive, QueueConfig,
};
use super::session::{HistoryPage, ImportReport, LabyrinthSession, SessionDeps};
use super::signer::{ChatKeySigner, OrchestratorChatSigner};
use super::space::{MlsPlacementVault, SpaceXrpcTransport};
use super::state::MlsStateVault;
use super::status::{now_ms, PendingDeletion};
use super::transport::{ApiGateway, GatewayXrpcTransport};
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::canonical_transport::derive_key_id;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::error::{OrchestratorError, Result};
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::types::{MLSMessagePayload, Message};
use crate::orchestrator::MLSOrchestrator;

/// The member DIDs Labyrinth addresses for a conversation ([CB-16]): the
/// participants of `getConversationState` that are active MLS members.
/// `labyrinthHead` is not required here: the directory lookup in
/// `resolve_roster` decides enrollment, so a server without the Labyrinth
/// schema still yields the right roster.
pub(crate) fn roster_members(conversation_state: &Value) -> Vec<String> {
    conversation_state["state"]["participants"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["status"].as_str().is_none_or(|s| s == "active"))
        .filter(|p| p["leafCount"].as_u64().is_none_or(|n| n > 0))
        .filter_map(|p| p["userDid"].as_str().map(str::to_owned))
        .collect()
}

pub(super) fn join_error(e: tokio::task::JoinError) -> OrchestratorError {
    OrchestratorError::Api(format!("labyrinth task failed: {e}"))
}

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// Session inputs for the current account and chat device.
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
        let runtime = tokio::runtime::Handle::current();
        let signer: Arc<dyn ChatKeySigner> = Arc::new(OrchestratorChatSigner {
            credentials: self.credentials().clone(),
            mls_context: self.mls_context().clone(),
            user_did: did.clone(),
            device_id: device_id.clone(),
            key_id: derive_key_id(&public_key),
            public_key,
            runtime: runtime.clone(),
        });
        let gateway = Arc::new(ApiGateway::new(self.api_client().clone(), runtime));
        let pds: Option<Arc<dyn labyrinth::store::pds::PdsRecords>> =
            if self.api_client().labyrinth_pds_enabled().await {
                Some(gateway.clone())
            } else {
                None
            };
        let space: Option<Arc<dyn labyrinth::store::xrpc::XrpcTransport>> =
            if self.api_client().labyrinth_space_enabled().await {
                Some(Arc::new(SpaceXrpcTransport::new(gateway.clone())))
            } else {
                None
            };
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
        })
    }

    /// Runs `f` on a blocking thread against this account's session.
    ///
    /// `open` decides what happens when the slot holds no session for the
    /// current account and chat key: it receives the deps and returns the
    /// session to install, or `None` to skip `f` (Labyrinth not enabled).
    pub(super) async fn with_labyrinth<R: Send + 'static>(
        &self,
        open: impl FnOnce(SessionDeps) -> Result<Option<LabyrinthSession>> + Send + 'static,
        f: impl FnOnce(&mut LabyrinthSession) -> Result<R> + Send + 'static,
    ) -> Result<Option<R>> {
        let deps = self.labyrinth_deps().await?;
        let slot = self.labyrinth_slot().clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            let key = deps.signer.public_key();
            if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
                *guard = None;
                *guard = open(deps)?;
            }
            match guard.as_mut() {
                Some(session) => f(session).map(Some),
                None => Ok(None),
            }
        })
        .await
        .map_err(join_error)?
    }

    /// Forgets the in-memory session (shutdown, account switch). The state
    /// stays saved and is reopened on the next Labyrinth call.
    pub fn labyrinth_close(&self) {
        *self
            .labyrinth_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// True if this device has a saved Labyrinth session for the account.
    pub async fn labyrinth_is_enabled(&self) -> Result<bool> {
        Ok(self
            .with_labyrinth(SessionDeps::open, |_| Ok(()))
            .await?
            .is_some())
    }

    /// Turns on encrypted history backup: opens the saved session, or
    /// creates the account's mailbox. Returns this device's Labyrinth device
    /// key (hex). If another device already created the mailbox this fails
    /// with a `labyrinth: store conflict` error; restore with a recovery
    /// code instead.
    ///
    /// A previous account deletion whose remote half is still pending is
    /// retried first; while it fails, enabling is refused (a new mailbox
    /// would be erased by the retry).
    pub async fn labyrinth_enable(&self) -> Result<String> {
        let key = self
            .labyrinth_enroll_after_deletion(false, SessionDeps::enable)
            .await?;
        self.labyrinth_start_archive_worker(self.labyrinth_deps().await?)
            .await?;
        Ok(key)
    }

    /// A new recovery code (show it to the user once).
    pub async fn labyrinth_create_recovery_code(&self) -> Result<String> {
        self.with_labyrinth(SessionDeps::open, |s| s.create_recovery_code())
            .await?
            .ok_or_else(not_enabled)
    }

    /// Enrolls this device into the account's mailbox from a recovery code.
    pub async fn labyrinth_restore_with_recovery_code(&self, code: &str) -> Result<String> {
        let code = code.to_owned();
        self.labyrinth_enroll_after_deletion(true, move |deps| {
            deps.restore_with_recovery_code(&code)
        })
        .await
    }

    async fn labyrinth_enroll_after_deletion(
        &self,
        replace: bool,
        enroll: impl FnOnce(SessionDeps) -> Result<LabyrinthSession> + Send + 'static,
    ) -> Result<String> {
        let deps = self.labyrinth_deps().await?;
        let store = self.labyrinth_queue_store();
        let slot = self.labyrinth_slot().clone();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        tokio::task::spawn_blocking(move || {
            let _lifecycle = lifecycle.lock().unwrap_or_else(|e| e.into_inner());
            // All explicit and background retries share this guard. No older
            // purge can remain in flight after enrollment begins, even when
            // the caller awaiting a blocking operation has been cancelled.
            if !super::hooks_status::retry_deletion_blocking(&deps, store.as_ref())? {
                return Err(OrchestratorError::Api(
                    "labyrinth: the previous account deletion is still pending on the server; \
                     retry when online"
                        .into(),
                ));
            }
            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            if replace
                || !guard
                    .as_ref()
                    .is_some_and(|s| s.is_for(&deps.did, &deps.signer.public_key()))
            {
                *guard = None;
                *guard = Some(enroll(deps)?);
            }
            guard
                .as_ref()
                .map(|s| s.device_key_hex())
                .ok_or_else(|| OrchestratorError::Api("labyrinth session missing".into()))
        })
        .await
        .map_err(join_error)?
    }

    /// Decrypted history of a conversation in `[from_ms, until_ms)`.
    pub async fn labyrinth_load_history(
        &self,
        conversation_id: &str,
        from_ms: Option<u64>,
        until_ms: Option<u64>,
    ) -> Result<HistoryPage> {
        let conversation_id = conversation_id.to_owned();
        let range = TimeRange { from_ms, until_ms };
        self.with_labyrinth(SessionDeps::open, move |s| {
            s.load_history(&conversation_id, range)
        })
        .await?
        .ok_or_else(not_enabled)
    }

    /// Loads a conversation's whole history and stores every attributable
    /// message this device does not have yet (a new or restored device).
    pub async fn labyrinth_import_history(&self, conversation_id: &str) -> Result<ImportReport> {
        let user_did = self.require_user_did().await?;
        let page = self
            .labyrinth_load_history(conversation_id, None, None)
            .await?;
        let mut report = ImportReport {
            undecryptable: page.undecryptable,
            ..ImportReport::default()
        };
        for m in page.messages {
            if m.conflict {
                report.skipped_conflicts += 1;
                continue;
            }
            let (MessageSource::Sender, Some(sender)) = (m.source, m.sender.clone()) else {
                report.skipped_unattributed += 1;
                continue;
            };
            let Ok(payload) = MLSMessagePayload::decode(&m.frame) else {
                report.skipped_undecodable += 1;
                continue;
            };
            if self.storage().message_exists(&m.message_id).await? {
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
                is_own: sender == user_did,
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
        Ok(report)
    }

    /// Revokes another device of the account by its Labyrinth device key
    /// (hex) and opens a new epoch without it. Returns the new epoch.
    /// Revoking a chat device ([`Self::remove_device`]) also revokes the
    /// Labyrinth device it enrolled, through
    /// [`Self::labyrinth_revoke_chat_device`].
    pub async fn labyrinth_revoke_device(&self, device_key_hex: &str) -> Result<u64> {
        let key: [u8; 32] = hex::decode(device_key_hex)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                OrchestratorError::InvalidInput("labyrinth device key must be 32 hex bytes".into())
            })?;
        self.with_labyrinth(SessionDeps::open, move |s| s.revoke_device(key))
            .await?
            .ok_or_else(not_enabled)
    }

    /// Revoke hook: after chat device `chat_key` was revoked, revokes the
    /// Labyrinth device(s) its chat binding names ([CB-36]) and returns the
    /// new epochs. A no-op until Labyrinth is enabled on this device.
    /// Rotations exclude unbound devices regardless, so a failure here
    /// delays the revocation to the next rotation; it never keeps the
    /// device in.
    pub async fn labyrinth_revoke_chat_device(&self, chat_key: [u8; 32]) -> Result<Vec<u64>> {
        Ok(self
            .with_labyrinth(SessionDeps::open, move |s| s.revoke_chat_device(chat_key))
            .await?
            .unwrap_or_default())
    }

    /// Sign-out / account removal on this device: drops the session and
    /// erases its saved state and its pending archive queue. The mailbox on
    /// mls-ds is kept, so the account can restore later with a recovery
    /// code. Returns whether anything was saved.
    pub async fn labyrinth_sign_out(&self) -> Result<bool> {
        let deps = self.labyrinth_deps().await?;
        let did = deps.did.clone();
        self.labyrinth_stop_archive_worker();
        let slot = self.labyrinth_slot().clone();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let queue = self.labyrinth_queue_store();
        tokio::task::spawn_blocking(move || {
            let _lifecycle = lifecycle.lock().unwrap_or_else(|e| e.into_inner());
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
            let had = deps
                .vault
                .load(&did)
                .map_err(OrchestratorError::Mls)?
                .is_some();
            deps.vault.delete(&did).map_err(OrchestratorError::Mls)?;
            deps.placements
                .delete(&did)
                .map_err(OrchestratorError::Mls)?;
            deps.placements
                .delete(&super::space::thread_placement_key(&did))
                .map_err(OrchestratorError::Mls)?;
            queue.clear(&did)?;
            Ok(had)
        })
        .await
        .map_err(join_error)?
    }

    /// Deletes the account's Labyrinth data everywhere (server-side
    /// `deleteAccountData`, PDS `mailboxKeys`), then this device's saved
    /// state and archive queue. Other devices of the account lose their
    /// mailbox; their own saved state is erased when they next sign out.
    ///
    /// The user can always delete: this device's state and queue are
    /// erased even when the remote half fails, or when the session cannot
    /// even be opened (offline). The remote half is then recorded as a
    /// pending deletion ([`PurgeReport::remote_pending`]; status
    /// `pending_remote_deletion`), retried in the background, at
    /// [`Self::labyrinth_flush_archive`] and before
    /// [`Self::labyrinth_enable`].
    pub async fn labyrinth_delete_account(&self) -> Result<PurgeReport> {
        self.labyrinth_stop_archive_worker();
        let deps = self.labyrinth_deps().await?;
        let retry_deps = deps.clone();
        let slot = self.labyrinth_slot().clone();
        let queue = self.labyrinth_queue_store();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let report = tokio::task::spawn_blocking(move || -> Result<PurgeReport> {
            let _lifecycle = lifecycle.lock().unwrap_or_else(|e| e.into_inner());
            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            // Write the retry intent before opening a network-backed session
            // or deleting local secrets. A crash at any later boundary must
            // leave an account-bound deletion to resume on the next launch.
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
                    super::space::Placement::parse(p.as_bytes()).ok_or_else(|| {
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
                _ => deps.clone().open(),
            };
            let saved = deps.vault.load(&deps.did).map_err(OrchestratorError::Mls)?;
            let mut report = match open {
                Ok(Some(mut s)) => s.purge_account()?,
                Ok(None) if saved.is_none() => PurgeReport {
                    remote_pending: deps.delete_account_remote_at(parsed_placement).err(),
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
            if let Err(error) =
                deps.delete_conversation_records(&conversation_spaces, space_cleanup_required)
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
                .delete(&super::space::thread_placement_key(&deps.did))
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
            })?;
            Ok(report)
        })
        .await
        .map_err(join_error)??;
        if let Some(error) = &report.remote_pending {
            tracing::warn!(%error, "labyrinth: remote account deletion failed; will retry");
            self.labyrinth_spawn_deletion_retry(retry_deps);
        }
        Ok(report)
    }

    /// The durable archive queue in the encrypted MLS database.
    pub(crate) fn labyrinth_queue_store(&self) -> Arc<dyn ArchiveQueueStore> {
        Arc::new(MlsArchiveQueue(self.mls_context().clone()))
    }

    /// Stops the background archive worker; pending rows stay saved.
    pub(crate) fn labyrinth_stop_archive_worker(&self) {
        self.labyrinth_archive().stop();
    }

    /// Starts the archive worker for the current account (no-op if it
    /// runs), counting rows a previous process left pending.
    async fn labyrinth_start_archive_worker(&self, deps: SessionDeps) -> Result<()> {
        let store = self.labyrinth_queue_store();
        let (did, s) = (deps.did.clone(), store.clone());
        let already = tokio::task::spawn_blocking(move || s.list(&did).map(|v| v.len()))
            .await
            .map_err(join_error)??;
        self.labyrinth_archive()
            .ensure(self.labyrinth_slot().clone(), deps, store, already);
        Ok(())
    }

    /// When the background worker flushes (default: 32 messages or 2 s).
    pub fn labyrinth_set_archive_policy(&self, config: QueueConfig) {
        self.labyrinth_archive().set_config(config);
        self.labyrinth_stop_archive_worker();
    }

    /// Archives every pending sent message now (for example before the app
    /// suspends, or at launch to drain what a killed process left). Returns
    /// how many left the queue.
    /// Also retries a pending remote account deletion first.
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
        self.labyrinth_start_archive_worker(deps).await?;
        Ok(n)
    }

    /// Send hook: queues a message this device just sent for the
    /// background archive worker ([`super::queue`]). Only a local database
    /// write happens here; no network call is added to the send. Best
    /// effort: a failure is logged and never fails the send.
    pub(crate) async fn labyrinth_archive_sent(
        &self,
        conversation_id: &str,
        message_id: &str,
        timestamp_ms: u64,
        frame: &[u8],
    ) {
        let result = async {
            let deps = self.labyrinth_deps().await?;
            let row =
                PendingArchive::new(&deps.did, conversation_id, message_id, timestamp_ms, frame);
            // Enabled on this device = a saved state exists.
            let (vault, did) = (deps.vault.clone(), deps.did.clone());
            let enabled = tokio::task::spawn_blocking(move || vault.load(&did))
                .await
                .map_err(join_error)?
                .map_err(OrchestratorError::Mls)?
                .is_some();
            if !enabled {
                return Ok(());
            }
            // Start (or keep) the worker first: it counts the rows already
            // pending, and this one is counted by `enqueued`.
            self.labyrinth_start_archive_worker(deps).await?;
            let store = self.labyrinth_queue_store();
            let queued = tokio::task::spawn_blocking(move || enqueue(store.as_ref(), &row))
                .await
                .map_err(join_error)??;
            if queued {
                self.labyrinth_archive().enqueued();
            }
            Ok::<_, OrchestratorError>(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(conversation_id, %error, "labyrinth: queueing a sent message failed");
        }
    }

    /// Leave hook ([CB-22]): copies the conversation's readable history into
    /// the account's mailbox before leaving. Best effort.
    pub(crate) async fn labyrinth_rearchive_before_leave(&self, conversation_id: &str) {
        let c = conversation_id.to_owned();
        let result = self
            .with_labyrinth(SessionDeps::open, move |s| s.rearchive_before_leave(&c))
            .await;
        match result {
            Ok(Some(n)) => {
                tracing::info!(conversation_id, n, "labyrinth: re-archived before leave")
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(conversation_id, %error, "labyrinth: re-archive before leave failed")
            }
        }
    }
}

pub(super) fn not_enabled() -> OrchestratorError {
    OrchestratorError::InvalidInput(
        "labyrinth: history backup is not enabled on this device".into(),
    )
}
