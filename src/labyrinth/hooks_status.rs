//! Async orchestrator hooks for Labyrinth archive status, quarantine retry,
//! peer re-pinning (`[CB-29]`), pending remote deletion retry, and thread listing.

#[cfg(feature = "legacy-orchestrator")]
use labyrinth::client::{RepinProposal, ThreadList};

#[cfg(feature = "legacy-orchestrator")]
use super::hooks::not_enabled;
use super::queue::PendingArchive;
#[cfg(feature = "legacy-orchestrator")]
use super::queue::{retry_quarantined, ArchiveQueueStore};
#[cfg(feature = "legacy-orchestrator")]
use super::session::SessionDeps;
#[cfg(feature = "legacy-orchestrator")]
use super::space::Placement;
use super::status::ArchiveStatus;
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::api_client::MLSAPIClient;
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::credentials::CredentialStore;
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::error::{OrchestratorError, Result};
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::mls_provider::MlsCryptoContext;
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::storage::MLSStorageBackend;
#[cfg(feature = "legacy-orchestrator")]
use crate::orchestrator::MLSOrchestrator;

/// Legacy orchestrator archive status summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveStatusReport {
    /// Rows waiting to be archived (not quarantined).
    pub pending: usize,
    /// Rows skipped by flush until quarantine retry.
    pub quarantined: Vec<PendingArchive>,
    /// Excluded members, dropped rows, and any pending remote deletion.
    pub status: ArchiveStatus,
}

#[cfg(feature = "legacy-orchestrator")]
pub(super) async fn retry_deletion_async(
    deps: &SessionDeps,
    store: &dyn ArchiveQueueStore,
) -> Result<bool> {
    let Some(pending) = store.load_status(&deps.did)?.pending_remote_deletion else {
        return Ok(true);
    };
    let placement = pending
        .mailbox_placement
        .as_deref()
        .map(|p| {
            Placement::parse(p.as_bytes()).ok_or_else(|| {
                OrchestratorError::Storage("invalid Labyrinth deletion placement".into())
            })
        })
        .transpose()?;
    let result = match deps.delete_account_remote_at(placement).await {
        Ok(()) => {
            deps.delete_conversation_records(
                &pending.conversation_spaces,
                pending.space_cleanup_required,
            )
            .await
        }
        Err(e) => Err(e),
    };
    store.update_status(
        &deps.did,
        &mut |s| match (&result, &mut s.pending_remote_deletion) {
            (Ok(()), p) => *p = None,
            (Err(e), Some(p)) => {
                p.attempts = p.attempts.saturating_add(1);
                p.last_error = e.to_string();
            }
            (Err(_), None) => {}
        },
    )?;
    match result {
        Ok(()) => {
            tracing::info!("labyrinth: pending remote account deletion completed");
            Ok(true)
        }
        Err(error) => {
            tracing::warn!(%error, "labyrinth: remote account deletion still failing");
            Ok(false)
        }
    }
}

#[cfg(feature = "legacy-orchestrator")]
impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    pub async fn labyrinth_archive_status(&self) -> Result<ArchiveStatusReport> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        let (quarantined, pending): (Vec<_>, Vec<_>) =
            store.list(&did)?.into_iter().partition(|r| r.quarantined);
        Ok(ArchiveStatusReport {
            pending: pending.len(),
            quarantined,
            status: store.load_status(&did)?,
        })
    }

    pub async fn labyrinth_retry_quarantined(&self) -> Result<usize> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        let n = retry_quarantined(store.as_ref(), &did)?;
        if n > 0 {
            self.labyrinth_flush_archive().await?;
        }
        Ok(n)
    }

    pub async fn labyrinth_clear_archive_reports(&self) -> Result<()> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        store.update_status(&did, &mut |s| {
            s.excluded_members.clear();
            s.dropped.clear();
        })
    }

    pub async fn labyrinth_propose_repin(&self, did: &str) -> Result<RepinProposal> {
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        let key = deps.signer.public_key();
        if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
            *guard = deps.open().await?;
        }
        let session = guard.as_mut().ok_or_else(not_enabled)?;
        session.propose_repin(did).await
    }

    pub async fn labyrinth_repin_peer(&self, did: &str, confirmed_head: [u8; 32]) -> Result<()> {
        {
            let deps = self.labyrinth_deps().await?;
            let mut guard = self.labyrinth_slot().lock().await;
            let key = deps.signer.public_key();
            if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
                *guard = deps.open().await?;
            }
            let session = guard.as_mut().ok_or_else(not_enabled)?;
            session.repin_peer(did, confirmed_head).await?;
        }
        let me = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        store.update_status(&me, &mut |s| {
            s.excluded_members
                .retain(|x| !(x.did == did && x.needs_repin))
        })?;
        retry_quarantined(store.as_ref(), &me)?;
        Ok(())
    }

    pub async fn labyrinth_list_threads(&self) -> Result<ThreadList> {
        let deps = self.labyrinth_deps().await?;
        let mut guard = self.labyrinth_slot().lock().await;
        let key = deps.signer.public_key();
        if !guard.as_ref().is_some_and(|s| s.is_for(&deps.did, &key)) {
            *guard = deps.open().await?;
        }
        let session = guard.as_mut().ok_or_else(not_enabled)?;
        session.list_threads().await
    }

    pub async fn labyrinth_retry_remote_deletion(&self) -> Result<bool> {
        let deps = self.labyrinth_deps().await?;
        let store = self.labyrinth_queue_store();
        let lifecycle = self.labyrinth_archive().lifecycle_lock();
        let _lifecycle = lifecycle.lock().await;
        retry_deletion_async(&deps, store.as_ref()).await
    }
}
