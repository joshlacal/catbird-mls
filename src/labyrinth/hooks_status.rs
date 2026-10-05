//! Orchestrator hooks for what Labyrinth background work could not do
//! (labyrinth review 2): the archive status, quarantine retry, the
//! user-confirmed re-pin after a peer reset ([CB-29]), the pending remote
//! account deletion, and the thread listing with unreachable sequencers.

use std::sync::Arc;
use std::time::Duration;

use labyrinth::client::{RepinProposal, ThreadList};

use super::hooks::{join_error, not_enabled};
use super::queue::{retry_quarantined, ArchiveQueueStore, PendingArchive};
use super::session::SessionDeps;
use super::status::ArchiveStatus;
use crate::orchestrator::api_client::MLSAPIClient;
use crate::orchestrator::credentials::CredentialStore;
use crate::orchestrator::error::Result;
use crate::orchestrator::mls_provider::MlsCryptoContext;
use crate::orchestrator::storage::MLSStorageBackend;
use crate::orchestrator::MLSOrchestrator;

/// [`MLSOrchestrator::labyrinth_archive_status`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveStatusReport {
    /// Rows waiting to be archived (not quarantined).
    pub pending: usize,
    /// Rows the flush skips until [`MLSOrchestrator::labyrinth_retry_quarantined`].
    pub quarantined: Vec<PendingArchive>,
    /// Excluded members, dropped rows and a pending remote deletion.
    pub status: ArchiveStatus,
}

/// Retries a pending remote deletion once. `Ok(true)`: nothing is pending
/// (any more). `Ok(false)`: it is still pending (the attempt is recorded).
fn retry_deletion_blocking(deps: &SessionDeps, store: &dyn ArchiveQueueStore) -> Result<bool> {
    if store
        .load_status(&deps.did)?
        .pending_remote_deletion
        .is_none()
    {
        return Ok(true);
    }
    let result = deps.delete_account_remote();
    store.update_status(
        &deps.did,
        &mut |s| match (&result, &mut s.pending_remote_deletion) {
            (Ok(()), p) => *p = None,
            (Err(e), Some(p)) => {
                p.attempts += 1;
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

impl<S, A, C, M> MLSOrchestrator<S, A, C, M>
where
    S: MLSStorageBackend + 'static,
    A: MLSAPIClient + 'static,
    C: CredentialStore + 'static,
    M: MlsCryptoContext + 'static,
{
    /// What the archive queue and account deletion could not do: pending
    /// and quarantined rows, excluded members (with `needs_repin` for pin
    /// conflicts), dropped rows and a pending remote deletion.
    pub async fn labyrinth_archive_status(&self) -> Result<ArchiveStatusReport> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        tokio::task::spawn_blocking(move || {
            let (quarantined, pending): (Vec<_>, Vec<_>) =
                store.list(&did)?.into_iter().partition(|r| r.quarantined);
            Ok(ArchiveStatusReport {
                pending: pending.len(),
                quarantined,
                status: store.load_status(&did)?,
            })
        })
        .await
        .map_err(join_error)?
    }

    /// Un-quarantines every row and flushes. Returns how many were
    /// quarantined.
    pub async fn labyrinth_retry_quarantined(&self) -> Result<usize> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        let n = tokio::task::spawn_blocking(move || retry_quarantined(store.as_ref(), &did))
            .await
            .map_err(join_error)??;
        if n > 0 {
            self.labyrinth_flush_archive().await?;
        }
        Ok(n)
    }

    /// Forgets the recorded member exclusions and dropped rows (the user
    /// has seen them). A pending remote deletion is kept.
    pub async fn labyrinth_clear_archive_reports(&self) -> Result<()> {
        let did = self.require_user_did().await?;
        let store = self.labyrinth_queue_store();
        tokio::task::spawn_blocking(move || {
            store.update_status(&did, &mut |s| {
                s.excluded_members.clear();
                s.dropped.clear();
            })
        })
        .await
        .map_err(join_error)?
    }

    /// The safety-number change to show the user before re-pinning `did`
    /// after it reset its mailbox ([CB-29]). Fails unless `did`'s current
    /// chain verifies from a genesis attested by one of its current chat
    /// devices. Changes nothing.
    pub async fn labyrinth_propose_repin(&self, did: &str) -> Result<RepinProposal> {
        let did = did.to_owned();
        self.with_labyrinth(SessionDeps::open, move |s| s.propose_repin(&did))
            .await?
            .ok_or_else(not_enabled)
    }

    /// The user accepted the new safety number for `did`: re-pin it to
    /// `confirmed_head` (the proposal's head; a newer head fails and must
    /// be proposed again). Clears `did`'s pin-conflict exclusions and
    /// retries its quarantined rows.
    pub async fn labyrinth_repin_peer(&self, did: &str, confirmed_head: [u8; 32]) -> Result<()> {
        let peer = did.to_owned();
        self.with_labyrinth(SessionDeps::open, move |s| {
            s.repin_peer(&peer, confirmed_head)
        })
        .await?
        .ok_or_else(not_enabled)?;
        let me = self.require_user_did().await?;
        let (peer, store) = (did.to_owned(), self.labyrinth_queue_store());
        tokio::task::spawn_blocking(move || {
            store.update_status(&me, &mut |s| {
                s.excluded_members
                    .retain(|x| !(x.did == peer && x.needs_repin))
            })?;
            retry_quarantined(store.as_ref(), &me)
        })
        .await
        .map_err(join_error)??;
        Ok(())
    }

    /// The conversations this account has history in, plus the sequencer
    /// DSes mls-ds could not reach (`incomplete`: the list may miss their
    /// conversations; show it as partial).
    pub async fn labyrinth_list_threads(&self) -> Result<ThreadList> {
        self.with_labyrinth(SessionDeps::open, |s| s.list_threads())
            .await?
            .ok_or_else(not_enabled)
    }

    /// Retries a pending remote account deletion once. Returns `true`
    /// when nothing is pending any more.
    pub async fn labyrinth_retry_remote_deletion(&self) -> Result<bool> {
        let deps = self.labyrinth_deps().await?;
        let store = self.labyrinth_queue_store();
        tokio::task::spawn_blocking(move || retry_deletion_blocking(&deps, store.as_ref()))
            .await
            .map_err(join_error)?
    }

    /// Retries the pending remote deletion in the background with
    /// exponential backoff (2 s doubling to 10 min, for this process's
    /// lifetime or until it succeeds). The record stays saved, so a later
    /// launch retries too.
    pub(super) fn labyrinth_spawn_deletion_retry(&self, deps: SessionDeps) {
        let store: Arc<dyn ArchiveQueueStore> = self.labyrinth_queue_store();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(2);
            loop {
                tokio::time::sleep(delay).await;
                let (d, s) = (deps.clone(), store.clone());
                match tokio::task::spawn_blocking(move || retry_deletion_blocking(&d, s.as_ref()))
                    .await
                {
                    Ok(Ok(true)) => return,
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "labyrinth: deletion retry could not run")
                    }
                    Err(error) => {
                        tracing::warn!(%error, "labyrinth: deletion retry task failed")
                    }
                }
                delay = (delay * 2).min(Duration::from_secs(600));
            }
        });
    }
}
