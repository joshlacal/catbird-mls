//! An in-memory reference store.
//!
//! # This is not a production store
//!
//! It holds nothing across process exit. It exists to prove three things that a
//! trait definition alone cannot:
//!
//! - that [`ChatV2Store`] is implementable with every method required, rather
//!   than being a shape that only compiles because twenty of its methods have
//!   defaults;
//! - that the atomic page commit can actually be implemented atomically, which
//!   is the claim [`super::page`] rests on;
//! - that the per-DID scope refuses a foreign principal at a real call site and
//!   not only in a unit test of the scope type.
//!
//! Platforms implement their own against a durable engine — GRDB on iOS, Room on
//! Android — opening a separate database file per DID. Nothing here should be
//! mistaken for that.
//!
//! # How atomicity is achieved
//!
//! Every fallible check runs before any state is touched, under one lock. That
//! is the same discipline `apply_terminal` uses in the reducer, and for the same
//! reason: a refusal that had already written half its effects would leave
//! durable state describing something that never happened. A test pins that a
//! refused commit deposits neither entries, nor a checkpoint, nor a cursor.

use super::super::cursor::AfterSeq;
use super::super::ids::Seq;
use super::super::interval::RecipientBinding;
use super::super::journal::{JournalEntry, OperationIdentity};
use super::super::reducer::ApplicationReducer;
use super::page::{PageCommit, PersistedEntry, RatchetCheckpoint};
use super::store::ChatV2Store;
use super::{RecordKind, StorageError, StoreScope};
use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

/// Everything one principal's store holds.
#[derive(Debug, Default)]
struct State {
    cursors: HashMap<RecipientBinding, AfterSeq>,
    entries: HashMap<RecipientBinding, BTreeMap<Seq, PersistedEntry>>,
    checkpoints: HashMap<RecipientBinding, RatchetCheckpoint>,
    journal: HashMap<OperationIdentity, JournalEntry>,
    schedules: HashMap<RecipientBinding, ApplicationReducer>,
}

/// A non-durable [`ChatV2Store`] for tests and for proving the trait's shape.
#[derive(Debug)]
pub struct MemoryStore {
    scope: StoreScope,
    state: Mutex<State>,
}

impl MemoryStore {
    /// Opens a store for exactly one principal.
    ///
    /// Mirrors the platform contract: a store is opened *for* a DID, and a
    /// second principal requires a second store rather than a second key.
    pub fn open(scope: StoreScope) -> Self {
        Self {
            scope,
            state: Mutex::new(State::default()),
        }
    }

    fn guard(&self, operation: &'static str) -> Result<MutexGuard<'_, State>, StorageError> {
        self.state.lock().map_err(|_| StorageError::Backend {
            operation,
            detail: "the in-memory store's lock was poisoned by an earlier panic".to_owned(),
        })
    }

    /// Confirms a page builds on the position this store actually holds.
    ///
    /// Split out so the check is visibly complete before any mutation begins.
    fn require_expected_cursor(state: &State, page: &PageCommit) -> Result<(), StorageError> {
        let binding = page.binding();
        match state.cursors.get(binding) {
            Some(stored) if *stored == page.previous_after_seq() => Ok(()),
            Some(stored) => Err(StorageError::CursorMismatch {
                binding: binding.clone(),
                page_built_on: page.previous_after_seq(),
                stored: *stored,
            }),
            // No stored position. Only a page that starts from the beginning
            // can be the first one; anything else continues from a position
            // this store never held, which is a misrouted store rather than a
            // lost race and is reported as the different thing it is.
            None if page.previous_after_seq() == AfterSeq::START => Ok(()),
            None => Err(StorageError::NotFound {
                record: RecordKind::Cursor,
                key: binding.to_string(),
            }),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl ChatV2Store for MemoryStore {
    fn scope(&self) -> &StoreScope {
        &self.scope
    }

    async fn cursor(&self, binding: &RecipientBinding) -> Result<Option<AfterSeq>, StorageError> {
        self.scope.require_binding_owner(binding)?;
        let state = self.guard("cursor")?;
        Ok(state.cursors.get(binding).copied())
    }

    async fn commit_page(&self, page: &PageCommit) -> Result<(), StorageError> {
        let binding = page.binding();
        self.scope.require_binding_owner(binding)?;
        let mut state = self.guard("commit_page")?;

        // Every fallible check first. Nothing below this line can fail, so the
        // effects and the position land together or the store is untouched.
        Self::require_expected_cursor(&state, page)?;

        let entries = state.entries.entry(binding.clone()).or_default();
        for entry in page.entries() {
            entries.insert(entry.seq, entry.clone());
        }
        if let Some(checkpoint) = page.ratchet() {
            state
                .checkpoints
                .insert(binding.clone(), checkpoint.clone());
        }
        state.cursors.insert(binding.clone(), page.next_after_seq());
        Ok(())
    }

    async fn entries_after(
        &self,
        binding: &RecipientBinding,
        after: AfterSeq,
        limit: u32,
    ) -> Result<Vec<PersistedEntry>, StorageError> {
        self.scope.require_binding_owner(binding)?;
        let state = self.guard("entries_after")?;
        let Some(entries) = state.entries.get(binding) else {
            return Ok(Vec::new());
        };
        Ok(entries
            .values()
            // `admits` is the append-log layer's own predicate for "above this
            // scan position". Reusing it keeps one definition of the exclusive
            // bound rather than restating it as a comparison here.
            .filter(|entry| after.admits(entry.seq))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn ratchet_checkpoint(
        &self,
        binding: &RecipientBinding,
    ) -> Result<Option<RatchetCheckpoint>, StorageError> {
        self.scope.require_binding_owner(binding)?;
        let state = self.guard("ratchet_checkpoint")?;
        Ok(state.checkpoints.get(binding).cloned())
    }

    async fn put_journal_entry(&self, entry: &JournalEntry) -> Result<(), StorageError> {
        self.scope.require_owner(&entry.identity().actor_did)?;
        let mut state = self.guard("put_journal_entry")?;
        // Stored verbatim: the same JournalEntry, not a re-encoding of it. Any
        // transformation on the way in is a transformation the server would
        // read as a different request.
        state
            .journal
            .insert(entry.identity().clone(), entry.clone());
        Ok(())
    }

    async fn journal_entry(
        &self,
        identity: &OperationIdentity,
    ) -> Result<Option<JournalEntry>, StorageError> {
        self.scope.require_owner(&identity.actor_did)?;
        let state = self.guard("journal_entry")?;
        Ok(state.journal.get(identity).cloned())
    }

    async fn put_schedule(&self, schedule: &ApplicationReducer) -> Result<(), StorageError> {
        let binding = schedule.binding();
        self.scope.require_binding_owner(binding)?;
        let mut state = self.guard("put_schedule")?;
        // Keyed by the exact binding, device included. A conversation-only key
        // would let a sibling device's schedule answer for this one.
        state.schedules.insert(binding.clone(), schedule.clone());
        Ok(())
    }

    async fn schedule(
        &self,
        binding: &RecipientBinding,
    ) -> Result<Option<ApplicationReducer>, StorageError> {
        self.scope.require_binding_owner(binding)?;
        let state = self.guard("schedule")?;
        Ok(state.schedules.get(binding).cloned())
    }

    async fn outstanding_journal_entries(&self) -> Result<Vec<JournalEntry>, StorageError> {
        let state = self.guard("outstanding_journal_entries")?;
        Ok(state
            .journal
            .values()
            // `should_submit` is the journal's own predicate for "outcome still
            // unknown". Restating it as a state match here would be a second
            // source of truth for which states are terminal.
            .filter(|entry| entry.should_submit())
            .cloned()
            .collect())
    }
}
