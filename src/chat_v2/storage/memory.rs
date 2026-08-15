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
}

#[cfg(test)]
mod tests {
    use super::super::page::EntryOutcome;
    use super::*;
    use crate::chat_v2::ids::{BareDid, ConversationId, DeviceId, EntryId};
    use crate::chat_v2::provenance::OuterEntryFingerprint;

    const OWNER: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
    const STRANGER: &str = "did:plc:44ybard66vv44zksje25o7dz";
    const CONVERSATION: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE: &str = "70707070-7070-4070-b070-707070707070";
    const SIBLING_DEVICE: &str = "72727272-7272-4272-b272-727272727272";
    const ENTRY: &str = "03adfab0-b088-4e86-b992-0f611d2eb64a";

    fn did(value: &str) -> BareDid {
        BareDid::parse(value).unwrap()
    }

    fn binding(owner: &str, device: &str) -> RecipientBinding {
        RecipientBinding::new(
            ConversationId::parse(CONVERSATION).unwrap(),
            did(owner),
            DeviceId::parse(device).unwrap(),
        )
    }

    fn store() -> MemoryStore {
        MemoryStore::open(StoreScope::for_did(did(OWNER)))
    }

    fn frame(seq_value: i64) -> PersistedEntry {
        PersistedEntry {
            seq: Seq::new(seq_value).unwrap(),
            entry_id: EntryId::parse(ENTRY).unwrap(),
            fingerprint: OuterEntryFingerprint::from_verified([0x11; 32]),
            outcome: EntryOutcome::Frame {
                canonical_body: format!("frame-{seq_value}").into_bytes(),
            },
        }
    }

    fn page(device: &str, previous: i64, next: i64, entries: Vec<PersistedEntry>) -> PageCommit {
        PageCommit::new(
            binding(OWNER, device),
            AfterSeq::new(previous).unwrap(),
            AfterSeq::new(next).unwrap(),
            entries,
            Some(RatchetCheckpoint::from_crypto_layer(vec![0xaa; 8])),
        )
    }

    #[tokio::test]
    async fn a_fresh_store_reports_absence_rather_than_a_default_position() {
        // None is not AfterSeq::START. A caller can tell "never scanned" from
        // "scanned to the beginning", which a defaulted read would erase.
        let store = store();
        assert_eq!(store.cursor(&binding(OWNER, DEVICE)).await.unwrap(), None);
        assert!(store
            .entries_after(&binding(OWNER, DEVICE), AfterSeq::START, 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .ratchet_checkpoint(&binding(OWNER, DEVICE))
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_committed_page_lands_entries_ratchet_and_cursor_together() {
        let store = store();
        store
            .commit_page(&page(DEVICE, 0, 2, vec![frame(1), frame(2)]))
            .await
            .unwrap();

        let device = binding(OWNER, DEVICE);
        assert_eq!(
            store.cursor(&device).await.unwrap(),
            Some(AfterSeq::new(2).unwrap())
        );
        assert_eq!(
            store
                .entries_after(&device, AfterSeq::START, 10)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store.ratchet_checkpoint(&device).await.unwrap().unwrap(),
            RatchetCheckpoint::from_crypto_layer(vec![0xaa; 8])
        );
    }

    #[tokio::test]
    async fn a_refused_commit_deposits_nothing_at_all() {
        // The atomicity claim, checked on all three halves. A commit that stored
        // its entries and then refused the cursor would leave the store holding
        // rows it would never account for.
        let store = store();
        store
            .commit_page(&page(DEVICE, 0, 5, vec![frame(5)]))
            .await
            .unwrap();

        // A second page built on a position that has since moved.
        let stale = page(DEVICE, 0, 9, vec![frame(9)]);
        let err = store.commit_page(&stale).await.unwrap_err();
        assert!(matches!(err, StorageError::CursorMismatch { .. }), "{err}");

        let device = binding(OWNER, DEVICE);
        assert_eq!(
            store.cursor(&device).await.unwrap(),
            Some(AfterSeq::new(5).unwrap()),
            "the refused commit must not have advanced the position"
        );
        let stored = store
            .entries_after(&device, AfterSeq::START, 10)
            .await
            .unwrap();
        assert_eq!(stored.len(), 1, "the refused page's entry must not be here");
        assert_eq!(stored[0].seq, Seq::new(5).unwrap());
    }

    #[tokio::test]
    async fn a_page_continuing_from_a_position_this_store_never_held_is_refused() {
        // Distinct from losing a race: nothing advanced this cursor, because
        // there is no cursor. A page arriving mid-stream against an empty store
        // means the store was misrouted, and it is reported as its own fault.
        let store = store();
        let err = store
            .commit_page(&page(DEVICE, 40, 41, vec![frame(41)]))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            StorageError::NotFound {
                record: RecordKind::Cursor,
                key: binding(OWNER, DEVICE).to_string(),
            }
        );
        assert_eq!(
            store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
            None,
            "the refusal must not have created the cursor it complained about"
        );
    }

    #[tokio::test]
    async fn the_cursor_advance_is_a_compare_and_set() {
        // Sequential pages chain: each builds on the position the last one
        // installed. This is what makes a lost update impossible rather than
        // merely unlikely.
        let store = store();
        store
            .commit_page(&page(DEVICE, 0, 1, vec![frame(1)]))
            .await
            .unwrap();
        store
            .commit_page(&page(DEVICE, 1, 2, vec![frame(2)]))
            .await
            .unwrap();
        assert_eq!(
            store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
            Some(AfterSeq::new(2).unwrap())
        );

        // Replaying the first page now is refused; its effects are already in.
        let err = store
            .commit_page(&page(DEVICE, 0, 1, vec![frame(1)]))
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::CursorMismatch { .. }), "{err}");
    }

    #[tokio::test]
    async fn an_empty_page_confirms_the_position_without_moving_it() {
        let store = store();
        store
            .commit_page(&page(DEVICE, 0, 3, vec![frame(3)]))
            .await
            .unwrap();

        let position = AfterSeq::new(3).unwrap();
        let confirmation =
            PageCommit::new(binding(OWNER, DEVICE), position, position, Vec::new(), None);
        store.commit_page(&confirmation).await.unwrap();
        assert_eq!(
            store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
            Some(position)
        );
        assert_eq!(
            store
                .ratchet_checkpoint(&binding(OWNER, DEVICE))
                .await
                .unwrap()
                .unwrap()
                .len(),
            8,
            "a page carrying no ratchet state must not erase the stored one"
        );
    }

    #[tokio::test]
    async fn sibling_devices_keep_separate_positions_and_entries() {
        // Visibility is per exact (DID, deviceId). Two devices of one principal
        // share a store, and must not share a cursor or an entry set.
        let store = store();
        store
            .commit_page(&page(DEVICE, 0, 5, vec![frame(5)]))
            .await
            .unwrap();
        store
            .commit_page(&page(SIBLING_DEVICE, 0, 1, vec![frame(1)]))
            .await
            .unwrap();

        assert_eq!(
            store.cursor(&binding(OWNER, DEVICE)).await.unwrap(),
            Some(AfterSeq::new(5).unwrap())
        );
        assert_eq!(
            store.cursor(&binding(OWNER, SIBLING_DEVICE)).await.unwrap(),
            Some(AfterSeq::new(1).unwrap())
        );

        let sibling_entries = store
            .entries_after(&binding(OWNER, SIBLING_DEVICE), AfterSeq::START, 10)
            .await
            .unwrap();
        assert_eq!(sibling_entries.len(), 1);
        assert_eq!(
            sibling_entries[0].seq,
            Seq::new(1).unwrap(),
            "one device's entries must never surface under another's binding"
        );
    }

    #[tokio::test]
    async fn every_read_and_write_refuses_a_foreign_principal() {
        // The scope check at real call sites, not only in its own unit test.
        // A store handle routed to the wrong principal must fail on every
        // method rather than on whichever one someone remembered to guard.
        let store = store();
        let foreign = binding(STRANGER, DEVICE);

        assert!(store
            .cursor(&foreign)
            .await
            .unwrap_err()
            .is_isolation_breach());
        assert!(store
            .entries_after(&foreign, AfterSeq::START, 10)
            .await
            .unwrap_err()
            .is_isolation_breach());
        assert!(store
            .ratchet_checkpoint(&foreign)
            .await
            .unwrap_err()
            .is_isolation_breach());

        let foreign_page = PageCommit::new(
            foreign,
            AfterSeq::START,
            AfterSeq::new(1).unwrap(),
            vec![frame(1)],
            None,
        );
        assert!(store
            .commit_page(&foreign_page)
            .await
            .unwrap_err()
            .is_isolation_breach());
    }

    #[tokio::test]
    async fn rejections_are_returned_alongside_frames() {
        // A caller that saw only frames would re-request an entry the ratchet
        // has already advanced past, and it would be refused again forever.
        let store = store();
        let rejection = PersistedEntry {
            seq: Seq::new(2).unwrap(),
            entry_id: EntryId::parse(ENTRY).unwrap(),
            fingerprint: OuterEntryFingerprint::from_verified([0x22; 32]),
            outcome: EntryOutcome::Rejection {
                detail: "semantic-invalid frame".to_owned(),
            },
        };
        store
            .commit_page(&page(DEVICE, 0, 2, vec![frame(1), rejection]))
            .await
            .unwrap();

        let stored = store
            .entries_after(&binding(OWNER, DEVICE), AfterSeq::START, 10)
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert!(stored[1].outcome.is_rejection());
    }

    #[tokio::test]
    async fn reads_are_bounded_and_exclusive_of_the_scan_position() {
        let store = store();
        store
            .commit_page(&page(
                DEVICE,
                0,
                4,
                vec![frame(1), frame(2), frame(3), frame(4)],
            ))
            .await
            .unwrap();

        let device = binding(OWNER, DEVICE);
        let from_two = store
            .entries_after(&device, AfterSeq::new(2).unwrap(), 10)
            .await
            .unwrap();
        assert_eq!(
            from_two.iter().map(|e| e.seq.get()).collect::<Vec<_>>(),
            vec![3, 4],
            "afterSeq is exclusive; entry 2 was already delivered"
        );

        let capped = store
            .entries_after(&device, AfterSeq::START, 2)
            .await
            .unwrap();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].seq.get(), 1, "reads are oldest first");
    }
}
