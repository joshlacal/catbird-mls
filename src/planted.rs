//! Named, runtime-selectable regressions for the pressure tank's calibration runs.
//!
//! Selection is thread-local and only takes effect with `feature = "sim"`. Wrap
//! the synchronous client call (not merely construction of a future) in
//! [`with_planted_bug`]. Selection is thread-local; dispatchers must capture
//! [`active_planted_bug`] before switching threads and restore it on the worker.

/// Real client and server-path regressions exercised by simulation oracles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlantedBug {
    P1KeepLoserStagedCommit,
    P2PrematureMergeBeforeServerAccept,
    P3NetworkInsideWriteTx,
    /// Omit the durable archive enqueue when recovering a previously reserved send.
    P4SkipLabyrinthEnqueueAfterSendRetry,
    /// Distribute a conversation MEK to a self-signed but unauthorized device epoch.
    P5WrapMekToUnverifiedDevice,
    P6OrderTimelineByEpochSeq,
    /// Server/simulator hook: keep application payload bytes after ack and archive flush.
    P8RetainServerCiphertextAfterAckAndFlush,
    /// Replace local MLS state with an external join after an application decrypt error.
    P9AutomatedForcedRejoinOnDecryptFailure,
    /// Skip cross-handle data-version cache eviction inside the next write transaction.
    P10SkipDataVersionCheckAfterNseAdvance,
    /// Revoke conversation Space membership before the removal commit is accepted.
    P11RevokeSpaceAccessBeforeKickedMemberFlushes,
    /// Re-decrypt a persisted message replay after reopening the account database.
    P12SkipMessageIdDedupeAfterCrashRestart,
    P13AdvanceSeqCursorBeforeDurableStore,
    /// Retire an uncertain commit's recovery journal and rebuild a fresh commit transition.
    P15NonIdempotentCommitSubmitRetry,
}

#[cfg(feature = "sim")]
thread_local! {
    static ACTIVE_BUG: std::cell::Cell<Option<PlantedBug>> = const { std::cell::Cell::new(None) };
}

/// Select a regression for subsequent client calls on this thread.
/// Has no effect in builds without `feature = "sim"`.
#[inline]
pub fn set_planted_bug(bug: Option<PlantedBug>) {
    #[cfg(feature = "sim")]
    ACTIVE_BUG.with(|active| active.set(bug));
    #[cfg(not(feature = "sim"))]
    let _ = bug;
}

/// Return this thread's scoped regression selection, or `None` without `sim`.
/// Compile-time `plant_p*` features are independent of this runtime selection.
#[inline]
pub fn active_planted_bug() -> Option<PlantedBug> {
    #[cfg(feature = "sim")]
    {
        ACTIVE_BUG.with(|active| active.get())
    }
    #[cfg(not(feature = "sim"))]
    {
        None
    }
}

/// Check a calibration hook; compiles to `false` outside simulation builds.
#[inline(always)]
pub fn is_planted_bug_active(bug: PlantedBug) -> bool {
    #[cfg(feature = "sim")]
    {
        if active_planted_bug() == Some(bug) {
            return true;
        }
        match bug {
            PlantedBug::P1KeepLoserStagedCommit => cfg!(feature = "plant_p1"),
            PlantedBug::P2PrematureMergeBeforeServerAccept => cfg!(feature = "plant_p2"),
            PlantedBug::P3NetworkInsideWriteTx => cfg!(feature = "plant_p3"),
            PlantedBug::P4SkipLabyrinthEnqueueAfterSendRetry => cfg!(feature = "plant_p4"),
            PlantedBug::P5WrapMekToUnverifiedDevice => cfg!(feature = "plant_p5"),
            PlantedBug::P6OrderTimelineByEpochSeq => cfg!(feature = "plant_p6"),
            PlantedBug::P8RetainServerCiphertextAfterAckAndFlush => cfg!(feature = "plant_p8"),
            PlantedBug::P9AutomatedForcedRejoinOnDecryptFailure => cfg!(feature = "plant_p9"),
            PlantedBug::P10SkipDataVersionCheckAfterNseAdvance => cfg!(feature = "plant_p10"),
            PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes => {
                cfg!(feature = "plant_p11")
            }
            PlantedBug::P12SkipMessageIdDedupeAfterCrashRestart => cfg!(feature = "plant_p12"),
            PlantedBug::P13AdvanceSeqCursorBeforeDurableStore => cfg!(feature = "plant_p13"),
            PlantedBug::P15NonIdempotentCommitSubmitRetry => cfg!(feature = "plant_p15"),
        }
    }
    #[cfg(not(feature = "sim"))]
    {
        let _ = bug;
        false
    }
}

/// Run a client operation with a scoped selection, restoring it even on unwind.
/// Nested `None` temporarily disables an outer selection.
pub fn with_planted_bug<R>(bug: Option<PlantedBug>, operation: impl FnOnce() -> R) -> R {
    #[cfg(feature = "sim")]
    {
        struct Restore(Option<PlantedBug>);
        impl Drop for Restore {
            fn drop(&mut self) {
                set_planted_bug(self.0);
            }
        }
        let _restore = Restore(ACTIVE_BUG.with(|active| active.replace(bug)));
        operation()
    }
    #[cfg(not(feature = "sim"))]
    {
        let _ = bug;
        operation()
    }
}

/// Durable OpenMLS state, not the conversation-row projection or server state.
#[cfg(all(feature = "sim", not(target_arch = "wasm32")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimGroupState {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    /// Sorted scoped `did#device` leaf credentials; no synthetic fallback member.
    pub members: Vec<String>,
    pub has_pending_commit: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sim")]
    #[test]
    fn scoped_selection_restores_after_nesting_and_unwind_and_is_thread_local() {
        let outer = PlantedBug::P1KeepLoserStagedCommit;
        let inner = PlantedBug::P3NetworkInsideWriteTx;
        set_planted_bug(None);
        assert_eq!(active_planted_bug(), None);
        with_planted_bug(Some(outer), || {
            assert_eq!(active_planted_bug(), Some(outer));
            assert!(is_planted_bug_active(outer));
            with_planted_bug(None, || {
                assert_eq!(active_planted_bug(), None);
                assert!(!is_planted_bug_active(outer));
            });
            assert!(is_planted_bug_active(outer));
            let panic = std::panic::catch_unwind(|| {
                with_planted_bug(Some(inner), || {
                    assert_eq!(active_planted_bug(), Some(inner));
                    assert!(is_planted_bug_active(inner));
                    panic!("calibration unwind");
                });
            });
            assert!(panic.is_err());
            assert_eq!(active_planted_bug(), Some(outer));
            assert!(is_planted_bug_active(outer));
            assert!(!is_planted_bug_active(inner));
            std::thread::spawn(move || {
                assert_eq!(active_planted_bug(), None);
                assert!(!is_planted_bug_active(outer));
            })
            .join()
            .unwrap();
        });
        assert_eq!(active_planted_bug(), None);
        assert!(!is_planted_bug_active(outer));
        for phase2 in [
            PlantedBug::P4SkipLabyrinthEnqueueAfterSendRetry,
            PlantedBug::P5WrapMekToUnverifiedDevice,
            PlantedBug::P8RetainServerCiphertextAfterAckAndFlush,
            PlantedBug::P9AutomatedForcedRejoinOnDecryptFailure,
            PlantedBug::P10SkipDataVersionCheckAfterNseAdvance,
            PlantedBug::P11RevokeSpaceAccessBeforeKickedMemberFlushes,
            PlantedBug::P12SkipMessageIdDedupeAfterCrashRestart,
            PlantedBug::P15NonIdempotentCommitSubmitRetry,
        ] {
            assert!(!is_planted_bug_active(phase2));
            with_planted_bug(Some(phase2), || assert!(is_planted_bug_active(phase2)));
        }
    }

    #[cfg(all(feature = "sim", not(target_arch = "wasm32")))]
    #[test]
    fn p10_skips_data_version_eviction_hook_after_external_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p10.db");
        let key = [9u8; 32];
        let app =
            crate::storage::MlsAccountDb::open_native(&path, &key, crate::storage::OpenMode::App)
                .unwrap();
        let nse = crate::storage::MlsAccountDb::open_native(
            &path,
            &key,
            crate::storage::OpenMode::PushExtension,
        )
        .unwrap();
        let evictions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&evictions);
        app.register_cache_eviction_hook(std::sync::Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));

        nse.write_tx(|tx| tx.put_account_meta("nse_epoch", "1", 1))
            .unwrap();
        with_planted_bug(
            Some(PlantedBug::P10SkipDataVersionCheckAfterNseAdvance),
            || app.write_tx(|_tx| Ok(())).unwrap(),
        );
        assert_eq!(evictions.load(std::sync::atomic::Ordering::SeqCst), 0);

        nse.write_tx(|tx| tx.put_account_meta("nse_epoch", "2", 2))
            .unwrap();
        app.write_tx(|_tx| Ok(())).unwrap();
        assert_eq!(evictions.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(all(feature = "sim", not(target_arch = "wasm32")))]
    #[test]
    fn p6_switches_timeline_order_from_seq_to_epoch_seq() {
        let db = crate::storage::MlsAccountDb::open_in_memory_for_test().unwrap();
        db.write_tx(|tx| {
            for (id, epoch, seq) in [("m-newer-epoch", 2, 3), ("m-late-old-epoch", 1, 4)] {
                tx.insert_message(&crate::storage::MessageRow {
                    message_id: id.to_string(),
                    conversation_id: "convo-p6".to_string(),
                    group_id: vec![7; 32],
                    epoch,
                    seq,
                    sender_did: "did:plc:alice".to_string(),
                    sender_device_id: "dev-1".to_string(),
                    plaintext_json: format!("{{\"text\":\"{id}\"}}"),
                    created_at_ms: 1,
                    is_own: false,
                })?;
            }
            Ok(())
        })
        .unwrap();

        let by_seq: Vec<String> = db
            .read_tx(|rx| rx.list_messages("convo-p6", None, 10))
            .unwrap()
            .into_iter()
            .map(|m| m.message_id)
            .collect();
        assert_eq!(by_seq, vec!["m-late-old-epoch", "m-newer-epoch"]);

        let by_epoch_seq: Vec<String> =
            with_planted_bug(Some(PlantedBug::P6OrderTimelineByEpochSeq), || {
                db.read_tx(|rx| rx.list_messages("convo-p6", None, 10))
                    .unwrap()
            })
            .into_iter()
            .map(|m| m.message_id)
            .collect();
        assert_eq!(by_epoch_seq, vec!["m-newer-epoch", "m-late-old-epoch"]);
    }

    #[cfg(not(feature = "sim"))]
    #[test]
    fn selection_is_inert_without_sim() {
        let bug = PlantedBug::P3NetworkInsideWriteTx;
        set_planted_bug(Some(bug));
        assert_eq!(active_planted_bug(), None);
        let value = with_planted_bug(Some(bug), || {
            assert!(!is_planted_bug_active(bug));
            42
        });
        assert_eq!(value, 42);
        assert!(!is_planted_bug_active(bug));
    }
}
