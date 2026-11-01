//! Plan 06 Task 1 — Two-process `PRAGMA data_version` reconciliation (`I7`,
//! including the paged-`SELECT`-before-`BEGIN IMMEDIATE` trap) and non-blocking
//! `prepare_for_background()` `< 50 ms` passive checkpoint + full FD closure (`I9`).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use catbird_mls::storage::{MessageRow, MlsAccountDb, OpenMode};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

#[cfg(target_os = "macos")]
fn count_open_fds_matching_prefix(prefix: &Path) -> usize {
    let prefix_str = prefix.to_string_lossy();
    let canonical_prefix = std::fs::canonicalize(prefix.parent().unwrap_or(prefix))
        .ok()
        .map(|parent| {
            parent
                .join(prefix.file_name().unwrap_or_default())
                .to_string_lossy()
                .into_owned()
        });

    let Ok(entries) = std::fs::read_dir("/dev/fd") else {
        return 0;
    };
    let mut matches = 0usize;
    for entry in entries.flatten() {
        let Ok(fd_str) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(fd) = fd_str.parse::<i32>() else {
            continue;
        };
        let mut buf = vec![0u8; 1024];
        // F_GETPATH = 50 on macOS/Darwin
        let rc = unsafe { libc_fcntl_getpath(fd, buf.as_mut_ptr().cast()) };
        if rc == 0 {
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(path_str) = std::str::from_utf8(&buf[..nul]) {
                if path_str.starts_with(prefix_str.as_ref())
                    || canonical_prefix
                        .as_deref()
                        .is_some_and(|cp| path_str.starts_with(cp))
                {
                    matches += 1;
                }
            }
        }
    }
    matches
}

#[cfg(target_os = "macos")]
unsafe fn libc_fcntl_getpath(fd: i32, buf: *mut std::ffi::c_char) -> i32 {
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    const F_GETPATH: i32 = 50;
    fcntl(fd, F_GETPATH, buf)
}

#[test]
fn i7_paged_select_before_begin_immediate_still_evicts_stale_group_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("i7_paged_select.db");
    let db_key_32 = [0x77u8; 32];

    let proc_a =
        MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).expect("open proc_a");
    let proc_b = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::PushExtension)
        .expect("open proc_b (NSE)");

    // Simulated in-memory MlsGroup cache in Process A (keyed by group_id -> cached MlsGroup).
    let cache_a: Arc<Mutex<Option<MlsGroup>>> = Arc::new(Mutex::new(None));
    let evictions = Arc::new(AtomicUsize::new(0));
    {
        let cache_ref = Arc::clone(&cache_a);
        let evictions_ref = Arc::clone(&evictions);
        proc_a.register_cache_eviction_hook(Arc::new(move || {
            *cache_ref.lock().unwrap() = None;
            evictions_ref.fetch_add(1, Ordering::SeqCst);
        }));
    }

    // 1. Process A creates an X-Wing group at epoch 0 and caches it in memory.
    let signer = SignatureKeyPair::new(SignatureScheme::from(CIPHERSUITE)).expect("ed25519 keygen");
    let group_id = proc_a
        .write_tx(|tx| {
            let provider = tx.openmls_provider();
            signer
                .store(provider.storage())
                .expect("store signer in openmls_kv");
            let join_config = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .use_ratchet_tree_extension(true)
                .build();
            let group = MlsGroup::new(
                &provider,
                &signer,
                &join_config,
                CredentialWithKey {
                    credential: BasicCredential::new(b"did:plc:alice#dev-1".to_vec()).into(),
                    signature_key: signer.public().into(),
                },
            )
            .expect("create group");
            let gid = group.group_id().clone();
            *cache_a.lock().unwrap() = Some(group);
            Ok(gid)
        })
        .expect("proc_a create group");

    assert_eq!(
        cache_a.lock().unwrap().as_ref().unwrap().epoch().as_u64(),
        0
    );
    let evictions_after_a_create = evictions.load(Ordering::SeqCst);

    // 2. Process B (NSE) opens a write_tx, loads the group from openmls_kv, advances
    //    epoch 0 -> 1 via self_update + merge_pending_commit, and inserts a message.
    proc_b
        .write_tx(|tx| {
            let provider = tx.openmls_provider();
            let mut group_b = MlsGroup::load(provider.storage(), &group_id)
                .expect("load group in proc_b")
                .expect("group exists");
            assert_eq!(group_b.epoch().as_u64(), 0);
            group_b
                .self_update(&provider, &signer, LeafNodeParameters::default())
                .expect("self_update to epoch 1");
            group_b
                .merge_pending_commit(&provider)
                .expect("merge epoch 1");
            assert_eq!(group_b.epoch().as_u64(), 1);

            tx.insert_message(&MessageRow {
                message_id: "nse-msg-epoch-1".to_string(),
                conversation_id: "convo-i7".to_string(),
                group_id: group_id.as_slice().to_vec(),
                epoch: 1,
                seq: 2,
                sender_did: "did:plc:alice".to_string(),
                sender_device_id: "dev-1".to_string(),
                plaintext_json: "{\"text\":\"decrypted in NSE\"}".to_string(),
                created_at_ms: 1_760_000_000_200,
                is_own: true,
            })?;
            Ok(())
        })
        .expect("proc_b commit epoch 1");

    // 3. TRAP: Process A runs a read-only paged SELECT *before* starting any write_tx!
    //    SQLite updates Connection A's observed `PRAGMA data_version` on this SELECT.
    //    `last_reconciled_data_version` MUST NOT be updated by `read_tx`, or the next
    //    `write_tx` would fail to evict `cache_a` (still holding epoch 0)!
    let paged = proc_a
        .read_tx(|rx| rx.list_messages("convo-i7", None, 20))
        .expect("paged read_tx in proc_a");
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0].message_id, "nse-msg-epoch-1");

    // 4. Process A now starts a write_tx to advance the group again.
    //    Inside `BEGIN IMMEDIATE`, `proc_a` MUST detect `dv != last_reconciled_data_version`,
    //    fire the eviction hook so `cache_a` is cleared, reload `epoch == 1` from `openmls_kv`,
    //    and advance cleanly to `epoch == 2`!
    let new_epoch = proc_a
        .write_tx(|tx| {
            assert!(
                cache_a.lock().unwrap().is_none(),
                "I7 violation: stale epoch-0 MlsGroup remained cached inside BEGIN IMMEDIATE after paged SELECT!"
            );
            let provider = tx.openmls_provider();
            let mut reloaded = MlsGroup::load(provider.storage(), &group_id)
                .expect("reload group from openmls_kv")
                .expect("group exists");
            assert_eq!(
                reloaded.epoch().as_u64(),
                1,
                "reloaded group must reflect Process B's epoch-1 commit"
            );
            reloaded
                .self_update(&provider, &signer, LeafNodeParameters::default())
                .expect("self_update to epoch 2");
            reloaded
                .merge_pending_commit(&provider)
                .expect("merge epoch 2");
            let epoch = reloaded.epoch().as_u64();
            *cache_a.lock().unwrap() = Some(reloaded);
            Ok(epoch)
        })
        .expect("proc_a advance to epoch 2");

    assert_eq!(new_epoch, 2);
    assert!(
        evictions.load(Ordering::SeqCst) > evictions_after_a_create,
        "cache eviction hook must have fired on BEGIN IMMEDIATE"
    );
}

#[test]
fn i9_prepare_for_background_completes_under_50ms_with_active_reader_and_closes_all_fds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("i9_suspend_0xdead10cc.db");
    let db_key_32 = [0x55u8; 32];

    let app_db =
        MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).expect("open app_db");

    // Populate several WAL frames so there is real WAL work pending.
    for idx in 1..=8 {
        app_db
            .write_tx(|tx| {
                tx.insert_message(&MessageRow {
                    message_id: format!("msg-{idx}"),
                    conversation_id: "convo-bg".to_string(),
                    group_id: vec![1, 2, 3, 4],
                    epoch: 0,
                    seq: idx,
                    sender_did: "did:plc:alice".to_string(),
                    sender_device_id: "dev-1".to_string(),
                    plaintext_json: format!("{{\"text\":\"frame {idx}\"}}"),
                    created_at_ms: 1_760_000_000_000 + idx,
                    is_own: true,
                })
            })
            .expect("insert WAL frame");
    }

    #[cfg(target_os = "macos")]
    assert!(
        count_open_fds_matching_prefix(&db_path) > 0,
        "app_db must hold at least one open FD before backgrounding"
    );

    // Spawn a separate thread holding an active SQLite read snapshot (simulating NSE mid-read)
    // for 300 ms. A blocking `TRUNCATE` or `RESTART` checkpoint would stall >= 300 ms or fail!
    let (snapshot_ready_tx, snapshot_ready_rx) = std::sync::mpsc::channel();
    let (release_reader_tx, release_reader_rx) = std::sync::mpsc::channel();
    let reader_path = db_path.clone();
    let reader_handle = std::thread::spawn(move || {
        let nse_db = MlsAccountDb::open_native(&reader_path, &db_key_32, OpenMode::PushExtension)
            .expect("open nse_db");
        nse_db
            .hold_read_snapshot_for_test(|| {
                snapshot_ready_tx.send(()).unwrap();
                release_reader_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            })
            .expect("hold_read_snapshot_for_test");
    });

    snapshot_ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("NSE reader snapshot acquired");

    // Measure `prepare_for_background()` while NSE holds its read snapshot!
    let start = Instant::now();
    let report = app_db
        .prepare_for_background()
        .expect("prepare_for_background must succeed non-blockingly");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(50),
        "0xdead10cc hazard: prepare_for_background took {elapsed:?} (>= 50ms) while reader held snapshot!"
    );
    assert!(
        !app_db.is_open(),
        "app_db handle must be closed after prepare_for_background"
    );
    assert!(report.handle_closed);

    // Release the NSE reader thread so ONLY app_db's FDs (if any leaked!) remain.
    release_reader_tx.send(()).unwrap();
    reader_handle.join().expect("join NSE reader thread");

    #[cfg(target_os = "macos")]
    {
        let open_fds = count_open_fds_matching_prefix(&db_path);
        assert_eq!(
            open_fds, 0,
            "I9 violation: process still holds {open_fds} open FDs on {:?}* after prepare_for_background()",
            db_path
        );
    }

    // Writes while suspended must be rejected before touching SQLite.
    let suspended_write = app_db.write_tx(|_tx| Ok(()));
    assert!(
        suspended_write.is_err(),
        "write_tx while backgrounded must be rejected"
    );

    // Resuming from background reopens cleanly and sees all prior messages.
    app_db
        .resume_from_background()
        .expect("resume_from_background");
    assert!(app_db.is_open());
    let msgs = app_db
        .read_tx(|rx| rx.list_messages("convo-bg", None, 20))
        .expect("read_tx after resume");
    assert_eq!(msgs.len(), 8);
}
