//! Plan 06 Task 1 — SQLCipher 96-hex raw key+HKDF salt (`I8`), 32-byte plaintext
//! header reopen test, unified 15-table schema verification, and atomic single-table
//! `openmls_kv` `StorageProvider<1>` commit + rollback tests (`I16` X-Wing).

use std::collections::BTreeSet;
use std::fs;

use catbird_mls::storage::{
    derive_sqlcipher_96hex_key_spec, ConversationRow, MessageRow, MlsAccountDb, OpenMode,
    UNIFIED_SCHEMA_DDL, UNIFIED_SCHEMA_TABLES,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

#[test]
fn i8_sqlcipher_96hex_plaintext_header_cold_reopen_never_bricks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("a1b2c3d4e5f6.db");
    let db_key_32 = [0x42u8; 32];

    let key_spec = derive_sqlcipher_96hex_key_spec(&db_key_32);
    assert!(
        key_spec.starts_with("x'") && key_spec.ends_with('\''),
        "key spec must be SQLCipher raw hex literal"
    );
    assert_eq!(
        key_spec.len(),
        99,
        "x' + 64-hex key + 32-hex HKDF salt + ' = 99 chars"
    );

    let secret_marker = b"SUPER_SECRET_PLAINTEXT_MESSAGE_MARKER_DO_NOT_LEAK_ON_DISK";
    let group_id_bytes: Vec<u8>;

    {
        let db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App)
            .expect("initial open_native must succeed");

        // Verify all 15 unified tables from Spec §6.1 exist and zero legacy
        // openmls_sqlite_storage tables exist.
        let tables: BTreeSet<String> = db
            .read_tx(|rx| rx.list_table_names())
            .expect("list_table_names")
            .into_iter()
            .collect();
        for expected in UNIFIED_SCHEMA_TABLES {
            assert!(
                tables.contains(*expected),
                "missing unified schema table `{expected}`; found: {tables:?}"
            );
        }
        assert!(
            !tables.contains("openmls_sqlite_storage_migrations"),
            "retired openmls_sqlite_storage must not exist"
        );
        assert!(
            !tables.contains("openmls_group_data"),
            "retired openmls_group_data table must not exist"
        );

        // Create a real post-quantum X-Wing MLS group + message inside one atomic write_tx.
        group_id_bytes = db
            .write_tx(|tx| {
                let provider = tx.openmls_provider();
                let credential = BasicCredential::new(b"did:plc:alice#dev-1".to_vec());
                let signer = SignatureKeyPair::new(SignatureScheme::from(CIPHERSUITE))
                    .expect("ed25519 keygen");
                signer
                    .store(provider.storage())
                    .expect("store signature keypair in openmls_kv");

                let credential_with_key = CredentialWithKey {
                    credential: credential.into(),
                    signature_key: signer.public().into(),
                };
                let join_config = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .build();

                let group = MlsGroup::new(
                    &provider,
                    &signer,
                    &join_config,
                    credential_with_key,
                )
                .expect("create X-Wing MlsGroup in openmls_kv");
                let gid = group.group_id().as_slice().to_vec();

                tx.upsert_conversation(&ConversationRow {
                    conversation_id: "convo-1".to_string(),
                    group_id: gid.clone(),
                    generation: 0,
                    epoch: 0,
                    last_seq: 1,
                    sequencer_did: "did:web:chat.catbird.blue".to_string(),
                    space_uri: Some(
                        "at://did:web:chat.catbird.blue/space/blue.catbird.labyrinth.conversation/convo-1-0"
                            .to_string(),
                    ),
                    title: Some("Clean Slate PQ Group".to_string()),
                    unread_count: 0,
                    updated_at_ms: 1_760_000_000_000,
                })?;

                tx.insert_message(&MessageRow {
                    message_id: "msg-1".to_string(),
                    conversation_id: "convo-1".to_string(),
                    group_id: gid.clone(),
                    epoch: 0,
                    seq: 1,
                    sender_did: "did:plc:alice".to_string(),
                    sender_device_id: "dev-1".to_string(),
                    plaintext_json: String::from_utf8(secret_marker.to_vec()).unwrap(),
                    created_at_ms: 1_760_000_000_001,
                    is_own: true,
                })?;

                Ok(gid)
            })
            .expect("atomic group + message write_tx");

        // Flush WAL into main DB file via passive prepare_for_background so page 2+ live in .db
        db.prepare_for_background()
            .expect("prepare_for_background must succeed");
    }

    // Inspect raw bytes on disk:
    // Bytes 0..16 MUST be plaintext "SQLite format 3\0" (32-byte plaintext header for iOS vnode inspection),
    // while table contents on subsequent pages MUST be encrypted (never containing secret_marker).
    let raw_db = fs::read(&db_path).expect("read raw .db file");
    assert!(
        raw_db.len() >= 8192,
        "expected >= 2 pages in checkpointed SQLCipher DB, got {} bytes",
        raw_db.len()
    );
    assert_eq!(
        &raw_db[0..16],
        b"SQLite format 3\0",
        "bytes 0..16 must be plaintext SQLite header when cipher_plaintext_header_size = 32"
    );
    assert!(
        !raw_db
            .windows(secret_marker.len())
            .any(|w| w == secret_marker),
        "plaintext message marker must NEVER appear unencrypted in .db file"
    );
    let wal_path = dir.path().join("a1b2c3d4e5f6.db-wal");
    if wal_path.exists() {
        let raw_wal = fs::read(&wal_path).expect("read raw .db-wal");
        assert!(
            !raw_wal
                .windows(secret_marker.len())
                .any(|w| w == secret_marker),
            "plaintext message marker must NEVER appear unencrypted in .db-wal file"
        );
    }

    // Cold reopen with the exact same 32-byte key must NOT hit SQLITE_NOTADB!
    let reopened = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App)
        .expect("cold reopen with 96-hex key+HKDF salt must succeed without SQLITE_NOTADB");

    let msgs = reopened
        .read_tx(|rx| rx.list_messages("convo-1", None, 10))
        .expect("read messages after cold reopen");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].plaintext_json.as_bytes(), secret_marker);

    // Reload the X-Wing MlsGroup from openmls_kv after cold reopen.
    let loaded_epoch = reopened
        .write_tx(|tx| {
            let provider = tx.openmls_provider();
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id_bytes))
                .expect("MlsGroup::load from openmls_kv")
                .expect("group must exist after cold reopen");
            assert_eq!(loaded.ciphersuite(), CIPHERSUITE);
            Ok(loaded.epoch().as_u64())
        })
        .expect("load group after reopen");
    assert_eq!(loaded_epoch, 0);

    // Opening with a wrong key MUST fail cleanly (authentication failure, never silent corruption).
    let wrong_key = [0x99u8; 32];
    let wrong_open = MlsAccountDb::open_native(&db_path, &wrong_key, OpenMode::App);
    assert!(
        wrong_open.is_err(),
        "wrong 32-byte DB key must fail to open"
    );
}

#[test]
fn pre_round4_database_is_refused_before_open_can_mutate_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("pre-round4.db");
    let db_key_32 = [0x24u8; 32];
    let key_spec = derive_sqlcipher_96hex_key_spec(&db_key_32);

    // Exact b2a401cf schema (sha256 b4ac1538…), which predates the format row.
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open fixture");
        conn.execute_batch(&format!(
            "PRAGMA cipher_memory_security = OFF;\n\
             PRAGMA key = \"{key_spec}\";\n\
             PRAGMA cipher_plaintext_header_size = 32;\n\
             PRAGMA journal_mode = WAL;\n\
             {UNIFIED_SCHEMA_DDL}"
        ))
        .expect("construct b2a401cf database");
    }

    let error = match MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App) {
        Err(error) => error,
        Ok(_) => panic!("an unversioned pre-Round-4 database must be rejected at open"),
    };
    assert_eq!(
        format!("{error:?}"),
        "LocalStateFormatUnsupported { found: 0, required: 1 }"
    );

    // The failed open cannot upgrade or otherwise partially mutate the old database.
    let conn = rusqlite::Connection::open(&db_path).expect("reopen fixture");
    conn.execute_batch(&format!(
        "PRAGMA cipher_memory_security = OFF;\n\
         PRAGMA key = \"{key_spec}\";\n\
         PRAGMA cipher_plaintext_header_size = 32;"
    ))
    .expect("unlock fixture");
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM account_meta WHERE key = 'local_state_format_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
}

#[test]
fn openmls_kv_and_app_tables_rollback_atomically_on_write_tx_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("rollback_atomicity.db");
    let db_key_32 = [0x11u8; 32];

    let db = MlsAccountDb::open_native(&db_path, &db_key_32, OpenMode::App).expect("open_native");
    let mut created_gid = Vec::new();

    let res: Result<(), catbird_mls::MLSError> = db.write_tx(|tx| {
        let provider = tx.openmls_provider();
        let credential = BasicCredential::new(b"did:plc:bob#dev-1".to_vec());
        let signer =
            SignatureKeyPair::new(SignatureScheme::from(CIPHERSUITE)).expect("ed25519 keygen");
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
                credential: credential.into(),
                signature_key: signer.public().into(),
            },
        )
        .expect("create group inside tx");
        created_gid = group.group_id().as_slice().to_vec();

        tx.insert_message(&MessageRow {
            message_id: "msg-rolled-back".to_string(),
            conversation_id: "convo-rb".to_string(),
            group_id: created_gid.clone(),
            epoch: 0,
            seq: 1,
            sender_did: "did:plc:bob".to_string(),
            sender_device_id: "dev-1".to_string(),
            plaintext_json: "{\"text\":\"abort me\"}".to_string(),
            created_at_ms: 1_760_000_000_100,
            is_own: true,
        })?;

        Err(catbird_mls::MLSError::invalid_input(
            "simulated failure after OpenMLS + app writes",
        ))
    });
    assert!(res.is_err());

    // Neither the message row NOR the OpenMLS group rows may survive the rollback!
    let msgs = db
        .read_tx(|rx| rx.list_messages("convo-rb", None, 10))
        .expect("list_messages");
    assert!(msgs.is_empty(), "message write must roll back");

    let kv_count = db
        .write_tx(|tx| {
            let provider = tx.openmls_provider();
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&created_gid))
                .expect("MlsGroup::load");
            assert!(
                loaded.is_none(),
                "OpenMLS group in openmls_kv must roll back"
            );
            tx.count_openmls_kv_rows()
        })
        .expect("verify openmls_kv empty");
    assert_eq!(
        kv_count, 0,
        "all openmls_kv writes from failed tx must roll back"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn apple_app_and_push_connections_request_full_drive_flushes() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, mode) in [
        ("app.db", OpenMode::App),
        ("push.db", OpenMode::PushExtension),
    ] {
        let db = MlsAccountDb::open_native(dir.path().join(name), &[0x5a; 32], mode)
            .expect("open SQLCipher database");
        let (fullfsync, checkpoint_fullfsync): (i64, i64) = db
            .read_tx(|tx| {
                Ok((
                    tx.conn()
                        .query_row("PRAGMA fullfsync", [], |row| row.get(0))
                        .map_err(|_| catbird_mls::MLSError::StorageFailed)?,
                    tx.conn()
                        .query_row("PRAGMA checkpoint_fullfsync", [], |row| row.get(0))
                        .map_err(|_| catbird_mls::MLSError::StorageFailed)?,
                ))
            })
            .expect("read Darwin durability pragmas");
        assert_eq!(
            (fullfsync, checkpoint_fullfsync),
            (1, 1),
            "{mode:?} must request F_FULLFSYNC for transactions and WAL checkpoints"
        );
    }
}
