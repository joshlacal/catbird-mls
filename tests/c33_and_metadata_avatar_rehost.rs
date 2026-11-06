//! Plan 06 Task 2 RED->GREEN integration tests for:
//! - `C33` direct requests (`>= 35d` KeyPackages + automatic Space archival of `first_message_id`
//!   once sender observes `consent == 'accepted'`).
//! - `1A` `GroupMetadataV1` Space avatar pointer (`{setter_did, space_blob_cid, sym_key, sha256}`)
//!   `<= 16 KiB` + automatic active-admin re-upload when setter admin A leaves.
//! - `D3` (`M-F01`) admin-only member removal enforcement.
//! - `I13` `archive_commitment` in OpenMLS `PrivateMessage` AAD + `accountDeleted` local purge.
//! - Post-SQLite-commit `acknowledgeEntries`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use catbird_mls::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use catbird_mls::groups::metadata_v1::{
    maybe_rehost_avatar_on_setter_leave, validate_metadata_snapshot_size, SpaceAvatarPointer,
    MAX_METADATA_SNAPSHOT_BYTES,
};
use catbird_mls::messaging::receive::{
    compute_archive_commitment, handle_account_deleted_event, verify_archive_commitment,
};
use catbird_mls::metadata::{decrypt_metadata_blob, encrypt_metadata_blob, GroupMetadataV1};
use catbird_mls::requests::c33::{
    archive_accepted_opening_messages, validate_direct_request_key_package_lifetime,
    DIRECT_REQUEST_KP_MIN_LIFETIME_SECS, RECOVERY_KP_MAX_LIFETIME_SECS,
};
use catbird_mls::storage::{MessageRow, MlsAccountDb, OpenMode, RequestRow};
use catbird_mls::sync::reconcile::persist_entries_then_acknowledge;
use sha2::{Digest, Sha256};

#[test]
fn c33_generic_receive_preserves_the_authenticated_opening_frame_and_rejects_legacy() {
    use catbird_mls::chat_v2::transcript::direct_request::{
        direct_request_application_aad, encode_direct_request_introduction,
    };
    use catbird_mls::messaging::receive::extract_plaintext_body_and_verify_aad;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../src/chat_v2/transcript/vectors/direct_request_vectors.json"
    ))
    .unwrap();
    let body = &vectors["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == "Publish")
        .unwrap()["body"];
    let (plaintext, opening) =
        encode_direct_request_introduction(br#"{"text":"C33 exact archive frame"}"#, &[33; 32])
            .unwrap();
    let coordinates = serde_json::to_vec(&body["next"]).unwrap();
    let message_id = body["firstMessageId"].as_str().unwrap();
    let aad = direct_request_application_aad(
        &[9; 32],
        &coordinates,
        message_id,
        &opening.archive_commitment,
    )
    .unwrap();
    let (text, frame, commitment, attestation) =
        extract_plaintext_body_and_verify_aad(&plaintext, &aad).unwrap();
    assert_eq!(text, "C33 exact archive frame");
    assert_eq!(frame.as_bytes(), opening.canonical_payload_bytes);
    assert_eq!(commitment, Some(opening.archive_commitment));
    assert!(attestation.is_none());
    let wrong_aad =
        direct_request_application_aad(&[9; 32], &coordinates, message_id, &[0; 32]).unwrap();
    assert!(extract_plaintext_body_and_verify_aad(&plaintext, &wrong_aad).is_err());
    let mut missing_commitment = b"CATBIRD-DIRECT-REQUEST-APPLICATION-AAD\0".to_vec();
    missing_commitment.extend(serde_ipld_dagcbor::to_vec(&serde_json::json!({})).unwrap());
    assert!(extract_plaintext_body_and_verify_aad(&plaintext, &missing_commitment).is_err());
    let legacy = serde_ipld_dagcbor::to_vec(&serde_json::json!({"text":"legacy"})).unwrap();
    assert!(extract_plaintext_body_and_verify_aad(&legacy, &aad).is_err());
}

#[tokio::test]
async fn c33_direct_request_35d_keypackage_and_opening_message_space_archival() {
    let now_sec = 1_760_000_000u64;

    // 1. Direct-request KeyPackage lifetime must be >= 35 days (3_024_000s), while recovery stays <= 30d.
    assert_eq!(DIRECT_REQUEST_KP_MIN_LIFETIME_SECS, 35 * 86_400);
    assert_eq!(RECOVERY_KP_MAX_LIFETIME_SECS, 30 * 86_400);
    assert!(
        validate_direct_request_key_package_lifetime(now_sec, now_sec + 30 * 86_400).is_err(),
        "30-day KeyPackage must be rejected for C33 direct requests"
    );
    validate_direct_request_key_package_lifetime(now_sec, now_sec + 36 * 86_400)
        .expect("36-day KeyPackage must satisfy C33 >= 35d requirement");

    // 2. When sender observes `consent == 'accepted'`, `first_message_id` is archived to the
    // conversation Space and marked `first_message_archived = true` idempotently.
    let dir = tempfile::tempdir().unwrap();
    let db =
        MlsAccountDb::open_native(dir.path().join("c33.db"), &[0x33; 32], OpenMode::App).unwrap();

    db.write_tx(|tx| {
        tx.insert_message(&MessageRow {
            message_id: "msg-opening-1".into(),
            conversation_id: "convo-c33".into(),
            group_id: b"gid-c33".to_vec(),
            epoch: 1,
            seq: 1,
            sender_did: "did:plc:alice0000000000000000000".into(),
            sender_device_id: "dev-a1".into(),
            plaintext_json: r#"{"text":"Hello via C33!"}"#.into(),
            created_at_ms: 1_760_000_001_000,
            is_own: true,
        })?;
        tx.upsert_request(&RequestRow {
            request_id: "req-1".into(),
            conversation_id: "convo-c33".into(),
            sender_did: "did:plc:alice0000000000000000000".into(),
            recipient_did: "did:plc:bob000000000000000000000".into(),
            consent: "pending".into(),
            first_message_id: Some("msg-opening-1".into()),
            first_message_archived: false,
            payload_json: "{}".into(),
            expires_at_ms: 1_763_110_400_000,
            updated_at_ms: 1_760_000_001_000,
        })
    })
    .unwrap();

    let archived_calls = Arc::new(AtomicUsize::new(0));
    let calls_ref = Arc::clone(&archived_calls);

    // While `consent == 'pending'`, nothing is archived to the conversation Space.
    let count_pending = archive_accepted_opening_messages(&db, |convo_id, msg| {
        let calls_ref = Arc::clone(&calls_ref);
        async move {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            panic!(
                "must not archive while pending: {convo_id} {}",
                msg.message_id
            );
        }
    })
    .await
    .unwrap();
    assert_eq!(count_pending, 0);

    // Transition request to `consent = 'accepted'`.
    db.write_tx(|tx| {
        let mut req = tx.get_request("req-1")?.unwrap();
        req.consent = "accepted".into();
        tx.upsert_request(&req)
    })
    .unwrap();

    let calls_ref = Arc::clone(&archived_calls);
    let count_accepted = archive_accepted_opening_messages(&db, move |convo_id, msg| {
        let calls_ref = Arc::clone(&calls_ref);
        async move {
            assert_eq!(convo_id, "convo-c33");
            assert_eq!(msg.message_id, "msg-opening-1");
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    })
    .await
    .unwrap();
    assert_eq!(count_accepted, 1);
    assert_eq!(archived_calls.load(Ordering::SeqCst), 1);

    // Re-running is a no-op because `first_message_archived` is now durably `true`.
    let calls_ref = Arc::clone(&archived_calls);
    let count_second = archive_accepted_opening_messages(&db, move |_convo_id, _msg| {
        let calls_ref = Arc::clone(&calls_ref);
        async move {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    })
    .await
    .unwrap();
    assert_eq!(count_second, 0);
    assert_eq!(archived_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn metadata_1a_space_avatar_rehost_on_setter_leave_and_d3_admin_only_removal() {
    // 1. D3 (`M-F01`): non-admin cannot remove another member; self-leave is allowed; admin can remove.
    assert!(
        enforce_admin_removal_policy(
            "did:plc:member000000000000000000",
            MemberRole::Member,
            &["did:plc:other0000000000000000000".to_string()],
        )
        .is_err(),
        "non-admin removing another member must be rejected (D3 / M-F01)"
    );
    enforce_admin_removal_policy(
        "did:plc:member000000000000000000",
        MemberRole::Member,
        &["did:plc:member000000000000000000".to_string()],
    )
    .expect("member self-leave must be permitted");
    enforce_admin_removal_policy(
        "did:plc:adminb000000000000000000",
        MemberRole::Admin,
        &["did:plc:other0000000000000000000".to_string()],
    )
    .expect("admin removing a member must be permitted");

    // 2. 1A GroupMetadataV1 with Space avatar pointer <= 16 KiB + active-admin B re-host when setter A leaves.
    let encrypted_avatar_bytes = b"aes-256-gcm-encrypted-avatar-ciphertext".to_vec();
    let avatar_sha256: [u8; 32] = Sha256::digest(&encrypted_avatar_bytes).into();
    let sym_key = [0x99u8; 32];

    let meta_a = GroupMetadataV1 {
        version: 1,
        title: "Clean Slate Squad".into(),
        description: "100% PQ + Spaces".into(),
        avatar_blob_locator: None,
        avatar_content_type: Some("image/webp".into()),
        space_avatar: Some(SpaceAvatarPointer {
            setter_did: "did:plc:admina000000000000000000".into(),
            space_blob_cid: "bafkreiavatarfromadmina".into(),
            sym_key: sym_key.to_vec(),
            sha256: avatar_sha256.to_vec(),
            mime_type: Some("image/webp".into()),
        }),
    };

    let key = [0x5Au8; 32];
    let blob = encrypt_metadata_blob(&key, b"gid-1a", 1, 1, &meta_a).unwrap();
    validate_metadata_snapshot_size(&blob).expect("metadata snapshot must be <= 16 KiB");
    assert!(blob.len() <= MAX_METADATA_SNAPSHOT_BYTES);

    let decoded = decrypt_metadata_blob(&key, b"gid-1a", 1, 1, &blob).unwrap();
    assert_eq!(decoded, meta_a);

    // Admin A leaves -> Active admin B re-hosts encrypted avatar blob to B's Space repo!
    let avatar_bytes_for_fetch = encrypted_avatar_bytes.clone();
    let rehosted = maybe_rehost_avatar_on_setter_leave(
        &meta_a,
        1,
        "did:plc:admina000000000000000000",
        "did:plc:adminb000000000000000000",
        MemberRole::Admin,
        move |setter_did, cid| {
            let bytes = avatar_bytes_for_fetch.clone();
            async move {
                assert_eq!(setter_did, "did:plc:admina000000000000000000");
                assert_eq!(cid, "bafkreiavatarfromadmina");
                Ok(bytes)
            }
        },
        move |new_setter_did, bytes, mime| async move {
            assert_eq!(new_setter_did, "did:plc:adminb000000000000000000");
            assert_eq!(bytes, encrypted_avatar_bytes);
            assert_eq!(mime.as_deref(), Some("image/webp"));
            Ok("bafkreiavatarrehostedbyb".to_string())
        },
    )
    .await
    .unwrap()
    .expect("active admin B must produce a re-hosted GroupMetadataV1");

    assert_eq!(rehosted.next_metadata_version, 2);
    let ptr = rehosted.metadata.space_avatar.unwrap();
    assert_eq!(ptr.setter_did, "did:plc:adminb000000000000000000");
    assert_eq!(ptr.space_blob_cid, "bafkreiavatarrehostedbyb");
    assert_eq!(ptr.sha256, avatar_sha256.to_vec());
}

#[tokio::test]
async fn i13_archive_commitment_account_deleted_purge_post_commit_ack() {
    let dir = tempfile::tempdir().unwrap();
    let db =
        MlsAccountDb::open_native(dir.path().join("sync.db"), &[0x66; 32], OpenMode::App).unwrap();

    // 1. I13 `archive_commitment` in OpenMLS PrivateMessage AAD:
    let commitment = compute_archive_commitment(
        "convo-i13",
        b"gid-i13",
        "msg-i13-1",
        b"{\"text\":\"bound\"}",
        1_760_000_000_000,
    );
    verify_archive_commitment(
        &commitment,
        "convo-i13",
        b"gid-i13",
        "msg-i13-1",
        b"{\"text\":\"bound\"}",
        1_760_000_000_000,
    )
    .expect("matching payload must verify I13 archive_commitment");
    assert!(
        verify_archive_commitment(
            &commitment,
            "convo-i13",
            b"gid-i13",
            "msg-i13-1",
            b"{\"text\":\"tampered\"}",
            1_760_000_000_000,
        )
        .is_err(),
        "tampered archived frame must fail I13 archive_commitment"
    );

    // 2. Post-SQLite-commit `acknowledgeEntries`:
    let ack_called = Arc::new(AtomicBool::new(false));
    let ack_ref = Arc::clone(&ack_called);
    let err = persist_entries_then_acknowledge(
        &db,
        |_tx| Err::<Vec<i64>, _>(catbird_mls::MLSError::StorageFailed),
        move |_seqs| {
            let ack_ref = Arc::clone(&ack_ref);
            async move {
                ack_ref.store(true, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await;
    assert!(err.is_err());
    assert!(
        !ack_called.load(Ordering::SeqCst),
        "acknowledgeEntries must NEVER run if SQLite write_tx fails"
    );

    let acked_seqs = Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let acked_ref = Arc::clone(&acked_seqs);
    persist_entries_then_acknowledge(
        &db,
        |tx| {
            tx.insert_message(&MessageRow {
                message_id: "m-del-1".into(),
                conversation_id: "convo-i13".into(),
                group_id: b"gid-i13".to_vec(),
                epoch: 1,
                seq: 10,
                sender_did: "did:plc:deleteduser000000000000".into(),
                sender_device_id: "dev-1".into(),
                plaintext_json: "{}".into(),
                created_at_ms: 100,
                is_own: false,
            })?;
            tx.insert_message(&MessageRow {
                message_id: "m-keep-2".into(),
                conversation_id: "convo-i13".into(),
                group_id: b"gid-i13".to_vec(),
                epoch: 1,
                seq: 11,
                sender_did: "did:plc:activeuser0000000000000".into(),
                sender_device_id: "dev-2".into(),
                plaintext_json: "{}".into(),
                created_at_ms: 101,
                is_own: false,
            })?;
            Ok(vec![10, 11])
        },
        move |seqs| {
            let acked_ref = Arc::clone(&acked_ref);
            async move {
                *acked_ref.lock().unwrap() = seqs;
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(*acked_seqs.lock().unwrap(), vec![10, 11]);

    // 3. `accountDeleted` event purges local messages from deleted sender (`I13`):
    let purged = handle_account_deleted_event(&db, "did:plc:deleteduser000000000000").unwrap();
    assert_eq!(purged, 1);
    let remaining = db
        .read_tx(|tx| tx.list_messages("convo-i13", None, 50))
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].sender_did, "did:plc:activeuser0000000000000");
}
