//! Plan 06 Task 2 RED->GREEN integration tests for Labyrinth Gates 4, 5, and 7:
//! - Gate 4: Crash mid-Gate-3 rotation rolls forward cleanly from `mutation_journal`
//!   (`mailboxKeys/self` `swapRecord` CAS + `mls-ds` `publishEpochHead(E+1)`) on reopen.
//! - Gate 7: Missing or tampered `Atproto-Space-Mac` (`atproto-space-repo` /
//!   `atproto-space-record`) is rejected in Rust before inspecting `MEK` or record bytes;
//!   cross-conversation or cross-group (`group_id`) replayed `MEK` is rejected.
//! - Gate 5 & [CB-22]: `.staged` -> `.space` `attachmentManifest` commits before MLS
//!   `sendMessage`; `rearchive_before_leave` copies readable batches and encrypted
//!   attachment blobs into the leaving user's personal mailbox Space before `clearRecords`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use atproto_spaces::kem::{encode_p256_did_key, P256SecretKey};
use atproto_spaces::mac::{
    format_accept_signature, sign_commit_mac, sign_record_mac, MacProfile, ACCEPT_SIGNATURE_HEADER,
    DEFAULT_MAC_LABEL, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER,
};
use catbird_mls::labyrinth::journal::{
    recover_pending_labyrinth_rotations, RotationCommitTransport, RotationJournalPayload,
    RotationJournalStage,
};
use catbird_mls::labyrinth::mac_gate::{
    verify_mek_conversation_binding, AtprotoSpaceMacVerifier, BoundMekContext, SharedSecretLookup,
};
use catbird_mls::labyrinth::{
    LabyrinthSpaceGateway, LabyrinthSpaceRequest, LabyrinthSpaceResponse, SpaceResponseMacVerifier,
    SpaceXrpcTransport,
};
use catbird_mls::messaging::attachments::{
    execute_leave_with_rearchive, send_message_with_promoted_attachments, AttachmentUploadStage,
    StagedAttachmentInput,
};
use catbird_mls::storage::{MlsAccountDb, MutationJournalRow, OpenMode};
use labyrinth::mek::Mek;

struct MockRotationTransport {
    fail_publish_head_once: AtomicBool,
    swap_calls: AtomicUsize,
    publish_head_calls: AtomicUsize,
    current_cid: std::sync::Mutex<String>,
}

#[async_trait::async_trait]
impl RotationCommitTransport for MockRotationTransport {
    async fn swap_mailbox_keys_cas(
        &self,
        expected_swap_cid: Option<&str>,
        next_epoch_seq: u64,
        _record_cbor: &[u8],
    ) -> Result<String, catbird_mls::MLSError> {
        self.swap_calls.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.current_cid.lock().unwrap();
        let new_cid = format!("bafyreimailboxkeys-e{next_epoch_seq}");
        if *guard == new_cid {
            // Idempotent replay when swapRecord already succeeded before crash!
            return Ok(new_cid);
        }
        if let Some(exp) = expected_swap_cid {
            if guard.as_str() != exp {
                return Err(catbird_mls::MLSError::invalid_input(format!(
                    "CAS mismatch: expected {exp}, got {}",
                    *guard
                )));
            }
        }
        *guard = new_cid.clone();
        Ok(new_cid)
    }

    async fn publish_epoch_head_on_ds(
        &self,
        _epoch_seq: u64,
        _epoch_head: &[u8; 32],
    ) -> Result<(), catbird_mls::MLSError> {
        self.publish_head_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_publish_head_once.swap(false, Ordering::SeqCst) {
            return Err(catbird_mls::MLSError::Internal(
                "simulated crash before publishEpochHead(E+1)".into(),
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn gate4_crash_mid_rotation_rolls_forward_from_mutation_journal_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("gate4.db");
    let key = [0x44u8; 32];

    let transport = Arc::new(MockRotationTransport {
        fail_publish_head_once: AtomicBool::new(true),
        swap_calls: AtomicUsize::new(0),
        publish_head_calls: AtomicUsize::new(0),
        current_cid: std::sync::Mutex::new("bafyreimailboxkeys-e1".into()),
    });

    // 1. Write pending Gate 4 rotation intent to `mutation_journal` and simulate crash
    // right after `mailboxKeys/self` CAS swap succeeded, while `publishEpochHead(E+1)` fails.
    {
        let db = MlsAccountDb::open_native(&db_path, &key, OpenMode::App).unwrap();
        let payload = RotationJournalPayload {
            did: "did:plc:alice0000000000000000000".into(),
            epoch_seq: 2,
            epoch_head: [0xAB; 32],
            expected_swap_cid: Some("bafyreimailboxkeys-e1".into()),
            committed_swap_cid: None,
            mailbox_keys_cbor: b"cbor-epoch-2-keys".to_vec(),
            stage: RotationJournalStage::PendingMailboxSwap,
        };
        db.write_tx(|tx| {
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: "labyrinth-rotate-e2".into(),
                op_type: "labyrinth_epoch_rotation".into(),
                epoch_seq: 2,
                state_json: serde_json::to_string(&payload).unwrap(),
                status: "pending".into(),
                created_at_ms: 1_700_000_000_000,
                updated_at_ms: 1_700_000_000_000,
            })
        })
        .unwrap();

        let err = recover_pending_labyrinth_rotations(&db, transport.as_ref())
            .await
            .expect_err("simulated crash during publishEpochHead must surface error");
        assert!(err.to_string().contains("publishEpochHead"));

        // Verify journal persisted intermediate `MailboxSwapped` state so CAS isn't lost.
        let pending = db.read_tx(|tx| tx.list_mutation_journal_pending()).unwrap();
        assert_eq!(pending.len(), 1);
        let saved: RotationJournalPayload = serde_json::from_str(&pending[0].state_json).unwrap();
        assert_eq!(saved.stage, RotationJournalStage::MailboxSwapped);
        assert_eq!(
            saved.committed_swap_cid.as_deref(),
            Some("bafyreimailboxkeys-e2")
        );
    }

    // 2. Reopen `<did_hash>.db` cold: journal rolls forward cleanly, `publishEpochHead(2)`
    // succeeds, and the journal entry is deleted!
    {
        let db = MlsAccountDb::open_native(&db_path, &key, OpenMode::App).unwrap();
        let completed = recover_pending_labyrinth_rotations(&db, transport.as_ref())
            .await
            .expect("reopen recovery must roll forward cleanly");
        assert_eq!(completed, 1);

        let pending = db.read_tx(|tx| tx.list_mutation_journal_pending()).unwrap();
        assert!(
            pending.is_empty(),
            "completed rotation journal entry must be removed"
        );
        assert_eq!(transport.swap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.publish_head_calls.load(Ordering::SeqCst), 2);
    }
}

struct StaticSecretLookup {
    secret: [u8; 32],
    key_share: String,
}

impl SharedSecretLookup for StaticSecretLookup {
    fn shared_secret_for_space(&self, _space_uri: &str) -> Option<[u8; 32]> {
        Some(self.secret)
    }

    fn key_share_for_space(&self, _space_uri: &str) -> Option<String> {
        Some(self.key_share.clone())
    }
}

struct MockMacSpaceGateway {
    response: std::sync::Mutex<LabyrinthSpaceResponse>,
}

#[async_trait::async_trait]
impl LabyrinthSpaceGateway for MockMacSpaceGateway {
    async fn submit_space(
        &self,
        _request: LabyrinthSpaceRequest,
    ) -> Result<catbird_mls::canonical_transport::GatewayResponse, String> {
        let r = self.response.lock().unwrap().clone();
        Ok(catbird_mls::canonical_transport::GatewayResponse {
            status: r.status,
            content_type: r.content_type,
            body: r.body,
        })
    }

    async fn submit_space_with_headers(
        &self,
        _request: LabyrinthSpaceRequest,
    ) -> Result<LabyrinthSpaceResponse, String> {
        Ok(self.response.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn gate7_space_mac_verifier_and_mek_conversation_group_binding() {
    let secret = [0x77u8; 32];
    let key_share = encode_p256_did_key(
        &P256SecretKey::from_slice(&[0x33u8; 32])
            .unwrap()
            .public_key(),
    );
    let space_uri =
        "at:space/did:web:ds.catbird.blue/blue.catbird.labyrinth.conversation/convo-1-0";
    let repo_did = "did:plc:alice0000000000000000000";
    let collection = "blue.catbird.labyrinth.messageBatch";
    let rkey = "batch-001";
    let record_uri = format!("{space_uri}/{repo_did}/{collection}/{rkey}");

    // Deterministic valid CIDv1 bytes + multibase string
    let cid_bytes = vec![0x01, 0x71, 0x12, 0x20, 0xAA, 0xBB, 0xCC, 0xDD];
    let cid_str = multibase::encode(multibase::Base::Base32Lower, &cid_bytes);
    let body_json = serde_json::to_vec(&serde_json::json!({
        "uri": record_uri,
        "cid": cid_str,
        "value": { "ciphertext": "opaque" }
    }))
    .unwrap();

    let (valid_record_headers, _) = sign_record_mac(
        &secret,
        &key_share,
        DEFAULT_MAC_LABEL,
        &record_uri,
        &cid_str,
    )
    .unwrap();

    let gateway = Arc::new(MockMacSpaceGateway {
        response: std::sync::Mutex::new(LabyrinthSpaceResponse {
            status: 200,
            content_type: Some("application/json".into()),
            headers: Vec::new(), // MISSING MAC headers!
            body: body_json.clone(),
        }),
    });

    let verifier = Arc::new(AtprotoSpaceMacVerifier::new(Arc::new(StaticSecretLookup {
        secret,
        key_share: key_share.clone(),
    })));
    let transport = SpaceXrpcTransport::new(gateway.clone()).with_mac_verifier(verifier);

    // 1. Missing `Atproto-Space-Record` headers MUST be rejected before returning record JSON.
    let err = transport
        .get_record(space_uri, repo_did, collection, rkey)
        .await
        .expect_err("missing Atproto-Space-Record must fail Gate 7");
    assert_eq!(err.error.as_deref(), Some("InvalidSpaceMac"));

    // 2. Tampered `Signature` header MUST be rejected.
    *gateway.response.lock().unwrap() = LabyrinthSpaceResponse {
        status: 200,
        content_type: Some("application/json".into()),
        headers: vec![
            (
                valid_record_headers.covered_header_name.into(),
                valid_record_headers.covered_header.clone(),
            ),
            (
                SIGNATURE_INPUT_HEADER.into(),
                valid_record_headers.signature_input.clone(),
            ),
            (
                SIGNATURE_HEADER.into(),
                format!(
                    "{DEFAULT_MAC_LABEL}=:{}:",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        [0xFFu8; 32]
                    )
                ),
            ),
        ],
        body: body_json.clone(),
    };
    let err = transport
        .get_record(space_uri, repo_did, collection, rkey)
        .await
        .expect_err("tampered Atproto-Space-Record signature must fail Gate 7");
    assert_eq!(err.error.as_deref(), Some("InvalidSpaceMac"));

    // 3. Valid `Atproto-Space-Record` + `Signature-Input` + `Signature` passes cleanly!
    *gateway.response.lock().unwrap() = LabyrinthSpaceResponse {
        status: 200,
        content_type: Some("application/json".into()),
        headers: vec![
            (
                valid_record_headers.covered_header_name.into(),
                valid_record_headers.covered_header,
            ),
            (
                SIGNATURE_INPUT_HEADER.into(),
                valid_record_headers.signature_input,
            ),
            (SIGNATURE_HEADER.into(), valid_record_headers.signature),
        ],
        body: body_json,
    };
    let ok_val = transport
        .get_record(space_uri, repo_did, collection, rkey)
        .await
        .expect("valid Atproto-Space-Record must succeed");
    assert!(ok_val.is_some());

    // 4. Commit MAC (`listRepoOps` / `Atproto-Space-Commit` + `Accept-Signature`) verification:
    let data_32 = [0x55u8; 32];
    let (commit_headers, _) = sign_commit_mac(
        &secret,
        &key_share,
        DEFAULT_MAC_LABEL,
        space_uri,
        repo_did,
        "3klmno",
        &data_32,
    )
    .unwrap();
    let commit_body = serde_json::to_vec(&serde_json::json!({
        "rev": "3klmno",
        "data": { "$bytes": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data_32) },
        "ops": []
    }))
    .unwrap();
    *gateway.response.lock().unwrap() = LabyrinthSpaceResponse {
        status: 200,
        content_type: Some("application/json".into()),
        headers: vec![
            (
                commit_headers.covered_header_name.into(),
                commit_headers.covered_header,
            ),
            (
                SIGNATURE_INPUT_HEADER.into(),
                commit_headers.signature_input,
            ),
            (SIGNATURE_HEADER.into(), commit_headers.signature),
        ],
        body: commit_body,
    };
    let mut ops_req = LabyrinthSpaceRequest::get(
        "com.atproto.space.listRepoOps",
        format!(
            "/xrpc/com.atproto.space.listRepoOps?space={}&repo={}",
            space_uri, repo_did
        ),
    );
    ops_req.headers.push((
        ACCEPT_SIGNATURE_HEADER.into(),
        format_accept_signature(MacProfile::Commit, &key_share).unwrap(),
    ));
    AtprotoSpaceMacVerifier::new(Arc::new(StaticSecretLookup { secret, key_share }))
        .verify_space_response(&ops_req, &gateway.response.lock().unwrap())
        .expect("valid commit MAC on listRepoOps must succeed");

    // 5. Cross-conversation & cross-group (`group_id`) replayed MEK rejection:
    let mek = Mek::generate(&[[0x11; 32], [0x22; 32]]).unwrap();
    let expected_ctx = BoundMekContext {
        conversation_id: "convo-1".into(),
        group_id: b"group-alpha".to_vec(),
    };
    verify_mek_conversation_binding(&mek, "convo-1", b"group-alpha", &expected_ctx)
        .expect("matching conversation_id + group_id must pass");
    assert!(
        verify_mek_conversation_binding(&mek, "convo-2", b"group-alpha", &expected_ctx).is_err(),
        "cross-conversation MEK replay must fail"
    );
    assert!(
        verify_mek_conversation_binding(&mek, "convo-1", b"group-beta", &expected_ctx).is_err(),
        "cross-group_id MEK replay must fail"
    );
}

#[tokio::test]
async fn gate5_staged_to_space_attachment_promotion_and_cb22_rearchive_before_leave() {
    let steps = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    // 1. `.staged` -> `.space` attachmentManifest commits BEFORE MLS `sendMessage`.
    let steps_upload = Arc::clone(&steps);
    let steps_send = Arc::clone(&steps);
    let msg_id = send_message_with_promoted_attachments(
        vec![StagedAttachmentInput {
            rkey: "att-1".into(),
            ciphertext: b"encrypted-image-bytes".to_vec(),
            mime_type_hint: Some("image/png".into()),
            created_at: "2026-10-31T12:00:00Z".into(),
        }],
        move |att, meta| {
            let steps_upload = Arc::clone(&steps_upload);
            async move {
                assert_eq!(meta.ciphertext_size, att.ciphertext.len() as u64);
                steps_upload
                    .lock()
                    .unwrap()
                    .push(format!("promote_to_space:{}", att.rkey));
                Ok(AttachmentUploadStage::PromotedToSpace {
                    rkey: att.rkey,
                    blob_cid: "bafkreiattachment1".into(),
                    sha256: meta.sha256,
                })
            }
        },
        move |promoted| {
            let steps_send = Arc::clone(&steps_send);
            async move {
                assert_eq!(promoted.len(), 1);
                assert_eq!(promoted[0].blob_cid, "bafkreiattachment1");
                steps_send.lock().unwrap().push("mls_send_message".into());
                Ok("msg-001".to_string())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(msg_id, "msg-001");
    assert_eq!(
        *steps.lock().unwrap(),
        vec!["promote_to_space:att-1", "mls_send_message"]
    );

    // Verify failure during Space promotion aborts BEFORE MLS `sendMessage` is called!
    let send_called = Arc::new(AtomicBool::new(false));
    let send_called_clone = Arc::clone(&send_called);
    let fail_res = send_message_with_promoted_attachments(
        vec![StagedAttachmentInput {
            rkey: "att-fail".into(),
            ciphertext: b"bytes".to_vec(),
            mime_type_hint: None,
            created_at: "2026-10-31T12:00:00Z".into(),
        }],
        |_att, _meta| async move {
            Err(catbird_mls::MLSError::Internal(
                "applyWrites attachmentManifest failed".into(),
            ))
        },
        move |_promoted| {
            let send_called_clone = Arc::clone(&send_called_clone);
            async move {
                send_called_clone.store(true, Ordering::SeqCst);
                Ok("never".to_string())
            }
        },
    )
    .await;
    assert!(fail_res.is_err());
    assert!(
        !send_called.load(Ordering::SeqCst),
        "MLS sendMessage must NEVER fire if .staged -> .space promotion fails"
    );

    // 2. `[CB-22]` `execute_leave_with_rearchive` copies batches + encrypted attachments
    // into personal mailbox Space BEFORE `clearRecords` and MLS `requestLeave`.
    let leave_steps = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let ls1 = Arc::clone(&leave_steps);
    let ls2 = Arc::clone(&leave_steps);
    let ls3 = Arc::clone(&leave_steps);
    let report = execute_leave_with_rearchive(
        "convo-leave-1",
        move |cid| {
            let ls1 = Arc::clone(&ls1);
            async move {
                ls1.lock()
                    .unwrap()
                    .push(format!("rearchive_batches_and_blobs:{cid}"));
                Ok((3usize, vec!["bafkreicopiedblob1".to_string()]))
            }
        },
        move |cid| {
            let ls2 = Arc::clone(&ls2);
            async move {
                ls2.lock()
                    .unwrap()
                    .push(format!("clear_space_records:{cid}"));
                Ok(())
            }
        },
        move |cid| {
            let ls3 = Arc::clone(&ls3);
            async move {
                ls3.lock().unwrap().push(format!("mls_leave_commit:{cid}"));
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(report.messages_rearchived, 3);
    assert_eq!(report.rearchived_blob_cids, vec!["bafkreicopiedblob1"]);
    assert_eq!(
        *leave_steps.lock().unwrap(),
        vec![
            "rearchive_batches_and_blobs:convo-leave-1",
            "clear_space_records:convo-leave-1",
            "mls_leave_commit:convo-leave-1",
        ]
    );
}
