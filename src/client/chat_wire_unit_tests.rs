use super::*;
use crate::storage::KvWriteBatch;

fn sample_coordinate(cid: &str, generation: i64, state_version: i64, epoch: i64) -> Value {
    json!({
        "conversationId": cid,
        "generation": generation,
        "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode([7u8; 32]) },
        "epoch": epoch,
        "groupContextHash": { "$bytes": STANDARD.encode([8u8; 32]) },
        "confirmationTag": { "$bytes": STANDARD.encode([9u8; 32]) },
        "lifecycle": "active",
    })
}

fn sample_pending_group_creation(
    attempts: Vec<PendingGroupCreationAttempt>,
    retry_at_ms: i64,
    retry_count: u32,
    retry_code: Option<&str>,
) -> PendingGroupCreation {
    PendingGroupCreation {
        version: GROUP_CREATION_JOURNAL_VERSION,
        conversation_id: "11111111-1111-4111-8111-111111111111".to_string(),
        journal_id: "22222222-2222-4222-8222-222222222222".to_string(),
        sequencer_did: "did:web:sequencer.example.com".to_string(),
        group_id: vec![7u8; 32],
        signer_public_key: vec![3u8; 32],
        attempts,
        kv_batch: KvWriteBatch::default(),
        title: None,
        description: None,
        new_signer_json: None,
        created_at_ms: 1_000,
        retry_at_ms,
        retry_count,
        retry_code: retry_code.map(str::to_owned),
    }
}

#[test]
fn peer_send_counter_safe_integer_boundary_and_state_keys() {
    assert!(verify_next_peer_send_counter(None, 9_007_199_254_740_991).is_ok());
    assert!(verify_next_peer_send_counter(Some("9007199254740990"), 9_007_199_254_740_991).is_ok());
    assert!(verify_next_peer_send_counter(None, 9_007_199_254_740_992).is_err());
    assert!(verify_next_peer_send_counter(None, u64::MAX).is_err());

    assert_eq!(fork_detected_key("convo-abc"), "fork_detected:convo-abc");
    assert_eq!(
        verified_reset_request_key("convo-abc"),
        "verified_reset_request:convo-abc"
    );
}

#[test]
fn own_commit_body_projects_verified_transition_and_rejects_wrong_signer() {
    let cid = "11111111-1111-4111-8111-111111111111";
    let transition_id = "22222222-2222-4222-8222-222222222222";
    let device_id = "33333333-3333-4333-8333-333333333333";
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("ed25519 signer");
    let other_signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("other signer");
    let key_id = derive_key_id(signer.public());

    let body = json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
        "resetRequestId": transition_id,
        "actorDid": "did:plc:alicewireaaaaaaaaaaaaaaa",
        "actorDeviceId": device_id,
        "keyId": key_id,
        "authGeneration": 1,
        "prior": sample_coordinate(cid, 0, 1, 2),
        "reason": "manualRecovery",
        "idempotencyKey": transition_id,
        "signedAt": "2026-11-13T00:00:00.000Z",
    });

    let prepared = sign_clean_chat_mutation(
        "did:plc:alicewireaaaaaaaaaaaaaaa",
        device_id,
        Some(1),
        CanonicalOperation::RequestReset,
        &body,
        &signer,
    )
    .expect("sign reset request");
    let request_json: Value =
        serde_json::from_slice(prepared.body.as_deref().expect("request bytes"))
            .expect("request json");
    let signed_wrapper = &request_json["signedRequest"];

    let verified =
        verify_own_commit_body(signed_wrapper, signer.public()).expect("verify own reset request");
    assert_eq!(verified["resetRequestId"], transition_id);
    assert_eq!(verified["actorDid"], "did:plc:alicewireaaaaaaaaaaaaaaa");
    assert!(verify_own_commit_body(signed_wrapper, other_signer.public()).is_err());
}

#[test]
fn pending_group_creation_status_deferral_expiry_and_refusal_classifiers() {
    let initial = sample_pending_group_creation(vec![], 5_000, 0, None);
    assert_eq!(initial.status_at(1_000).retry_at_ms, None);
    assert!(!initial.retry_is_deferred_at(1_000));

    let retried_without_code = sample_pending_group_creation(vec![], 5_000, 1, None);
    assert_eq!(
        retried_without_code.status_at(1_000).retry_at_ms,
        Some(5_000)
    );
    assert!(!retried_without_code.retry_is_deferred_at(5_000));
    assert!(retried_without_code.retry_is_deferred_at(4_999));

    let coded_without_count = sample_pending_group_creation(vec![], 6_000, 0, Some("RateLimited"));
    assert_eq!(
        coded_without_count.status_at(1_000).retry_at_ms,
        Some(6_000)
    );
    assert_eq!(
        coded_without_count
            .status_at(1_000)
            .last_error_code
            .as_deref(),
        Some("RateLimited")
    );

    assert_eq!(GROUP_CREATION_ABANDON_AFTER_MS, 360_000);

    let attempt_5s = PendingGroupCreationAttempt {
        operation_id: "44444444-4444-4444-8444-444444444444".to_string(),
        signed_at: "1970-01-01T00:00:05.123Z".to_string(),
        request: b"{}".to_vec(),
        expired_confirmed: false,
    };
    assert_eq!(
        group_creation_attempt_signed_at_ms(&attempt_5s).expect("valid signedAt"),
        5_123
    );
    let invalid_attempt = PendingGroupCreationAttempt {
        signed_at: "not-a-timestamp".to_string(),
        ..attempt_5s.clone()
    };
    assert!(group_creation_attempt_signed_at_ms(&invalid_attempt).is_err());

    assert!(group_creation_attempts_expired_at(&initial, 10_000).is_err());

    let single = sample_pending_group_creation(vec![attempt_5s.clone()], 0, 0, None);
    assert!(
        !group_creation_attempts_expired_at(&single, 5_123 + GROUP_CREATION_ABANDON_AFTER_MS)
            .expect("boundary not yet expired")
    );
    assert!(group_creation_attempts_expired_at(
        &single,
        5_123 + GROUP_CREATION_ABANDON_AFTER_MS + 1
    )
    .expect("past abandon threshold"));

    let confirmed = PendingGroupCreationAttempt {
        expired_confirmed: true,
        ..attempt_5s.clone()
    };
    let single_confirmed = sample_pending_group_creation(vec![confirmed.clone()], 0, 0, None);
    assert!(group_creation_attempts_expired_at(&single_confirmed, 5_123)
        .expect("server confirmed expiry"));

    let mixed = sample_pending_group_creation(vec![confirmed, attempt_5s], 0, 0, None);
    assert!(!group_creation_attempts_expired_at(&mixed, 5_123)
        .expect("fresh second attempt keeps journal live"));

    assert!(group_creation_refusal_is_expired(
        400,
        Some("SignedOperationExpired")
    ));
    assert!(!group_creation_refusal_is_expired(
        400,
        Some("InvalidRequest")
    ));
    assert!(!group_creation_refusal_is_expired(
        500,
        Some("SignedOperationExpired")
    ));

    assert!(group_creation_refusal_is_exists_evidence(
        400,
        Some("ConversationAlreadyExists")
    ));
    assert!(group_creation_refusal_is_exists_evidence(
        409,
        Some("IdempotencyConflict")
    ));
    assert!(!group_creation_refusal_is_exists_evidence(
        400,
        Some("SignedOperationExpired")
    ));
    assert!(!group_creation_refusal_is_exists_evidence(503, None));

    assert!(!group_creation_refusal_is_permanent(
        400,
        Some("ConversationAlreadyExists")
    ));
    assert!(!group_creation_refusal_is_permanent(
        400,
        Some("SignedOperationExpired")
    ));
    assert!(group_creation_refusal_is_permanent(
        400,
        Some("InvalidRequest")
    ));
    assert!(group_creation_refusal_is_permanent(403, None));
    assert!(group_creation_refusal_is_permanent(
        401,
        Some("DeviceRevoked")
    ));
    assert!(!group_creation_refusal_is_permanent(
        401,
        Some("ExpiredToken")
    ));
    assert!(group_creation_refusal_is_permanent(
        500,
        Some("InvalidRequest")
    ));
    assert!(!group_creation_refusal_is_permanent(
        500,
        Some("InternalError")
    ));
    assert!(!group_creation_refusal_is_permanent(503, None));

    assert_eq!(group_creation_retry_delay_ms(3, None), 4_000);
    assert_eq!(group_creation_retry_delay_ms(1, Some(600)), 300_000);
}

#[test]
fn invitation_provenance_fulfillment_welcome_receipt_actor_and_leaf_slice_guards() {
    let valid_prov = json!({
        "invitationTransitionId": "tx-1",
        "invitedByDid": "did:plc:alicewireaaaaaaaaaaaaaaa",
        "invitedByDeviceId": "dev-a",
    });
    assert!(canonical_invitation_provenance_value(&valid_prov).is_some());
    for empty_field in [
        "invitationTransitionId",
        "invitedByDid",
        "invitedByDeviceId",
    ] {
        let mut mutated = valid_prov.clone();
        mutated[empty_field] = json!("");
        assert!(
            canonical_invitation_provenance_value(&mutated).is_none(),
            "empty {empty_field} must fail closed"
        );
    }

    let cid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let welcome = b"mls-welcome-payload";
    let welcome_digest = Sha256::digest(welcome);
    let fulfillment_body = json!({
        "prior": sample_coordinate(cid, 0, 1, 1),
        "next": sample_coordinate(cid, 0, 2, 2),
        "recoveryRequestId": "req-1",
        "manifest": {
            "leafRecoveryRequestId": "req-1",
            "leafChanges": [{
                "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                "userDid": "did:plc:bobwirebbbbbbbbbbbbbbbbb",
                "deviceId": "dev-b",
                "recoveryRequestId": "req-1",
            }],
            "welcomeBundle": {
                "opaqueWelcome": { "$bytes": STANDARD.encode(welcome) },
                "sha256": { "$bytes": STANDARD.encode(welcome_digest) },
                "deliveries": [{
                    "recipientDid": "did:plc:bobwirebbbbbbbbbbbbbbbbb",
                    "recipientDeviceId": "dev-b",
                    "provenance": { "recoveryRequestId": "req-1" },
                }],
            },
        },
    });
    assert!(fulfillment_welcome_next(
        &fulfillment_body,
        cid,
        welcome,
        "did:plc:bobwirebbbbbbbbbbbbbbbbb",
        "dev-b"
    )
    .is_ok());

    let mut wrong_welcome_bytes = fulfillment_body.clone();
    wrong_welcome_bytes["manifest"]["welcomeBundle"]["opaqueWelcome"] =
        json!({ "$bytes": STANDARD.encode(b"different-welcome") });
    assert!(fulfillment_welcome_next(
        &wrong_welcome_bytes,
        cid,
        welcome,
        "did:plc:bobwirebbbbbbbbbbbbbbbbb",
        "dev-b"
    )
    .is_err());

    let mut wrong_welcome_hash = fulfillment_body;
    wrong_welcome_hash["manifest"]["welcomeBundle"]["sha256"] =
        json!({ "$bytes": STANDARD.encode([0u8; 32]) });
    assert!(fulfillment_welcome_next(
        &wrong_welcome_hash,
        cid,
        welcome,
        "did:plc:bobwirebbbbbbbbbbbbbbbbb",
        "dev-b"
    )
    .is_err());

    let sequencer_did = "did:web:sequencer.example.com";
    let entry_id = "33333333-3333-4333-8333-333333333333";
    let request_digest = [9u8; 32];
    let receipt_key = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).expect("p256 key");
    let receipt_sec1 = receipt_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
        sequencer_did: sequencer_did.into(),
        conversation_id: cid.into(),
        group_id: vec![7u8; 32],
        epoch: 3,
        sender_device_did_url: "did:plc:senderwiredddddddddddddd#device".into(),
        entry_id: entry_id.into(),
        archive_commitment: request_digest,
        seq: 4,
        issued_at_ms: 1_762_000_000_000,
    };
    let signed = labyrinth_protocol::receipt::sign_sequencer_receipt(
        &receipt_key,
        &format!("{sequencer_did}#mls-receipt-1"),
        &payload,
    )
    .expect("sign receipt");
    let receipt = json!({
        "kid": signed.key_id,
        "sequencerDid": sequencer_did,
        "conversationId": cid,
        "generation": 0,
        "groupId": { "$bytes": STANDARD.encode([7u8; 32]) },
        "epoch": 3,
        "seq": 4,
        "entryId": entry_id,
        "senderDid": "did:plc:senderwiredddddddddddddd",
        "senderDeviceId": "device",
        "archiveCommitment": { "$bytes": STANDARD.encode(request_digest) },
        "issuedAtMs": 1_762_000_000_000i64,
        "signature": { "$bytes": STANDARD.encode(signed.signature) },
    });
    let coord = sample_coordinate(cid, 0, 1, 3);
    assert!(verify_control_sequencer_receipt(
        &receipt,
        &receipt_sec1,
        sequencer_did,
        cid,
        entry_id,
        4,
        "did:plc:senderwiredddddddddddddd",
        "device",
        &coord,
        &request_digest,
    )
    .is_ok());
    assert!(verify_control_sequencer_receipt(
        &receipt,
        &receipt_sec1,
        sequencer_did,
        cid,
        entry_id,
        4,
        "did:plc:otherwireccccccccccccccc",
        "device",
        &coord,
        &request_digest,
    )
    .is_err());
    assert!(verify_control_sequencer_receipt(
        &receipt,
        &receipt_sec1,
        sequencer_did,
        cid,
        entry_id,
        4,
        "did:plc:senderwiredddddddddddddd",
        "other-device",
        &coord,
        &request_digest,
    )
    .is_err());

    assert!(verify_leaf_slice_i4(b"did:plc:alice#dev-1", &[7u8; 32], &[]).is_err());
}
