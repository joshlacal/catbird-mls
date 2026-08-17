//! Adversarial and empirical stress tests for Milestone 1.
//!
//! Covers:
//! 1. `sequencer_did_sync` edge cases and malformed inputs.
//! 2. `prepare_clean_chat_signed_request` & `prepare_clean_chat_request` fail-closed validation.
//! 3. Cryptographic binding verification across DPoP, device IDs, UUIDs, DIDs, and generations.

#![allow(dead_code)]

mod e2e_harness;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use catbird_mls::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackages;
use catbird_mls::atproto::blue_catbird::chat::{
    CanonicalDatetime, KeyPackageArtifact, KeyPackageReplenishmentBody,
    SignedKeyPackageReplenishment,
};
use catbird_mls::atproto::blue_catbird::mlsChat::ConvoView as TypedConvoView;
use catbird_mls::atproto::jacquard_common::deps::bytes::Bytes;
use catbird_mls::atproto::jacquard_common::types::string::Did;
use catbird_mls::orchestrator::canonical_transport::{
    decode_clean_chat_blob, decode_clean_chat_error, decode_clean_chat_response,
    CleanChatAuthContextFfi, CleanChatOperationFfi, CleanChatTransportFfiError,
};
use catbird_mls::orchestrator::prepare_clean_chat_signed_request;
use e2e_harness::TestWorld;
use std::str::FromStr;

fn valid_auth_ffi() -> CleanChatAuthContextFfi {
    CleanChatAuthContextFfi {
        authorization: "DPoP sample-valid-access-token".into(),
        dpop_proof: "sample-valid-dpop-proof".into(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        device_id: "11111111-1111-4111-8111-111111111111".into(),
        auth_generation: Some(1),
    }
}

fn enrollment_request_json(device_id: &str, dpop_jkt: &str, expected_generation: i64) -> Vec<u8> {
    serde_json::json!({
        "signedRequest": {
            "body": {
                "actorDid": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
                "capability": {
                    "addByValue": "allowed",
                    "applicationFrameProfile": "v1",
                    "attachmentProfile": "v1",
                    "cipherSuite": "0x004D",
                    "controlProfile": "v1",
                    "credentialType": "basic",
                    "externalPubGroupInfo": "allowed",
                    "metadataProfile": "v1",
                    "mlsVersion": "1.0",
                    "protocolVersion": "1",
                    "ratchetTreeGroupInfo": "allowed",
                    "removeByValue": "allowed",
                    "typingProfile": "v1",
                    "updatePath": "allowed"
                },
                "deviceId": device_id,
                "deviceName": "test device",
                "dpopJkt": dpop_jkt,
                "expectedAuthGeneration": expected_generation,
                "idempotencyKey": "22222222-2222-4222-8222-222222222222",
                "keyId": "test-key",
                "keyPackages": [],
                "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0000}",
                "signaturePublicKey": {"$bytes": BASE64.encode(vec![0; 32])},
                "signedAt": "2026-08-16T12:00:00.000Z"
            },
            "signature": {"$bytes": BASE64.encode(vec![0; 64])}
        }
    })
    .to_string()
    .into_bytes()
}

fn rebind_request_json(
    actor_device_id: &str,
    current_dpop_jkt: &str,
    new_dpop_jkt: &str,
    expected_generation: i64,
) -> Vec<u8> {
    serde_json::json!({
        "signedRequest": {
            "body": {
                "actorDeviceId": actor_device_id,
                "actorDid": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
                "currentDpopJkt": current_dpop_jkt,
                "expectedAuthGeneration": expected_generation,
                "idempotencyKey": "22222222-2222-4222-8222-222222222222",
                "keyId": "test-key",
                "newDpopJkt": new_dpop_jkt,
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0000}",
                "signedAt": "2026-08-16T12:00:00.000Z"
            },
            "signature": {"$bytes": BASE64.encode(vec![0; 64])}
        }
    })
    .to_string()
    .into_bytes()
}

fn replenish_request_json(
    actor_device_id: &str,
    actor_did: &str,
    dpop_jkt: &str,
    auth_gen: i64,
) -> Vec<u8> {
    let req = ReplenishKeyPackages::<String> {
        signed_request: SignedKeyPackageReplenishment {
            body: KeyPackageReplenishmentBody {
                actor_device_id: actor_device_id.to_string(),
                actor_did: Did::from_str(actor_did).unwrap(),
                auth_generation: auth_gen,
                dpop_jkt: dpop_jkt.to_string(),
                idempotency_key: "22222222-2222-4222-8222-222222222222".to_string(),
                key_id: "test-key".to_string(),
                key_packages: vec![KeyPackageArtifact {
                    bytes: Bytes::from_static(b"key-package"),
                    content_type: "keyPackage".into(),
                    framing: "mlsMessage".into(),
                    key_package_ref: Bytes::from(vec![1; 32]),
                    sha256: Bytes::from(vec![2; 32]),
                    extra_data: None,
                }],
                signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\u{0000}".to_string(),
                signature_public_key: Bytes::from(vec![0; 32]),
                signed_at: CanonicalDatetime::from_str("2026-08-16T12:00:00.000Z").unwrap(),
                extra_data: None,
            },
            signature: Bytes::from(vec![0; 64]),
            extra_data: None,
        },
        extra_data: None,
    };
    serde_json::to_vec(&req).unwrap()
}

// ===========================================================================
// 1. Stress Tests: Sequencer DID Sync & Wire Model
// ===========================================================================

#[test]
fn test_sequencer_did_wire_deserialization_fuzz_and_edge_cases() {
    // 1. Missing field -> None
    let wire_none = r#"{
        "conversationId": "c-1",
        "groupId": "g-1",
        "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [],
        "epoch": 1,
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z"
    }"#;
    let typed_none: TypedConvoView = serde_json::from_str(wire_none).expect("parse none");
    assert!(typed_none.sequencer_did.is_none());

    // 2. Explicit null -> None
    let wire_null = r#"{
        "conversationId": "c-1",
        "groupId": "g-1",
        "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [],
        "epoch": 1,
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z",
        "sequencerDid": null
    }"#;
    let typed_null: TypedConvoView = serde_json::from_str(wire_null).expect("parse null");
    assert!(typed_null.sequencer_did.is_none());

    // 3. Valid DID
    let wire_valid = r#"{
        "conversationId": "c-1",
        "groupId": "g-1",
        "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [],
        "epoch": 1,
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z",
        "sequencerDid": "did:web:ds-node-01.prod.example"
    }"#;
    let typed_valid: TypedConvoView = serde_json::from_str(wire_valid).expect("parse valid");
    assert_eq!(
        typed_valid.sequencer_did.as_ref().map(|d| d.as_str()),
        Some("did:web:ds-node-01.prod.example")
    );

    // 4. Invalid types for sequencerDid (integers, booleans, objects, arrays) must fail parsing
    let wire_int = r#"{
        "conversationId": "c-1", "groupId": "g-1", "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [], "epoch": 1, "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z",
        "sequencerDid": 12345
    }"#;
    assert!(serde_json::from_str::<TypedConvoView>(wire_int).is_err());

    let wire_obj = r#"{
        "conversationId": "c-1", "groupId": "g-1", "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [], "epoch": 1, "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z",
        "sequencerDid": { "did": "did:web:bad" }
    }"#;
    assert!(serde_json::from_str::<TypedConvoView>(wire_obj).is_err());

    let wire_arr = r#"{
        "conversationId": "c-1", "groupId": "g-1", "creator": "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        "members": [], "epoch": 1, "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "createdAt": "2026-08-16T12:00:00.000Z",
        "sequencerDid": ["did:web:bad"]
    }"#;
    assert!(serde_json::from_str::<TypedConvoView>(wire_arr).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_did_state_transitions_and_rapid_changes() {
    let mut world = TestWorld::new();
    world.add_client("Alice").await;
    world.register_device("Alice").await.expect("reg alice");

    let alice = world.client("Alice");
    let convo = alice
        .orchestrator
        .create_group("Adversarial Seq Test", None, None)
        .await
        .expect("create group");
    let convo_id = convo.conversation_id.clone();

    // 1. Initial sync with no sequencer
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync initial");
    assert_eq!(
        alice.storage.get_persisted_sequencer(&convo_id),
        None,
        "Initial state should have no sequencer"
    );

    // 2. Transition None -> Some("did:web:seq1.example")
    world
        .api_service
        .set_conversation_sequencer_for_test(&convo_id, Some("did:web:seq1.example".to_string()));
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync to seq1");
    assert_eq!(
        alice.storage.get_persisted_sequencer(&convo_id).as_deref(),
        Some("did:web:seq1.example")
    );
    let count1 = alice
        .storage
        .set_conversation_sequencer_call_count(&convo_id);
    assert_eq!(count1, 1);

    // 3. Repeated sync with unchanged value -> No re-persist
    for _ in 0..5 {
        alice
            .orchestrator
            .sync_with_server(false)
            .await
            .expect("sync unchanged");
    }
    assert_eq!(
        alice
            .storage
            .set_conversation_sequencer_call_count(&convo_id),
        count1,
        "Idempotent sync must not increment persist calls"
    );

    // 4. Transition Some("did:web:seq1") -> Some("did:web:seq2")
    world
        .api_service
        .set_conversation_sequencer_for_test(&convo_id, Some("did:web:seq2.example".to_string()));
    alice
        .orchestrator
        .sync_with_server(false)
        .await
        .expect("sync to seq2");
    assert_eq!(
        alice.storage.get_persisted_sequencer(&convo_id).as_deref(),
        Some("did:web:seq2.example")
    );
    assert_eq!(
        alice
            .storage
            .set_conversation_sequencer_call_count(&convo_id),
        count1 + 1
    );

    // 5. In-memory map consistency
    let in_mem = alice
        .orchestrator
        .conversations()
        .lock()
        .await
        .get(&convo_id)
        .and_then(|v| v.sequencer_did.clone());
    assert_eq!(in_mem.as_deref(), Some("did:web:seq2.example"));
}

// ===========================================================================
// 2. Stress Tests: Fail-Closed Input Validation on `prepare_clean_chat_signed_request`
// ===========================================================================

#[test]
fn test_auth_context_fail_closed_on_invalid_credentials() {
    let valid = valid_auth_ffi();

    // 1. Missing / whitespace authorization
    for bad_auth in ["", "   ", "\t\n", " \r "] {
        let ctx = CleanChatAuthContextFfi {
            authorization: bad_auth.to_string(),
            ..valid.clone()
        };
        let res = prepare_clean_chat_signed_request(
            ctx,
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(&valid.device_id, &valid.dpop_jkt, 0),
        );
        assert!(res.is_err(), "Empty authorization must fail closed");
    }

    // 2. Missing / whitespace DPoP proof
    for bad_proof in ["", "   ", "\t\n"] {
        let ctx = CleanChatAuthContextFfi {
            dpop_proof: bad_proof.to_string(),
            ..valid.clone()
        };
        let res = prepare_clean_chat_signed_request(
            ctx,
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(&valid.device_id, &valid.dpop_jkt, 0),
        );
        assert!(res.is_err(), "Empty DPoP proof must fail closed");
    }

    // 3. Malformed DPoP JKT (must be canonical 43-character base64url)
    let bad_jkts = [
        "",                                             // empty
        "   ",                                          // whitespace
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   // 42 chars (too short)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 44 chars (too long)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // padded base64 (illegal in base64url)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+", // '+' character (illegal in base64url)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/", // '/' character (illegal in base64url)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!", // non-base64 character
        "-------------------------------------------", // non-canonical base64url
    ];
    for bad_jkt in bad_jkts {
        let ctx = CleanChatAuthContextFfi {
            dpop_jkt: bad_jkt.to_string(),
            ..valid.clone()
        };
        let res = prepare_clean_chat_signed_request(
            ctx,
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(&valid.device_id, bad_jkt, 0),
        );
        assert!(
            res.is_err(),
            "Malformed DPoP JKT '{bad_jkt}' must fail closed"
        );
    }

    // 4. Malformed Device ID (must be canonical lowercase UUIDv4)
    let upper_uuid = "abcdef01-1111-4111-8111-111111111111".to_uppercase();
    let bad_device_ids = [
        "",
        "not-a-uuid",
        upper_uuid.as_str(),                     // uppercase rejected
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",  // UUIDv1 rejected
        "11111111-1111-3111-8111-111111111111",  // UUIDv3 rejected
        "11111111-1111-5111-8111-111111111111",  // UUIDv5 rejected
        "11111111-1111-4111-0111-111111111111", // Variant 0 (NCS) rejected
        "11111111-1111-4111-c111-111111111111", // Variant 2 (Microsoft) rejected
        "{11111111-1111-4111-8111-111111111111}", // Braces rejected
        "11111111-1111-4111-8111-111111111111 ", // Trailing space rejected
    ];
    for bad_dev in bad_device_ids {
        let ctx = CleanChatAuthContextFfi {
            device_id: bad_dev.to_string(),
            ..valid.clone()
        };
        let res = prepare_clean_chat_signed_request(
            ctx,
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(bad_dev, &valid.dpop_jkt, 0),
        );
        assert!(
            res.is_err(),
            "Non-canonical device UUID '{bad_dev}' must fail closed"
        );
    }
}

#[test]
fn test_prepare_clean_chat_signed_request_payload_fuzz_and_tampering() {
    let valid = valid_auth_ffi();

    // 1. Empty payload
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::EnrollDevice,
        vec![],
    );
    assert!(res.is_err(), "Empty payload must fail");

    // 2. Corrupted JSON / non-JSON bytes
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::EnrollDevice,
        b"{ not json }".to_vec(),
    );
    assert!(res.is_err(), "Corrupted JSON must fail");

    // 3. Missing signedRequest wrapper
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::EnrollDevice,
        b"{\"actorDid\": \"did:plc:z72i7hdynmk67x4h5wqf3s6a\"}".to_vec(),
    );
    assert!(res.is_err(), "Missing signedRequest must fail");

    // 4. Device ID mismatch between auth context and body
    let mismatched_dev = enrollment_request_json(
        "99999999-9999-4999-8999-999999999999",
        &valid.dpop_jkt,
        0,
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::EnrollDevice,
        mismatched_dev,
    );
    assert!(
        matches!(
            res,
            Err(CleanChatTransportFfiError::InvalidRequest { message }) if message.contains("device")
        ),
        "Mismatched device ID must fail closed"
    );

    // 5. DPoP JKT mismatch between auth context and body
    let other_jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let mismatched_jkt = enrollment_request_json(&valid.device_id, other_jkt, 0);
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::EnrollDevice,
        mismatched_jkt,
    );
    assert!(
        matches!(
            res,
            Err(CleanChatTransportFfiError::InvalidRequest { message }) if message.contains("DPoP") || message.contains("dpopJkt")
        ),
        "Mismatched DPoP JKT must fail closed"
    );

    // 6. Enrollment generation must strictly be 0
    for bad_gen in [1, 2, -1, 99] {
        let bad_gen_json = enrollment_request_json(&valid.device_id, &valid.dpop_jkt, bad_gen);
        let res = prepare_clean_chat_signed_request(
            valid.clone(),
            CleanChatOperationFfi::EnrollDevice,
            bad_gen_json,
        );
        assert!(
            res.is_err(),
            "Enrollment with generation {bad_gen} must fail closed"
        );
    }

    // 7. Rebind validation: currentDpopJkt and newDpopJkt checks
    let rebind_valid = rebind_request_json(
        &valid.device_id,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        &valid.dpop_jkt,
        1,
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::RebindDeviceAuthentication,
        rebind_valid,
    );
    assert!(res.is_ok(), "Valid rebind should succeed");

    // Rebind with newDpopJkt mismatched with auth.dpop_jkt
    let rebind_jkt_mismatch = rebind_request_json(
        &valid.device_id,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        1,
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::RebindDeviceAuthentication,
        rebind_jkt_mismatch,
    );
    assert!(
        res.is_err(),
        "Rebind with mismatched newDpopJkt must fail closed"
    );

    // Rebind with wrong auth generation
    let rebind_gen_mismatch = rebind_request_json(
        &valid.device_id,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        &valid.dpop_jkt,
        2, // expected 1 from valid_auth_ffi
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::RebindDeviceAuthentication,
        rebind_gen_mismatch,
    );
    assert!(
        res.is_err(),
        "Rebind with mismatched auth generation must fail closed"
    );

    // 8. ReplenishKeyPackages validation via prepare_clean_chat_signed_request
    let replenish_valid = replenish_request_json(
        &valid.device_id,
        "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        &valid.dpop_jkt,
        1,
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::ReplenishKeyPackages,
        replenish_valid,
    );
    assert!(
        res.is_ok(),
        "Valid replenish should succeed: {:?}",
        res.err()
    );

    // Replenish with mismatched generation
    let replenish_bad_gen = replenish_request_json(
        &valid.device_id,
        "did:plc:z72i7hdynmk67x4h5wqf3s6a",
        &valid.dpop_jkt,
        2,
    );
    let res = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::ReplenishKeyPackages,
        replenish_bad_gen,
    );
    assert!(
        res.is_err(),
        "Replenish with mismatched auth generation must fail"
    );
}

#[test]
fn test_unsupported_operations_fail_closed() {
    let valid = valid_auth_ffi();

    // 1. UploadBlob cannot use JSON transport (fails either on parse or in prepare)
    let res_empty = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::UploadBlob,
        b"{}".to_vec(),
    );
    assert!(res_empty.is_err(), "UploadBlob with empty body must fail");

    let res_typed = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::UploadBlob,
        serde_json::to_vec(&serde_json::json!({
            "body": "AQIDBA=="
        }))
        .unwrap(),
    );
    assert!(
        matches!(
            res_typed,
            Err(CleanChatTransportFfiError::InvalidRequest { message }) if message.contains("uploadBlob") || message.contains("octet-stream")
        ),
        "UploadBlob must fail closed with explicit unsupported operation reason"
    );

    // 2. SubscribeEvents cannot use JSON transport
    let res_empty = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::SubscribeEvents,
        b"{}".to_vec(),
    );
    assert!(
        res_empty.is_err(),
        "SubscribeEvents with empty body must fail"
    );

    let res_typed = prepare_clean_chat_signed_request(
        valid.clone(),
        CleanChatOperationFfi::SubscribeEvents,
        serde_json::to_vec(&serde_json::json!({
            "cursor": "0",
            "ticket": "ticket-token"
        }))
        .unwrap(),
    );
    assert!(
        matches!(
            res_typed,
            Err(CleanChatTransportFfiError::InvalidRequest { message }) if message.contains("subscribeEvents") || message.contains("WebSocket")
        ),
        "SubscribeEvents must fail closed with explicit unsupported operation reason"
    );
}

#[test]
fn test_decoder_fuzz_and_resilience() {
    // 1. decode_clean_chat_blob preserves bytes exactly
    let raw_bytes = vec![0x00, 0xFF, 0xFE, 0xAA, 0x55, 0x12, 0x34];
    let decoded = decode_clean_chat_blob(raw_bytes.clone()).expect("blob decodes");
    assert_eq!(decoded, raw_bytes);

    let empty_bytes = vec![];
    let decoded_empty = decode_clean_chat_blob(empty_bytes).expect("empty blob decodes");
    assert!(decoded_empty.is_empty());

    // 2. decode_clean_chat_response on invalid json -> error
    let bad_response = decode_clean_chat_response(
        CleanChatOperationFfi::GetConversations,
        b"not json".to_vec(),
    );
    assert!(bad_response.is_err(), "Invalid JSON response must error");

    // 3. decode_clean_chat_error on invalid json -> error
    let bad_error = decode_clean_chat_error(
        CleanChatOperationFfi::GetConversations,
        b"{ bad json }".to_vec(),
    );
    assert!(bad_error.is_err(), "Invalid JSON error must error");
}
