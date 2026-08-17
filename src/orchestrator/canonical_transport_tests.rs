use super::canonical_transport::{
    canonical_replenishment_transcript, canonical_route, derive_key_id, get_conversations,
    get_entries, map_wire_error, replenish_key_packages, route_for_nsid, validate_auth_generation,
    validate_bare_did, validate_datetime, validate_jkt, validate_key_packages, validate_uuid,
    CanonicalOperation, CleanChatAuthContext, CleanChatError, CleanChatRequest, CleanChatResponse,
    ReplenishKeyPackagesInput, TransportAuth, TransportError,
};
use std::str::FromStr;

fn auth() -> TransportAuth {
    TransportAuth {
        authorization: "Bearer gateway-token".into(),
        dpop_proof: "signed-dpop-proof".into(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        device_id: "11111111-1111-4111-8111-111111111111".into(),
    }
}

fn key_package() -> crate::atproto::blue_catbird::chat::KeyPackageArtifact<String> {
    use crate::atproto::jacquard_common::deps::bytes::Bytes;
    crate::atproto::blue_catbird::chat::KeyPackageArtifact {
        bytes: Bytes::from_static(b"key-package"),
        content_type: "keyPackage".into(),
        framing: "mlsMessage".into(),
        key_package_ref: Bytes::from(vec![1; 32]),
        sha256: Bytes::from(vec![2; 32]),
        extra_data: None,
    }
}

#[test]
fn canonical_routes_never_emit_the_legacy_mls_chat_namespace() {
    for operation in CanonicalOperation::ALL {
        let route = canonical_route(*operation);
        assert!(
            route.nsid.starts_with("blue.catbird.chat."),
            "{} still routes through the legacy namespace",
            route.nsid
        );
        assert_eq!(route.path, format!("/xrpc/{}", route.nsid));
    }
}

#[test]
fn canonical_generated_query_uses_the_generated_page_cursor_shape() {
    use crate::atproto::blue_catbird::chat::get_conversations::GetConversations;

    let request = GetConversations {
        limit: 25,
        page_cursor: Some("opaque-cursor".to_owned()),
    };
    let value = serde_json::to_value(request).expect("generated request serializes");
    assert_eq!(value["limit"], 25);
    assert_eq!(value["pageCursor"], "opaque-cursor");
    assert!(value.get("cursor").is_none());
}

#[test]
fn canonical_route_inventory_covers_only_generated_endpoints() {
    let expected = [
        (
            CanonicalOperation::AcceptConversation,
            "blue.catbird.chat.acceptConversation",
        ),
        (
            CanonicalOperation::AcknowledgeWelcome,
            "blue.catbird.chat.acknowledgeWelcome",
        ),
        (
            CanonicalOperation::ActivateReset,
            "blue.catbird.chat.activateReset",
        ),
        (
            CanonicalOperation::CancelLeafRecovery,
            "blue.catbird.chat.cancelLeafRecovery",
        ),
        (
            CanonicalOperation::CancelLeave,
            "blue.catbird.chat.cancelLeave",
        ),
        (
            CanonicalOperation::CloseConversation,
            "blue.catbird.chat.closeConversation",
        ),
        (
            CanonicalOperation::GetConversations,
            "blue.catbird.chat.getConversations",
        ),
        (
            CanonicalOperation::CreateConversation,
            "blue.catbird.chat.createConversation",
        ),
        (
            CanonicalOperation::DeleteBlob,
            "blue.catbird.chat.deleteBlob",
        ),
        (
            CanonicalOperation::SendMessage,
            "blue.catbird.chat.sendMessage",
        ),
        (CanonicalOperation::GetBlob, "blue.catbird.chat.getBlob"),
        (
            CanonicalOperation::GetBlobUsage,
            "blue.catbird.chat.getBlobUsage",
        ),
        (
            CanonicalOperation::GetConversationState,
            "blue.catbird.chat.getConversationState",
        ),
        (
            CanonicalOperation::GetDevices,
            "blue.catbird.chat.getDevices",
        ),
        (
            CanonicalOperation::GetEntries,
            "blue.catbird.chat.getEntries",
        ),
        (
            CanonicalOperation::GetLeafRecoveryInbox,
            "blue.catbird.chat.getLeafRecoveryInbox",
        ),
        (
            CanonicalOperation::GetOwnDevices,
            "blue.catbird.chat.getOwnDevices",
        ),
        (
            CanonicalOperation::GetPendingWelcomes,
            "blue.catbird.chat.getPendingWelcomes",
        ),
        (
            CanonicalOperation::GetSubscriptionTicket,
            "blue.catbird.chat.getSubscriptionTicket",
        ),
        (
            CanonicalOperation::PrepareBlobUpload,
            "blue.catbird.chat.prepareBlobUpload",
        ),
        (
            CanonicalOperation::PublishTyping,
            "blue.catbird.chat.publishTyping",
        ),
        (
            CanonicalOperation::RebindDeviceAuthentication,
            "blue.catbird.chat.rebindDeviceAuthentication",
        ),
        (
            CanonicalOperation::RejectWelcome,
            "blue.catbird.chat.rejectWelcome",
        ),
        (
            CanonicalOperation::ReplenishKeyPackages,
            "blue.catbird.chat.replenishKeyPackages",
        ),
        (
            CanonicalOperation::RequestLeafRecovery,
            "blue.catbird.chat.requestLeafRecovery",
        ),
        (
            CanonicalOperation::EnrollDevice,
            "blue.catbird.chat.enrollDevice",
        ),
        (
            CanonicalOperation::RequestLeave,
            "blue.catbird.chat.requestLeave",
        ),
        (
            CanonicalOperation::RequestReset,
            "blue.catbird.chat.requestReset",
        ),
        (
            CanonicalOperation::RevokeDevice,
            "blue.catbird.chat.revokeDevice",
        ),
        (
            CanonicalOperation::SubmitTransition,
            "blue.catbird.chat.submitTransition",
        ),
        (
            CanonicalOperation::SubscribeEvents,
            "blue.catbird.chat.subscribeEvents",
        ),
        (
            CanonicalOperation::UploadBlob,
            "blue.catbird.chat.uploadBlob",
        ),
    ];

    for (operation, nsid) in expected {
        assert_eq!(canonical_route(operation).nsid, nsid);
    }
    assert_eq!(CanonicalOperation::ALL.len(), expected.len());
}

#[test]
fn legacy_nsid_is_not_accepted_as_a_canonical_route() {
    assert!(route_for_nsid("blue.catbird.mlsChat.getMessages").is_none());
    assert!(route_for_nsid("blue.catbird.mlsChat.sendMessage").is_none());
    assert_eq!(
        route_for_nsid("blue.catbird.chat.getEntries").map(|route| route.path),
        Some("/xrpc/blue.catbird.chat.getEntries")
    );
}

#[test]
fn clean_read_requests_use_generated_names_and_transport_auth() {
    let request = get_conversations(&auth(), 25, Some("a cursor")).expect("query request");
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/xrpc/blue.catbird.chat.getConversations?limit=25&pageCursor=a%20cursor"
    );
    assert_eq!(request.authorization, "Bearer gateway-token");
    assert_eq!(request.dpop, "signed-dpop-proof");
    assert!(request.body.is_none());

    let request = get_entries(&auth(), "conversation/1", 4, 100).expect("entries request");
    assert_eq!(
        request.path,
        "/xrpc/blue.catbird.chat.getEntries?afterSeq=4&conversationId=conversation%2F1&limit=100"
    );
}

#[test]
fn parameterless_get_blob_usage_has_no_trailing_query_delimiter() {
    let request = CleanChatRequest::GetBlobUsage(
        crate::atproto::blue_catbird::chat::get_blob_usage::GetBlobUsage,
    );
    let auth = CleanChatAuthContext::new(
        auth().authorization,
        auth().dpop_proof,
        auth().dpop_jkt,
        auth().device_id,
    );
    let prepared = request.prepare(&auth).expect("getBlobUsage prepares");
    assert_eq!(prepared.path, "/xrpc/blue.catbird.chat.getBlobUsage");
    assert!(prepared.body.is_none());

    #[cfg(not(target_arch = "wasm32"))]
    {
        let ffi_auth = super::canonical_transport::CleanChatAuthContextFfi {
            authorization: auth.authorization,
            dpop_proof: auth.dpop_proof,
            dpop_jkt: auth.dpop_jkt,
            device_id: auth.device_id,
            auth_generation: None,
        };
        let prepared = super::canonical_transport::prepare_clean_chat_request(
            ffi_auth,
            super::canonical_transport::CleanChatOperationFfi::GetBlobUsage,
            b"null".to_vec(),
        )
        .expect("FFI getBlobUsage prepares");
        assert_eq!(prepared.path, "/xrpc/blue.catbird.chat.getBlobUsage");
    }
}

#[test]
fn get_blob_preserves_arbitrary_binary_response_bytes() {
    let body = [0_u8, 0xff, 0x80, b'\n', 0_u8];
    assert_eq!(
        super::canonical_transport::decode_clean_chat_blob_response(&body).unwrap(),
        body
    );
    assert!(matches!(
        CleanChatResponse::decode(CanonicalOperation::GetBlob, &body),
        Err(TransportError::UnsupportedOperation {
            operation: CanonicalOperation::GetBlob,
            ..
        })
    ));

    #[cfg(not(target_arch = "wasm32"))]
    assert_eq!(
        super::canonical_transport::decode_clean_chat_blob(body.to_vec()).unwrap(),
        body
    );
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
            "signature": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn rebind_binds_device_generation_and_new_jkt() {
    let auth = auth();
    let valid: serde_json::Value = serde_json::from_slice(&rebind_request_json(
        &auth.device_id,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        &auth.dpop_jkt,
        7,
    ))
    .unwrap();
    assert!(super::canonical_transport::validate_signed_request_context(
        &auth,
        Some(7),
        CanonicalOperation::RebindDeviceAuthentication,
        &valid,
    )
    .is_ok());

    let wrong_device: serde_json::Value = serde_json::from_slice(&rebind_request_json(
        "99999999-9999-4999-8999-999999999999",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        &auth.dpop_jkt,
        7,
    ))
    .unwrap();
    assert!(matches!(
        super::canonical_transport::validate_signed_request_context(
            &auth,
            Some(7),
            CanonicalOperation::RebindDeviceAuthentication,
            &wrong_device,
        ),
        Err(TransportError::DeviceBindingMismatch { .. })
    ));
    let wrong_generation: serde_json::Value = serde_json::from_slice(&rebind_request_json(
        &auth.device_id,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        &auth.dpop_jkt,
        8,
    ))
    .unwrap();
    assert!(matches!(
        super::canonical_transport::validate_signed_request_context(
            &auth,
            Some(7),
            CanonicalOperation::RebindDeviceAuthentication,
            &wrong_generation,
        ),
        Err(TransportError::AuthGenerationMismatch {
            expected: 7,
            actual: 8
        })
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn rebind_ffi_binds_device_generation_and_new_jkt() {
    let auth = auth();
    let context = super::canonical_transport::CleanChatAuthContextFfi {
        authorization: auth.authorization,
        dpop_proof: auth.dpop_proof,
        dpop_jkt: auth.dpop_jkt.clone(),
        device_id: auth.device_id.clone(),
        auth_generation: Some(7),
    };
    let prepared = super::canonical_transport::prepare_clean_chat_request(
        context.clone(),
        super::canonical_transport::CleanChatOperationFfi::RebindDeviceAuthentication,
        rebind_request_json(
            &auth.device_id,
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            &auth.dpop_jkt,
            7,
        ),
    )
    .expect("valid rebind prepares");
    assert_eq!(prepared.method, "POST");
    assert!(matches!(
        super::canonical_transport::prepare_clean_chat_request(
            context,
            super::canonical_transport::CleanChatOperationFfi::RebindDeviceAuthentication,
            rebind_request_json(
                &auth.device_id,
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                &auth.dpop_jkt,
                8,
            ),
        ),
        Err(super::canonical_transport::CleanChatTransportFfiError::InvalidRequest { message })
            if message.contains("authGeneration")
    ));
}

#[test]
fn media_specific_routes_have_typed_blockers() {
    let subscription = CleanChatRequest::SubscribeEvents(
        crate::atproto::blue_catbird::chat::subscribe_events::SubscribeEvents {
            cursor: "cursor".into(),
            ticket: "ticket".into(),
        },
    );
    assert!(matches!(
        subscription.prepare(&CleanChatAuthContext::new(
            auth().authorization,
            auth().dpop_proof,
            auth().dpop_jkt,
            auth().device_id,
        )),
        Err(TransportError::UnsupportedOperation {
            operation: CanonicalOperation::SubscribeEvents,
            ..
        })
    ));
    let upload = CleanChatRequest::UploadBlob(
        crate::atproto::blue_catbird::chat::upload_blob::UploadBlob {
            body: crate::atproto::jacquard_common::deps::bytes::Bytes::from_static(b"blob"),
        },
    );
    assert!(matches!(
        upload.prepare(&CleanChatAuthContext::new(
            auth().authorization,
            auth().dpop_proof,
            auth().dpop_jkt,
            auth().device_id,
        )),
        Err(TransportError::UnsupportedOperation {
            operation: CanonicalOperation::UploadBlob,
            ..
        })
    ));
}

#[test]
fn replenishment_serializes_generated_signed_envelope_and_binds_signature() {
    use base64::Engine as _;
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer;
    use serde_json::Value;

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("signer");
    let key_id = derive_key_id(signer.public());
    let input = ReplenishKeyPackagesInput {
        actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        actor_device_id: auth().device_id,
        auth_generation: 1,
        idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
        key_id,
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    let request = replenish_key_packages(&auth(), &signer, input).expect("signed request");

    let value: Value = serde_json::from_slice(request.body.as_ref().expect("body")).unwrap();
    assert_eq!(
        value["signedRequest"]["body"]["signatureDomain"],
        "CATBIRD-CHAT-DEVICE-REPLENISH\0"
    );
    assert_eq!(
        value["signedRequest"]["body"]["actorDeviceId"],
        auth().device_id
    );
    assert_eq!(
        value["signedRequest"]["body"]["dpopJkt"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        value["signedRequest"]["body"]["keyPackages"][0]["bytes"]["$bytes"],
        "a2V5LXBhY2thZ2U="
    );
    let signature = base64::engine::general_purpose::STANDARD
        .decode(
            value["signedRequest"]["signature"]["$bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let expected = canonical_replenishment_transcript(
        &ReplenishKeyPackagesInput {
            actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
            actor_device_id: auth().device_id,
            auth_generation: 1,
            idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
            key_id: derive_key_id(signer.public()),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
            key_packages: vec![key_package()],
            signed_at: "2026-08-16T12:00:00.000Z".into(),
        },
        signer.public(),
        &crate::atproto::blue_catbird::chat::CanonicalDatetime::from_str(
            "2026-08-16T12:00:00.000Z",
        )
        .unwrap(),
        &derive_key_id(signer.public()),
    )
    .unwrap();
    assert_eq!(signature, signer.sign(&expected).expect("sign transcript"));

    let mut changed = ReplenishKeyPackagesInput {
        actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        actor_device_id: auth().device_id,
        auth_generation: 2,
        idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
        key_id: derive_key_id(signer.public()),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    changed.key_packages[0].bytes =
        crate::atproto::jacquard_common::deps::bytes::Bytes::from_static(b"changed!");
    let changed_request = replenish_key_packages(&auth(), &signer, changed).unwrap();
    let changed_value: Value =
        serde_json::from_slice(changed_request.body.as_ref().unwrap()).unwrap();
    let changed_signature = base64::engine::general_purpose::STANDARD
        .decode(
            changed_value["signedRequest"]["signature"]["$bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_ne!(signature, changed_signature);
}

#[test]
fn replenishment_rejects_wrong_device_legacy_shape_and_missing_auth() {
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let input = || ReplenishKeyPackagesInput {
        actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        actor_device_id: "99999999-9999-4999-8999-999999999999".into(),
        auth_generation: 1,
        idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
        key_id: "device-key-id".into(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    assert!(matches!(
        replenish_key_packages(&auth(), &signer, input()),
        Err(TransportError::DeviceBindingMismatch { .. })
    ));

    let mut bad_auth = auth();
    bad_auth.dpop_jkt = format!("B{}", &auth().dpop_jkt[1..]);
    let mut good_input = input();
    good_input.actor_device_id = bad_auth.device_id.clone();
    assert_eq!(
        replenish_key_packages(&bad_auth, &signer, good_input),
        Err(TransportError::DpopBindingMismatch)
    );

    let mut missing = auth();
    missing.dpop_proof.clear();
    assert_eq!(
        get_entries(&missing, "conversation", 0, 10),
        Err(TransportError::MissingAuthentication)
    );
}

#[test]
fn replenishment_rejects_key_id_not_derived_from_signing_key() {
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let result = replenish_key_packages(
        &auth(),
        &signer,
        ReplenishKeyPackagesInput {
            actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
            actor_device_id: auth().device_id,
            auth_generation: 1,
            idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
            key_id: "wrong-key-id".into(),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
            key_packages: vec![key_package()],
            signed_at: "2026-08-16T12:00:00.000Z".into(),
        },
    );
    assert!(
        matches!(result, Err(TransportError::Serialization(message)) if message.contains("keyId"))
    );
}

#[test]
fn canonical_transport_rejects_noncanonical_identifiers_and_bounds() {
    assert!(validate_uuid("11111111-1111-4111-8111-111111111111", "deviceId").is_ok());
    assert!(validate_uuid("11111111-1111-4111-8111-111111111111", "deviceId").is_ok());
    assert!(validate_uuid("11111111-1111-4111-8111-11111111111A", "deviceId").is_err());
    assert!(validate_uuid("11111111-1111-4111-c111-111111111111", "deviceId").is_err());
    assert!(validate_datetime("2026-08-16T12:00:00.000Z").is_ok());
    assert!(validate_datetime("2026-08-16t12:00:00.00Z").is_err());
    assert!(validate_jkt("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
    assert!(validate_jkt("not-a-jkt").is_err());
    assert!(validate_auth_generation(1).is_ok());
    assert!(validate_auth_generation(9_007_199_254_740_991).is_ok());
    assert!(validate_auth_generation(0).is_err());
    assert!(validate_auth_generation(9_007_199_254_740_992).is_err());
    assert!(validate_bare_did("did:plc:z72i7hdynmk67x4h5wqf3s6a").is_ok());
    assert!(validate_bare_did("did:plc:Z72i7hdynmk67x4h5wqf3s6a").is_err());
    assert!(validate_bare_did("did:web:localhost").is_err());
    assert!(validate_key_packages(&[key_package()]).is_ok());
    assert!(validate_key_packages(&[]).is_err());
}

#[test]
fn generated_wire_errors_keep_operation_and_retry_contract() {
    assert_eq!(
        map_wire_error(CanonicalOperation::GetEntries, "DeviceRevoked"),
        TransportError::Remote {
            operation: CanonicalOperation::GetEntries,
            code: "DeviceRevoked".into(),
            retryable: false,
        }
    );
    assert_eq!(
        map_wire_error(CanonicalOperation::GetConversations, "CursorExpired"),
        TransportError::Remote {
            operation: CanonicalOperation::GetConversations,
            code: "CursorExpired".into(),
            retryable: false,
        }
    );
    assert_eq!(
        map_wire_error(CanonicalOperation::ReplenishKeyPackages, "FutureCode"),
        TransportError::Remote {
            operation: CanonicalOperation::ReplenishKeyPackages,
            code: "FutureCode".into(),
            retryable: false,
        }
    );
    assert_eq!(
        map_wire_error(
            CanonicalOperation::EnrollDevice,
            "AuthenticationGenerationConflict"
        ),
        TransportError::Remote {
            operation: CanonicalOperation::EnrollDevice,
            code: "AuthenticationGenerationConflict".into(),
            retryable: false,
        }
    );
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
                "signaturePublicKey": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
                "signedAt": "2026-08-16T12:00:00.000Z"
            },
            "signature": {"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn enrollment_binds_device_and_jkt_without_ordinary_auth_generation() {
    let auth = auth();
    let body: serde_json::Value =
        serde_json::from_slice(&enrollment_request_json(&auth.device_id, &auth.dpop_jkt, 0))
            .unwrap();
    assert!(super::canonical_transport::validate_signed_request_context(
        &auth,
        None,
        CanonicalOperation::EnrollDevice,
        &body,
    )
    .is_ok());

    let wrong_device: serde_json::Value = serde_json::from_slice(&enrollment_request_json(
        "99999999-9999-4999-8999-999999999999",
        &auth.dpop_jkt,
        0,
    ))
    .unwrap();
    assert!(matches!(
        super::canonical_transport::validate_signed_request_context(
            &auth,
            None,
            CanonicalOperation::EnrollDevice,
            &wrong_device,
        ),
        Err(TransportError::DeviceBindingMismatch { .. })
    ));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn enrollment_ffi_binds_device_and_requires_zero_expected_generation() {
    use super::canonical_transport::{
        prepare_clean_chat_request, CleanChatAuthContextFfi, CleanChatOperationFfi,
        CleanChatTransportFfiError,
    };
    let auth = auth();
    let context = CleanChatAuthContextFfi {
        authorization: auth.authorization.clone(),
        dpop_proof: auth.dpop_proof.clone(),
        dpop_jkt: auth.dpop_jkt.clone(),
        device_id: auth.device_id.clone(),
        auth_generation: None,
    };
    assert!(prepare_clean_chat_request(
        context.clone(),
        CleanChatOperationFfi::EnrollDevice,
        enrollment_request_json(&auth.device_id, &auth.dpop_jkt, 0),
    )
    .is_ok());
    assert!(matches!(
        prepare_clean_chat_request(
            context.clone(),
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(&auth.device_id, &auth.dpop_jkt, 1),
        ),
        Err(CleanChatTransportFfiError::InvalidRequest { message })
            if message.contains("expectedAuthGeneration")
    ));
    assert!(matches!(
        prepare_clean_chat_request(
            context,
            CleanChatOperationFfi::EnrollDevice,
            enrollment_request_json(
                "99999999-9999-4999-8999-999999999999",
                &auth.dpop_jkt,
                0,
            ),
        ),
        Err(CleanChatTransportFfiError::InvalidRequest { message })
            if message.contains("device")
    ));
}

#[test]
fn public_clean_chat_request_surface_uses_generated_types_and_auth_context() {
    let auth = CleanChatAuthContext::new(
        "Bearer gateway-token".into(),
        "signed-dpop-proof".into(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        "11111111-1111-4111-8111-111111111111".into(),
    );
    let request = CleanChatRequest::GetConversations(
        crate::atproto::blue_catbird::chat::get_conversations::GetConversations {
            limit: 25,
            page_cursor: Some("opaque-cursor".into()),
        },
    );
    let prepared = request.prepare(&auth).expect("public request prepares");
    assert_eq!(prepared.operation, CanonicalOperation::GetConversations);
    assert_eq!(prepared.method, "GET");
    assert_eq!(
        prepared.path,
        "/xrpc/blue.catbird.chat.getConversations?limit=25&pageCursor=opaque-cursor"
    );
    assert_eq!(prepared.authorization, "Bearer gateway-token");
    assert_eq!(prepared.dpop, "signed-dpop-proof");
}

#[test]
fn public_replenishment_binds_generation_and_device_context() {
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("signer");
    let auth = CleanChatAuthContext::new(
        "Bearer gateway-token".into(),
        "signed-dpop-proof".into(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        "11111111-1111-4111-8111-111111111111".into(),
    )
    .with_auth_generation(1);
    let key_id = derive_key_id(signer.public());
    let input = || ReplenishKeyPackagesInput {
        actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        actor_device_id: auth.device_id.clone(),
        auth_generation: 1,
        idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
        key_id: key_id.clone(),
        dpop_jkt: auth.dpop_jkt.clone(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    let prepared = super::canonical_transport::prepare_replenishment(&auth, &signer, input())
        .expect("public replenishment prepares");
    assert_eq!(prepared.operation, CanonicalOperation::ReplenishKeyPackages);

    let mut mismatch = auth.clone();
    mismatch.auth_generation = Some(2);
    assert!(matches!(
        super::canonical_transport::prepare_replenishment(&mismatch, &signer, input()),
        Err(TransportError::AuthGenerationMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn public_clean_chat_response_and_error_decode_to_generated_route_types() {
    let response = serde_json::json!({
        "hasMore": false,
        "inventorySessionId": "session",
        "items": [],
        "snapshotEventCursor": "cursor",
        "snapshotExpiresAt": "2026-08-16T12:00:00.000Z"
    });
    let decoded = CleanChatResponse::decode(
        CanonicalOperation::GetConversations,
        &serde_json::to_vec(&response).unwrap(),
    )
    .expect("generated response decodes");
    assert!(matches!(decoded, CleanChatResponse::GetConversations(_)));

    let error = CleanChatError::decode(
        CanonicalOperation::GetEntries,
        br#"{"error":"DeviceRevoked","message":"revoked"}"#,
    )
    .expect("generated error decodes");
    assert!(matches!(error, CleanChatError::GetEntries(_)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn uniffi_surface_parses_generated_json_before_preparing_wire_request() {
    let auth = super::canonical_transport::CleanChatAuthContextFfi {
        authorization: "Bearer gateway-token".into(),
        dpop_proof: "signed-dpop-proof".into(),
        dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        device_id: "11111111-1111-4111-8111-111111111111".into(),
        auth_generation: None,
    };
    let prepared = super::canonical_transport::prepare_clean_chat_request(
        auth,
        super::canonical_transport::CleanChatOperationFfi::GetConversations,
        br#"{"limit":25,"pageCursor":"opaque-cursor"}"#.to_vec(),
    )
    .expect("FFI request prepares");
    assert_eq!(prepared.method, "GET");
    assert_eq!(
        prepared.path,
        "/xrpc/blue.catbird.chat.getConversations?limit=25&pageCursor=opaque-cursor"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn signed_post_preparation_requires_exact_authenticated_generation() {
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("signer");
    let auth = CleanChatAuthContext::new(
        "Bearer gateway-token".into(),
        "signed-dpop-proof".into(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        "11111111-1111-4111-8111-111111111111".into(),
    )
    .with_auth_generation(1);
    let input = ReplenishKeyPackagesInput {
        actor_did: "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        actor_device_id: auth.device_id.clone(),
        auth_generation: 1,
        idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
        key_id: derive_key_id(signer.public()),
        dpop_jkt: auth.dpop_jkt.clone(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    let signed = super::canonical_transport::prepare_replenishment(&auth, &signer, input)
        .expect("signed generated request");
    let generated: crate::atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackages<
        String,
    > = serde_json::from_slice(signed.body.as_ref().expect("signed body"))
        .expect("generated request parses");
    let generated_json = serde_json::to_vec(&generated).expect("generated request JSON");
    let request = CleanChatRequest::ReplenishKeyPackages(generated);

    let missing_generation = CleanChatAuthContext {
        auth_generation: None,
        ..auth.clone()
    };
    assert!(matches!(
        request.prepare(&missing_generation),
        Err(TransportError::MissingAuthGeneration)
    ));

    let mismatched_generation = auth.clone().with_auth_generation(2);
    assert!(matches!(
        request.prepare(&mismatched_generation),
        Err(TransportError::AuthGenerationMismatch {
            expected: 2,
            actual: 1
        })
    ));

    let ffi_missing = super::canonical_transport::CleanChatAuthContextFfi {
        authorization: missing_generation.authorization,
        dpop_proof: missing_generation.dpop_proof,
        dpop_jkt: missing_generation.dpop_jkt,
        device_id: missing_generation.device_id,
        auth_generation: None,
    };
    assert!(matches!(
        super::canonical_transport::prepare_clean_chat_request(
            ffi_missing,
            super::canonical_transport::CleanChatOperationFfi::ReplenishKeyPackages,
            generated_json,
        ),
        Err(super::canonical_transport::CleanChatTransportFfiError::InvalidRequest { message })
            if message.contains("authGeneration")
    ));
}

#[cfg(not(target_arch = "wasm32"))]
mod signed_request_orchestrator_red_tests {
    use super::super::canonical_transport::{
        derive_key_id, prepare_signed_request_with_signer, CanonicalOperation,
        CleanChatSigningContext,
    };
    use super::auth;
    use openmls::prelude::SignatureScheme;
    use openmls_basic_credential::SignatureKeyPair;
    use serde_json::Value;

    const ACTOR_DID: &str = "did:plc:z72i7hdynmk67x4h5wqf3s6a";

    fn replenishment_wire(signer: &SignatureKeyPair) -> Value {
        let input = super::ReplenishKeyPackagesInput {
            actor_did: ACTOR_DID.into(),
            actor_device_id: auth().device_id,
            auth_generation: 1,
            idempotency_key: "22222222-2222-4222-8222-222222222222".into(),
            key_id: derive_key_id(signer.public()),
            dpop_jkt: auth().dpop_jkt,
            signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
            key_packages: vec![super::key_package()],
            signed_at: "2026-08-16T12:00:00.000Z".into(),
        };
        let prepared =
            super::super::canonical_transport::replenish_key_packages(&auth(), signer, input)
                .expect("existing generated replenishment fixture");
        let request: Value =
            serde_json::from_slice(prepared.body.as_deref().expect("generated body")).unwrap();
        request
    }

    fn replenishment_body(signer: &SignatureKeyPair) -> Value {
        replenishment_wire(signer)["signedRequest"]["body"].clone()
    }

    fn clean_auth(generation: Option<i64>) -> CleanChatSigningContext {
        CleanChatSigningContext {
            actor_did: ACTOR_DID.into(),
            dpop_jkt: auth().dpop_jkt,
            device_id: auth().device_id,
            auth_generation: generation,
        }
    }

    #[test]
    fn signed_orchestrator_signs_generated_body_from_configured_authority() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let body = replenishment_body(&signer);
        let prepared = prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        )
        .expect("supported mutation signs");

        assert_eq!(prepared.operation, CanonicalOperation::ReplenishKeyPackages);
        assert_eq!(prepared.method, "POST");
        assert_eq!(
            prepared.path,
            "/xrpc/blue.catbird.chat.replenishKeyPackages"
        );
        assert!(prepared.authorization.is_empty());
        assert!(prepared.dpop.is_empty());
        let wire: Value = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
        assert_eq!(wire["signedRequest"]["body"], body);
        assert_eq!(
            wire["signedRequest"]["signature"],
            replenishment_wire(&signer)["signedRequest"]["signature"]
        );
        assert_eq!(
            wire["signedRequest"]["signature"]["$bytes"]
                .as_str()
                .unwrap()
                .len(),
            88
        );
    }

    #[test]
    fn signed_orchestrator_is_deterministic_and_rejects_binding_tampering() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let body = replenishment_body(&signer);
        let body_json = serde_json::to_vec(&body).unwrap();
        let first = prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            body_json.clone(),
            &signer,
        )
        .unwrap();
        let reordered = serde_json::json!({
            "signedAt": body["signedAt"],
            "keyPackages": body["keyPackages"],
            "signatureDomain": body["signatureDomain"],
            "keyId": body["keyId"],
            "idempotencyKey": body["idempotencyKey"],
            "dpopJkt": body["dpopJkt"],
            "authGeneration": body["authGeneration"],
            "actorDid": body["actorDid"],
            "actorDeviceId": body["actorDeviceId"],
            "signaturePublicKey": body["signaturePublicKey"]
        });
        let second = prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&reordered).unwrap(),
            &signer,
        )
        .unwrap();
        assert_eq!(first.body, second.body);

        let mut tampered = body;
        tampered["authGeneration"] = Value::from(2);
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&tampered).unwrap(),
            &signer,
        )
        .is_err());
    }

    #[test]
    fn signed_orchestrator_rejects_missing_key_context_and_unsigned_operations() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let body = replenishment_body(&signer);
        let missing_generation = prepare_signed_request_with_signer(
            &clean_auth(None),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        );
        assert!(missing_generation.is_err());

        for operation in [
            CanonicalOperation::GetConversations,
            CanonicalOperation::GetSubscriptionTicket,
            CanonicalOperation::GetBlob,
            CanonicalOperation::UploadBlob,
            CanonicalOperation::SubscribeEvents,
        ] {
            assert!(
                prepare_signed_request_with_signer(
                    &clean_auth(Some(1)),
                    operation,
                    serde_json::to_vec(&body).unwrap(),
                    &signer,
                )
                .is_err(),
                "{operation:?} must not enter signed orchestrator"
            );
        }
    }

    #[test]
    fn signed_orchestrator_rejects_domain_actor_device_generation_and_key_id_mismatches() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let body = replenishment_body(&signer);

        let mut wrong_domain = body.clone();
        wrong_domain["signatureDomain"] = Value::from("CATBIRD-CHAT-MESSAGE\u{0000}");
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_domain).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_actor = body.clone();
        wrong_actor["actorDid"] = Value::from("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_actor).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_device = body.clone();
        wrong_device["actorDeviceId"] = Value::from("99999999-9999-4999-8999-999999999999");
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_device).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_generation = body.clone();
        wrong_generation["authGeneration"] = Value::from(2);
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_generation).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_jkt = body.clone();
        wrong_jkt["dpopJkt"] = Value::from("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_jkt).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_key_id = body.clone();
        wrong_key_id["keyId"] = Value::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_key_id).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_public_key = body.clone();
        wrong_public_key["signaturePublicKey"] =
            serde_json::json!({"$bytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&wrong_public_key).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_actor_binding = clean_auth(Some(1));
        wrong_actor_binding.actor_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(prepare_signed_request_with_signer(
            &wrong_actor_binding,
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_device_binding = clean_auth(Some(1));
        wrong_device_binding.device_id = "99999999-9999-4999-8999-999999999999".into();
        assert!(prepare_signed_request_with_signer(
            &wrong_device_binding,
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        )
        .is_err());

        let mut wrong_jkt_binding = clean_auth(Some(1));
        wrong_jkt_binding.dpop_jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into();
        assert!(prepare_signed_request_with_signer(
            &wrong_jkt_binding,
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        )
        .is_err());

        let wrong_generation_binding = clean_auth(Some(2));
        assert!(prepare_signed_request_with_signer(
            &wrong_generation_binding,
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body).unwrap(),
            &signer,
        )
        .is_err());

        let mut body_signature = body.clone();
        body_signature["signature"] = serde_json::json!({"$bytes": "AAAA"});
        assert!(prepare_signed_request_with_signer(
            &clean_auth(Some(1)),
            CanonicalOperation::ReplenishKeyPackages,
            serde_json::to_vec(&body_signature).unwrap(),
            &signer,
        )
        .is_err());
    }
}
