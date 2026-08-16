use super::canonical_transport::{
    canonical_replenishment_transcript, canonical_route, derive_key_id, get_conversations,
    get_entries, map_wire_error, replenish_key_packages, route_for_nsid, CanonicalOperation,
    ReplenishKeyPackagesInput, TransportAuth, TransportError,
};
use std::str::FromStr;

fn auth() -> TransportAuth {
    TransportAuth {
        authorization: "Bearer gateway-token".into(),
        dpop_proof: "signed-dpop-proof".into(),
        dpop_jkt: "device-jkt".into(),
        device_id: "11111111-1111-4111-8111-111111111111".into(),
    }
}

fn key_package() -> crate::atproto::blue_catbird::chat::KeyPackageArtifact<String> {
    use crate::atproto::jacquard_common::deps::bytes::Bytes;
    crate::atproto::blue_catbird::chat::KeyPackageArtifact {
        bytes: Bytes::from_static(b"key-package"),
        content_type: "application/octet-stream".into(),
        framing: "mls-key-package".into(),
        key_package_ref: Bytes::from_static(b"ref"),
        sha256: Bytes::from_static(b"sha256"),
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
            CanonicalOperation::GetConversations,
            "blue.catbird.chat.getConversations",
        ),
        (
            CanonicalOperation::CreateConversation,
            "blue.catbird.chat.createConversation",
        ),
        (
            CanonicalOperation::SendMessage,
            "blue.catbird.chat.sendMessage",
        ),
        (
            CanonicalOperation::GetEntries,
            "blue.catbird.chat.getEntries",
        ),
        (
            CanonicalOperation::ReplenishKeyPackages,
            "blue.catbird.chat.replenishKeyPackages",
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
            CanonicalOperation::SubmitTransition,
            "blue.catbird.chat.submitTransition",
        ),
    ];

    for (operation, nsid) in expected {
        assert_eq!(canonical_route(operation).nsid, nsid);
    }
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
        dpop_jkt: "device-jkt".into(),
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
    assert_eq!(value["signedRequest"]["body"]["dpopJkt"], "device-jkt");
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
            dpop_jkt: "device-jkt".into(),
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
        dpop_jkt: "device-jkt".into(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    changed.key_packages[0].bytes =
        crate::atproto::jacquard_common::deps::bytes::Bytes::from_static(b"changed");
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
        dpop_jkt: "device-jkt".into(),
        signature_domain: "CATBIRD-CHAT-DEVICE-REPLENISH\0".into(),
        key_packages: vec![key_package()],
        signed_at: "2026-08-16T12:00:00.000Z".into(),
    };
    assert!(matches!(
        replenish_key_packages(&auth(), &signer, input()),
        Err(TransportError::DeviceBindingMismatch { .. })
    ));

    let mut bad_auth = auth();
    bad_auth.dpop_jkt = "different-jkt".into();
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
            dpop_jkt: "device-jkt".into(),
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
            retryable: true,
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
}
