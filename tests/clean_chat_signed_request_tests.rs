mod e2e_harness;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::orchestrator::{
    CanonicalOperation, CleanChatSigningContext, CredentialStore, TransportError,
};
use e2e_harness::TestWorld;
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ACTOR_NAME: &str = "z72i7hdynmk67x4h5wqf3s6a";
const DEVICE_ID: &str = "11111111-1111-4111-8111-111111111111";
const DPOP_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn replenishment_body(signer: &SignatureKeyPair) -> Vec<u8> {
    let key_id = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()))
    };
    let body = json!({
        "actorDid": format!("did:plc:{ACTOR_NAME}"),
        "actorDeviceId": DEVICE_ID,
        "authGeneration": 1,
        "dpopJkt": DPOP_JKT,
        "idempotencyKey": "22222222-2222-4222-8222-222222222222",
        "keyId": key_id,
        "keyPackages": [{
            "bytes": {"$bytes": STANDARD.encode(b"key-package")},
            "contentType": "keyPackage",
            "framing": "mlsMessage",
            "keyPackageRef": {"$bytes": STANDARD.encode([1u8; 32])},
            "sha256": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
        }],
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\0",
        "signaturePublicKey": {"$bytes": STANDARD.encode(signer.public())},
        "signedAt": "2026-08-16T12:00:00.000Z"
    });
    serde_json::to_vec(&body).unwrap()
}

fn binding() -> CleanChatSigningContext {
    CleanChatSigningContext {
        actor_did: format!("did:plc:{ACTOR_NAME}"),
        device_id: DEVICE_ID.into(),
        dpop_jkt: DPOP_JKT.into(),
        auth_generation: Some(1),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_credential_store_signs_without_transport_headers() {
    let mut world = TestWorld::new();
    world.add_client(ACTOR_NAME).await;
    let client = world.client(ACTOR_NAME);
    client.orchestrator.initialize(&client.did).await.unwrap();

    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let serialized = serde_json::to_vec(&signer).unwrap();
    client
        .credentials
        .store_signing_key(&client.did, &serialized)
        .await
        .unwrap();

    let prepared = client
        .orchestrator
        .prepare_clean_chat_signed_request(
            binding(),
            CanonicalOperation::ReplenishKeyPackages,
            replenishment_body(&signer),
        )
        .await
        .expect("configured credential store signer");

    assert!(prepared.authorization.is_empty());
    assert!(prepared.dpop.is_empty());
    let wire: Value = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        wire["signedRequest"]["signature"]["$bytes"]
            .as_str()
            .unwrap()
            .len(),
        88
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_orchestrator_reports_missing_configured_key() {
    let mut world = TestWorld::new();
    world.add_client(ACTOR_NAME).await;
    let client = world.client(ACTOR_NAME);
    client.orchestrator.initialize(&client.did).await.unwrap();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();

    let result = client
        .orchestrator
        .prepare_clean_chat_signed_request(
            binding(),
            CanonicalOperation::ReplenishKeyPackages,
            replenishment_body(&signer),
        )
        .await;
    assert!(matches!(result, Err(TransportError::MissingSigningKey)));
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_orchestrator_rejects_invalid_configured_key_material() {
    let mut world = TestWorld::new();
    world.add_client(ACTOR_NAME).await;
    let client = world.client(ACTOR_NAME);
    client.orchestrator.initialize(&client.did).await.unwrap();
    client
        .credentials
        .store_signing_key(&client.did, b"not-a-signature-key")
        .await
        .unwrap();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();

    let result = client
        .orchestrator
        .prepare_clean_chat_signed_request(
            binding(),
            CanonicalOperation::ReplenishKeyPackages,
            replenishment_body(&signer),
        )
        .await;
    assert!(
        matches!(result, Err(TransportError::Credential(message)) if message.contains("Ed25519"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signed_orchestrator_rejects_binding_for_another_initialized_actor() {
    let mut world = TestWorld::new();
    world.add_client(ACTOR_NAME).await;
    let client = world.client(ACTOR_NAME);
    client.orchestrator.initialize(&client.did).await.unwrap();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let serialized = serde_json::to_vec(&signer).unwrap();
    client
        .credentials
        .store_signing_key(&client.did, &serialized)
        .await
        .unwrap();

    let mut wrong_binding = binding();
    wrong_binding.actor_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into();
    let result = client
        .orchestrator
        .prepare_clean_chat_signed_request(
            wrong_binding,
            CanonicalOperation::ReplenishKeyPackages,
            replenishment_body(&signer),
        )
        .await;
    assert!(
        matches!(result, Err(TransportError::Serialization(message)) if message.contains("actor DID"))
    );
}
