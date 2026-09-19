//! Real encrypted native intent storage across a full context reopen. These
//! tests exercise the pre-reservation fence; they do not claim service replay.
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request::{
    direct_request_signing_bytes, DirectRequestKind,
};
use catbird_mls::orchestrator::{direct_requests::DirectRequestIntent, MlsCryptoContext};
use catbird_mls::{DirectRequestInput, KeychainAccess, MLSContext, MLSError};
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct TestKeychain(Arc<Mutex<HashMap<String, Vec<u8>>>>);
#[async_trait]
impl KeychainAccess for TestKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.0.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        self.0.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
}
fn intent() -> DirectRequestIntent {
    let vectors: Value = serde_json::from_str(include_str!(
        "../src/chat_v2/transcript/vectors/direct_request_vectors.json"
    ))
    .unwrap();
    let mut body = vectors["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == "Prepare")
        .unwrap()["body"]
        .clone();
    body["recipientDid"] = json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
    let key = ed25519_dalek::SigningKey::from_bytes(&[39; 32]);
    body["keyId"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(key.verifying_key().as_bytes())));
    let transcript = direct_request_signing_bytes(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let wrapper =
        json!({"body":body,"signature":STANDARD.encode(key.sign(&transcript).to_bytes())});
    DirectRequestIntent {
        input: DirectRequestInput {
            draft_id: "11111111-1111-4111-8111-111111111111".into(),
            recipient_did: body["recipientDid"].as_str().unwrap().into(),
            text: "Protected introduction".into(),
            invitation: None,
        },
        actor_did: body["actorDid"].as_str().unwrap().into(),
        actor_device_id: body["actorDeviceId"].as_str().unwrap().into(),
        actor_public_key: key.verifying_key().as_bytes().to_vec(),
        prepare_wrapper: serde_json::to_vec(&wrapper).unwrap(),
        trusted_authority_document: authority_document(),
        preparation_response: None,
        cancel_wrapper: None,
        publication_wrapper: None,
        terminal_response: None,
        publication_attempted: false,
        cancellation_requested: false,
        projection_completed: false,
        previous_attempts: Vec::new(),
    }
}
fn open(path: &std::path::Path, keychain: &TestKeychain) -> Arc<MLSContext> {
    MLSContext::new(
        path.to_string_lossy().into_owned(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        Box::new(keychain.clone()),
    )
    .unwrap()
}
#[test]
fn pre_reservation_intent_survives_reopen_with_exact_signed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("requests.db");
    let keychain = TestKeychain::default();
    let record = intent();
    let raw = record.encode().unwrap();
    let context = open(&path, &keychain);
    assert!(context
        .compare_exchange_direct_request_intent(&record.input.draft_id, None, &raw)
        .unwrap());
    drop(context);
    let context = open(&path, &keychain);
    let retained = context
        .read_direct_request_intent(&record.input.draft_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained, raw);
    let recovered =
        DirectRequestIntent::decode(&retained, &record.actor_did, &record.actor_device_id).unwrap();
    assert_eq!(recovered.prepare_wrapper, record.prepare_wrapper);
    assert_eq!(recovered.input.text, "Protected introduction");
    assert!(DirectRequestIntent::decode(
        &retained,
        "did:plc:wrongaccount",
        &record.actor_device_id
    )
    .is_err());
    assert!(DirectRequestIntent::decode(
        &retained,
        &record.actor_did,
        "22222222-2222-4222-8222-222222222222"
    )
    .is_err());
}
#[test]
fn duplicate_draft_cas_cannot_overwrite_an_unknown_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let context = open(
        &directory.path().join("requests.db"),
        &TestKeychain::default(),
    );
    let record = intent();
    let raw = record.encode().unwrap();
    assert!(context
        .compare_exchange_direct_request_intent(&record.input.draft_id, None, &raw)
        .unwrap());
    let mut edited = record.clone();
    edited.input.text = "Edited after lost prepare response".into();
    assert!(!record.matches_input(&edited.input));
    assert!(!context
        .compare_exchange_direct_request_intent(
            &record.input.draft_id,
            None,
            &edited.encode().unwrap()
        )
        .unwrap());
    assert_eq!(
        context
            .read_direct_request_intent(&record.input.draft_id)
            .unwrap()
            .unwrap(),
        raw
    );
}
#[test]
fn tampered_signed_attempt_and_forged_cancel_state_fail_local_validation() {
    let mut record = intent();
    record.prepare_wrapper[10] ^= 1;
    assert!(record.encode().is_err());
    let mut record = intent();
    record.cancellation_requested = true;
    assert!(record.encode().is_err());
}

fn authority_document() -> Vec<u8> {
    let signer = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let point = signer.verifying_key().to_encoded_point(true);
    let id = catbird_mls::chat_v2::transcript::direct_request::direct_request_receipt_key_id(
        point.as_bytes(),
    )
    .unwrap();
    let mut bytes = vec![0x80, 0x24];
    bytes.extend_from_slice(point.as_bytes());
    serde_json::to_vec(&json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{"id":id,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,bytes)}]})).unwrap()
}

#[test]
fn offline_intent_hydration_rejects_unverified_preparation_and_terminal() {
    let mut record = intent();
    record.preparation_response =
        Some(br#"{"receiptKeyId":"did:web:chat.catbird.blue#forged"}"#.to_vec());
    assert!(record.encode().is_err());
    let mut record = intent();
    record.terminal_response = Some(
        br#"{"body":{"keyId":"did:web:chat.catbird.blue#forged"},"signature":"AAAA"}"#.to_vec(),
    );
    assert!(record.encode().is_err());
}
