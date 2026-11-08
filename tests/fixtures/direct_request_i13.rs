use base64::{engine::general_purpose::STANDARD, Engine as _};
use labyrinth_protocol::receipt::{
    expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};

#[allow(dead_code)] // Integration-test crates share this fixture but not every helper.
pub const AUTHORITY_DID: &str = "did:web:chat.catbird.blue";

#[allow(dead_code)] // Integration-test crates share this fixture but not every helper.
pub fn fixture_authority_key() -> SigningKey {
    SigningKey::from_slice(&[41; 32]).unwrap()
}

pub fn authority_document(
    key: &SigningKey,
    request_receipt_method: &str,
    authority_did: &str,
) -> Vec<u8> {
    let mut multikey = vec![0x80, 0x24];
    multikey.extend(key.verifying_key().to_encoded_point(true).as_bytes());
    let encoded = multibase::encode(multibase::Base::Base58Btc, multikey);
    let i13_method = expected_receipt_key_id(authority_did);
    let methods = [request_receipt_method, i13_method.as_str()]
        .map(|id| json!({"id":id,"controller":authority_did,"type":"Multikey","publicKeyMultibase":encoded}));
    serde_json::to_vec(&json!({
        "id":authority_did,
        "verificationMethod":methods,
    }))
    .unwrap()
}

#[allow(dead_code)] // Integration-test crates share this fixture but not every helper.
pub fn control_receipt(
    key: &SigningKey,
    body: &Value,
    entry_id: &str,
    seq: u64,
    received_at: &str,
    request_digest: [u8; 32],
    authority_did: &str,
) -> Value {
    let coordinate = body.get("next").unwrap_or(&body["retired"]);
    control_receipt_at(
        key,
        body,
        coordinate,
        entry_id,
        seq,
        received_at,
        request_digest,
        authority_did,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn control_receipt_at(
    key: &SigningKey,
    body: &Value,
    coordinate: &Value,
    entry_id: &str,
    seq: u64,
    received_at: &str,
    request_digest: [u8; 32],
    authority_did: &str,
) -> Value {
    control_receipt_at_with_key_id(
        key,
        body,
        coordinate,
        entry_id,
        seq,
        received_at,
        request_digest,
        authority_did,
        &expected_receipt_key_id(authority_did),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn control_receipt_at_with_key_id(
    key: &SigningKey,
    body: &Value,
    coordinate: &Value,
    entry_id: &str,
    seq: u64,
    received_at: &str,
    request_digest: [u8; 32],
    authority_did: &str,
    key_id: &str,
) -> Value {
    let bytes = |value: &Value| {
        STANDARD
            .decode(value.as_str().or_else(|| value["$bytes"].as_str()).unwrap())
            .unwrap()
    };
    let payload = SequencerReceiptPayload {
        sequencer_did: authority_did.into(),
        conversation_id: coordinate["conversationId"].as_str().unwrap().into(),
        group_id: bytes(&coordinate["groupId"]),
        epoch: coordinate["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap()
        ),
        entry_id: entry_id.into(),
        archive_commitment: request_digest,
        seq,
        issued_at_ms: chrono::DateTime::parse_from_rfc3339(received_at)
            .unwrap()
            .timestamp_millis(),
    };
    let signed = sign_sequencer_receipt(key, key_id, &payload).unwrap();
    json!({
        "sequencerDid": payload.sequencer_did,
        "conversationId": payload.conversation_id,
        "generation": coordinate["generation"],
        "groupId": STANDARD.encode(&payload.group_id),
        "epoch": payload.epoch,
        "senderDid": body["actorDid"],
        "senderDeviceId": body["actorDeviceId"],
        "entryId": payload.entry_id,
        "archiveCommitment": STANDARD.encode(payload.archive_commitment),
        "seq": payload.seq,
        "issuedAtMs": payload.issued_at_ms,
        "kid": signed.key_id,
        "signature": STANDARD.encode(signed.signature),
    })
}

pub fn receipt(key: &SigningKey, publication: &Value, seq: u64, authority_did: &str) -> Value {
    receipt_with_key_id(
        key,
        &expected_receipt_key_id(authority_did),
        publication,
        seq,
        authority_did,
    )
}

/// [`receipt`] signed under an exact retained method, e.g. a rotated `#mls-receipt-2`.
pub fn receipt_with_key_id(
    key: &SigningKey,
    key_id: &str,
    publication: &Value,
    seq: u64,
    authority_did: &str,
) -> Value {
    let bytes = |value: &Value| {
        STANDARD
            .decode(value.as_str().or_else(|| value["$bytes"].as_str()).unwrap())
            .unwrap()
    };
    let payload = SequencerReceiptPayload {
        sequencer_did: authority_did.into(),
        conversation_id: publication["conversationId"].as_str().unwrap().into(),
        group_id: bytes(&publication["next"]["groupId"]),
        epoch: publication["next"]["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            publication["actorDid"].as_str().unwrap(),
            publication["actorDeviceId"].as_str().unwrap()
        ),
        entry_id: publication["firstMessageId"].as_str().unwrap().into(),
        archive_commitment: bytes(&publication["archiveCommitment"]).try_into().unwrap(),
        seq,
        issued_at_ms: chrono::DateTime::parse_from_rfc3339(
            publication["signedAt"].as_str().unwrap(),
        )
        .unwrap()
        .timestamp_millis(),
    };
    let signed = sign_sequencer_receipt(key, key_id, &payload).unwrap();
    json!({
        "sequencerDid":payload.sequencer_did,"conversationId":payload.conversation_id,
        "generation":publication["next"]["generation"],"groupId":STANDARD.encode(&payload.group_id),
        "epoch":payload.epoch,"senderDid":publication["actorDid"],"senderDeviceId":publication["actorDeviceId"],
        "entryId":payload.entry_id,"archiveCommitment":STANDARD.encode(payload.archive_commitment),
        "seq":payload.seq,"issuedAtMs":payload.issued_at_ms,"kid":signed.key_id,
        "signature":STANDARD.encode(signed.signature),
    })
}
