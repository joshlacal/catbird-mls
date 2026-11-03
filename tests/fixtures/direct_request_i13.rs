use base64::{engine::general_purpose::STANDARD, Engine as _};
use labyrinth_protocol::receipt::{
    expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};

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

pub fn receipt(key: &SigningKey, publication: &Value, seq: u64, authority_did: &str) -> Value {
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
    let signed = sign_sequencer_receipt(
        key,
        &expected_receipt_key_id(&payload.sequencer_did),
        &payload,
    )
    .unwrap();
    json!({
        "sequencerDid":payload.sequencer_did,"conversationId":payload.conversation_id,
        "generation":publication["next"]["generation"],"groupId":STANDARD.encode(&payload.group_id),
        "epoch":payload.epoch,"senderDid":publication["actorDid"],"senderDeviceId":publication["actorDeviceId"],
        "entryId":payload.entry_id,"archiveCommitment":STANDARD.encode(payload.archive_commitment),
        "seq":payload.seq,"issuedAtMs":payload.issued_at_ms,"kid":signed.key_id,
        "signature":STANDARD.encode(signed.signature),
    })
}
