//! Device authority of a sequenced account deletion.
//!
//! An `accountDeletedEntry` is the sequencer's attestation that `deletedDid` deleted its account
//! data. The sequencer signature proves only that the sequencer recorded it. The entry takes
//! effect on this device only when it also carries `actorWrite`: the deleting device's own signed
//! `deleteAccountData` request, verified under a device key of `deletedDid`. Its `signedAt`, the
//! device-signed deletion instant, bounds which messages the deletion removes.
//!
//! Key ladder for `actorWrite.writeBody.actorDeviceId`, in order:
//! 1. that device's current MLS leaf in this conversation;
//! 2. that device's leaf in any other conversation this device holds;
//! 3. `keyProof`: a repository proof of `blue.catbird.chat.device/{actorDeviceId}` verified under
//!    the `#atproto` key of `deletedDid`'s DID document, which outlives the deleted repository.
//!
//! An entry that does not verify is never applied and never hidden: it is kept as evidence and
//! the conversation shows it as an unverified deletion.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Signature domain of `labyrinthWriteBody` (same bytes as the delivery service verifies).
pub const WRITE_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-WRITE\0";

/// `labyrinthWriteBody`, field for field, as the delivery service parses it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteBody {
    operation_id: String,
    actor_device_id: String,
    endpoint_nsid: String,
    #[allow(dead_code)]
    payload_sha256: String,
    signed_at: String,
}

/// The endpoint a deletion's `actorWrite` must be signed for.
pub const DELETE_ACCOUNT_DATA_NSID: &str = "blue.catbird.labyrinth.deleteAccountData";
/// The collection whose record `keyProof` proves.
pub const DEVICE_RECORD_COLLECTION: &str = "blue.catbird.chat.device";
/// Clock tolerance between the device-signed instant and the sequencer's instant, and the margin
/// a purge keeps after the device-signed instant.
pub const DELETION_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
/// Largest accepted `actorWrite.writeBody`.
pub const MAX_WRITE_BODY_BYTES: usize = 1024;
/// Largest accepted `actorWrite.payloadBytes` (the exact HTTP body).
pub const MAX_DELETE_PAYLOAD_BYTES: usize = 1024;
/// Largest accepted `keyProof`.
pub const MAX_KEY_PROOF_BYTES: usize = 16 * 1024;

/// A parsed, not yet verified `actorWrite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionActorWrite {
    pub operation_id: String,
    pub actor_device_id: String,
    pub signed_at_ms: i64,
    pub write_body: Vec<u8>,
    pub payload_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

/// Why a sequenced deletion is shown as unverified instead of applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnverifiedDeletionReason {
    /// No `actorWrite`: only the sequencer attests the deletion.
    NoActorWrite,
    /// Historical `actorWrite` omitted the HTTP body preimage of `payloadSha256`.
    NoPayloadBytes,
    /// `actorWrite` is malformed or not a `deleteAccountData` request.
    MalformedActorWrite,
    /// The device-signed instant is later than the sequencer's instant allows.
    SignedAfterSequenced,
    /// No key of the signing device was available: no local leaf and no usable `keyProof`.
    DeviceKeyUnavailable,
    /// A key of the signing device was found and the signature does not verify under it.
    BadSignature,
    /// A verified device revocation predates the device-signed deletion instant.
    DeviceRevokedAtSignedAt,
    /// The same signed request was already applied at another seq of this conversation.
    Replayed,
    /// The sequencer signature does not verify for this conversation.
    SequencerUnverified,
    /// The sequencer signed this deletion for another conversation than the one serving it.
    OtherConversation,
}

impl UnverifiedDeletionReason {
    /// Whether a later pass may still verify the entry (a key may become available).
    pub fn retryable(self) -> bool {
        matches!(self, Self::DeviceKeyUnavailable)
    }
}

fn json_bytes(value: &Value) -> Option<Vec<u8>> {
    let encoded = value
        .get("$bytes")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())?;
    STANDARD.decode(encoded).ok().or_else(|| {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(encoded)
            .ok()
    })
}

/// The deletion instant the sequencer signed (`receivedAt`), in milliseconds.
pub fn sequenced_at_ms(entry: &Value) -> Option<i64> {
    parse_instant_ms(entry["receivedAt"].as_str()?)
}

fn parse_instant_ms(text: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|instant| instant.timestamp_millis())
}

/// Parse `actorWrite`: the exact `labyrinthWriteBody` bytes of a `deleteAccountData` request
/// and a 64-byte signature.
pub fn parse_actor_write(entry: &Value) -> Result<DeletionActorWrite, UnverifiedDeletionReason> {
    let actor_write = entry
        .get("actorWrite")
        .filter(|value| !value.is_null())
        .ok_or(UnverifiedDeletionReason::NoActorWrite)?;
    let malformed = UnverifiedDeletionReason::MalformedActorWrite;
    let write_body = json_bytes(&actor_write["writeBody"]).ok_or(malformed)?;
    let payload_bytes = json_bytes(
        actor_write
            .get("payloadBytes")
            .filter(|value| !value.is_null())
            .ok_or(UnverifiedDeletionReason::NoPayloadBytes)?,
    )
    .ok_or(malformed)?;
    let signature: [u8; 64] = json_bytes(&actor_write["signature"])
        .ok_or(malformed)?
        .try_into()
        .map_err(|_| malformed)?;
    if write_body.is_empty() || write_body.len() > MAX_WRITE_BODY_BYTES {
        return Err(malformed);
    }
    if !(2..=MAX_DELETE_PAYLOAD_BYTES).contains(&payload_bytes.len()) {
        return Err(malformed);
    }
    let body: WriteBody = serde_json::from_slice(&write_body).map_err(|_| malformed)?;
    let operation_ok = body.operation_id.len() == 32
        && body
            .operation_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if body.endpoint_nsid != DELETE_ACCOUNT_DATA_NSID
        || !operation_ok
        || body.actor_device_id.is_empty()
        || body.actor_device_id.len() > 128
        || body.payload_sha256.len() != 64
        || !body
            .payload_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed);
    }
    let signed_at_ms = parse_instant_ms(&body.signed_at).ok_or(malformed)?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|_| malformed)?;
    if !payload.as_object().is_some_and(|object| object.is_empty())
        || hex::encode(Sha256::digest(&payload_bytes)) != body.payload_sha256
    {
        return Err(malformed);
    }
    Ok(DeletionActorWrite {
        operation_id: body.operation_id,
        actor_device_id: body.actor_device_id,
        signed_at_ms,
        write_body,
        payload_bytes,
        signature,
    })
}

/// The device-signed instant may not be later than the sequenced instant, beyond clock skew.
/// Any delay in the other direction is accepted: relayed copies arrive late.
pub fn signed_before_sequenced(write: &DeletionActorWrite, sequenced_at_ms: i64) -> bool {
    write.signed_at_ms <= sequenced_at_ms.saturating_add(DELETION_CLOCK_SKEW_MS)
}

/// Strict Ed25519 verification of `actorWrite` under one device key.
pub fn actor_write_signature_valid(write: &DeletionActorWrite, device_key: &[u8]) -> bool {
    let Ok(key_bytes) = <[u8; 32]>::try_from(device_key) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&write.signature);
    key.verify_strict(&[WRITE_DOMAIN, &write.write_body].concat(), &signature)
        .is_ok()
}

/// Latest message time a verified deletion removes: the device-signed instant plus skew.
pub fn purge_bound_ms(write: &DeletionActorWrite) -> i64 {
    write.signed_at_ms.saturating_add(DELETION_CLOCK_SKEW_MS)
}

/// The `keyProof` bytes of an entry, when present and within bounds.
pub fn key_proof_bytes(entry: &Value) -> Option<Vec<u8>> {
    json_bytes(entry.get("keyProof").filter(|value| !value.is_null())?)
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_KEY_PROOF_BYTES)
}

/// The Ed25519 MLS signature key `keyProof` proves for `device_id` of `did`, verified under the
/// `#atproto` key of `did`'s DID document `did_document`.
#[cfg(feature = "labyrinth")]
pub fn device_key_from_key_proof(
    key_proof: &[u8],
    did: &str,
    device_id: &str,
    signed_at_ms: i64,
    did_document: &[u8],
) -> Option<Vec<u8>> {
    let atproto_key = atproto_spaces::did_resolver::DidDocument::parse_json(did, did_document)
        .ok()?
        .atproto_key?;
    let (_, record) = crate::labyrinth::repo_proof::verify_car_record_proof(
        key_proof,
        did,
        DEVICE_RECORD_COLLECTION,
        device_id,
        &atproto_key,
    )
    .ok()??;
    let record: ipld_core::ipld::Ipld = serde_ipld_dagcbor::from_slice(&record).ok()?;
    let ipld_core::ipld::Ipld::Map(fields) = record else {
        return None;
    };
    if !matches!(fields.get("$type"), Some(ipld_core::ipld::Ipld::String(kind)) if kind == DEVICE_RECORD_COLLECTION)
        || !matches!(fields.get("deviceId"), Some(ipld_core::ipld::Ipld::String(id)) if id == device_id)
    {
        return None;
    }
    let enrolled_at_ms = match fields.get("createdAt") {
        Some(ipld_core::ipld::Ipld::String(at)) => parse_instant_ms(at)?,
        _ => return None,
    };
    if enrolled_at_ms > signed_at_ms {
        return None;
    }
    let algorithm_ok = matches!(
        fields.get("algorithm"),
        Some(ipld_core::ipld::Ipld::String(alg)) if alg.eq_ignore_ascii_case("ed25519")
    );
    match fields.get("mlsSignaturePublicKey") {
        Some(ipld_core::ipld::Ipld::Bytes(key)) if algorithm_ok && key.len() == 32 => {
            Some(key.clone())
        }
        _ => None,
    }
}

/// Without repository proofs no `keyProof` verifies.
#[cfg(not(feature = "labyrinth"))]
pub fn device_key_from_key_proof(
    _key_proof: &[u8],
    _did: &str,
    _device_id: &str,
    _signed_at_ms: i64,
    _did_document: &[u8],
) -> Option<Vec<u8>> {
    None
}

/// Stored form of a deletion this device applied (`native.account_deleted:{cid}:{did}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedAccountDeletion {
    pub seq: i64,
    pub signed_at_ms: i64,
    pub operation_id: String,
}

impl AppliedAccountDeletion {
    /// Latest message time this deletion removes.
    pub fn purge_bound_ms(&self) -> i64 {
        self.signed_at_ms.saturating_add(DELETION_CLOCK_SKEW_MS)
    }

    /// Read a stored marker. A marker written before deletions carried a device-signed instant
    /// holds only the seq: it hides by seq alone, as it always did.
    pub fn decode(raw: &[u8]) -> Option<StoredAccountDeletion> {
        let text = std::str::from_utf8(raw).ok()?.trim();
        if let Ok(seq) = text.parse::<i64>() {
            return Some(StoredAccountDeletion::SeqOnly(seq));
        }
        serde_json::from_str::<Self>(text)
            .ok()
            .map(StoredAccountDeletion::Signed)
    }
}

/// A stored deletion marker, either form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredAccountDeletion {
    SeqOnly(i64),
    Signed(AppliedAccountDeletion),
}

impl StoredAccountDeletion {
    pub fn seq(&self) -> i64 {
        match self {
            Self::SeqOnly(seq) => *seq,
            Self::Signed(applied) => applied.seq,
        }
    }

    /// Whether a message of the deleted account sequenced at `seq` and issued at `issued_at_ms`
    /// (when known) is covered.
    pub fn covers(&self, seq: i64, issued_at_ms: Option<i64>) -> bool {
        match self {
            Self::SeqOnly(deleted_seq) => seq < *deleted_seq,
            Self::Signed(applied) => {
                seq < applied.seq
                    && issued_at_ms.is_none_or(|issued| issued <= applied.purge_bound_ms())
            }
        }
    }
}

/// Evidence of a sequenced deletion this device did not apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnverifiedAccountDeletion {
    pub conversation_id: String,
    pub deleted_did: String,
    pub seq: i64,
    pub entry_id: String,
    pub reason: UnverifiedDeletionReason,
    pub operation_id: Option<String>,
    pub actor_device_id: Option<String>,
    /// The entry exactly as the sequencer returned it.
    pub entry: Value,
    pub recorded_at_ms: i64,
}

/// `labyrinth_state` key of [`UnverifiedAccountDeletion`] evidence.
pub fn unverified_deletion_key(cid: &str, deleted_did: &str, seq: i64) -> String {
    format!("native.account_deletion_unverified:{cid}:{deleted_did}:{seq:020}")
}

/// Prefix of every [`unverified_deletion_key`] of `cid`.
pub fn unverified_deletion_prefix(cid: &str) -> String {
    format!("native.account_deletion_unverified:{cid}:")
}

/// `labyrinth_state` key binding one signed deletion request to the seq of `cid` that applied
/// it. The same request is sequenced once in every conversation of the account.
pub fn deletion_operation_key(cid: &str, deleted_did: &str, operation_id: &str) -> String {
    format!("native.account_deletion_op:{cid}:{deleted_did}:{operation_id}")
}

/// Cached positive evidence from a repository-proven, device-signed revocation record. Never
/// infer the absence of revocation from a missing key: the repository may already be gone.
pub fn verified_device_revocation_key(did: &str, device_id: &str) -> String {
    format!("native.verified_device_revocation_at:{did}:{device_id}")
}

pub fn revoked_at_signed_instant(revoked_at_ms: Option<i64>, signed_at_ms: i64) -> bool {
    revoked_at_ms.is_some_and(|at| signed_at_ms >= at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    fn signed(nsid: &str, signed_at: &str) -> (ed25519_dalek::SigningKey, Value) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let body = serde_json::to_vec(&json!({
            "operationId": "0123456789abcdef0123456789abcdef",
            "actorDeviceId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "endpointNsid": nsid,
            "payloadSha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "signedAt": signed_at,
        }))
        .unwrap();
        let signature = key.sign(&[WRITE_DOMAIN, &body].concat());
        let entry = json!({
            "receivedAt": "2026-11-16T12:00:00.000Z",
            "actorWrite": {
                "writeBody": { "$bytes": STANDARD.encode(&body) },
                "payloadBytes": { "$bytes": STANDARD.encode(b"{}") },
                "signature": { "$bytes": STANDARD.encode(signature.to_bytes()) },
            },
        });
        (key, entry)
    }

    #[cfg(feature = "labyrinth")]
    #[test]
    fn the_write_domain_is_the_delivery_service_domain() {
        assert_eq!(WRITE_DOMAIN, crate::labyrinth::write_auth::WRITE_DOMAIN);
    }

    #[test]
    fn a_device_signed_deletion_parses_and_verifies_only_under_its_key() {
        let (key, entry) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T11:59:00.000Z");
        let write = parse_actor_write(&entry).unwrap();
        assert_eq!(
            write.signed_at_ms,
            sequenced_at_ms(&entry).unwrap() - 60_000
        );
        assert!(actor_write_signature_valid(
            &write,
            key.verifying_key().as_bytes()
        ));
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        assert!(!actor_write_signature_valid(
            &write,
            other.verifying_key().as_bytes()
        ));
        assert!(signed_before_sequenced(
            &write,
            sequenced_at_ms(&entry).unwrap()
        ));
        assert_eq!(
            purge_bound_ms(&write),
            write.signed_at_ms + DELETION_CLOCK_SKEW_MS
        );
    }

    #[test]
    fn deletions_without_a_device_signature_for_this_endpoint_do_not_parse() {
        assert_eq!(
            parse_actor_write(&json!({})),
            Err(UnverifiedDeletionReason::NoActorWrite)
        );
        let (_, entry) = signed(
            "blue.catbird.labyrinth.putArchive",
            "2026-11-16T11:59:00.000Z",
        );
        assert_eq!(
            parse_actor_write(&entry),
            Err(UnverifiedDeletionReason::MalformedActorWrite)
        );
        let (_, mut missing_payload) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T11:59:00.000Z");
        missing_payload["actorWrite"]
            .as_object_mut()
            .unwrap()
            .remove("payloadBytes");
        assert_eq!(
            parse_actor_write(&missing_payload),
            Err(UnverifiedDeletionReason::NoPayloadBytes)
        );
        let (_, mut wrong_payload) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T11:59:00.000Z");
        wrong_payload["actorWrite"]["payloadBytes"] = json!({ "$bytes": STANDARD.encode(b"{ }") });
        assert_eq!(
            parse_actor_write(&wrong_payload),
            Err(UnverifiedDeletionReason::MalformedActorWrite)
        );
        let (_, mut entry) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T11:59:00.000Z");
        entry["actorWrite"]["signature"] = json!({ "$bytes": STANDARD.encode([0u8; 63]) });
        assert_eq!(
            parse_actor_write(&entry),
            Err(UnverifiedDeletionReason::MalformedActorWrite)
        );
    }

    #[test]
    fn signed_noncanonical_empty_json_body_verifies_by_its_original_bytes() {
        let (key, mut entry) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T11:59:00.000Z");
        let payload = b"{ \n }";
        let mut body: Value =
            serde_json::from_slice(&json_bytes(&entry["actorWrite"]["writeBody"]).unwrap())
                .unwrap();
        body["payloadSha256"] = Value::String(hex::encode(Sha256::digest(payload)));
        let write_body = serde_json::to_vec(&body).unwrap();
        let signature = key.sign(&[WRITE_DOMAIN, &write_body].concat());
        entry["actorWrite"]["writeBody"] = json!({ "$bytes": STANDARD.encode(&write_body) });
        entry["actorWrite"]["payloadBytes"] = json!({ "$bytes": STANDARD.encode(payload) });
        entry["actorWrite"]["signature"] =
            json!({ "$bytes": STANDARD.encode(signature.to_bytes()) });
        let parsed = parse_actor_write(&entry).unwrap();
        assert_eq!(parsed.payload_bytes, payload);
        assert!(actor_write_signature_valid(
            &parsed,
            key.verifying_key().as_bytes()
        ));

        let nonempty_payload = b"{\"unexpected\":1}";
        body["payloadSha256"] = Value::String(hex::encode(Sha256::digest(nonempty_payload)));
        let nonempty_write_body = serde_json::to_vec(&body).unwrap();
        let signature = key.sign(&[WRITE_DOMAIN, &nonempty_write_body].concat());
        entry["actorWrite"]["writeBody"] =
            json!({ "$bytes": STANDARD.encode(&nonempty_write_body) });
        entry["actorWrite"]["payloadBytes"] =
            json!({ "$bytes": STANDARD.encode(nonempty_payload) });
        entry["actorWrite"]["signature"] =
            json!({ "$bytes": STANDARD.encode(signature.to_bytes()) });
        assert_eq!(
            parse_actor_write(&entry),
            Err(UnverifiedDeletionReason::MalformedActorWrite)
        );
    }

    #[test]
    fn a_deletion_signed_after_it_was_sequenced_is_refused() {
        let (_, entry) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T12:06:00.000Z");
        let write = parse_actor_write(&entry).unwrap();
        assert!(!signed_before_sequenced(
            &write,
            sequenced_at_ms(&entry).unwrap()
        ));
        let (_, entry) = signed(DELETE_ACCOUNT_DATA_NSID, "2026-11-16T12:04:00.000Z");
        let write = parse_actor_write(&entry).unwrap();
        assert!(signed_before_sequenced(
            &write,
            sequenced_at_ms(&entry).unwrap()
        ));
    }

    #[test]
    fn stored_markers_of_both_forms_bound_what_they_hide() {
        let legacy = AppliedAccountDeletion::decode(b"40").unwrap();
        assert!(legacy.covers(39, Some(i64::MAX)));
        assert!(!legacy.covers(40, None));
        let signed = AppliedAccountDeletion::decode(
            br#"{"seq":40,"signedAtMs":1000000,"operationId":"0123456789abcdef0123456789abcdef"}"#,
        )
        .unwrap();
        assert!(signed.covers(39, Some(1_000_000 + DELETION_CLOCK_SKEW_MS)));
        assert!(!signed.covers(39, Some(1_000_001 + DELETION_CLOCK_SKEW_MS)));
        assert!(signed.covers(39, None));
        assert!(!signed.covers(41, Some(0)));
    }
}
