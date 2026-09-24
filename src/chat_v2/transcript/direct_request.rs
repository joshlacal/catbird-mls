//! Strict protocol-two direct-request transcripts. No legacy transcript changes.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MAX_PUBLISH_HTTP_BODY_BYTES: usize = 16_777_216;
pub const MAX_PREPARE_HTTP_RESPONSE_BYTES: usize = 8_388_608;
pub const MAX_BOOTSTRAP_ARTIFACT_BYTES: usize = 8_388_608;
pub const MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES: usize = 98_304;
pub const MAX_REQUEST_TEXT_UTF8_BYTES: usize = 16_384;
pub const MAX_PREPARED_DEVICE_LEAVES: usize = 40;
pub const REQUEST_PREPARATION_TTL_SECONDS: u64 = 300;
pub const MAX_LIVE_PREPARATIONS_PER_SENDER: usize = 2;
pub const MAX_LIVE_PREPARATIONS_PER_SENDER_DEVICE_PAIR: usize = 1;
pub const MAX_LIVE_PREPARATIONS_PER_RECIPIENT: usize = 4;
pub const MAX_PREPARATIONS_PER_SENDER_PER_HOUR: usize = 20;
pub const MAX_PENDING_ARTIFACT_BYTES_PER_ACCOUNT: u64 = 67_108_864;
pub const MAX_PENDING_ARTIFACT_BYTES_GLOBAL: u64 = 1_073_741_824;
pub const MAX_RETAINED_REQUEST_ARTIFACT_BYTES_GLOBAL: u64 = 8_589_934_592;
pub const REQUEST_KEY_POOL_TARGET: usize = 64;
pub const REQUEST_KEY_POOL_REPLENISH_BELOW: usize = 16;
pub const REQUEST_KEY_POOL_MAXIMUM: usize = 128;
pub const REQUEST_MIN_IMPORT_HORIZON_SECONDS: u64 = 604_800;
pub const REQUEST_IMPORT_CLOCK_MARGIN_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRequestTranscriptError(pub String);
impl std::fmt::Display for DirectRequestTranscriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DirectRequestTranscriptError {}
fn error(value: impl std::fmt::Display) -> DirectRequestTranscriptError {
    DirectRequestTranscriptError(value.to_string())
}
type Result<T> = std::result::Result<T, DirectRequestTranscriptError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRequestKind {
    Grant,
    Keys,
    Prepare,
    Publish,
    Cancel,
    Accept,
    Outcome,
    AcceptanceCommit,
}
impl DirectRequestKind {
    pub const ALL: &'static [Self] = &[
        Self::Grant,
        Self::Keys,
        Self::Prepare,
        Self::Publish,
        Self::Cancel,
        Self::Accept,
        Self::Outcome,
        Self::AcceptanceCommit,
    ];
    pub fn body_name(self) -> &'static str {
        match self {
            Self::Grant => "directRequestGrantBody",
            Self::Keys => "directRequestKeysPublicationBody",
            Self::Prepare => "directRequestPreparationBody",
            Self::Publish => "directRequestPublicationBody",
            Self::Cancel => "directRequestCancellationBody",
            Self::Accept => "directRequestAcceptanceBody",
            Self::Outcome => "directRequestReceiptBody",
            Self::AcceptanceCommit => "directRequestAcceptanceCommitReceiptBody",
        }
    }
    pub fn wrapper_name(self) -> &'static str {
        match self {
            Self::Grant => "signedDirectRequestGrant",
            Self::Keys => "signedDirectRequestKeysPublication",
            Self::Prepare => "signedDirectRequestPreparation",
            Self::Publish => "signedDirectRequestPublication",
            Self::Cancel => "signedDirectRequestCancellation",
            Self::Accept => "signedDirectRequestAcceptance",
            Self::Outcome => "signedDirectRequestReceipt",
            Self::AcceptanceCommit => "signedDirectRequestAcceptanceCommitReceipt",
        }
    }
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::Grant => b"CATBIRD-DIRECT-REQUEST-GRANT\0",
            Self::Keys => b"CATBIRD-DIRECT-REQUEST-KEYS\0",
            Self::Prepare => b"CATBIRD-DIRECT-REQUEST-PREPARE\0",
            Self::Publish => b"CATBIRD-DIRECT-REQUEST-PUBLISH\0",
            Self::Cancel => b"CATBIRD-DIRECT-REQUEST-CANCEL\0",
            Self::Accept => b"CATBIRD-DIRECT-REQUEST-ACCEPT\0",
            Self::Outcome => b"CATBIRD-DIRECT-REQUEST-OUTCOME\0",
            Self::AcceptanceCommit => b"CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0",
        }
    }
}

/// Validates the complete body and returns the exact bytes to sign.
pub fn direct_request_signing_bytes(
    kind: DirectRequestKind,
    raw_body_json: &[u8],
) -> Result<Vec<u8>> {
    let projected = project(raw_body_json, kind.body_name(), true)?;
    if kind == DirectRequestKind::Publish {
        let body: Value = serde_json::from_slice(raw_body_json).map_err(error)?;
        let artifacts = &body["artifacts"];
        if artifacts["metadataSnapshot"].get("avatarBinding").is_some() {
            return Err(error("request bootstrap forbids blob bindings"));
        }
        let paths = [
            &artifacts["genesisGroupInfo"]["bytes"],
            &artifacts["addCommit"]["bytes"],
            &artifacts["finalGroupInfo"]["bytes"],
            &artifacts["welcome"]["opaqueWelcome"],
            &artifacts["metadataSnapshot"]["ciphertext"],
            &artifacts["metadataSnapshot"]["nonce"],
            &artifacts["initialCiphertext"],
        ];
        let mut lengths = Vec::new();
        for value in paths {
            lengths.push(
                STANDARD
                    .decode(
                        value
                            .as_str()
                            .ok_or_else(|| error("artifact bytes missing"))?,
                    )
                    .map_err(error)?
                    .len(),
            );
        }
        validate_bootstrap_artifact_lengths(&lengths)?;
    }

    let mut transcript = kind.domain().to_vec();
    transcript.extend(projected);
    Ok(transcript)
}

/// Identity fields remain schema-validated JSON values; callers must compare them
/// to the authenticated principal and locked device generation before effects.
#[derive(Debug)]
pub struct VerifiedDirectRequest {
    kind: DirectRequestKind,
    body: Value,
    transcript: Vec<u8>,
    signature: [u8; 64],
    digest: [u8; 32],
    accepted_wrapper: Vec<u8>,
}
impl VerifiedDirectRequest {
    pub fn kind(&self) -> DirectRequestKind {
        self.kind
    }
    pub fn body(&self) -> &Value {
        &self.body
    }
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn accepted_wrapper_bytes(&self) -> &[u8] {
        &self.accepted_wrapper
    }
    pub fn actor_did(&self) -> Option<&str> {
        self.body["actorDid"].as_str()
    }
    pub fn actor_device_id(&self) -> Option<&str> {
        self.body["actorDeviceId"].as_str()
    }
    pub fn key_id(&self) -> &str {
        self.body["keyId"].as_str().expect("validated key ID")
    }
    pub fn auth_generation(&self) -> Option<u64> {
        self.body["authGeneration"].as_u64()
    }
    pub fn request_id(&self) -> Option<&str> {
        self.body["requestId"].as_str()
    }
    pub fn idempotency_key(&self) -> Option<&str> {
        self.body["idempotencyKey"].as_str()
    }
}

/// Verification does not authorize publication or establish current device state.
pub fn verify_signed_request(
    kind: DirectRequestKind,
    raw_wrapper: &[u8],
    public_key: &[u8],
) -> Result<VerifiedDirectRequest> {
    // Project the ORIGINAL bytes first, preserving duplicate-field rejection.
    strict_document(raw_wrapper)?;
    let presentation: Value = serde_json::from_slice(raw_wrapper).map_err(error)?;
    let tagged = kind == DirectRequestKind::Outcome && presentation.get("$type").is_some();
    project(raw_wrapper, kind.wrapper_name(), tagged)?;
    let wrapper: Value = serde_json::from_slice(raw_wrapper).map_err(error)?;
    let body = wrapper["body"].clone();
    let transcript =
        direct_request_signing_bytes(kind, &serde_json::to_vec(&body).map_err(error)?)?;
    let signature: [u8; 64] = STANDARD
        .decode(
            wrapper["signature"]
                .as_str()
                .ok_or_else(|| error("signature"))?,
        )
        .map_err(error)?
        .try_into()
        .map_err(|_| error("signature length"))?;
    if matches!(
        kind,
        DirectRequestKind::Outcome | DirectRequestKind::AcceptanceCommit
    ) {
        use p256::ecdsa::signature::Verifier;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(error)?;
        if body["keyId"].as_str() != Some(direct_request_receipt_key_id(public_key)?.as_str()) {
            return Err(error("receipt method fingerprint mismatch"));
        }
        let sig = p256::ecdsa::Signature::from_slice(&signature).map_err(error)?;
        if sig.normalize_s().is_some() {
            return Err(error("noncanonical high-S receipt"));
        }
        key.verify(&transcript, &sig).map_err(error)?;
    } else {
        let key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| error("Ed25519 public key length"))?;
        if body["keyId"].as_str() != Some(URL_SAFE_NO_PAD.encode(Sha256::digest(key)).as_str()) {
            return Err(error("key ID mismatch"));
        }
        VerifyingKey::from_bytes(&key)
            .map_err(error)?
            .verify_strict(&transcript, &Signature::from_bytes(&signature))
            .map_err(error)?;
    }
    let digest = Sha256::digest(&transcript).into();
    Ok(VerifiedDirectRequest {
        kind,
        body,
        transcript,
        signature,
        digest,
        accepted_wrapper: raw_wrapper.to_vec(),
    })
}

pub fn direct_request_context_hash(raw_context_json: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = b"CATBIRD-DIRECT-REQUEST-CONTEXT\0".to_vec();
    bytes.extend(project(raw_context_json, "directRequestContext", false)?);
    Ok(Sha256::digest(bytes).into())
}
pub fn direct_request_commit_aad(context_hash: &[u8; 32]) -> Result<Vec<u8>> {
    aad(
        b"CATBIRD-DIRECT-REQUEST-COMMIT-AAD\0",
        "directRequestCommitAad",
        json!({"protocolVersion":"2","contextHash":STANDARD.encode(context_hash)}),
    )
}
pub fn direct_request_application_aad(
    context_hash: &[u8; 32],
    coordinates_json: &[u8],
    message_id: &str,
) -> Result<Vec<u8>> {
    project(coordinates_json, "conversationCoordinates", false)?;
    let coordinate: Value = serde_json::from_slice(coordinates_json).map_err(error)?;
    aad(
        b"CATBIRD-DIRECT-REQUEST-APPLICATION-AAD\0",
        "directRequestApplicationAad",
        json!({"protocolVersion":"2","contextHash":STANDARD.encode(context_hash),"coordinates":coordinate,"messageId":message_id}),
    )
}
fn aad(domain: &[u8], name: &str, value: Value) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(project(
        &serde_json::to_vec(&value).map_err(error)?,
        name,
        false,
    )?);
    Ok(bytes)
}

/// Limits the sum of the exact decoded MLS and metadata artifact bytes before
/// reservation/publication. Identical Welcome bytes are counted only once here;
/// accounting charges this total independently to both accounts.
pub fn validate_bootstrap_artifact_lengths(lengths: &[usize]) -> Result<usize> {
    let sum = lengths
        .iter()
        .try_fold(0usize, |total, len| total.checked_add(*len))
        .ok_or_else(|| error("artifact size overflow"))?;
    if sum > MAX_BOOTSTRAP_ARTIFACT_BYTES {
        return Err(error("bootstrap artifact byte cap"));
    }
    Ok(sum)
}

fn project(raw: &[u8], name: &str, tagged: bool) -> Result<Vec<u8>> {
    if raw.len() > MAX_PUBLISH_HTTP_BODY_BYTES {
        return Err(error("JSON body cap"));
    }
    let strict = super::decode_strict_json(raw).map_err(error)?;
    let canonical = super::project_ref(name, &strict, tagged).map_err(error)?;
    serde_ipld_dagcbor::to_vec(&canonical).map_err(error)
}

/// Domain-prefixed exact snapshot for the independently configured ES256 receipt signer.
pub fn direct_request_preparation_signing_bytes(raw_snapshot_json: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = b"CATBIRD-DIRECT-REQUEST-PREPARATION-RECEIPT\0".to_vec();
    bytes.extend(project(
        raw_snapshot_json,
        "directRequestPreparationSnapshot",
        false,
    )?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vectors() -> Value {
        serde_json::from_str(include_str!("vectors/direct_request_vectors.json")).unwrap()
    }
    fn kind(value: &str) -> DirectRequestKind {
        *DirectRequestKind::ALL
            .iter()
            .find(|k| format!("{k:?}") == value)
            .unwrap()
    }
    #[test]
    fn independent_cbor_vectors_match_all_operations_and_terminal_outcomes() {
        let v = vectors();
        for row in v["signed"].as_array().unwrap() {
            let bytes = direct_request_signing_bytes(
                kind(row["kind"].as_str().unwrap()),
                &serde_json::to_vec(&row["body"]).unwrap(),
            )
            .unwrap();
            assert_eq!(hex::encode(&bytes), row["transcriptHex"].as_str().unwrap());
            assert_eq!(
                hex::encode(Sha256::digest(&bytes)),
                row["digestHex"].as_str().unwrap()
            );
        }
        let hash = direct_request_context_hash(&serde_json::to_vec(&v["context"]["body"]).unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(hash),
            v["context"]["digestHex"].as_str().unwrap()
        );
    }
    #[test]
    fn every_signed_binding_rejects_tamper_duplicate_and_unknown_fields() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        for row in vectors()["signed"].as_array().unwrap() {
            let kind = kind(row["kind"].as_str().unwrap());
            if matches!(
                kind,
                DirectRequestKind::Outcome | DirectRequestKind::AcceptanceCommit
            ) {
                continue;
            }
            let mut body = row["body"].clone();
            body["keyId"] = Value::String(
                URL_SAFE_NO_PAD.encode(Sha256::digest(signing.verifying_key().as_bytes())),
            );
            let bytes =
                direct_request_signing_bytes(kind, &serde_json::to_vec(&body).unwrap()).unwrap();
            let signature = STANDARD.encode(signing.sign(&bytes).to_bytes());
            let wrapper = json!({"body":body,"signature":signature});
            verify_signed_request(
                kind,
                &serde_json::to_vec(&wrapper).unwrap(),
                signing.verifying_key().as_bytes(),
            )
            .unwrap();
            // Every top-level field participates in the signature or strict schema.
            for field in body.as_object().unwrap().keys() {
                let mut altered = wrapper.clone();
                altered["body"][field] = Value::String("tampered".into());
                assert!(
                    verify_signed_request(
                        kind,
                        &serde_json::to_vec(&altered).unwrap(),
                        signing.verifying_key().as_bytes()
                    )
                    .is_err(),
                    "{kind:?} {field}"
                );
            }
            let mut altered = wrapper.clone();
            altered["unsignedExtra"] = json!(true);
            assert!(verify_signed_request(
                kind,
                &serde_json::to_vec(&altered).unwrap(),
                signing.verifying_key().as_bytes()
            )
            .is_err());
            let raw = serde_json::to_string(&wrapper).unwrap();
            let duplicate = raw.replacen('{', "{\"signature\":\"AA==\",", 1);
            assert!(verify_signed_request(
                kind,
                duplicate.as_bytes(),
                signing.verifying_key().as_bytes()
            )
            .is_err());
        }
    }
    #[test]
    fn exact_and_plus_one_limits() {
        assert_eq!(
            validate_bootstrap_artifact_lengths(&[MAX_BOOTSTRAP_ARTIFACT_BYTES]).unwrap(),
            MAX_BOOTSTRAP_ARTIFACT_BYTES
        );
        assert!(validate_bootstrap_artifact_lengths(&[MAX_BOOTSTRAP_ARTIFACT_BYTES, 1]).is_err());
        assert!(validate_bootstrap_artifact_lengths(&[usize::MAX, 1]).is_err());
        let mut raw = serde_json::to_vec(&vectors()["context"]["body"]).unwrap();
        raw.resize(MAX_PUBLISH_HTTP_BODY_BYTES, b' ');
        assert!(direct_request_context_hash(&raw).is_ok());
        raw.push(b' ');
        assert!(direct_request_context_hash(&raw).is_err());
    }
    #[test]
    fn dedicated_es256_outcomes_bind_every_terminal_state() {
        use p256::ecdsa::signature::Signer;
        let key = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        for row in vectors()["signed"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "Outcome")
        {
            let mut body = row["body"].clone();
            body["keyId"] = json!(direct_request_receipt_key_id(
                key.verifying_key().to_encoded_point(true).as_bytes()
            )
            .unwrap());
            let bytes = direct_request_signing_bytes(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
            let sig: p256::ecdsa::Signature = key.sign(&bytes);
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut wrapper = json!({"body":body,"signature":STANDARD.encode(sig.to_bytes())});
            verify_signed_request(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&wrapper).unwrap(),
                key.verifying_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap();
            wrapper["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
            verify_signed_request(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&wrapper).unwrap(),
                key.verifying_key().to_encoded_point(true).as_bytes(),
            )
            .unwrap();
            wrapper["$type"] =
                json!("blue.catbird.chat.defs#signedDirectRequestAcceptanceCommitReceipt");
            assert!(verify_signed_request(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&wrapper).unwrap(),
                key.verifying_key().to_encoded_point(true).as_bytes()
            )
            .is_err());
            wrapper.as_object_mut().unwrap().remove("$type");
            wrapper["body"]["receipt"]["requestDigest"] = json!(STANDARD.encode([1; 32]));
            assert!(verify_signed_request(
                DirectRequestKind::Outcome,
                &serde_json::to_vec(&wrapper).unwrap(),
                key.verifying_key().to_encoded_point(true).as_bytes()
            )
            .is_err());
        }
    }
}

/// Identifier only, not trust establishment. The caller must resolve this exact
/// retained method from the authenticated configured authority DID document.
pub fn direct_request_receipt_key_id(public_key: &[u8]) -> Result<String> {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(error)?;
    let hash = Sha256::digest(key.to_encoded_point(true).as_bytes());
    Ok(format!(
        "did:web:chat.catbird.blue#chat-request-receipt-{}",
        hex::encode(hash)
    ))
}
/// Verify the complete immutable snapshot with an independently trusted method.
pub fn verify_direct_request_preparation(
    raw_view: &[u8],
    trusted_public_key: &[u8],
) -> Result<Value> {
    use p256::ecdsa::signature::Verifier;
    if raw_view.len() > MAX_PREPARE_HTTP_RESPONSE_BYTES {
        return Err(error("preparation response byte cap"));
    }
    let normalized = normalize_read_presentation(raw_view, "directRequestPreparationView", false)?;
    let normalized_bytes = serde_json::to_vec(&normalized).map_err(error)?;
    project(&normalized_bytes, "directRequestPreparationView", false)?;
    let view = normalized;
    if view["receiptKeyId"].as_str()
        != Some(direct_request_receipt_key_id(trusted_public_key)?.as_str())
    {
        return Err(error("preparation receipt method mismatch"));
    }
    let mut snapshot = view.clone();
    let object = snapshot.as_object_mut().ok_or_else(|| error("snapshot"))?;
    object.remove("preparationDigest");
    object.remove("preparationSignature");
    let transcript =
        direct_request_preparation_signing_bytes(&serde_json::to_vec(&snapshot).map_err(error)?)?;
    if view["preparationDigest"].as_str()
        != Some(STANDARD.encode(Sha256::digest(&transcript)).as_str())
    {
        return Err(error("preparation digest mismatch"));
    }
    let sig = STANDARD
        .decode(
            view["preparationSignature"]
                .as_str()
                .ok_or_else(|| error("signature"))?,
        )
        .map_err(error)?;
    let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(error)?;
    if sig.normalize_s().is_some() {
        return Err(error("noncanonical high-S receipt"));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(trusted_public_key)
        .map_err(error)?
        .verify(&transcript, &sig)
        .map_err(error)?;
    Ok(view)
}

/// The document must have been obtained through the caller's authenticated DID
/// resolver. This pure validation never turns receipt-provided keys into trust.
pub fn resolve_direct_request_receipt_key(
    authenticated_document: &[u8],
    method_id: &str,
) -> Result<Vec<u8>> {
    const AUTHORITY: &str = "did:web:chat.catbird.blue";
    if authenticated_document.len() > 1024 * 1024 {
        return Err(error("DID document byte cap"));
    }
    strict_document(authenticated_document)?;
    let doc: Value = serde_json::from_slice(authenticated_document).map_err(error)?;
    if doc["id"].as_str() != Some(AUTHORITY) {
        return Err(error("receipt document owner mismatch"));
    }
    let methods = doc["verificationMethod"]
        .as_array()
        .ok_or_else(|| error("receipt verification methods missing"))?;
    let found: Vec<_> = methods
        .iter()
        .filter(|m| m["id"].as_str() == Some(method_id))
        .collect();
    if found.len() != 1 {
        return Err(error("receipt method missing or ambiguous"));
    }
    let method = found[0];
    if method["controller"].as_str() != Some(AUTHORITY)
        || method["type"].as_str() != Some("Multikey")
    {
        return Err(error("receipt controller or key type mismatch"));
    }
    let (_, bytes) = multibase::decode(
        method["publicKeyMultibase"]
            .as_str()
            .ok_or_else(|| error("receipt multikey missing"))?,
    )
    .map_err(error)?;
    if bytes.len() != 35 || bytes[..2] != [0x80, 0x24] {
        return Err(error("receipt key must be compressed P256 multikey"));
    }
    let key = &bytes[2..];
    if direct_request_receipt_key_id(key)? != method_id {
        return Err(error("receipt immutable method fingerprint mismatch"));
    }
    Ok(key.to_vec())
}

fn strict_document(raw: &[u8]) -> Result<()> {
    super::decode_strict_json(raw).map_err(error)?;
    Ok(())
}

#[cfg(test)]
mod receipt_rotation_tests {
    use super::*;
    fn method(key: &p256::ecdsa::SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(true);
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(point.as_bytes());
        json!({"id":direct_request_receipt_key_id(point.as_bytes()).unwrap(),"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)})
    }
    #[test]
    fn rotation_retains_old_method_and_rejects_untrusted_shapes() {
        let old = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let new = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let old_method = method(&old);
        let new_method = method(&new);
        let id = old_method["id"].as_str().unwrap();
        let mut doc =
            json!({"id":"did:web:chat.catbird.blue","verificationMethod":[old_method,new_method]});
        assert_eq!(
            resolve_direct_request_receipt_key(&serde_json::to_vec(&doc).unwrap(), id).unwrap(),
            old.verifying_key().to_encoded_point(true).as_bytes()
        );
        let baseline = doc.clone();
        doc["verificationMethod"][0]["controller"] = json!("did:web:attacker.example");
        assert!(
            resolve_direct_request_receipt_key(&serde_json::to_vec(&doc).unwrap(), id).is_err()
        );
        doc = baseline.clone();
        doc["verificationMethod"][0]["publicKeyMultibase"] =
            doc["verificationMethod"][1]["publicKeyMultibase"].clone();
        assert!(
            resolve_direct_request_receipt_key(&serde_json::to_vec(&doc).unwrap(), id).is_err()
        );
        doc = baseline.clone();
        doc["verificationMethod"][1] = doc["verificationMethod"][0].clone();
        assert!(
            resolve_direct_request_receipt_key(&serde_json::to_vec(&doc).unwrap(), id).is_err()
        );
        doc = baseline;
        doc["verificationMethod"].as_array_mut().unwrap().remove(0);
        assert!(
            resolve_direct_request_receipt_key(&serde_json::to_vec(&doc).unwrap(), id).is_err()
        );
    }
}

/// Verify recipient intent and committed server policy inclusion. The caller must
/// additionally bind the prior coordinate to its independently retained history.
pub fn verify_direct_request_acceptance_proof(
    raw_proof: &[u8],
    trusted_authority_key: &[u8],
    recipient_device_key: &[u8],
) -> Result<Value> {
    project(raw_proof, "directRequestAcceptanceProof", false)?;
    let proof: Value = serde_json::from_slice(raw_proof).map_err(error)?;
    let acceptance = verify_signed_request(
        DirectRequestKind::Accept,
        &serde_json::to_vec(&proof["entry"]["signedRequest"]).map_err(error)?,
        recipient_device_key,
    )?;
    let receipt = verify_signed_request(
        DirectRequestKind::AcceptanceCommit,
        &serde_json::to_vec(&proof["receipt"]).map_err(error)?,
        trusted_authority_key,
    )?;
    let body = acceptance.body();
    let commit = receipt.body();
    let mut bytes = b"CATBIRD-DIRECT-REQUEST-ACCEPTANCE-ENTRY\0".to_vec();
    bytes.extend(project(
        &serde_json::to_vec(&proof["entry"]).map_err(error)?,
        "directRequestAcceptanceEntry",
        false,
    )?);
    if commit["entryHash"] != json!(STANDARD.encode(Sha256::digest(bytes)))
        || commit["acceptanceDigest"] != json!(STANDARD.encode(acceptance.request_digest()))
    {
        return Err(error("acceptance inclusion digest mismatch"));
    }
    for field in ["requestId", "prior", "next"] {
        if commit[field] != body[field] {
            return Err(error("acceptance inclusion coordinate mismatch"));
        }
    }
    if proof["entry"]["conversationId"] != body["prior"]["conversationId"] {
        return Err(error("acceptance entry conversation mismatch"));
    }
    let mut expected = body["prior"].clone();
    let version = expected["stateVersion"]
        .as_u64()
        .ok_or_else(|| error("state version"))?;
    expected["stateVersion"] = json!(version
        .checked_add(1)
        .ok_or_else(|| error("state version overflow"))?);
    if body["next"] != expected {
        return Err(error("acceptance must change only policy state version"));
    }
    Ok(proof)
}

/// Strict introduction plaintext profile. This function must run before encryption
/// and after decryption; it never authorizes bot forwarding or account acceptance.
pub fn validate_direct_request_introduction(raw_json: &[u8]) -> Result<Value> {
    project(raw_json, "directRequestIntroduction", false)?;
    let value: Value = serde_json::from_slice(raw_json).map_err(error)?;
    let text = value["text"]
        .as_str()
        .ok_or_else(|| error("introduction text"))?;
    if text.is_empty() || text.len() > MAX_REQUEST_TEXT_UTF8_BYTES {
        return Err(error("introduction UTF-8 byte cap"));
    }
    Ok(value)
}

/// Hash of exact retained server entry fields and recipient signed consent.
pub fn direct_request_acceptance_entry_hash(raw_entry: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = b"CATBIRD-DIRECT-REQUEST-ACCEPTANCE-ENTRY\0".to_vec();
    bytes.extend(project(raw_entry, "directRequestAcceptanceEntry", false)?);
    Ok(Sha256::digest(bytes).into())
}
#[cfg(test)]
mod field_bound_tests {
    use super::*;
    #[test]
    fn unicode_text_and_application_ciphertext_exact_bounds() {
        let text = "é".repeat(MAX_REQUEST_TEXT_UTF8_BYTES / 2);
        assert!(validate_direct_request_introduction(
            &serde_json::to_vec(&json!({"text":text})).unwrap()
        )
        .is_ok());
        assert!(validate_direct_request_introduction(
            &serde_json::to_vec(&json!({"text":format!("{text}a")})).unwrap()
        )
        .is_err());
        let fixture: Value =
            serde_json::from_str(include_str!("vectors/direct_request_vectors.json")).unwrap();
        let mut publish = fixture["signed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == "Publish")
            .unwrap()["body"]
            .clone();
        publish["artifacts"]["initialCiphertext"] =
            json!(STANDARD.encode(vec![0; MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES]));
        assert!(direct_request_signing_bytes(
            DirectRequestKind::Publish,
            &serde_json::to_vec(&publish).unwrap()
        )
        .is_ok());
        publish["artifacts"]["initialCiphertext"] =
            json!(STANDARD.encode(vec![0; MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES + 1]));
        assert!(direct_request_signing_bytes(
            DirectRequestKind::Publish,
            &serde_json::to_vec(&publish).unwrap()
        )
        .is_err());
    }
}

/// Strict endpoint presence check preserving the byte-identical legacy form.
/// Returns true for directRequest (v2), false for signedRequest (v1).
pub fn direct_request_acceptance_endpoint_is_v2(raw_endpoint: &[u8]) -> Result<bool> {
    strict_document(raw_endpoint)?;
    let value: Value = serde_json::from_slice(raw_endpoint).map_err(error)?;
    let object = value
        .as_object()
        .ok_or_else(|| error("acceptance endpoint object"))?;
    if object.len() != 1 {
        return Err(error("acceptance requires exactly one versioned request"));
    }
    if object.contains_key("signedRequest") {
        // Version selection precedes the established v1 DTO normalization.
        // The legacy signed body may be untagged at this host boundary; its
        // existing canonical decoder remains the signature/schema authority.
        let wrapper = object["signedRequest"]
            .as_object()
            .ok_or_else(|| error("legacy signed wrapper"))?;
        if wrapper.len() != 2
            || !wrapper.get("body").is_some_and(Value::is_object)
            || !wrapper.contains_key("signature")
        {
            return Err(error("legacy signed wrapper fields"));
        }
        Ok(false)
    } else if object.contains_key("directRequest") {
        project(
            &serde_json::to_vec(&object["directRequest"]).map_err(error)?,
            "signedDirectRequestAcceptance",
            false,
        )?;
        Ok(true)
    } else {
        Err(error("unknown acceptance endpoint field"))
    }
}

#[cfg(test)]
mod acceptance_presence_tests {
    use super::*;
    #[test]
    fn exact_legacy_or_direct_form_is_required() {
        let fixture: Value =
            serde_json::from_str(include_str!("vectors/direct_request_vectors.json")).unwrap();
        let old =
            json!({"body":fixture["legacyAcceptanceBody"],"signature":STANDARD.encode([0;64])});
        let new_body = fixture["signed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == "Accept")
            .unwrap()["body"]
            .clone();
        let new = json!({"body":new_body,"signature":STANDARD.encode([0;64])});
        let legacy = json!({"signedRequest":old});
        let direct = json!({"directRequest":new});
        let mut untagged_legacy = legacy.clone();
        untagged_legacy["signedRequest"]["body"]
            .as_object_mut()
            .unwrap()
            .remove("$type");
        assert!(!direct_request_acceptance_endpoint_is_v2(
            &serde_json::to_vec(&untagged_legacy).unwrap()
        )
        .unwrap());

        assert!(
            !direct_request_acceptance_endpoint_is_v2(&serde_json::to_vec(&legacy).unwrap())
                .unwrap()
        );
        assert!(
            direct_request_acceptance_endpoint_is_v2(&serde_json::to_vec(&direct).unwrap())
                .unwrap()
        );
        assert!(direct_request_acceptance_endpoint_is_v2(b"{}").is_err());
        assert!(direct_request_acceptance_endpoint_is_v2(
            &serde_json::to_vec(&json!({"signedRequest":old,"directRequest":new})).unwrap()
        )
        .is_err());
    }
}

/// Canonical immutable request entry fingerprint. This hash is an identity,
/// not a substitute for publication receipt or authenticated read authority.
pub fn direct_request_entry_hash(raw_entry: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = b"CATBIRD-DIRECT-REQUEST-ENTRY\0".to_vec();
    bytes.extend(project(raw_entry, "directRequestEntry", false)?);
    Ok(Sha256::digest(bytes).into())
}

/// Host JSON is validated before encryption. Plaintext is canonical DAG-CBOR;
/// unlike signing projections, UUIDs/DIDs in this application object stay text.
pub fn encode_direct_request_introduction(raw_host_json: &[u8]) -> Result<Vec<u8>> {
    let value = validate_direct_request_introduction(raw_host_json)?;
    serde_ipld_dagcbor::to_vec(&value).map_err(error)
}
/// Exact canonical bytes are required before any preview or invitation projection.
pub fn decode_direct_request_introduction(raw_cbor: &[u8]) -> Result<Value> {
    if raw_cbor.len() > MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES {
        return Err(error("introduction plaintext byte cap"));
    }
    let value: Value = serde_ipld_dagcbor::from_slice(raw_cbor).map_err(error)?;
    let canonical = serde_ipld_dagcbor::to_vec(&value).map_err(error)?;
    if canonical != raw_cbor {
        return Err(error("noncanonical introduction CBOR"));
    }
    validate_direct_request_introduction(&serde_json::to_vec(&value).map_err(error)?)
}
#[cfg(test)]
mod introduction_cbor_tests {
    use super::*;
    #[test]
    fn worst_case_json_escape_text_and_invitation_fit_unchanged_ciphertext_budget() {
        let text = "\0".repeat(MAX_REQUEST_TEXT_UTF8_BYTES);
        let value = json!({"text":text,"invitation":{"authorityDid":"did:web:chat.catbird.blue","conversationId":"12345678-1234-4234-8234-123456789abc","invitationTransitionId":"22345678-1234-4234-8234-123456789abc","invitedByDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","invitedByDeviceId":"32345678-1234-4234-8234-123456789abc","recipientDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}});
        let host = serde_json::to_vec(&value).unwrap();
        assert!(host.len() > MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES);
        let encrypted_plaintext = encode_direct_request_introduction(&host).unwrap();
        assert!(encrypted_plaintext.len() < MAX_REQUEST_TEXT_UTF8_BYTES + 1024);
        assert_eq!(
            decode_direct_request_introduction(&encrypted_plaintext).unwrap(),
            value
        );
    }
    #[test]
    fn duplicates_unknowns_and_noncanonical_encodings_fail_closed() {
        // Two text keys in a map, even if a generic decoder would choose one.
        assert!(decode_direct_request_introduction(b"\xa2\x64text\x61a\x64text\x61b").is_err());
        assert!(decode_direct_request_introduction(b"\xbf\x64text\x61a\xff").is_err());
        let unknown =
            serde_ipld_dagcbor::to_vec(&json!({"text":"hello","attachment":"forbidden"})).unwrap();
        assert!(decode_direct_request_introduction(&unknown).is_err());
        let mut invalid = json!({"text":"hello","invitation":{"authorityDid":"did:web:chat.catbird.blue","conversationId":"NOT-A-UUID","invitationTransitionId":"22345678-1234-4234-8234-123456789abc","invitedByDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","invitedByDeviceId":"32345678-1234-4234-8234-123456789abc","recipientDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"}});
        assert!(
            encode_direct_request_introduction(&serde_json::to_vec(&invalid).unwrap()).is_err()
        );
        invalid["invitation"] = Value::Null;
        assert!(
            encode_direct_request_introduction(&serde_json::to_vec(&invalid).unwrap()).is_err()
        );
    }
}

/// Compare already signature-verified preparation/publication bodies. This is
/// a binding check, not a replacement for either signature verification.
pub fn direct_request_preparation_matches_publication(
    preparation: &Value,
    publication: &Value,
) -> bool {
    for field in [
        "requestId",
        "firstMessageId",
        "conversationId",
        "recipientDid",
        "origin",
        "profile",
        "preparationDigest",
        "preparationRequestDigest",
    ] {
        if preparation.get(field).is_none() || preparation[field] != publication[field] {
            return false;
        }
    }
    for field in ["actorDid", "actorDeviceId", "keyId", "authGeneration"] {
        if preparation["creator"].get(field).is_none()
            || preparation["creator"][field] != publication[field]
        {
            return false;
        }
    }
    let Some(selected) = preparation["selectedDevices"].as_array() else {
        return false;
    };
    let Some(deliveries) = publication["artifacts"]["welcome"]["deliveries"].as_array() else {
        return false;
    };
    if selected.is_empty() || selected.len() != deliveries.len() {
        return false;
    }
    let mut identities = std::collections::BTreeSet::new();
    selected.iter().all(|selected| {
        let (Some(did), Some(device)) = (
            selected["actorDid"].as_str(),
            selected["actorDeviceId"].as_str(),
        ) else {
            return false;
        };
        if !identities.insert((did, device)) {
            return false;
        }
        deliveries
            .iter()
            .filter(|delivery| {
                let provenance = &delivery["provenance"];
                delivery["recipientDid"] == selected["actorDid"]
                    && delivery["recipientDeviceId"] == selected["actorDeviceId"]
                    && selected["keyPackage"].get("keyPackageRef").is_some()
                    && provenance["keyPackageRef"] == selected["keyPackage"]["keyPackageRef"]
                    && provenance["grantId"] == selected["grant"]["body"]["grantId"]
                    && provenance["grantRevision"] == selected["grant"]["body"]["grantRevision"]
                    && [
                        "requestId",
                        "preparationDigest",
                        "contextHash",
                        "importUntil",
                    ]
                    .iter()
                    .all(|field| {
                        publication.get(field).is_some()
                            && provenance[*field] == publication[*field]
                    })
            })
            .count()
            == 1
    })
}

#[cfg(test)]
mod preparation_publication_binding_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn signed_preparation_and_publication_require_exact_nested_delivery_provenance() {
        // Real signatures over strict wire shapes. MLS validity is deliberately
        // delegated to the retained OpenMLS corpus; this test targets the DB
        // hydration comparison that formerly looked at a nonexistent flat ref.
        let fixtures: Value =
            serde_json::from_str(include_str!("vectors/direct_request_vectors.json")).unwrap();
        let sample = |kind: &str| {
            fixtures["signed"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["kind"] == kind)
                .unwrap()["body"]
                .clone()
        };
        let actor = SigningKey::from_bytes(&[7; 32]);
        let recipient = SigningKey::from_bytes(&[8; 32]);
        let actor_id = URL_SAFE_NO_PAD.encode(Sha256::digest(actor.verifying_key().as_bytes()));
        let recipient_id =
            URL_SAFE_NO_PAD.encode(Sha256::digest(recipient.verifying_key().as_bytes()));
        let sign = |kind, body: &Value, key: &SigningKey| {
            let bytes =
                direct_request_signing_bytes(kind, &serde_json::to_vec(body).unwrap()).unwrap();
            json!({"body":body,"signature":STANDARD.encode(key.sign(&bytes).to_bytes())})
        };
        let mut publication = sample("Publish");
        publication["keyId"] = json!(actor_id);
        publication["recipientDid"] = json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
        let mut grant = sample("Grant");
        grant["actorDid"] = publication["recipientDid"].clone();
        grant["keyId"] = json!(recipient_id);
        let signed_grant = sign(DirectRequestKind::Grant, &grant, &recipient);
        verify_signed_request(
            DirectRequestKind::Grant,
            &serde_json::to_vec(&signed_grant).unwrap(),
            recipient.verifying_key().as_bytes(),
        )
        .unwrap();
        let authority = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let public = authority.verifying_key().to_encoded_point(true);
        let mut preparation = json!({"protocolVersion":"2","requestId":publication["requestId"],"firstMessageId":publication["firstMessageId"],"conversationId":publication["conversationId"],"recipientDid":publication["recipientDid"],"origin":publication["origin"],"profile":publication["profile"],"creator":{"actorDid":publication["actorDid"],"actorDeviceId":publication["actorDeviceId"],"keyId":publication["keyId"],"authGeneration":publication["authGeneration"]},"selectedDevices":[{"actorDid":grant["actorDid"],"actorDeviceId":grant["actorDeviceId"],"keyId":grant["keyId"],"authGeneration":grant["authGeneration"],"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":STANDARD.encode([1;8]),"sha256":STANDARD.encode(Sha256::digest([1;8])),"keyPackageRef":grant["keyPackageRef"]},"grant":signed_grant}],"preparedAt":"2026-09-19T12:00:00.000Z","leaseExpiresAt":"2026-09-19T12:05:00.000Z","minimumImportUntil":"2026-09-26T12:05:00.000Z","preparationRequestDigest":publication["preparationRequestDigest"],"authorityDid":"did:web:chat.catbird.blue","receiptKeyId":direct_request_receipt_key_id(public.as_bytes()).unwrap()});
        let bytes =
            direct_request_preparation_signing_bytes(&serde_json::to_vec(&preparation).unwrap())
                .unwrap();
        let signature: p256::ecdsa::Signature = authority.sign(&bytes);
        let signature = signature.normalize_s().unwrap_or(signature);
        preparation["preparationDigest"] = json!(STANDARD.encode(Sha256::digest(bytes)));
        preparation["preparationSignature"] = json!(STANDARD.encode(signature.to_bytes()));
        let preparation = verify_direct_request_preparation(
            &serde_json::to_vec(&preparation).unwrap(),
            public.as_bytes(),
        )
        .unwrap();
        publication["preparationDigest"] = preparation["preparationDigest"].clone();
        publication["artifacts"]["welcome"]["deliveries"] = json!([{"recipientDid":grant["actorDid"],"recipientDeviceId":grant["actorDeviceId"],"provenance":{"requestId":publication["requestId"],"preparationDigest":publication["preparationDigest"],"contextHash":publication["contextHash"],"grantId":grant["grantId"],"grantRevision":grant["grantRevision"],"keyPackageRef":grant["keyPackageRef"],"importUntil":publication["importUntil"]}}]);
        let signed = sign(DirectRequestKind::Publish, &publication, &actor);
        let verified = verify_signed_request(
            DirectRequestKind::Publish,
            &serde_json::to_vec(&signed).unwrap(),
            actor.verifying_key().as_bytes(),
        )
        .unwrap();
        assert!(direct_request_preparation_matches_publication(
            &preparation,
            verified.body()
        ));
        let mut flat = publication.clone();
        flat["artifacts"]["welcome"]["deliveries"][0]["keyPackageRef"] =
            grant["keyPackageRef"].clone();
        flat["artifacts"]["welcome"]["deliveries"][0]["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("keyPackageRef");
        assert!(!direct_request_preparation_matches_publication(
            &preparation,
            &flat
        ));
        let mut wrong = publication.clone();
        wrong["artifacts"]["welcome"]["deliveries"][0]["provenance"]["grantRevision"] = json!(2);
        assert!(!direct_request_preparation_matches_publication(
            &preparation,
            &wrong
        ));
        let mut wrong = preparation.clone();
        wrong["creator"]["authGeneration"] = json!(2);
        assert!(!direct_request_preparation_matches_publication(
            &wrong,
            &publication
        ));
    }
}

fn read_definition(name: &str) -> Result<&'static Value> {
    super::contract::definition(name).map_err(error)
}

/// Normalize only schema-declared bytes in a received read presentation of any
/// `blue.catbird.chat.defs` definition (entries of every kind, state, inventory
/// scopes, outcomes, receipts): lexicon `{"$bytes"}` objects become bare
/// canonical base64 and bare base64 is kept. This is not mutation admission:
/// the strict signing and ingress APIs remain unchanged.
/// Duplicate raw fields are rejected before JSON values can discard evidence.
/// The returned value still passes the complete closed contract projection.
pub fn normalize_read_presentation(
    raw: &[u8],
    name: &str,
    tagged: bool,
) -> Result<Value> {
    if raw.len() > MAX_PUBLISH_HTTP_BODY_BYTES {
        return Err(error("JSON body cap"));
    }
    strict_document(raw)?;
    let mut value: Value = serde_json::from_slice(raw).map_err(error)?;
    normalize_read_bytes(name, &mut value)?;
    project(&serde_json::to_vec(&value).map_err(error)?, name, tagged)?;
    Ok(value)
}

/// The schema-directed byte conversion of [`normalize_read_presentation`]
/// alone, for callers that project or verify the value themselves.
pub(crate) fn normalize_read_bytes(name: &str, value: &mut Value) -> Result<()> {
    normalize_read_schema(read_definition(name)?, value, 0)
}

fn normalize_read_schema(schema: &Value, value: &mut Value, depth: usize) -> Result<()> {
    if depth > 128 {
        return Err(error("read presentation nesting cap"));
    }
    match schema["type"].as_str() {
        Some("ref") => {
            let name = schema["ref"]
                .as_str()
                .and_then(|s| s.strip_prefix('#'))
                .ok_or_else(|| error("unsupported read schema reference"))?;
            normalize_read_schema(read_definition(name)?, value, depth + 1)?;
        }
        Some("bytes") => {
            if let Some(object) = value.as_object() {
                if object.len() != 1 {
                    return Err(error("bytes presentation must contain only $bytes"));
                }
                let encoded = object
                    .get("$bytes")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error("invalid bytes presentation"))?;
                let bytes = STANDARD.decode(encoded).map_err(error)?;
                if STANDARD.encode(&bytes) != encoded {
                    return Err(error("noncanonical bytes presentation"));
                }
                *value = Value::String(encoded.to_owned());
            }
        }
        Some("object") => {
            if let Some(object) = value.as_object_mut() {
                let properties = schema["properties"]
                    .as_object()
                    .ok_or_else(|| error("invalid object schema"))?;
                for (field, value) in object {
                    // Preserve undeclared fields for the strict projector to
                    // reject. Never guess byte semantics from a field's name.
                    if let Some(property) = properties.get(field) {
                        normalize_read_schema(property, value, depth + 1)?;
                    }
                }
            }
        }
        Some("array") => {
            if let Some(values) = value.as_array_mut() {
                for value in values {
                    normalize_read_schema(&schema["items"], value, depth + 1)?;
                }
            }
        }
        Some("union") => {
            // An untagged value has no selected variant; the strict projector
            // decides whether the tag is required.
            let Some(tag) = value.get("$type") else {
                return Ok(());
            };
            let name = tag
                .as_str()
                .and_then(|s| s.strip_prefix("blue.catbird.chat.defs#"))
                .ok_or_else(|| error("invalid read union tag"))?;
            let allowed = schema["refs"]
                .as_array()
                .ok_or_else(|| error("invalid union schema"))?
                .iter()
                .any(|r| r.as_str().and_then(|s| s.strip_prefix('#')) == Some(name));
            if !allowed {
                return Err(error("unknown read union tag"));
            }
            normalize_read_schema(read_definition(name)?, value, depth + 1)?;
        }
        Some("string" | "integer" | "boolean") => {}
        _ => return Err(error("unsupported read schema type")),
    }
    Ok(())
}

/// Verify a received read representation through the unchanged strict verifier.
/// Body values use bare canonical base64 for downstream identity comparisons;
/// provenance retains the exact received wrapper bytes, never rewritten bytes.
pub fn verify_received_signed_request(
    kind: DirectRequestKind,
    raw_wrapper: &[u8],
    public_key: &[u8],
) -> Result<VerifiedDirectRequest> {
    strict_document(raw_wrapper)?;
    let wrapper: Value = serde_json::from_slice(raw_wrapper).map_err(error)?;
    let tagged = kind == DirectRequestKind::Outcome && wrapper.get("$type").is_some();
    let normalized =
        normalize_read_presentation(raw_wrapper, kind.wrapper_name(), tagged)?;
    let mut verified = verify_signed_request(
        kind,
        &serde_json::to_vec(&normalized).map_err(error)?,
        public_key,
    )?;
    verified.accepted_wrapper = raw_wrapper.to_vec();
    Ok(verified)
}

/// Read-side counterpart: normalize nested byte presentations before strict
/// signature verification and acceptance-entry/receipt equality checks.
pub fn verify_received_direct_request_acceptance_proof(
    raw_proof: &[u8],
    trusted_authority_key: &[u8],
    recipient_device_key: &[u8],
) -> Result<Value> {
    let proof = normalize_read_presentation(
        raw_proof,
        "directRequestAcceptanceProof",
        false,
    )?;
    verify_direct_request_acceptance_proof(
        &serde_json::to_vec(&proof).map_err(error)?,
        trusted_authority_key,
        recipient_device_key,
    )
}

#[cfg(test)]
mod read_presentation_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("vectors/direct_request_vectors.json")).unwrap()
    }
    fn body(kind: DirectRequestKind) -> Value {
        vectors()["signed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == format!("{kind:?}"))
            .unwrap()["body"]
            .clone()
    }
    // Test producer traverses the schema independently of the normalization
    // routine; arbitrary base64-looking text is never a bytes field.
    fn present(schema: &Value, value: &mut Value) {
        match schema["type"].as_str().unwrap() {
            "bytes" => *value = json!({"$bytes":value.clone()}),
            "ref" => present(
                read_definition(schema["ref"].as_str().unwrap().strip_prefix('#').unwrap())
                    .unwrap(),
                value,
            ),
            "union" => {
                let name = value["$type"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("blue.catbird.chat.defs#")
                    .unwrap();
                present(read_definition(name).unwrap(), value);
            }
            "array" => {
                for item in value.as_array_mut().unwrap() {
                    present(&schema["items"], item)
                }
            }
            "object" => {
                for (key, item) in value.as_object_mut().unwrap() {
                    if let Some(schema) = schema["properties"].get(key) {
                        present(schema, item)
                    }
                }
            }
            _ => {}
        }
    }
    fn signed(kind: DirectRequestKind, mut body: Value) -> (Value, Vec<u8>) {
        let device = SigningKey::from_bytes(&[7; 32]);
        let authority = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let is_receipt = matches!(
            kind,
            DirectRequestKind::Outcome | DirectRequestKind::AcceptanceCommit
        );
        let public = if is_receipt {
            authority
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        } else {
            device.verifying_key().as_bytes().to_vec()
        };
        body["keyId"] = json!(if is_receipt {
            direct_request_receipt_key_id(&public).unwrap()
        } else {
            URL_SAFE_NO_PAD.encode(Sha256::digest(&public))
        });
        let bytes =
            direct_request_signing_bytes(kind, &serde_json::to_vec(&body).unwrap()).unwrap();
        let signature = if is_receipt {
            let signature: p256::ecdsa::Signature = authority.sign(&bytes);
            STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes())
        } else {
            STANDARD.encode(device.sign(&bytes).to_bytes())
        };
        (json!({"body":body,"signature":signature}), public)
    }
    #[test]
    fn all_operations_read_bytes_keep_golden_transcripts_signatures_and_provenance() {
        for row in vectors()["signed"].as_array().unwrap() {
            let kind = *DirectRequestKind::ALL
                .iter()
                .find(|k| row["kind"] == format!("{k:?}"))
                .unwrap();
            let mut read_body = row["body"].clone();
            present(read_definition(kind.body_name()).unwrap(), &mut read_body);
            let normalized = normalize_read_presentation(
                &serde_json::to_vec(&read_body).unwrap(),
                kind.body_name(),
                true,
            )
            .unwrap();
            assert_eq!(normalized, row["body"]);
            let transcript =
                direct_request_signing_bytes(kind, &serde_json::to_vec(&normalized).unwrap())
                    .unwrap();
            assert_eq!(hex::encode(&transcript), row["transcriptHex"]);
            assert_eq!(hex::encode(Sha256::digest(&transcript)), row["digestHex"]);
            let (bare, key) = signed(kind, row["body"].clone());
            let strict =
                verify_signed_request(kind, &serde_json::to_vec(&bare).unwrap(), &key).unwrap();
            let mut received = bare.clone();
            present(read_definition(kind.wrapper_name()).unwrap(), &mut received);
            let raw = serde_json::to_vec(&received).unwrap();
            assert!(
                verify_signed_request(kind, &raw, &key).is_err(),
                "mutation boundary must remain bare"
            );
            let verified = verify_received_signed_request(kind, &raw, &key).unwrap();
            assert_eq!(verified.body(), strict.body());
            assert_eq!(verified.transcript_bytes(), strict.transcript_bytes());
            assert_eq!(verified.signature(), strict.signature());
            assert_eq!(verified.request_digest(), strict.request_digest());
            assert_eq!(verified.accepted_wrapper_bytes(), raw);
            if kind == DirectRequestKind::Outcome {
                received["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
                verify_received_signed_request(kind, &serde_json::to_vec(&received).unwrap(), &key)
                    .unwrap();
            }
        }
    }
    #[test]
    fn read_bytes_reject_ambiguity_tags_unknowns_arrays_and_malformed_objects() {
        let kind = DirectRequestKind::Publish;
        let (mut value, key) = signed(kind, body(kind));
        present(read_definition(kind.wrapper_name()).unwrap(), &mut value);
        for malformed in [
            json!({"$bytes":1}),
            json!({"$bytes":"AA==","extra":true}),
            json!({"$bytes":"AB=="}),
            json!({"$bytes":"AA"}),
            json!({"$bytes":null}),
            json!([0, 1]),
            json!({"bytes":"AA=="}),
        ] {
            let mut altered = value.clone();
            altered["signature"] = malformed;
            assert!(verify_received_signed_request(
                kind,
                &serde_json::to_vec(&altered).unwrap(),
                &key
            )
            .is_err());
        }
        let raw = serde_json::to_string(&value).unwrap();
        let duplicate = raw.replacen("\"$bytes\":", "\"$bytes\":\"AA==\",\"$bytes\":", 1);
        assert!(verify_received_signed_request(kind, duplicate.as_bytes(), &key).is_err());
        for field in ["unknown", "$type"] {
            let mut altered = value.clone();
            altered["body"]["artifacts"][field] = json!({"$bytes":"AA=="});
            assert!(verify_received_signed_request(
                kind,
                &serde_json::to_vec(&altered).unwrap(),
                &key
            )
            .is_err());
        }
        let mut altered = value.clone();
        altered["body"]["origin"]["$type"] =
            json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
        assert!(
            verify_received_signed_request(kind, &serde_json::to_vec(&altered).unwrap(), &key)
                .is_err()
        );
        let text = json!({"text":"YWJjZA=="});
        assert_eq!(
            normalize_read_presentation(
                &serde_json::to_vec(&text).unwrap(),
                "directRequestIntroduction",
                false
            )
            .unwrap(),
            text
        );
        assert!(normalize_read_presentation(
            br#"{"text":{"$bytes":"YWJjZA=="}}"#,
            "directRequestIntroduction",
            false
        )
        .is_err());
    }
    #[test]
    fn nested_mixed_acceptance_proof_normalizes_before_digest_and_coordinate_comparison() {
        let mut consent = body(DirectRequestKind::Accept);
        consent["next"]["stateVersion"] =
            json!(consent["prior"]["stateVersion"].as_u64().unwrap() + 1);
        let (acceptance, recipient) = signed(DirectRequestKind::Accept, consent);
        let checked = verify_signed_request(
            DirectRequestKind::Accept,
            &serde_json::to_vec(&acceptance).unwrap(),
            &recipient,
        )
        .unwrap();
        let entry = json!({"entryId":"12345678-1234-4234-8234-123456789abc","conversationId":checked.body()["prior"]["conversationId"],"seq":1,"signedRequest":acceptance,"receivedAt":"2026-09-19T12:00:00.000Z"});
        let mut receipt = body(DirectRequestKind::AcceptanceCommit);
        for field in ["requestId", "prior", "next"] {
            receipt[field] = checked.body()[field].clone();
        }
        receipt["acceptanceDigest"] = json!(STANDARD.encode(checked.request_digest()));
        receipt["entryHash"] = json!(STANDARD.encode(
            direct_request_acceptance_entry_hash(&serde_json::to_vec(&entry).unwrap()).unwrap()
        ));
        let (receipt, authority) = signed(DirectRequestKind::AcceptanceCommit, receipt);
        let bare = json!({"entry":entry,"receipt":receipt});
        let expected = verify_direct_request_acceptance_proof(
            &serde_json::to_vec(&bare).unwrap(),
            &authority,
            &recipient,
        )
        .unwrap();
        let mut read = bare.clone();
        present(
            read_definition("directRequestAcceptanceProof").unwrap(),
            &mut read,
        );
        read["entry"]["signedRequest"]["signature"] =
            bare["entry"]["signedRequest"]["signature"].clone();
        read["receipt"]["body"]["next"]["groupId"] =
            bare["receipt"]["body"]["next"]["groupId"].clone();
        assert!(verify_direct_request_acceptance_proof(
            &serde_json::to_vec(&read).unwrap(),
            &authority,
            &recipient
        )
        .is_err());
        assert_eq!(
            verify_received_direct_request_acceptance_proof(
                &serde_json::to_vec(&read).unwrap(),
                &authority,
                &recipient
            )
            .unwrap(),
            expected
        );
    }
}
