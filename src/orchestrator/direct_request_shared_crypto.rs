//! Provider-independent request crypto and receipt checks shared by native and WASM.
//! Callers own the encrypted transaction and must not expose/cache state until commit.
use super::direct_request_bootstrap::{
    self as bootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
};
use super::direct_request_journal::{DirectRequestJournal, DirectRequestJournalPhase};
use super::direct_request_keys::{DirectRequestKeyPublication, DirectRequestKeyPublicationInput};
use crate::{
    chat_v2::transcript::direct_request::{
        self as transcript, verify_received_signed_request as verify_signed_request,
        DirectRequestKind,
    },
    MLSError,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, OpenMlsProvider};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};
fn error(_: impl std::fmt::Debug) -> MLSError {
    MLSError::StorageFailed
}
fn invalid(reason: &str) -> MLSError {
    MLSError::invalid_input(reason)
}
fn crypto_error(value: impl std::fmt::Debug) -> MLSError {
    MLSError::OpenMLS(format!("direct request bootstrap: {value:?}"))
}

impl DirectRequestJournal {
    pub fn verify_terminal_receipt(
        &self,
        receipt: &[u8],
        authority_key: &[u8],
        published: bool,
    ) -> Result<(), MLSError> {
        let record = self;
        let id = self.request_id.as_str();
        let verified = verify_signed_request(DirectRequestKind::Outcome, receipt, authority_key)
            .map_err(error)?;
        let proof = &verified.body()["receipt"];
        let digest = proof["requestDigest"]
            .as_str()
            .or_else(|| proof["requestDigest"]["$bytes"].as_str())
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or(MLSError::StorageFailed)?;
        let preparation_digest = proof["preparationRequestDigest"]
            .as_str()
            .or_else(|| proof["preparationRequestDigest"]["$bytes"].as_str())
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or(MLSError::StorageFailed)?;
        if proof["requestId"] != id
            || preparation_digest != record.preparation_request_digest
            || (published
                && (proof["requestKind"] != "publish"
                    || Some(digest.as_slice())
                        != record.publication_digest.as_ref().map(|v| v.as_slice())))
        {
            return Err(MLSError::invalid_input(
                "Receipt does not fence exact request attempt",
            ));
        }
        let (ctx, _) = bootstrap::context(&record.bootstrap.context_json)?;
        for field in ["actorDid", "actorDeviceId", "actorKeyId"] {
            if proof[field] != ctx[field] {
                return Err(MLSError::invalid_input(
                    "Receipt actor differs from prepared request",
                ));
            }
        }
        let kind = proof["$type"].as_str().ok_or(MLSError::StorageFailed)?;
        if published {
            if kind != "blue.catbird.chat.defs#directRequestPublishedReceipt"
                || proof["coordinates"] != record.bootstrap.coordinates
                || proof["conversationId"] != record.conversation_id
                || proof["firstMessageId"] != record.first_message_id
            {
                return Err(MLSError::invalid_input(
                    "Published receipt coordinate mismatch",
                ));
            }
        } else if ![
            "blue.catbird.chat.defs#directRequestCancelledReceipt",
            "blue.catbird.chat.defs#directRequestExpiredReceipt",
            "blue.catbird.chat.defs#directRequestRejectedReceipt",
            "blue.catbird.chat.defs#directRequestExistingDirectReceipt",
        ]
        .contains(&kind)
        {
            return Err(MLSError::invalid_input(
                "Receipt is not terminal nonpublication",
            ));
        }
        Ok(())
    }
}

pub fn validate_request_welcome_receipt(input: &DirectRequestWelcomeInput) -> Result<(), MLSError> {
    let (ctx, _) = bootstrap::context(&input.bootstrap.context_json)?;
    let request_id = ctx["requestId"].as_str().ok_or(MLSError::StorageFailed)?;
    let record = DirectRequestJournal {
        request_id: request_id.into(),
        draft_id: request_id.into(),
        actor_did: ctx["actorDid"].as_str().unwrap().into(),
        actor_device_id: ctx["actorDeviceId"].as_str().unwrap().into(),
        first_message_id: ctx["firstMessageId"].as_str().unwrap().into(),
        conversation_id: ctx["conversationId"].as_str().unwrap().into(),
        input_sha256: [0; 32],
        preparation_request_digest: input.preparation_request_digest,
        receipt_authority_key: input.receipt_authority_key.clone(),
        bootstrap: input.bootstrap.clone(),
        phase: DirectRequestJournalPhase::PreparedCrypto,
        publish_request: None,
        publish_request_sha256: None,
        publication_digest: None,
        terminal_receipt: None,
        terminal_authority_key: None,
    };
    let digest = record.verify_publication(
        &input.publication_request,
        &input.actor_signature_public_key,
    )?;
    let verified = verify_signed_request(
        DirectRequestKind::Outcome,
        &input.published_receipt,
        &input.receipt_authority_key,
    )
    .map_err(crypto_error)?;
    let receipt = &verified.body()["receipt"];
    if receipt["$type"] != "blue.catbird.chat.defs#directRequestPublishedReceipt"
        || receipt["requestId"] != request_id
        || receipt["requestKind"] != "publish"
        || receipt["coordinates"] != input.bootstrap.coordinates
        || receipt["conversationId"] != record.conversation_id
        || receipt["firstMessageId"] != record.first_message_id
        || receipt["requestDigest"].as_str() != Some(STANDARD.encode(digest).as_str())
        || receipt["preparationRequestDigest"].as_str()
            != Some(STANDARD.encode(input.preparation_request_digest).as_str())
    {
        return Err(invalid("Request Welcome publication receipt mismatch"));
    }
    for field in ["actorDid", "actorDeviceId", "actorKeyId"] {
        if receipt[field] != ctx[field] {
            return Err(invalid("Request Welcome receipt actor mismatch"));
        }
    }
    Ok(())
}

pub fn decrypt_introduction_with_provider<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    input: &DirectRequestWelcomeInput,
) -> Result<DirectRequestIntroductionResult, MLSError> {
    let (ctx, hash) = bootstrap::context(&input.bootstrap.context_json)?;
    if hash != input.bootstrap.context_hash {
        return Err(invalid("Introduction context mismatch"));
    }
    let aad = crate::chat_v2::transcript::direct_request::direct_request_application_aad(
        &hash,
        &serde_json::to_vec(&input.bootstrap.coordinates).map_err(error)?,
        ctx["firstMessageId"].as_str().unwrap(),
    )
    .map_err(crypto_error)?;
    let expected_sender = format!(
        "{}#{}",
        ctx["actorDid"].as_str().unwrap(),
        ctx["actorDeviceId"].as_str().unwrap()
    );
    let mut process = || -> Result<Vec<u8>, MLSError> {
        let protocol = MlsMessageIn::tls_deserialize_exact(&input.bootstrap.initial_ciphertext)
            .map_err(crypto_error)?
            .try_into_protocol_message()
            .map_err(crypto_error)?;
        if protocol.content_type() != ContentType::Application {
            return Err(invalid("Introduction must be an application ciphertext"));
        }
        let processed = group
            .process_message(provider, protocol)
            .map_err(|e| match e {
                ProcessMessageError::StorageError(_)
                | ProcessMessageError::GroupStateError(_)
                | ProcessMessageError::LibraryError(_) => MLSError::StorageFailed,
                other => crypto_error(other),
            })?;
        if processed.aad() != aad
            || processed.credential().serialized_content() != expected_sender.as_bytes()
        {
            return Err(invalid("Introduction sender or AAD mismatch"));
        }
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(invalid("Introduction is not an application message"));
        };
        let plaintext = application.into_bytes();
        let value = crate::chat_v2::transcript::direct_request::decode_direct_request_introduction(
            &plaintext,
        )
        .map_err(crypto_error)?;
        if value
            .get("invitation")
            .is_some_and(|i| i["recipientDid"] != ctx["recipientDid"])
        {
            return Err(invalid("Introduction invitation recipient mismatch"));
        }
        Ok(plaintext)
    };
    // This classified result is persisted with the ratchet write. An invalid
    // intro never rolls back its successful Welcome import or implies consent.
    let outcome = match process() {
        Ok(plaintext) => DirectRequestIntroductionResult::Ready { plaintext },
        Err(MLSError::StorageFailed) => return Err(MLSError::StorageFailed),
        Err(_) => DirectRequestIntroductionResult::Unavailable {
            code: "InvalidIntroduction".into(),
        },
    };
    Ok(outcome)
}

/// Generate one exact signed publication and its private bundles. The provider
/// must be inside the caller's transaction; storage failure must roll all back.
pub fn build_request_key_publication<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    input: &DirectRequestKeyPublicationInput,
    now: i64,
) -> Result<(Vec<u8>, Vec<(Vec<u8>, KeyPackageBundle)>), MLSError> {
    crate::chat_v2::ids::BareDid::parse(&input.actor_did).map_err(error)?;
    crate::chat_v2::ids::CanonicalUuid::parse(&input.actor_device_id).map_err(error)?;
    if input.count > 64
        || (!input.enabled && input.count != 0)
        || input.auth_generation < 1
        || input.revision < 1
        || now < 0
    {
        return Err(invalid("Invalid request key input"));
    }
    let identity = format!("{}#{}", input.actor_did, input.actor_device_id);

    let date = |value: i64| {
        chrono::DateTime::from_timestamp(value, 0)
            .ok_or_else(|| invalid("Invalid request key input"))
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    };
    let signed_at = date(now)?;
    let expiry = date(now + 28 * 86400)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
    let suite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[suite]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let sign = |kind, body: Value| -> Result<Value, MLSError> {
        let raw = serde_json::to_vec(&body).map_err(error)?;
        let message = transcript::direct_request_signing_bytes(kind, &raw).map_err(error)?;
        let signature = signer.sign(&message).map_err(error)?;
        Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
    };
    let mut entries = Vec::new();
    let mut bundles = Vec::new();
    for _ in 0..input.count {
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(
                now.saturating_sub(60) as u64,
                (now + 29 * 86400) as u64,
            ))
            .leaf_node_capabilities(capabilities.clone())
            .build(
                suite,
                provider,
                signer,
                CredentialWithKey {
                    credential: Credential::new(
                        CredentialType::Basic,
                        identity.as_bytes().to_vec(),
                    ),
                    signature_key: signer.public().into(),
                },
            )
            .map_err(error)?;
        let package = bundle.key_package();
        let encoded = MlsMessageOut::from(package.clone())
            .tls_serialize_detached()
            .map_err(error)?;
        let reference = package
            .hash_ref(provider.crypto())
            .map_err(error)?
            .as_slice()
            .to_vec();
        let hash = STANDARD.encode(Sha256::digest(&encoded));
        let grant_id = uuid::Uuid::new_v4().to_string();
        let grant = sign(
            DirectRequestKind::Grant,
            json!({"$type":"blue.catbird.chat.defs#directRequestGrantBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\u{0}","protocolVersion":"2","actorDid":input.actor_did,"actorDeviceId":input.actor_device_id,"keyId":key_id,"authGeneration":input.auth_generation,"grantId":grant_id,"grantRevision":input.revision,"purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1","keyPackageRef":STANDARD.encode(&reference),"keyPackageSha256":hash,"expiresAt":expiry,"idempotencyKey":grant_id,"signedAt":signed_at}),
        )?;
        entries.push(json!({"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":STANDARD.encode(encoded),"sha256":hash,"keyPackageRef":STANDARD.encode(&reference)},"grant":grant}));
        bundles.push((reference, bundle));
    }
    let signed = sign(
        DirectRequestKind::Keys,
        json!({"$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\u{0}","protocolVersion":"2","actorDid":input.actor_did,"actorDeviceId":input.actor_device_id,"keyId":key_id,"authGeneration":input.auth_generation,"revision":input.revision,"enabled":input.enabled,"keys":entries,"idempotencyKey":uuid::Uuid::new_v4().to_string(),"signedAt":signed_at}),
    )?;
    let record = DirectRequestKeyPublication {
        actor_did: input.actor_did.clone(),
        actor_device_id: input.actor_device_id.clone(),
        public_key: signer.public().to_vec(),
        exact_request: serde_json::to_vec(&json!({"signedRequest":signed})).map_err(error)?,
        acknowledged: false,
    };
    record.body()?;
    let raw = serde_json::to_vec(&record).map_err(error)?;
    if raw.len() > 16 * 1024 * 1024 {
        return Err(invalid("Invalid request key input"));
    }
    Ok((raw, bundles))
}
