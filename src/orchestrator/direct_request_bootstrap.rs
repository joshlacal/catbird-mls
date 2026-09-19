//! Isolated request bootstrap. No live-group mapping is created during preparation.
use crate::error::MLSError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openmls::prelude::*;
use openmls::treesync::LeafNodeSource;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

pub const MIN_IMPORT_HORIZON: u64 = 604800;
pub const IMPORT_CLOCK_MARGIN: u64 = 300;
pub const MAX_LEAVES: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestBootstrapInput {
    pub draft_id: String,
    /// Strict T01 context JSON, retained exactly; its canonical digest binds AAD.
    pub context_json: Vec<u8>,
    pub group_id: Vec<u8>,
    pub generation: u64,
    pub state_version: u64,
    pub key_packages: Vec<Vec<u8>>,
    pub expected_package_refs: Vec<Vec<u8>>,
    /// Minimum deadline from the validated grants in the immutable preparation.
    pub authority_import_until: u64,
    pub preparation_request_digest: [u8; 32],
    /// Independently pinned dedicated server receipt key (compressed P256 SEC1).
    pub receipt_authority_key: Vec<u8>,
    pub text: String,
    pub invitation: Option<super::direct_request_types::GroupInvitationReference>,
    pub metadata: crate::metadata::GroupMetadataV1,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestBootstrap {
    pub context_json: Vec<u8>,
    pub context_hash: [u8; 32],
    pub coordinates: Value,
    pub import_until: u64,
    pub expected_package_refs: Vec<Vec<u8>>,
    pub genesis_group_info: Vec<u8>,
    pub add_commit: Vec<u8>,
    pub final_group_info: Vec<u8>,
    pub welcome: Vec<u8>,
    pub metadata_nonce: Vec<u8>,
    pub metadata_ciphertext: Vec<u8>,
    pub initial_ciphertext: Vec<u8>,
}
fn invalid(reason: &str) -> MLSError {
    MLSError::invalid_input(reason)
}
fn crypto_error(error: impl std::fmt::Debug) -> MLSError {
    MLSError::OpenMLS(format!("direct request bootstrap: {error:?}"))
}

/// The final tree is authoritative: a creator leaf can change source during Add.
pub fn final_tree_import_until(group: &MlsGroup, authority_deadline: u64) -> Result<u64, MLSError> {
    if group.members().count() < 2 || group.members().count() > MAX_LEAVES {
        return Err(invalid("Invalid request tree size"));
    }
    Ok(group
        .export_ratchet_tree()
        .leaves()
        .filter_map(|leaf| match leaf.leaf_node_source() {
            LeafNodeSource::KeyPackage(lifetime) => Some(lifetime.not_after()),
            _ => None,
        })
        .fold(authority_deadline, u64::min))
}
pub fn require_import_horizon(import_until: u64, now: u64) -> Result<(), MLSError> {
    if now
        .checked_add(MIN_IMPORT_HORIZON + IMPORT_CLOCK_MARGIN)
        .is_none_or(|deadline| deadline > import_until)
    {
        return Err(invalid(
            "Request final tree does not satisfy import horizon",
        ));
    }
    Ok(())
}
/// Strict exact-set validation; never slice or rewrite an MLS Welcome.
pub fn validate_full_welcome(welcome: &Welcome, expected: &[Vec<u8>]) -> Result<(), MLSError> {
    use std::collections::BTreeSet;
    let expected_set: BTreeSet<_> = expected.iter().cloned().collect();
    let actual: BTreeSet<_> = welcome
        .secrets()
        .iter()
        .map(|s| s.new_member().as_slice().to_vec())
        .collect();
    if expected.is_empty()
        || expected.len() >= MAX_LEAVES
        || expected_set.len() != expected.len()
        || welcome.secrets().len() != expected.len()
        || actual.len() != welcome.secrets().len()
        || expected_set != actual
    {
        return Err(invalid(
            "Request Welcome does not cover the exact selected packages",
        ));
    }
    Ok(())
}
pub fn context(input: &[u8]) -> Result<(Value, [u8; 32]), MLSError> {
    let hash = crate::chat_v2::transcript::direct_request::direct_request_context_hash(input)
        .map_err(crypto_error)?;
    let value = serde_json::from_slice(input).map_err(crypto_error)?;
    Ok((value, hash))
}
/// Production AAD emitter: accepts only a canonical validated request binding,
/// derives the application AAD from the actual group, and clears it on failure.
pub fn encrypt_bound_introduction<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
    context_hash: &[u8; 32],
    coordinates: &Value,
    message_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, MLSError> {
    let expected = group_coordinates(
        group,
        provider,
        coordinates["conversationId"]
            .as_str()
            .ok_or_else(|| invalid("Missing conversation"))?,
        coordinates["generation"]
            .as_u64()
            .ok_or_else(|| invalid("Missing generation"))?,
        coordinates["stateVersion"]
            .as_u64()
            .ok_or_else(|| invalid("Missing state version"))?,
    )?;
    if expected != *coordinates
        || plaintext.is_empty()
        || plaintext.len()
            > crate::chat_v2::transcript::direct_request::MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES
    {
        return Err(invalid("Invalid request application binding"));
    }
    let aad = crate::chat_v2::transcript::direct_request::direct_request_application_aad(
        context_hash,
        &serde_json::to_vec(coordinates).map_err(crypto_error)?,
        message_id,
    )
    .map_err(crypto_error)?;
    group.set_aad(aad);
    let result = group
        .create_message(provider, signer, plaintext)
        .map_err(crypto_error)
        .and_then(|m| m.tls_serialize_detached().map_err(crypto_error));
    group.set_aad(Vec::new());
    result.and_then(|bytes| {
        if bytes.len()
            > crate::chat_v2::transcript::direct_request::MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES
        {
            Err(invalid("Initial ciphertext exceeds request resource bound"))
        } else {
            Ok(bytes)
        }
    })
}
pub fn group_coordinates<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    conversation_id: &str,
    generation: u64,
    state_version: u64,
) -> Result<Value, MLSError> {
    let context: GroupContext = provider
        .storage()
        .group_context(group.group_id())
        .map_err(crypto_error)?
        .ok_or(MLSError::StorageFailed)?;
    let context = context.tls_serialize_detached().map_err(crypto_error)?;
    let tag = group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(crypto_error)?;
    let tag = if tag.len() == 33 && tag[0] == 32 {
        &tag[1..]
    } else {
        &tag
    };
    Ok(
        serde_json::json!({"conversationId":conversation_id,"groupId":STANDARD.encode(group.group_id().as_slice()),"generation":generation,"stateVersion":state_version,"epoch":group.epoch().as_u64(),"lifecycle":"active","groupContextHash":STANDARD.encode(Sha256::digest(context)),"confirmationTag":STANDARD.encode(tag)}),
    )
}

pub fn prepare_with_provider<P: OpenMlsProvider>(
    provider: &P,
    signer: &SignatureKeyPair,
    input: &DirectRequestBootstrapInput,
    now: u64,
) -> Result<(MlsGroup, DirectRequestBootstrap), MLSError> {
    let (ctx, context_hash) = context(&input.context_json)?;
    if uuid::Uuid::parse_str(&input.draft_id).is_err()
        || input.group_id.len() != 32
        || input.key_packages.is_empty()
        || input.key_packages.len() >= MAX_LEAVES
        || input.key_packages.len() != input.expected_package_refs.len()
    {
        return Err(invalid("Invalid request bootstrap input"));
    }
    if ctx["actorDid"] == ctx["recipientDid"]
        || ctx["actorKeyId"].as_str()
            != Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(signer.public()))
                    .as_str(),
            )
    {
        return Err(invalid("Request actor signer mismatch"));
    }
    let identity = format!(
        "{}#{}",
        ctx["actorDid"].as_str().unwrap(),
        ctx["actorDeviceId"].as_str().unwrap()
    );
    let mut packages = Vec::new();
    for (bytes, expected) in input.key_packages.iter().zip(&input.expected_package_refs) {
        let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(crypto_error)?
            .extract()
        else {
            return Err(invalid("Expected MLS KeyPackage"));
        };
        let kp = kp
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(crypto_error)?;
        if kp.last_resort()
            || kp.ciphersuite() != Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            || kp
                .hash_ref(provider.crypto())
                .map_err(crypto_error)?
                .as_slice()
                != expected
        {
            return Err(invalid("Selected request package mismatch"));
        }
        let credential = std::str::from_utf8(kp.leaf_node().credential().serialized_content())
            .map_err(crypto_error)?;
        let (did, device) = credential
            .split_once('#')
            .ok_or_else(|| invalid("Unscoped request package"))?;
        if (did != ctx["actorDid"].as_str().unwrap()
            && did != ctx["recipientDid"].as_str().unwrap())
            || uuid::Uuid::parse_str(device).is_err()
            || credential == identity
        {
            return Err(invalid("Request package outside prepared account pair"));
        }
        packages.push(kp);
    }
    if !packages.iter().any(|kp| {
        std::str::from_utf8(kp.leaf_node().credential().serialized_content()).is_ok_and(
            |identity| identity.starts_with(&format!("{}#", ctx["recipientDid"].as_str().unwrap())),
        )
    }) {
        return Err(invalid("Request has no recipient device"));
    }
    let capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
        .capabilities(capabilities)
        .lifetime(Lifetime::init(now.saturating_sub(60), now + 29 * 86400))
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group = MlsGroup::new_with_group_id(
        provider,
        signer,
        &config,
        GroupId::from_slice(&input.group_id),
        CredentialWithKey {
            credential: BasicCredential::new(identity.into_bytes()).into(),
            signature_key: signer.to_public_vec().into(),
        },
    )
    .map_err(crypto_error)?;
    let genesis_group_info = group
        .export_group_info(provider.crypto(), signer, true)
        .map_err(crypto_error)?
        .tls_serialize_detached()
        .map_err(crypto_error)?;
    group.set_aad(
        crate::chat_v2::transcript::direct_request::direct_request_commit_aad(&context_hash)
            .map_err(crypto_error)?,
    );
    let (commit, welcome, _) = group
        .add_members(provider, signer, &packages)
        .map_err(crypto_error)?;
    let welcome = welcome.tls_serialize_detached().map_err(crypto_error)?;
    let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&welcome)
        .map_err(crypto_error)?
        .extract()
    else {
        return Err(invalid("Expected Welcome"));
    };
    validate_full_welcome(&w, &input.expected_package_refs)?;
    group.merge_pending_commit(provider).map_err(crypto_error)?;
    group.set_aad(Vec::new());
    let import_until = final_tree_import_until(&group, input.authority_import_until)?;
    require_import_horizon(import_until, now)?;
    let coordinates = group_coordinates(
        &group,
        provider,
        ctx["conversationId"].as_str().unwrap(),
        input.generation,
        input.state_version,
    )?;
    let final_group_info = group
        .export_group_info(provider.crypto(), signer, true)
        .map_err(crypto_error)?
        .tls_serialize_detached()
        .map_err(crypto_error)?;
    let initial_ciphertext = encrypt_bound_introduction(
        &mut group,
        provider,
        signer,
        &context_hash,
        &coordinates,
        ctx["firstMessageId"].as_str().unwrap(),
        &introduction_plaintext(input)?,
    )?;
    let metadata_nonce: [u8; 12] = rand::random();
    let metadata_ciphertext = encrypt_request_metadata(
        &group,
        provider,
        signer,
        &ctx,
        &coordinates,
        &input.metadata,
        &metadata_nonce,
    )?;
    let bundle = DirectRequestBootstrap {
        context_json: input.context_json.clone(),
        context_hash,
        coordinates,
        import_until,
        expected_package_refs: input.expected_package_refs.clone(),
        genesis_group_info,
        add_commit: commit.tls_serialize_detached().map_err(crypto_error)?,
        final_group_info,
        welcome,
        metadata_nonce: metadata_nonce.to_vec(),
        metadata_ciphertext,
        initial_ciphertext,
    };
    if bundle.decoded_size() > 8388608
        || bundle.initial_ciphertext.len()
            > crate::chat_v2::transcript::direct_request::MAX_INITIAL_APPLICATION_CIPHERTEXT_BYTES
    {
        return Err(invalid("Request artifact size exceeds contract"));
    }
    Ok((group, bundle))
}
impl DirectRequestBootstrap {
    pub fn decoded_size(&self) -> usize {
        self.genesis_group_info.len()
            + self.add_commit.len()
            + self.final_group_info.len()
            + self.welcome.len()
            + self.metadata_ciphertext.len()
            + self.metadata_nonce.len()
            + self.initial_ciphertext.len()
    }
}

/// Request-only multi-secret importer. Caller must wrap this operation and its
/// accepted provenance record in one durable transaction; recovery is unchanged.
pub fn import_with_provider<P: OpenMlsProvider>(
    provider: &P,
    bootstrap: &DirectRequestBootstrap,
    local_identity: &[u8],
    local_package_ref: &[u8],
    now: u64,
) -> Result<MlsGroup, MLSError> {
    let (_, hash) = context(&bootstrap.context_json)?;
    if hash != bootstrap.context_hash {
        return Err(invalid("Request Welcome binding mismatched"));
    }
    if now >= bootstrap.import_until {
        return Err(MLSError::RequestImportExpired);
    }
    let MlsMessageBodyIn::Welcome(welcome) =
        MlsMessageIn::tls_deserialize_exact(&bootstrap.welcome)
            .map_err(crypto_error)?
            .extract()
    else {
        return Err(invalid("Expected request Welcome"));
    };
    validate_full_welcome(&welcome, &bootstrap.expected_package_refs)?;
    let mut local_matches = Vec::new();
    for secret in welcome.secrets() {
        let bundle: Option<KeyPackageBundle> = provider
            .storage()
            .key_package(&secret.new_member())
            .map_err(crypto_error)?;
        if let Some(bundle) = bundle {
            local_matches.push((secret.new_member().as_slice().to_vec(), bundle));
        }
    }
    if local_matches.len() != 1
        || local_matches[0].1.key_package().last_resort()
        || local_matches[0].0 != local_package_ref
        || local_matches[0]
            .1
            .key_package()
            .leaf_node()
            .credential()
            .serialized_content()
            != local_identity
        || bootstrap.import_until > local_matches[0].1.key_package().life_time().not_after()
    {
        return Err(invalid(
            "Request Welcome must match exactly one local authorized package",
        ));
    }
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let group = StagedWelcome::new_from_welcome(provider, &config, welcome, None)
        .map_err(crypto_error)?
        .into_group(provider)
        .map_err(crypto_error)?;
    let expected = group_coordinates(
        &group,
        provider,
        bootstrap.coordinates["conversationId"]
            .as_str()
            .ok_or_else(|| invalid("Missing conversation"))?,
        bootstrap.coordinates["generation"]
            .as_u64()
            .ok_or_else(|| invalid("Missing generation"))?,
        bootstrap.coordinates["stateVersion"]
            .as_u64()
            .ok_or_else(|| invalid("Missing version"))?,
    )?;
    if expected != bootstrap.coordinates
        || group
            .own_leaf_node()
            .is_none_or(|leaf| leaf.credential().serialized_content() != local_identity)
        || final_tree_import_until(&group, bootstrap.import_until)? != bootstrap.import_until
    {
        return Err(invalid("Request Welcome final tree or coordinate mismatch"));
    }
    Ok(group)
}

fn metadata_cbor(schema: &str, value: &Value) -> Result<Vec<u8>, MLSError> {
    use crate::chat_v2::transcript::{decode_strict_json, project_ref};
    let strict = decode_strict_json(&serde_json::to_vec(value).map_err(crypto_error)?)
        .map_err(crypto_error)?;
    serde_ipld_dagcbor::to_vec(&project_ref(schema, &strict, false).map_err(crypto_error)?)
        .map_err(crypto_error)
}
pub fn metadata_coordinate(coordinates: &Value) -> Result<Value, MLSError> {
    let mut coordinate = coordinates.clone();
    let map = coordinate
        .as_object_mut()
        .ok_or_else(|| invalid("Invalid metadata coordinate"))?;
    map.remove("stateVersion");
    map.remove("lifecycle");
    let uuid = uuid::Uuid::parse_str(
        coordinates["conversationId"]
            .as_str()
            .ok_or_else(|| invalid("Missing conversation"))?,
    )
    .map_err(crypto_error)?;
    map.insert(
        "conversationId".into(),
        Value::String(STANDARD.encode(uuid.as_bytes())),
    );
    Ok(coordinate)
}
pub fn request_metadata_key<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    coordinates: &Value,
) -> Result<[u8; 32], MLSError> {
    let coordinate = metadata_coordinate(coordinates)?;
    let exporter = serde_json::json!({"protocol":"blue.catbird.chat.metadata","version":1,"conversationId":coordinate["conversationId"],"generation":coordinate["generation"],"epoch":coordinate["epoch"],"groupContextHash":coordinate["groupContextHash"],"metadataVersion":1});
    group
        .export_secret(
            provider.crypto(),
            "blue.catbird.chat.metadata.v1",
            &metadata_cbor("metadataExporterContext", &exporter)?,
            32,
        )
        .map_err(crypto_error)?
        .try_into()
        .map_err(|_| invalid("Invalid metadata key"))
}
pub fn request_metadata_aad(
    coordinates: &Value,
    request_id: &str,
    ciphertext_size: usize,
) -> Result<Vec<u8>, MLSError> {
    let origin = uuid::Uuid::parse_str(request_id).map_err(crypto_error)?;
    let value = serde_json::json!({"protocol":"blue.catbird.chat.metadata","version":1,"coordinate":metadata_coordinate(coordinates)?,"metadataVersion":1,"originTransitionId":STANDARD.encode(origin.as_bytes()),"ciphertextSize":ciphertext_size});
    let mut aad = b"CATBIRD-CHAT-METADATA\0".to_vec();
    aad.extend(metadata_cbor("metadataAad", &value)?);
    Ok(aad)
}
pub fn encrypt_request_metadata<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
    ctx: &Value,
    coordinates: &Value,
    metadata: &crate::metadata::GroupMetadataV1,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, MLSError> {
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes256Gcm, KeyInit,
    };
    use openmls_traits::signatures::Signer;
    if metadata.avatar_blob_locator.is_some() || metadata.avatar_content_type.is_some() {
        return Err(invalid("Request bootstrap has no avatar binding"));
    }
    let request_id = ctx["requestId"]
        .as_str()
        .ok_or_else(|| invalid("Missing request"))?;
    let origin = uuid::Uuid::parse_str(request_id).map_err(crypto_error)?;
    let device =
        uuid::Uuid::parse_str(ctx["actorDeviceId"].as_str().unwrap()).map_err(crypto_error)?;
    let mut content = serde_json::json!({"protocol":"blue.catbird.chat.metadata","version":1,"originTransitionId":STANDARD.encode(origin.as_bytes()),"metadataVersion":1,"authorDid":ctx["actorDid"],"authorDeviceId":STANDARD.encode(device.as_bytes()),"authorKeyId":ctx["actorKeyId"],"title":metadata.title});
    if !metadata.description.is_empty() {
        content["description"] = Value::String(metadata.description.clone());
    }
    let mut signing = b"CATBIRD-CHAT-METADATA-CONTENT\0".to_vec();
    signing.extend(metadata_cbor("metadataContentProjection", &content)?);
    let signed = serde_json::json!({"content":content,"contentSignature":STANDARD.encode(signer.sign(&signing).map_err(crypto_error)?)});
    let plaintext = metadata_cbor("metadataPlaintext", &signed)?;
    let aad = request_metadata_aad(coordinates, request_id, plaintext.len() + 16)?;
    let key = request_metadata_key(group, provider, coordinates)?;
    Aes256Gcm::new_from_slice(&key)
        .map_err(crypto_error)?
        .encrypt(
            nonce.into(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(crypto_error)
}

pub fn introduction_plaintext(input: &DirectRequestBootstrapInput) -> Result<Vec<u8>, MLSError> {
    if input.text.is_empty() || input.text.len() > 16384 {
        return Err(invalid("Introduction text exceeds limit"));
    }
    let (ctx, _) = context(&input.context_json)?;
    if input
        .invitation
        .as_ref()
        .is_some_and(|i| ctx["recipientDid"] != i.recipient_did)
    {
        return Err(invalid("Invitation recipient mismatch"));
    }
    let mut value = serde_json::json!({"text":input.text});
    if let Some(invitation) = &input.invitation {
        value["invitation"] = serde_json::to_value(invitation).map_err(crypto_error)?;
    }
    let bytes = serde_json::to_vec(&value).map_err(crypto_error)?;
    crate::chat_v2::transcript::direct_request::encode_direct_request_introduction(&bytes)
        .map_err(crypto_error)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectRequestWelcomeInput {
    pub bootstrap: DirectRequestBootstrap,
    pub local_identity: Vec<u8>,
    pub local_package_ref: Vec<u8>,
    pub publication_request: Vec<u8>,
    pub actor_signature_public_key: Vec<u8>,
    pub published_receipt: Vec<u8>,
    /// Resolved independently through the trusted service DID by the caller.
    pub receipt_authority_key: Vec<u8>,
    pub preparation_request_digest: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn adopt_request_welcome(
    inner: &mut crate::mls_context::MLSContext,
    input: &DirectRequestWelcomeInput,
) -> Result<crate::types::WelcomeResult, MLSError> {
    use super::direct_request_journal::{
        native::{error, Provider},
        DirectRequestJournal, DirectRequestJournalPhase,
    };
    use crate::chat_v2::transcript::direct_request::{verify_signed_request, DirectRequestKind};
    use rusqlite::OptionalExtension;
    let (ctx, _) = context(&input.bootstrap.context_json)?;
    let request_id = ctx["requestId"].as_str().unwrap();
    let local = std::str::from_utf8(&input.local_identity).map_err(crypto_error)?;
    let signer = inner
        .get_signer_for_identity(local)
        .ok_or(MLSError::StorageFailed)?;
    super::direct_request_shared_crypto::validate_request_welcome_receipt(input)?;
    let group_id = STANDARD
        .decode(
            input.bootstrap.coordinates["groupId"]
                .as_str()
                .ok_or(MLSError::StorageFailed)?,
        )
        .map_err(crypto_error)?;
    let key = format!(
        "direct_request_import_v2:{request_id}:{}",
        hex::encode(&input.local_package_ref)
    );
    let input_bytes = serde_json::to_vec(input).map_err(error)?;
    let input_digest = hex::encode(Sha256::digest(&input_bytes));
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key=?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    if let Some(old) = old {
        if old != input_digest || !inner.groups.contains_key(&group_id) {
            return Err(MLSError::StorageFailed);
        }
        return Ok(crate::types::WelcomeResult { group_id });
    }
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    if MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
        .map_err(error)?
        .is_some()
    {
        return Err(invalid("Request Welcome cannot replace an existing group"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    let group = import_with_provider(
        &provider,
        &input.bootstrap,
        &input.local_identity,
        &input.local_package_ref,
        now,
    )?;
    if group
        .own_leaf_node()
        .is_none_or(|leaf| leaf.signature_key().as_slice() != signer.public())
    {
        return Err(invalid("Request Welcome local signer mismatch"));
    }
    let raw: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key='group_ids'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    let mut ids: Vec<String> = raw
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(error)?
        .unwrap_or_default();
    let hex_id = hex::encode(&group_id);
    if !ids.contains(&hex_id) {
        ids.push(hex_id);
    }
    tx.execute(
        "INSERT OR REPLACE INTO mls_manifests(key,value) VALUES('group_ids',?1)",
        [serde_json::to_string(&ids).map_err(error)?],
    )
    .map_err(error)?;
    tx.execute(
        "INSERT INTO mls_manifests(key,value) VALUES(?1,?2)",
        [key, input_digest],
    )
    .map_err(error)?;
    // Retain complete authenticated provenance separately, encrypted at rest.
    tx.execute(
        "INSERT INTO mls_manifests(key,value) VALUES(?1,?2)",
        rusqlite::params![
            format!(
                "direct_request_import_proof_v2:{request_id}:{}",
                hex::encode(&input.local_package_ref)
            ),
            input_bytes
        ],
    )
    .map_err(error)?;
    tx.execute(
        "DELETE FROM mls_key_package_bundles WHERE hash_ref=?1",
        [hex::encode(&input.local_package_ref)],
    )
    .map_err(error)?;
    tx.commit().map_err(error)?;
    inner.publish_welcome_group(group, signer.public().to_vec());
    inner.key_package_bundles.remove(&input.local_package_ref);
    inner.manifest_storage.flush_database()?;
    Ok(crate::types::WelcomeResult { group_id })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DirectRequestIntroductionResult {
    Ready { plaintext: Vec<u8> },
    Unavailable { code: String },
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn decrypt_introduction(
    inner: &mut crate::mls_context::MLSContext,
    input: &DirectRequestWelcomeInput,
) -> Result<DirectRequestIntroductionResult, MLSError> {
    use super::direct_request_journal::native::{error, Provider};
    use rusqlite::OptionalExtension;
    let (ctx, hash) = context(&input.bootstrap.context_json)?;
    if hash != input.bootstrap.context_hash {
        return Err(invalid("Introduction context mismatch"));
    }
    let request_id = ctx["requestId"].as_str().unwrap();
    let import_key = format!(
        "direct_request_import_v2:{request_id}:{}",
        hex::encode(&input.local_package_ref)
    );
    let cache_key = format!(
        "direct_request_plaintext_v2:{request_id}:{}",
        hex::encode(Sha256::digest(&input.bootstrap.initial_ciphertext))
    );
    let input_digest = hex::encode(Sha256::digest(serde_json::to_vec(input).map_err(error)?));
    let tx = inner
        .manifest_storage
        .welcome_ack_connection()
        .unchecked_transaction()
        .map_err(error)?;
    let proof: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key=?1",
            [&import_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    if proof.as_deref() != Some(&input_digest) {
        return Err(invalid(
            "Introduction requires its exact accepted Welcome provenance",
        ));
    }
    let old: Option<String> = tx
        .query_row(
            "SELECT value FROM mls_manifests WHERE key=?1",
            [&cache_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    if let Some(old) = old {
        return serde_json::from_str(&old).map_err(error);
    }
    let group_id = STANDARD
        .decode(
            input.bootstrap.coordinates["groupId"]
                .as_str()
                .ok_or(MLSError::StorageFailed)?,
        )
        .map_err(error)?;
    let provider = Provider {
        storage: openmls_sqlite_storage::SqliteStorageProvider::new(&*tx),
        crypto: inner.provider.crypto(),
    };
    let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
        .map_err(error)?
        .ok_or(MLSError::StorageFailed)?;
    let signer_public = group
        .own_leaf_node()
        .ok_or(MLSError::StorageFailed)?
        .signature_key()
        .as_slice()
        .to_vec();
    let outcome=super::direct_request_shared_crypto::decrypt_introduction_with_provider(&provider,&mut group,input)?;
    tx.execute(
        "INSERT INTO mls_manifests(key,value) VALUES(?1,?2)",
        [cache_key, serde_json::to_string(&outcome).map_err(error)?],
    )
    .map_err(error)?;
    tx.commit().map_err(error)?;
    inner.publish_welcome_group(group, signer_public);
    inner.manifest_storage.flush_database()?;
    Ok(outcome)
}
