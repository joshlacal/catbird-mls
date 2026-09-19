//! Real pinned XWING/Libcrux feasibility corpus. Every device has an independent
//! encrypted SQLite provider, reopened across preparation/import boundaries.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::orchestrator::direct_request_bootstrap::*;
use openmls::prelude::*;
use openmls::treesync::LeafNodeSource;
use openmls_basic_credential::SignatureKeyPair;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};

#[derive(Default)]
struct Json;
impl Codec for Json {
    type Error = serde_json::Error;
    fn to_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(v)
    }
    fn from_slice<T: serde::de::DeserializeOwned>(v: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(v)
    }
}
struct Provider {
    storage: SqliteStorageProvider<Json, Connection>,
    crypto: openmls_libcrux_crypto::CryptoProvider,
}
impl OpenMlsProvider for Provider {
    type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
    type RandProvider = openmls_libcrux_crypto::CryptoProvider;
    type StorageProvider = SqliteStorageProvider<Json, Connection>;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
impl Provider {
    fn open(path: &std::path::Path) -> Self {
        let conn = Connection::open(path).unwrap();
        conn.pragma_update(None, "key", "feasibility-test-only-key")
            .unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "synchronous", "FULL").unwrap();
        let mut storage = SqliteStorageProvider::new(conn);
        storage.run_migrations().unwrap();
        Self {
            storage,
            crypto: openmls_libcrux_crypto::CryptoProvider::new().unwrap(),
        }
    }
}
const SUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[SUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}
fn corpus(count: usize) {
    corpus_variant(count, false);
}
fn corpus_variant(count: usize, legacy: bool) {
    let directory = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut signers = Vec::new();
    let mut credentials = Vec::new();
    let mut packages = Vec::new();
    for index in 0..count {
        let provider = Provider::open(&directory.path().join(format!("{index}.db")));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[index as u8 + 1; 32]);
        let signer = SignatureKeyPair::from_raw(
            SUITE.signature_algorithm(),
            signing.to_bytes().to_vec(),
            signing.verifying_key().to_bytes().to_vec(),
        );
        let account = if index % 2 == 0 {
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
        };
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                format!("{account}#00000000-0000-4000-8000-{index:012}").into_bytes(),
            )
            .into(),
            signature_key: signer.to_public_vec().into(),
        };
        if index > 0 {
            let package = KeyPackage::builder()
                .key_package_lifetime(Lifetime::init(
                    now - 60,
                    now + (if count == 3 && index == 2 {
                        3
                    } else {
                        11 + (index as u64 - 1) % 18
                    }) * 86400,
                ))
                .leaf_node_capabilities(capabilities())
                .build(SUITE, &provider, &signer, credential.clone())
                .unwrap();
            packages.push(package.key_package().clone());
        }
        credentials.push(credential);
        signers.push(signer);
    }
    let alice_path = directory.path().join("0.db");
    let provider = Provider::open(&alice_path);
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .capabilities(capabilities())
        .lifetime(Lifetime::init(now - 60, now + 29 * 86400))
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let prior = if legacy {
        let old = MlsGroup::new_with_group_id(
            &provider,
            &signers[0],
            &config,
            GroupId::from_slice(&[201; 32]),
            credentials[0].clone(),
        )
        .unwrap();
        let coordinate = group_coordinates(&old, &provider, &conversation_id, 0, 1).unwrap();
        let info = old
            .export_group_info(provider.crypto(), &signers[0], true)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        Some((coordinate, info))
    } else {
        None
    };
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signers[0],
        &config,
        GroupId::from_slice(&[count as u8; 32]),
        credentials[0].clone(),
    )
    .unwrap();
    let gid = group.group_id().clone();
    let genesis = group
        .export_group_info(provider.crypto(), &signers[0], true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    drop(group);
    drop(provider);
    let provider = Provider::open(&alice_path);
    let mut group = MlsGroup::load(provider.storage(), &gid).unwrap().unwrap();
    let context_json=serde_json::to_vec(&serde_json::json!({"protocolVersion":"2","requestId":uuid::Uuid::new_v4().to_string(),"firstMessageId":uuid::Uuid::new_v4().to_string(),"conversationId":conversation_id,"origin":if let Some((coordinate,_))=&prior {serde_json::json!({"$type":"blue.catbird.chat.defs#legacyPendingDirectOrigin","exactPrior":coordinate,"originalInvitationProvenance":{"invitationTransitionId":uuid::Uuid::new_v4().to_string(),"invitedByDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","invitedByDeviceId":"00000000-0000-4000-8000-000000000000"}})}else{serde_json::json!({"$type":"blue.catbird.chat.defs#freshDirectOrigin"})},"actorDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","actorDeviceId":"00000000-0000-4000-8000-000000000000","actorKeyId":URL_SAFE_NO_PAD.encode(Sha256::digest(signers[0].public())),"recipientDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","preparationDigest":STANDARD.encode([42;32])})).unwrap();
    let (ctx, context_hash) = context(&context_json).unwrap();
    group.set_aad(
        catbird_mls::chat_v2::transcript::direct_request::direct_request_commit_aad(&context_hash)
            .unwrap(),
    );
    let (commit, welcome, _) = group
        .add_members(&provider, &signers[0], &packages)
        .unwrap();
    assert_eq!(group.epoch().as_u64(), 0, "ordinary Add stays staged");
    let commit = commit.tls_serialize_detached().unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    drop(group);
    drop(provider);
    let provider = Provider::open(&alice_path);
    let mut group = MlsGroup::load(provider.storage(), &gid).unwrap().unwrap();
    group.merge_pending_commit(&provider).unwrap();
    assert_eq!(group.epoch().as_u64(), 1);
    assert_eq!(group.members().count(), count);
    let mut expiries = Vec::new();
    for leaf in group.export_ratchet_tree().leaves() {
        if let LeafNodeSource::KeyPackage(lifetime) = leaf.leaf_node_source() {
            expiries.push(lifetime.not_after());
        }
    }
    let expected_deadline = now + if count == 3 { 3 * 86400 } else { 11 * 86400 };
    assert_eq!(expiries.iter().min().copied(), Some(expected_deadline));
    assert_eq!(
        final_tree_import_until(&group, now + 60 * 86400).unwrap(),
        expected_deadline
    );
    assert_eq!(
        require_import_horizon(expected_deadline, now).is_ok(),
        count != 3
    );
    let coordinates = group_coordinates(
        &group,
        &provider,
        ctx["conversationId"].as_str().unwrap(),
        if legacy { 1 } else { 0 },
        1,
    )
    .unwrap();
    let aad = catbird_mls::chat_v2::transcript::direct_request::direct_request_application_aad(
        &context_hash,
        &serde_json::to_vec(&coordinates).unwrap(),
        ctx["firstMessageId"].as_str().unwrap(),
    )
    .unwrap();
    let plaintext =
        catbird_mls::chat_v2::transcript::direct_request::encode_direct_request_introduction(
            &serde_json::to_vec(&serde_json::json!({"text":"x".repeat(16384)})).unwrap(),
        )
        .unwrap();
    let message = encrypt_bound_introduction(
        &mut group,
        &provider,
        &signers[0],
        &context_hash,
        &coordinates,
        ctx["firstMessageId"].as_str().unwrap(),
        &plaintext,
    )
    .unwrap();
    let final_info = group
        .export_group_info(provider.crypto(), &signers[0], true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let metadata = catbird_mls::metadata::GroupMetadataV1 {
        version: 1,
        title: "Direct request".into(),
        description: "Encrypted first contact".into(),
        avatar_blob_locator: None,
        avatar_content_type: None,
    };
    let metadata_key = request_metadata_key(&group, &provider, &coordinates).unwrap();
    let metadata_nonce = [7; 12];
    let metadata_ciphertext = encrypt_request_metadata(
        &group,
        &provider,
        &signers[0],
        &ctx,
        &coordinates,
        &metadata,
        &metadata_nonce,
    )
    .unwrap();
    let context = group
        .export_secret(provider.crypto(), "request-coordinate", b"", 32)
        .unwrap();
    drop(group);
    drop(provider);
    for index in 1..count {
        let provider = Provider::open(&directory.path().join(format!("{index}.db")));
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&welcome)
            .unwrap()
            .extract()
        else {
            panic!()
        };
        assert_eq!(w.secrets().len(), count - 1);
        let expected: std::collections::BTreeSet<_> = packages
            .iter()
            .map(|p| p.hash_ref(provider.crypto()).unwrap().as_slice().to_vec())
            .collect();
        let actual: std::collections::BTreeSet<_> = w
            .secrets()
            .iter()
            .map(|s| s.new_member().as_slice().to_vec())
            .collect();
        assert_eq!(expected, actual);
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(&provider, &config, w, None)
            .unwrap()
            .into_group(&provider)
            .unwrap();
        assert_eq!(group.group_id(), &gid);
        assert_eq!(group.epoch().as_u64(), 1);
        assert_eq!(
            group
                .export_secret(provider.crypto(), "request-coordinate", b"", 32)
                .unwrap(),
            context
        );
        let key = request_metadata_key(&group, &provider, &coordinates).unwrap();
        assert_eq!(key, metadata_key);
        use aes_gcm::{
            aead::{Aead, Payload},
            Aes256Gcm, KeyInit,
        };
        let metadata_aad = request_metadata_aad(
            &coordinates,
            ctx["requestId"].as_str().unwrap(),
            metadata_ciphertext.len(),
        )
        .unwrap();
        let decrypted = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                (&metadata_nonce).into(),
                Payload {
                    msg: &metadata_ciphertext,
                    aad: &metadata_aad,
                },
            )
            .unwrap();
        assert!(!decrypted.is_empty());
        drop(group);
        drop(provider);
        let provider = Provider::open(&directory.path().join(format!("{index}.db")));
        let mut group = MlsGroup::load(provider.storage(), &gid).unwrap().unwrap();
        let protocol = MlsMessageIn::tls_deserialize_exact(&message)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = group.process_message(&provider, protocol).unwrap();
        assert_eq!(processed.aad(), aad);
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            panic!()
        };
        assert_eq!(application.into_bytes(), plaintext);
    }
    let outsider = Provider::open(&directory.path().join("outsider.db"));
    let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&welcome)
        .unwrap()
        .extract()
    else {
        panic!()
    };
    assert!(
        StagedWelcome::new_from_welcome(&outsider, &MlsGroupJoinConfig::default(), w, None)
            .is_err()
    );
    let total = genesis.len()
        + commit.len()
        + final_info.len()
        + welcome.len()
        + message.len()
        + metadata_ciphertext.len()
        + metadata_nonce.len();
    let artifact_dir = std::env::var("T02_CORPUS_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/t02-real-corpus"));
    let artifact_dir = artifact_dir.join(if legacy {
        format!("leaves-{count}-legacy")
    } else {
        format!("leaves-{count}")
    });
    std::fs::create_dir_all(&artifact_dir).unwrap();
    for (name, bytes) in [
        ("genesis.mls", &genesis),
        ("add.mls", &commit),
        ("final.mls", &final_info),
        ("welcome.mls", &welcome),
        ("application.mls", &message),
        ("metadata.bin", &metadata_ciphertext),
    ] {
        std::fs::write(artifact_dir.join(name), bytes).unwrap();
    }
    for (index, package) in packages.iter().enumerate() {
        let bytes = MlsMessageOut::from(package.clone())
            .tls_serialize_detached()
            .unwrap();
        std::fs::write(
            artifact_dir.join(format!("key-package-{}.mls", index + 1)),
            bytes,
        )
        .unwrap();
    }
    if let Some((coordinate, info)) = prior {
        std::fs::write(
            artifact_dir.join("prior.json"),
            serde_json::to_vec_pretty(&coordinate).unwrap(),
        )
        .unwrap();
        std::fs::write(artifact_dir.join("prior-genesis.mls"), info).unwrap();
    }
    std::fs::write(artifact_dir.join("context.json"), &context_json).unwrap();
    std::fs::write(artifact_dir.join("metadata-nonce.bin"), metadata_nonce).unwrap();
    std::fs::write(
        artifact_dir.join("actor-signature-public-key.bin"),
        signers[0].public(),
    )
    .unwrap();
    std::fs::write(artifact_dir.join("lifetimes.json"),serde_json::to_vec_pretty(&serde_json::json!({"now":now,"finalKeyPackageLeafExpiries":expiries,"minimumImportUntil":expected_deadline,"expectedAddedPackageRefs":packages.iter().map(|p|STANDARD.encode(p.hash_ref(outsider.crypto()).unwrap().as_slice())).collect::<Vec<_>>()})).unwrap()).unwrap();
    std::fs::write(
        artifact_dir.join("coordinates.json"),
        serde_json::to_vec_pretty(&coordinates).unwrap(),
    )
    .unwrap();
    println!("REQUEST_CORPUS leaves={count} legacy={legacy} genesis={} commit={} final_group_info={} welcome={} application={} metadata={} nonce={} decoded_total={total}",genesis.len(),commit.len(),final_info.len(),welcome.len(),message.len(),metadata_ciphertext.len(),metadata_nonce.len());
}
#[test]
fn xwing_two_devices() {
    corpus(2)
}
#[test]
fn xwing_forty_leaves_with_sender_siblings() {
    corpus(40)
}
#[test]
fn near_expiry_sender_sibling_shortens_every_import_deadline() {
    corpus(3)
}

#[derive(Clone, Default)]
struct Keychain(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>);
#[async_trait::async_trait]
impl catbird_mls::KeychainAccess for Keychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, catbird_mls::MLSError> {
        Ok(self.0.lock().unwrap().get(&key).cloned())
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), catbird_mls::MLSError> {
        self.0.lock().unwrap().insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: String) -> Result<(), catbird_mls::MLSError> {
        self.0.lock().unwrap().remove(&key);
        Ok(())
    }
}
#[test]
fn native_unpublished_journal_survives_reopen_without_live_inventory() {
    use catbird_mls::orchestrator::MlsCryptoContext;
    let dir = tempfile::tempdir().unwrap();
    let alice_keys = Keychain::default();
    let bob_keys = Keychain::default();
    let alice_path = dir.path().join("alice");
    let bob_path = dir.path().join("bob");
    let open = |path: &std::path::Path, keychain: &Keychain| {
        catbird_mls::MLSContext::new(
            path.to_str().unwrap().into(),
            "request-native-test-key".into(),
            Box::new(keychain.clone()),
        )
        .unwrap()
    };
    let alice = open(&alice_path, &alice_keys);
    let bob = open(&bob_path, &bob_keys);
    let actor = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#00000000-0000-4000-8000-000000000000";
    let recipient = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb#00000000-0000-4000-8000-000000000001";
    let actor_package = alice.create_key_package(actor.as_bytes().to_vec()).unwrap();
    let package = bob
        .create_key_package(recipient.as_bytes().to_vec())
        .unwrap();
    let verifier = openmls_libcrux_crypto::Provider::new().unwrap();
    let MlsMessageBodyIn::KeyPackage(kp) =
        MlsMessageIn::tls_deserialize_exact(&actor_package.key_package_data)
            .unwrap()
            .extract()
    else {
        panic!()
    };
    let kp = kp
        .validate(verifier.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let context_json=serde_json::to_vec(&serde_json::json!({"protocolVersion":"2","requestId":uuid::Uuid::new_v4().to_string(),"firstMessageId":uuid::Uuid::new_v4().to_string(),"conversationId":uuid::Uuid::new_v4().to_string(),"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},"actorDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","actorDeviceId":"00000000-0000-4000-8000-000000000000","actorKeyId":URL_SAFE_NO_PAD.encode(Sha256::digest(kp.leaf_node().signature_key().as_slice())),"recipientDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","preparationDigest":STANDARD.encode([42;32])})).unwrap();
    let input = DirectRequestBootstrapInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        context_json,
        group_id: vec![37; 32],
        generation: 0,
        state_version: 1,
        key_packages: vec![package.key_package_data],
        expected_package_refs: vec![package.hash_ref],
        authority_import_until: now + 20 * 86400,
        preparation_request_digest: [21; 32],
        receipt_authority_key: vec![2; 33],
        text: "protected draft remains readable".into(),
        invitation: None,
        metadata: catbird_mls::metadata::GroupMetadataV1 {
            version: 1,
            title: "Direct request".into(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    };
    assert!(alice
        .compare_exchange_direct_request_intent(
            &input.draft_id,
            None,
            b"exact signed prepare bytes"
        )
        .unwrap());
    assert!(!alice
        .compare_exchange_direct_request_intent(&input.draft_id, None, b"replacement")
        .unwrap());
    let mut expired_candidate = input.clone();
    expired_candidate.authority_import_until = now + 60;
    assert!(alice
        .prepare_direct_request_bootstrap(&expired_candidate)
        .is_err());
    assert!(alice.list_direct_request_journal().unwrap().is_empty());
    let journal = alice.prepare_direct_request_bootstrap(&input).unwrap();
    assert!(alice.get_epoch(input.group_id.clone()).is_err());
    drop(alice);
    let alice = open(&alice_path, &alice_keys);
    assert_eq!(
        alice
            .read_direct_request_intent(&input.draft_id)
            .unwrap()
            .unwrap(),
        b"exact signed prepare bytes"
    );
    assert_eq!(
        alice.list_direct_request_journal().unwrap(),
        vec![journal.clone()]
    );
    assert_eq!(
        alice.prepare_direct_request_bootstrap(&input).unwrap(),
        journal
    );
    assert!(alice.get_epoch(input.group_id.clone()).is_err());
    assert!(alice
        .mark_direct_request_projected(&journal.request_id)
        .is_err());
    assert!(alice
        .confirm_published_bootstrap(&journal.request_id, b"{}", &input.receipt_authority_key)
        .is_err());
    assert!(alice
        .abandon_rejected_bootstrap(&journal.request_id, b"{}", &input.receipt_authority_key)
        .is_err());
    assert_eq!(
        alice.list_direct_request_journal().unwrap(),
        vec![journal.clone()]
    );
    let mut changed = input.clone();
    changed.text = "different first message".into();
    assert!(alice.prepare_direct_request_bootstrap(&changed).is_err());
    use catbird_mls::chat_v2::transcript::direct_request::{
        direct_request_receipt_key_id, direct_request_signing_bytes, DirectRequestKind,
    };
    use chrono::{SecondsFormat, TimeZone, Utc};
    let (ctx, _) = context(&input.context_json).unwrap();
    let b = &journal.bootstrap;
    let import_until = Utc
        .timestamp_opt(b.import_until as i64, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let signed_at = Utc
        .timestamp_opt(now as i64, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let artifact = |bytes: &Vec<u8>, content_type: &str| serde_json::json!({"framing":"mlsMessage","contentType":content_type,"bytes":STANDARD.encode(bytes),"sha256":STANDARD.encode(Sha256::digest(bytes))});
    let metadata = serde_json::json!({"coordinate":metadata_coordinate(&b.coordinates).unwrap(),"originTransitionId":ctx["requestId"],"metadataVersion":1,"nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),"ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),"ciphertextSize":b.metadata_ciphertext.len(),"authorProof":{"authorDid":ctx["actorDid"],"authorDeviceId":ctx["actorDeviceId"],"authorKeyId":ctx["actorKeyId"],"signaturePublicKey":STANDARD.encode(kp.leaf_node().signature_key().as_slice()),"authGenerationAtOrigin":1,"originTransitionId":ctx["requestId"],"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}});
    let body = serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestPublicationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-PUBLISH\0","protocolVersion":"2","actorDid":ctx["actorDid"],"actorDeviceId":ctx["actorDeviceId"],"keyId":ctx["actorKeyId"],"authGeneration":1,"requestId":ctx["requestId"],"firstMessageId":ctx["firstMessageId"],"conversationId":ctx["conversationId"],"recipientDid":ctx["recipientDid"],"origin":ctx["origin"],"profile":"encryptedIntroduction1","preparationDigest":ctx["preparationDigest"],"preparationRequestDigest":STANDARD.encode(input.preparation_request_digest),"contextHash":STANDARD.encode(b.context_hash),"next":b.coordinates,"importUntil":import_until,"artifacts":{"genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),"addCommit":artifact(&b.add_commit,"publicMessageCommit"),"finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),"welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":[{"recipientDid":ctx["recipientDid"],"recipientDeviceId":"00000000-0000-4000-8000-000000000001","provenance":{"requestId":ctx["requestId"],"preparationDigest":ctx["preparationDigest"],"contextHash":STANDARD.encode(b.context_hash),"grantId":uuid::Uuid::new_v4().to_string(),"grantRevision":1,"keyPackageRef":STANDARD.encode(&input.expected_package_refs[0]),"importUntil":import_until}}]},"metadataSnapshot":metadata,"initialCiphertext":STANDARD.encode(&b.initial_ciphertext)},"idempotencyKey":uuid::Uuid::new_v4().to_string(),"signedAt":signed_at});
    let transcript = direct_request_signing_bytes(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let signature = alice
        .sign_with_identity_key(actor.into(), transcript.clone())
        .unwrap();
    let publication = serde_json::to_vec(
        &serde_json::json!({"signedRequest":{"body":body,"signature":STANDARD.encode(signature)}}),
    )
    .unwrap();
    alice
        .persist_direct_request_publish(&journal.request_id, &publication)
        .unwrap();
    alice
        .persist_direct_request_publish(&journal.request_id, &publication)
        .unwrap();
    drop(alice);
    let alice = open(&alice_path, &alice_keys);
    let pending = alice.list_direct_request_journal().unwrap().remove(0);
    assert_eq!(
        pending.publish_request.as_deref(),
        Some(publication.as_slice())
    );
    assert!(alice.get_epoch(input.group_id.clone()).is_err());
    use p256::ecdsa::signature::Signer as _;
    let authority = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
    let authority_key = authority
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let make_receipt = |coordinates: serde_json::Value| {
        let body = serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":direct_request_receipt_key_id(&authority_key).unwrap(),"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":ctx["requestId"],"requestKind":"publish","actorDid":ctx["actorDid"],"actorDeviceId":ctx["actorDeviceId"],"actorKeyId":ctx["actorKeyId"],"authGeneration":1,"preparationRequestDigest":STANDARD.encode(input.preparation_request_digest),"requestDigest":STANDARD.encode(Sha256::digest(&transcript)),"recordedAt":signed_at,"conversationId":ctx["conversationId"],"firstMessageId":ctx["firstMessageId"],"coordinates":coordinates}});
        let input = direct_request_signing_bytes(
            DirectRequestKind::Outcome,
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        let sig: p256::ecdsa::Signature = authority.sign(&input);
        let sig = sig.normalize_s().unwrap_or(sig);
        serde_json::to_vec(
            &serde_json::json!({"body":body,"signature":STANDARD.encode(sig.to_bytes())}),
        )
        .unwrap()
    };
    let mut wrong = b.coordinates.clone();
    wrong["confirmationTag"] = serde_json::json!(STANDARD.encode([99; 32]));
    assert!(alice
        .confirm_published_bootstrap(&journal.request_id, &make_receipt(wrong), &authority_key)
        .is_err());
    let receipt = make_receipt(b.coordinates.clone());
    alice
        .confirm_published_bootstrap(&journal.request_id, &receipt, &authority_key)
        .unwrap();
    drop(alice);
    let alice = open(&alice_path, &alice_keys);
    assert_eq!(alice.get_epoch(input.group_id.clone()).unwrap(), 1);
    assert_eq!(alice.list_direct_request_journal().unwrap()[0].phase,catbird_mls::orchestrator::direct_request_journal::DirectRequestJournalPhase::PublishedAwaitingProjection);
    alice
        .confirm_published_bootstrap(&journal.request_id, &receipt, &authority_key)
        .unwrap();
    alice
        .mark_direct_request_projected(&journal.request_id)
        .unwrap();
    alice
        .mark_direct_request_projected(&journal.request_id)
        .unwrap();
    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: b.clone(),
        local_identity: recipient.as_bytes().to_vec(),
        local_package_ref: input.expected_package_refs[0].clone(),
        publication_request: publication,
        actor_signature_public_key: kp.leaf_node().signature_key().as_slice().to_vec(),
        published_receipt: receipt,
        receipt_authority_key: authority_key,
        preparation_request_digest: input.preparation_request_digest,
    };
    let mut wrong = welcome_input.clone();
    wrong.bootstrap.coordinates["confirmationTag"] = serde_json::json!(STANDARD.encode([99; 32]));
    assert!(bob.process_direct_request_welcome(&wrong).is_err());
    bob.process_direct_request_welcome(&welcome_input).unwrap();
    drop(bob);
    let bob = open(&bob_path, &bob_keys);
    bob.process_direct_request_welcome(&welcome_input).unwrap();
    let decrypted = bob
        .decrypt_direct_request_introduction(&welcome_input)
        .unwrap();
    assert_eq!(
        decrypted,
        DirectRequestIntroductionResult::Ready {
            plaintext: introduction_plaintext(&input).unwrap()
        }
    );
    drop(bob);
    let bob = open(&bob_path, &bob_keys);
    assert_eq!(
        bob.decrypt_direct_request_introduction(&welcome_input)
            .unwrap(),
        decrypted
    );
}

#[test]
fn horizon_requires_seven_days_and_clock_margin_without_overflow() {
    assert!(require_import_horizon(100 + MIN_IMPORT_HORIZON + IMPORT_CLOCK_MARGIN, 100).is_ok());
    assert!(require_import_horizon(99 + MIN_IMPORT_HORIZON + IMPORT_CLOCK_MARGIN, 100).is_err());
    assert!(require_import_horizon(u64::MAX, u64::MAX).is_err());
}

#[test]
fn legacy_pending_direct_binds_real_prior_and_successor() {
    corpus_variant(2, true);
}

#[test]
fn maximum_utf8_text_does_not_expand_past_ciphertext_budget() {
    use catbird_mls::chat_v2::transcript::direct_request::{
        decode_direct_request_introduction, encode_direct_request_introduction,
    };
    let text = "\0".repeat(16384);
    let encoded = encode_direct_request_introduction(
        &serde_json::to_vec(&serde_json::json!({"text":text})).unwrap(),
    )
    .unwrap();
    assert!(encoded.len() < 17000);
    assert_eq!(
        decode_direct_request_introduction(&encoded).unwrap()["text"],
        text
    );
}
