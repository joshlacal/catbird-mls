//! Pinned `0x004D` (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` / `XWingKemDraft06`)
//! hybrid post-quantum and MLSWG test-vector suite with SHA-256 manifest verification.

use std::collections::{BTreeMap, HashMap};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use base64::Engine as _;
use catbird_mls::sim_hooks::{
    build_staged_welcome_at, sim_signature_keypair, validate_key_package_at, ChaChaSimEntropy,
    SeededOpenMlsCryptoProvider, SimEntropy,
};
use libcrux_kem::{key_gen_derand, Algorithm as KemAlg, Ct as KemCt, PublicKey as KemPublicKey};
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::types::{
    Ciphersuite, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType,
    SignatureScheme,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

const SUITE_0X004D: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const VECTOR_NOW_SECS: u64 = 1_760_000_000;

/// Expected vector filenames inside `tests/vectors/xwing_0x004d/`.
const EXPECTED_VECTOR_FILES: &[&str] = &[
    "ietf_xwing_draft06_kats.json",
    "mlswg_deserialization.json",
    "mlswg_tree_math.json",
    "openmls_0x004d_protocol_vectors.json",
    "openmls_0x004d_storage_stability.json",
];

/// Pinned SHA-256 of `tests/vectors/xwing_0x004d/MANIFEST.sha256` itself.
const EXPECTED_MANIFEST_SHA256: &str =
    "0ba56756b44988ad43274b16efcac01fe9162167655d5e346f6d1e8d38532092";

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("xwing_0x004d")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_manifest(manifest_text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for (line_no, raw_line) in manifest_text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(format!(
                "manifest line {} missing two-space separator: {line:?}",
                line_no + 1
            ));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!(
                "manifest line {} has non-canonical SHA-256 digest: {digest:?}",
                line_no + 1
            ));
        }
        if name.contains('/') || name.contains("..") {
            return Err(format!(
                "manifest line {} has unsafe filename: {name:?}",
                line_no + 1
            ));
        }
        if map.insert(name.to_owned(), digest.to_owned()).is_some() {
            return Err(format!("duplicate manifest entry for {name}"));
        }
    }
    Ok(map)
}

fn verify_manifest_against_blobs(
    manifest_map: &BTreeMap<String, String>,
    actual_blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let expected_names: Vec<String> = EXPECTED_VECTOR_FILES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let manifest_names: Vec<String> = manifest_map.keys().cloned().collect();
    if manifest_names != expected_names {
        return Err(format!(
            "manifest file list {manifest_names:?} != expected {expected_names:?}"
        ));
    }
    for (name, expected_sha) in manifest_map {
        let Some(bytes) = actual_blobs.get(name) else {
            return Err(format!("missing vector file on disk: {name}"));
        };
        let actual_sha = sha256_hex(bytes);
        if &actual_sha != expected_sha {
            return Err(format!(
                "SHA-256 mismatch for {name}: expected {expected_sha}, got {actual_sha}"
            ));
        }
    }
    Ok(())
}

fn load_verified_vector_bytes(filename: &str) -> Vec<u8> {
    let dir = vectors_dir();
    let manifest_bytes = std::fs::read(dir.join("MANIFEST.sha256")).expect("read MANIFEST.sha256");
    let manifest_sha = sha256_hex(&manifest_bytes);
    assert_eq!(
        manifest_sha, EXPECTED_MANIFEST_SHA256,
        "MANIFEST.sha256 digest changed; expected {EXPECTED_MANIFEST_SHA256}, got {manifest_sha}"
    );
    let manifest_text = std::str::from_utf8(&manifest_bytes).expect("UTF-8 manifest");
    let manifest_map = parse_manifest(manifest_text).expect("valid manifest syntax");

    let mut blobs = BTreeMap::new();
    for &name in EXPECTED_VECTOR_FILES {
        let raw = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        blobs.insert(name.to_owned(), raw);
    }
    verify_manifest_against_blobs(&manifest_map, &blobs).expect("manifest verification");
    blobs
        .remove(filename)
        .expect("requested vector file present")
}

// ---------------------------------------------------------------------------
// 1. IETF draft-connolly-cfrg-xwing-kem-06 KATs + HPKE 0x004D
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct XWingIetfKat {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

#[test]
fn xwing_0x004d_ciphersuite_ids_and_manifest_integrity() {
    assert_eq!(SUITE_0X004D as u16, 0x004D);
    assert_eq!(SUITE_0X004D as u16, 77);
    assert_eq!(HpkeKemType::XWingKemDraft6 as u16, 0x004D);
    assert_eq!(
        SUITE_0X004D.hpke_kem_algorithm(),
        HpkeKemType::XWingKemDraft6
    );
    assert_eq!(
        SUITE_0X004D.hpke_aead_algorithm(),
        HpkeAeadType::ChaCha20Poly1305
    );
    assert_eq!(SUITE_0X004D.hpke_kdf_algorithm(), HpkeKdfType::HkdfSha256);

    let _ = load_verified_vector_bytes("ietf_xwing_draft06_kats.json");

    // Negative manifest controls: 1-bit payload mutation and missing-entry detection.
    let dir = vectors_dir();
    let manifest_text =
        std::fs::read_to_string(dir.join("MANIFEST.sha256")).expect("read manifest");
    let manifest_map = parse_manifest(&manifest_text).expect("parse manifest");
    let mut blobs = BTreeMap::new();
    for &name in EXPECTED_VECTOR_FILES {
        blobs.insert(name.to_owned(), std::fs::read(dir.join(name)).unwrap());
    }
    assert!(verify_manifest_against_blobs(&manifest_map, &blobs).is_ok());

    let mut corrupted = blobs.clone();
    corrupted.get_mut("ietf_xwing_draft06_kats.json").unwrap()[0] ^= 0x01;
    assert!(verify_manifest_against_blobs(&manifest_map, &corrupted).is_err());

    let mut missing = blobs;
    missing.remove("mlswg_tree_math.json");
    assert!(verify_manifest_against_blobs(&manifest_map, &missing).is_err());
}

#[test]
fn ietf_xwing_draft06_kats_and_hpke_0x004d_roundtrip() {
    let raw = load_verified_vector_bytes("ietf_xwing_draft06_kats.json");
    let kats: Vec<XWingIetfKat> = serde_json::from_slice(&raw).expect("parse X-Wing KATs");
    assert_eq!(kats.len(), 3, "expected all 3 official IETF X-Wing KATs");

    for (idx, kat) in kats.iter().enumerate() {
        let seed = hex::decode(&kat.seed).expect("seed hex");
        let eseed = hex::decode(&kat.eseed).expect("eseed hex");
        let expected_sk = hex::decode(&kat.sk).expect("sk hex");
        let expected_pk = hex::decode(&kat.pk).expect("pk hex");
        let expected_ct = hex::decode(&kat.ct).expect("ct hex");
        let expected_ss = hex::decode(&kat.ss).expect("ss hex");

        assert_eq!(seed.len(), 32);
        assert_eq!(eseed.len(), 64);
        assert_eq!(expected_sk.len(), 32);
        assert_eq!(expected_pk.len(), 1216);
        assert_eq!(expected_ct.len(), 1120);
        assert_eq!(expected_ss.len(), 32);

        let (sk, pk) = key_gen_derand(KemAlg::XWingKemDraft06, &seed)
            .unwrap_or_else(|e| panic!("KAT #{idx} key_gen_derand failed: {e:?}"));
        assert_eq!(sk.encode(), expected_sk, "KAT #{idx} sk mismatch");
        assert_eq!(pk.encode(), expected_pk, "KAT #{idx} pk mismatch");

        let decoded_pk = KemPublicKey::decode(KemAlg::XWingKemDraft06, &expected_pk)
            .unwrap_or_else(|e| panic!("KAT #{idx} PublicKey::decode failed: {e:?}"));
        let (ss_enc, ct_enc) = decoded_pk
            .encapsulate_derand(&eseed)
            .unwrap_or_else(|e| panic!("KAT #{idx} encapsulate_derand failed: {e:?}"));
        assert_eq!(ct_enc.encode(), expected_ct, "KAT #{idx} ct mismatch");
        assert_eq!(
            ss_enc.encode(),
            expected_ss,
            "KAT #{idx} encaps ss mismatch"
        );

        let decoded_ct = KemCt::decode(KemAlg::XWingKemDraft06, &expected_ct)
            .unwrap_or_else(|e| panic!("KAT #{idx} Ct::decode failed: {e:?}"));
        let ss_dec = decoded_ct
            .decapsulate(&sk)
            .unwrap_or_else(|e| panic!("KAT #{idx} decapsulate failed: {e:?}"));
        assert_eq!(
            ss_dec.encode(),
            expected_ss,
            "KAT #{idx} decaps ss mismatch"
        );

        // Implicit rejection across both hybrid halves: ML-KEM-768 (bytes 0..1088)
        // and X25519 (bytes 1088..1120).
        let mut bad_mlkem = expected_ct.clone();
        bad_mlkem[0] ^= 0x80;
        let bad_mlkem_ss = KemCt::decode(KemAlg::XWingKemDraft06, &bad_mlkem)
            .expect("decode mutated ML-KEM ct")
            .decapsulate(&sk)
            .expect("implicit rejection returns pseudorandom secret");
        assert_ne!(bad_mlkem_ss.encode(), expected_ss);

        let mut bad_x25519 = expected_ct.clone();
        bad_x25519[1100] ^= 0x04;
        let bad_x25519_ss = KemCt::decode(KemAlg::XWingKemDraft06, &bad_x25519)
            .expect("decode mutated X25519 ct")
            .decapsulate(&sk)
            .expect("X25519 component tamper diverges combiner output");
        assert_ne!(bad_x25519_ss.encode(), expected_ss);

        // Exercise OpenMLS LibcruxCryptoProvider HPKE 0x004D (`XWingKemDraft6` + ChaCha20Poly1305)
        // directly with this IETF KAT keypair.
        let crypto = LibcruxCryptoProvider::new().expect("libcrux crypto provider");
        assert!(crypto.supports(SUITE_0X004D).is_ok());
        let hpke_cfg = || {
            HpkeConfig(
                HpkeKemType::XWingKemDraft6,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            )
        };
        let info = b"openmls-0x004d-hpke-info";
        let aad = b"openmls-0x004d-hpke-aad";
        let plain = b"hybrid post-quantum leaf secret payload";
        let sealed: HpkeCiphertext = crypto
            .hpke_seal(hpke_cfg(), &expected_pk, info, aad, plain)
            .expect("hpke_seal 0x004D");
        assert_eq!(sealed.kem_output.as_slice().len(), 1120);
        let opened = crypto
            .hpke_open(hpke_cfg(), &sealed, &expected_sk, info, aad)
            .expect("hpke_open 0x004D");
        assert_eq!(opened, plain);
        assert!(crypto
            .hpke_open(hpke_cfg(), &sealed, &expected_sk, info, b"wrong-aad")
            .is_err());
    }
}

// ---------------------------------------------------------------------------
// 2. Upstream OpenMLS 0x004D Storage-Stability Vector
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct StorageStabilityEnvelope {
    cipher_suite_id: u16,
    cipher_suite_hex: String,
    cipher_suite_name: String,
    entry: StorageStabilityKatData,
}

#[derive(Debug, Deserialize)]
struct StorageStabilityKatData {
    group_id: GroupId,
    storages: Vec<String>,
}

fn decode_openmls_kat_storage(serialized: &[u8]) -> MemoryStorage {
    let mut r = serialized;
    let read_u64 = |cursor: &mut &[u8]| -> usize {
        let mut buf = [0u8; 8];
        cursor.read_exact(&mut buf).expect("read u64");
        u64::from_be_bytes(buf) as usize
    };
    let mut count = read_u64(&mut r);
    let mut map = HashMap::with_capacity(count);
    while count > 0 {
        let k_len = read_u64(&mut r);
        let v_len = read_u64(&mut r);
        let mut k = vec![0u8; k_len];
        let mut v = vec![0u8; v_len];
        r.read_exact(&mut k).expect("read key");
        r.read_exact(&mut v).expect("read val");
        map.insert(k, v);
        count -= 1;
    }
    assert!(r.is_empty(), "storage snapshot had trailing bytes");
    MemoryStorage {
        values: RwLock::new(map),
    }
}

#[test]
fn openmls_upstream_0x004d_storage_stability_vectors() {
    let raw = load_verified_vector_bytes("openmls_0x004d_storage_stability.json");
    let env: StorageStabilityEnvelope =
        serde_json::from_slice(&raw).expect("parse 0x004D storage-stability vector");
    assert_eq!(env.cipher_suite_id, 0x004D);
    assert_eq!(env.cipher_suite_hex, "0x004D");
    assert_eq!(
        env.cipher_suite_name,
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
    assert_eq!(env.entry.storages.len(), 6);

    let url_safe = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new(),
    );
    let decoded_storages: Vec<MemoryStorage> = env
        .entry
        .storages
        .iter()
        .map(|s| decode_openmls_kat_storage(&url_safe.decode(s).expect("base64 decode")))
        .collect();

    let group_id = &env.entry.group_id;

    // Stage 0: Newly created 0x004D group (epoch 0, alice).
    let g0 = MlsGroup::load(&decoded_storages[0], group_id)
        .expect("load stage 0")
        .expect("group stage 0 present");
    assert_eq!(g0.ciphersuite(), SUITE_0X004D);
    assert_eq!(g0.epoch().as_u64(), 0);
    assert_eq!(g0.members().count(), 1);
    assert!(g0.pending_commit().is_none());

    // Stage 1: Pending Add(bob) commit in epoch 0.
    let g1 = MlsGroup::load(&decoded_storages[1], group_id)
        .expect("load stage 1")
        .expect("group stage 1 present");
    assert_eq!(g1.ciphersuite(), SUITE_0X004D);
    assert_eq!(g1.epoch().as_u64(), 0);
    let staged_add = g1.pending_commit().expect("pending add commit");
    assert_eq!(staged_add.add_proposals().count(), 1);

    // Stage 2: Merged Add(bob) at epoch 1.
    let g2 = MlsGroup::load(&decoded_storages[2], group_id)
        .expect("load stage 2")
        .expect("group stage 2 present");
    assert_eq!(g2.ciphersuite(), SUITE_0X004D);
    assert_eq!(g2.epoch().as_u64(), 1);
    let members_2: Vec<_> = g2.members().collect();
    assert_eq!(members_2.len(), 2);
    assert_eq!(
        members_2[0].credential,
        BasicCredential::new(b"alice".to_vec()).into()
    );
    assert_eq!(
        members_2[1].credential,
        BasicCredential::new(b"bob".to_vec()).into()
    );

    // Stage 3 & 4: Pending GCE commit (epoch 1) -> merged GCE commit (epoch 2).
    let g3 = MlsGroup::load(&decoded_storages[3], group_id)
        .expect("load stage 3")
        .expect("group stage 3 present");
    assert_eq!(g3.epoch().as_u64(), 1);
    assert!(g3.pending_commit().is_some());

    let g4 = MlsGroup::load(&decoded_storages[4], group_id)
        .expect("load stage 4")
        .expect("group stage 4 present");
    assert_eq!(g4.ciphersuite(), SUITE_0X004D);
    assert_eq!(g4.epoch().as_u64(), 2);
    assert!(g4.pending_commit().is_none());

    // Stage 5: Queued Add(charlie) proposal at epoch 2 with 1216-byte X-Wing key package.
    let g5 = MlsGroup::load(&decoded_storages[5], group_id)
        .expect("load stage 5")
        .expect("group stage 5 present");
    assert_eq!(g5.ciphersuite(), SUITE_0X004D);
    assert_eq!(g5.epoch().as_u64(), 2);
    let proposals: Vec<_> = g5.pending_proposals().collect();
    assert_eq!(proposals.len(), 1);
    match proposals[0].proposal() {
        Proposal::Add(add_p) => {
            assert_eq!(add_p.key_package().ciphersuite(), SUITE_0X004D);
            assert_eq!(add_p.key_package().hpke_init_key().as_slice().len(), 1216);
            assert_eq!(
                add_p.key_package().leaf_node().credential(),
                &BasicCredential::new(b"charlie".to_vec()).into()
            );
        }
        other => panic!("expected Add proposal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. MLSWG RFC 9420 Deserialization & Tree-Math Vectors
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DeserializationVector {
    vlbytes_header: String,
    length: usize,
}

#[derive(Debug, Deserialize)]
struct TreeMathVector {
    n_leaves: u32,
    n_nodes: u32,
    root: u32,
    left: Vec<Option<u32>>,
    right: Vec<Option<u32>>,
    parent: Vec<Option<u32>>,
    sibling: Vec<Option<u32>>,
}

fn rfc9420_level(x: u32) -> u32 {
    if (x & 1) == 0 {
        0
    } else {
        let mut k = 0u32;
        while ((x >> k) & 1) == 1 {
            k += 1;
        }
        k
    }
}

fn rfc9420_node_width(n_leaves: u32) -> u32 {
    if n_leaves == 0 {
        0
    } else {
        2 * (n_leaves - 1) + 1
    }
}

fn rfc9420_root(n_leaves: u32) -> u32 {
    let w = rfc9420_node_width(n_leaves);
    let log2 = u32::BITS - 1 - w.leading_zeros();
    (1u32 << log2) - 1
}

fn rfc9420_left(x: u32) -> Option<u32> {
    let k = rfc9420_level(x);
    if k == 0 {
        None
    } else {
        Some(x ^ (0x01 << (k - 1)))
    }
}

fn rfc9420_right(x: u32, n_leaves: u32) -> Option<u32> {
    let k = rfc9420_level(x);
    if k == 0 {
        return None;
    }
    let w = rfc9420_node_width(n_leaves);
    let mut r = x ^ (0x03 << (k - 1));
    while r >= w {
        r = rfc9420_left(r)?;
    }
    Some(r)
}

fn rfc9420_parent_step(x: u32) -> u32 {
    let k = rfc9420_level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}

fn rfc9420_parent(x: u32, n_leaves: u32) -> Option<u32> {
    if x == rfc9420_root(n_leaves) {
        return None;
    }
    let w = rfc9420_node_width(n_leaves);
    let mut p = rfc9420_parent_step(x);
    while p >= w {
        p = rfc9420_parent_step(p);
    }
    Some(p)
}

fn rfc9420_sibling(x: u32, n_leaves: u32) -> Option<u32> {
    let p = rfc9420_parent(x, n_leaves)?;
    if x < p {
        rfc9420_right(p, n_leaves)
    } else {
        rfc9420_left(p)
    }
}

#[test]
fn mlswg_deserialization_and_tree_math_vectors() {
    let deser_raw = load_verified_vector_bytes("mlswg_deserialization.json");
    let deser_vecs: Vec<DeserializationVector> =
        serde_json::from_slice(&deser_raw).expect("parse mlswg deserialization vectors");
    assert_eq!(deser_vecs.len(), 14);
    for vec_item in &deser_vecs {
        let mut wire = hex::decode(&vec_item.vlbytes_header).expect("header hex");
        let header_len = wire.len();
        wire.extend((0..vec_item.length).map(|i| (i & 0xff) as u8));
        let mut cursor = wire.as_slice();
        let decoded = VLBytes::tls_deserialize(&mut cursor).expect("VLBytes decode");
        assert!(cursor.is_empty());
        assert_eq!(decoded.as_slice().len(), vec_item.length);

        let reencoded = decoded.tls_serialize_detached().expect("VLBytes encode");
        assert_eq!(reencoded, wire);

        if vec_item.length > 0 {
            let mut truncated = &wire[..header_len + vec_item.length - 1];
            assert!(VLBytes::tls_deserialize(&mut truncated).is_err());
        }
    }

    let tm_raw = load_verified_vector_bytes("mlswg_tree_math.json");
    let tm_vecs: Vec<TreeMathVector> =
        serde_json::from_slice(&tm_raw).expect("parse mlswg tree-math vectors");
    assert_eq!(tm_vecs.len(), 10);
    for tv in &tm_vecs {
        assert_eq!(rfc9420_node_width(tv.n_leaves), tv.n_nodes);
        assert_eq!(rfc9420_root(tv.n_leaves), tv.root);
        for x in 0..tv.n_nodes {
            let idx = x as usize;
            assert_eq!(rfc9420_left(x), tv.left[idx], "left({x}) n={}", tv.n_leaves);
            assert_eq!(
                rfc9420_right(x, tv.n_leaves),
                tv.right[idx],
                "right({x}) n={}",
                tv.n_leaves
            );
            assert_eq!(
                rfc9420_parent(x, tv.n_leaves),
                tv.parent[idx],
                "parent({x}) n={}",
                tv.n_leaves
            );
            assert_eq!(
                rfc9420_sibling(x, tv.n_leaves),
                tv.sibling[idx],
                "sibling({x}) n={}",
                tv.n_leaves
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Deterministic OpenMLS 0x004D Multi-Epoch Protocol Wire Vectors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OpenMls0x004dProtocolVectors {
    cipher_suite: u16,
    cipher_suite_name: String,
    group_id_hex: String,
    bob_key_package_hex: String,
    carol_key_package_hex: String,
    epoch1_add_bob_commit_hex: String,
    epoch1_welcome_bob_hex: String,
    epoch1_authenticator_hex: String,
    epoch1_exporter_secret_hex: String,
    epoch1_alice_app_ciphertext_hex: String,
    epoch1_alice_app_plaintext_hex: String,
    epoch2_add_carol_commit_hex: String,
    epoch2_welcome_carol_hex: String,
    epoch2_authenticator_hex: String,
    epoch2_exporter_secret_hex: String,
    epoch3_bob_self_update_commit_hex: String,
    epoch3_authenticator_hex: String,
    epoch3_exporter_secret_hex: String,
    epoch4_alice_remove_bob_commit_hex: String,
    epoch4_authenticator_hex: String,
    epoch4_exporter_secret_hex: String,
}

fn apply_commit_wire<P: openmls::storage::OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    commit_wire: &[u8],
) {
    let msg_in = MlsMessageIn::tls_deserialize_exact(commit_wire).expect("parse commit wire");
    let proto: ProtocolMessage = match msg_in.extract() {
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        other => panic!("expected Public/Private commit message, got {other:?}"),
    };
    let processed = group
        .process_message(provider, proto)
        .expect("process commit");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(provider, *staged)
                .expect("merge staged commit");
        }
        other => panic!("expected StagedCommitMessage, got {other:?}"),
    }
}

fn verify_pinned_0x004d_protocol_transcript(pinned: &OpenMls0x004dProtocolVectors) {
    let mk_actor = |seed: u64, label: &[u8], cred_bytes: &[u8]| {
        let entropy: Arc<dyn SimEntropy> = Arc::new(ChaChaSimEntropy::from_seed(seed, label));
        let provider = SeededOpenMlsCryptoProvider::with_storage(
            Arc::clone(&entropy),
            MemoryStorage::default(),
        );
        let sig = sim_signature_keypair(entropy.as_ref(), SignatureScheme::ED25519)
            .expect("actor signature keypair");
        sig.store(provider.storage()).expect("store signer");
        let cred = CredentialWithKey {
            credential: BasicCredential::new(cred_bytes.to_vec()).into(),
            signature_key: sig.public().into(),
        };
        (provider, sig, cred)
    };

    let (alice_p, alice_sig, alice_cred) =
        mk_actor(0x004D_A11C_E001, b"kat-0x004d-alice", b"did:plc:alice#dev1");
    let (bob_p, bob_sig, bob_cred) =
        mk_actor(0x004D_B0B0_0002, b"kat-0x004d-bob", b"did:plc:bob#dev1");
    let (carol_p, carol_sig, carol_cred) =
        mk_actor(0x004D_CA20_1003, b"kat-0x004d-carol", b"did:plc:carol#dev1");

    let pinned_lifetime = Lifetime::init(1_700_000_000, 4_102_444_800);
    let kp_caps = Capabilities::builder()
        .ciphersuites(vec![SUITE_0X004D])
        .build();
    let bob_kp_bundle = KeyPackage::builder()
        .key_package_lifetime(pinned_lifetime)
        .leaf_node_capabilities(kp_caps.clone())
        .build(SUITE_0X004D, &bob_p, &bob_sig, bob_cred)
        .expect("bob 0x004D key package");
    let carol_kp_bundle = KeyPackage::builder()
        .key_package_lifetime(pinned_lifetime)
        .leaf_node_capabilities(kp_caps)
        .build(SUITE_0X004D, &carol_p, &carol_sig, carol_cred)
        .expect("carol 0x004D key package");

    let bob_kp_bytes = bob_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize bob kp");
    let carol_kp_bytes = carol_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize carol kp");
    assert_eq!(hex::encode(&bob_kp_bytes), pinned.bob_key_package_hex);
    assert_eq!(hex::encode(&carol_kp_bytes), pinned.carol_key_package_hex);

    let group_id_bytes = hex::decode(&pinned.group_id_hex).expect("group id hex");
    assert_eq!(group_id_bytes, [0x4du8; 32]);
    let create_cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE_0X004D)
        .lifetime(pinned_lifetime)
        .use_ratchet_tree_extension(true)
        .build();
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_p,
        &alice_sig,
        &create_cfg,
        GroupId::from_slice(&group_id_bytes),
        alice_cred,
    )
    .expect("create 0x004D group");

    let bob_kp_verified = validate_key_package_at(
        KeyPackageIn::tls_deserialize_exact(&bob_kp_bytes).expect("parse bob kp"),
        alice_p.crypto(),
        ProtocolVersion::Mls10,
        VECTOR_NOW_SECS,
    )
    .expect("validate bob kp");
    let (e1_commit, e1_welcome, _) = alice_group
        .add_members(&alice_p, &alice_sig, &[bob_kp_verified])
        .expect("add bob");
    alice_group
        .merge_pending_commit(&alice_p)
        .expect("merge epoch 1");
    let e1_auth_hex = hex::encode(alice_group.epoch_authenticator().as_slice());
    let e1_commit_bytes = e1_commit.tls_serialize_detached().expect("e1 commit bytes");
    let e1_welcome_bytes = e1_welcome
        .tls_serialize_detached()
        .expect("e1 welcome bytes");
    assert_eq!(
        hex::encode(&e1_commit_bytes),
        pinned.epoch1_add_bob_commit_hex
    );
    assert_eq!(
        hex::encode(&e1_welcome_bytes),
        pinned.epoch1_welcome_bob_hex
    );
    assert_eq!(e1_auth_hex, pinned.epoch1_authenticator_hex);

    let pinned_e1_welcome = hex::decode(&pinned.epoch1_welcome_bob_hex).expect("e1 welcome hex");
    let MlsMessageBodyIn::Welcome(welcome_bob) =
        MlsMessageIn::tls_deserialize_exact(&pinned_e1_welcome)
            .expect("parse e1 welcome")
            .extract()
    else {
        panic!("expected Welcome");
    };
    let mut bob_group =
        build_staged_welcome_at(&bob_p, &join_cfg, welcome_bob, None, VECTOR_NOW_SECS)
            .expect("stage bob welcome")
            .into_group(&bob_p)
            .expect("bob into_group");
    assert_eq!(
        hex::encode(bob_group.epoch_authenticator().as_slice()),
        pinned.epoch1_authenticator_hex
    );

    let e1_secret_alice = alice_group
        .export_secret(alice_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-1", 32)
        .expect("export e1 alice");
    assert_eq!(
        hex::encode(&e1_secret_alice),
        pinned.epoch1_exporter_secret_hex
    );
    assert_eq!(
        bob_group
            .export_secret(bob_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-1", 32)
            .unwrap(),
        e1_secret_alice
    );

    let app_plain = hex::decode(&pinned.epoch1_alice_app_plaintext_hex).expect("app plain hex");
    let app_out = alice_group
        .create_message(&alice_p, &alice_sig, &app_plain)
        .expect("create e1 app message");
    let app_wire = app_out.tls_serialize_detached().expect("app wire");
    assert_eq!(
        hex::encode(&app_wire),
        pinned.epoch1_alice_app_ciphertext_hex
    );

    // Negative control: 1-bit flip on PrivateMessage ciphertext must fail AEAD authentication
    // on an isolated snapshot of Bob's epoch-1 storage (preserving generation 0 on `bob_group`).
    let bob_e1_snapshot = MemoryStorage {
        values: RwLock::new(bob_p.storage().values.read().unwrap().clone()),
    };
    let bob_tamper_p = SeededOpenMlsCryptoProvider::with_storage(
        Arc::new(ChaChaSimEntropy::from_seed(0x004D_9998, b"tamper-app")),
        bob_e1_snapshot,
    );
    let mut bob_tamper_group = MlsGroup::load(
        bob_tamper_p.storage(),
        &GroupId::from_slice(&group_id_bytes),
    )
    .expect("load bob snapshot")
    .expect("bob group exists");
    let mut bad_app_wire = app_wire.clone();
    let app_last = bad_app_wire.len() - 1;
    bad_app_wire[app_last] ^= 0x01;
    if let Ok(bad_msg) = MlsMessageIn::tls_deserialize_exact(&bad_app_wire) {
        if let MlsMessageBodyIn::PrivateMessage(bad_priv) = bad_msg.extract() {
            assert!(bob_tamper_group
                .process_message(&bob_tamper_p, bad_priv)
                .is_err());
        }
    }

    let MlsMessageBodyIn::PrivateMessage(priv_in) = MlsMessageIn::tls_deserialize_exact(&app_wire)
        .expect("parse app wire")
        .extract()
    else {
        panic!("expected PrivateMessage");
    };
    let processed_app = bob_group
        .process_message(&bob_p, priv_in)
        .expect("bob decrypt app message");
    match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), app_plain);
        }
        other => panic!("expected ApplicationMessage, got {other:?}"),
    }

    let carol_kp_verified = validate_key_package_at(
        KeyPackageIn::tls_deserialize_exact(&carol_kp_bytes).expect("parse carol kp"),
        alice_p.crypto(),
        ProtocolVersion::Mls10,
        VECTOR_NOW_SECS,
    )
    .expect("validate carol kp");
    let (e2_commit, e2_welcome, _) = alice_group
        .add_members(&alice_p, &alice_sig, &[carol_kp_verified])
        .expect("add carol");
    alice_group
        .merge_pending_commit(&alice_p)
        .expect("alice merge e2");
    let e2_auth_hex = hex::encode(alice_group.epoch_authenticator().as_slice());
    let e2_commit_bytes = e2_commit.tls_serialize_detached().expect("e2 commit bytes");
    let e2_welcome_bytes = e2_welcome
        .tls_serialize_detached()
        .expect("e2 welcome bytes");
    assert_eq!(
        hex::encode(&e2_commit_bytes),
        pinned.epoch2_add_carol_commit_hex
    );
    assert_eq!(
        hex::encode(&e2_welcome_bytes),
        pinned.epoch2_welcome_carol_hex
    );
    assert_eq!(e2_auth_hex, pinned.epoch2_authenticator_hex);

    apply_commit_wire(&mut bob_group, &bob_p, &e2_commit_bytes);
    let MlsMessageBodyIn::Welcome(welcome_carol) =
        MlsMessageIn::tls_deserialize_exact(&e2_welcome_bytes)
            .expect("parse e2 welcome")
            .extract()
    else {
        panic!("expected Welcome");
    };
    let mut carol_group =
        build_staged_welcome_at(&carol_p, &join_cfg, welcome_carol, None, VECTOR_NOW_SECS)
            .expect("stage carol welcome")
            .into_group(&carol_p)
            .expect("carol into_group");
    assert_eq!(
        hex::encode(bob_group.epoch_authenticator().as_slice()),
        pinned.epoch2_authenticator_hex
    );
    assert_eq!(
        hex::encode(carol_group.epoch_authenticator().as_slice()),
        pinned.epoch2_authenticator_hex
    );

    let e2_secret = alice_group
        .export_secret(alice_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-2", 32)
        .expect("export e2");
    assert_eq!(hex::encode(&e2_secret), pinned.epoch2_exporter_secret_hex);
    assert_eq!(
        bob_group
            .export_secret(bob_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-2", 32)
            .unwrap(),
        e2_secret
    );
    assert_eq!(
        carol_group
            .export_secret(carol_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-2", 32)
            .unwrap(),
        e2_secret
    );

    // Epoch 3: Consume pinned 2-level 0x004D X-Wing UpdatePath Commit from Bob on both Alice & Carol.
    let e3_commit_bytes =
        hex::decode(&pinned.epoch3_bob_self_update_commit_hex).expect("e3 commit hex");
    assert!(e3_commit_bytes.len() > 6_000);

    // Negative control at Epoch 2: 1-bit flip in UpdatePath commit ciphertext must fail on clone.
    let alice_e2_snapshot = MemoryStorage {
        values: RwLock::new(alice_p.storage().values.read().unwrap().clone()),
    };
    let alice_tamper_p = SeededOpenMlsCryptoProvider::with_storage(
        Arc::new(ChaChaSimEntropy::from_seed(0x004D_9999, b"tamper")),
        alice_e2_snapshot,
    );
    let mut alice_tamper_group = MlsGroup::load(
        alice_tamper_p.storage(),
        &GroupId::from_slice(&group_id_bytes),
    )
    .expect("load snapshot")
    .expect("group exists");
    let mut tampered_e3 = e3_commit_bytes.clone();
    let mid = tampered_e3.len() / 2;
    tampered_e3[mid] ^= 0x40;
    if let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(&tampered_e3) {
        match msg_in.extract() {
            MlsMessageBodyIn::PrivateMessage(pm) => {
                assert!(alice_tamper_group
                    .process_message(&alice_tamper_p, pm)
                    .is_err());
            }
            MlsMessageBodyIn::PublicMessage(pm) => {
                assert!(alice_tamper_group
                    .process_message(&alice_tamper_p, pm)
                    .is_err());
            }
            _ => {}
        }
    }

    apply_commit_wire(&mut alice_group, &alice_p, &e3_commit_bytes);
    apply_commit_wire(&mut carol_group, &carol_p, &e3_commit_bytes);
    assert_eq!(alice_group.epoch().as_u64(), 3);
    assert_eq!(carol_group.epoch().as_u64(), 3);
    assert_eq!(
        hex::encode(alice_group.epoch_authenticator().as_slice()),
        pinned.epoch3_authenticator_hex
    );
    assert_eq!(
        hex::encode(carol_group.epoch_authenticator().as_slice()),
        pinned.epoch3_authenticator_hex
    );
    let e3_secret_alice = alice_group
        .export_secret(alice_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-3", 32)
        .expect("export e3 alice");
    let e3_secret_carol = carol_group
        .export_secret(carol_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-3", 32)
        .expect("export e3 carol");
    assert_eq!(
        hex::encode(&e3_secret_alice),
        pinned.epoch3_exporter_secret_hex
    );
    assert_eq!(e3_secret_alice, e3_secret_carol);

    // Epoch 4: Consume pinned 0x004D X-Wing Remove(Bob) Commit from Alice on Carol.
    let e4_commit_bytes =
        hex::decode(&pinned.epoch4_alice_remove_bob_commit_hex).expect("e4 commit hex");
    assert!(e4_commit_bytes.len() > 3_500);
    apply_commit_wire(&mut carol_group, &carol_p, &e4_commit_bytes);
    assert_eq!(carol_group.epoch().as_u64(), 4);
    assert_eq!(carol_group.members().count(), 2);
    assert_eq!(
        hex::encode(carol_group.epoch_authenticator().as_slice()),
        pinned.epoch4_authenticator_hex
    );
    let e4_secret_carol = carol_group
        .export_secret(carol_p.crypto(), "catbird-xwing-0x004d-kat", b"epoch-4", 32)
        .expect("export e4 carol");
    assert_eq!(
        hex::encode(&e4_secret_carol),
        pinned.epoch4_exporter_secret_hex
    );
}

#[test]
fn openmls_0x004d_pinned_protocol_wire_vectors_and_tamper_rejection() {
    let raw = load_verified_vector_bytes("openmls_0x004d_protocol_vectors.json");
    let pinned: OpenMls0x004dProtocolVectors =
        serde_json::from_slice(&raw).expect("parse pinned 0x004D protocol vectors");
    assert_eq!(pinned.cipher_suite, 0x004D);

    // 1. Replay pinned 0x004D wire vectors across Epochs 0..4 and assert cryptographic parity.
    verify_pinned_0x004d_protocol_transcript(&pinned);

    // 2. Independently decode and validate pinned KeyPackage + negative signature tamper control.
    let crypto = LibcruxCryptoProvider::new().expect("libcrux crypto provider");
    let bob_kp_wire = hex::decode(&pinned.bob_key_package_hex).expect("bob kp hex");
    let bob_kp = validate_key_package_at(
        KeyPackageIn::tls_deserialize_exact(&bob_kp_wire).expect("bob kp parse"),
        &crypto,
        ProtocolVersion::Mls10,
        VECTOR_NOW_SECS,
    )
    .expect("bob kp valid");
    assert_eq!(bob_kp.ciphersuite(), SUITE_0X004D);
    assert_eq!(bob_kp.hpke_init_key().as_slice().len(), 1216);
    let enc_key_wire = bob_kp
        .leaf_node()
        .encryption_key()
        .tls_serialize_detached()
        .expect("serialize leaf encryption key");
    assert!(enc_key_wire.len() > 1216);

    let mut tampered_kp = bob_kp_wire.clone();
    let last = tampered_kp.len() - 1;
    tampered_kp[last] ^= 0x01;
    if let Ok(kp_in) = KeyPackageIn::tls_deserialize_exact(&tampered_kp) {
        assert!(
            validate_key_package_at(kp_in, &crypto, ProtocolVersion::Mls10, VECTOR_NOW_SECS)
                .is_err(),
            "tampered KeyPackage signature must be rejected"
        );
    }
}
