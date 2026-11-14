#![no_main]

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use catbird_mls::sim_hooks::{
    build_staged_welcome_at, sim_signature_keypair, ChaChaSimEntropy, SeededOpenMlsCryptoProvider,
    SimEntropy,
};
use libfuzzer_sys::fuzz_target;
use openmls::prelude::*;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

const SUITE_0X004D: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const NOW_SECS: u64 = 1_760_000_000;

struct WelcomeSeed {
    bob_storage_snapshot: HashMap<Vec<u8>, Vec<u8>>,
    welcome_wire: Vec<u8>,
    ratchet_tree_wire: Vec<u8>,
}

fn welcome_seed() -> &'static WelcomeSeed {
    static SEED: OnceLock<WelcomeSeed> = OnceLock::new();
    SEED.get_or_init(|| {
        let alice_entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(0x4D15_0010, b"welcome-alice"));
        let alice_provider = SeededOpenMlsCryptoProvider::with_storage(
            Arc::clone(&alice_entropy),
            MemoryStorage::default(),
        );
        let alice_sig =
            sim_signature_keypair(alice_entropy.as_ref(), SignatureScheme::ED25519).expect("sig");
        alice_sig.store(alice_provider.storage()).expect("store");
        let alice_cred = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:alice#dev1".to_vec()).into(),
            signature_key: alice_sig.public().into(),
        };

        let bob_entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(0x4D15_0011, b"welcome-bob"));
        let bob_provider = SeededOpenMlsCryptoProvider::with_storage(
            Arc::clone(&bob_entropy),
            MemoryStorage::default(),
        );
        let bob_sig =
            sim_signature_keypair(bob_entropy.as_ref(), SignatureScheme::ED25519).expect("sig");
        bob_sig.store(bob_provider.storage()).expect("store");
        let bob_cred = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:bob#dev1".to_vec()).into(),
            signature_key: bob_sig.public().into(),
        };
        let pinned_lifetime = Lifetime::init(1_700_000_000, 4_102_444_800);
        let bob_kp = KeyPackage::builder()
            .key_package_lifetime(pinned_lifetime)
            .leaf_node_capabilities(
                Capabilities::builder()
                    .ciphersuites(vec![SUITE_0X004D])
                    .build(),
            )
            .build(SUITE_0X004D, &bob_provider, &bob_sig, bob_cred)
            .expect("bob kp");

        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE_0X004D)
            .lifetime(pinned_lifetime)
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &alice_provider,
            &alice_sig,
            &cfg,
            GroupId::from_slice(&[0x55u8; 32]),
            alice_cred,
        )
        .expect("alice group");

        let (_, welcome_out, _) = group
            .add_members(&alice_provider, &alice_sig, &[bob_kp.key_package().clone()])
            .expect("add bob");
        group.merge_pending_commit(&alice_provider).expect("merge");

        let welcome_wire = welcome_out.tls_serialize_detached().expect("welcome wire");
        let ratchet_tree_wire = group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .expect("ratchet tree wire");
        let bob_storage_snapshot = bob_provider
            .storage()
            .values
            .read()
            .expect("storage read")
            .clone();

        WelcomeSeed {
            bob_storage_snapshot,
            welcome_wire,
            ratchet_tree_wire,
        }
    })
}

fn try_open_welcome(seed: &WelcomeSeed, welcome_bytes: &[u8], ratchet_tree_bytes: Option<&[u8]>) {
    let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(welcome_bytes) else {
        return;
    };
    let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
        return;
    };
    let rt_opt = match ratchet_tree_bytes {
        Some(raw) => match RatchetTreeIn::tls_deserialize_exact(raw) {
            Ok(rt) => Some(rt),
            Err(_) => return,
        },
        None => None,
    };

    let entropy: Arc<dyn SimEntropy> =
        Arc::new(ChaChaSimEntropy::from_seed(0x4D15_0012, b"welcome-join"));
    let storage = MemoryStorage {
        values: RwLock::new(seed.bob_storage_snapshot.clone()),
    };
    let provider = SeededOpenMlsCryptoProvider::with_storage(entropy, storage);
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    if let Ok(staged) = build_staged_welcome_at(&provider, &join_cfg, welcome, rt_opt, NOW_SECS) {
        let _ = staged.into_group(&provider);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let seed = welcome_seed();

    // 1. Direct untrusted Welcome bytes.
    try_open_welcome(seed, data, None);

    // 2. Split untrusted Welcome + out-of-band RatchetTreeIn bytes.
    if data.len() >= 4 {
        let split = usize::from(u16::from_be_bytes([data[0], data[1]])) % (data.len() - 2);
        let (w_part, rt_part) = data[2..].split_at(split);
        try_open_welcome(seed, w_part, Some(rt_part));
    }

    // 3. Differential mutation over a valid 0x004D X-Wing Welcome + RatchetTree.
    if data.len() >= 4 && !seed.welcome_wire.is_empty() {
        let mut mutated_welcome = seed.welcome_wire.clone();
        let w_off = usize::from(u16::from_be_bytes([data[0], data[1]])) % mutated_welcome.len();
        for (dst, &mask) in mutated_welcome[w_off..].iter_mut().zip(data[2..].iter()) {
            *dst ^= mask;
        }
        try_open_welcome(seed, &mutated_welcome, None);

        if !seed.ratchet_tree_wire.is_empty() {
            let mut mutated_rt = seed.ratchet_tree_wire.clone();
            let rt_off = usize::from(u16::from_be_bytes([data[0], data[1]])) % mutated_rt.len();
            for (dst, &mask) in mutated_rt[rt_off..].iter_mut().zip(data[2..].iter()) {
                *dst ^= mask;
            }
            try_open_welcome(seed, &seed.welcome_wire, Some(&mutated_rt));
        }
    }
});
