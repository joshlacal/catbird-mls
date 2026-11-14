#![no_main]

use std::sync::{Arc, OnceLock};

use catbird_mls::client::chat_wire::{json_bytes, verify_next_peer_send_counter};
use catbird_mls::sim_hooks::{
    sim_signature_keypair, ChaChaSimEntropy, SeededOpenMlsCryptoProvider, SimEntropy,
};
use libfuzzer_sys::fuzz_target;
use openmls::prelude::*;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

const SUITE_0X004D: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

struct SeedMessages {
    private_msg: Vec<u8>,
    commit_msg: Vec<u8>,
}

fn seed_messages() -> &'static SeedMessages {
    static SEEDS: OnceLock<SeedMessages> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(0x4D15_0001, b"fuzz-mls-msg"));
        let provider = SeededOpenMlsCryptoProvider::with_storage(
            Arc::clone(&entropy),
            MemoryStorage::default(),
        );
        let alice_sig =
            sim_signature_keypair(entropy.as_ref(), SignatureScheme::ED25519).expect("sig");
        alice_sig.store(provider.storage()).expect("store sig");
        let alice_cred = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:alice#dev1".to_vec()).into(),
            signature_key: alice_sig.public().into(),
        };
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE_0X004D)
            .lifetime(Lifetime::init(1_700_000_000, 4_102_444_800))
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &provider,
            &alice_sig,
            &cfg,
            GroupId::from_slice(&[0x4du8; 32]),
            alice_cred,
        )
        .expect("create group");

        let app_msg = group
            .create_message(&provider, &alice_sig, b"fuzz-seed-payload")
            .expect("create_message");
        let private_msg = app_msg.tls_serialize_detached().expect("serialize app");

        let (commit_out, _, _) = group
            .self_update(&provider, &alice_sig, LeafNodeParameters::default())
            .expect("self_update")
            .into_contents();
        let commit_msg = commit_out
            .tls_serialize_detached()
            .expect("serialize commit");

        SeedMessages {
            private_msg,
            commit_msg,
        }
    })
}

fn check_mls_wire_decode(bytes: &[u8]) {
    if let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(bytes) {
        let reencoded = msg_in
            .tls_serialize_detached()
            .expect("deserialized MlsMessageIn must re-serialize");
        let _ = MlsMessageIn::tls_deserialize_exact(&reencoded)
            .expect("re-serialized MlsMessageIn must parse");

        match msg_in.extract() {
            MlsMessageBodyIn::PublicMessage(pub_msg) => {
                let proto: ProtocolMessage = pub_msg.into();
                let _ = (proto.group_id(), proto.epoch(), proto.content_type());
            }
            MlsMessageBodyIn::PrivateMessage(priv_msg) => {
                let proto: ProtocolMessage = priv_msg.into();
                let _ = (proto.group_id(), proto.epoch(), proto.content_type());
            }
            MlsMessageBodyIn::Welcome(_)
            | MlsMessageBodyIn::GroupInfo(_)
            | MlsMessageBodyIn::KeyPackage(_) => {}
        }
    }

    let mut slice = bytes;
    let _ = MlsMessageIn::tls_deserialize(&mut slice);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }

    // 1. Direct untrusted wire input.
    check_mls_wire_decode(data);

    // 2. Differential mutation over valid 0x004D PrivateMessage and Commit frames.
    if data.len() >= 3 {
        let seeds = seed_messages();
        let base = if (data[0] & 1) == 0 {
            &seeds.private_msg
        } else {
            &seeds.commit_msg
        };
        if !base.is_empty() {
            let mut mutated = base.clone();
            let offset = usize::from(u16::from_be_bytes([data[1], data[2]])) % mutated.len();
            for (dst, &mask) in mutated[offset..].iter_mut().zip(data[3..].iter()) {
                *dst ^= mask;
            }
            check_mls_wire_decode(&mutated);
        }
    }

    // 3. Exercise chat_wire JSON bytes and counter parser on UTF-8 slices.
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            let _ = json_bytes(&val);
        }
        let _ = verify_next_peer_send_counter(Some("42"), data.len() as u64);
    }
});
