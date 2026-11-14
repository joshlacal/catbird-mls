#![no_main]

use std::sync::{Arc, OnceLock};

use catbird_mls::sim_hooks::{
    sim_signature_keypair, validate_key_package_at, ChaChaSimEntropy, SeededOpenMlsCryptoProvider,
    SimEntropy,
};
use libfuzzer_sys::fuzz_target;
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

const SUITE_0X004D: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const NOW_SECS: u64 = 1_760_000_000;

fn valid_xwing_key_package_wire() -> &'static Vec<u8> {
    static WIRE: OnceLock<Vec<u8>> = OnceLock::new();
    WIRE.get_or_init(|| {
        let entropy: Arc<dyn SimEntropy> =
            Arc::new(ChaChaSimEntropy::from_seed(0x4D15_0020, b"kp-fuzz-seed"));
        let provider = SeededOpenMlsCryptoProvider::with_storage(
            Arc::clone(&entropy),
            MemoryStorage::default(),
        );
        let sig = sim_signature_keypair(entropy.as_ref(), SignatureScheme::ED25519).expect("sig");
        sig.store(provider.storage()).expect("store");
        let cred = CredentialWithKey {
            credential: BasicCredential::new(b"did:plc:carol#dev1".to_vec()).into(),
            signature_key: sig.public().into(),
        };
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(1_700_000_000, 4_102_444_800))
            .leaf_node_capabilities(
                Capabilities::builder()
                    .ciphersuites(vec![SUITE_0X004D])
                    .build(),
            )
            .build(SUITE_0X004D, &provider, &sig, cred)
            .expect("build xwing kp");
        bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialize kp")
    })
}

fn check_key_package_bytes(crypto: &LibcruxCryptoProvider, bytes: &[u8]) {
    if let Ok(kp_in) = KeyPackageIn::tls_deserialize_exact(bytes) {
        if let Ok(kp) = validate_key_package_at(kp_in, crypto, ProtocolVersion::Mls10, NOW_SECS) {
            let reencoded = kp
                .tls_serialize_detached()
                .expect("validated KeyPackage must re-serialize");
            let kp_in_2 = KeyPackageIn::tls_deserialize_exact(&reencoded)
                .expect("re-serialized KeyPackage must deserialize");
            let kp_2 = validate_key_package_at(kp_in_2, crypto, ProtocolVersion::Mls10, NOW_SECS)
                .expect("re-serialized KeyPackage must re-validate");
            assert_eq!(kp.ciphersuite(), kp_2.ciphersuite());
            assert_eq!(
                kp.hpke_init_key().as_slice(),
                kp_2.hpke_init_key().as_slice()
            );
            if kp.ciphersuite() == SUITE_0X004D {
                assert_eq!(kp.hpke_init_key().as_slice().len(), 1216);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let crypto = LibcruxCryptoProvider::new().expect("libcrux crypto provider");

    // 1. Arbitrary untrusted KeyPackageIn wire bytes.
    check_key_package_bytes(&crypto, data);

    // 2. Differential mutation over a valid 0x004D X-Wing KeyPackage.
    if data.len() >= 3 {
        let base = valid_xwing_key_package_wire();
        if !base.is_empty() {
            let mut mutated = base.clone();
            let off = usize::from(u16::from_be_bytes([data[0], data[1]])) % mutated.len();
            for (dst, &mask) in mutated[off..].iter_mut().zip(data[2..].iter()) {
                *dst ^= mask;
            }
            check_key_package_bytes(&crypto, &mutated);
        }
    }
});
