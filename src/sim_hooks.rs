//! Pure-Rust deterministic clock, entropy, OpenMLS crypto/rand provider,
//! `I6` autocommit transaction probe, and `buggify!` fault-injection seams
//! for the Catbird MLS Hydrostatic Pressure Tank (`catbird-sim`).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{SecondsFormat, TimeZone, Utc};
use hpke_rs_crypto::{
    error::Error as HpkeCryptoError,
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    HpkeCrypto, HpkeTestRng, TryCryptoRng, TryRng,
};
use hpke_rs_libcrux::HpkeLibcrux;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};
use openmls_traits::OpenMlsProvider;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use tls_codec::SecretVLBytes;
use zeroize::Zeroize;

use crate::error::MLSError;

/// Initial canonical `buggify!` fault-injection site identifiers.
pub const INITIAL_BUGGIFY_SITES: &[&str] = &[
    "after_http_2xx_before_db_commit",
    "between_labyrinth_enqueue_and_flush",
    "before_wal_passive_checkpoint",
];

// ---------------------------------------------------------------------------
// SimClock
// ---------------------------------------------------------------------------

/// Format Unix epoch milliseconds as canonical `YYYY-MM-DDTHH:MM:SS.sssZ`.
pub fn format_ms_rfc3339_millis(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(|| Utc.timestamp_millis_opt(0).single().expect("epoch 0 valid"))
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Deterministic or wall-clock time source for [`crate::client::CatbirdMlsClient`].
pub trait SimClock: Send + Sync {
    /// Current Unix timestamp in milliseconds.
    fn now_ms(&self) -> i64;

    /// Current Unix timestamp in whole seconds.
    fn now_secs(&self) -> u64 {
        (self.now_ms().max(0) as u64) / 1_000
    }

    /// Current UTC timestamp formatted as millisecond-precision RFC 3339 (`...Z`).
    fn now_rfc3339_millis(&self) -> String {
        format_ms_rfc3339_millis(self.now_ms())
    }
}

/// Production wall-clock implementation backed by [`chrono::Utc::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SimClock for SystemClock {
    fn now_ms(&self) -> i64 {
        Utc::now().timestamp_millis()
    }
}

/// Deterministic monotonically advancing clock for simulation tests.
#[derive(Debug)]
pub struct FixedStepClock {
    next_ms: AtomicI64,
    step_ms: i64,
}

impl FixedStepClock {
    pub fn new(start_ms: i64, step_ms: i64) -> Self {
        Self {
            next_ms: AtomicI64::new(start_ms),
            step_ms,
        }
    }

    /// Inspect the next timestamp without advancing the counter.
    pub fn peek_ms(&self) -> i64 {
        self.next_ms.load(Ordering::SeqCst)
    }

    /// Advance the clock by `delta_ms` and return the new timestamp.
    pub fn advance_ms(&self, delta_ms: i64) -> i64 {
        self.next_ms.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
    }
}

impl SimClock for FixedStepClock {
    fn now_ms(&self) -> i64 {
        self.next_ms.fetch_add(self.step_ms, Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// SimEntropy
// ---------------------------------------------------------------------------

/// Deterministic or OS CSPRNG byte source for [`crate::client::CatbirdMlsClient`].
pub trait SimEntropy: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]);
}

/// Production OS CSPRNG entropy source (`rand::rngs::OsRng`).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsSimEntropy;

impl SimEntropy for OsSimEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(dest);
    }
}

/// Seeded `ChaCha20` deterministic CSPRNG with domain-separated `(seed, label)` derivation.
pub struct ChaChaSimEntropy {
    rng: Mutex<ChaCha20Rng>,
}

impl fmt::Debug for ChaChaSimEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaChaSimEntropy").finish_non_exhaustive()
    }
}

impl ChaChaSimEntropy {
    pub fn from_seed(seed: u64, label: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"catbird-sim-entropy-v1\0");
        hasher.update(seed.to_le_bytes());
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        let seed_bytes: [u8; 32] = hasher.finalize().into();
        Self {
            rng: Mutex::new(ChaCha20Rng::from_seed(seed_bytes)),
        }
    }
}

impl SimEntropy for ChaChaSimEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        self.rng
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fill_bytes(dest);
    }
}

/// Draw a fixed-size random byte array from a [`SimEntropy`] source.
pub fn sim_random_array<const N: usize>(entropy: &dyn SimEntropy) -> [u8; N] {
    let mut out = [0u8; N];
    entropy.fill_bytes(&mut out);
    out
}

/// Draw a deterministic RFC 4122 UUIDv4 from a [`SimEntropy`] source.
pub fn sim_uuid_v4(entropy: &dyn SimEntropy) -> uuid::Uuid {
    let mut bytes = sim_random_array::<16>(entropy);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

/// Draw an RFC 4122 UUIDv4 from an [`OpenMlsRand`] provider.
pub fn openmls_rand_uuid_v4<R: OpenMlsRand>(rand: &R) -> Result<uuid::Uuid, MLSError> {
    let mut bytes: [u8; 16] = rand
        .random_array()
        .map_err(|e| MLSError::Cryptography(format!("OpenMlsRand uuid_v4 failed: {e:?}")))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes))
}

/// Deterministically generate an OpenMLS `SignatureKeyPair` from [`SimEntropy`].
pub fn sim_signature_keypair(
    entropy: &dyn SimEntropy,
    scheme: SignatureScheme,
) -> Result<SignatureKeyPair, MLSError> {
    match scheme {
        SignatureScheme::ED25519 => {
            for _ in 0..100 {
                let mut sk = [0u8; 32];
                entropy.fill_bytes(&mut sk);
                if sk.iter().any(|&b| b != 0) {
                    let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
                    let pk = signing.verifying_key().to_bytes().to_vec();
                    let sk_vec = sk.to_vec();
                    sk.zeroize();
                    return Ok(SignatureKeyPair::from_raw(scheme, sk_vec, pk));
                }
            }
            Err(MLSError::Cryptography(
                "SimEntropy produced 100 consecutive all-zero Ed25519 keys".to_string(),
            ))
        }
        other => Err(MLSError::Cryptography(format!(
            "unsupported signature scheme for deterministic keygen: {other:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// SimClientHooks & TxAutocommitProbe (`I6`)
// ---------------------------------------------------------------------------

/// Clock + entropy bundle injected into [`crate::client::CatbirdMlsClient::open_with_hooks`].
#[derive(Clone)]
pub struct SimClientHooks {
    pub clock: Arc<dyn SimClock>,
    pub entropy: Arc<dyn SimEntropy>,
}

impl fmt::Debug for SimClientHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimClientHooks").finish_non_exhaustive()
    }
}

impl Default for SimClientHooks {
    fn default() -> Self {
        Self::system_default()
    }
}

impl SimClientHooks {
    pub fn system_default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            entropy: Arc::new(OsSimEntropy),
        }
    }

    pub fn new(clock: Arc<dyn SimClock>, entropy: Arc<dyn SimEntropy>) -> Self {
        Self { clock, entropy }
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    pub fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    pub fn now_rfc3339_millis(&self) -> String {
        self.clock.now_rfc3339_millis()
    }

    pub fn fill_bytes(&self, dest: &mut [u8]) {
        self.entropy.fill_bytes(dest);
    }

    pub fn random_array<const N: usize>(&self) -> [u8; N] {
        sim_random_array(self.entropy.as_ref())
    }

    pub fn uuid_v4(&self) -> uuid::Uuid {
        sim_uuid_v4(self.entropy.as_ref())
    }

    pub fn signature_keypair(&self, scheme: SignatureScheme) -> Result<SignatureKeyPair, MLSError> {
        sim_signature_keypair(self.entropy.as_ref(), scheme)
    }

    pub fn openmls_provider<S>(&self, storage: S) -> SeededOpenMlsCryptoProvider<S> {
        SeededOpenMlsCryptoProvider::with_storage(Arc::clone(&self.entropy), storage)
    }

    /// Execute `f` with Labyrinth's CSPRNG routed strictly through `self.entropy`.
    #[cfg(feature = "labyrinth")]
    pub fn with_labyrinth_rng<T>(&self, f: impl FnOnce() -> T) -> T {
        let entropy = Arc::clone(&self.entropy);
        let hook: labyrinth::encoding::RandomFillHook = Arc::new(move |out: &mut [u8]| {
            entropy.fill_bytes(out);
            Ok(())
        });
        labyrinth::encoding::with_random_hook(hook, f)
    }

    /// No-op passthrough when the `labyrinth` feature is disabled.
    #[cfg(not(feature = "labyrinth"))]
    pub fn with_labyrinth_rng<T>(&self, f: impl FnOnce() -> T) -> T {
        f()
    }
}

/// Shareable probe allowing `SimTransport::execute_http` to assert that no SQLite
/// transaction is active on the calling device (`Spec §5 I6`, Oracle `O1`).
#[derive(Clone)]
pub struct TxAutocommitProbe {
    is_in_tx: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl fmt::Debug for TxAutocommitProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxAutocommitProbe")
            .field("is_in_transaction", &self.is_in_transaction())
            .finish()
    }
}

impl TxAutocommitProbe {
    pub fn new(is_in_tx: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self { is_in_tx }
    }

    pub fn is_in_transaction(&self) -> bool {
        (self.is_in_tx)()
    }
}

// ---------------------------------------------------------------------------
// SeededOpenMlsCryptoProvider
// ---------------------------------------------------------------------------

/// Error type for [`SimOpenMlsRand`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimRandError;

impl fmt::Display for SimRandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SimOpenMlsRand error")
    }
}

impl std::error::Error for SimRandError {}

/// [`OpenMlsRand`] adapter backed strictly by [`SimEntropy`].
#[derive(Clone)]
pub struct SimOpenMlsRand {
    entropy: Arc<dyn SimEntropy>,
}

impl fmt::Debug for SimOpenMlsRand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimOpenMlsRand").finish_non_exhaustive()
    }
}

impl SimOpenMlsRand {
    pub fn new(entropy: Arc<dyn SimEntropy>) -> Self {
        Self { entropy }
    }
}

impl OpenMlsRand for SimOpenMlsRand {
    type Error = SimRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        self.entropy.fill_bytes(&mut out);
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        self.entropy.fill_bytes(&mut out);
        Ok(out)
    }
}

thread_local! {
    static ACTIVE_HPKE_ENTROPY: RefCell<Option<Arc<dyn SimEntropy>>> = const { RefCell::new(None) };
}

fn with_active_hpke_entropy<T>(entropy: &Arc<dyn SimEntropy>, f: impl FnOnce() -> T) -> T {
    struct Guard(Option<Arc<dyn SimEntropy>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            let prev = self.0.take();
            ACTIVE_HPKE_ENTROPY.with(|slot| {
                *slot.borrow_mut() = prev;
            });
        }
    }
    let prev = ACTIVE_HPKE_ENTROPY.with(|slot| slot.borrow_mut().replace(Arc::clone(entropy)));
    let _guard = Guard(prev);
    f()
}

struct SimHpkePrng {
    entropy: Arc<dyn SimEntropy>,
}

impl Zeroize for SimHpkePrng {
    fn zeroize(&mut self) {}
}

impl TryCryptoRng for SimHpkePrng {}

impl TryRng for SimHpkePrng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.entropy.fill_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.entropy.fill_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.entropy.fill_bytes(dst);
        Ok(())
    }
}

impl HpkeTestRng for SimHpkePrng {
    type Error = HpkeCryptoError;

    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.entropy.fill_bytes(dest);
        Ok(())
    }

    fn seed(&mut self, _seed: &[u8]) {}
}

#[derive(Debug)]
struct SimHpkeLibcrux;

impl HpkeCrypto for SimHpkeLibcrux {
    type HpkePrng = SimHpkePrng;

    fn name() -> String {
        "SimHpkeLibcrux".to_string()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::supports_kdf(alg)
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::supports_kem(alg)
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::supports_aead(alg)
    }

    fn prng() -> Self::HpkePrng {
        let entropy = ACTIVE_HPKE_ENTROPY
            .with(|slot| slot.borrow().clone())
            .unwrap_or_else(|| Arc::new(OsSimEntropy));
        SimHpkePrng { entropy }
    }

    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::kdf_extract(alg, salt, ikm)
    }

    fn kdf_expand(
        alg: KdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::kdf_expand(alg, prk, info, output_size)
    }

    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::dh(alg, pk, sk)
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::secret_to_public(alg, sk)
    }

    fn kem_key_gen(
        alg: KemAlgorithm,
        prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeCryptoError> {
        match alg {
            KemAlgorithm::XWingDraft06 => {
                libcrux_kem::key_gen(libcrux_kem::Algorithm::XWingKemDraft06, prng)
                    .map(|(sk, pk)| (pk.encode(), sk.encode()))
                    .map_err(|e| {
                        HpkeCryptoError::CryptoLibraryError(format!("KEM key gen error: {e:?}"))
                    })
            }
            KemAlgorithm::DhKem25519 => {
                let sk = libcrux_ecdh::generate_secret(libcrux_ecdh::Algorithm::X25519, prng)
                    .map_err(|e| {
                        HpkeCryptoError::CryptoLibraryError(format!("ECDH key gen error: {e:?}"))
                    })?;
                let pk = <HpkeLibcrux as HpkeCrypto>::secret_to_public(alg, &sk)?;
                Ok((pk, sk))
            }
            KemAlgorithm::DhKemP256 => {
                let sk = libcrux_ecdh::generate_secret(libcrux_ecdh::Algorithm::P256, prng)
                    .map_err(|e| {
                        HpkeCryptoError::CryptoLibraryError(format!("ECDH key gen error: {e:?}"))
                    })?;
                let pk = <HpkeLibcrux as HpkeCrypto>::secret_to_public(alg, &sk)?;
                Ok((pk, sk))
            }
            _ => Err(HpkeCryptoError::UnknownKemAlgorithm),
        }
    }

    fn kem_key_gen_derand(
        alg: KemAlgorithm,
        seed: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::kem_key_gen_derand(alg, seed)
    }

    fn kem_encaps(
        alg: KemAlgorithm,
        pk_r: &[u8],
        prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), HpkeCryptoError> {
        let kem_alg = match alg {
            KemAlgorithm::DhKem25519 => libcrux_kem::Algorithm::X25519,
            KemAlgorithm::DhKemP256 => libcrux_kem::Algorithm::Secp256r1,
            KemAlgorithm::XWingDraft06 => libcrux_kem::Algorithm::XWingKemDraft06,
            _ => return Err(HpkeCryptoError::UnknownKemAlgorithm),
        };
        let pk = libcrux_kem::PublicKey::decode(kem_alg, pk_r)
            .map_err(|_| HpkeCryptoError::KemInvalidPublicKey)?;
        pk.encapsulate(prng)
            .map_err(|e| HpkeCryptoError::CryptoLibraryError(format!("Encaps error: {e:?}")))
            .map(|(ss, ct)| (ss.encode(), ct.encode()))
    }

    fn kem_decaps(alg: KemAlgorithm, ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::kem_decaps(alg, ct, sk_r)
    }

    fn dh_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::dh_validate_sk(alg, sk)
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::aead_seal(alg, key, nonce, aad, msg)
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, HpkeCryptoError> {
        <HpkeLibcrux as HpkeCrypto>::aead_open(alg, key, nonce, aad, msg)
    }
}

fn shared_stateless_libcrux() -> Result<&'static LibcruxCryptoProvider, CryptoError> {
    static INSTANCE: OnceLock<Option<LibcruxCryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| LibcruxCryptoProvider::new().ok())
        .as_ref()
        .ok_or(CryptoError::InsufficientRandomness)
}

fn map_hpke_config(config: HpkeConfig) -> hpke_rs::Hpke<SimHpkeLibcrux> {
    let kem = match config.0 {
        HpkeKemType::DhKemP256 => KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => KemAlgorithm::DhKem448,
        HpkeKemType::XWingKemDraft6 => KemAlgorithm::XWingDraft06,
        HpkeKemType::MlKem768 => KemAlgorithm::MlKem768,
        HpkeKemType::MlKem1024 => KemAlgorithm::MlKem1024,
    };
    let kdf = match config.1 {
        HpkeKdfType::HkdfSha256 => KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => KdfAlgorithm::HkdfSha512,
    };
    let aead = match config.2 {
        HpkeAeadType::AesGcm128 => AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => AeadAlgorithm::HpkeExport,
    };
    hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead)
}

/// Deterministic [`OpenMlsCrypto`] provider delegating pure primitives to `libcrux`
/// while routing every keygen and HPKE encapsulation strictly through [`SimEntropy`].
#[derive(Clone)]
pub struct SeededOpenMlsCrypto {
    entropy: Arc<dyn SimEntropy>,
}

impl fmt::Debug for SeededOpenMlsCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeededOpenMlsCrypto")
            .finish_non_exhaustive()
    }
}

impl SeededOpenMlsCrypto {
    pub fn new(entropy: Arc<dyn SimEntropy>) -> Self {
        Self { entropy }
    }
}

impl OpenMlsCrypto for SeededOpenMlsCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        shared_stateless_libcrux()?.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        shared_stateless_libcrux()
            .map(|c| c.supported_ciphersuites())
            .unwrap_or_default()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        shared_stateless_libcrux()?.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        shared_stateless_libcrux()?.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        shared_stateless_libcrux()?.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shared_stateless_libcrux()?.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        shared_stateless_libcrux()?.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        shared_stateless_libcrux()?.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        let mut sk = [0u8; 32];
        for _ in 0..100 {
            self.entropy.fill_bytes(&mut sk);
            if sk.iter().any(|&b| b != 0) {
                let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
                let pk = signing.verifying_key().to_bytes().to_vec();
                let sk_vec = sk.to_vec();
                sk.zeroize();
                return Ok((sk_vec, pk));
            }
        }
        Err(CryptoError::InsufficientRandomness)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        shared_stateless_libcrux()?.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        shared_stateless_libcrux()?.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        with_active_hpke_entropy(&self.entropy, || {
            let mut hpke = map_hpke_config(config);
            let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());
            let (kem_output, ciphertext) = hpke
                .seal(&pk_r, info, aad, ptxt, None, None, None)
                .map_err(|e| match e {
                    hpke_rs::HpkeError::InvalidConfig => CryptoError::SenderSetupError,
                    _ => CryptoError::HpkeEncryptionError,
                })?;
            Ok(HpkeCiphertext {
                kem_output: kem_output.into(),
                ciphertext: ciphertext.into(),
            })
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        shared_stateless_libcrux()?.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        with_active_hpke_entropy(&self.entropy, || {
            let mut hpke = map_hpke_config(config);
            let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());
            let (enc, ctx) = hpke
                .setup_sender(&pk_r, info, None, None, None)
                .map_err(|_| CryptoError::SenderSetupError)?;
            ctx.export(exporter_context, exporter_length)
                .map_err(|_| CryptoError::ExporterError)
                .map(|exported| (enc, exported.into()))
        })
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        shared_stateless_libcrux()?.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        shared_stateless_libcrux()?.derive_hpke_keypair(config, ikm)
    }
}

/// [`OpenMlsProvider`] implementation whose [`OpenMlsRand`] and [`OpenMlsCrypto`]
/// draw all randomness strictly from an injected [`SimEntropy`] handle.
pub struct SeededOpenMlsCryptoProvider<S = MemoryStorage> {
    crypto: SeededOpenMlsCrypto,
    rand: SimOpenMlsRand,
    storage: S,
}

impl<S: fmt::Debug> fmt::Debug for SeededOpenMlsCryptoProvider<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeededOpenMlsCryptoProvider")
            .field("storage", &self.storage)
            .finish_non_exhaustive()
    }
}

impl SeededOpenMlsCryptoProvider<MemoryStorage> {
    pub fn new(entropy: Arc<dyn SimEntropy>) -> Self {
        Self::with_storage(entropy, MemoryStorage::default())
    }

    pub fn in_memory(entropy: Arc<dyn SimEntropy>) -> Self {
        Self::new(entropy)
    }
}

impl<S> SeededOpenMlsCryptoProvider<S> {
    pub fn with_storage(entropy: Arc<dyn SimEntropy>, storage: S) -> Self {
        Self {
            crypto: SeededOpenMlsCrypto::new(Arc::clone(&entropy)),
            rand: SimOpenMlsRand::new(entropy),
            storage,
        }
    }

    pub fn into_storage(self) -> S {
        self.storage
    }
}

impl<S: StorageProvider<CURRENT_VERSION>> OpenMlsProvider for SeededOpenMlsCryptoProvider<S> {
    type CryptoProvider = SeededOpenMlsCrypto;
    type RandProvider = SimOpenMlsRand;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

// ---------------------------------------------------------------------------
// BUGGIFY Controller & Macro
// ---------------------------------------------------------------------------

enum BuggifyPolicy {
    EnabledSites(BTreeSet<String>),
    SeededProbability {
        entropy: Box<ChaChaSimEntropy>,
        probability_ppm: u32,
    },
}

/// Thread-local fault-injection controller consulted by [`crate::buggify!`]
/// when compiled with `feature = "sim"`.
pub struct BuggifyController {
    policy: BuggifyPolicy,
    hit_counts: BTreeMap<String, u64>,
}

impl fmt::Debug for BuggifyController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuggifyController")
            .field("hit_counts", &self.hit_counts)
            .finish_non_exhaustive()
    }
}

thread_local! {
    static BUGGIFY_CONTROLLER: RefCell<Option<BuggifyController>> = const { RefCell::new(None) };
}

/// RAII guard restoring the previous thread-local [`BuggifyController`] on drop.
pub struct BuggifyGuard {
    prev: Option<BuggifyController>,
}

impl Drop for BuggifyGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        BUGGIFY_CONTROLLER.with(|slot| {
            *slot.borrow_mut() = prev;
        });
    }
}

impl BuggifyController {
    /// Create a controller that deterministically fires whenever any site in `sites` is evaluated.
    pub fn enabled_sites(sites: &[&str]) -> Self {
        Self {
            policy: BTreeSet::from_iter(sites.iter().map(|s| (*s).to_string())).into(),
            hit_counts: BTreeMap::new(),
        }
    }

    /// Create a swarm controller firing with `probability_ppm / 1_000_000` driven by `seed`.
    pub fn seeded_probability(seed: u64, probability_ppm: u32) -> Self {
        Self {
            policy: BuggifyPolicy::SeededProbability {
                entropy: Box::new(ChaChaSimEntropy::from_seed(seed, b"buggify-controller")),
                probability_ppm: probability_ppm.min(1_000_000),
            },
            hit_counts: BTreeMap::new(),
        }
    }

    /// Install `self` on the current thread until the returned [`BuggifyGuard`] drops.
    pub fn install(self) -> BuggifyGuard {
        let prev = BUGGIFY_CONTROLLER.with(|slot| slot.borrow_mut().replace(self));
        BuggifyGuard { prev }
    }

    /// Run `f` with deterministic firing enabled for `sites` on the current thread.
    pub fn with_enabled_sites<R>(sites: &[&str], f: impl FnOnce() -> R) -> R {
        let _guard = Self::enabled_sites(sites).install();
        f()
    }

    /// Run `f` with seeded probabilistic firing (`probability_ppm / 1_000_000`), returning
    /// `(result, hit_counts_by_site)`.
    pub fn with_seeded_probability<R>(
        seed: u64,
        probability_ppm: u32,
        f: impl FnOnce() -> R,
    ) -> (R, BTreeMap<String, u64>) {
        let prev = BUGGIFY_CONTROLLER.with(|slot| {
            slot.borrow_mut()
                .replace(Self::seeded_probability(seed, probability_ppm))
        });
        struct Restore(Option<BuggifyController>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let prev = self.0.take();
                BUGGIFY_CONTROLLER.with(|slot| {
                    *slot.borrow_mut() = prev;
                });
            }
        }
        let mut restore = Restore(prev);
        let out = f();
        let counts = BUGGIFY_CONTROLLER.with(|slot| {
            let prev_inner = restore.0.take();
            let finished = std::mem::replace(&mut *slot.borrow_mut(), prev_inner);
            finished.map(|c| c.hit_counts).unwrap_or_default()
        });
        (out, counts)
    }

    /// Snapshot hit counts recorded on the current thread's active controller.
    pub fn hit_counts() -> BTreeMap<String, u64> {
        BUGGIFY_CONTROLLER.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|c| c.hit_counts.clone())
                .unwrap_or_default()
        })
    }

    /// Evaluate whether `site` fires on the current thread.
    pub fn should_fire(site: &'static str) -> bool {
        BUGGIFY_CONTROLLER.with(|slot| {
            let mut borrow = slot.borrow_mut();
            let Some(ctrl) = borrow.as_mut() else {
                return false;
            };
            let fired = match &ctrl.policy {
                BuggifyPolicy::EnabledSites(set) => set.contains(site),
                BuggifyPolicy::SeededProbability {
                    entropy,
                    probability_ppm,
                } => {
                    if *probability_ppm == 0 {
                        false
                    } else if *probability_ppm >= 1_000_000 {
                        true
                    } else {
                        let mut b = [0u8; 4];
                        entropy.fill_bytes(&mut b);
                        (u32::from_le_bytes(b) % 1_000_000) < *probability_ppm
                    }
                }
            };
            if fired {
                *ctrl.hit_counts.entry(site.to_string()).or_insert(0) += 1;
            }
            fired
        })
    }
}

impl From<BTreeSet<String>> for BuggifyPolicy {
    fn from(set: BTreeSet<String>) -> Self {
        Self::EnabledSites(set)
    }
}

/// Fault-injection hook point. Compiles to `false` unless `feature = "sim"` is enabled
/// and a thread-local [`BuggifyController`] fires for `$site`.
#[cfg(feature = "sim")]
#[macro_export]
macro_rules! buggify {
    ($site:literal) => {
        $crate::sim_hooks::BuggifyController::should_fire($site)
    };
}

/// Fault-injection hook point (no-op `false` when `feature = "sim"` is disabled).
#[cfg(not(feature = "sim"))]
#[macro_export]
macro_rules! buggify {
    ($site:literal) => {{
        let _ = $site;
        false
    }};
}
