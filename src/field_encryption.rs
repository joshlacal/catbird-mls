use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub const PAYLOAD_VERSION_V1: u8 = 1;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const HMAC_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const MIN_PAYLOAD_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

pub const HMAC_SEED: [u8; HMAC_LEN] = [0u8; HMAC_LEN];

#[derive(Debug, thiserror::Error)]
pub enum FieldEncryptionError {
    #[error("unknown payload version: {0}")]
    UnknownVersion(u8),
    #[error("payload too short ({0} bytes, need at least {1})")]
    PayloadTooShort(usize, usize),
    #[error("aead authentication failed")]
    AuthFailed,
    #[error("content root key not set")]
    RootKeyNotSet,
    #[error("invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("hkdf expand failed")]
    KdfFailed,
}

pub fn derive_content_key(
    root_key: &[u8],
    conversation_id: &str,
) -> Result<[u8; KEY_LEN], FieldEncryptionError> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = [0u8; KEY_LEN];
    let info = format!("content/v1/{}", conversation_id);
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|_| FieldEncryptionError::KdfFailed)?;
    Ok(out)
}

pub fn derive_hmac_key(
    root_key: &[u8],
    conversation_id: &str,
) -> Result<[u8; KEY_LEN], FieldEncryptionError> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = [0u8; KEY_LEN];
    let info = format!("hmac/v1/{}", conversation_id);
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|_| FieldEncryptionError::KdfFailed)?;
    Ok(out)
}

pub fn encrypt_payload(
    root_key: &[u8],
    conversation_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, FieldEncryptionError> {
    if root_key.len() != KEY_LEN {
        return Err(FieldEncryptionError::InvalidKeyLength(root_key.len()));
    }
    let key_bytes = derive_content_key(root_key, conversation_id)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| FieldEncryptionError::AuthFailed)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(PAYLOAD_VERSION_V1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_payload(
    root_key: &[u8],
    conversation_id: &str,
    wire: &[u8],
) -> Result<Vec<u8>, FieldEncryptionError> {
    if root_key.len() != KEY_LEN {
        return Err(FieldEncryptionError::InvalidKeyLength(root_key.len()));
    }
    if wire.len() < MIN_PAYLOAD_LEN {
        return Err(FieldEncryptionError::PayloadTooShort(
            wire.len(),
            MIN_PAYLOAD_LEN,
        ));
    }
    let version = wire[0];
    if version != PAYLOAD_VERSION_V1 {
        return Err(FieldEncryptionError::UnknownVersion(version));
    }
    let nonce_bytes: [u8; NONCE_LEN] = wire[1..1 + NONCE_LEN]
        .try_into()
        .expect("slice length checked above");
    let ciphertext = &wire[1 + NONCE_LEN..];
    let key_bytes = derive_content_key(root_key, conversation_id)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
        .map_err(|_| FieldEncryptionError::AuthFailed)
}

pub fn compute_entry_hmac(
    root_key: &[u8],
    conversation_id: &str,
    prev_hmac: Option<&[u8]>,
    message_id: &str,
    payload_wire: &[u8],
) -> Result<[u8; HMAC_LEN], FieldEncryptionError> {
    if root_key.len() != KEY_LEN {
        return Err(FieldEncryptionError::InvalidKeyLength(root_key.len()));
    }
    let hmac_key = derive_hmac_key(root_key, conversation_id)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
    let prev = prev_hmac.unwrap_or(&HMAC_SEED);
    mac.update(prev);
    mac.update(message_id.as_bytes());
    mac.update(payload_wire);
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

pub fn verify_entry_hmac(
    root_key: &[u8],
    conversation_id: &str,
    prev_hmac: Option<&[u8]>,
    message_id: &str,
    payload_wire: &[u8],
    expected: &[u8],
) -> Result<bool, FieldEncryptionError> {
    let computed = compute_entry_hmac(
        root_key,
        conversation_id,
        prev_hmac,
        message_id,
        payload_wire,
    )?;
    use subtle::ConstantTimeEq;
    Ok(bool::from(computed.ct_eq(expected)))
}

/// Walk a sequence of stored transcript entries and verify each row's
/// `entry_hmac` matches the recomputed HMAC against the previous row's
/// computed HMAC. Returns `Ok(None)` if the chain is intact, or
/// `Ok(Some(idx))` for the first entry index that fails verification.
///
/// Caller passes entries in **sequence-number order**, including any
/// tombstones (their `entry_hmac` and `payload_wire` must remain intact
/// after soft-delete for the chain to validate).
///
/// **Not exposed via UniFFI:** the walker takes lifetime-bound borrows and
/// is awkward to express across FFI. Platforms that need integrity walks
/// should iterate their DB rows in sequence order and call the already-
/// exposed `verify_message_hmac` per row, threading the previously
/// computed HMAC manually.
pub fn verify_chain<'a, I>(
    root_key: &[u8],
    conversation_id: &str,
    entries: I,
) -> Result<Option<usize>, FieldEncryptionError>
where
    I: IntoIterator<Item = (&'a str, &'a [u8], &'a [u8])>, // (message_id, payload_wire, stored_hmac)
{
    if root_key.len() != KEY_LEN {
        return Err(FieldEncryptionError::InvalidKeyLength(root_key.len()));
    }
    let mut prev: Option<[u8; HMAC_LEN]> = None;
    for (idx, (message_id, payload_wire, expected)) in entries.into_iter().enumerate() {
        let computed = compute_entry_hmac(
            root_key,
            conversation_id,
            prev.as_ref().map(|b| b.as_slice()),
            message_id,
            payload_wire,
        )?;
        // Constant-time compare to avoid leaking position-of-divergence on
        // timing channels (defensive, even though this is a local op).
        use subtle::ConstantTimeEq;
        if !bool::from(computed.ct_eq(expected)) {
            return Ok(Some(idx));
        }
        prev = Some(computed);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_root_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            k[i] = i as u8;
        }
        k
    }

    #[test]
    fn round_trip_simple_payload() {
        let root = fixed_root_key();
        let plaintext = b"hello, world";
        let wire = encrypt_payload(&root, "conv-1", plaintext).unwrap();
        assert_eq!(wire[0], PAYLOAD_VERSION_V1);
        assert_eq!(wire.len(), 1 + NONCE_LEN + plaintext.len() + TAG_LEN);
        let decrypted = decrypt_payload(&root, "conv-1", &wire).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_conversation_id_fails_auth() {
        let root = fixed_root_key();
        let wire = encrypt_payload(&root, "conv-1", b"secret").unwrap();
        let err = decrypt_payload(&root, "conv-2", &wire).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::AuthFailed));
    }

    #[test]
    fn wrong_root_key_fails_auth() {
        let root_a = fixed_root_key();
        let mut root_b = fixed_root_key();
        root_b[0] ^= 0xff;
        let wire = encrypt_payload(&root_a, "conv-1", b"secret").unwrap();
        let err = decrypt_payload(&root_b, "conv-1", &wire).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::AuthFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let root = fixed_root_key();
        let mut wire = encrypt_payload(&root, "conv-1", b"secret").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let err = decrypt_payload(&root, "conv-1", &wire).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::AuthFailed));
    }

    #[test]
    fn unknown_version_byte_rejected() {
        let root = fixed_root_key();
        let mut wire = encrypt_payload(&root, "conv-1", b"x").unwrap();
        wire[0] = 0xff;
        let err = decrypt_payload(&root, "conv-1", &wire).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::UnknownVersion(0xff)));
    }

    #[test]
    fn short_payload_rejected() {
        let root = fixed_root_key();
        let err = decrypt_payload(&root, "conv-1", &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::PayloadTooShort(_, _)));
    }

    #[test]
    fn nonce_varies_between_encryptions() {
        let root = fixed_root_key();
        let a = encrypt_payload(&root, "conv-1", b"same plaintext").unwrap();
        let b = encrypt_payload(&root, "conv-1", b"same plaintext").unwrap();
        assert_ne!(a[1..1 + NONCE_LEN], b[1..1 + NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_chain_round_trip() {
        let root = fixed_root_key();
        let conv = "conv-1";
        let wire1 = encrypt_payload(&root, conv, b"msg-1").unwrap();
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &wire1).unwrap();
        let wire2 = encrypt_payload(&root, conv, b"msg-2").unwrap();
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &wire2).unwrap();
        assert!(verify_entry_hmac(&root, conv, None, "m1", &wire1, &h1).unwrap());
        assert!(verify_entry_hmac(&root, conv, Some(&h1), "m2", &wire2, &h2).unwrap());
    }

    #[test]
    fn hmac_chain_detects_wrong_prev() {
        let root = fixed_root_key();
        let wire = encrypt_payload(&root, "conv-1", b"msg-2").unwrap();
        let h_with_seed = compute_entry_hmac(&root, "conv-1", None, "m2", &wire).unwrap();
        let bogus_prev = [0xaau8; HMAC_LEN];
        let ok = verify_entry_hmac(
            &root,
            "conv-1",
            Some(&bogus_prev),
            "m2",
            &wire,
            &h_with_seed,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn hmac_chain_detects_tampered_payload() {
        let root = fixed_root_key();
        let mut wire = encrypt_payload(&root, "conv-1", b"msg").unwrap();
        let h = compute_entry_hmac(&root, "conv-1", None, "m", &wire).unwrap();
        wire[1] ^= 0x01;
        let ok = verify_entry_hmac(&root, "conv-1", None, "m", &wire, &h).unwrap();
        assert!(!ok);
    }

    #[test]
    fn key_length_validation() {
        let short = [0u8; 16];
        let err = encrypt_payload(&short, "conv-1", b"x").unwrap_err();
        assert!(matches!(err, FieldEncryptionError::InvalidKeyLength(16)));
    }

    #[test]
    fn verify_chain_accepts_intact_chain() {
        let root = fixed_root_key();
        let conv = "conv-1";
        let wire1 = encrypt_payload(&root, conv, b"m1-plaintext").unwrap();
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &wire1).unwrap();
        let wire2 = encrypt_payload(&root, conv, b"m2-plaintext").unwrap();
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &wire2).unwrap();
        let wire3 = encrypt_payload(&root, conv, b"m3-plaintext").unwrap();
        let h3 = compute_entry_hmac(&root, conv, Some(&h2), "m3", &wire3).unwrap();

        let entries: Vec<(&str, &[u8], &[u8])> = vec![
            ("m1", &wire1, &h1),
            ("m2", &wire2, &h2),
            ("m3", &wire3, &h3),
        ];
        assert_eq!(verify_chain(&root, conv, entries).unwrap(), None);
    }

    #[test]
    fn verify_chain_finds_first_tampered_index() {
        let root = fixed_root_key();
        let conv = "conv-1";
        let wire1 = encrypt_payload(&root, conv, b"a").unwrap();
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &wire1).unwrap();
        let wire2 = encrypt_payload(&root, conv, b"b").unwrap();
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &wire2).unwrap();
        let wire3 = encrypt_payload(&root, conv, b"c").unwrap();
        let h3 = compute_entry_hmac(&root, conv, Some(&h2), "m3", &wire3).unwrap();
        let wire4 = encrypt_payload(&root, conv, b"d").unwrap();
        // Tamper: corrupt the HMAC of entry 3 (zero-indexed).
        let mut tampered_h4 = compute_entry_hmac(&root, conv, Some(&h3), "m4", &wire4).unwrap();
        tampered_h4[0] ^= 0xff;

        let entries: Vec<(&str, &[u8], &[u8])> = vec![
            ("m1", &wire1, &h1),
            ("m2", &wire2, &h2),
            ("m3", &wire3, &h3),
            ("m4", &wire4, &tampered_h4),
        ];
        assert_eq!(verify_chain(&root, conv, entries).unwrap(), Some(3));
    }

    #[test]
    fn verify_chain_intact_with_tombstoned_entries() {
        // Tombstones in the field-level scheme keep payload_wire + entry_hmac
        // unchanged (only `is_tombstone` / `deleted_at` flags change). The
        // chain must still validate because the verifier doesn't know or care
        // about the tombstone flag.
        let root = fixed_root_key();
        let conv = "conv-1";
        let w1 = encrypt_payload(&root, conv, b"keep-1").unwrap();
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &w1).unwrap();
        let w2 = encrypt_payload(&root, conv, b"tombstoned").unwrap();
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &w2).unwrap();
        let w3 = encrypt_payload(&root, conv, b"keep-3").unwrap();
        let h3 = compute_entry_hmac(&root, conv, Some(&h2), "m3", &w3).unwrap();

        // Caller still presents all three rows in sequence order even though
        // row 2 is "tombstoned" from the UI's perspective.
        let entries: Vec<(&str, &[u8], &[u8])> =
            vec![("m1", &w1, &h1), ("m2", &w2, &h2), ("m3", &w3, &h3)];
        assert_eq!(verify_chain(&root, conv, entries).unwrap(), None);
    }

    #[test]
    fn verify_chain_detects_dropped_tombstone_payload() {
        // If a "tombstone" mistakenly zeroed out payload_wire (the wrong
        // implementation of tombstoning), the chain breaks because the
        // computed HMAC over the zeroed payload no longer matches the
        // originally-stored entry_hmac.
        let root = fixed_root_key();
        let conv = "conv-1";
        let w1 = encrypt_payload(&root, conv, b"a").unwrap();
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &w1).unwrap();
        let w2 = encrypt_payload(&root, conv, b"b").unwrap();
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &w2).unwrap();
        let w3 = encrypt_payload(&root, conv, b"c").unwrap();
        let h3 = compute_entry_hmac(&root, conv, Some(&h2), "m3", &w3).unwrap();

        // Simulate a "wrong" tombstone that nukes the payload.
        let empty: &[u8] = &[];
        let entries: Vec<(&str, &[u8], &[u8])> = vec![
            ("m1", &w1, &h1),
            ("m2", empty, &h2), // payload was wiped — h2 no longer matches
            ("m3", &w3, &h3),
        ];
        assert_eq!(verify_chain(&root, conv, entries).unwrap(), Some(1));
    }

    #[test]
    fn verify_chain_empty_iterator_is_ok() {
        let root = fixed_root_key();
        let entries: Vec<(&str, &[u8], &[u8])> = vec![];
        assert_eq!(verify_chain(&root, "conv-1", entries).unwrap(), None);
    }

    #[test]
    fn verify_chain_rejects_short_root_key() {
        let short = [0u8; 16];
        let entries: Vec<(&str, &[u8], &[u8])> = vec![];
        let err = verify_chain(&short, "conv-1", entries).unwrap_err();
        assert!(matches!(err, FieldEncryptionError::InvalidKeyLength(16)));
    }

    #[test]
    #[ignore = "vector emitter; run with --include-ignored to print"]
    fn emit_test_vectors() {
        let root = [0x42u8; KEY_LEN];
        let conv = "conv-1";

        let ck = derive_content_key(&root, conv).unwrap();
        println!("content_key = {}", hex::encode(ck));
        let hk = derive_hmac_key(&root, conv).unwrap();
        println!("hmac_key    = {}", hex::encode(hk));

        let p1 = [0xABu8; 40];
        let h1 = compute_entry_hmac(&root, conv, None, "m1", &p1).unwrap();
        println!("hmac_m1     = {}", hex::encode(h1));

        let p2 = [0xCDu8; 40];
        let h2 = compute_entry_hmac(&root, conv, Some(&h1), "m2", &p2).unwrap();
        println!("hmac_m2     = {}", hex::encode(h2));

        let p3 = [0xEFu8; 40];
        let h3 = compute_entry_hmac(&root, conv, Some(&h2), "m3", &p3).unwrap();
        println!("hmac_m3     = {}", hex::encode(h3));
    }
}
