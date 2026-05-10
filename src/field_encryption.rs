use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
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
        return Err(FieldEncryptionError::PayloadTooShort(wire.len(), MIN_PAYLOAD_LEN));
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
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC accepts any key length");
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
        let ok = verify_entry_hmac(&root, "conv-1", Some(&bogus_prev), "m2", &wire, &h_with_seed).unwrap();
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
}
