use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::AeadCore;
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobCryptoError {
    #[error("blob integrity check failed")]
    IntegrityCheckFailed,
    #[error("blob decryption failed")]
    DecryptionFailed,
    #[error("blob encryption failed")]
    EncryptionFailed,
}

pub fn encrypt_blob(plaintext: &[u8]) -> Result<EncryptedBlob, BlobCryptoError> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| BlobCryptoError::EncryptionFailed)?;

    Ok(EncryptedBlob {
        sha256: sha256_hex(&ciphertext),
        ciphertext,
        key: key.to_vec(),
        iv: nonce.to_vec(),
    })
}

pub fn decrypt_blob(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    expected_sha256: &str,
) -> Result<Vec<u8>, BlobCryptoError> {
    if sha256_hex(ciphertext) != expected_sha256 {
        return Err(BlobCryptoError::IntegrityCheckFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BlobCryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BlobCryptoError::DecryptionFailed)
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_blob_crypto() {
        let encrypted = encrypt_blob(b"hello image").unwrap();
        let decrypted = decrypt_blob(
            &encrypted.ciphertext,
            &encrypted.key,
            &encrypted.iv,
            &encrypted.sha256,
        )
        .unwrap();

        assert_eq!(decrypted, b"hello image");
    }
}
