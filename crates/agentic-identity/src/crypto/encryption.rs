//! Symmetric encryption using ChaCha20-Poly1305 and passphrase-based
//! key derivation using Argon2id.
//!
//! Used for encrypting private keys at rest in `.aid` identity files.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;

use crate::crypto::random::{random_nonce_12, random_salt_16};
use crate::error::{IdentityError, Result};

/// Argon2id parameters for passphrase-based key derivation.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

/// Derive a 32-byte encryption key from a passphrase and salt using Argon2id.
pub fn derive_passphrase_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| IdentityError::DerivationFailed(format!("Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| IdentityError::DerivationFailed(format!("Argon2 hash: {e}")))?;

    Ok(output)
}

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns `(nonce, ciphertext)`. The nonce must be stored alongside
/// the ciphertext for decryption.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce_bytes = random_nonce_12();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| IdentityError::EncryptionFailed(format!("cipher init: {e}")))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| IdentityError::EncryptionFailed(format!("encrypt: {e}")))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| IdentityError::DecryptionFailed(format!("cipher init: {e}")))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| IdentityError::InvalidPassphrase)
}

/// Encrypt data with a passphrase. Returns `(salt, nonce, ciphertext)`.
pub fn encrypt_with_passphrase(
    passphrase: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 16], Vec<u8>, Vec<u8>)> {
    let salt = random_salt_16();
    let mut key = derive_passphrase_key(passphrase, &salt)?;
    let (nonce, ciphertext) = encrypt(&key, plaintext)?;
    key.zeroize();
    Ok((salt, nonce, ciphertext))
}

/// Decrypt data with a passphrase.
pub fn decrypt_with_passphrase(
    passphrase: &[u8],
    salt: &[u8; 16],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut key = derive_passphrase_key(passphrase, salt)?;
    let result = decrypt(&key, nonce, ciphertext);
    key.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_passphrase_derivation() {
        let pass = b"my-secret-passphrase";
        let salt = random_salt_16();
        let key = derive_passphrase_key(pass, &salt).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_argon2_deterministic() {
        let pass = b"test";
        let salt = [1u8; 16];
        let k1 = derive_passphrase_key(pass, &salt).unwrap();
        let k2 = derive_passphrase_key(pass, &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_argon2_wrong_passphrase() {
        let salt = [1u8; 16];
        let k1 = derive_passphrase_key(b"correct", &salt).unwrap();
        let k2 = derive_passphrase_key(b"wrong", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() {
        let key = [42u8; 32];
        let plaintext = b"secret agent identity data";
        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_tamper_detection() {
        let key = [42u8; 32];
        let plaintext = b"secret agent identity data";
        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        // Tamper with ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_with_passphrase() {
        let pass = b"strong-passphrase-123";
        let plaintext = b"identity anchor private key material";
        let (salt, nonce, ciphertext) = encrypt_with_passphrase(pass, plaintext).unwrap();
        let decrypted = decrypt_with_passphrase(pass, &salt, &nonce, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_fails() {
        let plaintext = b"secret";
        let (salt, nonce, ciphertext) = encrypt_with_passphrase(b"correct", plaintext).unwrap();
        assert!(decrypt_with_passphrase(b"wrong", &salt, &nonce, &ciphertext).is_err());
    }
}
