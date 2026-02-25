//! Ed25519 signing and verification.
//!
//! Provides a simple API for signing arbitrary messages and verifying
//! signatures against known public keys.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::{IdentityError, Result};

/// Sign a message with an Ed25519 signing key.
///
/// Returns the signature as 64 bytes.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| IdentityError::SignatureInvalid)
}

/// Sign a message and return the signature as a base64-encoded string.
pub fn sign_to_base64(signing_key: &SigningKey, message: &[u8]) -> String {
    let sig = sign(signing_key, message);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
}

/// Verify a base64-encoded signature.
pub fn verify_from_base64(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
            .map_err(|e| IdentityError::InvalidKey(format!("invalid base64 signature: {e}")))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("signature must be 64 bytes".into()))?;

    let signature = Signature::from_bytes(&sig_array);
    verify(verifying_key, message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Ed25519KeyPair;

    #[test]
    fn test_sign_verify() {
        let kp = Ed25519KeyPair::generate();
        let message = b"hello world";
        let sig = sign(kp.signing_key(), message);
        assert!(verify(kp.verifying_key(), message, &sig).is_ok());
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let kp_a = Ed25519KeyPair::generate();
        let kp_b = Ed25519KeyPair::generate();
        let message = b"hello world";
        let sig = sign(kp_a.signing_key(), message);
        assert!(verify(kp_b.verifying_key(), message, &sig).is_err());
    }

    #[test]
    fn test_sign_verify_tampered_message() {
        let kp = Ed25519KeyPair::generate();
        let message = b"hello world";
        let sig = sign(kp.signing_key(), message);
        let tampered = b"hello worlD";
        assert!(verify(kp.verifying_key(), tampered, &sig).is_err());
    }

    #[test]
    fn test_sign_verify_base64_roundtrip() {
        let kp = Ed25519KeyPair::generate();
        let message = b"action: deployed v1.2.3";
        let sig_b64 = sign_to_base64(kp.signing_key(), message);
        assert!(verify_from_base64(kp.verifying_key(), message, &sig_b64).is_ok());
    }

    #[test]
    fn test_verify_invalid_base64() {
        let kp = Ed25519KeyPair::generate();
        let message = b"test";
        assert!(verify_from_base64(kp.verifying_key(), message, "not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_deterministic_signature() {
        // Ed25519 signatures are deterministic for the same key + message
        let kp = Ed25519KeyPair::generate();
        let message = b"deterministic";
        let sig1 = sign(kp.signing_key(), message);
        let sig2 = sign(kp.signing_key(), message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
