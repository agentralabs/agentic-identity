//! Key derivation using HKDF-SHA256.
//!
//! Derives scoped child keys from a root signing key using
//! context strings. This enables session keys, capability keys,
//! and device keys without exposing the root.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{IdentityError, Result};

/// Derive a 32-byte child key from a root key and context string.
///
/// Uses HKDF-SHA256 (RFC 5869) with the root key as IKM and
/// the context as info.
pub fn derive_key(root_key_bytes: &[u8; 32], context: &str) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, root_key_bytes);
    let mut output = [0u8; 32];
    hk.expand(context.as_bytes(), &mut output)
        .map_err(|e| IdentityError::DerivationFailed(format!("HKDF expand failed: {e}")))?;
    Ok(output)
}

/// Derive an Ed25519 signing key from a root key and context.
pub fn derive_signing_key(root_key_bytes: &[u8; 32], context: &str) -> Result<SigningKey> {
    let derived = derive_key(root_key_bytes, context)?;
    Ok(SigningKey::from_bytes(&derived))
}

/// Build a derivation path string for a session key.
pub fn session_context(session_id: &str) -> String {
    format!("agentic-identity/session/{session_id}")
}

/// Build a derivation path string for a capability key.
pub fn capability_context(capability_uri: &str) -> String {
    format!("agentic-identity/capability/{capability_uri}")
}

/// Build a derivation path string for a device key.
pub fn device_context(device_id: &str) -> String {
    format!("agentic-identity/device/{device_id}")
}

/// Build a derivation path string for an encryption key.
pub fn encryption_context() -> String {
    "agentic-identity/encryption".to_string()
}

/// Build a derivation path string for a revocation key.
pub fn revocation_context(trust_id: &str) -> String {
    format!("agentic-identity/revocation/{trust_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Ed25519KeyPair;

    #[test]
    fn test_hkdf_derivation_deterministic() {
        let root = [42u8; 32];
        let ctx = "test/context";
        let a = derive_key(&root, ctx).unwrap();
        let b = derive_key(&root, ctx).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_hkdf_different_context_different_key() {
        let root = [42u8; 32];
        let a = derive_key(&root, "context-a").unwrap();
        let b = derive_key(&root, "context-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_hkdf_different_root_different_key() {
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let a = derive_key(&root_a, "same-context").unwrap();
        let b = derive_key(&root_b, "same-context").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_derive_signing_key() {
        let kp = Ed25519KeyPair::generate();
        let root_bytes = kp.signing_key_bytes();
        let derived = derive_signing_key(&root_bytes, &session_context("sess-1")).unwrap();
        // Derived key should be a valid signing key
        let verifying = derived.verifying_key();
        assert_eq!(verifying.to_bytes().len(), 32);
    }

    #[test]
    fn test_session_keys_differ_by_id() {
        let root = [99u8; 32];
        let k1 = derive_key(&root, &session_context("session-1")).unwrap();
        let k2 = derive_key(&root, &session_context("session-2")).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_capability_keys_differ_by_uri() {
        let root = [99u8; 32];
        let k1 = derive_key(&root, &capability_context("read:calendar")).unwrap();
        let k2 = derive_key(&root, &capability_context("write:calendar")).unwrap();
        assert_ne!(k1, k2);
    }
}
