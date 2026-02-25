//! Ed25519 and X25519 key pair generation.
//!
//! Ed25519 is used for signing and identity anchors.
//! X25519 is used for Diffie-Hellman key exchange (encrypted channels).

use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{IdentityError, Result};

/// An Ed25519 key pair for signing operations.
///
/// The signing key is zeroized on drop to prevent private key leakage.
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Reconstruct a key pair from raw signing key bytes.
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Reconstruct a verifying key from raw bytes.
    pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(bytes)
            .map_err(|e| IdentityError::InvalidKey(format!("invalid verifying key: {e}")))
    }

    /// Return a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Return the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Return the signing key bytes. Caller must zeroize after use.
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Return the verifying key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // SigningKey stores bytes internally; zeroize via conversion
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

/// An X25519 static key pair for Diffie-Hellman key exchange.
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct from secret key bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    ///
    /// Returns the shared secret (32 bytes).
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(peer_public).as_bytes()
    }

    /// Return the public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Return the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

/// Generate an ephemeral X25519 key pair for one-time use.
pub fn ephemeral_x25519() -> (EphemeralSecret, X25519PublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let kp = Ed25519KeyPair::generate();
        let pub_bytes = kp.verifying_key_bytes();
        assert_eq!(pub_bytes.len(), 32);
        let priv_bytes = kp.signing_key_bytes();
        assert_eq!(priv_bytes.len(), 32);
    }

    #[test]
    fn test_ed25519_unique_keys() {
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        assert_ne!(kp1.verifying_key_bytes(), kp2.verifying_key_bytes());
    }

    #[test]
    fn test_ed25519_from_bytes_roundtrip() {
        let kp = Ed25519KeyPair::generate();
        let bytes = kp.signing_key_bytes();
        let kp2 = Ed25519KeyPair::from_signing_key_bytes(&bytes).unwrap();
        assert_eq!(kp.verifying_key_bytes(), kp2.verifying_key_bytes());
    }

    #[test]
    fn test_x25519_key_generation() {
        let kp = X25519KeyPair::generate();
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_different_peers_different_secrets() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        let charlie = X25519KeyPair::generate();
        let ab = alice.diffie_hellman(bob.public_key());
        let ac = alice.diffie_hellman(charlie.public_key());
        assert_ne!(ab, ac);
    }
}
