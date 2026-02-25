//! Identity anchor — the root cryptographic identity.
//!
//! An identity anchor is an Ed25519 key pair that serves as the
//! permanent root of an agent's identity. The public key IS the
//! identity. The private key proves ownership.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::derivation;
use crate::crypto::keys::Ed25519KeyPair;
use crate::error::{IdentityError, Result};

/// Unique identifier for an identity.
///
/// Format: `aid_` + base58 of first 16 bytes of SHA-256(public_key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub String);

impl IdentityId {
    /// Compute an identity ID from a verifying (public) key.
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let hash = Sha256::digest(key.as_bytes());
        let truncated = &hash[..16];
        let encoded = bs58::encode(truncated).into_string();
        Self(format!("aid_{encoded}"))
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The root identity anchor containing key material.
///
/// The signing key is zeroized on drop to prevent leakage.
pub struct IdentityAnchor {
    /// The root key pair.
    key_pair: Ed25519KeyPair,
    /// Creation timestamp (microseconds since Unix epoch).
    pub created_at: u64,
    /// Human-readable name (optional).
    pub name: Option<String>,
    /// Key rotation history.
    pub rotation_history: Vec<KeyRotation>,
}

impl IdentityAnchor {
    /// Create a new identity anchor with a fresh key pair.
    pub fn new(name: Option<String>) -> Self {
        let now = crate::time::now_micros();
        Self {
            key_pair: Ed25519KeyPair::generate(),
            created_at: now,
            name,
            rotation_history: Vec::new(),
        }
    }

    /// Reconstruct from existing key bytes and metadata.
    pub fn from_parts(
        signing_key_bytes: &[u8; 32],
        created_at: u64,
        name: Option<String>,
        rotation_history: Vec<KeyRotation>,
    ) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_signing_key_bytes(signing_key_bytes)?;
        Ok(Self {
            key_pair,
            created_at,
            name,
            rotation_history,
        })
    }

    /// Return the identity ID (derived from public key).
    pub fn id(&self) -> IdentityId {
        IdentityId::from_verifying_key(self.key_pair.verifying_key())
    }

    /// Return a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        self.key_pair.signing_key()
    }

    /// Return the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.key_pair.verifying_key()
    }

    /// Return the signing key bytes. Caller must zeroize after use.
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.key_pair.signing_key_bytes()
    }

    /// Return the verifying key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key_pair.verifying_key_bytes()
    }

    /// Return the public key as base64.
    pub fn public_key_base64(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.verifying_key_bytes(),
        )
    }

    /// Derive a scoped signing key for a session.
    pub fn derive_session_key(&self, session_id: &str) -> Result<SigningKey> {
        let root = self.signing_key_bytes();
        let ctx = derivation::session_context(session_id);

        // root bytes are on stack and will be overwritten
        derivation::derive_signing_key(&root, &ctx)
    }

    /// Derive a scoped signing key for a capability.
    pub fn derive_capability_key(&self, capability_uri: &str) -> Result<SigningKey> {
        let root = self.signing_key_bytes();
        let ctx = derivation::capability_context(capability_uri);
        derivation::derive_signing_key(&root, &ctx)
    }

    /// Derive a scoped signing key for a device.
    pub fn derive_device_key(&self, device_id: &str) -> Result<SigningKey> {
        let root = self.signing_key_bytes();
        let ctx = derivation::device_context(device_id);
        derivation::derive_signing_key(&root, &ctx)
    }

    /// Derive a revocation signing key for a trust grant.
    pub fn derive_revocation_key(&self, trust_id: &str) -> Result<SigningKey> {
        let root = self.signing_key_bytes();
        let ctx = derivation::revocation_context(trust_id);
        derivation::derive_signing_key(&root, &ctx)
    }

    /// Rotate the root key. Returns the new anchor with the old key
    /// recorded in rotation history.
    pub fn rotate(&self, reason: RotationReason) -> Result<Self> {
        let old_pub_b64 = self.public_key_base64();
        let new_kp = Ed25519KeyPair::generate();
        let new_pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            new_kp.verifying_key_bytes(),
        );
        let now = crate::time::now_micros();

        // The old key signs authorization of the rotation
        let auth_message = format!(
            "rotate:{old_pub_b64}:{new_pub_b64}:{now}:{}",
            reason.as_str()
        );
        let auth_sig =
            crate::crypto::signing::sign_to_base64(self.signing_key(), auth_message.as_bytes());

        let rotation = KeyRotation {
            previous_key: old_pub_b64,
            new_key: new_pub_b64,
            rotated_at: now,
            reason: reason.clone(),
            authorization_signature: auth_sig,
        };

        let mut history = self.rotation_history.clone();
        history.push(rotation);

        Ok(Self {
            key_pair: new_kp,
            created_at: self.created_at,
            name: self.name.clone(),
            rotation_history: history,
        })
    }

    /// Generate the public identity document.
    pub fn to_document(&self) -> IdentityDocument {
        let id = self.id();
        let pub_key_b64 = self.public_key_base64();
        let public_rotations: Vec<PublicKeyRotation> = self
            .rotation_history
            .iter()
            .map(|r| PublicKeyRotation {
                previous_key: r.previous_key.clone(),
                new_key: r.new_key.clone(),
                rotated_at: r.rotated_at,
                reason: r.reason.clone(),
                authorization_signature: r.authorization_signature.clone(),
            })
            .collect();

        // Build the document without signature first
        let mut doc = IdentityDocument {
            id,
            public_key: pub_key_b64,
            algorithm: "ed25519".to_string(),
            created_at: self.created_at,
            name: self.name.clone(),
            rotation_history: public_rotations,
            attestations: Vec::new(),
            signature: String::new(),
        };

        // Self-sign the document
        let to_sign = serde_json::to_string(&DocumentSignPayload::from(&doc)).unwrap_or_default();
        doc.signature =
            crate::crypto::signing::sign_to_base64(self.signing_key(), to_sign.as_bytes());

        doc
    }
}

/// Payload used for document self-signature (excludes the signature field).
#[derive(Serialize)]
struct DocumentSignPayload {
    id: String,
    public_key: String,
    algorithm: String,
    created_at: u64,
    name: Option<String>,
}

impl From<&IdentityDocument> for DocumentSignPayload {
    fn from(doc: &IdentityDocument) -> Self {
        Self {
            id: doc.id.0.clone(),
            public_key: doc.public_key.clone(),
            algorithm: doc.algorithm.clone(),
            created_at: doc.created_at,
            name: doc.name.clone(),
        }
    }
}

/// Public identity document (shareable, does not contain private keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDocument {
    pub id: IdentityId,
    pub public_key: String,
    pub algorithm: String,
    pub created_at: u64,
    pub name: Option<String>,
    pub rotation_history: Vec<PublicKeyRotation>,
    pub attestations: Vec<Attestation>,
    pub signature: String,
}

impl IdentityDocument {
    /// Verify the self-signature on this document.
    pub fn verify_signature(&self) -> Result<()> {
        let pub_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.public_key)
                .map_err(|e| {
                    IdentityError::InvalidKey(format!("invalid base64 public key: {e}"))
                })?;

        let key_bytes: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("public key must be 32 bytes".into()))?;

        let verifying_key = Ed25519KeyPair::verifying_key_from_bytes(&key_bytes)?;

        let payload = DocumentSignPayload::from(self);
        let to_verify = serde_json::to_string(&payload)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        crate::crypto::signing::verify_from_base64(
            &verifying_key,
            to_verify.as_bytes(),
            &self.signature,
        )
    }
}

/// Record of a key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotation {
    pub previous_key: String,
    pub new_key: String,
    pub rotated_at: u64,
    pub reason: RotationReason,
    pub authorization_signature: String,
}

impl Zeroize for KeyRotation {
    fn zeroize(&mut self) {
        self.authorization_signature.zeroize();
    }
}

/// Public view of key rotation (no private data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRotation {
    pub previous_key: String,
    pub new_key: String,
    pub rotated_at: u64,
    pub reason: RotationReason,
    pub authorization_signature: String,
}

/// Reason for key rotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RotationReason {
    Scheduled,
    Compromised,
    DeviceLost,
    PolicyRequired,
    Manual,
}

impl RotationReason {
    /// Return a stable string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Compromised => "compromised",
            Self::DeviceLost => "device_lost",
            Self::PolicyRequired => "policy_required",
            Self::Manual => "manual",
        }
    }
}

/// Attestation from another identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub attester: IdentityId,
    pub attester_key: String,
    pub claim: AttestationClaim,
    pub attested_at: u64,
    pub signature: String,
}

/// Types of attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationClaim {
    KeyOwnership,
    NameVerification {
        name: String,
    },
    OrganizationMembership {
        org: String,
    },
    Custom {
        claim_type: String,
        claim_value: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_create() {
        let anchor = IdentityAnchor::new(Some("test-agent".to_string()));
        let id = anchor.id();
        assert!(id.0.starts_with("aid_"));
        assert!(anchor.created_at > 0);
        assert_eq!(anchor.name.as_deref(), Some("test-agent"));
    }

    #[test]
    fn test_identity_id_from_key() {
        let anchor = IdentityAnchor::new(None);
        let id1 = anchor.id();
        let id2 = IdentityId::from_verifying_key(anchor.verifying_key());
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_identity_document_self_signed() {
        let anchor = IdentityAnchor::new(Some("doc-test".to_string()));
        let doc = anchor.to_document();
        assert!(doc.verify_signature().is_ok());
    }

    #[test]
    fn test_identity_derive_session_key() {
        let anchor = IdentityAnchor::new(None);
        let session_key = anchor.derive_session_key("session-123").unwrap();
        let verifying = session_key.verifying_key();
        // Session key should be different from root
        assert_ne!(verifying.to_bytes(), anchor.verifying_key_bytes());
        // But deterministic for same session ID
        let session_key2 = anchor.derive_session_key("session-123").unwrap();
        assert_eq!(
            session_key.verifying_key().to_bytes(),
            session_key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_identity_derive_capability_key() {
        let anchor = IdentityAnchor::new(None);
        let k1 = anchor.derive_capability_key("read:calendar").unwrap();
        let k2 = anchor.derive_capability_key("write:calendar").unwrap();
        assert_ne!(k1.verifying_key().to_bytes(), k2.verifying_key().to_bytes());
    }

    #[test]
    fn test_identity_derive_device_key() {
        let anchor = IdentityAnchor::new(None);
        let k1 = anchor.derive_device_key("macbook-pro").unwrap();
        let k2 = anchor.derive_device_key("iphone-15").unwrap();
        assert_ne!(k1.verifying_key().to_bytes(), k2.verifying_key().to_bytes());
    }

    #[test]
    fn test_identity_rotation() {
        let anchor = IdentityAnchor::new(Some("rotate-test".to_string()));
        let old_pub = anchor.verifying_key_bytes();
        let rotated = anchor.rotate(RotationReason::Scheduled).unwrap();
        let new_pub = rotated.verifying_key_bytes();
        assert_ne!(old_pub, new_pub);
        assert_eq!(rotated.rotation_history.len(), 1);
        assert_eq!(
            rotated.rotation_history[0].reason,
            RotationReason::Scheduled
        );
    }

    #[test]
    fn test_identity_rotation_chain() {
        let a = IdentityAnchor::new(None);
        let b = a.rotate(RotationReason::Scheduled).unwrap();
        let c = b.rotate(RotationReason::Manual).unwrap();
        assert_eq!(c.rotation_history.len(), 2);
        assert_eq!(c.rotation_history[0].reason, RotationReason::Scheduled);
        assert_eq!(c.rotation_history[1].reason, RotationReason::Manual);
    }

    #[test]
    fn test_identity_unique_ids() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);
        assert_ne!(a.id(), b.id());
    }
}
