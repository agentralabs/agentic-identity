//! Trust grants — signed trust relationships between identities.
//!
//! A trust grant is a cryptographic object where identity A says
//! "I trust identity B to do {capabilities} under {constraints}."

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::{IdentityError, Result};
use crate::identity::IdentityId;

use super::capability::Capability;
use super::constraint::TrustConstraints;
use super::revocation::{RevocationChannel, RevocationConfig};

/// Unique identifier for a trust grant.
///
/// Format: `atrust_` + base58 of first 16 bytes of SHA-256(grant_hash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustId(pub String);

impl std::fmt::Display for TrustId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A signed trust relationship between two identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Unique trust ID.
    pub id: TrustId,
    /// Grantor identity (who is granting trust).
    pub grantor: IdentityId,
    /// Grantor's public key used for signing.
    pub grantor_key: String,
    /// Grantee identity (who receives trust).
    pub grantee: IdentityId,
    /// Grantee's public key at time of grant.
    pub grantee_key: String,
    /// Capabilities being granted.
    pub capabilities: Vec<Capability>,
    /// Constraints on the grant.
    pub constraints: TrustConstraints,
    /// Can grantee delegate to others?
    pub delegation_allowed: bool,
    /// Maximum delegation depth (if delegation allowed).
    pub max_delegation_depth: Option<u32>,
    /// Parent grant (if this is a delegated grant).
    pub parent_grant: Option<TrustId>,
    /// Current delegation depth (0 = direct grant).
    pub delegation_depth: u32,
    /// Revocation configuration.
    pub revocation: RevocationConfig,
    /// Grant timestamp (microseconds since epoch).
    pub granted_at: u64,
    /// Hash of all grant fields.
    pub grant_hash: String,
    /// Grantor's signature over the grant hash.
    pub grantor_signature: String,
    /// Grantee's acknowledgment signature (optional).
    pub grantee_acknowledgment: Option<String>,
}

impl TrustGrant {
    /// Verify the grantor's signature on this grant.
    pub fn verify_signature(&self) -> Result<()> {
        let pub_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.grantor_key,
        )
        .map_err(|e| IdentityError::InvalidKey(format!("invalid base64 grantor key: {e}")))?;

        let key_bytes: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("grantor key must be 32 bytes".into()))?;

        let verifying_key =
            crate::crypto::keys::Ed25519KeyPair::verifying_key_from_bytes(&key_bytes)?;

        signing::verify_from_base64(
            &verifying_key,
            self.grant_hash.as_bytes(),
            &self.grantor_signature,
        )
    }

    /// Add the grantee's acknowledgment signature.
    pub fn acknowledge(&mut self, grantee_signing_key: &SigningKey) -> Result<()> {
        let ack_message = format!("ack:{}:{}", self.id.0, self.grant_hash);
        let sig = signing::sign_to_base64(grantee_signing_key, ack_message.as_bytes());
        self.grantee_acknowledgment = Some(sig);
        Ok(())
    }
}

/// Builder for creating trust grants.
pub struct TrustGrantBuilder {
    grantor: IdentityId,
    grantee: IdentityId,
    grantee_key: String,
    capabilities: Vec<Capability>,
    constraints: TrustConstraints,
    delegation_allowed: bool,
    max_delegation_depth: Option<u32>,
    parent_grant: Option<TrustId>,
    delegation_depth: u32,
    revocation_channel: RevocationChannel,
    required_witnesses: Vec<IdentityId>,
}

impl TrustGrantBuilder {
    /// Start building a trust grant from grantor to grantee.
    pub fn new(grantor: IdentityId, grantee: IdentityId, grantee_key: String) -> Self {
        Self {
            grantor,
            grantee,
            grantee_key,
            capabilities: Vec::new(),
            constraints: TrustConstraints::open(),
            delegation_allowed: false,
            max_delegation_depth: None,
            parent_grant: None,
            delegation_depth: 0,
            revocation_channel: RevocationChannel::Local,
            required_witnesses: Vec::new(),
        }
    }

    /// Add a capability to the grant.
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Add multiple capabilities.
    pub fn capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities.extend(caps);
        self
    }

    /// Set the constraints.
    pub fn constraints(mut self, constraints: TrustConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Allow the grantee to delegate trust to others.
    pub fn allow_delegation(mut self, max_depth: u32) -> Self {
        self.delegation_allowed = true;
        self.max_delegation_depth = Some(max_depth);
        self
    }

    /// Mark this as a delegated grant from a parent.
    pub fn delegated_from(mut self, parent: TrustId, depth: u32) -> Self {
        self.parent_grant = Some(parent);
        self.delegation_depth = depth;
        self
    }

    /// Set the revocation channel.
    pub fn revocation_channel(mut self, channel: RevocationChannel) -> Self {
        self.revocation_channel = channel;
        self
    }

    /// Set required witnesses for revocation.
    pub fn revocation_witnesses(mut self, witnesses: Vec<IdentityId>) -> Self {
        self.required_witnesses = witnesses;
        self
    }

    /// Sign and finalize the trust grant.
    pub fn sign(self, grantor_signing_key: &SigningKey) -> Result<TrustGrant> {
        if self.capabilities.is_empty() {
            return Err(IdentityError::TrustNotGranted(
                "no capabilities specified".into(),
            ));
        }

        let now = crate::time::now_micros();
        let grantor_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            grantor_signing_key.verifying_key().to_bytes(),
        );

        // Derive revocation key ID
        let revocation_key_id = format!("revkey_{}", &self.grantor.0[4..]);

        let revocation = RevocationConfig {
            revocation_key_id,
            revocation_channel: self.revocation_channel,
            required_witnesses: self.required_witnesses,
        };

        // Compute grant hash over all fields
        let caps_json = serde_json::to_string(&self.capabilities).unwrap_or_default();
        let constraints_json = serde_json::to_string(&self.constraints).unwrap_or_default();

        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.grantor.0,
            grantor_key,
            self.grantee.0,
            self.grantee_key,
            caps_json,
            constraints_json,
            self.delegation_allowed,
            self.max_delegation_depth.unwrap_or(0),
            now,
        );
        let grant_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        // Generate trust ID from the hash
        let id_hash = Sha256::digest(grant_hash.as_bytes());
        let id_encoded = bs58::encode(&id_hash[..16]).into_string();
        let id = TrustId(format!("atrust_{id_encoded}"));

        // Sign the grant hash
        let grantor_signature = signing::sign_to_base64(grantor_signing_key, grant_hash.as_bytes());

        Ok(TrustGrant {
            id,
            grantor: self.grantor,
            grantor_key,
            grantee: self.grantee,
            grantee_key: self.grantee_key,
            capabilities: self.capabilities,
            constraints: self.constraints,
            delegation_allowed: self.delegation_allowed,
            max_delegation_depth: self.max_delegation_depth,
            parent_grant: self.parent_grant,
            delegation_depth: self.delegation_depth,
            revocation,
            granted_at: now,
            grant_hash,
            grantor_signature,
            grantee_acknowledgment: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    fn make_grantee_key(anchor: &IdentityAnchor) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anchor.verifying_key_bytes(),
        )
    }

    #[test]
    fn test_trust_grant_create() {
        let grantor = IdentityAnchor::new(Some("grantor".into()));
        let grantee = IdentityAnchor::new(Some("grantee".into()));

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        assert!(grant.id.0.starts_with("atrust_"));
        assert_eq!(grant.grantor, grantor.id());
        assert_eq!(grant.grantee, grantee.id());
        assert!(!grant.grant_hash.is_empty());
        assert!(!grant.grantor_signature.is_empty());
    }

    #[test]
    fn test_trust_grant_verify_signature() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:*"))
            .sign(grantor.signing_key())
            .unwrap();

        assert!(grant.verify_signature().is_ok());
    }

    #[test]
    fn test_trust_grant_no_capabilities_fails() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let result = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .sign(grantor.signing_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_trust_grant_with_delegation() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:*"))
            .allow_delegation(3)
            .sign(grantor.signing_key())
            .unwrap();

        assert!(grant.delegation_allowed);
        assert_eq!(grant.max_delegation_depth, Some(3));
    }

    #[test]
    fn test_trust_grant_acknowledge() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let mut grant =
            TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
                .capability(Capability::new("read:calendar"))
                .sign(grantor.signing_key())
                .unwrap();

        assert!(grant.grantee_acknowledgment.is_none());
        grant.acknowledge(grantee.signing_key()).unwrap();
        assert!(grant.grantee_acknowledgment.is_some());
    }

    #[test]
    fn test_trust_grant_unique_ids() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let g1 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));

        let g2 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        assert_ne!(g1.id, g2.id);
    }
}
