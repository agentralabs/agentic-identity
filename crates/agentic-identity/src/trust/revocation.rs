//! Revocation — revoking trust grants.
//!
//! When a trust grant needs to be invalidated, a revocation record is
//! created, signed with the revocation key derived from the grantor's
//! root identity, and published to the configured revocation channel.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::signing;
use crate::identity::IdentityId;
use crate::receipt::WitnessSignature;

use super::grant::TrustId;

/// Configuration for how a trust grant can be revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationConfig {
    /// Revocation key ID (derived key for revoking this specific grant).
    pub revocation_key_id: String,
    /// Channel where revocation will be published.
    pub revocation_channel: RevocationChannel,
    /// Required witnesses for revocation (optional).
    pub required_witnesses: Vec<IdentityId>,
}

/// Where revocation is published.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationChannel {
    /// Local revocation list (checked on verify).
    Local,
    /// HTTP endpoint for publishing/checking revocations.
    Http { url: String },
    /// Distributed ledger.
    Ledger { ledger_id: String },
    /// Multiple channels simultaneously.
    Multi(Vec<RevocationChannel>),
}

/// A revocation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    /// Trust grant being revoked.
    pub trust_id: TrustId,
    /// Who is revoking (must be grantor or authorized revoker).
    pub revoker: IdentityId,
    /// Revoker's public key.
    pub revoker_key: String,
    /// Revocation timestamp (microseconds since epoch).
    pub revoked_at: u64,
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Signature with revocation key (signs trust_id + revoker + revoked_at + reason).
    pub signature: String,
    /// Witness signatures (if required by revocation config).
    pub witnesses: Vec<WitnessSignature>,
}

impl Revocation {
    /// Create a new revocation record.
    pub fn create(
        trust_id: TrustId,
        revoker: IdentityId,
        reason: RevocationReason,
        signing_key: &SigningKey,
    ) -> Self {
        let now = crate::time::now_micros();
        let revoker_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing_key.verifying_key().to_bytes(),
        );

        let to_sign = format!(
            "revoke:{}:{}:{}:{}",
            trust_id.0,
            revoker.0,
            now,
            reason.as_str(),
        );
        let signature = signing::sign_to_base64(signing_key, to_sign.as_bytes());

        Self {
            trust_id,
            revoker,
            revoker_key,
            revoked_at: now,
            reason,
            signature,
            witnesses: Vec::new(),
        }
    }

    /// Add a witness to this revocation.
    pub fn add_witness(&mut self, witness: WitnessSignature) {
        self.witnesses.push(witness);
    }

    /// Verify the revocation signature.
    pub fn verify_signature(&self) -> crate::error::Result<()> {
        let pub_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.revoker_key,
        )
        .map_err(|e| {
            crate::error::IdentityError::InvalidKey(format!("invalid base64 revoker key: {e}"))
        })?;

        let key_bytes: [u8; 32] = pub_bytes.try_into().map_err(|_| {
            crate::error::IdentityError::InvalidKey("revoker key must be 32 bytes".into())
        })?;

        let verifying_key =
            crate::crypto::keys::Ed25519KeyPair::verifying_key_from_bytes(&key_bytes)?;

        let to_verify = format!(
            "revoke:{}:{}:{}:{}",
            self.trust_id.0,
            self.revoker.0,
            self.revoked_at,
            self.reason.as_str(),
        );

        signing::verify_from_base64(&verifying_key, to_verify.as_bytes(), &self.signature)
    }
}

/// Reason for revocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    /// Trust grant has expired naturally.
    Expired,
    /// Grantee's key or system has been compromised.
    Compromised,
    /// Grantee violated the terms of the trust.
    PolicyViolation,
    /// Manual revocation by grantor.
    ManualRevocation,
    /// Grantee requested revocation.
    GranteeRequest,
    /// Custom reason.
    Custom(String),
}

impl RevocationReason {
    /// Return a stable string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Expired => "expired",
            Self::Compromised => "compromised",
            Self::PolicyViolation => "policy_violation",
            Self::ManualRevocation => "manual_revocation",
            Self::GranteeRequest => "grantee_request",
            Self::Custom(s) => s.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    #[test]
    fn test_revocation_create_and_verify() {
        let grantor = IdentityAnchor::new(Some("grantor".into()));
        let trust_id = TrustId("atrust_test123".to_string());

        let revocation = Revocation::create(
            trust_id.clone(),
            grantor.id(),
            RevocationReason::ManualRevocation,
            grantor.signing_key(),
        );

        assert_eq!(revocation.trust_id, trust_id);
        assert_eq!(revocation.revoker, grantor.id());
        assert_eq!(revocation.reason, RevocationReason::ManualRevocation);
        assert!(revocation.verify_signature().is_ok());
    }

    #[test]
    fn test_revocation_reason_strings() {
        assert_eq!(RevocationReason::Expired.as_str(), "expired");
        assert_eq!(RevocationReason::Compromised.as_str(), "compromised");
        assert_eq!(
            RevocationReason::PolicyViolation.as_str(),
            "policy_violation"
        );
        assert_eq!(
            RevocationReason::ManualRevocation.as_str(),
            "manual_revocation"
        );
        assert_eq!(RevocationReason::GranteeRequest.as_str(), "grantee_request");
        assert_eq!(RevocationReason::Custom("breach".into()).as_str(), "breach");
    }
}
