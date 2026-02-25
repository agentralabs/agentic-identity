//! Trust verification — checking if a trust grant is currently valid.
//!
//! Verification checks:
//! 1. Signature validity (grantor signed the grant)
//! 2. Time validity (within not_before / not_after window)
//! 3. Revocation status (not revoked)
//! 4. Use count (within max_uses)
//! 5. Capability match (requested capability is covered)

use crate::error::Result;

use super::capability::capabilities_cover;
use super::grant::TrustGrant;
use super::revocation::Revocation;

/// Result of verifying a trust grant.
#[derive(Debug, Clone)]
pub struct TrustVerification {
    /// Is the grant signature valid?
    pub signature_valid: bool,
    /// Is the grant within its validity period?
    pub time_valid: bool,
    /// Is the grant not revoked?
    pub not_revoked: bool,
    /// Has max uses been exceeded?
    pub uses_valid: bool,
    /// Is the requested capability specifically granted?
    pub capability_granted: bool,
    /// Trust chain (if delegated).
    pub trust_chain: Vec<super::grant::TrustId>,
    /// Overall validity.
    pub is_valid: bool,
    /// Verification timestamp.
    pub verified_at: u64,
}

/// Verify a trust grant for a specific capability at the current time.
///
/// `current_uses` is the number of times this grant has been used so far.
/// `revocations` is the list of known revocations to check against.
pub fn verify_trust_grant(
    grant: &TrustGrant,
    requested_capability: &str,
    current_uses: u64,
    revocations: &[Revocation],
) -> Result<TrustVerification> {
    let now = crate::time::now_micros();

    // 1. Signature check
    let signature_valid = grant.verify_signature().is_ok();

    // 2. Time validity
    let time_valid = grant.constraints.is_time_valid(now);

    // 3. Revocation check
    let not_revoked = !revocations.iter().any(|r| r.trust_id == grant.id);

    // 4. Use count check
    let uses_valid = grant.constraints.is_within_uses(current_uses);

    // 5. Capability match
    let capability_granted = capabilities_cover(&grant.capabilities, requested_capability);

    let is_valid = signature_valid && time_valid && not_revoked && uses_valid && capability_granted;

    Ok(TrustVerification {
        signature_valid,
        time_valid,
        not_revoked,
        uses_valid,
        capability_granted,
        trust_chain: Vec::new(),
        is_valid,
        verified_at: now,
    })
}

/// Quick check: is a grant valid for a capability right now?
pub fn is_grant_valid(
    grant: &TrustGrant,
    requested_capability: &str,
    current_uses: u64,
    revocations: &[Revocation],
) -> bool {
    verify_trust_grant(grant, requested_capability, current_uses, revocations)
        .map(|v| v.is_valid)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::trust::capability::Capability;
    use crate::trust::constraint::TrustConstraints;
    use crate::trust::grant::TrustGrantBuilder;
    use crate::trust::revocation::{Revocation, RevocationReason};

    fn make_grantee_key(anchor: &IdentityAnchor) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anchor.verifying_key_bytes(),
        )
    }

    #[test]
    fn test_verify_valid_grant() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        let result = verify_trust_grant(&grant, "read:calendar", 0, &[]).unwrap();
        assert!(result.signature_valid);
        assert!(result.time_valid);
        assert!(result.not_revoked);
        assert!(result.uses_valid);
        assert!(result.capability_granted);
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_expired_grant() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let now = crate::time::now_micros();

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .constraints(TrustConstraints::time_bounded(
                now - 2_000_000,
                now - 1_000_000,
            ))
            .sign(grantor.signing_key())
            .unwrap();

        let result = verify_trust_grant(&grant, "read:calendar", 0, &[]).unwrap();
        assert!(result.signature_valid);
        assert!(!result.time_valid);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_not_yet_valid_grant() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let now = crate::time::now_micros();

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .constraints(TrustConstraints::time_bounded(
                now + 1_000_000,
                now + 2_000_000,
            ))
            .sign(grantor.signing_key())
            .unwrap();

        let result = verify_trust_grant(&grant, "read:calendar", 0, &[]).unwrap();
        assert!(!result.time_valid);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_max_uses_exceeded() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .constraints(TrustConstraints::open().with_max_uses(3))
            .sign(grantor.signing_key())
            .unwrap();

        // Uses 0, 1, 2 are valid
        assert!(
            verify_trust_grant(&grant, "read:calendar", 0, &[])
                .unwrap()
                .is_valid
        );
        assert!(
            verify_trust_grant(&grant, "read:calendar", 2, &[])
                .unwrap()
                .is_valid
        );
        // Use 3 exceeds max
        let result = verify_trust_grant(&grant, "read:calendar", 3, &[]).unwrap();
        assert!(!result.uses_valid);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_revoked_grant() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        let revocation = Revocation::create(
            grant.id.clone(),
            grantor.id(),
            RevocationReason::ManualRevocation,
            grantor.signing_key(),
        );

        let result = verify_trust_grant(&grant, "read:calendar", 0, &[revocation]).unwrap();
        assert!(!result.not_revoked);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_capability_mismatch() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        let result = verify_trust_grant(&grant, "write:calendar", 0, &[]).unwrap();
        assert!(!result.capability_granted);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_wildcard_capability() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:*"))
            .sign(grantor.signing_key())
            .unwrap();

        assert!(
            verify_trust_grant(&grant, "read:calendar", 0, &[])
                .unwrap()
                .is_valid
        );
        assert!(
            verify_trust_grant(&grant, "read:email", 0, &[])
                .unwrap()
                .is_valid
        );
        assert!(
            !verify_trust_grant(&grant, "write:calendar", 0, &[])
                .unwrap()
                .is_valid
        );
    }

    #[test]
    fn test_is_grant_valid_convenience() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_grantee_key(&grantee))
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .unwrap();

        assert!(is_grant_valid(&grant, "read:calendar", 0, &[]));
        assert!(!is_grant_valid(&grant, "write:calendar", 0, &[]));
    }
}
