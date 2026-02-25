//! Trust chain walking — delegation verification.
//!
//! When Identity A trusts B, and B delegates to C, then C's trust
//! must be verified through the entire chain: A → B → C.
//! Each link must be valid: signed, not expired, not revoked, and
//! the delegator must have delegation rights with sufficient depth.

use crate::error::{IdentityError, Result};

use super::capability::capabilities_cover;
use super::grant::{TrustGrant, TrustId};
use super::revocation::Revocation;
use super::verify::TrustVerification;

/// Verify a trust chain for a specific capability.
///
/// `chain` is the delegation chain from root grant to the final delegated grant.
/// The chain must be ordered: chain[0] is the root grant (A→B),
/// chain[1] is the first delegation (B→C), etc.
///
/// Each link in the chain is verified:
/// 1. Signature is valid
/// 2. Time constraints are satisfied
/// 3. Not revoked
/// 4. Capability is covered
/// 5. Delegation is allowed with sufficient depth
pub fn verify_trust_chain(
    chain: &[TrustGrant],
    requested_capability: &str,
    revocations: &[Revocation],
) -> Result<TrustVerification> {
    let now = crate::time::now_micros();

    if chain.is_empty() {
        return Err(IdentityError::InvalidChain);
    }

    let mut trust_chain_ids: Vec<TrustId> = Vec::new();
    let mut all_valid = true;
    let mut sig_valid = true;
    let mut time_valid = true;
    let mut not_revoked = true;
    let mut cap_granted = true;

    for (i, grant) in chain.iter().enumerate() {
        trust_chain_ids.push(grant.id.clone());

        // 1. Signature check
        if grant.verify_signature().is_err() {
            sig_valid = false;
            all_valid = false;
        }

        // 2. Time validity
        if !grant.constraints.is_time_valid(now) {
            time_valid = false;
            all_valid = false;
        }

        // 3. Revocation check — if ANY link is revoked, chain is invalid
        if revocations.iter().any(|r| r.trust_id == grant.id) {
            not_revoked = false;
            all_valid = false;
        }

        // 4. Capability coverage — every link must cover the requested capability
        if !capabilities_cover(&grant.capabilities, requested_capability) {
            cap_granted = false;
            all_valid = false;
        }

        // 5. Delegation checks (for links after the root)
        if i > 0 {
            let parent = &chain[i - 1];

            // Parent must allow delegation
            if !parent.delegation_allowed {
                return Err(IdentityError::DelegationNotAllowed);
            }

            // Check delegation depth
            if let Some(max_depth) = parent.max_delegation_depth {
                if grant.delegation_depth > max_depth {
                    return Err(IdentityError::DelegationDepthExceeded);
                }
            }

            // The delegator (chain[i].grantor) must be the grantee of the parent
            if grant.grantor != parent.grantee {
                return Err(IdentityError::InvalidChain);
            }
        }
    }

    Ok(TrustVerification {
        signature_valid: sig_valid,
        time_valid,
        not_revoked,
        uses_valid: true, // Use counting is per-grant, handled externally
        capability_granted: cap_granted,
        trust_chain: trust_chain_ids,
        is_valid: all_valid,
        verified_at: now,
    })
}

/// Create a delegated trust grant from an existing grant.
///
/// The grantee of `parent_grant` becomes the grantor of the new grant.
/// Returns an error if delegation is not allowed or depth is exceeded.
pub fn validate_delegation(
    parent_grant: &TrustGrant,
    requested_capabilities: &[super::capability::Capability],
) -> Result<()> {
    // Check delegation is allowed
    if !parent_grant.delegation_allowed {
        return Err(IdentityError::DelegationNotAllowed);
    }

    // Check depth
    let next_depth = parent_grant.delegation_depth + 1;
    if let Some(max_depth) = parent_grant.max_delegation_depth {
        if next_depth > max_depth {
            return Err(IdentityError::DelegationDepthExceeded);
        }
    }

    // Check that requested capabilities are covered by parent
    for cap in requested_capabilities {
        if !capabilities_cover(&parent_grant.capabilities, &cap.uri) {
            return Err(IdentityError::TrustNotGranted(format!(
                "parent grant does not cover capability: {}",
                cap.uri
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::trust::capability::Capability;
    use crate::trust::grant::TrustGrantBuilder;
    use crate::trust::revocation::{Revocation, RevocationReason};

    fn make_key_b64(anchor: &IdentityAnchor) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anchor.verifying_key_bytes(),
        )
    }

    #[test]
    fn test_single_grant_chain() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:calendar"))
            .sign(a.signing_key())
            .unwrap();

        let result = verify_trust_chain(&[grant], "read:calendar", &[]).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_chain.len(), 1);
    }

    #[test]
    fn test_delegation_chain_a_b_c() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);
        let c = IdentityAnchor::new(None);

        // A trusts B with delegation
        let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:*"))
            .allow_delegation(2)
            .sign(a.signing_key())
            .unwrap();

        // B delegates to C
        let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
            .capability(Capability::new("read:calendar"))
            .delegated_from(ab.id.clone(), 1)
            .sign(b.signing_key())
            .unwrap();

        let result = verify_trust_chain(&[ab, bc], "read:calendar", &[]).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.trust_chain.len(), 2);
    }

    #[test]
    fn test_delegation_not_allowed() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);
        let c = IdentityAnchor::new(None);

        // A trusts B WITHOUT delegation
        let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:*"))
            .sign(a.signing_key())
            .unwrap();

        // B tries to delegate to C
        let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
            .capability(Capability::new("read:calendar"))
            .delegated_from(ab.id.clone(), 1)
            .sign(b.signing_key())
            .unwrap();

        let result = verify_trust_chain(&[ab, bc], "read:calendar", &[]);
        assert!(matches!(result, Err(IdentityError::DelegationNotAllowed)));
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);
        let c = IdentityAnchor::new(None);
        let d = IdentityAnchor::new(None);

        // A trusts B with max depth 1
        let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:*"))
            .allow_delegation(1)
            .sign(a.signing_key())
            .unwrap();

        // B delegates to C (depth 1, ok)
        let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
            .capability(Capability::new("read:*"))
            .allow_delegation(1)
            .delegated_from(ab.id.clone(), 1)
            .sign(b.signing_key())
            .unwrap();

        // C tries to delegate to D (depth 2, exceeds A's max of 1)
        let cd = TrustGrantBuilder::new(c.id(), d.id(), make_key_b64(&d))
            .capability(Capability::new("read:calendar"))
            .delegated_from(bc.id.clone(), 2)
            .sign(c.signing_key())
            .unwrap();

        let result = verify_trust_chain(&[ab, bc, cd], "read:calendar", &[]);
        assert!(matches!(
            result,
            Err(IdentityError::DelegationDepthExceeded)
        ));
    }

    #[test]
    fn test_revoked_link_invalidates_chain() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);
        let c = IdentityAnchor::new(None);

        let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:*"))
            .allow_delegation(2)
            .sign(a.signing_key())
            .unwrap();

        let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
            .capability(Capability::new("read:calendar"))
            .delegated_from(ab.id.clone(), 1)
            .sign(b.signing_key())
            .unwrap();

        // Revoke A→B
        let revocation = Revocation::create(
            ab.id.clone(),
            a.id(),
            RevocationReason::ManualRevocation,
            a.signing_key(),
        );

        let result = verify_trust_chain(&[ab, bc], "read:calendar", &[revocation]).unwrap();
        assert!(!result.not_revoked);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_delegation_ok() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:*"))
            .allow_delegation(2)
            .sign(a.signing_key())
            .unwrap();

        let caps = vec![Capability::new("read:calendar")];
        assert!(validate_delegation(&grant, &caps).is_ok());
    }

    #[test]
    fn test_validate_delegation_capability_not_covered() {
        let a = IdentityAnchor::new(None);
        let b = IdentityAnchor::new(None);

        let grant = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
            .capability(Capability::new("read:calendar"))
            .allow_delegation(2)
            .sign(a.signing_key())
            .unwrap();

        let caps = vec![Capability::new("write:calendar")];
        assert!(validate_delegation(&grant, &caps).is_err());
    }

    #[test]
    fn test_empty_chain_error() {
        let result = verify_trust_chain(&[], "read:calendar", &[]);
        assert!(matches!(result, Err(IdentityError::InvalidChain)));
    }
}
