//! Stress test: create a trust chain of depth 50 and verify terminal trust.

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::chain::verify_trust_chain;
use agentic_identity::trust::grant::TrustGrantBuilder;

/// Helper to get base64 public key from an anchor.
fn pub_key_b64(anchor: &IdentityAnchor) -> String {
    anchor.public_key_base64()
}

#[test]
fn stress_trust_chain_depth_50() {
    let chain_depth = 50;

    // Create chain_depth + 1 identities (one root + 50 delegates)
    let identities: Vec<IdentityAnchor> = (0..=chain_depth)
        .map(|i| IdentityAnchor::new(Some(format!("node-{i}"))))
        .collect();

    let mut grants = Vec::with_capacity(chain_depth);

    // Build the root grant: identities[0] -> identities[1]
    let root_grant = TrustGrantBuilder::new(
        identities[0].id(),
        identities[1].id(),
        pub_key_b64(&identities[1]),
    )
    .capability(Capability::new("read:*"))
    .allow_delegation(chain_depth as u32)
    .sign(identities[0].signing_key())
    .expect("root grant signing should succeed");

    grants.push(root_grant);

    // Build delegation chain: identities[i] -> identities[i+1] for i in 1..chain_depth
    for i in 1..chain_depth {
        let parent_id = grants.last().unwrap().id.clone();
        let grant = TrustGrantBuilder::new(
            identities[i].id(),
            identities[i + 1].id(),
            pub_key_b64(&identities[i + 1]),
        )
        .capability(Capability::new("read:*"))
        .allow_delegation(chain_depth as u32)
        .delegated_from(parent_id, i as u32)
        .sign(identities[i].signing_key())
        .unwrap_or_else(|_| panic!("delegation grant {i} signing should succeed"));

        grants.push(grant);
    }

    assert_eq!(grants.len(), chain_depth);

    // Verify the entire trust chain
    let verification = verify_trust_chain(&grants, "read:docs", &[])
        .expect("trust chain verification should succeed");

    assert!(
        verification.is_valid,
        "Trust chain of depth {chain_depth} should be valid"
    );
    assert!(verification.signature_valid);
    assert!(verification.capability_granted);
    assert_eq!(verification.trust_chain.len(), chain_depth);
}

#[test]
fn stress_trust_chain_depth_50_specific_capability() {
    let chain_depth = 50;

    let identities: Vec<IdentityAnchor> = (0..=chain_depth)
        .map(|i| IdentityAnchor::new(Some(format!("cap-node-{i}"))))
        .collect();

    let mut grants = Vec::with_capacity(chain_depth);

    // Root grant with specific capability
    let root_grant = TrustGrantBuilder::new(
        identities[0].id(),
        identities[1].id(),
        pub_key_b64(&identities[1]),
    )
    .capability(Capability::new("execute:deploy:*"))
    .allow_delegation(chain_depth as u32)
    .sign(identities[0].signing_key())
    .expect("root grant should succeed");

    grants.push(root_grant);

    for i in 1..chain_depth {
        let parent_id = grants.last().unwrap().id.clone();
        let grant = TrustGrantBuilder::new(
            identities[i].id(),
            identities[i + 1].id(),
            pub_key_b64(&identities[i + 1]),
        )
        .capability(Capability::new("execute:deploy:*"))
        .allow_delegation(chain_depth as u32)
        .delegated_from(parent_id, i as u32)
        .sign(identities[i].signing_key())
        .expect("delegation should succeed");

        grants.push(grant);
    }

    // Verify with matching capability
    let result = verify_trust_chain(&grants, "execute:deploy:production", &[])
        .expect("chain verification should succeed");
    assert!(result.is_valid, "Matching capability should be valid");

    // Verify with non-matching capability
    let result = verify_trust_chain(&grants, "read:calendar", &[])
        .expect("chain verification should succeed");
    assert!(
        !result.is_valid,
        "Non-matching capability should not be valid"
    );
}
