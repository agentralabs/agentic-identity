//! Stress test: create 100 identities, verify all have unique IDs,
//! and all can sign and verify a receipt.

use std::collections::HashSet;

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;

#[test]
fn stress_100_unique_identities() {
    let mut ids = HashSet::new();
    let mut anchors = Vec::with_capacity(100);

    // Create 100 identities
    for i in 0..100 {
        let anchor = IdentityAnchor::new(Some(format!("agent-{i}")));
        let id = anchor.id();

        // Each ID must be unique
        assert!(
            ids.insert(id.0.clone()),
            "Duplicate identity ID found: {}",
            id.0
        );

        anchors.push(anchor);
    }

    assert_eq!(ids.len(), 100);
}

#[test]
fn stress_100_identities_sign_and_verify() {
    let anchors: Vec<IdentityAnchor> = (0..100)
        .map(|i| IdentityAnchor::new(Some(format!("agent-{i}"))))
        .collect();

    for (i, anchor) in anchors.iter().enumerate() {
        // Each identity signs a receipt
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(format!("Decision by agent-{i}")),
        )
        .sign(anchor.signing_key())
        .expect("signing should succeed");

        // Verify the receipt
        let verification = verify_receipt(&receipt).expect("verification should succeed");
        assert!(
            verification.is_valid,
            "Receipt from agent-{i} should be valid"
        );
        assert!(
            verification.signature_valid,
            "Signature from agent-{i} should be valid"
        );
    }
}
