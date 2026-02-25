//! Stress test: single identity performs 1000 sequential sign operations,
//! all receipts must be valid.

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;

#[test]
fn stress_1000_sequential_signs() {
    let anchor = IdentityAnchor::new(Some("high-throughput-agent".to_string()));
    let mut receipts = Vec::with_capacity(1000);

    for i in 0..1000 {
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(format!("Operation {i}")),
        )
        .sign(anchor.signing_key())
        .expect("signing should succeed");

        receipts.push(receipt);
    }

    assert_eq!(receipts.len(), 1000);

    // Verify all receipts
    for (i, receipt) in receipts.iter().enumerate() {
        let verification = verify_receipt(receipt).expect("verification should succeed");
        assert!(verification.is_valid, "Receipt {i} should be valid");
        assert!(
            verification.signature_valid,
            "Receipt {i} signature should be valid"
        );
    }
}

#[test]
fn stress_1000_signs_unique_receipt_ids() {
    let anchor = IdentityAnchor::new(None);
    let mut seen_ids = std::collections::HashSet::new();

    for i in 0..1000 {
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Observation,
            ActionContent::new(format!("Observation {i}")),
        )
        .sign(anchor.signing_key())
        .expect("signing should succeed");

        assert!(
            seen_ids.insert(receipt.id.0.clone()),
            "Duplicate receipt ID at iteration {i}: {}",
            receipt.id.0
        );
    }

    assert_eq!(seen_ids.len(), 1000);
}
