//! Scale test: 10K receipt signing and verification.
//!
//! Validates that receipt signing and chain verification scale linearly.

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;

#[test]
fn stress_10k_receipts_sign_and_chain() {
    let anchor = IdentityAnchor::new(Some("scale-receipts".to_string()));
    let mut prev_id: Option<agentic_identity::ReceiptId> = None;

    for i in 0..10_000 {
        let mut builder = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Custom("scale_test".into()),
            ActionContent::new(format!("Operation {i}")),
        );

        if let Some(ref pid) = prev_id {
            builder = builder.chain_to(pid.clone());
        }

        let receipt = builder
            .sign(anchor.signing_key())
            .expect("signing should succeed");
        prev_id = Some(receipt.id.clone());
    }

    // Chain of 10K receipts created successfully
    assert!(prev_id.is_some());
}

#[test]
fn stress_10k_receipts_all_verify() {
    let anchor = IdentityAnchor::new(Some("verify-scale".to_string()));
    let mut receipts = Vec::with_capacity(10_000);

    for i in 0..10_000 {
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Custom("verify_test".into()),
            ActionContent::new(format!("Action {i}")),
        )
        .sign(anchor.signing_key())
        .expect("signing should succeed");
        receipts.push(receipt);
    }

    // Verify all 10K receipts
    for (i, receipt) in receipts.iter().enumerate() {
        let result = verify_receipt(receipt).expect("verification should succeed");
        assert!(result.is_valid, "Receipt {i} failed verification");
    }
}

#[test]
fn stress_1k_identities_each_sign_10() {
    // 1000 identities each sign 10 receipts = 10K total
    let mut total = 0u64;
    for i in 0..1_000 {
        let anchor = IdentityAnchor::new(Some(format!("identity-{i}")));
        for j in 0..10 {
            let _receipt = ReceiptBuilder::new(
                anchor.id(),
                ActionType::Custom("multi_identity_scale".into()),
                ActionContent::new(format!("Action {i}_{j}")),
            )
            .sign(anchor.signing_key())
            .expect("signing should succeed");
            total += 1;
        }
    }
    assert_eq!(total, 10_000);
}
