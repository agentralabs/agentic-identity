//! Stress test: create a chain of 1000 receipts, verify chain integrity,
//! and ensure it completes in reasonable time.

use std::time::Instant;

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::chain::verify_chain;
use agentic_identity::receipt::receipt::ReceiptBuilder;

#[test]
fn stress_receipt_chain_1000() {
    let anchor = IdentityAnchor::new(Some("chain-agent".to_string()));
    let mut chain = Vec::with_capacity(1000);

    let start = Instant::now();

    // Build the first receipt (no previous)
    let first = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Observation,
        ActionContent::new("Chain receipt 0"),
    )
    .sign(anchor.signing_key())
    .expect("first receipt signing should succeed");

    chain.push(first);

    // Build 999 more receipts, each chaining to the previous
    for i in 1..1000 {
        let prev_id = chain.last().unwrap().id.clone();
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(format!("Chain receipt {i}")),
        )
        .chain_to(prev_id)
        .sign(anchor.signing_key())
        .unwrap_or_else(|_| panic!("receipt {i} signing should succeed"));

        chain.push(receipt);
    }

    let build_elapsed = start.elapsed();
    assert_eq!(chain.len(), 1000);

    // Verify the chain links are correct
    for i in 1..chain.len() {
        assert_eq!(
            chain[i].previous_receipt.as_ref().unwrap(),
            &chain[i - 1].id,
            "Receipt {i} should chain to receipt {}",
            i - 1
        );
    }

    // Verify the full chain cryptographically
    let verify_start = Instant::now();
    let result = verify_chain(&chain);
    let verify_elapsed = verify_start.elapsed();

    assert!(
        result.is_ok(),
        "Chain of 1000 receipts should verify successfully"
    );

    let total_elapsed = start.elapsed();

    // Ensure reasonable performance (under 60 seconds total)
    assert!(
        total_elapsed.as_secs() < 60,
        "1000-receipt chain should complete in under 60 seconds, took {:?}",
        total_elapsed
    );

    eprintln!(
        "Receipt chain stress test: build={:?}, verify={:?}, total={:?}",
        build_elapsed, verify_elapsed, total_elapsed
    );
}

#[test]
fn stress_receipt_chain_1000_unique_ids() {
    let anchor = IdentityAnchor::new(None);
    let mut chain = Vec::with_capacity(1000);
    let mut seen_ids = std::collections::HashSet::new();

    let first = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Decision,
        ActionContent::new("First"),
    )
    .sign(anchor.signing_key())
    .expect("signing should succeed");

    seen_ids.insert(first.id.0.clone());
    chain.push(first);

    for i in 1..1000 {
        let prev_id = chain.last().unwrap().id.clone();
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(format!("Receipt {i}")),
        )
        .chain_to(prev_id)
        .sign(anchor.signing_key())
        .expect("signing should succeed");

        assert!(
            seen_ids.insert(receipt.id.0.clone()),
            "Duplicate receipt ID at position {i}"
        );
        chain.push(receipt);
    }

    assert_eq!(seen_ids.len(), 1000);
}
