//! Concurrency test: parallel trust verification and signing.
//!
//! Validates that trust operations are thread-safe and produce consistent results.

use std::sync::{Arc, Mutex};
use std::thread;

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::verify::verify_trust_grant;

#[test]
fn stress_50_concurrent_signers() {
    let anchor = Arc::new(IdentityAnchor::new(Some("concurrent-signer".to_string())));
    let receipts = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for thread_id in 0..50 {
        let anchor = Arc::clone(&anchor);
        let receipts = Arc::clone(&receipts);
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let receipt = ReceiptBuilder::new(
                    anchor.id(),
                    ActionType::Custom("concurrent_sign".into()),
                    ActionContent::new(format!("Thread {thread_id} action {i}")),
                )
                .sign(anchor.signing_key())
                .expect("signing should succeed");
                receipts.lock().unwrap().push(receipt);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let receipts = receipts.lock().unwrap();
    assert_eq!(receipts.len(), 5_000);

    // Verify all receipts are valid
    for receipt in receipts.iter() {
        let result = verify_receipt(receipt).expect("verification should succeed");
        assert!(result.is_valid);
    }
}

#[test]
fn stress_100_concurrent_trust_verifiers() {
    let grantor = IdentityAnchor::new(Some("grantor".to_string()));
    let grantee = IdentityAnchor::new(Some("grantee".to_string()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
        .capability(Capability::new("calendar:*"))
        .sign(grantor.signing_key())
        .expect("grant should succeed");

    let grant = Arc::new(grant);
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for _ in 0..100 {
        let grant = Arc::clone(&grant);
        let results = Arc::clone(&results);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let result = verify_trust_grant(&grant, "calendar:events:read", 0, &[])
                    .expect("verification should succeed");
                results.lock().unwrap().push(result.is_valid);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let results = results.lock().unwrap();
    assert_eq!(results.len(), 5_000);
    assert!(
        results.iter().all(|v| *v),
        "All trust verifications should be valid"
    );
}

#[test]
fn stress_concurrent_sign_and_verify() {
    // Half threads sign, half verify — interleaved
    let anchor = Arc::new(IdentityAnchor::new(Some("sign-verify".to_string())));
    let shared_receipts = Arc::new(Mutex::new(Vec::new()));
    let verify_count = Arc::new(Mutex::new(0u64));

    let mut handles = Vec::new();

    // 25 signer threads
    for thread_id in 0..25 {
        let anchor = Arc::clone(&anchor);
        let shared = Arc::clone(&shared_receipts);
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let receipt = ReceiptBuilder::new(
                    anchor.id(),
                    ActionType::Custom("sign_verify_test".into()),
                    ActionContent::new(format!("Thread {thread_id} op {i}")),
                )
                .sign(anchor.signing_key())
                .expect("signing should succeed");
                shared.lock().unwrap().push(receipt);
            }
        });
        handles.push(handle);
    }

    // 25 verifier threads
    for _ in 0..25 {
        let shared = Arc::clone(&shared_receipts);
        let count = Arc::clone(&verify_count);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let receipts = shared.lock().unwrap();
                if let Some(receipt) = receipts.last() {
                    let result = verify_receipt(receipt).expect("verification should succeed");
                    if result.is_valid {
                        let mut c = count.lock().unwrap();
                        *c += 1;
                    }
                }
                drop(receipts);
                std::thread::yield_now();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let total_receipts = shared_receipts.lock().unwrap().len();
    let verified = *verify_count.lock().unwrap();
    assert_eq!(total_receipts, 2_500);
    assert!(verified > 0, "Should have verified at least some receipts");
}
