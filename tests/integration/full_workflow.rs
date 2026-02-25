//! Integration test: full end-to-end workflow.
//!
//! Tests the complete lifecycle:
//! 1. Create identities
//! 2. Sign actions (create receipts)
//! 3. Chain receipts together
//! 4. Grant trust between identities
//! 5. Verify trust grants
//! 6. Revoke trust and verify revocation

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::chain::verify_chain;
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::chain::verify_trust_chain;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::revocation::{Revocation, RevocationReason};
use agentic_identity::trust::verify::verify_trust_grant;

#[test]
fn full_workflow_identity_to_revocation() {
    // ── Step 1: Create identities ───────────────────────────────────────
    let alice = IdentityAnchor::new(Some("alice".to_string()));
    let bob = IdentityAnchor::new(Some("bob".to_string()));
    let charlie = IdentityAnchor::new(Some("charlie".to_string()));

    // Verify IDs are unique and properly formatted
    assert_ne!(alice.id(), bob.id());
    assert_ne!(bob.id(), charlie.id());
    assert!(alice.id().0.starts_with("aid_"));
    assert!(bob.id().0.starts_with("aid_"));
    assert!(charlie.id().0.starts_with("aid_"));

    // Verify identity documents are self-signed
    let alice_doc = alice.to_document();
    assert!(
        alice_doc.verify_signature().is_ok(),
        "Alice's identity document should be self-signed"
    );

    // ── Step 2: Sign actions (create receipts) ──────────────────────────
    let receipt_1 = ReceiptBuilder::new(
        alice.id(),
        ActionType::Observation,
        ActionContent::new("Observed deployment request from Bob"),
    )
    .sign(alice.signing_key())
    .expect("Alice should be able to sign a receipt");

    assert!(receipt_1.id.0.starts_with("arec_"));
    assert_eq!(receipt_1.actor, alice.id());

    // Verify the receipt
    let v1 = verify_receipt(&receipt_1).expect("Verification should not error");
    assert!(v1.is_valid, "Alice's receipt should be valid");
    assert!(v1.signature_valid, "Alice's signature should be valid");

    // ── Step 3: Chain receipts together ──────────────────────────────────
    let receipt_2 = ReceiptBuilder::new(
        alice.id(),
        ActionType::Decision,
        ActionContent::new("Approved Bob's deployment request"),
    )
    .chain_to(receipt_1.id.clone())
    .sign(alice.signing_key())
    .expect("Chain receipt should succeed");

    assert_eq!(
        receipt_2.previous_receipt.as_ref().unwrap(),
        &receipt_1.id,
        "Receipt 2 should chain to receipt 1"
    );

    let receipt_3 = ReceiptBuilder::new(
        alice.id(),
        ActionType::Mutation,
        ActionContent::new("Executed deployment to staging"),
    )
    .chain_to(receipt_2.id.clone())
    .sign(alice.signing_key())
    .expect("Chain receipt should succeed");

    // Verify the full receipt chain
    let chain_result = verify_chain(&[receipt_1.clone(), receipt_2.clone(), receipt_3.clone()]);
    assert!(
        chain_result.is_ok(),
        "Receipt chain should verify successfully"
    );

    // ── Step 4: Grant trust between identities ──────────────────────────
    // Alice grants Bob read access to calendar
    let alice_to_bob = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("read:calendar"))
        .capability(Capability::new("read:email"))
        .sign(alice.signing_key())
        .expect("Trust grant should succeed");

    assert!(alice_to_bob.id.0.starts_with("atrust_"));
    assert_eq!(alice_to_bob.grantor, alice.id());
    assert_eq!(alice_to_bob.grantee, bob.id());

    // Alice grants Bob delegation rights for deploy
    let alice_to_bob_deploy = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("execute:deploy:*"))
        .allow_delegation(2)
        .sign(alice.signing_key())
        .expect("Delegation grant should succeed");

    assert!(alice_to_bob_deploy.delegation_allowed);

    // ── Step 5: Verify trust grants ─────────────────────────────────────
    // Verify Alice -> Bob for read:calendar
    let tv = verify_trust_grant(&alice_to_bob, "read:calendar", 0, &[])
        .expect("Trust verification should not error");
    assert!(
        tv.is_valid,
        "Alice's grant to Bob for read:calendar should be valid"
    );
    assert!(tv.signature_valid);
    assert!(tv.capability_granted);

    // Verify Alice -> Bob for read:email
    let tv = verify_trust_grant(&alice_to_bob, "read:email", 0, &[])
        .expect("Trust verification should not error");
    assert!(
        tv.is_valid,
        "Alice's grant to Bob for read:email should be valid"
    );

    // Verify Alice -> Bob does NOT cover write:calendar
    let tv = verify_trust_grant(&alice_to_bob, "write:calendar", 0, &[])
        .expect("Trust verification should not error");
    assert!(
        !tv.is_valid,
        "Alice's grant to Bob should NOT cover write:calendar"
    );

    // Bob delegates deploy:staging to Charlie
    let bob_to_charlie =
        TrustGrantBuilder::new(bob.id(), charlie.id(), charlie.public_key_base64())
            .capability(Capability::new("execute:deploy:staging"))
            .delegated_from(alice_to_bob_deploy.id.clone(), 1)
            .sign(bob.signing_key())
            .expect("Delegation should succeed");

    // Verify the trust chain: Alice -> Bob -> Charlie for deploy:staging
    let chain_v = verify_trust_chain(
        &[alice_to_bob_deploy.clone(), bob_to_charlie.clone()],
        "execute:deploy:staging",
        &[],
    )
    .expect("Trust chain verification should succeed");
    assert!(
        chain_v.is_valid,
        "Trust chain Alice->Bob->Charlie for deploy:staging should be valid"
    );
    assert_eq!(chain_v.trust_chain.len(), 2);

    // ── Step 6: Revoke trust and verify revocation ──────────────────────
    // Alice revokes the calendar/email trust grant to Bob
    let revocation = Revocation::create(
        alice_to_bob.id.clone(),
        alice.id(),
        RevocationReason::ManualRevocation,
        alice.signing_key(),
    );

    assert_eq!(revocation.trust_id, alice_to_bob.id);
    assert!(
        revocation.verify_signature().is_ok(),
        "Revocation signature should be valid"
    );

    // Verify the grant is now invalid
    let tv = verify_trust_grant(
        &alice_to_bob,
        "read:calendar",
        0,
        std::slice::from_ref(&revocation),
    )
    .expect("Trust verification should not error");
    assert!(!tv.is_valid, "Revoked grant should not be valid");
    assert!(!tv.not_revoked, "Grant should be marked as revoked");

    // The deploy delegation chain should still work (different grant)
    let chain_v = verify_trust_chain(
        &[alice_to_bob_deploy.clone(), bob_to_charlie.clone()],
        "execute:deploy:staging",
        &[revocation],
    )
    .expect("Trust chain verification should succeed");
    assert!(
        chain_v.is_valid,
        "Unrelated trust chain should still be valid after revoking a different grant"
    );
}

#[test]
fn workflow_receipt_with_structured_data() {
    let agent = IdentityAnchor::new(Some("data-agent".to_string()));

    let receipt = ReceiptBuilder::new(
        agent.id(),
        ActionType::Mutation,
        ActionContent::with_data(
            "Updated configuration",
            serde_json::json!({
                "key": "max_retries",
                "old_value": 3,
                "new_value": 5,
            }),
        ),
    )
    .context_hash("sha256:abc123def456".to_string())
    .sign(agent.signing_key())
    .expect("Receipt with structured data should succeed");

    assert!(receipt.action.data.is_some());
    assert_eq!(receipt.context_hash.as_deref(), Some("sha256:abc123def456"));

    let v = verify_receipt(&receipt).expect("Verification should succeed");
    assert!(v.is_valid);
}

#[test]
fn workflow_identity_key_rotation() {
    let original = IdentityAnchor::new(Some("rotate-test".to_string()));
    let _original_id = original.id();
    let original_pub = original.verifying_key_bytes();

    // Sign a receipt with the original key
    let receipt_before = ReceiptBuilder::new(
        original.id(),
        ActionType::Decision,
        ActionContent::new("Before rotation"),
    )
    .sign(original.signing_key())
    .expect("Signing should succeed");

    // Rotate the key
    let rotated = original
        .rotate(agentic_identity::identity::RotationReason::Scheduled)
        .expect("Rotation should succeed");

    // Rotated identity has a different public key
    assert_ne!(original_pub, rotated.verifying_key_bytes());

    // Rotation history is recorded
    assert_eq!(rotated.rotation_history.len(), 1);

    // The receipt signed with the old key is still verifiable
    let v = verify_receipt(&receipt_before).expect("Verification should succeed");
    assert!(
        v.is_valid,
        "Receipt signed with old key should still verify"
    );

    // Sign a new receipt with the rotated key
    let receipt_after = ReceiptBuilder::new(
        rotated.id(),
        ActionType::Decision,
        ActionContent::new("After rotation"),
    )
    .sign(rotated.signing_key())
    .expect("Signing with rotated key should succeed");

    let v = verify_receipt(&receipt_after).expect("Verification should succeed");
    assert!(v.is_valid, "Receipt signed with rotated key should verify");
}
