//! Trust Delegation — grant trust, delegate, verify chains, and revoke.
//!
//! Run with:
//!   cargo run --example trust_delegation -p agentic-identity

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::chain::{validate_delegation, verify_trust_chain};
use agentic_identity::trust::constraint::TrustConstraints;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::revocation::{Revocation, RevocationReason};
use agentic_identity::trust::verify::verify_trust_grant;

fn main() {
    // ── Setup: three identities ─────────────────────────────────────────────
    let alice = IdentityAnchor::new(Some("alice-orchestrator".to_string()));
    let bob = IdentityAnchor::new(Some("bob-worker".to_string()));
    let carol = IdentityAnchor::new(Some("carol-specialist".to_string()));

    println!("Identities:");
    println!("  Alice (orchestrator): {}", alice.id());
    println!("  Bob   (worker):       {}", bob.id());
    println!("  Carol (specialist):   {}", carol.id());
    println!();

    // ── 1. Alice grants trust to Bob ────────────────────────────────────────
    //
    // Alice trusts Bob to read calendars and documents. The grant is signed
    // by Alice's private key and includes Bob's public key for binding.
    let grant_ab = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::with_description(
            "read:calendar",
            "Read calendar events",
        ))
        .capability(Capability::with_description(
            "read:documents",
            "Read shared documents",
        ))
        .sign(alice.signing_key())
        .expect("trust grant signing should succeed");

    println!("Trust grant: Alice -> Bob");
    println!("  Grant ID:      {}", grant_ab.id);
    println!(
        "  Capabilities:  {:?}",
        grant_ab
            .capabilities
            .iter()
            .map(|c| &c.uri)
            .collect::<Vec<_>>()
    );
    println!("  Delegation:    allowed={}", grant_ab.delegation_allowed);
    println!("  Signature:     {}...", &grant_ab.grantor_signature[..32]);
    println!();

    // ── 2. Verify the grant ─────────────────────────────────────────────────
    //
    // Verification checks: signature, time window, revocation status,
    // use count, and whether the requested capability is covered.
    let v = verify_trust_grant(&grant_ab, "read:calendar", 0, &[])
        .expect("verification should succeed");
    println!("Verify grant for 'read:calendar':");
    println!("  Signature valid:    {}", v.signature_valid);
    println!("  Time valid:         {}", v.time_valid);
    println!("  Not revoked:        {}", v.not_revoked);
    println!("  Uses valid:         {}", v.uses_valid);
    println!("  Capability granted: {}", v.capability_granted);
    println!("  Overall valid:      {}", v.is_valid);
    assert!(v.is_valid);
    println!();

    // Verify a capability that was NOT granted.
    let v_write = verify_trust_grant(&grant_ab, "write:calendar", 0, &[])
        .expect("verification should succeed");
    println!("Verify grant for 'write:calendar' (not granted):");
    println!("  Capability granted: {}", v_write.capability_granted);
    println!("  Overall valid:      {}", v_write.is_valid);
    assert!(!v_write.is_valid);
    println!();

    // ── 3. Grant with wildcard capabilities ─────────────────────────────────
    //
    // Wildcards allow broad grants. "read:*" covers any "read:..." capability.
    let grant_wildcard = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("read:*"))
        .sign(alice.signing_key())
        .expect("wildcard grant");

    println!("Wildcard grant 'read:*':");
    let checks = [
        "read:calendar",
        "read:email",
        "read:files",
        "write:calendar",
    ];
    for cap in &checks {
        let v = verify_trust_grant(&grant_wildcard, cap, 0, &[]).unwrap();
        println!("  {cap:<20} -> valid={}", v.is_valid);
    }
    println!();

    // ── 4. Grant with constraints ───────────────────────────────────────────
    //
    // Trust grants can have time bounds and use limits.
    let now = agentic_identity::time::now_micros();
    let one_hour = 3_600_000_000u64; // 1 hour in microseconds

    let constrained_grant = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("execute:deploy:staging"))
        .constraints(TrustConstraints::time_bounded(now, now + one_hour).with_max_uses(5))
        .sign(alice.signing_key())
        .expect("constrained grant");

    println!("Constrained grant (1 hour, max 5 uses):");
    // Within limits: valid
    let v = verify_trust_grant(&constrained_grant, "execute:deploy:staging", 0, &[]).unwrap();
    println!("  Use 0 of 5:  valid={}", v.is_valid);
    assert!(v.is_valid);
    // At the limit: invalid
    let v = verify_trust_grant(&constrained_grant, "execute:deploy:staging", 5, &[]).unwrap();
    println!("  Use 5 of 5:  valid={} (max uses exceeded)", v.is_valid);
    assert!(!v.is_valid);
    println!();

    // ── 5. Delegation: Alice -> Bob -> Carol ────────────────────────────────
    //
    // Alice grants Bob trust WITH delegation rights. Bob can then delegate
    // a subset of those capabilities to Carol.
    let grant_delegatable = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("read:*"))
        .allow_delegation(2) // max delegation depth of 2
        .sign(alice.signing_key())
        .expect("delegatable grant");

    println!("Delegatable grant: Alice -> Bob (max depth: 2)");
    println!("  Grant ID:   {}", grant_delegatable.id);
    println!(
        "  Delegation: allowed={}, max_depth={:?}",
        grant_delegatable.delegation_allowed, grant_delegatable.max_delegation_depth
    );
    println!();

    // Validate that Bob CAN delegate to Carol.
    let delegation_caps = vec![Capability::new("read:calendar")];
    validate_delegation(&grant_delegatable, &delegation_caps).expect("delegation should be valid");
    println!("Delegation validation: Bob can delegate 'read:calendar' to Carol");

    // Bob delegates to Carol.
    let grant_bc = TrustGrantBuilder::new(bob.id(), carol.id(), carol.public_key_base64())
        .capability(Capability::new("read:calendar"))
        .delegated_from(grant_delegatable.id.clone(), 1)
        .sign(bob.signing_key())
        .expect("delegated grant");

    println!("Delegated grant: Bob -> Carol");
    println!("  Grant ID:         {}", grant_bc.id);
    println!("  Parent grant:     {:?}", grant_bc.parent_grant);
    println!("  Delegation depth: {}", grant_bc.delegation_depth);
    println!();

    // ── 6. Verify the trust chain ───────────────────────────────────────────
    //
    // Chain verification walks every link: Alice->Bob->Carol.
    // Each link must have a valid signature, time window, and capabilities.
    let chain = vec![grant_delegatable.clone(), grant_bc.clone()];
    let chain_result = verify_trust_chain(&chain, "read:calendar", &[])
        .expect("chain verification should succeed");

    println!("Trust chain verification (Alice -> Bob -> Carol):");
    println!("  Signature valid:    {}", chain_result.signature_valid);
    println!("  Time valid:         {}", chain_result.time_valid);
    println!("  Not revoked:        {}", chain_result.not_revoked);
    println!("  Capability granted: {}", chain_result.capability_granted);
    println!("  Chain length:       {}", chain_result.trust_chain.len());
    println!("  Overall valid:      {}", chain_result.is_valid);
    assert!(chain_result.is_valid);
    println!();

    // Verify a capability NOT in the chain.
    let chain_write =
        verify_trust_chain(&chain, "write:calendar", &[]).expect("verification should succeed");
    println!("Chain verify for 'write:calendar' (not in Carol's grant):");
    println!("  Overall valid: {}", chain_write.is_valid);
    assert!(!chain_write.is_valid);
    println!();

    // ── 7. Grantee acknowledgment ───────────────────────────────────────────
    //
    // The grantee can optionally sign an acknowledgment of the grant.
    let mut ack_grant = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("read:calendar"))
        .sign(alice.signing_key())
        .expect("grant for acknowledgment");

    println!("Grantee acknowledgment:");
    println!("  Before: {:?}", ack_grant.grantee_acknowledgment);
    ack_grant
        .acknowledge(bob.signing_key())
        .expect("acknowledgment");
    println!(
        "  After:  {}...",
        &ack_grant.grantee_acknowledgment.as_ref().unwrap()[..32]
    );
    println!();

    // ── 8. Revocation ───────────────────────────────────────────────────────
    //
    // When trust needs to be withdrawn, a signed revocation record is created.
    // Any grant verified against a revocation list containing its ID will fail.
    let revocable_grant = TrustGrantBuilder::new(alice.id(), bob.id(), bob.public_key_base64())
        .capability(Capability::new("read:calendar"))
        .sign(alice.signing_key())
        .expect("revocable grant");

    // Verify before revocation: valid.
    let v_before = verify_trust_grant(&revocable_grant, "read:calendar", 0, &[]).unwrap();
    println!("Before revocation: valid={}", v_before.is_valid);
    assert!(v_before.is_valid);

    // Create a revocation record.
    let revocation = Revocation::create(
        revocable_grant.id.clone(),
        alice.id(),
        RevocationReason::ManualRevocation,
        alice.signing_key(),
    );
    println!("Revocation created for grant {}", revocable_grant.id);

    // Verify after revocation: invalid.
    let v_after = verify_trust_grant(
        &revocable_grant,
        "read:calendar",
        0,
        std::slice::from_ref(&revocation),
    )
    .unwrap();
    println!("After revocation:  valid={}", v_after.is_valid);
    assert!(!v_after.is_valid);
    println!();

    // ── 9. Revocation invalidates entire chain ──────────────────────────────
    //
    // If any link in a trust chain is revoked, the entire chain becomes invalid.
    let chain_with_revocation = vec![grant_delegatable.clone(), grant_bc.clone()];
    let revoke_root = Revocation::create(
        grant_delegatable.id.clone(),
        alice.id(),
        RevocationReason::ManualRevocation,
        alice.signing_key(),
    );
    let chain_revoked = verify_trust_chain(&chain_with_revocation, "read:calendar", &[revoke_root])
        .expect("chain verification with revocation");
    println!("Chain with revoked root grant:");
    println!("  Not revoked: {}", chain_revoked.not_revoked);
    println!("  Overall:     valid={}", chain_revoked.is_valid);
    assert!(!chain_revoked.is_valid);
    println!();

    println!("All operations completed successfully.");
}
