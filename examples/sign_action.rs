//! Sign Action — create signed action receipts, chain them, and verify.
//!
//! Run with:
//!   cargo run --example sign_action -p agentic-identity

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::receipt::chain::verify_chain;

fn main() {
    let agent = IdentityAnchor::new(Some("deploy-agent".to_string()));
    println!("Agent: {} ({})", agent.name.as_deref().unwrap(), agent.id());
    println!();

    // ── 1. Sign a simple action receipt ─────────────────────────────────────
    //
    // A receipt is cryptographic proof that this agent took a specific action.
    // The receipt includes the actor identity, action type, description,
    // timestamp, and a signature over the entire payload.
    let receipt = ReceiptBuilder::new(
        agent.id(),
        ActionType::Decision,
        ActionContent::new("Approved deployment of api-service v2.4.1 to production"),
    )
    .sign(agent.signing_key())
    .expect("signing should succeed");

    println!("Receipt created:");
    println!("  ID:          {}", receipt.id);
    println!("  Actor:       {}", receipt.actor);
    println!("  Type:        {:?}", receipt.action_type);
    println!("  Description: {}", receipt.action.description);
    println!("  Hash:        {}...", &receipt.receipt_hash[..32]);
    println!("  Signature:   {}...", &receipt.signature[..32]);
    println!();

    // ── 2. Verify the receipt ───────────────────────────────────────────────
    //
    // Anyone with access to the receipt can verify the signature using the
    // public key embedded in the receipt. No access to the private key needed.
    let verification = verify_receipt(&receipt).expect("verification should not error");
    println!("Verification result:");
    println!("  Signature valid: {}", verification.signature_valid);
    println!("  Overall valid:   {}", verification.is_valid);
    assert!(verification.is_valid);
    println!();

    // ── 3. Sign a receipt with structured data ──────────────────────────────
    //
    // Receipts can carry structured data (JSON) alongside the description.
    let receipt_with_data = ReceiptBuilder::new(
        agent.id(),
        ActionType::Mutation,
        ActionContent::with_data(
            "Updated max_retries configuration",
            serde_json::json!({
                "key": "max_retries",
                "old_value": 3,
                "new_value": 5,
                "service": "api-service"
            }),
        ),
    )
    .context_hash("sha256:a1b2c3d4e5f6".to_string())
    .sign(agent.signing_key())
    .expect("signing with data");

    println!("Receipt with structured data:");
    println!("  ID:           {}", receipt_with_data.id);
    println!("  Context hash: {:?}", receipt_with_data.context_hash);
    println!("  Data:         {:?}", receipt_with_data.action.data);
    let v = verify_receipt(&receipt_with_data).unwrap();
    assert!(v.is_valid);
    println!("  Verified:     OK");
    println!();

    // ── 4. Chain receipts for an audit trail ────────────────────────────────
    //
    // Receipts can be chained: each receipt references the previous one by ID.
    // This creates a tamper-evident, ordered audit trail.
    println!("Building receipt chain (observation -> decision -> mutation)...");

    let r1 = ReceiptBuilder::new(
        agent.id(),
        ActionType::Observation,
        ActionContent::new("Detected error rate spike: 5xx errors at 12% (threshold: 5%)"),
    )
    .sign(agent.signing_key())
    .expect("chain receipt 1");
    println!("  [1] {} - Observation: {}", r1.id, r1.action.description);

    let r2 = ReceiptBuilder::new(
        agent.id(),
        ActionType::Decision,
        ActionContent::new("Decided to rollback api-service to v2.3.0"),
    )
    .chain_to(r1.id.clone())
    .sign(agent.signing_key())
    .expect("chain receipt 2");
    println!("  [2] {} - Decision: {}", r2.id, r2.action.description);
    println!("      chains to: {}", r2.previous_receipt.as_ref().unwrap());

    let r3 = ReceiptBuilder::new(
        agent.id(),
        ActionType::Mutation,
        ActionContent::with_data(
            "Executed rollback to v2.3.0",
            serde_json::json!({
                "action": "rollback",
                "from": "v2.4.1",
                "to": "v2.3.0",
                "service": "api-service"
            }),
        ),
    )
    .chain_to(r2.id.clone())
    .sign(agent.signing_key())
    .expect("chain receipt 3");
    println!("  [3] {} - Mutation: {}", r3.id, r3.action.description);
    println!("      chains to: {}", r3.previous_receipt.as_ref().unwrap());
    println!();

    // ── 5. Verify the entire chain ──────────────────────────────────────────
    //
    // Chain verification checks every signature AND the chain linkage.
    // If any receipt is tampered with or a link is broken, verification fails.
    let chain = vec![r1, r2, r3];
    let chain_valid = verify_chain(&chain).expect("chain verification should succeed");
    println!("Chain verification: valid={chain_valid}");
    assert!(chain_valid);
    println!();

    // ── 6. Different action types ───────────────────────────────────────────
    //
    // AgenticIdentity supports several built-in action types plus custom ones.
    let action_types = vec![
        ("Decision",          ActionType::Decision),
        ("Observation",       ActionType::Observation),
        ("Mutation",          ActionType::Mutation),
        ("Delegation",        ActionType::Delegation),
        ("Revocation",        ActionType::Revocation),
        ("IdentityOperation", ActionType::IdentityOperation),
        ("Custom(audit)",     ActionType::Custom("audit".into())),
    ];

    println!("All action types:");
    for (label, action_type) in action_types {
        let r = ReceiptBuilder::new(
            agent.id(),
            action_type,
            ActionContent::new(format!("Example {label} action")),
        )
        .sign(agent.signing_key())
        .unwrap();
        let v = verify_receipt(&r).unwrap();
        println!("  {label:<20} -> {} (valid={})", r.id, v.is_valid);
    }
    println!();

    println!("All operations completed successfully.");
}
