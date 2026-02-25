//! Basic Identity — create an identity anchor, inspect it, derive scoped keys.
//!
//! Run with:
//!   cargo run --example basic_identity -p agentic-identity

use agentic_identity::identity::{IdentityAnchor, RotationReason};

fn main() {
    // ── 1. Create a new identity anchor ─────────────────────────────────────
    //
    // A fresh Ed25519 key pair is generated. The public key becomes the
    // permanent identity; the private key proves ownership.
    let anchor = IdentityAnchor::new(Some("my-agent".to_string()));

    let id = anchor.id();
    println!("Identity created");
    println!("  ID:         {id}");
    println!(
        "  Name:       {}",
        anchor.name.as_deref().unwrap_or("(none)")
    );
    println!("  Public key: {}", anchor.public_key_base64());
    println!("  Created at: {} us", anchor.created_at);
    println!();

    // ── 2. Generate the public identity document ────────────────────────────
    //
    // The identity document is the shareable, self-signed public half.
    // It contains the public key, name, rotation history, and a signature
    // that anyone can verify without possessing the private key.
    let doc = anchor.to_document();
    println!("Identity document (self-signed):");
    println!("  Algorithm:  {}", doc.algorithm);
    println!("  Signature:  {}...", &doc.signature[..32]);
    doc.verify_signature()
        .expect("document signature should verify");
    println!("  Verified:   OK");
    println!();

    // ── 3. Derive scoped session keys ───────────────────────────────────────
    //
    // Session keys are deterministically derived from the root key via
    // HKDF-SHA256. They isolate key material per session so that
    // compromising one session key does not expose the root.
    let session_key = anchor
        .derive_session_key("session-2025-06-01")
        .expect("session key derivation should succeed");
    println!("Session key derived for 'session-2025-06-01'");
    println!(
        "  Verifying key: {}",
        hex::encode(session_key.verifying_key().to_bytes())
    );

    // Same session ID always produces the same key (deterministic).
    let session_key_again = anchor
        .derive_session_key("session-2025-06-01")
        .expect("deterministic derivation");
    assert_eq!(
        session_key.verifying_key().to_bytes(),
        session_key_again.verifying_key().to_bytes(),
    );
    println!("  Deterministic: confirmed (same input => same key)");
    println!();

    // ── 4. Derive scoped capability keys ────────────────────────────────────
    //
    // Capability keys scope operations to specific permissions.
    // Different capability URIs produce different keys.
    let cap_read = anchor
        .derive_capability_key("read:calendar")
        .expect("capability key derivation");
    let cap_write = anchor
        .derive_capability_key("write:calendar")
        .expect("capability key derivation");
    println!("Capability keys:");
    println!(
        "  read:calendar  -> {}",
        hex::encode(cap_read.verifying_key().to_bytes())
    );
    println!(
        "  write:calendar -> {}",
        hex::encode(cap_write.verifying_key().to_bytes())
    );
    assert_ne!(
        cap_read.verifying_key().to_bytes(),
        cap_write.verifying_key().to_bytes(),
    );
    println!("  Different URIs produce different keys: confirmed");
    println!();

    // ── 5. Derive a device key ──────────────────────────────────────────────
    let device_key = anchor
        .derive_device_key("macbook-pro")
        .expect("device key derivation");
    println!("Device key for 'macbook-pro':");
    println!(
        "  Verifying key: {}",
        hex::encode(device_key.verifying_key().to_bytes())
    );
    println!();

    // ── 6. Key rotation ─────────────────────────────────────────────────────
    //
    // When a key needs to be replaced (scheduled rotation, compromise, etc.),
    // the old key signs an authorization transferring trust to the new key.
    // The rotation history is preserved for auditability.
    let rotated = anchor
        .rotate(RotationReason::Scheduled)
        .expect("rotation should succeed");
    println!("Key rotated (reason: scheduled)");
    println!("  New ID:       {}", rotated.id());
    println!("  New pub key:  {}", rotated.public_key_base64());
    println!(
        "  Rotation history: {} entries",
        rotated.rotation_history.len()
    );
    println!(
        "    [0] reason={:?}, previous_key={}...",
        rotated.rotation_history[0].reason,
        &rotated.rotation_history[0].previous_key[..20]
    );

    // Rotate again to show chain accumulation.
    let rotated2 = rotated
        .rotate(RotationReason::Manual)
        .expect("second rotation");
    println!(
        "  After second rotation: {} history entries",
        rotated2.rotation_history.len()
    );
    println!();

    println!("All operations completed successfully.");
}
