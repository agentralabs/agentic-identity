use agentic_identity::crypto::derivation::derive_key;
use agentic_identity::crypto::keys::Ed25519KeyPair;
use agentic_identity::crypto::signing::{sign, verify};
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::verify::verify_trust_grant;
use criterion::{criterion_group, criterion_main, Criterion};

fn crypto_benchmarks(c: &mut Criterion) {
    // 1. Key generation
    c.bench_function("ed25519_key_generation", |b| {
        b.iter(|| {
            Ed25519KeyPair::generate();
        });
    });

    // 2. Signing
    let key_pair = Ed25519KeyPair::generate();
    let message = b"The quick brown fox jumps over the lazy dog";
    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            sign(key_pair.signing_key(), message);
        });
    });

    // 3. Verification
    let signature = sign(key_pair.signing_key(), message);
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            verify(key_pair.verifying_key(), message, &signature).unwrap();
        });
    });

    // 4. Key derivation (HKDF)
    let ikm = [0u8; 32];
    c.bench_function("hkdf_derive_key", |b| {
        b.iter(|| {
            derive_key(&ikm, "agentic-identity/session/bench-001").unwrap();
        });
    });

    // 5. Identity anchor creation
    c.bench_function("identity_anchor_create", |b| {
        b.iter(|| {
            IdentityAnchor::new(None);
        });
    });

    // 6. Action receipt creation + signing
    let anchor = IdentityAnchor::new(None);
    c.bench_function("receipt_sign", |b| {
        b.iter(|| {
            ReceiptBuilder::new(
                anchor.id(),
                ActionType::Decision,
                ActionContent::new("Chose PostgreSQL for JSON support"),
            )
            .sign(anchor.signing_key())
        });
    });

    // 7. Receipt verification
    let receipt = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Decision,
        ActionContent::new("Test action for benchmarking"),
    )
    .sign(anchor.signing_key())
    .unwrap();
    c.bench_function("receipt_verify", |b| {
        b.iter(|| agentic_identity::receipt::verify::verify_receipt(&receipt));
    });

    // 8. Trust grant creation + signing
    let grantor = IdentityAnchor::new(None);
    let grantee = IdentityAnchor::new(None);
    c.bench_function("trust_grant_sign", |b| {
        b.iter(|| {
            TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
                .capability(Capability {
                    uri: "read:*".to_string(),
                    description: Some("Read access".to_string()),
                    constraints: None,
                })
                .sign(grantor.signing_key())
        });
    });

    // 9. Trust grant verification
    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
        .capability(Capability {
            uri: "read:*".to_string(),
            description: Some("Read access".to_string()),
            constraints: None,
        })
        .sign(grantor.signing_key())
        .unwrap();
    c.bench_function("trust_grant_verify", |b| {
        b.iter(|| verify_trust_grant(&grant, "read:documents", 0, &[]));
    });

    // 10. Trust chain verification (depth 2)
    let root = IdentityAnchor::new(None);
    let mid = IdentityAnchor::new(None);
    let leaf = IdentityAnchor::new(None);
    let grant1 = TrustGrantBuilder::new(root.id(), mid.id(), mid.public_key_base64())
        .capability(Capability {
            uri: "*".to_string(),
            description: None,
            constraints: None,
        })
        .allow_delegation(5)
        .sign(root.signing_key())
        .unwrap();
    let grant2 = TrustGrantBuilder::new(mid.id(), leaf.id(), leaf.public_key_base64())
        .capability(Capability {
            uri: "*".to_string(),
            description: None,
            constraints: None,
        })
        .delegated_from(grant1.id.clone(), 1)
        .allow_delegation(4)
        .sign(mid.signing_key())
        .unwrap();
    let chain = vec![grant1.clone(), grant2.clone()];
    c.bench_function("trust_chain_verify_depth_2", |b| {
        b.iter(|| agentic_identity::trust::chain::verify_trust_chain(&chain, "read:docs", &[]));
    });

    // 11. Receipt chain creation (10 receipts)
    c.bench_function("receipt_chain_10", |b| {
        b.iter(|| {
            let a = IdentityAnchor::new(None);
            let mut prev: Option<agentic_identity::receipt::ReceiptId> = None;
            for i in 0..10 {
                let mut builder = ReceiptBuilder::new(
                    a.id(),
                    ActionType::Observation,
                    ActionContent::new(format!("Action {i}")),
                );
                if let Some(p) = prev {
                    builder = builder.chain_to(p);
                }
                let r = builder.sign(a.signing_key()).unwrap();
                prev = Some(r.id.clone());
            }
        });
    });
}

criterion_group!(benches, crypto_benchmarks);
criterion_main!(benches);
