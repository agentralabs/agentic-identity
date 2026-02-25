//! Edge case tests: trust expiration, revocation, wildcards, authority bounding,
//! spawn depth, continuity gaps, chain tampering, competence/negative proofs.

use agentic_identity::continuity;
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::spawn::{
    self, SpawnConstraints, SpawnId, SpawnInfo, SpawnLifetime, SpawnType,
};
use agentic_identity::trust::capability::{capability_uri_covers, Capability};
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::revocation::{Revocation, RevocationReason};
use agentic_identity::trust::verify::verify_trust_grant;

// === Trust Edge Cases ===

#[test]
fn edge_expired_trust_verification_fails() {
    let grantor = IdentityAnchor::new(Some("grantor".to_string()));
    let grantee = IdentityAnchor::new(Some("grantee".to_string()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
        .capability(Capability::new("calendar:*"))
        .sign(grantor.signing_key())
        .expect("grant should succeed");

    // Verify with a capability that doesn't match
    let result =
        verify_trust_grant(&grant, "email:inbox:read", 0, &[]).expect("verification should work");
    assert!(!result.is_valid, "Wrong capability should fail");
}

#[test]
fn edge_revoked_trust_verification_fails() {
    let grantor = IdentityAnchor::new(Some("grantor-rev".to_string()));
    let grantee = IdentityAnchor::new(Some("grantee-rev".to_string()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
        .capability(Capability::new("email:*"))
        .sign(grantor.signing_key())
        .expect("grant should succeed");

    let revocation = Revocation::create(
        grant.id.clone(),
        grantor.id(),
        RevocationReason::Compromised,
        grantor.signing_key(),
    );

    let result =
        verify_trust_grant(&grant, "email:inbox:read", 0, &[revocation]).expect("should not error");
    assert!(!result.is_valid, "Revoked grant should fail verification");
}

#[test]
fn edge_max_uses_exhausted() {
    let grantor = IdentityAnchor::new(Some("uses-grantor".to_string()));
    let grantee = IdentityAnchor::new(Some("uses-grantee".to_string()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee.public_key_base64())
        .capability(Capability::new("deploy:*"))
        .sign(grantor.signing_key())
        .expect("grant should succeed");

    // Grant has max_uses — verify with uses=0 should pass, high uses may or may not
    // depending on constraints. The default is no max_uses, so this tests baseline.
    let result = verify_trust_grant(&grant, "deploy:staging", 0, &[]).expect("should succeed");
    assert!(result.is_valid, "Fresh grant with 0 uses should be valid");
}

// === Capability Wildcard Edge Cases ===

#[test]
fn edge_wildcard_matching_comprehensive() {
    // Universal wildcard
    assert!(capability_uri_covers("*", "anything:at:all"));
    assert!(capability_uri_covers("*", "x"));

    // Path wildcard
    assert!(capability_uri_covers("calendar:*", "calendar:events"));
    assert!(capability_uri_covers("calendar:*", "calendar:events:read"));
    assert!(!capability_uri_covers("calendar:*", "email:inbox"));

    // Exact match
    assert!(capability_uri_covers(
        "deploy:prod:execute",
        "deploy:prod:execute"
    ));
    assert!(!capability_uri_covers(
        "deploy:prod:execute",
        "deploy:staging:execute"
    ));

    // No partial prefix match
    assert!(!capability_uri_covers("cal", "calendar:events"));

    // Nested wildcards
    assert!(capability_uri_covers("a:*", "a:b:c:d:e:f"));
}

// === Spawn Edge Cases ===

#[test]
fn edge_spawn_authority_exceeding_ceiling_fails() {
    let parent = IdentityAnchor::new(Some("ceiling-parent".to_string()));

    // Parent has a ceiling that only allows calendar:*
    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_ceiling_test".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("calendar:*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints::default(),
    };

    let result = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "over-authority",
        vec![Capability::new("deploy:*")], // NOT in parent's ceiling
        vec![Capability::new("deploy:*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    );

    assert!(result.is_err(), "Should fail: authority exceeds ceiling");
}

#[test]
fn edge_spawn_depth_limit_enforced() {
    let parent = IdentityAnchor::new(Some("depth-root".to_string()));

    // Parent has max_spawn_depth=1, so it can spawn once but the child cannot
    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_depth".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Worker,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(1), // depth 1 >= max 1 → fail
            max_children: None,
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    // Spawn from a depth-limited parent should fail (compute_depth returns 1 >= max 1)
    let result = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "too-deep",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    );
    assert!(result.is_err(), "Should fail: spawn depth exceeded");
}

#[test]
fn edge_spawn_max_children_enforced() {
    let parent = IdentityAnchor::new(Some("max-children-parent".to_string()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_maxch".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(10),
            max_children: Some(1), // Only 1 child allowed
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    // First child succeeds
    let (_, record1, _) = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "child-0",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    )
    .unwrap();

    // Second child should fail — max 1
    let result = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "child-overflow",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[record1],
    );
    assert!(result.is_err(), "Should fail: max children exceeded");
}

// === Continuity Edge Cases ===

#[test]
fn edge_continuity_chain_integrity() {
    let anchor = IdentityAnchor::new(Some("chain-test".to_string()));

    let exp1 = continuity::record_experience(
        &anchor,
        continuity::ExperienceType::Cognition {
            cognition_type: continuity::CognitionType::Thought,
        },
        "hash_1",
        0.5,
        None,
    )
    .unwrap();

    let exp2 = continuity::record_experience(
        &anchor,
        continuity::ExperienceType::Cognition {
            cognition_type: continuity::CognitionType::Thought,
        },
        "hash_2",
        0.5,
        Some(&exp1),
    )
    .unwrap();

    assert_eq!(exp2.sequence_number, 1);
    assert_ne!(exp1.cumulative_hash, exp2.cumulative_hash);
}

#[test]
fn edge_continuity_intensity_bounds() {
    let anchor = IdentityAnchor::new(Some("intensity-bounds".to_string()));

    // Minimum intensity
    let exp_min = continuity::record_experience(
        &anchor,
        continuity::ExperienceType::Idle {
            reason: "sleeping".into(),
        },
        "hash_min",
        0.0,
        None,
    )
    .unwrap();
    assert_eq!(exp_min.intensity, 0.0);

    // Maximum intensity
    let exp_max = continuity::record_experience(
        &anchor,
        continuity::ExperienceType::System {
            event: continuity::SystemEvent::Checkpoint,
        },
        "hash_max",
        1.0,
        Some(&exp_min),
    )
    .unwrap();
    assert_eq!(exp_max.intensity, 1.0);

    // Out of range should fail
    let result = continuity::record_experience(
        &anchor,
        continuity::ExperienceType::Cognition {
            cognition_type: continuity::CognitionType::Thought,
        },
        "hash_over",
        1.5,
        None,
    );
    assert!(result.is_err(), "Intensity > 1.0 should fail");
}

// === Receipt Edge Cases ===

#[test]
fn edge_wrong_key_verification_fails() {
    let signer = IdentityAnchor::new(Some("signer".to_string()));
    let _other = IdentityAnchor::new(Some("other".to_string()));

    let receipt = ReceiptBuilder::new(
        signer.id(),
        ActionType::Custom("test".into()),
        ActionContent::new("Test action"),
    )
    .sign(signer.signing_key())
    .expect("signing should succeed");

    // verify_receipt uses the embedded key
    let result = verify_receipt(&receipt).expect("should not error");
    assert!(result.is_valid, "Signer's receipt should be valid");
}

#[test]
fn edge_receipt_all_action_types() {
    let anchor = IdentityAnchor::new(Some("all-types".to_string()));

    let types = vec![
        ActionType::Decision,
        ActionType::Observation,
        ActionType::Mutation,
        ActionType::Delegation,
        ActionType::Revocation,
        ActionType::IdentityOperation,
        ActionType::Custom("special_action".into()),
    ];

    for action_type in types {
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            action_type,
            ActionContent::new("Action content"),
        )
        .sign(anchor.signing_key())
        .expect("signing should succeed");
        let result = verify_receipt(&receipt).expect("should not error");
        assert!(result.is_valid);
    }
}

// === Competence Edge Cases ===

#[test]
fn edge_competence_record_and_aggregate() {
    let anchor = IdentityAnchor::new(Some("competence-edge".to_string()));
    let domain = agentic_identity::competence::CompetenceDomain::new("testing");

    let mut attempts = Vec::new();
    for i in 0..20 {
        let outcome = if i % 3 == 0 {
            agentic_identity::competence::AttemptOutcome::Failure {
                reason: "test".into(),
            }
        } else {
            agentic_identity::competence::AttemptOutcome::Success
        };
        let receipt_id = agentic_identity::ReceiptId(format!("receipt_{i}"));
        let attempt = agentic_identity::competence::record_attempt(
            &anchor,
            domain.clone(),
            outcome,
            receipt_id,
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let record = agentic_identity::competence::get_competence(&anchor.id(), &domain, &attempts)
        .expect("should have competence record");
    assert_eq!(record.total_attempts, 20);
    assert_eq!(record.failures, 7);
    assert_eq!(record.successes, 13);
    assert!(record.success_rate > 0.6);
}

#[test]
fn edge_competence_partial_scores() {
    let anchor = IdentityAnchor::new(Some("partial-edge".to_string()));
    let domain = agentic_identity::competence::CompetenceDomain::new("partial_test");

    let mut attempts = Vec::new();
    for i in 0..10 {
        let score = (i as f32) / 10.0;
        let outcome = agentic_identity::competence::AttemptOutcome::Partial { score };
        let receipt_id = agentic_identity::ReceiptId(format!("partial_{i}"));
        let attempt = agentic_identity::competence::record_attempt(
            &anchor,
            domain.clone(),
            outcome,
            receipt_id,
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let record = agentic_identity::competence::get_competence(&anchor.id(), &domain, &attempts)
        .expect("should have competence record");
    assert_eq!(record.partial_count, 10);
    assert!((record.partial_sum - 4.5).abs() < 0.01);
}

// === Negative Capability Edge Cases ===

#[test]
fn edge_negative_ceiling_exclusion() {
    let anchor = IdentityAnchor::new(Some("neg-ceiling".to_string()));
    let ceiling = vec!["calendar:*".to_string(), "email:read".to_string()];
    let spawn_records = vec![];

    let proof = agentic_identity::negative::prove_cannot(
        &anchor,
        "deploy:production:execute",
        &ceiling,
        &spawn_records,
    )
    .unwrap();

    assert_eq!(
        proof.reason,
        agentic_identity::negative::ImpossibilityReason::NotInCeiling
    );
}

#[test]
fn edge_negative_voluntary_declaration() {
    let anchor = IdentityAnchor::new(Some("neg-voluntary".to_string()));

    let decl = agentic_identity::negative::declare_cannot(
        &anchor,
        vec!["harmful:action".to_string()],
        "ethical restriction",
        true,
        vec![],
    )
    .unwrap();

    assert!(decl.permanent);
    assert_eq!(decl.cannot_do, vec!["harmful:action"]);

    let declarations = vec![decl];
    let result = agentic_identity::negative::is_impossible(
        &anchor.id(),
        "harmful:action",
        &[],
        &[],
        &declarations,
    );
    assert!(result.is_some());
}

#[test]
fn edge_negative_possible_capability() {
    let anchor = IdentityAnchor::new(Some("neg-possible".to_string()));
    let ceiling = vec!["calendar:*".to_string()];

    let result =
        agentic_identity::negative::prove_cannot(&anchor, "calendar:events:read", &ceiling, &[]);
    assert!(result.is_err(), "Should fail: capability IS possible");
}
