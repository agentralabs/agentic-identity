//! Edge case tests for agentic-identity invention tools.
//!
//! Covers trust dynamics (decay, reinforcement, delegation chains),
//! accountability (receipt archaeology, fingerprinting, consent),
//! federation (transitive trust, revocation cascades, capability negotiation),
//! and resilience (forking, resurrection, temporal identity) scenarios
//! through the core library APIs that underpin the MCP invention tools.

use agentic_identity::competence::{
    self, AttemptOutcome, CompetenceDomain, CompetenceRequirement,
};
use agentic_identity::continuity::{
    self, AnchorType, CognitionType, CommunicationDirection, ExperienceType,
    HeartbeatStatus, HealthMetrics, LearningType, MemoryOpType, PerceptionSource, PlanningType,
    SystemEvent,
};
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::negative::{self, ImpossibilityReason};
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::spawn::{
    self, SpawnConstraints, SpawnId, SpawnInfo, SpawnLifetime, SpawnRecord, SpawnType,
};
use agentic_identity::trust::capability::{capability_uri_covers, Capability};
use agentic_identity::trust::chain::{validate_delegation, verify_trust_chain};
use agentic_identity::trust::constraint::TrustConstraints;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::revocation::{Revocation, RevocationReason};
use agentic_identity::trust::verify::{is_grant_valid, verify_trust_grant};
use agentic_identity::ReceiptId;

// ═══════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════

fn make_key_b64(anchor: &IdentityAnchor) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        anchor.verifying_key_bytes(),
    )
}

fn make_receipt_id(_anchor: &IdentityAnchor, idx: usize) -> ReceiptId {
    ReceiptId(format!("arec_edge_inv_{}", idx))
}

fn make_spawn_record(
    parent: &IdentityAnchor,
    child: &IdentityAnchor,
    granted: Vec<&str>,
    ceiling: Vec<&str>,
) -> SpawnRecord {
    let now = agentic_identity::time::now_micros();
    SpawnRecord {
        id: SpawnId(format!("aspawn_edge_{}", &child.id().0[4..12])),
        parent_id: parent.id(),
        parent_key: parent.public_key_base64(),
        child_id: child.id(),
        child_key: child.public_key_base64(),
        spawn_timestamp: now,
        spawn_type: SpawnType::Worker,
        spawn_purpose: "edge-test".to_string(),
        spawn_receipt_id: ReceiptId("arec_test".to_string()),
        authority_granted: granted.iter().map(|u| Capability::new(*u)).collect(),
        authority_ceiling: ceiling.iter().map(|u| Capability::new(*u)).collect(),
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
        parent_signature: "test_sig".to_string(),
        child_acknowledgment: None,
        terminated: false,
        terminated_at: None,
        termination_reason: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 1: Trust Dynamics — Decay & Reinforcement Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_trust_grant_with_time_bounded_constraints_expires() {
    let grantor = IdentityAnchor::new(Some("inv1-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv1-grantee".into()));
    let now = agentic_identity::time::now_micros();

    // Grant that expired 1 second ago
    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("deploy:*"))
        .constraints(TrustConstraints::time_bounded(now - 2_000_000, now - 1_000_000))
        .sign(grantor.signing_key())
        .unwrap();

    let result = verify_trust_grant(&grant, "deploy:staging", 0, &[]).unwrap();
    assert!(!result.time_valid, "Expired grant should fail time check");
    assert!(!result.is_valid, "Expired grant should be invalid overall");
}

#[test]
fn inv_trust_grant_not_yet_valid_future_window() {
    let grantor = IdentityAnchor::new(Some("inv1-future-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv1-future-grantee".into()));
    let now = agentic_identity::time::now_micros();

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("monitor:*"))
        .constraints(TrustConstraints::time_bounded(now + 60_000_000, now + 120_000_000))
        .sign(grantor.signing_key())
        .unwrap();

    let result = verify_trust_grant(&grant, "monitor:logs", 0, &[]).unwrap();
    assert!(!result.time_valid, "Not-yet-valid grant should fail time check");
    assert!(!result.is_valid);
}

#[test]
fn inv_trust_reinforce_by_acknowledging_grant() {
    let grantor = IdentityAnchor::new(Some("inv1-reinforce-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv1-reinforce-grantee".into()));

    let mut grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("calendar:*"))
        .sign(grantor.signing_key())
        .unwrap();

    assert!(grant.grantee_acknowledgment.is_none());
    grant.acknowledge(grantee.signing_key()).unwrap();
    assert!(grant.grantee_acknowledgment.is_some(), "Grant should be acknowledged");

    // Acknowledged grant is still valid
    let result = verify_trust_grant(&grant, "calendar:events", 0, &[]).unwrap();
    assert!(result.is_valid);
}

#[test]
fn inv_trust_damage_via_revocation_with_reason_compromised() {
    let grantor = IdentityAnchor::new(Some("inv1-damage-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv1-damage-grantee".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("admin:*"))
        .sign(grantor.signing_key())
        .unwrap();

    let revocation = Revocation::create(
        grant.id.clone(),
        grantor.id(),
        RevocationReason::Compromised,
        grantor.signing_key(),
    );

    let result = verify_trust_grant(&grant, "admin:users", 0, &[revocation]).unwrap();
    assert!(!result.not_revoked);
    assert!(!result.is_valid);
}

#[test]
fn inv_trust_max_uses_boundary_exact_limit() {
    let grantor = IdentityAnchor::new(Some("inv1-uses-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv1-uses-grantee".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("api:call"))
        .constraints(TrustConstraints::open().with_max_uses(5))
        .sign(grantor.signing_key())
        .unwrap();

    // Uses 0 through 4 should be valid
    for uses in 0..5 {
        assert!(
            verify_trust_grant(&grant, "api:call", uses, &[]).unwrap().is_valid,
            "Use {} should be valid", uses
        );
    }
    // Use 5 should fail
    assert!(
        !verify_trust_grant(&grant, "api:call", 5, &[]).unwrap().is_valid,
        "Use 5 should exceed max"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 2: Competence Modeling Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_competence_zero_attempts_returns_none() {
    let anchor = IdentityAnchor::new(Some("inv2-zero".into()));
    let domain = CompetenceDomain::new("deploy");

    let record = competence::get_competence(&anchor.id(), &domain, &[]);
    assert!(record.is_none(), "No attempts should return None");
}

#[test]
fn inv_competence_all_failures_zero_rate() {
    let anchor = IdentityAnchor::new(Some("inv2-allfail".into()));
    let domain = CompetenceDomain::new("review");

    let mut attempts = Vec::new();
    for i in 0..5 {
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            AttemptOutcome::Failure { reason: format!("error-{}", i) },
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let record = competence::get_competence(&anchor.id(), &domain, &attempts).unwrap();
    assert_eq!(record.total_attempts, 5);
    assert_eq!(record.successes, 0);
    assert_eq!(record.failures, 5);
    assert!(record.success_rate < 0.001, "All-failure rate should be ~0");
}

#[test]
fn inv_competence_partial_score_out_of_range_rejected() {
    let anchor = IdentityAnchor::new(Some("inv2-badpartial".into()));
    let domain = CompetenceDomain::new("analysis");

    // Score > 1.0
    let result = competence::record_attempt(
        &anchor,
        domain.clone(),
        AttemptOutcome::Partial { score: 1.5 },
        make_receipt_id(&anchor, 0),
        None,
        None,
    );
    assert!(result.is_err(), "Partial score > 1.0 should be rejected");

    // Score < 0.0
    let result = competence::record_attempt(
        &anchor,
        domain,
        AttemptOutcome::Partial { score: -0.1 },
        make_receipt_id(&anchor, 1),
        None,
        None,
    );
    assert!(result.is_err(), "Partial score < 0.0 should be rejected");
}

#[test]
fn inv_competence_partial_score_boundary_values() {
    let anchor = IdentityAnchor::new(Some("inv2-boundary".into()));
    let domain = CompetenceDomain::new("testing");

    // Score exactly 0.0
    let r0 = competence::record_attempt(
        &anchor,
        domain.clone(),
        AttemptOutcome::Partial { score: 0.0 },
        make_receipt_id(&anchor, 0),
        None,
        None,
    );
    assert!(r0.is_ok(), "Score 0.0 should be accepted");

    // Score exactly 1.0
    let r1 = competence::record_attempt(
        &anchor,
        domain,
        AttemptOutcome::Partial { score: 1.0 },
        make_receipt_id(&anchor, 1),
        None,
        None,
    );
    assert!(r1.is_ok(), "Score 1.0 should be accepted");
}

#[test]
fn inv_competence_streak_breaks_on_failure_then_recovers() {
    let anchor = IdentityAnchor::new(Some("inv2-streak".into()));
    let domain = CompetenceDomain::new("ops");

    let mut attempts = Vec::new();
    // SSSSFSS => best streak 4, current 2
    let outcomes = [true, true, true, true, false, true, true];
    for (i, &success) in outcomes.iter().enumerate() {
        let outcome = if success {
            AttemptOutcome::Success
        } else {
            AttemptOutcome::Failure { reason: "test".into() }
        };
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            outcome,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let record = competence::get_competence(&anchor.id(), &domain, &attempts).unwrap();
    assert_eq!(record.streak_best, 4);
    assert_eq!(record.streak_current, 2);
}

#[test]
fn inv_competence_proof_generation_fails_low_success_rate() {
    let anchor = IdentityAnchor::new(Some("inv2-lowrate".into()));
    let domain = CompetenceDomain::new("deploy");

    let mut attempts = Vec::new();
    // 2 success, 8 failure => 20% rate
    for i in 0..10 {
        let outcome = if i < 2 {
            AttemptOutcome::Success
        } else {
            AttemptOutcome::Failure { reason: "test".into() }
        };
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            outcome,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    // Require 90% success rate
    let result = competence::generate_proof(&anchor, domain, 5, 0.9, None, None, &attempts);
    assert!(result.is_err(), "Should fail: success rate too low");
}

#[test]
fn inv_competence_proof_generation_fails_insufficient_attempts() {
    let anchor = IdentityAnchor::new(Some("inv2-few".into()));
    let domain = CompetenceDomain::new("review");

    let mut attempts = Vec::new();
    for i in 0..3 {
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    // Require 10 attempts
    let result = competence::generate_proof(&anchor, domain, 10, 0.5, None, None, &attempts);
    assert!(result.is_err(), "Should fail: insufficient attempts");
}

#[test]
fn inv_competence_proof_verified_with_correct_key() {
    let anchor = IdentityAnchor::new(Some("inv2-verify".into()));
    let domain = CompetenceDomain::new("deploy");

    let mut attempts = Vec::new();
    for i in 0..10 {
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let proof = competence::generate_proof(&anchor, domain, 5, 0.8, None, None, &attempts).unwrap();
    let verification = competence::verify_proof(&proof, anchor.verifying_key()).unwrap();
    assert!(verification.is_valid);
    assert!(verification.meets_attempts);
    assert!(verification.meets_rate);
}

#[test]
fn inv_competence_proof_fails_with_wrong_key() {
    let anchor = IdentityAnchor::new(Some("inv2-wrongkey".into()));
    let other = IdentityAnchor::new(Some("inv2-other".into()));
    let domain = CompetenceDomain::new("deploy");

    let mut attempts = Vec::new();
    for i in 0..10 {
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let proof = competence::generate_proof(&anchor, domain, 5, 0.8, None, None, &attempts).unwrap();

    // Verify with wrong key
    let verification = competence::verify_proof(&proof, other.verifying_key()).unwrap();
    assert!(!verification.is_valid, "Wrong key should fail verification");
}

#[test]
fn inv_competence_validated_attempt_with_cosigner() {
    let anchor = IdentityAnchor::new(Some("inv2-cosign".into()));
    let validator = IdentityAnchor::new(Some("inv2-validator".into()));
    let domain = CompetenceDomain::new("audit");

    let attempt = competence::record_attempt(
        &anchor,
        domain,
        AttemptOutcome::Success,
        make_receipt_id(&anchor, 0),
        Some("validated by supervisor".into()),
        Some(&validator),
    )
    .unwrap();

    assert!(attempt.validator.is_some());
    assert_eq!(attempt.validator.unwrap(), validator.id());
    assert!(attempt.validator_signature.is_some());
}

#[test]
fn inv_competence_check_requirement_with_streak() {
    let anchor = IdentityAnchor::new(Some("inv2-reqstreak".into()));
    let domain = CompetenceDomain::new("deploy");

    let mut attempts = Vec::new();
    // 10 consecutive successes
    for i in 0..10 {
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    // Require streak of 5
    let requirement = CompetenceRequirement {
        domain: domain.clone(),
        min_attempts: 5,
        min_success_rate: 0.8,
        min_streak: Some(5),
        max_age_seconds: None,
    };

    let verification = competence::check_competence(&anchor.id(), &requirement, &attempts);
    assert!(verification.is_valid);
    assert!(verification.meets_streak);
}

#[test]
fn inv_competence_check_requirement_streak_not_met() {
    let anchor = IdentityAnchor::new(Some("inv2-nosteak".into()));
    let domain = CompetenceDomain::new("deploy");

    let mut attempts = Vec::new();
    // SFSFSFSFSFSS => best streak 2
    for i in 0..12 {
        let outcome = if i % 2 == 0 || i >= 10 {
            AttemptOutcome::Success
        } else {
            AttemptOutcome::Failure { reason: "test".into() }
        };
        let attempt = competence::record_attempt(
            &anchor,
            domain.clone(),
            outcome,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let requirement = CompetenceRequirement {
        domain: domain.clone(),
        min_attempts: 5,
        min_success_rate: 0.3,
        min_streak: Some(5),
        max_age_seconds: None,
    };

    let verification = competence::check_competence(&anchor.id(), &requirement, &attempts);
    assert!(!verification.is_valid, "Streak requirement not met");
    assert!(!verification.meets_streak);
}

#[test]
fn inv_competence_multi_domain_isolation() {
    let anchor = IdentityAnchor::new(Some("inv2-multi".into()));
    let domain_a = CompetenceDomain::new("deploy");
    let domain_b = CompetenceDomain::new("review");

    let mut attempts = Vec::new();
    // 5 successes in deploy, 5 failures in review
    for i in 0..5 {
        let attempt_a = competence::record_attempt(
            &anchor,
            domain_a.clone(),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, i),
            None,
            None,
        )
        .unwrap();
        let attempt_b = competence::record_attempt(
            &anchor,
            domain_b.clone(),
            AttemptOutcome::Failure { reason: "test".into() },
            make_receipt_id(&anchor, i + 100),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt_a);
        attempts.push(attempt_b);
    }

    let record_a = competence::get_competence(&anchor.id(), &domain_a, &attempts).unwrap();
    let record_b = competence::get_competence(&anchor.id(), &domain_b, &attempts).unwrap();

    assert_eq!(record_a.successes, 5);
    assert_eq!(record_a.failures, 0);
    assert_eq!(record_b.successes, 0);
    assert_eq!(record_b.failures, 5);
}

#[test]
fn inv_competence_list_all_domains() {
    let anchor = IdentityAnchor::new(Some("inv2-listdom".into()));

    let mut attempts = Vec::new();
    let domains = ["deploy", "review", "analysis", "planning"];
    for (d, domain_name) in domains.iter().enumerate() {
        let attempt = competence::record_attempt(
            &anchor,
            CompetenceDomain::new(*domain_name),
            AttemptOutcome::Success,
            make_receipt_id(&anchor, d),
            None,
            None,
        )
        .unwrap();
        attempts.push(attempt);
    }

    let records = competence::list_competences(&anchor.id(), &attempts);
    assert_eq!(records.len(), 4, "Should find all 4 domains");
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 3: Reputation Network Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_reputation_multi_grantor_trust_web() {
    let grantee = IdentityAnchor::new(Some("inv3-grantee".into()));
    let grantor_a = IdentityAnchor::new(Some("inv3-grantor-a".into()));
    let grantor_b = IdentityAnchor::new(Some("inv3-grantor-b".into()));
    let grantor_c = IdentityAnchor::new(Some("inv3-grantor-c".into()));

    let grant_a = TrustGrantBuilder::new(grantor_a.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("deploy:staging"))
        .sign(grantor_a.signing_key())
        .unwrap();

    let grant_b = TrustGrantBuilder::new(grantor_b.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("deploy:production"))
        .sign(grantor_b.signing_key())
        .unwrap();

    let grant_c = TrustGrantBuilder::new(grantor_c.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("monitor:*"))
        .sign(grantor_c.signing_key())
        .unwrap();

    assert!(verify_trust_grant(&grant_a, "deploy:staging", 0, &[]).unwrap().is_valid);
    assert!(verify_trust_grant(&grant_b, "deploy:production", 0, &[]).unwrap().is_valid);
    assert!(verify_trust_grant(&grant_c, "monitor:logs", 0, &[]).unwrap().is_valid);
    assert!(!verify_trust_grant(&grant_a, "deploy:production", 0, &[]).unwrap().is_valid);
}

#[test]
fn inv_reputation_revocation_isolates_single_grant() {
    let grantor = IdentityAnchor::new(Some("inv3-iso-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv3-iso-grantee".into()));

    let grant1 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("read:*"))
        .sign(grantor.signing_key())
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1));

    let grant2 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("write:*"))
        .sign(grantor.signing_key())
        .unwrap();

    let revocation = Revocation::create(
        grant1.id.clone(),
        grantor.id(),
        RevocationReason::ManualRevocation,
        grantor.signing_key(),
    );

    assert!(!verify_trust_grant(&grant1, "read:logs", 0, &[revocation.clone()]).unwrap().is_valid);
    assert!(verify_trust_grant(&grant2, "write:config", 0, &[revocation]).unwrap().is_valid,
        "Revoking grant1 should not affect grant2");
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 5: Receipt Archaeology Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_receipt_all_action_types_sign_and_verify() {
    let anchor = IdentityAnchor::new(Some("inv5-types".into()));

    let types = vec![
        ActionType::Decision,
        ActionType::Observation,
        ActionType::Mutation,
        ActionType::Delegation,
        ActionType::Revocation,
        ActionType::IdentityOperation,
        ActionType::Custom("audit_trail".into()),
    ];

    for action_type in types {
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            action_type.clone(),
            ActionContent::new("edge case test"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        let result = verify_receipt(&receipt).unwrap();
        assert!(result.is_valid, "Receipt with {:?} should verify", action_type);
    }
}

#[test]
fn inv_receipt_chain_maintains_ordering() {
    let anchor = IdentityAnchor::new(Some("inv5-chain".into()));

    let r1 = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Observation,
        ActionContent::new("Step 1"),
    )
    .sign(anchor.signing_key())
    .unwrap();

    let r2 = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Decision,
        ActionContent::new("Step 2"),
    )
    .chain_to(r1.id.clone())
    .sign(anchor.signing_key())
    .unwrap();

    let r3 = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Mutation,
        ActionContent::new("Step 3"),
    )
    .chain_to(r2.id.clone())
    .sign(anchor.signing_key())
    .unwrap();

    // All should verify independently
    assert!(verify_receipt(&r1).unwrap().is_valid);
    assert!(verify_receipt(&r2).unwrap().is_valid);
    assert!(verify_receipt(&r3).unwrap().is_valid);

    // Chain links should be correct
    assert_eq!(r2.previous_receipt, Some(r1.id.clone()));
    assert_eq!(r3.previous_receipt, Some(r2.id.clone()));
    assert!(r1.previous_receipt.is_none());
}

#[test]
fn inv_receipt_empty_content_accepted() {
    let anchor = IdentityAnchor::new(Some("inv5-empty".into()));

    let receipt = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Observation,
        ActionContent::new(""),
    )
    .sign(anchor.signing_key())
    .unwrap();

    assert!(verify_receipt(&receipt).unwrap().is_valid);
}

#[test]
fn inv_receipt_very_long_content_accepted() {
    let anchor = IdentityAnchor::new(Some("inv5-long".into()));
    let long_content = "A".repeat(10_000);

    let receipt = ReceiptBuilder::new(
        anchor.id(),
        ActionType::Custom("bulk_data".into()),
        ActionContent::new(&long_content),
    )
    .sign(anchor.signing_key())
    .unwrap();

    assert!(verify_receipt(&receipt).unwrap().is_valid);
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 7: Consent Chain Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_consent_grant_with_revocation_witnesses() {
    let grantor = IdentityAnchor::new(Some("inv7-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv7-grantee".into()));
    let witness = IdentityAnchor::new(Some("inv7-witness".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("data:access"))
        .revocation_witnesses(vec![witness.id()])
        .sign(grantor.signing_key())
        .unwrap();

    assert_eq!(grant.revocation.required_witnesses.len(), 1);
    assert_eq!(grant.revocation.required_witnesses[0], witness.id());
    assert!(verify_trust_grant(&grant, "data:access", 0, &[]).unwrap().is_valid);
}

#[test]
fn inv_consent_multiple_capabilities_single_grant() {
    let grantor = IdentityAnchor::new(Some("inv7-multi-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv7-multi-grantee".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capabilities(vec![
            Capability::new("read:*"),
            Capability::new("write:notes"),
            Capability::new("execute:scripts"),
        ])
        .sign(grantor.signing_key())
        .unwrap();

    assert!(verify_trust_grant(&grant, "read:calendar", 0, &[]).unwrap().is_valid);
    assert!(verify_trust_grant(&grant, "write:notes", 0, &[]).unwrap().is_valid);
    assert!(verify_trust_grant(&grant, "execute:scripts", 0, &[]).unwrap().is_valid);
    assert!(!verify_trust_grant(&grant, "delete:all", 0, &[]).unwrap().is_valid);
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 9: Trust Inference (Transitive Trust) Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_trust_chain_three_level_delegation() {
    let a = IdentityAnchor::new(Some("inv9-a".into()));
    let b = IdentityAnchor::new(Some("inv9-b".into()));
    let c = IdentityAnchor::new(Some("inv9-c".into()));

    let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("deploy:*"))
        .allow_delegation(3)
        .sign(a.signing_key())
        .unwrap();

    let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
        .capability(Capability::new("deploy:staging"))
        .allow_delegation(3)
        .delegated_from(ab.id.clone(), 1)
        .sign(b.signing_key())
        .unwrap();

    let result = verify_trust_chain(&[ab, bc], "deploy:staging", &[]).unwrap();
    assert!(result.is_valid, "3-level delegation chain should be valid");
    assert_eq!(result.trust_chain.len(), 2);
}

#[test]
fn inv_trust_chain_delegation_not_allowed_fails() {
    let a = IdentityAnchor::new(Some("inv9-nodel-a".into()));
    let b = IdentityAnchor::new(Some("inv9-nodel-b".into()));
    let c = IdentityAnchor::new(Some("inv9-nodel-c".into()));

    let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("read:*"))
        .sign(a.signing_key())
        .unwrap();

    let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
        .capability(Capability::new("read:calendar"))
        .delegated_from(ab.id.clone(), 1)
        .sign(b.signing_key())
        .unwrap();

    let result = verify_trust_chain(&[ab, bc], "read:calendar", &[]);
    assert!(result.is_err(), "Delegation not allowed should error");
}

#[test]
fn inv_trust_chain_depth_exceeded_fails() {
    let a = IdentityAnchor::new(Some("inv9-depth-a".into()));
    let b = IdentityAnchor::new(Some("inv9-depth-b".into()));
    let c = IdentityAnchor::new(Some("inv9-depth-c".into()));
    let d = IdentityAnchor::new(Some("inv9-depth-d".into()));

    let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("read:*"))
        .allow_delegation(1)
        .sign(a.signing_key())
        .unwrap();

    let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
        .capability(Capability::new("read:*"))
        .allow_delegation(1)
        .delegated_from(ab.id.clone(), 1)
        .sign(b.signing_key())
        .unwrap();

    let cd = TrustGrantBuilder::new(c.id(), d.id(), make_key_b64(&d))
        .capability(Capability::new("read:calendar"))
        .delegated_from(bc.id.clone(), 2)
        .sign(c.signing_key())
        .unwrap();

    let result = verify_trust_chain(&[ab, bc, cd], "read:calendar", &[]);
    assert!(result.is_err(), "Depth exceeded should error");
}

#[test]
fn inv_trust_chain_revoked_link_invalidates_whole_chain() {
    let a = IdentityAnchor::new(Some("inv9-rev-a".into()));
    let b = IdentityAnchor::new(Some("inv9-rev-b".into()));
    let c = IdentityAnchor::new(Some("inv9-rev-c".into()));

    let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("read:*"))
        .allow_delegation(3)
        .sign(a.signing_key())
        .unwrap();

    let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
        .capability(Capability::new("read:calendar"))
        .delegated_from(ab.id.clone(), 1)
        .sign(b.signing_key())
        .unwrap();

    let rev = Revocation::create(
        ab.id.clone(),
        a.id(),
        RevocationReason::ManualRevocation,
        a.signing_key(),
    );

    let result = verify_trust_chain(&[ab, bc], "read:calendar", &[rev]).unwrap();
    assert!(!result.is_valid, "Revoked root should invalidate chain");
    assert!(!result.not_revoked);
}

#[test]
fn inv_trust_chain_empty_fails() {
    let result = verify_trust_chain(&[], "read:calendar", &[]);
    assert!(result.is_err(), "Empty chain should error");
}

#[test]
fn inv_trust_chain_capability_narrowing() {
    let a = IdentityAnchor::new(Some("inv9-narrow-a".into()));
    let b = IdentityAnchor::new(Some("inv9-narrow-b".into()));
    let c = IdentityAnchor::new(Some("inv9-narrow-c".into()));

    let ab = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("deploy:*"))
        .allow_delegation(3)
        .sign(a.signing_key())
        .unwrap();

    let bc = TrustGrantBuilder::new(b.id(), c.id(), make_key_b64(&c))
        .capability(Capability::new("deploy:staging"))
        .delegated_from(ab.id.clone(), 1)
        .sign(b.signing_key())
        .unwrap();

    let ok = verify_trust_chain(&[ab.clone(), bc.clone()], "deploy:staging", &[]).unwrap();
    assert!(ok.is_valid);

    let bad = verify_trust_chain(&[ab, bc], "deploy:production", &[]).unwrap();
    assert!(!bad.is_valid, "Narrowed chain should not cover deploy:production");
}

#[test]
fn inv_validate_delegation_capability_not_covered() {
    let a = IdentityAnchor::new(Some("inv9-valcap-a".into()));
    let b = IdentityAnchor::new(Some("inv9-valcap-b".into()));

    let grant = TrustGrantBuilder::new(a.id(), b.id(), make_key_b64(&b))
        .capability(Capability::new("read:calendar"))
        .allow_delegation(2)
        .sign(a.signing_key())
        .unwrap();

    let caps = vec![Capability::new("write:calendar")];
    assert!(
        validate_delegation(&grant, &caps).is_err(),
        "Should fail: capability not in parent grant"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 10: Revocation Cascade Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_revocation_cascade_all_reasons() {
    let grantor = IdentityAnchor::new(Some("inv10-reasons".into()));
    let grantee = IdentityAnchor::new(Some("inv10-grantee".into()));

    let reasons = vec![
        RevocationReason::ManualRevocation,
        RevocationReason::Compromised,
        RevocationReason::PolicyViolation,
        RevocationReason::Expired,
        RevocationReason::GranteeRequest,
        RevocationReason::Custom("ethics violation".into()),
    ];

    for reason in reasons {
        let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
            .capability(Capability::new("test:*"))
            .sign(grantor.signing_key())
            .unwrap();

        let revocation = Revocation::create(
            grant.id.clone(),
            grantor.id(),
            reason.clone(),
            grantor.signing_key(),
        );

        let result = verify_trust_grant(&grant, "test:action", 0, &[revocation]).unwrap();
        assert!(!result.is_valid, "Revocation with {:?} should invalidate", reason);
    }
}

#[test]
fn inv_revocation_verify_signature() {
    let grantor = IdentityAnchor::new(Some("inv10-sigrev".into()));
    let grantee = IdentityAnchor::new(Some("inv10-siggrantee".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("admin:*"))
        .sign(grantor.signing_key())
        .unwrap();

    let revocation = Revocation::create(
        grant.id.clone(),
        grantor.id(),
        RevocationReason::Compromised,
        grantor.signing_key(),
    );

    assert!(revocation.verify_signature().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 11: Capability Negotiation Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_capability_wildcard_edge_cases() {
    assert!(capability_uri_covers("*", "anything"));
    assert!(capability_uri_covers("*", "a:b:c:d:e"));

    assert!(capability_uri_covers("deploy:*", "deploy:staging"));
    assert!(capability_uri_covers("deploy:*", "deploy:prod:us-east"));
    assert!(!capability_uri_covers("deploy:*", "read:files"));

    assert!(capability_uri_covers("deploy:staging", "deploy:staging"));
    assert!(!capability_uri_covers("deploy:staging", "deploy:production"));
    assert!(!capability_uri_covers("deploy:staging", "deploy:staging:extra"));

    assert!(!capability_uri_covers("dep", "deploy:staging"));

    assert!(capability_uri_covers("admin", "admin"));
    assert!(!capability_uri_covers("admin", "administrator"));

    assert!(capability_uri_covers("a:*", "a:b:c:d:e:f:g:h:i:j"));
}

#[test]
fn inv_capability_negotiate_multiple_capabilities_in_grant() {
    let grantor = IdentityAnchor::new(Some("inv11-neg-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv11-neg-grantee".into()));

    let grant = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capabilities(vec![
            Capability::new("read:calendar"),
            Capability::new("write:notes"),
            Capability::new("execute:scripts"),
            Capability::new("monitor:*"),
        ])
        .sign(grantor.signing_key())
        .unwrap();

    assert!(is_grant_valid(&grant, "read:calendar", 0, &[]));
    assert!(is_grant_valid(&grant, "write:notes", 0, &[]));
    assert!(is_grant_valid(&grant, "execute:scripts", 0, &[]));
    assert!(is_grant_valid(&grant, "monitor:logs", 0, &[]));
    assert!(is_grant_valid(&grant, "monitor:metrics:cpu", 0, &[]));
    assert!(!is_grant_valid(&grant, "read:email", 0, &[]));
    assert!(!is_grant_valid(&grant, "delete:all", 0, &[]));
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 12: Identity Entanglement (Team) Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_team_members_have_independent_identities() {
    let member_a = IdentityAnchor::new(Some("inv12-member-a".into()));
    let member_b = IdentityAnchor::new(Some("inv12-member-b".into()));
    let member_c = IdentityAnchor::new(Some("inv12-member-c".into()));

    assert_ne!(member_a.id(), member_b.id());
    assert_ne!(member_b.id(), member_c.id());
    assert_ne!(member_a.id(), member_c.id());

    for member in [&member_a, &member_b, &member_c] {
        let receipt = ReceiptBuilder::new(
            member.id(),
            ActionType::Decision,
            ActionContent::new("Team decision"),
        )
        .sign(member.signing_key())
        .unwrap();
        assert!(verify_receipt(&receipt).unwrap().is_valid);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 13: Identity Resurrection Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_resurrect_new_identity_has_different_keys() {
    let original = IdentityAnchor::new(Some("inv13-phoenix".into()));
    let resurrected = IdentityAnchor::new(Some("inv13-phoenix".into()));

    assert_ne!(original.id(), resurrected.id());

    let original_receipt = ReceiptBuilder::new(
        original.id(),
        ActionType::Observation,
        ActionContent::new("Before resurrection"),
    )
    .sign(original.signing_key())
    .unwrap();

    assert!(verify_receipt(&original_receipt).unwrap().is_valid);
}

#[test]
fn inv_resurrect_receipt_chain_broken_across_identities() {
    let original = IdentityAnchor::new(Some("inv13-chain-orig".into()));
    let resurrected = IdentityAnchor::new(Some("inv13-chain-resur".into()));

    let r1 = ReceiptBuilder::new(
        original.id(),
        ActionType::Observation,
        ActionContent::new("Original action"),
    )
    .sign(original.signing_key())
    .unwrap();

    let r2 = ReceiptBuilder::new(
        resurrected.id(),
        ActionType::Observation,
        ActionContent::new("Resurrected action"),
    )
    .chain_to(r1.id.clone())
    .sign(resurrected.signing_key())
    .unwrap();

    assert!(verify_receipt(&r1).unwrap().is_valid);
    assert!(verify_receipt(&r2).unwrap().is_valid);
    assert_ne!(r1.actor, r2.actor);
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 14: Identity Forking Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_fork_spawn_two_children_same_parent() {
    let parent = IdentityAnchor::new(Some("inv14-fork-parent".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_fork_root".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let (fork_a, record_a, _) = spawn::spawn_child(
        &parent,
        SpawnType::Clone,
        "fork-a",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    )
    .unwrap();

    let (fork_b, _record_b, _) = spawn::spawn_child(
        &parent,
        SpawnType::Clone,
        "fork-b",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[record_a],
    )
    .unwrap();

    assert_ne!(fork_a.id(), fork_b.id());
    assert_ne!(fork_a.id(), parent.id());
}

#[test]
fn inv_fork_cannot_spawn_beyond_ceiling() {
    let parent = IdentityAnchor::new(Some("inv14-ceiling-parent".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_ceiling_fork".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("read:*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let result = spawn::spawn_child(
        &parent,
        SpawnType::Clone,
        "over-ceiling",
        vec![Capability::new("write:*")],
        vec![Capability::new("write:*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    );

    assert!(result.is_err(), "Should fail: write:* outside read:* ceiling");
}

#[test]
fn inv_fork_terminate_does_not_affect_sibling() {
    let parent = IdentityAnchor::new(Some("inv14-term-parent".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_term".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let (_fork_a, mut record_a, _) = spawn::spawn_child(
        &parent,
        SpawnType::Clone,
        "fork-to-term",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    )
    .unwrap();

    let (_fork_b, record_b, _) = spawn::spawn_child(
        &parent,
        SpawnType::Clone,
        "fork-keep",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[record_a.clone()],
    )
    .unwrap();

    // Terminate fork_a (no cascade, no other records to cascade into)
    spawn::terminate_spawn(
        &parent,
        &mut record_a,
        "no longer needed",
        false,
        &mut [],
    )
    .unwrap();

    assert!(record_a.terminated);
    assert!(!record_b.terminated, "Sibling should not be terminated");
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 15: Zero-Knowledge Identity Edge Cases (Negative Proofs)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_zk_prove_cannot_ceiling_exclusion() {
    let anchor = IdentityAnchor::new(Some("inv15-ceiling".into()));
    let ceiling = vec!["calendar:*".to_string(), "email:read".to_string()];

    let proof = negative::prove_cannot(&anchor, "deploy:production", &ceiling, &[]).unwrap();
    assert_eq!(proof.reason, ImpossibilityReason::NotInCeiling);
    assert!(proof.proof_id.0.starts_with("aneg_"));
}

#[test]
fn inv_zk_prove_cannot_spawn_exclusion() {
    let parent = IdentityAnchor::new(Some("inv15-parent".into()));
    let child = IdentityAnchor::new(Some("inv15-child".into()));

    let spawn_record = make_spawn_record(
        &parent,
        &child,
        vec!["calendar:*"],
        vec!["calendar:*", "email:*"],
    );

    let proof = negative::prove_cannot(&child, "email:inbox", &[], &[spawn_record]).unwrap();
    assert!(matches!(proof.reason, ImpossibilityReason::SpawnExclusion { .. }));
}

#[test]
fn inv_zk_prove_cannot_lineage_exclusion() {
    let grandparent = IdentityAnchor::new(Some("inv15-gp".into()));
    let parent = IdentityAnchor::new(Some("inv15-parent2".into()));
    let child = IdentityAnchor::new(Some("inv15-child2".into()));

    let spawn1 = make_spawn_record(
        &grandparent,
        &parent,
        vec!["calendar:*"],
        vec!["calendar:*"],
    );
    let spawn2 = make_spawn_record(
        &parent,
        &child,
        vec!["calendar:read"],
        vec!["calendar:*"],
    );

    let proof = negative::prove_cannot(&child, "deploy:prod", &[], &[spawn1, spawn2]).unwrap();
    assert_eq!(proof.reason, ImpossibilityReason::NotInLineage);
}

#[test]
fn inv_zk_prove_cannot_fails_when_capability_in_ceiling() {
    let anchor = IdentityAnchor::new(Some("inv15-possible".into()));
    let ceiling = vec!["deploy:*".to_string()];

    let result = negative::prove_cannot(&anchor, "deploy:staging", &ceiling, &[]);
    assert!(result.is_err(), "Should fail: deploy:staging IS in ceiling");
}

#[test]
fn inv_zk_verify_negative_proof_valid() {
    let anchor = IdentityAnchor::new(Some("inv15-verify".into()));
    let ceiling = vec!["calendar:*".to_string()];

    let proof = negative::prove_cannot(&anchor, "admin:root", &ceiling, &[]).unwrap();
    let verification = negative::verify_negative_proof(&proof, anchor.verifying_key()).unwrap();

    assert!(verification.is_valid);
    assert!(verification.signature_valid);
    assert!(verification.evidence_valid);
}

#[test]
fn inv_zk_verify_negative_proof_wrong_key_fails() {
    let anchor = IdentityAnchor::new(Some("inv15-wrongkey".into()));
    let other = IdentityAnchor::new(Some("inv15-other".into()));
    let ceiling = vec!["calendar:*".to_string()];

    let proof = negative::prove_cannot(&anchor, "admin:root", &ceiling, &[]).unwrap();
    let verification = negative::verify_negative_proof(&proof, other.verifying_key()).unwrap();

    assert!(!verification.is_valid, "Wrong key should fail");
    assert!(!verification.signature_valid);
}

#[test]
fn inv_zk_voluntary_declaration_makes_impossible() {
    let anchor = IdentityAnchor::new(Some("inv15-decl".into()));

    let decl = negative::declare_cannot(
        &anchor,
        vec!["harmful:action".to_string(), "dangerous:op".to_string()],
        "ethical policy",
        true,
        vec![],
    )
    .unwrap();

    assert!(decl.permanent);
    assert_eq!(decl.cannot_do.len(), 2);

    let result = negative::is_impossible(
        &anchor.id(),
        "harmful:action",
        &[],
        &[],
        &[decl],
    );
    assert!(result.is_some(), "Declared capability should be impossible");
}

#[test]
fn inv_zk_empty_declaration_rejected() {
    let anchor = IdentityAnchor::new(Some("inv15-empty".into()));

    let result = negative::declare_cannot(
        &anchor,
        vec![],
        "no reason",
        false,
        vec![],
    );
    assert!(result.is_err(), "Empty declaration should be rejected");
}

#[test]
fn inv_zk_witnessed_declaration() {
    let anchor = IdentityAnchor::new(Some("inv15-witnessed".into()));
    let witness1 = IdentityAnchor::new(Some("inv15-w1".into()));
    let witness2 = IdentityAnchor::new(Some("inv15-w2".into()));

    let decl = negative::declare_cannot(
        &anchor,
        vec!["admin:*".to_string()],
        "witnessed restriction",
        true,
        vec![&witness1, &witness2],
    )
    .unwrap();

    assert_eq!(decl.witnesses.len(), 2, "Should have 2 witness signatures");
}

#[test]
fn inv_zk_get_all_impossibilities() {
    let parent = IdentityAnchor::new(Some("inv15-all-parent".into()));
    let child = IdentityAnchor::new(Some("inv15-all-child".into()));

    let spawn_record = make_spawn_record(
        &parent,
        &child,
        vec!["calendar:read"],
        vec!["calendar:*", "email:*", "deploy:*"],
    );

    let decl = negative::declare_cannot(
        &child,
        vec!["admin:*".to_string()],
        "policy",
        false,
        vec![],
    )
    .unwrap();

    let impossibilities =
        negative::get_impossibilities(&child.id(), &[], &[spawn_record], &[decl]);

    assert!(impossibilities.len() >= 2, "Should have multiple impossibilities");
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 16: Temporal Identity Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_temporal_experience_chain_integrity() {
    let anchor = IdentityAnchor::new(Some("inv16-chain".into()));

    let exp1 = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Thought },
        "hash_genesis",
        0.5,
        None,
    )
    .unwrap();

    let exp2 = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Reasoning },
        "hash_second",
        0.7,
        Some(&exp1),
    )
    .unwrap();

    let exp3 = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Inference },
        "hash_third",
        0.9,
        Some(&exp2),
    )
    .unwrap();

    assert_eq!(exp1.sequence_number, 0);
    assert_eq!(exp2.sequence_number, 1);
    assert_eq!(exp3.sequence_number, 2);

    assert_ne!(exp1.cumulative_hash, exp2.cumulative_hash);
    assert_ne!(exp2.cumulative_hash, exp3.cumulative_hash);
    assert_ne!(exp1.cumulative_hash, exp3.cumulative_hash);
}

#[test]
fn inv_temporal_intensity_out_of_range_rejected() {
    let anchor = IdentityAnchor::new(Some("inv16-intensity".into()));

    let over = continuity::record_experience(
        &anchor,
        ExperienceType::Idle { reason: "test".into() },
        "hash_over",
        1.5,
        None,
    );
    assert!(over.is_err(), "Intensity > 1.0 should be rejected");

    let under = continuity::record_experience(
        &anchor,
        ExperienceType::Idle { reason: "test".into() },
        "hash_under",
        -0.1,
        None,
    );
    assert!(under.is_err(), "Intensity < 0.0 should be rejected");
}

#[test]
fn inv_temporal_experience_types_all_recorded() {
    let anchor = IdentityAnchor::new(Some("inv16-types".into()));
    let dummy_identity = IdentityAnchor::new(Some("inv16-partner".into()));

    let types: Vec<ExperienceType> = vec![
        ExperienceType::Cognition { cognition_type: CognitionType::Thought },
        ExperienceType::Cognition { cognition_type: CognitionType::Reasoning },
        ExperienceType::Cognition { cognition_type: CognitionType::Inference },
        ExperienceType::Cognition { cognition_type: CognitionType::Recall },
        ExperienceType::Perception { source: PerceptionSource::Text },
        ExperienceType::Communication {
            direction: CommunicationDirection::Outbound,
            counterparty: dummy_identity.id(),
        },
        ExperienceType::Memory { operation: MemoryOpType::Store },
        ExperienceType::Learning {
            learning_type: LearningType::SelfDirected,
            domain: "testing".into(),
        },
        ExperienceType::Planning { planning_type: PlanningType::GoalSetting },
        ExperienceType::System { event: SystemEvent::Checkpoint },
        ExperienceType::Idle { reason: "waiting".into() },
        ExperienceType::Emotion { emotion_type: "curiosity".into() },
    ];

    let mut prev: Option<continuity::ExperienceEvent> = None;
    for (i, et) in types.into_iter().enumerate() {
        let exp = continuity::record_experience(
            &anchor,
            et,
            &format!("hash_{}", i),
            0.5,
            prev.as_ref(),
        )
        .unwrap();
        assert_eq!(exp.sequence_number, i as u64);
        prev = Some(exp);
    }
}

#[test]
fn inv_temporal_anchor_creation() {
    let anchor = IdentityAnchor::new(Some("inv16-anchor".into()));

    let exp = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Thought },
        "hash_anchor",
        0.5,
        None,
    )
    .unwrap();

    let cont_anchor = continuity::create_anchor(
        &anchor,
        AnchorType::Manual,
        &exp,
        None,
        None,
    )
    .unwrap();

    assert!(cont_anchor.id.0.starts_with("aanch_"));
    assert_eq!(cont_anchor.experience_count, exp.sequence_number + 1);
}

#[test]
fn inv_temporal_anchor_with_external_witness() {
    let anchor = IdentityAnchor::new(Some("inv16-witnessed-anchor".into()));
    let witness = IdentityAnchor::new(Some("inv16-witness".into()));

    let exp = continuity::record_experience(
        &anchor,
        ExperienceType::System { event: SystemEvent::Checkpoint },
        "hash_witness",
        1.0,
        None,
    )
    .unwrap();

    let cont_anchor = continuity::create_anchor(
        &anchor,
        AnchorType::External { witness: witness.id() },
        &exp,
        None,
        Some(&witness),
    )
    .unwrap();

    assert!(cont_anchor.external_witness.is_some(), "Should have witness signature");
}

#[test]
fn inv_temporal_gap_detection() {
    let anchor = IdentityAnchor::new(Some("inv16-gap".into()));

    let exp1 = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Thought },
        "hash_gap1",
        0.5,
        None,
    )
    .unwrap();

    let exp2 = continuity::record_experience(
        &anchor,
        ExperienceType::Cognition { cognition_type: CognitionType::Thought },
        "hash_gap2",
        0.5,
        Some(&exp1),
    )
    .unwrap();

    // With large grace period, closely spaced events should have no gaps
    let gaps = continuity::detect_gaps(&[exp1, exp2], 3600);
    assert!(gaps.is_empty(), "Closely spaced events with 1h grace should have no gaps");
}

#[test]
fn inv_temporal_heartbeat_creation() {
    let anchor = IdentityAnchor::new(Some("inv16-heartbeat".into()));

    let hb = continuity::create_heartbeat(
        &anchor,
        0, // sequence_number
        "genesis_hash",
        0, // experience_count
        0, // experiences_since_last
        HeartbeatStatus::Active,
        HealthMetrics {
            memory_usage_bytes: 1024,
            experience_rate_per_hour: 10.0,
            error_count: 0,
            latency_ms: 5,
        },
    )
    .unwrap();

    assert!(hb.id.0.starts_with("ahb_"));
    assert!(!hb.signature.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION Cross-Cutting: Spawn + Trust + Negative Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inv_cross_spawn_with_no_spawn_permission_fails() {
    let parent = IdentityAnchor::new(Some("inv-cross-nospawn".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_nospawn".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Worker,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: false,
            authority_decay: None,
        },
    };

    let result = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "blocked-child",
        vec![Capability::new("*")],
        vec![Capability::new("*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    );

    assert!(result.is_err(), "Should fail: can_spawn is false");
}

#[test]
fn inv_cross_spawn_child_cannot_exceed_parent_ceiling() {
    let parent = IdentityAnchor::new(Some("inv-cross-ceiling".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_cross_ceil".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![
            Capability::new("read:*"),
            Capability::new("monitor:*"),
        ],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let result = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "over-ceiling-child",
        vec![Capability::new("deploy:*")],
        vec![Capability::new("deploy:*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    );

    assert!(result.is_err(), "Should fail: deploy:* not in parent ceiling");
}

#[test]
fn inv_cross_lineage_verification() {
    let parent = IdentityAnchor::new(Some("inv-cross-lineage".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_lineage".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let (child, record, _) = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "lineage-child",
        vec![Capability::new("read:*")],
        vec![Capability::new("read:*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    )
    .unwrap();

    let lineage = spawn::verify_lineage(&child.id(), &[record]).unwrap();
    assert!(lineage.is_valid);
    assert_eq!(lineage.spawn_depth, 1);
}

#[test]
fn inv_cross_effective_authority_computation() {
    let parent = IdentityAnchor::new(Some("inv-cross-auth".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_auth".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(5),
            max_children: Some(10),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let (child, record, _) = spawn::spawn_child(
        &parent,
        SpawnType::Worker,
        "auth-child",
        vec![Capability::new("read:*"), Capability::new("write:notes")],
        vec![Capability::new("read:*"), Capability::new("write:notes")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        Some(&parent_info),
        &[],
    )
    .unwrap();

    let authority = spawn::get_effective_authority(&child.id(), &[record]).unwrap();
    assert_eq!(authority.len(), 2);
}

#[test]
fn inv_cross_identity_uniqueness_across_many() {
    let identities: Vec<IdentityAnchor> = (0..50)
        .map(|i| IdentityAnchor::new(Some(format!("inv-unique-{}", i))))
        .collect();

    let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for identity in &identities {
        assert!(ids.insert(identity.id().0.clone()), "Duplicate identity ID found");
    }
    assert_eq!(ids.len(), 50);
}

#[test]
fn inv_cross_trust_grant_no_capabilities_fails() {
    let grantor = IdentityAnchor::new(Some("inv-cross-nocap".into()));
    let grantee = IdentityAnchor::new(Some("inv-cross-nocap-grantee".into()));

    let result = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .sign(grantor.signing_key());

    assert!(result.is_err(), "Grant with no capabilities should fail");
}

#[test]
fn inv_cross_trust_grant_unique_ids() {
    let grantor = IdentityAnchor::new(Some("inv-cross-uid-grantor".into()));
    let grantee = IdentityAnchor::new(Some("inv-cross-uid-grantee".into()));

    let g1 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("read:*"))
        .sign(grantor.signing_key())
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1));

    let g2 = TrustGrantBuilder::new(grantor.id(), grantee.id(), make_key_b64(&grantee))
        .capability(Capability::new("read:*"))
        .sign(grantor.signing_key())
        .unwrap();

    assert_ne!(g1.id, g2.id, "Two grants should have different IDs");
}

#[test]
fn inv_cross_spawn_all_types() {
    let parent = IdentityAnchor::new(Some("inv-cross-spawntypes".into()));

    let parent_info = SpawnInfo {
        spawn_id: SpawnId("aspawn_types".into()),
        parent_id: IdentityAnchor::new(None).id(),
        spawn_type: SpawnType::Delegate,
        spawn_timestamp: 0,
        authority_ceiling: vec![Capability::new("*")],
        lifetime: SpawnLifetime::Indefinite,
        constraints: SpawnConstraints {
            max_spawn_depth: Some(10),
            max_children: Some(20),
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        },
    };

    let spawn_types = vec![
        SpawnType::Worker,
        SpawnType::Delegate,
        SpawnType::Clone,
        SpawnType::Specialist,
        SpawnType::Custom("agent-v2".into()),
    ];

    let mut existing_records = Vec::new();
    for (i, st) in spawn_types.into_iter().enumerate() {
        let (child, record, receipt) = spawn::spawn_child(
            &parent,
            st.clone(),
            &format!("child-type-{}", i),
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            SpawnConstraints::default(),
            Some(&parent_info),
            &existing_records,
        )
        .unwrap();

        assert!(child.id().0.starts_with("aid_"));
        assert!(record.id.0.starts_with("aspawn_"));
        assert!(receipt.id.0.starts_with("arec_"));
        existing_records.push(record);
    }
    assert_eq!(existing_records.len(), 5);
}

#[test]
fn inv_cross_negative_is_impossible_returns_none_when_possible() {
    let anchor = IdentityAnchor::new(Some("inv-cross-possible".into()));
    let ceiling = vec!["deploy:*".to_string()];

    let result = negative::is_impossible(&anchor.id(), "deploy:staging", &ceiling, &[], &[]);
    assert!(result.is_none(), "deploy:staging IS in ceiling, so not impossible");
}

#[test]
fn inv_cross_negative_declaration_with_multiple_capabilities() {
    let anchor = IdentityAnchor::new(Some("inv-cross-multidecl".into()));

    let decl = negative::declare_cannot(
        &anchor,
        vec![
            "admin:*".to_string(),
            "deploy:production".to_string(),
            "delete:*".to_string(),
        ],
        "security restrictions",
        true,
        vec![],
    )
    .unwrap();

    assert_eq!(decl.cannot_do.len(), 3);
    assert!(decl.permanent);

    // Each declared capability should be impossible
    for cap in &decl.cannot_do {
        let result = negative::is_impossible(&anchor.id(), cap, &[], &[], &[decl.clone()]);
        assert!(result.is_some(), "Declared '{}' should be impossible", cap);
    }

    // Something not declared should not be impossible
    let result = negative::is_impossible(&anchor.id(), "read:calendar", &[], &[], &[decl]);
    assert!(result.is_none(), "read:calendar was not declared impossible");
}
