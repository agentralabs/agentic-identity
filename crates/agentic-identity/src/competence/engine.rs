//! Competence engine — recording attempts, generating proofs, verification.

use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityAnchor, IdentityId};
use crate::receipt::ReceiptId;

use super::types::*;

// ---------------------------------------------------------------------------
// Record attempt
// ---------------------------------------------------------------------------

/// Record a competence attempt.
///
/// Creates a signed attempt record linking to a receipt. An optional validator
/// can co-sign the outcome (e.g., another agent confirming the result).
pub fn record_attempt(
    identity: &IdentityAnchor,
    domain: CompetenceDomain,
    outcome: AttemptOutcome,
    receipt_id: ReceiptId,
    context: Option<String>,
    validator: Option<&IdentityAnchor>,
) -> Result<CompetenceAttempt> {
    let now = crate::time::now_micros();

    // Validate partial score
    if let AttemptOutcome::Partial { score } = &outcome {
        if *score < 0.0 || *score > 1.0 {
            return Err(IdentityError::InvalidKey(format!(
                "Partial score must be 0.0-1.0, got {}",
                score
            )));
        }
    }

    // Generate attempt ID
    let id_input = format!("{}:{}:{}:{}", identity.id().0, domain.0, receipt_id.0, now);
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let attempt_id = AttemptId(format!("aatt_{id_encoded}"));

    // Sign the attempt
    let outcome_tag = match &outcome {
        AttemptOutcome::Success => "success".to_string(),
        AttemptOutcome::Failure { reason } => format!("failure:{}", reason),
        AttemptOutcome::Partial { score } => format!("partial:{}", score),
    };

    let sign_input = format!(
        "attempt:{}:{}:{}:{}:{}",
        attempt_id.0,
        identity.id().0,
        domain.0,
        outcome_tag,
        now
    );
    let signature = signing::sign_to_base64(identity.signing_key(), sign_input.as_bytes());

    // Validator co-signature
    let (validator_id, validator_sig) = if let Some(val) = validator {
        let val_sign_input = format!(
            "validate:{}:{}:{}:{}",
            attempt_id.0,
            val.id().0,
            outcome_tag,
            now
        );
        let val_sig = signing::sign_to_base64(val.signing_key(), val_sign_input.as_bytes());
        (Some(val.id()), Some(val_sig))
    } else {
        (None, None)
    };

    Ok(CompetenceAttempt {
        attempt_id,
        identity: identity.id(),
        domain,
        outcome,
        timestamp: now,
        receipt_id,
        context,
        validator: validator_id,
        validator_signature: validator_sig,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Get competence (from a list of attempts)
// ---------------------------------------------------------------------------

/// Get aggregated competence record for an identity + domain from a list of attempts.
pub fn get_competence(
    identity: &IdentityId,
    domain: &CompetenceDomain,
    attempts: &[CompetenceAttempt],
) -> Option<CompetenceRecord> {
    let relevant: Vec<&CompetenceAttempt> = attempts
        .iter()
        .filter(|a| &a.identity == identity && &a.domain == domain)
        .collect();

    if relevant.is_empty() {
        return None;
    }

    let mut record = CompetenceRecord::new(identity.clone(), domain.clone());
    for attempt in relevant {
        record.record_attempt(attempt);
    }
    Some(record)
}

// ---------------------------------------------------------------------------
// List competences
// ---------------------------------------------------------------------------

/// List all competence domains for an identity.
pub fn list_competences(
    identity: &IdentityId,
    attempts: &[CompetenceAttempt],
) -> Vec<CompetenceRecord> {
    let mut domains = std::collections::HashSet::new();
    for a in attempts {
        if &a.identity == identity {
            domains.insert(a.domain.clone());
        }
    }

    let mut records = Vec::new();
    for domain in domains {
        if let Some(record) = get_competence(identity, &domain, attempts) {
            records.push(record);
        }
    }
    records
}

// ---------------------------------------------------------------------------
// Generate proof
// ---------------------------------------------------------------------------

/// Generate a competence proof with evidence.
///
/// The proof is a signed claim that the identity meets certain competence
/// criteria in a domain. It samples evidence attempts and is optionally
/// time-bounded.
pub fn generate_proof(
    identity: &IdentityAnchor,
    domain: CompetenceDomain,
    min_attempts: u64,
    min_success_rate: f32,
    min_streak: Option<u32>,
    valid_duration_seconds: Option<u64>,
    attempts: &[CompetenceAttempt],
) -> Result<CompetenceProof> {
    let now = crate::time::now_micros();

    // Build the record
    let record = get_competence(&identity.id(), &domain, attempts).ok_or_else(|| {
        IdentityError::NotFound(format!("No competence record for domain '{}'", domain.0))
    })?;

    // Check minimum attempts
    if record.total_attempts < min_attempts {
        return Err(IdentityError::NotFound(format!(
            "Insufficient attempts: required {}, actual {}",
            min_attempts, record.total_attempts
        )));
    }

    // Check minimum success rate
    if record.success_rate < min_success_rate {
        return Err(IdentityError::TrustNotGranted(format!(
            "Competence not met for {}: required {}%, actual {:.1}%",
            domain.0,
            min_success_rate * 100.0,
            record.success_rate * 100.0
        )));
    }

    // Check minimum streak
    if let Some(min_s) = min_streak {
        if record.streak_best < min_s {
            return Err(IdentityError::TrustNotGranted(format!(
                "Streak not met for {}: required {}, best {}",
                domain.0, min_s, record.streak_best
            )));
        }
    }

    let claim = CompetenceClaim {
        min_attempts,
        min_success_rate,
        min_streak,
        recency_window: None,
        actual_attempts: record.total_attempts,
        actual_success_rate: record.success_rate,
        actual_streak: record.streak_current,
    };

    // Sample evidence (up to 20 most recent)
    let evidence_sample: Vec<AttemptId> = record.evidence.iter().rev().take(20).cloned().collect();

    let valid_until = valid_duration_seconds.map(|d| now + d * 1_000_000);

    // Compute proof hash
    let hash_input = format!(
        "proof:{}:{}:{}:{}:{}:{}",
        identity.id().0,
        domain.0,
        record.total_attempts,
        record.success_rate,
        now,
        valid_until.unwrap_or(0)
    );
    let proof_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    // Generate proof ID
    let id_hash = Sha256::digest(proof_hash.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let proof_id = ProofId(format!("aprf_{id_encoded}"));

    // Sign the proof
    let signature = signing::sign_to_base64(identity.signing_key(), proof_hash.as_bytes());

    Ok(CompetenceProof {
        proof_id,
        identity: identity.id(),
        domain,
        claim,
        evidence_sample,
        evidence_count: record.total_attempts,
        generated_at: now,
        valid_until,
        proof_hash,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Verify proof
// ---------------------------------------------------------------------------

/// Verify a competence proof's signature and check if it has expired.
pub fn verify_proof(
    proof: &CompetenceProof,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<CompetenceVerification> {
    let now = crate::time::now_micros();
    let mut errors = Vec::new();

    // Verify signature
    let sig_valid =
        signing::verify_from_base64(verifying_key, proof.proof_hash.as_bytes(), &proof.signature)
            .is_ok();

    if !sig_valid {
        errors.push("Signature verification failed".to_string());
    }

    // Check expiration
    let not_expired = match proof.valid_until {
        Some(until) => {
            if now > until {
                errors.push("Competence proof expired".to_string());
                false
            } else {
                true
            }
        }
        None => true,
    };

    // Check claim validity
    let meets_attempts = proof.claim.actual_attempts >= proof.claim.min_attempts;
    if !meets_attempts {
        errors.push(format!(
            "Insufficient attempts: claimed {} >= {}, actual {}",
            proof.claim.actual_attempts, proof.claim.min_attempts, proof.claim.actual_attempts
        ));
    }

    let meets_rate = proof.claim.actual_success_rate >= proof.claim.min_success_rate;
    if !meets_rate {
        errors.push(format!(
            "Success rate not met: claimed {:.1}% >= {:.1}%",
            proof.claim.actual_success_rate * 100.0,
            proof.claim.min_success_rate * 100.0
        ));
    }

    let meets_streak = match proof.claim.min_streak {
        Some(min_s) => {
            let meets = proof.claim.actual_streak >= 0 && proof.claim.actual_streak as u32 >= min_s;
            if !meets {
                errors.push(format!(
                    "Streak not met: actual {}, required {}",
                    proof.claim.actual_streak, min_s
                ));
            }
            meets
        }
        None => true,
    };

    let is_valid = sig_valid && not_expired && meets_attempts && meets_rate && meets_streak;

    Ok(CompetenceVerification {
        identity: proof.identity.clone(),
        domain: proof.domain.clone(),
        meets_attempts,
        meets_rate,
        meets_streak,
        meets_recency: not_expired,
        is_valid,
        verified_at: now,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Check competence
// ---------------------------------------------------------------------------

/// Check if an identity meets a competence requirement.
pub fn check_competence(
    identity: &IdentityId,
    requirement: &CompetenceRequirement,
    attempts: &[CompetenceAttempt],
) -> CompetenceVerification {
    let now = crate::time::now_micros();
    let mut errors = Vec::new();

    // Filter attempts by recency if max_age_seconds is set
    let relevant_attempts: Vec<&CompetenceAttempt> = if let Some(max_age) =
        requirement.max_age_seconds
    {
        let cutoff = now.saturating_sub(max_age * 1_000_000);
        attempts
            .iter()
            .filter(|a| {
                &a.identity == identity && a.domain == requirement.domain && a.timestamp >= cutoff
            })
            .collect()
    } else {
        attempts
            .iter()
            .filter(|a| &a.identity == identity && a.domain == requirement.domain)
            .collect()
    };

    if relevant_attempts.is_empty() {
        return CompetenceVerification {
            identity: identity.clone(),
            domain: requirement.domain.clone(),
            meets_attempts: false,
            meets_rate: false,
            meets_streak: false,
            meets_recency: true,
            is_valid: false,
            verified_at: now,
            errors: vec!["No competence attempts found".to_string()],
        };
    }

    // Build record from relevant attempts
    let mut record = CompetenceRecord::new(identity.clone(), requirement.domain.clone());
    for attempt in relevant_attempts {
        record.record_attempt(attempt);
    }

    let meets_attempts = record.total_attempts >= requirement.min_attempts;
    if !meets_attempts {
        errors.push(format!(
            "Insufficient attempts: required {}, actual {}",
            requirement.min_attempts, record.total_attempts
        ));
    }

    let meets_rate = record.success_rate >= requirement.min_success_rate;
    if !meets_rate {
        errors.push(format!(
            "Success rate not met: required {:.1}%, actual {:.1}%",
            requirement.min_success_rate * 100.0,
            record.success_rate * 100.0
        ));
    }

    let meets_streak = match requirement.min_streak {
        Some(min_s) => {
            let meets = record.streak_best >= min_s;
            if !meets {
                errors.push(format!(
                    "Streak not met: required {}, best {}",
                    min_s, record.streak_best
                ));
            }
            meets
        }
        None => true,
    };

    let is_valid = meets_attempts && meets_rate && meets_streak;

    CompetenceVerification {
        identity: identity.clone(),
        domain: requirement.domain.clone(),
        meets_attempts,
        meets_rate,
        meets_streak,
        meets_recency: true,
        is_valid,
        verified_at: now,
        errors,
    }
}

// ---------------------------------------------------------------------------
// Tests (12 scenarios)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::receipt::ReceiptBuilder;
    use crate::receipt::{ActionContent, ActionType, ReceiptId};

    fn test_identity() -> IdentityAnchor {
        IdentityAnchor::new(Some("competence-tester".to_string()))
    }

    fn make_receipt(anchor: &IdentityAnchor) -> ReceiptId {
        ReceiptBuilder::new(
            anchor.id(),
            ActionType::Custom("competence_test".into()),
            ActionContent::new("test action"),
        )
        .sign(anchor.signing_key())
        .unwrap()
        .id
    }

    // 1. Record successful attempt
    #[test]
    fn test_record_successful_attempt() {
        let identity = test_identity();
        let receipt_id = make_receipt(&identity);
        let domain = CompetenceDomain::new("deploy");

        let attempt = record_attempt(
            &identity,
            domain.clone(),
            AttemptOutcome::Success,
            receipt_id,
            None,
            None,
        )
        .unwrap();

        assert!(attempt.attempt_id.0.starts_with("aatt_"));
        assert_eq!(attempt.identity, identity.id());
        assert_eq!(attempt.domain, domain);
        assert_eq!(attempt.outcome, AttemptOutcome::Success);
        assert!(!attempt.signature.is_empty());
        assert!(attempt.validator.is_none());
    }

    // 2. Record failed attempt
    #[test]
    fn test_record_failed_attempt() {
        let identity = test_identity();
        let receipt_id = make_receipt(&identity);
        let domain = CompetenceDomain::new("deploy");

        let attempt = record_attempt(
            &identity,
            domain.clone(),
            AttemptOutcome::Failure {
                reason: "timeout".to_string(),
            },
            receipt_id,
            Some("production deploy".to_string()),
            None,
        )
        .unwrap();

        assert!(matches!(attempt.outcome, AttemptOutcome::Failure { .. }));
        assert_eq!(attempt.context.as_deref(), Some("production deploy"));
    }

    // 3. Record partial attempt
    #[test]
    fn test_record_partial_attempt() {
        let identity = test_identity();
        let receipt_id = make_receipt(&identity);
        let domain = CompetenceDomain::new("code_review");

        let attempt = record_attempt(
            &identity,
            domain,
            AttemptOutcome::Partial { score: 0.8 },
            receipt_id,
            None,
            None,
        )
        .unwrap();

        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::Partial { score } if (score - 0.8).abs() < 0.001
        ));
    }

    // 4. Success rate calculation correct
    #[test]
    fn test_success_rate_calculation() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        // 7 successes, 3 failures => rate = 7/10 = 0.7
        for i in 0..10 {
            let receipt_id = make_receipt(&identity);
            let outcome = if i < 7 {
                AttemptOutcome::Success
            } else {
                AttemptOutcome::Failure {
                    reason: "test".into(),
                }
            };
            let attempt =
                record_attempt(&identity, domain.clone(), outcome, receipt_id, None, None).unwrap();
            attempts.push(attempt);
        }

        let record = get_competence(&identity.id(), &domain, &attempts).unwrap();
        assert_eq!(record.total_attempts, 10);
        assert_eq!(record.successes, 7);
        assert_eq!(record.failures, 3);
        assert!((record.success_rate - 0.7).abs() < 0.01);
    }

    // 5. Streak tracking works
    #[test]
    fn test_streak_tracking() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        // 5 successes, 1 failure, 3 successes => best streak = 5, current = 3
        let outcomes = vec![
            AttemptOutcome::Success,
            AttemptOutcome::Success,
            AttemptOutcome::Success,
            AttemptOutcome::Success,
            AttemptOutcome::Success,
            AttemptOutcome::Failure {
                reason: "test".into(),
            },
            AttemptOutcome::Success,
            AttemptOutcome::Success,
            AttemptOutcome::Success,
        ];

        for outcome in outcomes {
            let receipt_id = make_receipt(&identity);
            let attempt =
                record_attempt(&identity, domain.clone(), outcome, receipt_id, None, None).unwrap();
            attempts.push(attempt);
        }

        let record = get_competence(&identity.id(), &domain, &attempts).unwrap();
        assert_eq!(record.streak_best, 5);
        assert_eq!(record.streak_current, 3);
    }

    // 6. Generate proof succeeds when criteria met
    #[test]
    fn test_generate_proof_succeeds() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..10 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        let proof = generate_proof(
            &identity,
            domain.clone(),
            5,   // min 5 attempts
            0.8, // min 80% success
            None,
            None,
            &attempts,
        )
        .unwrap();

        assert!(proof.proof_id.0.starts_with("aprf_"));
        assert_eq!(proof.identity, identity.id());
        assert_eq!(proof.domain, domain);
        assert_eq!(proof.claim.actual_attempts, 10);
        assert!((proof.claim.actual_success_rate - 1.0).abs() < 0.01);
        assert!(!proof.evidence_sample.is_empty());
        assert!(!proof.signature.is_empty());
    }

    // 7. Generate proof fails when criteria not met
    #[test]
    fn test_generate_proof_fails_insufficient() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..3 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        // Require 10 attempts but only have 3
        let result = generate_proof(&identity, domain, 10, 0.8, None, None, &attempts);
        assert!(result.is_err());
    }

    // 8. Verify valid proof succeeds
    #[test]
    fn test_verify_valid_proof() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..10 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        let proof = generate_proof(&identity, domain, 5, 0.8, None, None, &attempts).unwrap();

        let verification = verify_proof(&proof, identity.verifying_key()).unwrap();
        assert!(verification.is_valid);
        assert!(verification.meets_attempts);
        assert!(verification.meets_rate);
        assert!(verification.meets_recency);
        assert!(verification.errors.is_empty());
    }

    // 9. Verify tampered proof fails
    #[test]
    fn test_verify_tampered_proof_fails() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..10 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        let mut proof = generate_proof(&identity, domain, 5, 0.8, None, None, &attempts).unwrap();

        // Tamper with the proof hash
        proof.proof_hash = "tampered_hash_value".to_string();

        let verification = verify_proof(&proof, identity.verifying_key()).unwrap();
        assert!(!verification.is_valid);
        assert!(!verification.errors.is_empty());
    }

    // 10. Trust grant with competence requirement - met
    #[test]
    fn test_competence_requirement_met() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..20 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        let requirement = CompetenceRequirement {
            domain: domain.clone(),
            min_attempts: 10,
            min_success_rate: 0.9,
            min_streak: Some(5),
            max_age_seconds: None,
        };

        let verification = check_competence(&identity.id(), &requirement, &attempts);
        assert!(verification.is_valid);
        assert!(verification.meets_attempts);
        assert!(verification.meets_rate);
        assert!(verification.meets_streak);
    }

    // 11. Trust grant with competence requirement - not met
    #[test]
    fn test_competence_requirement_not_met() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        // Only 3 successes, 7 failures => 30% success rate
        for i in 0..10 {
            let receipt_id = make_receipt(&identity);
            let outcome = if i < 3 {
                AttemptOutcome::Success
            } else {
                AttemptOutcome::Failure {
                    reason: "test".into(),
                }
            };
            let attempt =
                record_attempt(&identity, domain.clone(), outcome, receipt_id, None, None).unwrap();
            attempts.push(attempt);
        }

        let requirement = CompetenceRequirement {
            domain: domain.clone(),
            min_attempts: 5,
            min_success_rate: 0.9,
            min_streak: None,
            max_age_seconds: None,
        };

        let verification = check_competence(&identity.id(), &requirement, &attempts);
        assert!(!verification.is_valid);
        assert!(!verification.meets_rate);
    }

    // 12. Competence proof expiration works
    #[test]
    fn test_competence_proof_expiration() {
        let identity = test_identity();
        let domain = CompetenceDomain::new("deploy");

        let mut attempts = Vec::new();
        for _ in 0..10 {
            let receipt_id = make_receipt(&identity);
            let attempt = record_attempt(
                &identity,
                domain.clone(),
                AttemptOutcome::Success,
                receipt_id,
                None,
                None,
            )
            .unwrap();
            attempts.push(attempt);
        }

        // Create proof that's already expired (valid_until in the past)
        let mut proof =
            generate_proof(&identity, domain, 5, 0.8, None, Some(1), &attempts).unwrap();

        // Manually set valid_until to a past timestamp (1 second ago)
        proof.valid_until = Some(crate::time::now_micros().saturating_sub(1_000_000));

        // Re-sign with the updated hash (re-compute to test expiration check)
        // For the expiration test, we just check the verification detects expiration
        let verification = verify_proof(&proof, identity.verifying_key()).unwrap();

        // The proof is expired, but the signature may or may not match
        // (since we modified valid_until after signing). The point is
        // expiration should be caught.
        assert!(!verification.meets_recency);
        assert!(!verification.is_valid);
    }
}
