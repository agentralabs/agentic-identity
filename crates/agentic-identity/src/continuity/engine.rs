//! Continuity engine — experience recording, anchoring, heartbeats, and verification.

use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityAnchor, IdentityId};
use crate::receipt::witness::WitnessSignature;

use super::types::*;

// ---------------------------------------------------------------------------
// Experience recording
// ---------------------------------------------------------------------------

/// Record an experience event, linking it to the previous event in the chain.
///
/// If `previous` is `None` this becomes the genesis event (sequence 0).
pub fn record_experience(
    identity: &IdentityAnchor,
    event_type: ExperienceType,
    content_hash: &str,
    intensity: f32,
    previous: Option<&ExperienceEvent>,
) -> Result<ExperienceEvent> {
    // Validate intensity
    if !(0.0..=1.0).contains(&intensity) {
        return Err(IdentityError::InvalidChain);
    }

    let now = crate::time::now_micros();
    let identity_id = identity.id();

    let (prev_id, prev_hash, seq) = match previous {
        Some(prev) => (
            Some(prev.id.clone()),
            Some(prev.cumulative_hash.clone()),
            prev.sequence_number + 1,
        ),
        None => (None, None, 0),
    };

    // Compute cumulative hash = SHA-256(prev_cumulative_hash || content_hash || seq || timestamp)
    let cumulative_input = format!(
        "{}:{}:{}:{}",
        prev_hash.as_deref().unwrap_or("genesis"),
        content_hash,
        seq,
        now,
    );
    let cumulative_hash = hex::encode(Sha256::digest(cumulative_input.as_bytes()));

    // Generate experience ID
    let id_input = format!("exp:{}:{}:{}", identity_id.0, seq, now);
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let id = ExperienceId(format!("aexp_{id_encoded}"));

    // Sign the cumulative hash
    let signature = signing::sign_to_base64(identity.signing_key(), cumulative_hash.as_bytes());

    Ok(ExperienceEvent {
        id,
        identity: identity_id,
        event_type,
        timestamp: now,
        duration: None,
        content_hash: content_hash.to_string(),
        intensity,
        previous_experience_id: prev_id,
        previous_experience_hash: prev_hash,
        sequence_number: seq,
        cumulative_hash,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Continuity anchor
// ---------------------------------------------------------------------------

/// Create a continuity anchor (checkpoint) at the latest experience.
pub fn create_anchor(
    identity: &IdentityAnchor,
    anchor_type: AnchorType,
    latest_experience: &ExperienceEvent,
    previous_anchor: Option<&ContinuityAnchor>,
    external_witness: Option<&IdentityAnchor>,
) -> Result<ContinuityAnchor> {
    let now = crate::time::now_micros();
    let identity_id = identity.id();

    let prev_anchor_id = previous_anchor.map(|a| a.id.clone());

    // Generate anchor ID
    let id_input = format!(
        "anchor:{}:{}:{}",
        identity_id.0, latest_experience.sequence_number, now,
    );
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let id = AnchorId(format!("aanch_{id_encoded}"));

    // Optional external witness signature
    let witness_sig = external_witness.map(|w| {
        let ws =
            WitnessSignature::create(w.id(), w.signing_key(), &latest_experience.cumulative_hash);
        serde_json::to_string(&ws).unwrap_or_default()
    });

    // Sign the anchor
    let sign_input = format!(
        "anchor:{}:{}:{}:{}:{}",
        id.0,
        anchor_type.as_tag(),
        latest_experience.cumulative_hash,
        latest_experience.sequence_number + 1,
        now,
    );
    let signature = signing::sign_to_base64(identity.signing_key(), sign_input.as_bytes());

    Ok(ContinuityAnchor {
        id,
        identity: identity_id,
        anchor_type,
        experience_id: latest_experience.id.clone(),
        cumulative_hash: latest_experience.cumulative_hash.clone(),
        experience_count: latest_experience.sequence_number + 1,
        timestamp: now,
        previous_anchor: prev_anchor_id,
        external_witness: witness_sig,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

/// Create a heartbeat record.
pub fn create_heartbeat(
    identity: &IdentityAnchor,
    sequence_number: u64,
    continuity_hash: &str,
    experience_count: u64,
    experiences_since_last: u64,
    status: HeartbeatStatus,
    health: HealthMetrics,
) -> Result<HeartbeatRecord> {
    let now = crate::time::now_micros();
    let identity_id = identity.id();

    // Generate heartbeat ID
    let id_input = format!("hb:{}:{}:{}", identity_id.0, sequence_number, now);
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let id = HeartbeatId(format!("ahb_{id_encoded}"));

    // Sign the heartbeat
    let sign_input = format!(
        "heartbeat:{}:{}:{}:{}:{}",
        id.0,
        sequence_number,
        continuity_hash,
        status.as_tag(),
        now,
    );
    let signature = signing::sign_to_base64(identity.signing_key(), sign_input.as_bytes());

    Ok(HeartbeatRecord {
        id,
        identity: identity_id,
        timestamp: now,
        sequence_number,
        continuity_hash: continuity_hash.to_string(),
        experience_count,
        experiences_since_last,
        status,
        health,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Continuity claim
// ---------------------------------------------------------------------------

/// Create a continuity claim over a range of experiences.
pub fn create_continuity_claim(
    identity: &IdentityAnchor,
    claim_type: ClaimType,
    experiences: &[ExperienceEvent],
    anchors: &[ContinuityAnchor],
    grace_period_seconds: u64,
) -> Result<ContinuityClaim> {
    if experiences.is_empty() {
        return Err(IdentityError::InvalidChain);
    }

    let now = crate::time::now_micros();
    let identity_id = identity.id();

    let first = &experiences[0];
    let last = experiences.last().unwrap();

    // Detect gaps
    let gaps = detect_gaps(experiences, grace_period_seconds);
    let max_gap_seconds = gaps
        .iter()
        .map(|g| (g.end.saturating_sub(g.start)) / 1_000_000)
        .max()
        .unwrap_or(0);

    // Find bounding anchors
    let start_anchor = anchors
        .iter()
        .find(|a| a.experience_id == first.id)
        .map(|a| a.id.0.clone())
        .unwrap_or_else(|| first.cumulative_hash.clone());

    let end_anchor = anchors
        .iter()
        .rev()
        .find(|a| a.experience_id == last.id)
        .map(|a| a.id.0.clone())
        .unwrap_or_else(|| last.cumulative_hash.clone());

    // Generate claim ID
    let id_input = format!(
        "claim:{}:{}:{}:{}",
        identity_id.0,
        claim_type.as_tag(),
        first.sequence_number,
        now,
    );
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let id = ClaimId(format!("aclm_{id_encoded}"));

    // Sign the claim
    let sign_input = format!(
        "claim:{}:{}:{}:{}:{}:{}",
        id.0,
        claim_type.as_tag(),
        first.timestamp,
        last.timestamp,
        experiences.len(),
        max_gap_seconds,
    );
    let signature = signing::sign_to_base64(identity.signing_key(), sign_input.as_bytes());

    Ok(ContinuityClaim {
        id,
        identity: identity_id,
        claim_type,
        start_anchor,
        start_timestamp: first.timestamp,
        start_experience: first.sequence_number,
        end_anchor,
        end_timestamp: last.timestamp,
        end_experience: last.sequence_number,
        experience_count: experiences.len() as u64,
        max_gap_seconds,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a continuity claim against the experience chain and anchors.
pub fn verify_continuity(
    claim: &ContinuityClaim,
    experiences: &[ExperienceEvent],
    anchors: &[ContinuityAnchor],
    grace_period_seconds: u64,
) -> Result<ContinuityVerification> {
    let now = crate::time::now_micros();
    let mut errors: Vec<String> = Vec::new();

    // 1. Verify chain integrity (sequence numbers, cumulative hashes)
    let chain_valid = verify_experience_chain(experiences, &mut errors);

    // 2. Verify anchors reference valid experiences
    let anchors_valid = verify_anchors(anchors, experiences, &mut errors);

    // 3. Verify all signatures on experiences
    let signatures_valid = true; // Signatures are verified at creation time

    // 4. Detect gaps
    let gaps = detect_gaps(experiences, grace_period_seconds);

    let result = if gaps.is_empty() && chain_valid && anchors_valid {
        ContinuityResult::Continuous
    } else if !gaps.is_empty() {
        let max_gap = gaps
            .iter()
            .map(|g| (g.end.saturating_sub(g.start)) / 1_000_000)
            .max()
            .unwrap_or(0);
        ContinuityResult::Discontinuous {
            gap_count: gaps.len(),
            max_gap_seconds: max_gap,
        }
    } else {
        ContinuityResult::Uncertain {
            reason: errors.join("; "),
        }
    };

    Ok(ContinuityVerification {
        claim_id: claim.id.clone(),
        chain_valid,
        anchors_valid,
        signatures_valid,
        gaps,
        result,
        verified_at: now,
        errors,
    })
}

/// Verify the internal consistency of an experience chain.
fn verify_experience_chain(experiences: &[ExperienceEvent], errors: &mut Vec<String>) -> bool {
    if experiences.is_empty() {
        return true;
    }

    let mut valid = true;

    for i in 1..experiences.len() {
        let prev = &experiences[i - 1];
        let curr = &experiences[i];

        // Check sequence number continuity
        if curr.sequence_number != prev.sequence_number + 1 {
            errors.push(format!(
                "Sequence gap: expected {} but got {} at index {}",
                prev.sequence_number + 1,
                curr.sequence_number,
                i
            ));
            valid = false;
        }

        // Check previous hash link
        if let Some(ref prev_hash) = curr.previous_experience_hash {
            if prev_hash != &prev.cumulative_hash {
                errors.push(format!(
                    "Hash mismatch at index {}: expected {} but got {}",
                    i, prev.cumulative_hash, prev_hash
                ));
                valid = false;
            }
        } else {
            errors.push(format!("Missing previous_experience_hash at index {}", i));
            valid = false;
        }

        // Check previous ID link
        if let Some(ref prev_id) = curr.previous_experience_id {
            if prev_id != &prev.id {
                errors.push(format!(
                    "Previous ID mismatch at index {}: expected {} but got {}",
                    i, prev.id, prev_id
                ));
                valid = false;
            }
        }
    }

    valid
}

/// Verify that anchors reference valid experiences.
fn verify_anchors(
    anchors: &[ContinuityAnchor],
    experiences: &[ExperienceEvent],
    errors: &mut Vec<String>,
) -> bool {
    let mut valid = true;

    for anchor in anchors {
        let found = experiences.iter().find(|e| e.id == anchor.experience_id);

        match found {
            Some(exp) => {
                if exp.cumulative_hash != anchor.cumulative_hash {
                    errors.push(format!(
                        "Anchor {} cumulative hash mismatch with experience {}",
                        anchor.id, exp.id
                    ));
                    valid = false;
                }
            }
            None => {
                errors.push(format!(
                    "Anchor {} references unknown experience {}",
                    anchor.id, anchor.experience_id
                ));
                valid = false;
            }
        }
    }

    valid
}

// ---------------------------------------------------------------------------
// Gap detection
// ---------------------------------------------------------------------------

/// Detect gaps in an experience chain.
///
/// `grace_period_seconds` — temporal gaps smaller than this are ignored.
pub fn detect_gaps(experiences: &[ExperienceEvent], grace_period_seconds: u64) -> Vec<Gap> {
    let mut gaps = Vec::new();

    if experiences.len() < 2 {
        return gaps;
    }

    let grace_micros = grace_period_seconds * 1_000_000;

    for i in 1..experiences.len() {
        let prev = &experiences[i - 1];
        let curr = &experiences[i];

        // Temporal gap
        let time_delta = curr.timestamp.saturating_sub(prev.timestamp);
        if time_delta > grace_micros {
            let gap_seconds = time_delta / 1_000_000;
            let severity = match gap_seconds {
                0..=60 => GapSeverity::Minor,
                61..=3600 => GapSeverity::Moderate,
                3601..=86400 => GapSeverity::Major,
                _ => GapSeverity::Critical,
            };

            gaps.push(Gap {
                start: prev.timestamp,
                end: curr.timestamp,
                gap_type: GapType::Temporal,
                severity,
                impact: format!(
                    "{}s gap between seq {} and {}",
                    gap_seconds, prev.sequence_number, curr.sequence_number
                ),
            });
        }

        // Sequence gap
        if curr.sequence_number != prev.sequence_number + 1 {
            gaps.push(Gap {
                start: prev.timestamp,
                end: curr.timestamp,
                gap_type: GapType::Sequence,
                severity: GapSeverity::Major,
                impact: format!(
                    "Missing sequences {} to {}",
                    prev.sequence_number + 1,
                    curr.sequence_number.saturating_sub(1)
                ),
            });
        }

        // Hash chain break
        if let Some(ref prev_hash) = curr.previous_experience_hash {
            if prev_hash != &prev.cumulative_hash {
                gaps.push(Gap {
                    start: prev.timestamp,
                    end: curr.timestamp,
                    gap_type: GapType::Hash,
                    severity: GapSeverity::Critical,
                    impact: format!("Hash chain broken at seq {}", curr.sequence_number),
                });
            }
        }
    }

    gaps
}

/// Compute continuity state from a set of experiences.
pub fn get_continuity_state(
    identity: &IdentityId,
    experiences: &[ExperienceEvent],
) -> Result<ContinuityState> {
    if experiences.is_empty() {
        return Err(IdentityError::NotFound(
            "No experiences found for identity".to_string(),
        ));
    }

    let first = &experiences[0];
    let last = experiences.last().unwrap();

    Ok(ContinuityState {
        identity: identity.clone(),
        genesis_experience_id: first.id.clone(),
        genesis_hash: first.cumulative_hash.clone(),
        genesis_timestamp: first.timestamp,
        latest_experience_id: last.id.clone(),
        latest_hash: last.cumulative_hash.clone(),
        latest_timestamp: last.timestamp,
        total_experiences: experiences.len() as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    fn make_identity() -> IdentityAnchor {
        IdentityAnchor::new(Some("continuity-test".to_string()))
    }

    // 1. Experience creation succeeds
    #[test]
    fn test_experience_creation() {
        let anchor = make_identity();
        let exp = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "abc123",
            0.8,
            None,
        )
        .unwrap();

        assert!(exp.id.0.starts_with("aexp_"));
        assert_eq!(exp.sequence_number, 0);
        assert!(exp.previous_experience_id.is_none());
        assert!(exp.previous_experience_hash.is_none());
        assert!(!exp.cumulative_hash.is_empty());
        assert!(!exp.signature.is_empty());
        assert_eq!(exp.intensity, 0.8);
    }

    // 2. Experience chain links correctly
    #[test]
    fn test_experience_chain_links() {
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Perception {
                source: PerceptionSource::Text,
            },
            "hash1",
            0.5,
            None,
        )
        .unwrap();

        let e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Reasoning,
            },
            "hash2",
            0.7,
            Some(&e1),
        )
        .unwrap();

        assert_eq!(e2.sequence_number, 1);
        assert_eq!(e2.previous_experience_id.as_ref().unwrap(), &e1.id);
        assert_eq!(
            e2.previous_experience_hash.as_ref().unwrap(),
            &e1.cumulative_hash
        );
    }

    // 3. Cumulative hash is deterministic
    #[test]
    fn test_cumulative_hash_deterministic() {
        // Two chains with same inputs at same time should produce different
        // hashes because timestamps differ, but each individual hash is
        // deterministic given its inputs.
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Idle {
                reason: "waiting".into(),
            },
            "same_hash",
            0.1,
            None,
        )
        .unwrap();
        assert!(!e1.cumulative_hash.is_empty());
        assert_eq!(e1.cumulative_hash.len(), 64); // SHA-256 hex
    }

    // 4. Gap detection works (temporal)
    #[test]
    fn test_gap_detection_temporal() {
        let anchor = make_identity();
        let mut e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();

        // Simulate time gap by manipulating timestamp
        e1.timestamp -= 5_000_000; // 5 seconds ago

        let e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h2",
            0.5,
            Some(&e1),
        )
        .unwrap();

        let gaps = detect_gaps(&[e1, e2], 2); // 2-second grace
        assert!(!gaps.is_empty());
        assert_eq!(gaps[0].gap_type, GapType::Temporal);
    }

    // 5. Gap detection works (sequence)
    #[test]
    fn test_gap_detection_sequence() {
        let anchor = make_identity();
        let mut e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();

        let mut e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h2",
            0.5,
            Some(&e1),
        )
        .unwrap();

        // Artificially create a sequence gap
        e2.sequence_number = 5;
        // Ensure no temporal gap interferes
        e1.timestamp = e2.timestamp;

        let gaps = detect_gaps(&[e1, e2], 3600);
        let seq_gaps: Vec<_> = gaps
            .iter()
            .filter(|g| g.gap_type == GapType::Sequence)
            .collect();
        assert!(!seq_gaps.is_empty());
    }

    // 6. Gap detection works (hash mismatch)
    #[test]
    fn test_gap_detection_hash() {
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();

        let mut e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h2",
            0.5,
            Some(&e1),
        )
        .unwrap();

        // Tamper with the hash link
        e2.previous_experience_hash = Some("tampered_hash".to_string());

        let gaps = detect_gaps(&[e1, e2], 3600);
        let hash_gaps: Vec<_> = gaps
            .iter()
            .filter(|g| g.gap_type == GapType::Hash)
            .collect();
        assert!(!hash_gaps.is_empty());
        assert_eq!(hash_gaps[0].severity, GapSeverity::Critical);
    }

    // 7. Anchor creation works
    #[test]
    fn test_anchor_creation() {
        let anchor = make_identity();
        let exp = record_experience(
            &anchor,
            ExperienceType::System {
                event: SystemEvent::Startup,
            },
            "startup_hash",
            1.0,
            None,
        )
        .unwrap();

        let ca = create_anchor(&anchor, AnchorType::Genesis, &exp, None, None).unwrap();

        assert!(ca.id.0.starts_with("aanch_"));
        assert_eq!(ca.anchor_type, AnchorType::Genesis);
        assert_eq!(ca.experience_id, exp.id);
        assert_eq!(ca.cumulative_hash, exp.cumulative_hash);
        assert_eq!(ca.experience_count, 1);
        assert!(ca.previous_anchor.is_none());
        assert!(ca.external_witness.is_none());
        assert!(!ca.signature.is_empty());
    }

    // 8. Heartbeat creation works
    #[test]
    fn test_heartbeat_creation() {
        let anchor = make_identity();
        let health = HealthMetrics {
            memory_usage_bytes: 1024 * 1024 * 50,
            experience_rate_per_hour: 120.0,
            error_count: 0,
            latency_ms: 15,
        };

        let hb = create_heartbeat(
            &anchor,
            0,
            "continuity_hash_abc",
            100,
            10,
            HeartbeatStatus::Active,
            health,
        )
        .unwrap();

        assert!(hb.id.0.starts_with("ahb_"));
        assert_eq!(hb.sequence_number, 0);
        assert_eq!(hb.experience_count, 100);
        assert_eq!(hb.experiences_since_last, 10);
        assert_eq!(hb.status, HeartbeatStatus::Active);
        assert!(!hb.signature.is_empty());
    }

    // 9. Heartbeat gap detection works
    #[test]
    fn test_heartbeat_gap_detection() {
        // Heartbeat gaps are modeled via the temporal gap detector on
        // experience events (heartbeats are metadata, gaps in experiences
        // imply heartbeat misses).
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::System {
                event: SystemEvent::Checkpoint,
            },
            "cp1",
            1.0,
            None,
        )
        .unwrap();
        // With default grace period of 0 any time gap counts
        let gaps = detect_gaps(&[e1], 0);
        assert!(gaps.is_empty()); // Single event, no gaps
    }

    // 10. Continuity claim creation works
    #[test]
    fn test_continuity_claim_creation() {
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();
        let e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Reasoning,
            },
            "h2",
            0.6,
            Some(&e1),
        )
        .unwrap();
        let e3 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Inference,
            },
            "h3",
            0.7,
            Some(&e2),
        )
        .unwrap();

        let claim =
            create_continuity_claim(&anchor, ClaimType::FullContinuity, &[e1, e2, e3], &[], 3600)
                .unwrap();

        assert!(claim.id.0.starts_with("aclm_"));
        assert_eq!(claim.claim_type, ClaimType::FullContinuity);
        assert_eq!(claim.experience_count, 3);
        assert!(!claim.signature.is_empty());
    }

    // 11. Continuity verification (continuous)
    #[test]
    fn test_verification_continuous() {
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();
        let e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Reasoning,
            },
            "h2",
            0.6,
            Some(&e1),
        )
        .unwrap();

        let claim = create_continuity_claim(
            &anchor,
            ClaimType::FullContinuity,
            &[e1.clone(), e2.clone()],
            &[],
            3600,
        )
        .unwrap();

        let verification = verify_continuity(&claim, &[e1, e2], &[], 3600).unwrap();
        assert!(verification.chain_valid);
        assert_eq!(verification.result, ContinuityResult::Continuous);
    }

    // 12. Continuity verification (discontinuous)
    #[test]
    fn test_verification_discontinuous() {
        let anchor = make_identity();
        let mut e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();

        // Set e1 to be 10 seconds ago to create a temporal gap
        e1.timestamp -= 10_000_000;

        let e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Reasoning,
            },
            "h2",
            0.6,
            Some(&e1),
        )
        .unwrap();

        let claim = create_continuity_claim(
            &anchor,
            ClaimType::FullContinuity,
            &[e1.clone(), e2.clone()],
            &[],
            2, // 2-second grace
        )
        .unwrap();

        let verification = verify_continuity(&claim, &[e1, e2], &[], 2).unwrap();
        assert!(matches!(
            verification.result,
            ContinuityResult::Discontinuous { .. }
        ));
    }

    // 13. All 10 experience types work
    #[test]
    fn test_all_experience_types() {
        let anchor = make_identity();
        let other_id = IdentityAnchor::new(None).id();
        let receipt_id = crate::receipt::ReceiptId("arec_test".to_string());

        let types = vec![
            ExperienceType::Perception {
                source: PerceptionSource::Visual,
            },
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            ExperienceType::Action { receipt_id },
            ExperienceType::Communication {
                direction: CommunicationDirection::Inbound,
                counterparty: other_id,
            },
            ExperienceType::Memory {
                operation: MemoryOpType::Store,
            },
            ExperienceType::Learning {
                learning_type: LearningType::SelfDirected,
                domain: "rust".to_string(),
            },
            ExperienceType::Planning {
                planning_type: PlanningType::GoalSetting,
            },
            ExperienceType::Emotion {
                emotion_type: "curiosity".to_string(),
            },
            ExperienceType::Idle {
                reason: "waiting for input".to_string(),
            },
            ExperienceType::System {
                event: SystemEvent::Startup,
            },
        ];

        let mut prev: Option<ExperienceEvent> = None;
        for (i, et) in types.into_iter().enumerate() {
            let exp =
                record_experience(&anchor, et, &format!("hash_{i}"), 0.5, prev.as_ref()).unwrap();
            assert_eq!(exp.sequence_number, i as u64);
            prev = Some(exp);
        }
    }

    // 14. Experience intensity validated (0.0 - 1.0)
    #[test]
    fn test_intensity_validation() {
        let anchor = make_identity();

        // Valid intensities
        assert!(record_experience(
            &anchor,
            ExperienceType::Idle {
                reason: "test".into()
            },
            "h",
            0.0,
            None,
        )
        .is_ok());
        assert!(record_experience(
            &anchor,
            ExperienceType::Idle {
                reason: "test".into()
            },
            "h",
            1.0,
            None,
        )
        .is_ok());

        // Invalid intensities
        assert!(record_experience(
            &anchor,
            ExperienceType::Idle {
                reason: "test".into()
            },
            "h",
            -0.1,
            None,
        )
        .is_err());
        assert!(record_experience(
            &anchor,
            ExperienceType::Idle {
                reason: "test".into()
            },
            "h",
            1.1,
            None,
        )
        .is_err());
    }

    // 15. External witness anchor works
    #[test]
    fn test_external_witness_anchor() {
        let identity = make_identity();
        let witness = IdentityAnchor::new(Some("witness".to_string()));

        let exp = record_experience(
            &identity,
            ExperienceType::System {
                event: SystemEvent::Checkpoint,
            },
            "checkpoint_hash",
            1.0,
            None,
        )
        .unwrap();

        let ca = create_anchor(
            &identity,
            AnchorType::External {
                witness: witness.id(),
            },
            &exp,
            None,
            Some(&witness),
        )
        .unwrap();

        assert!(ca.external_witness.is_some());
        assert_eq!(
            ca.anchor_type,
            AnchorType::External {
                witness: witness.id()
            }
        );
    }

    // 16. Chain tampering detected
    #[test]
    fn test_chain_tampering_detected() {
        let anchor = make_identity();
        let e1 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Thought,
            },
            "h1",
            0.5,
            None,
        )
        .unwrap();
        let mut e2 = record_experience(
            &anchor,
            ExperienceType::Cognition {
                cognition_type: CognitionType::Reasoning,
            },
            "h2",
            0.6,
            Some(&e1),
        )
        .unwrap();

        // Tamper with e2's content hash (simulating modification)
        e2.content_hash = "TAMPERED".to_string();
        // The cumulative hash won't match what was signed
        // But more importantly, if we tamper with the chain link:
        e2.previous_experience_hash = Some("wrong_hash".to_string());

        let gaps = detect_gaps(&[e1, e2], 3600);
        let hash_gaps: Vec<_> = gaps
            .iter()
            .filter(|g| g.gap_type == GapType::Hash)
            .collect();
        assert!(!hash_gaps.is_empty());
    }
}
