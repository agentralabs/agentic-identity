//! Scale test: 5K continuity experiences in chain.
//!
//! Validates that experience recording and cumulative hashing scale.

use agentic_identity::continuity;
use agentic_identity::IdentityAnchor;

#[test]
fn stress_5k_continuity_experiences() {
    let anchor = IdentityAnchor::new(Some("continuity-scale".to_string()));
    let mut experiences = Vec::with_capacity(5_000);

    for i in 0..5_000 {
        let event_type = continuity::ExperienceType::Cognition {
            cognition_type: continuity::CognitionType::Thought,
        };
        let exp = continuity::record_experience(
            &anchor,
            event_type,
            &format!("content_hash_{i}"),
            0.5,
            if i > 0 {
                Some(&experiences[i - 1])
            } else {
                None
            },
        )
        .unwrap();
        experiences.push(exp);
    }

    assert_eq!(experiences.len(), 5_000);
    // Verify chain — each experience should have increasing sequence numbers
    for (i, exp) in experiences.iter().enumerate() {
        assert_eq!(exp.sequence_number, i as u64);
    }
}

#[test]
fn stress_continuity_chain_hashes_unique() {
    let anchor = IdentityAnchor::new(Some("hash-unique".to_string()));
    let mut experiences = Vec::with_capacity(1_000);
    let mut seen_hashes = std::collections::HashSet::new();

    for i in 0..1_000 {
        let exp = continuity::record_experience(
            &anchor,
            continuity::ExperienceType::Cognition {
                cognition_type: continuity::CognitionType::Thought,
            },
            &format!("hash_{i}"),
            0.5,
            if i > 0 {
                Some(&experiences[i - 1])
            } else {
                None
            },
        )
        .unwrap();
        assert!(
            seen_hashes.insert(exp.cumulative_hash.clone()),
            "Duplicate cumulative hash at experience {i}"
        );
        experiences.push(exp);
    }
}

#[test]
fn stress_continuity_mixed_experience_types() {
    let anchor = IdentityAnchor::new(Some("mixed-types".to_string()));
    let types = [
        continuity::ExperienceType::Cognition {
            cognition_type: continuity::CognitionType::Thought,
        },
        continuity::ExperienceType::Perception {
            source: continuity::PerceptionSource::Text,
        },
        continuity::ExperienceType::Idle {
            reason: "waiting".into(),
        },
        continuity::ExperienceType::System {
            event: continuity::SystemEvent::Checkpoint,
        },
        continuity::ExperienceType::Memory {
            operation: continuity::MemoryOpType::Store,
        },
    ];

    let mut experiences = Vec::new();
    for i in 0..2_500 {
        let event_type = types[i % types.len()].clone();
        let exp = continuity::record_experience(
            &anchor,
            event_type,
            &format!("hash_{i}"),
            0.5,
            if i > 0 {
                Some(&experiences[i - 1])
            } else {
                None
            },
        )
        .unwrap();
        experiences.push(exp);
    }
    assert_eq!(experiences.len(), 2_500);
}
