//! Competence proof — cryptographic proofs of demonstrated ability.
//!
//! The competence module provides:
//! - Competence attempt recording (success, failure, partial)
//! - Aggregated competence records per domain
//! - Success rate calculation and streak tracking
//! - Competence proof generation with evidence
//! - Proof verification and expiration
//! - Competence requirements for trust grants

pub mod engine;
pub mod types;

pub use types::{
    AttemptId, AttemptOutcome, CompetenceAttempt, CompetenceClaim, CompetenceDomain,
    CompetenceProof, CompetenceRecord, CompetenceRequirement, CompetenceVerification, ProofId,
};

pub use engine::{
    check_competence, generate_proof, get_competence, list_competences, record_attempt,
    verify_proof,
};
