//! Data structures for competence proofs.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::receipt::ReceiptId;

// ---------------------------------------------------------------------------
// Competence domain
// ---------------------------------------------------------------------------

/// A competence domain identifier (e.g., "deploy", "code_review").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompetenceDomain(pub String);

impl CompetenceDomain {
    pub const DEPLOY: &'static str = "deploy";
    pub const CODE_REVIEW: &'static str = "code_review";
    pub const DATA_ANALYSIS: &'static str = "data_analysis";
    pub const COMMUNICATION: &'static str = "communication";
    pub const PLANNING: &'static str = "planning";
    pub const MEMORY_MANAGEMENT: &'static str = "memory_management";

    /// Create a new competence domain.
    pub fn new(domain: impl Into<String>) -> Self {
        Self(domain.into())
    }
}

impl std::fmt::Display for CompetenceDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Attempt outcome
// ---------------------------------------------------------------------------

/// Outcome of a competence attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttemptOutcome {
    Success,
    Failure { reason: String },
    Partial { score: f32 }, // 0.0 - 1.0
}

// ---------------------------------------------------------------------------
// Competence attempt
// ---------------------------------------------------------------------------

/// Unique identifier for an attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub String);

impl std::fmt::Display for AttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Record of a single competence attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceAttempt {
    pub attempt_id: AttemptId,
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub outcome: AttemptOutcome,
    pub timestamp: u64,
    pub receipt_id: ReceiptId,
    pub context: Option<String>,
    pub validator: Option<IdentityId>,
    pub validator_signature: Option<String>,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Competence record (aggregate)
// ---------------------------------------------------------------------------

/// Aggregated competence record for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceRecord {
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub total_attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub partial_sum: f32,
    pub partial_count: u64,
    pub success_rate: f32,
    pub first_attempt: u64,
    pub last_attempt: u64,
    pub streak_current: i32,
    pub streak_best: u32,
    pub evidence: Vec<AttemptId>,
}

impl CompetenceRecord {
    /// Create an empty competence record.
    pub fn new(identity: IdentityId, domain: CompetenceDomain) -> Self {
        Self {
            identity,
            domain,
            total_attempts: 0,
            successes: 0,
            failures: 0,
            partial_sum: 0.0,
            partial_count: 0,
            success_rate: 0.0,
            first_attempt: 0,
            last_attempt: 0,
            streak_current: 0,
            streak_best: 0,
            evidence: Vec::new(),
        }
    }

    /// Record an attempt and update aggregated stats.
    pub fn record_attempt(&mut self, attempt: &CompetenceAttempt) {
        self.total_attempts += 1;
        self.last_attempt = attempt.timestamp;
        if self.first_attempt == 0 {
            self.first_attempt = attempt.timestamp;
        }

        match &attempt.outcome {
            AttemptOutcome::Success => {
                self.successes += 1;
                if self.streak_current >= 0 {
                    self.streak_current += 1;
                } else {
                    self.streak_current = 1;
                }
            }
            AttemptOutcome::Failure { .. } => {
                self.failures += 1;
                if self.streak_current <= 0 {
                    self.streak_current -= 1;
                } else {
                    self.streak_current = -1;
                }
            }
            AttemptOutcome::Partial { score } => {
                self.partial_sum += score;
                self.partial_count += 1;
                if *score >= 0.5 {
                    if self.streak_current >= 0 {
                        self.streak_current += 1;
                    } else {
                        self.streak_current = 1;
                    }
                } else if self.streak_current <= 0 {
                    self.streak_current -= 1;
                } else {
                    self.streak_current = -1;
                }
            }
        }

        if self.streak_current > 0 && self.streak_current as u32 > self.streak_best {
            self.streak_best = self.streak_current as u32;
        }

        // Recalculate success rate
        let effective_successes = self.successes as f32 + self.partial_sum;
        self.success_rate = effective_successes / self.total_attempts as f32;

        // Keep recent evidence (last 100)
        self.evidence.push(attempt.attempt_id.clone());
        if self.evidence.len() > 100 {
            self.evidence.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Competence proof
// ---------------------------------------------------------------------------

/// Unique identifier for a competence proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub String);

impl std::fmt::Display for ProofId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What the proof claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceClaim {
    pub min_attempts: u64,
    pub min_success_rate: f32,
    pub min_streak: Option<u32>,
    pub recency_window: Option<u64>,
    pub actual_attempts: u64,
    pub actual_success_rate: f32,
    pub actual_streak: i32,
}

/// Competence proof — cryptographic claim of ability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceProof {
    pub proof_id: ProofId,
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub claim: CompetenceClaim,
    pub evidence_sample: Vec<AttemptId>,
    pub evidence_count: u64,
    pub generated_at: u64,
    pub valid_until: Option<u64>,
    pub proof_hash: String,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Competence requirement
// ---------------------------------------------------------------------------

/// Competence requirement in trust grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceRequirement {
    pub domain: CompetenceDomain,
    pub min_attempts: u64,
    pub min_success_rate: f32,
    pub min_streak: Option<u32>,
    pub max_age_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Competence verification
// ---------------------------------------------------------------------------

/// Competence verification result.
#[derive(Debug, Clone)]
pub struct CompetenceVerification {
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub meets_attempts: bool,
    pub meets_rate: bool,
    pub meets_streak: bool,
    pub meets_recency: bool,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}
