//! Data structures for temporal continuity.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::receipt::ReceiptId;

// ---------------------------------------------------------------------------
// Experience Event
// ---------------------------------------------------------------------------

/// Unique identifier for an experience event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExperienceId(pub String);

impl std::fmt::Display for ExperienceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An experience event in the continuity chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperienceEvent {
    pub id: ExperienceId,
    pub identity: IdentityId,
    pub event_type: ExperienceType,
    pub timestamp: u64,
    pub duration: Option<u64>,
    pub content_hash: String,
    /// Intensity of the experience (0.0 – 1.0).
    pub intensity: f32,

    // Chain links
    pub previous_experience_id: Option<ExperienceId>,
    pub previous_experience_hash: Option<String>,
    pub sequence_number: u64,
    pub cumulative_hash: String,

    pub signature: String,
}

// ---------------------------------------------------------------------------
// Experience types
// ---------------------------------------------------------------------------

/// Type of experience event (10 variants).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExperienceType {
    Perception {
        source: PerceptionSource,
    },
    Cognition {
        cognition_type: CognitionType,
    },
    Action {
        receipt_id: ReceiptId,
    },
    Communication {
        direction: CommunicationDirection,
        counterparty: IdentityId,
    },
    Memory {
        operation: MemoryOpType,
    },
    Learning {
        learning_type: LearningType,
        domain: String,
    },
    Planning {
        planning_type: PlanningType,
    },
    Emotion {
        emotion_type: String,
    },
    Idle {
        reason: String,
    },
    System {
        event: SystemEvent,
    },
}

impl ExperienceType {
    /// Return a stable string tag for hashing.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Perception { .. } => "perception",
            Self::Cognition { .. } => "cognition",
            Self::Action { .. } => "action",
            Self::Communication { .. } => "communication",
            Self::Memory { .. } => "memory",
            Self::Learning { .. } => "learning",
            Self::Planning { .. } => "planning",
            Self::Emotion { .. } => "emotion",
            Self::Idle { .. } => "idle",
            Self::System { .. } => "system",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerceptionSource {
    Visual,
    Auditory,
    Text,
    Sensor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CognitionType {
    Thought,
    Reasoning,
    Inference,
    Recall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommunicationDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryOpType {
    Store,
    Retrieve,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LearningType {
    Supervised,
    Unsupervised,
    Reinforcement,
    SelfDirected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanningType {
    GoalSetting,
    PlanCreation,
    PlanUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemEvent {
    Startup,
    Shutdown,
    Checkpoint,
    Error { message: String },
}

// ---------------------------------------------------------------------------
// Continuity State
// ---------------------------------------------------------------------------

/// Summary of an identity's continuity chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityState {
    pub identity: IdentityId,
    pub genesis_experience_id: ExperienceId,
    pub genesis_hash: String,
    pub genesis_timestamp: u64,
    pub latest_experience_id: ExperienceId,
    pub latest_hash: String,
    pub latest_timestamp: u64,
    pub total_experiences: u64,
}

// ---------------------------------------------------------------------------
// Continuity Anchor
// ---------------------------------------------------------------------------

/// Unique identifier for a continuity anchor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnchorId(pub String);

impl std::fmt::Display for AnchorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A checkpoint in the continuity chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityAnchor {
    pub id: AnchorId,
    pub identity: IdentityId,
    pub anchor_type: AnchorType,
    pub experience_id: ExperienceId,
    pub cumulative_hash: String,
    pub experience_count: u64,
    pub timestamp: u64,
    pub previous_anchor: Option<AnchorId>,
    pub external_witness: Option<String>,
    pub signature: String,
}

/// Type of continuity anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorType {
    Genesis,
    TimeBased { interval_hours: u32 },
    ExperienceCount { interval: u64 },
    Manual,
    External { witness: IdentityId },
}

impl AnchorType {
    /// Return a stable string tag.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Genesis => "genesis",
            Self::TimeBased { .. } => "time_based",
            Self::ExperienceCount { .. } => "experience_count",
            Self::Manual => "manual",
            Self::External { .. } => "external",
        }
    }
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

/// Unique identifier for a heartbeat record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HeartbeatId(pub String);

impl std::fmt::Display for HeartbeatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Periodic heartbeat record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub id: HeartbeatId,
    pub identity: IdentityId,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub continuity_hash: String,
    pub experience_count: u64,
    pub experiences_since_last: u64,
    pub status: HeartbeatStatus,
    pub health: HealthMetrics,
    pub signature: String,
}

/// Heartbeat status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeartbeatStatus {
    Active,
    Idle,
    Suspended,
    Degraded,
}

impl HeartbeatStatus {
    /// Return a stable string tag.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Idle => "idle",
            Self::Suspended => "suspended",
            Self::Degraded => "degraded",
        }
    }
}

/// Health metrics included in a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub memory_usage_bytes: u64,
    pub experience_rate_per_hour: f64,
    pub error_count: u64,
    pub latency_ms: u64,
}

// ---------------------------------------------------------------------------
// Continuity Claim
// ---------------------------------------------------------------------------

/// Unique identifier for a continuity claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimId(pub String);

impl std::fmt::Display for ClaimId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A claim asserting continuity over a range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityClaim {
    pub id: ClaimId,
    pub identity: IdentityId,
    pub claim_type: ClaimType,
    pub start_anchor: String,
    pub start_timestamp: u64,
    pub start_experience: u64,
    pub end_anchor: String,
    pub end_timestamp: u64,
    pub end_experience: u64,
    pub experience_count: u64,
    pub max_gap_seconds: u64,
    pub signature: String,
}

/// Type of continuity claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimType {
    FullContinuity,
    RangeContinuity,
    SinceContinuity,
}

impl ClaimType {
    /// Return a stable string tag.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::FullContinuity => "full",
            Self::RangeContinuity => "range",
            Self::SinceContinuity => "since",
        }
    }
}

// ---------------------------------------------------------------------------
// Gap
// ---------------------------------------------------------------------------

/// A gap detected in the continuity chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
    pub gap_type: GapType,
    pub severity: GapSeverity,
    pub impact: String,
}

/// Type of continuity gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapType {
    Temporal,
    Sequence,
    Hash,
    Heartbeat,
}

/// Severity of a gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapSeverity {
    Minor,
    Moderate,
    Major,
    Critical,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Result of verifying a continuity claim.
#[derive(Debug, Clone)]
pub struct ContinuityVerification {
    pub claim_id: ClaimId,
    pub chain_valid: bool,
    pub anchors_valid: bool,
    pub signatures_valid: bool,
    pub gaps: Vec<Gap>,
    pub result: ContinuityResult,
    pub verified_at: u64,
    pub errors: Vec<String>,
}

impl ContinuityVerification {
    /// Whether the overall verification passed.
    pub fn is_valid(&self) -> bool {
        self.chain_valid && self.anchors_valid && self.signatures_valid && self.gaps.is_empty()
    }
}

/// Overall continuity result.
#[derive(Debug, Clone, PartialEq)]
pub enum ContinuityResult {
    Continuous,
    Discontinuous {
        gap_count: usize,
        max_gap_seconds: u64,
    },
    Uncertain {
        reason: String,
    },
}
