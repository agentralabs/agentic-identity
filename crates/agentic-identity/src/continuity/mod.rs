//! Temporal continuity — experience chains, anchors, heartbeats, and proofs.
//!
//! The continuity module provides:
//! - Experience event recording and chaining
//! - Cumulative hash computation for tamper detection
//! - Continuity anchors (time-based, count-based, manual, external)
//! - Heartbeat monitoring
//! - Continuity claims and verification
//! - Gap detection (temporal, sequence, hash, heartbeat)

pub mod engine;
pub mod types;

pub use types::{
    AnchorId, AnchorType, ClaimId, ClaimType, CognitionType, CommunicationDirection,
    ContinuityAnchor, ContinuityClaim, ContinuityResult, ContinuityState, ContinuityVerification,
    ExperienceEvent, ExperienceId, ExperienceType, Gap, GapSeverity, GapType, HealthMetrics,
    HeartbeatId, HeartbeatRecord, HeartbeatStatus, LearningType, MemoryOpType, PerceptionSource,
    PlanningType, SystemEvent,
};

pub use engine::{
    create_anchor, create_continuity_claim, create_heartbeat, detect_gaps, get_continuity_state,
    record_experience, verify_continuity,
};
