//! AgenticIdentity — Cryptographic identity anchor for AI agents.
//!
//! Provides persistent identity, signed action receipts, revocable
//! trust relationships, temporal continuity, identity inheritance,
//! competence proofs, and negative capability proofs
//! for AI agents operating via MCP.

pub mod competence;
pub mod continuity;
pub mod contracts;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod index;
pub mod negative;
pub mod query;
pub mod receipt;
pub mod spawn;
pub mod storage;
pub mod time;
pub mod trust;

// Re-export primary types
pub use error::{IdentityError, Result};
pub use identity::{IdentityAnchor, IdentityDocument, IdentityId};
pub use receipt::{ActionContent, ActionReceipt, ActionType, ReceiptId, ReceiptVerification};
pub use trust::{Capability, TrustConstraints, TrustGrant, TrustId, TrustVerification};

// Re-export continuity types
pub use continuity::{
    ContinuityAnchor, ContinuityClaim, ContinuityResult, ContinuityState, ContinuityVerification,
    ExperienceEvent, ExperienceId, ExperienceType, Gap, GapType,
};

// Re-export spawn types
pub use spawn::{
    Lineage, LineageVerification, SpawnConstraints, SpawnId, SpawnInfo, SpawnLifetime, SpawnRecord,
    SpawnType,
};

// Re-export competence types
pub use competence::{
    AttemptId, AttemptOutcome, CompetenceAttempt, CompetenceClaim, CompetenceDomain,
    CompetenceProof, CompetenceRecord, CompetenceRequirement, CompetenceVerification, ProofId,
};

// Re-export negative types
pub use negative::{
    DeclarationId, ImpossibilityReason, NegativeCapabilityProof, NegativeDeclaration,
    NegativeEvidence, NegativeProofId, NegativeVerification,
};
