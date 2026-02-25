//! Data structures for negative capability proofs.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::receipt::witness::WitnessSignature;
use crate::spawn::SpawnId;

// ---------------------------------------------------------------------------
// Impossibility reason
// ---------------------------------------------------------------------------

/// Reason why a capability is structurally impossible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImpossibilityReason {
    /// Not in identity's capabilities ceiling
    NotInCeiling,

    /// No ancestor in lineage has this capability
    NotInLineage,

    /// Explicitly excluded at spawn time
    SpawnExclusion { spawn_id: SpawnId },

    /// Capability structurally doesn't exist
    CapabilityNonexistent,

    /// Voluntarily declared impossible
    VoluntaryDeclaration { declaration_id: DeclarationId },
}

// ---------------------------------------------------------------------------
// Negative capability proof
// ---------------------------------------------------------------------------

/// Unique identifier for a negative proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NegativeProofId(pub String);

impl std::fmt::Display for NegativeProofId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Negative capability proof — cryptographic evidence that an agent CANNOT do something.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeCapabilityProof {
    pub proof_id: NegativeProofId,
    pub identity: IdentityId,
    pub cannot_do: String, // CapabilityUri
    pub reason: ImpossibilityReason,
    pub evidence: NegativeEvidence,
    pub generated_at: u64,
    pub valid_until: Option<u64>,
    pub proof_hash: String,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Negative evidence
// ---------------------------------------------------------------------------

/// Evidence supporting the impossibility claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NegativeEvidence {
    /// Ceiling proof — the ceiling doesn't include the capability
    CeilingExclusion {
        ceiling: Vec<String>,
        ceiling_hash: String,
    },

    /// Lineage proof — no ancestor has the capability
    LineageExclusion {
        lineage: Vec<IdentityId>,
        ancestor_ceilings: Vec<(IdentityId, Vec<String>)>,
        lineage_hash: String,
    },

    /// Spawn exclusion — spawn record explicitly excludes
    SpawnExclusion {
        spawn_id: SpawnId,
        spawn_record_hash: String,
        exclusions: Vec<String>,
    },

    /// Voluntary declaration as evidence
    Declaration { declaration_id: DeclarationId },
}

// ---------------------------------------------------------------------------
// Negative declaration
// ---------------------------------------------------------------------------

/// Unique identifier for a negative declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeclarationId(pub String);

impl std::fmt::Display for DeclarationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Voluntary negative capability declaration — self-imposed restriction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeDeclaration {
    pub declaration_id: DeclarationId,
    pub identity: IdentityId,
    pub cannot_do: Vec<String>, // CapabilityUris
    pub reason: String,
    pub declared_at: u64,
    pub permanent: bool,
    pub witnesses: Vec<WitnessSignature>,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Negative verification
// ---------------------------------------------------------------------------

/// Verification result for a negative proof.
#[derive(Debug, Clone)]
pub struct NegativeVerification {
    pub proof_id: NegativeProofId,
    pub identity: IdentityId,
    pub capability: String,
    pub reason_valid: bool,
    pub evidence_valid: bool,
    pub signature_valid: bool,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}
