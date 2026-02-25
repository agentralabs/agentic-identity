//! Negative capability — proofs of structural impossibility.
//!
//! The negative module provides:
//! - Proofs that an agent CANNOT do something (by structure, not policy)
//! - Ceiling-based impossibility (not in capabilities ceiling)
//! - Lineage-based impossibility (no ancestor has capability)
//! - Spawn exclusion proofs (explicitly excluded at spawn)
//! - Voluntary negative declarations (self-imposed restrictions)
//! - Verification of negative proofs

pub mod engine;
pub mod types;

pub use types::{
    DeclarationId, ImpossibilityReason, NegativeCapabilityProof, NegativeDeclaration,
    NegativeEvidence, NegativeProofId, NegativeVerification,
};

pub use engine::{
    declare_cannot, get_impossibilities, is_impossible, list_declarations, prove_cannot,
    verify_negative_proof,
};
