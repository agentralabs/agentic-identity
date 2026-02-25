//! Identity management — creation, derivation, rotation.
//!
//! The identity module provides the core `IdentityAnchor` type
//! which is the root of an agent's cryptographic identity.

pub mod anchor;

pub use anchor::{
    Attestation, AttestationClaim, IdentityAnchor, IdentityDocument, IdentityId, KeyRotation,
    PublicKeyRotation, RotationReason,
};
