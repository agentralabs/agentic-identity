//! Trust web — revocable, scoped trust relationships between identities.
//!
//! The trust module provides:
//! - Capability URI parsing with wildcard matching
//! - Time-bounded, use-limited trust constraints
//! - Signed trust grants between identities
//! - Revocation mechanism
//! - Trust chain verification for delegation
//! - Delegation depth limits

pub mod capability;
pub mod chain;
pub mod constraint;
pub mod grant;
pub mod revocation;
pub mod verify;

pub use capability::{capabilities_cover, capabilities_cover_all, Capability};
pub use chain::{validate_delegation, verify_trust_chain};
pub use constraint::TrustConstraints;
pub use grant::{TrustGrant, TrustGrantBuilder, TrustId};
pub use revocation::{Revocation, RevocationChannel, RevocationConfig, RevocationReason};
pub use verify::{is_grant_valid, verify_trust_grant, TrustVerification};
