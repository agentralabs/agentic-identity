//! Identity inheritance — spawning child identities with bounded authority.
//!
//! The spawn module provides:
//! - Child identity creation with authority bounding
//! - Five spawn types (Worker, Delegate, Clone, Specialist, Custom)
//! - Lineage tracking and verification
//! - Spawn lifetime management
//! - Authority decay and depth limits
//! - Termination with optional cascade

pub mod engine;
pub mod types;

pub use types::{
    Lineage, LineageVerification, SpawnConstraints, SpawnId, SpawnInfo, SpawnLifetime, SpawnRecord,
    SpawnType,
};

pub use engine::{
    can_spawn, get_ancestors, get_children, get_descendants, get_effective_authority, spawn_child,
    terminate_spawn, verify_lineage,
};
