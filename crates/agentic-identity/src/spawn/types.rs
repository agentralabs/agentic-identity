//! Data structures for identity inheritance (spawn).

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::receipt::ReceiptId;
use crate::trust::Capability;

// ---------------------------------------------------------------------------
// Spawn Record
// ---------------------------------------------------------------------------

/// Unique identifier for a spawn record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpawnId(pub String);

impl std::fmt::Display for SpawnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Record of a child identity being spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnRecord {
    pub id: SpawnId,
    pub parent_id: IdentityId,
    pub parent_key: String,
    pub child_id: IdentityId,
    pub child_key: String,
    pub spawn_timestamp: u64,
    pub spawn_type: SpawnType,
    pub spawn_purpose: String,
    pub spawn_receipt_id: ReceiptId,
    pub authority_granted: Vec<Capability>,
    pub authority_ceiling: Vec<Capability>,
    pub lifetime: SpawnLifetime,
    pub constraints: SpawnConstraints,
    pub parent_signature: String,
    pub child_acknowledgment: Option<String>,
    pub terminated: bool,
    pub terminated_at: Option<u64>,
    pub termination_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Spawn Type
// ---------------------------------------------------------------------------

/// Type of spawned identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpawnType {
    /// Temporary, task-specific worker.
    Worker,
    /// Acts on behalf of parent with delegated authority.
    Delegate,
    /// Full copy of parent's authority (within ceiling).
    Clone,
    /// Subset of capabilities for a specific domain.
    Specialist,
    /// Custom spawn type.
    Custom(String),
}

impl SpawnType {
    /// Return a stable string tag.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Worker => "worker",
            Self::Delegate => "delegate",
            Self::Clone => "clone",
            Self::Specialist => "specialist",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn Lifetime
// ---------------------------------------------------------------------------

/// Lifetime of a spawned identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpawnLifetime {
    /// No expiration.
    Indefinite,
    /// Expires after a duration (seconds).
    Duration { seconds: u64 },
    /// Expires at a specific timestamp (microseconds since epoch).
    Until { timestamp: u64 },
    /// Expires when a specific task is completed.
    TaskCompletion { task_id: String },
    /// Expires when the parent is terminated.
    ParentTermination,
}

impl SpawnLifetime {
    /// Return a stable string tag.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Indefinite => "indefinite",
            Self::Duration { .. } => "duration",
            Self::Until { .. } => "until",
            Self::TaskCompletion { .. } => "task_completion",
            Self::ParentTermination => "parent_termination",
        }
    }

    /// Check if the lifetime has expired.
    pub fn is_expired(&self, spawn_timestamp: u64) -> bool {
        let now = crate::time::now_micros();
        match self {
            Self::Indefinite => false,
            Self::Duration { seconds } => now > spawn_timestamp + (seconds * 1_000_000),
            Self::Until { timestamp } => now > *timestamp,
            Self::TaskCompletion { .. } => false, // Cannot determine from timestamp alone
            Self::ParentTermination => false,     // Cannot determine without parent state
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn Constraints
// ---------------------------------------------------------------------------

/// Constraints on a spawned identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnConstraints {
    /// Maximum depth in the spawn tree (None = unlimited).
    pub max_spawn_depth: Option<u32>,
    /// Maximum number of direct children (None = unlimited).
    pub max_children: Option<u32>,
    /// Maximum number of total descendants (None = unlimited).
    pub max_descendants: Option<u64>,
    /// Whether this identity can spawn children.
    pub can_spawn: bool,
    /// Authority decay factor per generation (None = no decay).
    /// Value between 0.0 and 1.0 — multiplied against parent authority.
    pub authority_decay: Option<f32>,
}

impl Default for SpawnConstraints {
    fn default() -> Self {
        Self {
            max_spawn_depth: Some(10),
            max_children: None,
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn Info (attached to spawned identity)
// ---------------------------------------------------------------------------

/// Information about a spawn attached to the child identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnInfo {
    pub spawn_id: SpawnId,
    pub parent_id: IdentityId,
    pub spawn_type: SpawnType,
    pub spawn_timestamp: u64,
    pub authority_ceiling: Vec<Capability>,
    pub lifetime: SpawnLifetime,
    pub constraints: SpawnConstraints,
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

/// Lineage information for an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lineage {
    pub identity: IdentityId,
    pub root_ancestor: IdentityId,
    pub parent_chain: Vec<IdentityId>,
    pub spawn_depth: u32,
    pub sibling_index: u32,
    pub total_siblings: u32,
}

/// Result of verifying an identity's lineage.
#[derive(Debug, Clone)]
pub struct LineageVerification {
    pub identity: IdentityId,
    pub lineage_valid: bool,
    pub all_ancestors_active: bool,
    pub effective_authority: Vec<Capability>,
    pub spawn_depth: u32,
    pub revoked_ancestor: Option<IdentityId>,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}
