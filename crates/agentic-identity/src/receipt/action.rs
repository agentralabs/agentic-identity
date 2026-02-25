//! Action types and content for receipts.

use serde::{Deserialize, Serialize};

/// Type of action being recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    Decision,
    Observation,
    Mutation,
    Delegation,
    Revocation,
    IdentityOperation,
    Custom(String),
}

impl ActionType {
    /// Return a stable string tag for hashing.
    pub fn as_tag(&self) -> &str {
        match self {
            Self::Decision => "decision",
            Self::Observation => "observation",
            Self::Mutation => "mutation",
            Self::Delegation => "delegation",
            Self::Revocation => "revocation",
            Self::IdentityOperation => "identity_operation",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Content of an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContent {
    /// Human-readable description.
    pub description: String,
    /// Structured data (type-specific).
    pub data: Option<serde_json::Value>,
    /// References to related resources.
    pub references: Vec<String>,
}

impl ActionContent {
    /// Create a simple action with just a description.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            data: None,
            references: Vec::new(),
        }
    }

    /// Create an action with description and structured data.
    pub fn with_data(description: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            description: description.into(),
            data: Some(data),
            references: Vec::new(),
        }
    }
}
