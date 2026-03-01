//! Sister integration bridge traits for AgenticIdentity.
//!
//! Each bridge defines the interface for integrating with another Agentra sister.
//! Default implementations are no-ops, allowing gradual adoption.
//! Trait-based design ensures Hydra compatibility — swap implementors without refactoring.

/// Bridge to agentic-memory for persisting identity operations.
pub trait MemoryBridge: Send + Sync {
    /// Store an identity event as a memory node
    fn store_identity_event(&self, event_type: &str, details: &str) -> Result<u64, String> {
        let _ = (event_type, details);
        Err("Memory bridge not connected".to_string())
    }

    /// Recall trust history for an agent from memory
    fn recall_trust_history(&self, agent_id: &str, max_results: usize) -> Vec<String> {
        let _ = (agent_id, max_results);
        Vec::new()
    }

    /// Link a receipt to a memory node for cross-referencing
    fn link_receipt_to_memory(&self, receipt_id: &str, node_id: u64) -> Result<(), String> {
        let _ = (receipt_id, node_id);
        Err("Memory bridge not connected".to_string())
    }
}

/// Bridge to agentic-time for temporal identity operations.
pub trait TimeBridge: Send + Sync {
    /// Schedule trust expiry check at a future time
    fn schedule_trust_expiry(&self, trust_id: &str, expires_at: u64) -> Result<String, String> {
        let _ = (trust_id, expires_at);
        Err("Time bridge not connected".to_string())
    }

    /// Check if a trust grant has expired based on temporal context
    fn is_trust_expired(&self, trust_id: &str) -> Option<bool> {
        let _ = trust_id;
        None
    }

    /// Get temporal context for continuity gap analysis
    fn continuity_temporal_context(&self, since: u64) -> Vec<String> {
        let _ = since;
        Vec::new()
    }

    /// Create a deadline for an obligation linked to identity
    fn create_obligation_deadline(&self, label: &str, due_at: u64) -> Result<String, String> {
        let _ = (label, due_at);
        Err("Time bridge not connected".to_string())
    }
}

/// Bridge to agentic-contract for policy enforcement on identity operations.
pub trait ContractBridge: Send + Sync {
    /// Check if an identity operation is allowed by current policies
    fn check_policy(&self, operation: &str, agent_id: &str) -> Result<bool, String> {
        let _ = (operation, agent_id);
        Ok(true) // Default: allow all
    }

    /// Record an identity operation for contract audit
    fn record_identity_action(&self, action_type: &str, details: &str) -> Result<(), String> {
        let _ = (action_type, details);
        Err("Contract bridge not connected".to_string())
    }

    /// Validate that a trust grant complies with contract obligations
    fn validate_trust_grant(&self, grantee: &str, capabilities: &[String]) -> Result<bool, String> {
        let _ = (grantee, capabilities);
        Ok(true) // Default: allow all
    }
}

/// Bridge to agentic-codebase for code attribution and signing.
pub trait CodebaseBridge: Send + Sync {
    /// Attribute a code change to an identity
    fn attribute_commit(&self, identity_id: &str, commit_hash: &str) -> Result<(), String> {
        let _ = (identity_id, commit_hash);
        Err("Codebase bridge not connected".to_string())
    }

    /// Verify code authorship via identity signatures
    fn verify_code_author(&self, symbol: &str) -> Option<String> {
        let _ = symbol;
        None
    }
}

/// Bridge to agentic-vision for visual identity verification.
pub trait VisionBridge: Send + Sync {
    /// Link a visual capture to an identity receipt
    fn link_capture_to_receipt(&self, capture_id: u64, receipt_id: &str) -> Result<(), String> {
        let _ = (capture_id, receipt_id);
        Err("Vision bridge not connected".to_string())
    }

    /// Capture visual evidence of an identity action
    fn capture_identity_evidence(&self, description: &str) -> Result<u64, String> {
        let _ = description;
        Err("Vision bridge not connected".to_string())
    }
}

/// Bridge to agentic-comm for identity-aware messaging.
pub trait CommBridge: Send + Sync {
    /// Broadcast an identity event to a comm channel
    fn broadcast_identity_event(&self, event_type: &str, details: &str) -> Result<(), String> {
        let _ = (event_type, details);
        Err("Comm bridge not connected".to_string())
    }

    /// Verify message sender identity via comm channel
    fn verify_channel_sender(&self, channel_id: u64, sender_id: &str) -> bool {
        let _ = (channel_id, sender_id);
        true // Default: trust all
    }
}

/// No-op implementation of all bridges for standalone use.
#[derive(Debug, Clone, Default)]
pub struct NoOpBridges;

impl MemoryBridge for NoOpBridges {}
impl TimeBridge for NoOpBridges {}
impl ContractBridge for NoOpBridges {}
impl CodebaseBridge for NoOpBridges {}
impl VisionBridge for NoOpBridges {}
impl CommBridge for NoOpBridges {}

/// Configuration for which bridges are active.
#[derive(Debug, Clone, Default)]
pub struct BridgeConfig {
    pub memory_enabled: bool,
    pub time_enabled: bool,
    pub contract_enabled: bool,
    pub codebase_enabled: bool,
    pub vision_enabled: bool,
    pub comm_enabled: bool,
}

/// Hydra adapter trait — future orchestrator discovery interface.
pub trait HydraAdapter: Send + Sync {
    /// Unique adapter identifier for this sister instance
    fn adapter_id(&self) -> &str;

    /// List capabilities this sister exposes to Hydra
    fn capabilities(&self) -> Vec<String>;

    /// Handle an adapter request from Hydra
    fn handle_request(&self, method: &str, params: &str) -> Result<String, String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_bridges_implements_all_traits() {
        let b = NoOpBridges;
        let _: &dyn MemoryBridge = &b;
        let _: &dyn TimeBridge = &b;
        let _: &dyn ContractBridge = &b;
        let _: &dyn CodebaseBridge = &b;
        let _: &dyn VisionBridge = &b;
        let _: &dyn CommBridge = &b;
    }

    #[test]
    fn memory_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b.store_identity_event("trust_grant", "details").is_err());
        assert!(b.recall_trust_history("agent-1", 10).is_empty());
        assert!(b.link_receipt_to_memory("arec_123", 1).is_err());
    }

    #[test]
    fn time_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b.schedule_trust_expiry("atrust_1", 1000).is_err());
        assert!(b.is_trust_expired("atrust_1").is_none());
        assert!(b.continuity_temporal_context(0).is_empty());
        assert!(b.create_obligation_deadline("label", 1000).is_err());
    }

    #[test]
    fn contract_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b.check_policy("sign", "agent-1").unwrap());
        assert!(b.record_identity_action("sign", "details").is_err());
        assert!(b
            .validate_trust_grant("agent-2", &["read:memory".to_string()])
            .unwrap());
    }

    #[test]
    fn codebase_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b.attribute_commit("aid_123", "abc123").is_err());
        assert!(b.verify_code_author("my_func").is_none());
    }

    #[test]
    fn vision_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b.link_capture_to_receipt(1, "arec_123").is_err());
        assert!(b.capture_identity_evidence("screenshot").is_err());
    }

    #[test]
    fn comm_bridge_defaults() {
        let b = NoOpBridges;
        assert!(b
            .broadcast_identity_event("trust_grant", "details")
            .is_err());
        assert!(b.verify_channel_sender(1, "agent-1"));
    }

    #[test]
    fn bridge_config_defaults_all_false() {
        let cfg = BridgeConfig::default();
        assert!(!cfg.memory_enabled);
        assert!(!cfg.time_enabled);
        assert!(!cfg.contract_enabled);
        assert!(!cfg.codebase_enabled);
        assert!(!cfg.vision_enabled);
        assert!(!cfg.comm_enabled);
    }

    #[test]
    fn noop_bridges_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpBridges>();
    }

    #[test]
    fn noop_bridges_default_and_clone() {
        let b = NoOpBridges;
        let _b2 = b.clone();
    }
}
