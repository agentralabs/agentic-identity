# SPEC-DATA-STRUCTURES.md

> **Complete type definitions for AgenticIdentity**

---

## ID Types

All IDs follow a consistent format: `{prefix}_{base58(sha256(content)[0:16])}`

```rust
use serde::{Deserialize, Serialize};

/// ID prefix constants
pub mod prefix {
    pub const IDENTITY: &str = "aid";
    pub const RECEIPT: &str = "arec";
    pub const TRUST: &str = "atrust";
    pub const EXPERIENCE: &str = "aexp";
    pub const SPAWN: &str = "aspawn";
    pub const ANCHOR: &str = "aanch";
    pub const HEARTBEAT: &str = "ahb";
    pub const CLAIM: &str = "aclaim";
    pub const REVOCATION: &str = "arev";
}

/// Identity ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub String);

/// Receipt ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);

/// Trust grant ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustId(pub String);

/// Experience event ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExperienceId(pub String);

/// Spawn record ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpawnId(pub String);

/// Continuity anchor ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnchorId(pub String);

/// Heartbeat ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HeartbeatId(pub String);

/// Continuity claim ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimId(pub String);

/// Revocation ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevocationId(pub String);

/// Capability URI
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityUri(pub String);
```

---

## Identity Types

```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use zeroize::Zeroize;
use std::collections::HashMap;

/// Identity type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityType {
    /// Created directly, not spawned
    Root,
    /// Created by parent identity
    Spawned { parent: IdentityId },
    /// Continuation after key rotation
    Rotated { previous_key: String },
    /// Recovered via social recovery (future: v0.3)
    Recovered { recovery_id: String },
}

/// The root identity anchor (PRIVATE - contains secrets)
/// This struct is zeroized on drop to clear secret key material
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct IdentityAnchor {
    /// Root signing key (SECRET - never expose)
    #[zeroize(skip)]  // ed25519_dalek handles its own zeroization
    signing_key: SigningKey,
    
    /// Root verifying key (public)
    #[zeroize(skip)]
    pub verifying_key: VerifyingKey,
    
    /// Derived identity ID
    pub id: IdentityId,
    
    /// Creation timestamp (microseconds since Unix epoch)
    pub created_at: u64,
    
    /// Human-readable name (optional, mutable)
    pub name: Option<String>,
    
    /// Identity type
    pub identity_type: IdentityType,
    
    /// Maximum capabilities this identity can ever have
    pub capabilities_ceiling: Vec<CapabilityUri>,
    
    /// Key rotation history
    pub rotation_history: Vec<KeyRotation>,
    
    /// Spawn information (if this identity was spawned)
    pub spawn_info: Option<SpawnInfo>,
    
    /// Current continuity state
    pub continuity: ContinuityState,
    
    /// Searchable tags
    pub tags: Vec<String>,
}

/// Public identity document (shareable, no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDocument {
    /// Identity ID
    pub id: IdentityId,
    
    /// Public key (base64 encoded Ed25519 public key)
    pub public_key: String,
    
    /// Signature algorithm identifier
    pub algorithm: String,  // Always "Ed25519"
    
    /// Document format version
    pub version: u32,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Human-readable name
    pub name: Option<String>,
    
    /// Identity type
    pub identity_type: IdentityType,
    
    /// Capabilities ceiling
    pub capabilities_ceiling: Vec<CapabilityUri>,
    
    /// Key rotation history (public parts only)
    pub rotation_history: Vec<PublicKeyRotation>,
    
    /// Attestations from other identities
    pub attestations: Vec<Attestation>,
    
    /// Spawn lineage (if spawned)
    pub lineage: Option<Lineage>,
    
    /// Current continuity hash
    pub continuity_hash: Option<String>,
    
    /// Total experience count
    pub experience_count: u64,
    
    /// Self-signature over all above fields
    pub signature: String,
}

/// Key rotation record (contains private authorization)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KeyRotation {
    pub previous_key: String,
    pub new_key: String,
    pub rotated_at: u64,
    pub reason: RotationReason,
    pub authorization_signature: String,
    pub witnesses: Vec<WitnessSignature>,
}

/// Public key rotation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRotation {
    pub previous_key: String,
    pub new_key: String,
    pub rotated_at: u64,
    pub reason: RotationReason,
    pub authorization_signature: String,
}

/// Rotation reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub enum RotationReason {
    /// Regular scheduled rotation
    Scheduled,
    /// Key may be compromised
    Compromised,
    /// Device containing key was lost
    DeviceLost,
    /// Policy requires rotation
    PolicyRequired,
    /// Manual rotation by user
    Manual,
}

/// Attestation from another identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub attester: IdentityId,
    pub attester_key: String,
    pub claim: AttestationClaim,
    pub attested_at: u64,
    pub expires_at: Option<u64>,
    pub signature: String,
}

/// Types of attestation claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationClaim {
    KeyOwnership,
    NameVerification { name: String },
    OrganizationMembership { org: String },
    CapabilityAttestation { capability: CapabilityUri },
    ContinuityAttestation { since: u64 },
    Custom { claim_type: String, claim_value: String },
}
```

---

## Derived Key Types

```rust
/// Purpose of a derived key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Session-specific key (ephemeral)
    Session {
        session_id: String,
        expires_at: u64,
    },
    /// Capability-specific key (scoped to permission)
    Capability {
        capability_uri: CapabilityUri,
    },
    /// Device-specific key (bound to hardware)
    Device {
        device_id: String,
        device_fingerprint: String,
    },
    /// Encryption key (X25519 for key exchange)
    Encryption,
    /// Spawn key (for creating child identity)
    Spawn {
        child_id: IdentityId,
        authority_hash: String,
    },
}

/// A derived key with metadata
pub struct DerivedKey {
    /// The derived signing key (SECRET)
    signing_key: SigningKey,
    /// The derived verifying key (public)
    pub verifying_key: VerifyingKey,
    /// Purpose of this key
    pub purpose: KeyPurpose,
    /// Parent identity ID
    pub parent_id: IdentityId,
    /// Full derivation path
    pub derivation_path: String,
    /// When this key was created
    pub created_at: u64,
    /// When this key expires (None = never)
    pub expires_at: Option<u64>,
}

/// Key type indicator (for receipts)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    Root,
    Session,
    Capability,
    Device,
    Spawn,
}
```

---

## Action Receipt Types

```rust
/// Action receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceipt {
    /// Unique receipt ID
    pub id: ReceiptId,
    
    /// Actor identity
    pub actor: IdentityId,
    /// Actor's public key used for signing
    pub actor_key: String,
    /// Type of key used
    pub key_type: KeyType,
    /// Derivation path if derived key
    pub key_derivation_path: Option<String>,
    
    /// Action type
    pub action_type: ActionType,
    /// Action content
    pub action: ActionContent,
    
    /// Timestamp (microseconds)
    pub timestamp: u64,
    /// Timestamp source
    pub timestamp_source: TimestampSource,
    /// Sequence number in actor's chain
    pub sequence_number: u64,
    /// Duration (for long actions)
    pub duration: Option<u64>,
    
    /// Context at time of action
    pub context: Option<ActionContext>,
    
    /// Chain information
    pub chain: ChainInfo,
    
    /// Continuity binding
    pub continuity: ContinuityBinding,
    
    /// Hash of all above fields (SHA-256)
    pub receipt_hash: String,
    
    /// Signature over receipt_hash
    pub signature: String,
    
    /// Witness signatures
    pub witnesses: Vec<WitnessSignature>,
}

/// Action type enumeration (12 types)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType {
    /// Observed/recorded something
    Observation {
        source: ObservationSource,
        confidence: f32,
    },
    /// Made a decision
    Decision {
        decision_type: DecisionType,
        alternatives_considered: u32,
        confidence: f32,
        reasoning_reference: Option<String>,
    },
    /// Changed state
    Mutation {
        target: String,
        mutation_type: MutationType,
        reversible: bool,
        previous_state_hash: Option<String>,
        new_state_hash: Option<String>,
    },
    /// Granted authority to another
    Delegation {
        grantee: IdentityId,
        trust_id: TrustId,
        capabilities: Vec<CapabilityUri>,
    },
    /// Removed authority
    Revocation {
        trust_id: TrustId,
        reason: RevocationReason,
        cascade: bool,
    },
    /// Created child identity
    Spawn {
        child_id: IdentityId,
        spawn_type: SpawnType,
        authority_granted: Vec<CapabilityUri>,
    },
    /// Ended an identity
    Termination {
        target_id: IdentityId,
        termination_type: TerminationType,
        reason: String,
    },
    /// Sent or received communication
    Communication {
        direction: CommunicationDirection,
        counterparty: IdentityId,
        channel: String,
        message_hash: String,
        encrypted: bool,
    },
    /// Made a commitment
    Commitment {
        commitment_type: CommitmentType,
        commitment_hash: String,
        deadline: Option<u64>,
        counterparty: Option<IdentityId>,
    },
    /// Memory operation
    MemoryOperation {
        operation: MemoryOpType,
        memory_node_id: Option<String>,
        memory_hash_before: String,
        memory_hash_after: String,
    },
    /// Learning event
    Learning {
        learning_type: LearningType,
        domain: String,
        competence_delta: f32,
    },
    /// Custom action type
    Custom {
        type_uri: String,
        type_version: u32,
    },
}

/// Observation source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObservationSource {
    Vision,
    Web,
    Sensor,
    Communication,
    Internal,
    Custom(String),
}

/// Decision type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionType {
    Binary,
    Selection,
    Ranking,
    Allocation,
    Judgment,
}

/// Mutation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutationType {
    Create,
    Update,
    Delete,
    Move,
    Transform,
}

/// Spawn type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpawnType {
    Worker,
    Delegate,
    Clone,
    Specialist,
    Custom(String),
}

/// Termination type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TerminationType {
    SelfTermination,
    ParentTermination,
    Expiration,
    Revocation,
    Error,
}

/// Communication direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommunicationDirection {
    Sent,
    Received,
    Forwarded,
}

/// Commitment type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentType {
    Promise,
    Goal,
    Deadline,
    Constraint,
    Contract,
}

/// Memory operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryOpType {
    Store,
    Recall,
    Update,
    Forget,
    Link,
}

/// Learning type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LearningType {
    SkillAcquisition,
    PatternRecognition,
    ErrorCorrection,
    Reinforcement,
    Transfer,
}

/// Action content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContent {
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Timestamp source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimestampSource {
    Local,
    Ntp,
    Authority { authority: String, signature: String },
    Witnessed { witness: IdentityId },
}

/// Action context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    pub context_hash: String,
    pub context_type: ContextType,
    pub references: Vec<String>,
    pub description: Option<String>,
}

/// Context type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContextType {
    MemoryGraph,
    CodebaseGraph,
    VisualState,
    Environment,
    Custom(String),
}

/// Chain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub previous_receipt_id: Option<ReceiptId>,
    pub previous_receipt_hash: Option<String>,
    pub chain_position: u64,
    pub chain_root: ReceiptId,
    pub branch_from: Option<ReceiptId>,
}

/// Continuity binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityBinding {
    pub continuity_hash: String,
    pub experience_count: u64,
    pub last_heartbeat: u64,
}

/// Witness signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness: IdentityId,
    pub witness_key: String,
    pub witnessed_at: u64,
    pub witness_type: WitnessType,
    pub signature: String,
}

/// Witness type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WitnessType {
    Observer,
    Participant,
    Validator,
    TimeAuthority,
}
```

---

## Trust Types

```rust
/// Trust grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    pub id: TrustId,
    pub version: u32,
    pub grant_type: GrantType,
    
    /// Parties
    pub grantor: IdentityId,
    pub grantor_key: String,
    pub grantee: IdentityId,
    pub grantee_key: String,
    
    /// What is granted
    pub capabilities: Vec<Capability>,
    
    /// Constraints
    pub temporal_constraints: TemporalConstraints,
    pub usage_constraints: UsageConstraints,
    pub context_constraints: Option<ContextConstraints>,
    
    /// Delegation
    pub delegation_rules: DelegationRules,
    
    /// Revocation
    pub revocation_config: RevocationConfig,
    
    /// Timing
    pub granted_at: u64,
    
    /// Signatures
    pub grant_hash: String,
    pub grantor_signature: String,
    pub grantee_acknowledgment: Option<String>,
}

/// Grant type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantType {
    Direct,
    Delegated { parent_grant: TrustId },
    Inherited { spawn_id: SpawnId },
    Transitive,
}

/// Capability with constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub uri: CapabilityUri,
    pub description: Option<String>,
    pub rate_limit: Option<RateLimit>,
    pub resource_limit: Option<ResourceLimit>,
    pub target_restriction: Option<Vec<String>>,
    pub custom_constraints: Option<serde_json::Value>,
}

/// Rate limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_per_second: Option<u32>,
    pub max_per_minute: Option<u32>,
    pub max_per_hour: Option<u32>,
    pub max_per_day: Option<u32>,
}

/// Resource limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimit {
    pub max_bytes: Option<u64>,
    pub max_items: Option<u64>,
    pub max_cost: Option<f64>,
}

/// Temporal constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalConstraints {
    pub not_before: u64,
    pub not_after: Option<u64>,
    pub valid_hours: Option<Vec<(u8, u8)>>,
    pub valid_days: Option<Vec<u8>>,
    pub timezone: Option<String>,
}

/// Usage constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageConstraints {
    pub max_uses: Option<u64>,
    pub uses_remaining: u64,
    pub max_uses_per_hour: Option<u64>,
    pub cooldown_seconds: Option<u64>,
    pub last_used: Option<u64>,
}

/// Context constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConstraints {
    pub required_environment: Option<Vec<String>>,
    pub required_device: Option<Vec<String>>,
    pub required_ip_range: Option<Vec<String>>,
    pub required_continuity_hours: Option<u64>,
    pub required_witnesses: Option<Vec<IdentityId>>,
}

/// Delegation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRules {
    pub delegation_allowed: bool,
    pub max_delegation_depth: Option<u32>,
    pub delegatable_capabilities: Option<Vec<CapabilityUri>>,
    pub delegation_requires_approval: bool,
    pub narrowing_only: bool,
}

/// Revocation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationConfig {
    pub revocation_key_derivation: String,
    pub revocation_channel: RevocationChannel,
    pub check_interval_seconds: u64,
    pub required_witnesses: Vec<IdentityId>,
    pub auto_revoke_conditions: Vec<AutoRevokeCondition>,
}

/// Revocation channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationChannel {
    Local,
    Http { url: String },
    Dns { domain: String },
    Multi(Vec<RevocationChannel>),
}

/// Auto revoke condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutoRevokeCondition {
    OnViolation,
    OnInactivity { seconds: u64 },
    OnAncestorRevocation,
}

/// Revocation reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    Expired,
    Compromised,
    PolicyViolation { policy: String },
    GrantorRequest,
    GranteeRequest,
    AncestorRevoked { ancestor: TrustId },
    SpawnTerminated { spawn_id: SpawnId },
    Custom(String),
}

/// Revocation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub id: RevocationId,
    pub trust_id: TrustId,
    pub revoker: IdentityId,
    pub revoker_key: String,
    pub revoked_at: u64,
    pub reason: RevocationReason,
    pub scope: RevocationScope,
    pub revocation_hash: String,
    pub signature: String,
    pub witness_signatures: Vec<WitnessSignature>,
}

/// Revocation scope
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationScope {
    Single,
    Cascade,
    Family,
}
```

---

## Continuity Types

```rust
/// Experience event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperienceEvent {
    pub id: ExperienceId,
    pub identity: IdentityId,
    pub event_type: ExperienceType,
    pub timestamp: u64,
    pub duration: Option<u64>,
    pub content_hash: String,
    pub intensity: f32,
    
    /// Chain links
    pub previous_experience_id: Option<ExperienceId>,
    pub previous_experience_hash: Option<String>,
    pub sequence_number: u64,
    pub cumulative_hash: String,
    
    pub signature: String,
}

/// Experience type (10 types)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExperienceType {
    Perception { source: PerceptionSource },
    Cognition { cognition_type: CognitionType },
    Action { receipt_id: ReceiptId },
    Communication { direction: CommunicationDirection, counterparty: IdentityId },
    Memory { operation: MemoryOpType },
    Learning { learning_type: LearningType, domain: String },
    Planning { planning_type: PlanningType },
    Emotion { emotion_type: String },
    Idle { reason: String },
    System { event: SystemEvent },
}

/// Perception source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerceptionSource {
    Visual,
    Auditory,
    Text,
    Sensor,
}

/// Cognition type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CognitionType {
    Thought,
    Reasoning,
    Inference,
    Recall,
}

/// Planning type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanningType {
    GoalSetting,
    PlanCreation,
    PlanUpdate,
}

/// System event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemEvent {
    Startup,
    Shutdown,
    Checkpoint,
    Error { message: String },
}

/// Continuity state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityState {
    pub genesis_experience_id: ExperienceId,
    pub genesis_hash: String,
    pub genesis_timestamp: u64,
    pub latest_experience_id: ExperienceId,
    pub latest_hash: String,
    pub latest_timestamp: u64,
    pub total_experiences: u64,
}

/// Continuity anchor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityAnchor {
    pub id: AnchorId,
    pub anchor_type: AnchorType,
    pub experience_id: ExperienceId,
    pub cumulative_hash: String,
    pub experience_count: u64,
    pub timestamp: u64,
    pub previous_anchor: Option<AnchorId>,
    pub external_witness: Option<WitnessSignature>,
    pub signature: String,
}

/// Anchor type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorType {
    Genesis,
    TimeBased { interval_hours: u32 },
    ExperienceCount { interval: u64 },
    Manual,
    External { witness: IdentityId },
}

/// Heartbeat record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub id: HeartbeatId,
    pub identity: IdentityId,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub continuity_hash: String,
    pub experience_count: u64,
    pub experiences_since_last: u64,
    pub status: HeartbeatStatus,
    pub health: HealthMetrics,
    pub signature: String,
}

/// Heartbeat status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeartbeatStatus {
    Active,
    Idle,
    Suspended,
    Degraded,
}

/// Health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub memory_usage_bytes: u64,
    pub experience_rate_per_hour: f64,
    pub error_count: u64,
    pub latency_ms: u64,
}

/// Continuity claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityClaim {
    pub id: ClaimId,
    pub identity: IdentityId,
    pub claim_type: ClaimType,
    pub start_anchor: String,
    pub start_timestamp: u64,
    pub start_experience: u64,
    pub end_anchor: String,
    pub end_timestamp: u64,
    pub end_experience: u64,
    pub experience_count: u64,
    pub max_gap_seconds: u64,
    pub signature: String,
}

/// Claim type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimType {
    FullContinuity,
    RangeContinuity,
    SinceContinuity,
}

/// Gap information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
    pub gap_type: GapType,
    pub severity: GapSeverity,
    pub impact: String,
}

/// Gap type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapType {
    Temporal,
    Sequence,
    Hash,
    Heartbeat,
}

/// Gap severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapSeverity {
    Minor,      // < grace period
    Moderate,   // < 1 hour
    Major,      // < 24 hours
    Critical,   // >= 24 hours
}
```

---

## Spawn Types

```rust
/// Spawn record
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
    pub authority_granted: Vec<CapabilityUri>,
    pub authority_ceiling: Vec<CapabilityUri>,
    pub lifetime: SpawnLifetime,
    pub constraints: SpawnConstraints,
    pub parent_signature: String,
    pub child_acknowledgment: Option<String>,
}

/// Spawn lifetime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpawnLifetime {
    Indefinite,
    Duration { seconds: u64 },
    Until { timestamp: u64 },
    TaskCompletion { task_id: String },
    ParentTermination,
}

/// Spawn constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnConstraints {
    pub max_spawn_depth: Option<u32>,
    pub max_children: Option<u32>,
    pub max_descendants: Option<u64>,
    pub can_spawn: bool,
    pub authority_decay: Option<f32>,
}

/// Spawn info (attached to spawned identity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnInfo {
    pub spawn_id: SpawnId,
    pub parent_id: IdentityId,
    pub spawn_type: SpawnType,
    pub spawn_timestamp: u64,
    pub authority_ceiling: Vec<CapabilityUri>,
    pub lifetime: SpawnLifetime,
}

/// Lineage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lineage {
    pub root_ancestor: IdentityId,
    pub parent_chain: Vec<IdentityId>,
    pub spawn_depth: u32,
    pub sibling_index: u32,
    pub total_siblings: u32,
}
```

---

## Verification Result Types

```rust
/// Receipt verification result
#[derive(Debug, Clone)]
pub struct ReceiptVerification {
    pub receipt_id: ReceiptId,
    pub signature_valid: bool,
    pub chain_valid: Option<bool>,
    pub continuity_valid: Option<bool>,
    pub witnesses_valid: Vec<(IdentityId, bool)>,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Trust verification result
#[derive(Debug, Clone)]
pub struct TrustVerification {
    pub trust_id: TrustId,
    pub capability: CapabilityUri,
    pub signature_valid: bool,
    pub time_valid: bool,
    pub not_revoked: bool,
    pub uses_valid: bool,
    pub context_valid: bool,
    pub capability_matched: bool,
    pub trust_chain: Vec<TrustId>,
    pub effective_capabilities: Vec<CapabilityUri>,
    pub effective_constraints: EffectiveConstraints,
    pub is_valid: bool,
    pub verified_at: u64,
    pub expires_at: Option<u64>,
    pub uses_remaining: Option<u64>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Effective constraints (most restrictive from chain)
#[derive(Debug, Clone)]
pub struct EffectiveConstraints {
    pub not_after: Option<u64>,
    pub max_uses: Option<u64>,
    pub rate_limit: Option<RateLimit>,
    pub resource_limit: Option<ResourceLimit>,
}

/// Continuity verification result
#[derive(Debug, Clone)]
pub struct ContinuityVerification {
    pub claim_id: ClaimId,
    pub chain_valid: bool,
    pub anchors_valid: bool,
    pub signatures_valid: bool,
    pub gaps: Vec<Gap>,
    pub result: ContinuityResult,
    pub verified_at: u64,
    pub errors: Vec<String>,
}

/// Continuity result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityResult {
    Continuous,
    Discontinuous { gap_count: usize, max_gap_seconds: u64 },
    Uncertain { reason: String },
}

/// Lineage verification result
#[derive(Debug, Clone)]
pub struct LineageVerification {
    pub identity: IdentityId,
    pub lineage_valid: bool,
    pub all_ancestors_active: bool,
    pub effective_authority: Vec<CapabilityUri>,
    pub spawn_depth: u32,
    pub revoked_ancestor: Option<IdentityId>,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}
```

---

## Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    // Crypto errors
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signature verification failed")]
    SignatureInvalid,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    
    // Identity errors
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),
    #[error("Identity already exists: {0}")]
    IdentityAlreadyExists(String),
    #[error("Identity terminated: {0}")]
    IdentityTerminated(String),
    
    // Trust errors
    #[error("Trust not granted for capability: {0}")]
    TrustNotGranted(String),
    #[error("Trust revoked: {0}")]
    TrustRevoked(String),
    #[error("Trust expired")]
    TrustExpired,
    #[error("Max uses exceeded")]
    MaxUsesExceeded,
    #[error("Delegation not allowed")]
    DelegationNotAllowed,
    #[error("Delegation depth exceeded: {0} > {1}")]
    DelegationDepthExceeded(u32, u32),
    
    // Receipt errors
    #[error("Invalid receipt chain")]
    InvalidReceiptChain,
    #[error("Receipt not found: {0}")]
    ReceiptNotFound(String),
    
    // Continuity errors
    #[error("Continuity gap detected: {0}")]
    ContinuityGap(String),
    #[error("Invalid continuity proof")]
    InvalidContinuityProof,
    #[error("Continuity requirement not met: required {0}h, have {1}h")]
    ContinuityRequirementNotMet(u64, u64),
    
    // Spawn errors
    #[error("Spawn depth exceeded: {0} > {1}")]
    SpawnDepthExceeded(u32, u32),
    #[error("Max children exceeded: {0} >= {1}")]
    MaxChildrenExceeded(u32, u32),
    #[error("Authority exceeds ceiling")]
    AuthorityExceedsCeiling,
    #[error("Ancestor revoked: {0}")]
    AncestorRevoked(String),
    #[error("Cannot spawn: not authorized")]
    SpawnNotAuthorized,
    
    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Invalid file format: {0}")]
    InvalidFileFormat(String),
    
    // Serialization errors
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
```
