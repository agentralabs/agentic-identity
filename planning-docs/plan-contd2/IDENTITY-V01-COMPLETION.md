# Identity v0.1 Completion — Temporal Continuity + Identity Inheritance

> **Goal:** Complete the remaining 2 inventions to ship full v0.1

---

## Current State

```
IDENTITY v0.1 SPEC vs BUILT
───────────────────────────
✅ Invention 1: Identity Anchor      — BUILT (196 tests)
✅ Invention 2: Action Receipts      — BUILT
✅ Invention 3: Trust Web            — BUILT
❌ Invention 4: Temporal Continuity  — SPEC ONLY
❌ Invention 5: Identity Inheritance — SPEC ONLY
```

---

## Invention 4: Temporal Continuity

### Data Structures to Add

```rust
// src/continuity/mod.rs

/// Experience event ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExperienceId(pub String);

/// Experience event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperienceEvent {
    pub id: ExperienceId,
    pub identity: IdentityId,
    pub event_type: ExperienceType,
    pub timestamp: u64,
    pub duration: Option<u64>,
    pub content_hash: String,
    pub intensity: f32,  // 0.0 - 1.0
    
    // Chain links
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerceptionSource { Visual, Auditory, Text, Sensor }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CognitionType { Thought, Reasoning, Inference, Recall }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanningType { GoalSetting, PlanCreation, PlanUpdate }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemEvent { Startup, Shutdown, Checkpoint, Error { message: String } }

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

/// Continuity anchor (checkpoint)
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnchorId(pub String);

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HeartbeatId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeartbeatStatus { Active, Idle, Suspended, Degraded }

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimType { FullContinuity, RangeContinuity, SinceContinuity }

/// Gap information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
    pub gap_type: GapType,
    pub severity: GapSeverity,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapType { Temporal, Sequence, Hash, Heartbeat }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapSeverity { Minor, Moderate, Major, Critical }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuityResult {
    Continuous,
    Discontinuous { gap_count: usize, max_gap_seconds: u64 },
    Uncertain { reason: String },
}
```

### Functions to Implement

```rust
// src/continuity/engine.rs

/// Record an experience event
pub fn record_experience(
    identity: &IdentityAnchor,
    event_type: ExperienceType,
    content_hash: &str,
    intensity: f32,
) -> Result<ExperienceEvent, IdentityError>;

/// Create continuity anchor
pub fn create_anchor(
    identity: &IdentityAnchor,
    anchor_type: AnchorType,
    external_witness: Option<&IdentityAnchor>,
) -> Result<ContinuityAnchor, IdentityError>;

/// Create heartbeat
pub fn create_heartbeat(
    identity: &IdentityAnchor,
    status: HeartbeatStatus,
    health: HealthMetrics,
) -> Result<HeartbeatRecord, IdentityError>;

/// Create continuity claim
pub fn create_continuity_claim(
    identity: &IdentityAnchor,
    claim_type: ClaimType,
    start_timestamp: u64,
    end_timestamp: u64,
) -> Result<ContinuityClaim, IdentityError>;

/// Verify continuity claim
pub fn verify_continuity(
    claim: &ContinuityClaim,
    experiences: &[ExperienceEvent],
    anchors: &[ContinuityAnchor],
) -> Result<ContinuityVerification, IdentityError>;

/// Detect gaps in experience chain
pub fn detect_gaps(
    experiences: &[ExperienceEvent],
    grace_period_seconds: u64,
) -> Vec<Gap>;

/// Get continuity state for identity
pub fn get_continuity_state(
    identity: &IdentityId,
    store: &impl ContinuityStore,
) -> Result<ContinuityState, IdentityError>;
```

### Tests (16 scenarios)

```rust
#[cfg(test)]
mod continuity_tests {
    // 1. Experience creation succeeds
    // 2. Experience chain links correctly
    // 3. Cumulative hash is deterministic
    // 4. Gap detection works (temporal)
    // 5. Gap detection works (sequence)
    // 6. Gap detection works (hash mismatch)
    // 7. Anchor creation works
    // 8. Heartbeat creation works
    // 9. Heartbeat gap detection works
    // 10. Continuity claim creation works
    // 11. Continuity verification (continuous)
    // 12. Continuity verification (discontinuous)
    // 13. All 10 experience types work
    // 14. Experience intensity validated (0.0-1.0)
    // 15. External witness anchor works
    // 16. Chain tampering detected
}
```

---

## Invention 5: Identity Inheritance (Spawn)

### Data Structures to Add

```rust
// src/spawn/mod.rs

/// Spawn record ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpawnId(pub String);

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

/// Spawn type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpawnType {
    Worker,      // Temporary, task-specific
    Delegate,    // Acts on behalf of parent
    Clone,       // Full copy of authority
    Specialist,  // Subset of capabilities
    Custom(String),
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

### Functions to Implement

```rust
// src/spawn/engine.rs

/// Spawn a child identity
pub fn spawn_child(
    parent: &IdentityAnchor,
    spawn_type: SpawnType,
    purpose: &str,
    authority_granted: Vec<CapabilityUri>,
    authority_ceiling: Vec<CapabilityUri>,
    lifetime: SpawnLifetime,
    constraints: SpawnConstraints,
) -> Result<(IdentityAnchor, SpawnRecord, ActionReceipt), IdentityError>;

/// Terminate a spawned child
pub fn terminate_spawn(
    parent: &IdentityAnchor,
    child_id: &IdentityId,
    reason: &str,
    cascade: bool,
) -> Result<ActionReceipt, IdentityError>;

/// Verify lineage
pub fn verify_lineage(
    identity: &IdentityId,
    store: &impl SpawnStore,
) -> Result<LineageVerification, IdentityError>;

/// Get effective authority (bounded by lineage)
pub fn get_effective_authority(
    identity: &IdentityId,
    store: &impl SpawnStore,
) -> Result<Vec<CapabilityUri>, IdentityError>;

/// Get ancestors
pub fn get_ancestors(
    identity: &IdentityId,
    store: &impl SpawnStore,
) -> Result<Vec<IdentityId>, IdentityError>;

/// Get descendants
pub fn get_descendants(
    identity: &IdentityId,
    store: &impl SpawnStore,
) -> Result<Vec<IdentityId>, IdentityError>;

/// Get children
pub fn get_children(
    identity: &IdentityId,
    store: &impl SpawnStore,
) -> Result<Vec<IdentityId>, IdentityError>;

/// Check if spawn is allowed
pub fn can_spawn(
    parent: &IdentityAnchor,
    proposed_authority: &[CapabilityUri],
    store: &impl SpawnStore,
) -> Result<bool, IdentityError>;

/// Revoke spawn and cascade
pub fn revoke_spawn(
    revoker: &IdentityAnchor,
    spawn_id: &SpawnId,
    cascade: bool,
    store: &mut impl SpawnStore,
) -> Result<Vec<SpawnId>, IdentityError>;
```

### Tests (16 scenarios)

```rust
#[cfg(test)]
mod spawn_tests {
    // 1. Spawn creation succeeds
    // 2. Child authority bounded by parent
    // 3. Authority exceeding ceiling fails
    // 4. Lineage chain builds correctly
    // 5. Spawn depth limit enforced
    // 6. Max children limit enforced
    // 7. All 5 spawn types work
    // 8. Spawn termination works
    // 9. Parent termination cascades to children
    // 10. Revocation cascade works
    // 11. Ancestry walking works
    // 12. Descendant listing works
    // 13. Effective authority calculation correct
    // 14. Lifetime Duration expiration works
    // 15. Lifetime Until expiration works
    // 16. Spawn receipt is created correctly
}
```

---

## CLI Additions

```rust
// Add to aid CLI

// Continuity commands
aid continuity record --type perception --source visual --content-hash "abc123" --intensity 0.8
aid continuity anchor --type manual
aid continuity anchor --type time-based --interval 24
aid continuity heartbeat --status active
aid continuity prove --since "2026-02-01T00:00:00Z"
aid continuity prove --range "2026-02-01" "2026-02-24"
aid continuity verify CLAIM_ID
aid continuity status
aid continuity gaps --grace-period 300

// Spawn commands
aid spawn create --type worker --purpose "Process documents" --authority "memory:docs:*"
aid spawn create --type delegate --purpose "Act on my behalf" --authority "calendar:*,email:read"
aid spawn list [--active] [--terminated]
aid spawn terminate CHILD_ID --reason "Task complete" [--cascade]
aid spawn lineage [IDENTITY_ID]
aid spawn children [IDENTITY_ID]
aid spawn ancestors [IDENTITY_ID]
aid spawn authority [IDENTITY_ID]  # Show effective authority
```

---

## MCP Additions

```rust
// Add to MCP server

// Continuity tools
continuity_record     // Record experience event
continuity_anchor     // Create anchor
continuity_heartbeat  // Create heartbeat
continuity_prove      // Generate continuity proof
continuity_verify     // Verify continuity claim
continuity_status     // Get continuity state
continuity_gaps       // Detect gaps

// Spawn tools
spawn_create          // Spawn child identity
spawn_terminate       // Terminate child
spawn_list           // List children
spawn_lineage        // Get lineage info
spawn_authority      // Get effective authority

// Continuity resources
continuity://{identity}     // Continuity state
experiences://{identity}    // Experience list
heartbeats://{identity}     // Heartbeat list
anchors://{identity}        // Anchor list

// Spawn resources
spawn://{id}               // Spawn record
children://{identity}      // Children list
lineage://{identity}       // Lineage info
```

---

## File Format Additions

```
~/.agentic-identity/
├── identities/
├── receipts/
├── trust/
├── experience/              # NEW
│   └── {identity_id}/
│       ├── events/          # Experience events
│       │   └── {seq}.exp
│       ├── anchors/         # Continuity anchors
│       │   └── {anchor_id}.anchor
│       └── heartbeats/      # Heartbeat records
│           └── {seq}.hb
├── spawn/                   # NEW
│   ├── records/             # Spawn records
│   │   └── {spawn_id}.spawn
│   ├── by_parent/           # Index: parent -> children
│   │   └── {parent_id}.json
│   └── by_child/            # Index: child -> parent
│       └── {child_id}.json
└── config.json
```

---

## Integration Points

### Continuity ↔ Receipts
- Every `ActionReceipt` includes `ContinuityBinding`
- Recording an experience can create a receipt (Action type)

### Continuity ↔ Trust
- Trust grants can require `required_continuity_hours`
- Verification checks continuity state

### Spawn ↔ Identity
- Spawned identities have `IdentityType::Spawned`
- Identity document includes `Lineage`

### Spawn ↔ Trust
- Authority ceiling enforced on trust verification
- Inherited trust from parent

### Spawn ↔ Receipts
- Spawn creates `ActionType::Spawn` receipt
- Termination creates `ActionType::Termination` receipt

---

## Success Criteria

```
[ ] All 10 experience types implemented and tested
[ ] Experience chain linking works
[ ] Cumulative hash calculation correct
[ ] Gap detection for all 4 gap types
[ ] Anchors (5 types) working
[ ] Heartbeat system working
[ ] Continuity claims and proofs working
[ ] Continuity verification working

[ ] All 5 spawn types implemented and tested
[ ] Authority bounding enforced (child ⊆ parent)
[ ] Lineage chain building and walking
[ ] Spawn depth limits enforced
[ ] Max children limits enforced
[ ] Termination and cascade working
[ ] Effective authority calculation correct
[ ] Lifetime expiration working

[ ] CLI commands for continuity working
[ ] CLI commands for spawn working
[ ] MCP tools for continuity working
[ ] MCP tools for spawn working

[ ] 32 new tests (16 continuity + 16 spawn)
[ ] Integration tests with existing features
[ ] Stress tests for long chains
```

---

## Estimated Effort

```
Continuity implementation:  ~4-6 hours
Spawn implementation:       ~4-6 hours
CLI additions:              ~2 hours
MCP additions:              ~2 hours
Tests:                      ~2-3 hours
Integration testing:        ~2 hours
────────────────────────────────────
Total:                      ~16-21 hours
```

---

## Claude Code Task

```
TASK: Complete Identity v0.1

Add Temporal Continuity (Invention 4):
1. Create src/continuity/ module with all types
2. Implement experience chain with cumulative hash
3. Implement anchors (5 types)
4. Implement heartbeat system
5. Implement continuity claims and proofs
6. Implement verification and gap detection
7. Add CLI commands
8. Add MCP tools
9. Write 16 tests

Add Identity Inheritance (Invention 5):
1. Create src/spawn/ module with all types
2. Implement spawn with authority bounding
3. Implement lineage chain
4. Implement constraints (depth, children, decay)
5. Implement termination with cascade
6. Implement effective authority calculation
7. Add CLI commands
8. Add MCP tools
9. Write 16 tests

Integration:
- Connect continuity to receipts (ContinuityBinding)
- Connect spawn to identity (IdentityType::Spawned)
- Connect spawn to trust (authority ceiling)
- Update existing tests for integration

Run all tests: cargo test --all
Target: 228+ tests (196 existing + 32 new)
```
