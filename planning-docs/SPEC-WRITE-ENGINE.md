# SPEC-WRITE-ENGINE.md

## Identity Creation
```rust
fn create_identity(name: Option<&str>, ceiling: Vec<CapabilityUri>) -> Result<IdentityAnchor>
fn create_spawned_identity(parent: &IdentityAnchor, spawn_type: SpawnType, authority: Vec<CapabilityUri>) -> Result<(IdentityAnchor, SpawnRecord)>
```

## Receipt Creation
```rust
fn create_receipt(identity: &IdentityAnchor, action_type: ActionType, content: ActionContent, key_type: KeyType) -> Result<ActionReceipt>
fn chain_receipt(identity: &IdentityAnchor, previous: &ActionReceipt, action_type: ActionType, content: ActionContent) -> Result<ActionReceipt>
fn add_witness(receipt: &mut ActionReceipt, witness: &IdentityAnchor) -> Result<()>
```

## Trust Creation
```rust
fn create_trust_grant(grantor: &IdentityAnchor, grantee: &IdentityId, capabilities: Vec<Capability>, constraints: TrustConstraints) -> Result<TrustGrant>
fn delegate_trust(delegator: &IdentityAnchor, parent_grant: &TrustGrant, grantee: &IdentityId, capabilities: Vec<Capability>) -> Result<TrustGrant>
fn revoke_trust(revoker: &IdentityAnchor, trust_id: &TrustId, reason: RevocationReason, scope: RevocationScope) -> Result<Revocation>
```

## Continuity
```rust
fn record_experience(identity: &IdentityAnchor, event_type: ExperienceType, content_hash: &str) -> Result<ExperienceEvent>
fn create_anchor(identity: &IdentityAnchor, anchor_type: AnchorType) -> Result<ContinuityAnchor>
fn create_heartbeat(identity: &IdentityAnchor, status: HeartbeatStatus, health: HealthMetrics) -> Result<HeartbeatRecord>
fn create_continuity_claim(identity: &IdentityAnchor, claim_type: ClaimType, start: u64, end: u64) -> Result<ContinuityClaim>
```

## Spawn
```rust
fn spawn_child(parent: &IdentityAnchor, spawn_type: SpawnType, purpose: &str, authority: Vec<CapabilityUri>, lifetime: SpawnLifetime) -> Result<(IdentityAnchor, SpawnRecord, ActionReceipt)>
fn terminate_spawn(parent: &IdentityAnchor, child_id: &IdentityId, reason: &str) -> Result<ActionReceipt>
```

## Key Operations
```rust
fn derive_session_key(identity: &IdentityAnchor, session_id: &str, ttl: Duration) -> Result<DerivedKey>
fn derive_capability_key(identity: &IdentityAnchor, capability: &CapabilityUri) -> Result<DerivedKey>
fn rotate_key(identity: &mut IdentityAnchor, reason: RotationReason) -> Result<KeyRotation>
```
