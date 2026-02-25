# SPEC-QUERY-ENGINE.md

## Verification Queries
```rust
fn verify_receipt(receipt: &ActionReceipt) -> Result<ReceiptVerification>
fn verify_receipt_chain(receipts: &[ActionReceipt]) -> Result<Vec<ReceiptVerification>>
fn verify_trust(identity: &IdentityId, capability: &CapabilityUri, context: Option<&VerificationContext>) -> Result<TrustVerification>
fn verify_continuity(claim: &ContinuityClaim, proof_type: ProofType) -> Result<ContinuityVerification>
fn verify_lineage(identity: &IdentityId) -> Result<LineageVerification>
```

## Receipt Queries
```rust
fn get_receipt(id: &ReceiptId) -> Result<Option<ActionReceipt>>
fn get_receipts_by_actor(actor: &IdentityId, limit: usize) -> Result<Vec<ActionReceipt>>
fn get_receipts_by_type(actor: &IdentityId, action_type: ActionType) -> Result<Vec<ActionReceipt>>
fn get_receipts_in_range(actor: &IdentityId, start: u64, end: u64) -> Result<Vec<ActionReceipt>>
fn get_receipt_chain(actor: &IdentityId, from: u64, to: u64) -> Result<Vec<ActionReceipt>>
```

## Trust Queries
```rust
fn get_trust_grant(id: &TrustId) -> Result<Option<TrustGrant>>
fn get_grants_to(grantee: &IdentityId) -> Result<Vec<TrustGrant>>
fn get_grants_from(grantor: &IdentityId) -> Result<Vec<TrustGrant>>
fn get_effective_capabilities(identity: &IdentityId) -> Result<Vec<CapabilityUri>>
fn is_revoked(trust_id: &TrustId) -> Result<bool>
fn get_trust_chain(trust_id: &TrustId) -> Result<Vec<TrustGrant>>
```

## Continuity Queries
```rust
fn get_experience(id: &ExperienceId) -> Result<Option<ExperienceEvent>>
fn get_experiences_in_range(identity: &IdentityId, start: u64, end: u64) -> Result<Vec<ExperienceEvent>>
fn get_continuity_state(identity: &IdentityId) -> Result<ContinuityState>
fn get_anchors(identity: &IdentityId) -> Result<Vec<ContinuityAnchor>>
fn get_heartbeats(identity: &IdentityId, limit: usize) -> Result<Vec<HeartbeatRecord>>
fn detect_gaps(identity: &IdentityId, start: u64, end: u64) -> Result<Vec<Gap>>
```

## Spawn Queries
```rust
fn get_spawn_record(id: &SpawnId) -> Result<Option<SpawnRecord>>
fn get_children(parent: &IdentityId) -> Result<Vec<IdentityId>>
fn get_descendants(ancestor: &IdentityId) -> Result<Vec<IdentityId>>
fn get_ancestors(identity: &IdentityId) -> Result<Vec<IdentityId>>
fn get_lineage(identity: &IdentityId) -> Result<Lineage>
fn get_effective_authority(identity: &IdentityId) -> Result<Vec<CapabilityUri>>
```
