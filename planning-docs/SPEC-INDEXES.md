# SPEC-INDEXES.md

## Receipt Indexes
- `receipts_by_actor`: BTreeMap<IdentityId, Vec<ReceiptId>>
- `receipts_by_type`: BTreeMap<ActionType, Vec<ReceiptId>>
- `receipts_by_time`: BTreeMap<u64, Vec<ReceiptId>>
- `receipt_chain`: BTreeMap<(IdentityId, u64), ReceiptId> // (actor, position) -> id

## Trust Indexes
- `trust_by_grantor`: BTreeMap<IdentityId, Vec<TrustId>>
- `trust_by_grantee`: BTreeMap<IdentityId, Vec<TrustId>>
- `trust_by_capability`: BTreeMap<CapabilityUri, Vec<TrustId>>
- `revocations`: HashSet<TrustId>
- `delegation_chains`: BTreeMap<TrustId, TrustId> // child -> parent

## Experience Indexes
- `experiences_by_identity`: BTreeMap<IdentityId, Vec<ExperienceId>>
- `experiences_by_time`: BTreeMap<(IdentityId, u64), ExperienceId>
- `experience_chain`: BTreeMap<(IdentityId, u64), ExperienceId> // (identity, seq) -> id
- `anchors`: BTreeMap<IdentityId, Vec<AnchorId>>
- `heartbeats`: BTreeMap<(IdentityId, u64), HeartbeatId>

## Spawn Indexes
- `spawn_by_parent`: BTreeMap<IdentityId, Vec<SpawnId>>
- `spawn_by_child`: BTreeMap<IdentityId, SpawnId>
- `lineage_cache`: BTreeMap<IdentityId, Vec<IdentityId>> // child -> ancestors
- `active_spawns`: HashSet<IdentityId>
- `terminated_spawns`: HashSet<IdentityId>

## Performance Requirements
- Index lookup: O(log n)
- Range query: O(log n + k) where k = results
- Capability matching with wildcards: O(m) where m = capability parts
