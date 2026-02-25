# Identity v0.1 Completion — Competence Proof + Negative Capability

> **Goal:** Add inventions 4 and 5 to complete v0.1 with 7 inventions

---

## Current State

```
IDENTITY v0.1
─────────────
1. Identity Anchor        ✅ BUILT
2. Action Receipts        ✅ BUILT
3. Trust Web              ✅ BUILT
4. Competence Proof       ❌ NOT BUILT
5. Negative Capability    ❌ NOT BUILT
7. Temporal Continuity    ✅ BUILT
8. Identity Inheritance   ✅ BUILT
```

---

## Invention 4: Competence Proof

### The Problem

Trust grants answer "what is this agent ALLOWED to do?" but not "what CAN this agent actually do?" An agent might have permission to deploy but zero track record. Current systems conflate authorization with ability.

### The Invention

Cryptographic proofs of demonstrated competence — verifiable track records that prove an agent has successfully performed a capability, not just that they're authorized to.

### Data Structures

```rust
// src/competence/mod.rs

/// Competence domain identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompetenceDomain(pub String);

impl CompetenceDomain {
    /// Standard domains
    pub const DEPLOY: &'static str = "deploy";
    pub const CODE_REVIEW: &'static str = "code_review";
    pub const DATA_ANALYSIS: &'static str = "data_analysis";
    pub const COMMUNICATION: &'static str = "communication";
    pub const PLANNING: &'static str = "planning";
    pub const MEMORY_MANAGEMENT: &'static str = "memory_management";
    
    /// Custom domain
    pub fn custom(domain: &str) -> Self {
        Self(domain.to_string())
    }
}

/// Outcome of an attempt
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttemptOutcome {
    Success,
    Failure { reason: String },
    Partial { score: f32 },  // 0.0 - 1.0
}

/// Record of a single competence attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceAttempt {
    pub attempt_id: AttemptId,
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub outcome: AttemptOutcome,
    pub timestamp: u64,
    pub receipt_id: ReceiptId,  // Links to the action receipt
    pub context: Option<String>,
    pub validator: Option<IdentityId>,  // Who validated the outcome
    pub validator_signature: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(pub String);

/// Aggregated competence record for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceRecord {
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub total_attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub partial_sum: f32,  // Sum of partial scores
    pub partial_count: u64,
    pub success_rate: f32,  // Calculated: (successes + partial_sum) / total
    pub first_attempt: u64,  // Timestamp
    pub last_attempt: u64,
    pub streak_current: i32,  // Positive = success streak, negative = failure
    pub streak_best: u32,
    pub evidence: Vec<AttemptId>,  // Recent attempts for verification
}

impl CompetenceRecord {
    pub fn new(identity: IdentityId, domain: CompetenceDomain) -> Self {
        Self {
            identity,
            domain,
            total_attempts: 0,
            successes: 0,
            failures: 0,
            partial_sum: 0.0,
            partial_count: 0,
            success_rate: 0.0,
            first_attempt: 0,
            last_attempt: 0,
            streak_current: 0,
            streak_best: 0,
            evidence: Vec::new(),
        }
    }
    
    pub fn record_attempt(&mut self, attempt: &CompetenceAttempt) {
        self.total_attempts += 1;
        self.last_attempt = attempt.timestamp;
        if self.first_attempt == 0 {
            self.first_attempt = attempt.timestamp;
        }
        
        match &attempt.outcome {
            AttemptOutcome::Success => {
                self.successes += 1;
                if self.streak_current >= 0 {
                    self.streak_current += 1;
                } else {
                    self.streak_current = 1;
                }
            }
            AttemptOutcome::Failure { .. } => {
                self.failures += 1;
                if self.streak_current <= 0 {
                    self.streak_current -= 1;
                } else {
                    self.streak_current = -1;
                }
            }
            AttemptOutcome::Partial { score } => {
                self.partial_sum += score;
                self.partial_count += 1;
                // Partial counts as success for streak if >= 0.5
                if *score >= 0.5 {
                    if self.streak_current >= 0 {
                        self.streak_current += 1;
                    } else {
                        self.streak_current = 1;
                    }
                } else {
                    if self.streak_current <= 0 {
                        self.streak_current -= 1;
                    } else {
                        self.streak_current = -1;
                    }
                }
            }
        }
        
        if self.streak_current > 0 && self.streak_current as u32 > self.streak_best {
            self.streak_best = self.streak_current as u32;
        }
        
        // Recalculate success rate
        let effective_successes = self.successes as f32 + self.partial_sum;
        self.success_rate = effective_successes / self.total_attempts as f32;
        
        // Keep recent evidence (last 100)
        self.evidence.push(attempt.attempt_id.clone());
        if self.evidence.len() > 100 {
            self.evidence.remove(0);
        }
    }
}

/// Competence proof - cryptographic claim of ability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceProof {
    pub proof_id: ProofId,
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub claim: CompetenceClaim,
    pub evidence_sample: Vec<AttemptId>,  // Sample of attempts as evidence
    pub evidence_count: u64,
    pub generated_at: u64,
    pub valid_until: Option<u64>,  // Proof can expire
    pub proof_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub String);

/// What the proof claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceClaim {
    pub min_attempts: u64,
    pub min_success_rate: f32,
    pub min_streak: Option<u32>,
    pub recency_window: Option<u64>,  // Only count attempts within N seconds
    pub actual_attempts: u64,
    pub actual_success_rate: f32,
    pub actual_streak: i32,
}

/// Competence requirement in trust grants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetenceRequirement {
    pub domain: CompetenceDomain,
    pub min_attempts: u64,
    pub min_success_rate: f32,
    pub min_streak: Option<u32>,
    pub max_age_seconds: Option<u64>,  // Proof must be recent
}

/// Competence verification result
#[derive(Debug, Clone)]
pub struct CompetenceVerification {
    pub identity: IdentityId,
    pub domain: CompetenceDomain,
    pub requirement: CompetenceRequirement,
    pub proof: Option<CompetenceProof>,
    pub meets_attempts: bool,
    pub meets_rate: bool,
    pub meets_streak: bool,
    pub meets_recency: bool,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}
```

### Functions to Implement

```rust
// src/competence/engine.rs

/// Record a competence attempt
pub fn record_attempt(
    identity: &IdentityAnchor,
    domain: CompetenceDomain,
    outcome: AttemptOutcome,
    receipt_id: ReceiptId,
    validator: Option<&IdentityAnchor>,
) -> Result<CompetenceAttempt, IdentityError>;

/// Get competence record for identity + domain
pub fn get_competence(
    identity: &IdentityId,
    domain: &CompetenceDomain,
    store: &impl CompetenceStore,
) -> Result<Option<CompetenceRecord>, IdentityError>;

/// Generate competence proof
pub fn generate_proof(
    identity: &IdentityAnchor,
    domain: CompetenceDomain,
    claim: CompetenceClaim,
    store: &impl CompetenceStore,
) -> Result<CompetenceProof, IdentityError>;

/// Verify competence proof
pub fn verify_proof(
    proof: &CompetenceProof,
    store: &impl CompetenceStore,
) -> Result<CompetenceVerification, IdentityError>;

/// Check if identity meets competence requirement
pub fn check_competence(
    identity: &IdentityId,
    requirement: &CompetenceRequirement,
    store: &impl CompetenceStore,
) -> Result<CompetenceVerification, IdentityError>;

/// List all competence domains for identity
pub fn list_competences(
    identity: &IdentityId,
    store: &impl CompetenceStore,
) -> Result<Vec<CompetenceRecord>, IdentityError>;
```

### Trust Integration

```rust
// Update TrustGrant to include competence requirements

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    // ... existing fields ...
    
    /// Competence requirements (identity must prove ability)
    pub competence_requirements: Vec<CompetenceRequirement>,
}

// Update trust verification

pub fn verify_trust(
    identity: &IdentityId,
    capability: &CapabilityUri,
    context: Option<&VerificationContext>,
    competence_store: &impl CompetenceStore,  // Add this
) -> Result<TrustVerification, IdentityError> {
    // ... existing checks ...
    
    // Check competence requirements
    for requirement in &grant.competence_requirements {
        let competence_check = check_competence(identity, requirement, competence_store)?;
        if !competence_check.is_valid {
            return Err(IdentityError::CompetenceNotMet {
                domain: requirement.domain.clone(),
                required_rate: requirement.min_success_rate,
                actual_rate: competence_check.proof
                    .map(|p| p.claim.actual_success_rate)
                    .unwrap_or(0.0),
            });
        }
    }
    
    // ... rest of verification ...
}
```

### Tests (12 scenarios)

```rust
#[cfg(test)]
mod competence_tests {
    // 1. Record successful attempt
    // 2. Record failed attempt
    // 3. Record partial attempt
    // 4. Success rate calculation correct
    // 5. Streak tracking works
    // 6. Generate proof succeeds when criteria met
    // 7. Generate proof fails when criteria not met
    // 8. Verify valid proof succeeds
    // 9. Verify tampered proof fails
    // 10. Trust grant with competence requirement - met
    // 11. Trust grant with competence requirement - not met
    // 12. Competence proof expiration works
}
```

---

## Invention 5: Negative Capability Proof

### The Problem

Agents can prove what they CAN do (competence) and what they're ALLOWED to do (trust). But sometimes you need to prove what an agent structurally CANNOT do — not by policy, but by cryptographic impossibility.

### The Invention

Proofs of structural impossibility — cryptographic evidence that an agent cannot perform certain actions, regardless of what permissions they might be granted.

### Data Structures

```rust
// src/negative/mod.rs

/// Reason why capability is impossible
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImpossibilityReason {
    /// Not in identity's capabilities ceiling
    NotInCeiling,
    
    /// No ancestor in lineage has this capability
    NotInLineage,
    
    /// Explicitly excluded at spawn time
    SpawnExclusion { spawn_id: SpawnId },
    
    /// Capability structurally doesn't exist
    CapabilityNonexistent,
    
    /// Key cannot sign for this domain
    KeyRestriction { key_purpose: KeyPurpose },
    
    /// Time-locked impossibility
    TimeLocked { unlocks_at: u64 },
    
    /// Quorum requirement impossible (not enough trustees)
    QuorumImpossible { required: u32, available: u32 },
}

/// Negative capability proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeCapabilityProof {
    pub proof_id: NegativeProofId,
    pub identity: IdentityId,
    pub cannot_do: CapabilityUri,
    pub reason: ImpossibilityReason,
    pub evidence: NegativeEvidence,
    pub generated_at: u64,
    pub valid_until: Option<u64>,
    pub proof_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NegativeProofId(pub String);

/// Evidence supporting the impossibility claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NegativeEvidence {
    /// Ceiling proof - show the ceiling doesn't include capability
    CeilingExclusion {
        ceiling: Vec<CapabilityUri>,
        ceiling_hash: String,
        identity_signature: String,
    },
    
    /// Lineage proof - show no ancestor has capability
    LineageExclusion {
        lineage: Vec<IdentityId>,
        ancestor_ceilings: Vec<(IdentityId, Vec<CapabilityUri>)>,
        lineage_hash: String,
    },
    
    /// Spawn exclusion - show spawn record explicitly excludes
    SpawnExclusion {
        spawn_id: SpawnId,
        spawn_record_hash: String,
        exclusions: Vec<CapabilityUri>,
    },
    
    /// Key restriction - show key derivation path excludes
    KeyRestriction {
        key_purpose: KeyPurpose,
        derivation_path: String,
        allowed_capabilities: Vec<CapabilityUri>,
    },
    
    /// Time lock - show unlock time
    TimeLock {
        lock_id: String,
        unlocks_at: u64,
        current_time: u64,
    },
}

/// Request for negative proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeProofRequest {
    pub identity: IdentityId,
    pub capability: CapabilityUri,
    pub requestor: Option<IdentityId>,
    pub purpose: Option<String>,
}

/// Verification result for negative proof
#[derive(Debug, Clone)]
pub struct NegativeVerification {
    pub proof_id: NegativeProofId,
    pub identity: IdentityId,
    pub capability: CapabilityUri,
    pub reason_valid: bool,
    pub evidence_valid: bool,
    pub signature_valid: bool,
    pub is_valid: bool,
    pub verified_at: u64,
    pub errors: Vec<String>,
}

/// Negative capability declaration (voluntary restriction)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeDeclaration {
    pub declaration_id: DeclarationId,
    pub identity: IdentityId,
    pub cannot_do: Vec<CapabilityUri>,
    pub reason: String,
    pub declared_at: u64,
    pub permanent: bool,  // If true, cannot be undone
    pub witnesses: Vec<WitnessSignature>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeclarationId(pub String);
```

### Functions to Implement

```rust
// src/negative/engine.rs

/// Generate negative capability proof
pub fn prove_cannot(
    identity: &IdentityAnchor,
    capability: &CapabilityUri,
    store: &impl IdentityStore,
    spawn_store: &impl SpawnStore,
) -> Result<NegativeCapabilityProof, IdentityError>;

/// Verify negative capability proof
pub fn verify_negative_proof(
    proof: &NegativeCapabilityProof,
    store: &impl IdentityStore,
    spawn_store: &impl SpawnStore,
) -> Result<NegativeVerification, IdentityError>;

/// Check if capability is impossible for identity
pub fn is_impossible(
    identity: &IdentityId,
    capability: &CapabilityUri,
    store: &impl IdentityStore,
    spawn_store: &impl SpawnStore,
) -> Result<Option<ImpossibilityReason>, IdentityError>;

/// Create voluntary negative declaration
pub fn declare_cannot(
    identity: &IdentityAnchor,
    capabilities: Vec<CapabilityUri>,
    reason: &str,
    permanent: bool,
    witnesses: Vec<&IdentityAnchor>,
) -> Result<NegativeDeclaration, IdentityError>;

/// List all negative declarations for identity
pub fn list_declarations(
    identity: &IdentityId,
    store: &impl NegativeStore,
) -> Result<Vec<NegativeDeclaration>, IdentityError>;

/// Get all capabilities identity structurally cannot do
pub fn get_impossibilities(
    identity: &IdentityId,
    store: &impl IdentityStore,
    spawn_store: &impl SpawnStore,
) -> Result<Vec<(CapabilityUri, ImpossibilityReason)>, IdentityError>;
```

### Ceiling Integration

```rust
// The capabilities ceiling already exists - enhance it

impl IdentityAnchor {
    /// Check if capability is in ceiling
    pub fn ceiling_allows(&self, capability: &CapabilityUri) -> bool {
        self.capabilities_ceiling.iter().any(|c| c.matches(capability))
    }
    
    /// Get capabilities NOT in ceiling (provably impossible)
    pub fn ceiling_excludes(&self, capabilities: &[CapabilityUri]) -> Vec<CapabilityUri> {
        capabilities
            .iter()
            .filter(|c| !self.ceiling_allows(c))
            .cloned()
            .collect()
    }
}

// Spawn already enforces child ⊆ parent - enhance for negative proofs

impl SpawnRecord {
    /// Get capabilities explicitly excluded at spawn
    pub fn excluded_capabilities(&self) -> Vec<CapabilityUri> {
        // Parent ceiling minus child ceiling = what child cannot do
        // that parent could do
        self.authority_ceiling
            .iter()
            .filter(|c| !self.authority_granted.iter().any(|g| g.matches(c)))
            .cloned()
            .collect()
    }
}
```

### Tests (12 scenarios)

```rust
#[cfg(test)]
mod negative_tests {
    // 1. Prove cannot - not in ceiling
    // 2. Prove cannot - not in lineage
    // 3. Prove cannot - spawn exclusion
    // 4. Verify valid negative proof
    // 5. Verify invalid negative proof (actually CAN do it)
    // 6. is_impossible returns correct reason
    // 7. is_impossible returns None when possible
    // 8. Voluntary declaration creates proof
    // 9. Permanent declaration cannot be undone
    // 10. Lineage proof walks entire ancestry
    // 11. Ceiling hash prevents tampering
    // 12. Spawned child inherits impossibilities from parent
}
```

---

## CLI Additions

```bash
# Competence commands
aid competence record --domain deploy --outcome success --receipt arec_xxx
aid competence record --domain deploy --outcome failure --reason "timeout"
aid competence record --domain code_review --outcome partial --score 0.8
aid competence show [--domain DOMAIN]
aid competence prove --domain deploy --min-rate 0.95 --min-attempts 100
aid competence verify PROOF_ID
aid competence list

# Negative capability commands
aid cannot prove CAPABILITY
aid cannot verify PROOF_ID
aid cannot declare CAPABILITY [CAPABILITY...] --reason "security policy" [--permanent]
aid cannot list
aid cannot check CAPABILITY  # Quick check if impossible
```

---

## MCP Additions

```rust
// Competence tools
competence_record     // Record attempt outcome
competence_show       // Get competence record
competence_prove      // Generate competence proof
competence_verify     // Verify competence proof
competence_list       // List all competence domains

// Negative tools
negative_prove        // Generate negative capability proof
negative_verify       // Verify negative proof
negative_declare      // Create voluntary restriction
negative_list         // List declarations
negative_check        // Quick impossibility check

// Resources
competence://{identity}/{domain}  // Competence record
competence://{identity}           // All competence records
negative://{identity}             // All negative proofs/declarations
```

---

## Storage Additions

```
~/.agentic-identity/
├── competence/
│   └── {identity_id}/
│       ├── attempts/
│       │   └── {attempt_id}.attempt
│       ├── records/
│       │   └── {domain}.record
│       └── proofs/
│           └── {proof_id}.proof
└── negative/
    └── {identity_id}/
        ├── proofs/
        │   └── {proof_id}.negproof
        └── declarations/
            └── {declaration_id}.decl
```

---

## Error Additions

```rust
#[derive(Debug, Error)]
pub enum IdentityError {
    // ... existing errors ...
    
    // Competence errors
    #[error("Competence not met for {domain}: required {required_rate}%, actual {actual_rate}%")]
    CompetenceNotMet {
        domain: String,
        required_rate: f32,
        actual_rate: f32,
    },
    
    #[error("Insufficient attempts: required {required}, actual {actual}")]
    InsufficientAttempts { required: u64, actual: u64 },
    
    #[error("Competence proof expired")]
    CompetenceProofExpired,
    
    // Negative errors
    #[error("Cannot prove impossibility: identity CAN do {capability}")]
    NotImpossible { capability: String },
    
    #[error("Invalid negative proof: {reason}")]
    InvalidNegativeProof { reason: String },
    
    #[error("Permanent declaration cannot be revoked")]
    PermanentDeclaration,
}
```

---

## Success Criteria

```
[ ] CompetenceAttempt recording works
[ ] CompetenceRecord aggregation correct
[ ] Success rate calculation accurate
[ ] Streak tracking works
[ ] CompetenceProof generation works
[ ] CompetenceProof verification works
[ ] Trust grants with competence requirements work
[ ] Competence requirement enforcement works

[ ] NegativeCapabilityProof generation works
[ ] Ceiling-based impossibility proofs work
[ ] Lineage-based impossibility proofs work
[ ] Spawn exclusion proofs work
[ ] NegativeVerification works
[ ] Voluntary declarations work
[ ] Permanent declarations are enforced
[ ] is_impossible correctly identifies all cases

[ ] CLI commands for competence work
[ ] CLI commands for negative work
[ ] MCP tools for competence work
[ ] MCP tools for negative work

[ ] 24 new tests (12 competence + 12 negative)
[ ] Integration with existing trust verification
```

---

## Summary

After adding Competence (4) and Negative Capability (5):

```
IDENTITY v0.1 — 7 INVENTIONS
────────────────────────────
1. Identity Anchor        ✅
2. Action Receipts        ✅
3. Trust Web              ✅
4. Competence Proof       ✅ (after this)
5. Negative Capability    ✅ (after this)
7. Temporal Continuity    ✅
8. Identity Inheritance   ✅

WHAT EACH PROVES
────────────────
1. WHO this agent is
2. WHAT this agent did
3. WHAT this agent may do
4. WHAT this agent CAN do (demonstrated ability)
5. WHAT this agent CANNOT do (structural impossibility)
7. THAT this agent has continuous experience
8. WHERE this agent came from (lineage)

FUTURE (v0.2+)
──────────────
6. Contextual Identity
9. Social Recovery
10. Reputation Accumulation
```
