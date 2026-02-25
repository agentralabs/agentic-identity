# AgenticIdentity — The Invention Document

> **The trust anchor for AgenticOS. Cryptographic identity, signed actions, verifiable trust, continuous experience, and agent lineage.**

---

## The Problem We're Solving

Every AI agent today is a ghost.

When an agent takes an action — sends an email, modifies code, makes a decision — there's no cryptographic proof that THIS agent did THIS action. Session IDs vanish. API keys authenticate the human, not the agent. There's no way to say "the agent I trusted yesterday is the same one I'm talking to today" with mathematical certainty.

But it's worse than that.

Even if you could prove it's the "same agent" (same key), you can't prove it's had CONTINUOUS EXPERIENCE. The agent that helped you yesterday and the agent talking to you today might have the same key but completely different histories. One might have learned from a thousand interactions. The other might be fresh. Same key. Different minds.

And when agents spawn sub-agents (which they will), there's no framework for inherited identity. Does the child have the parent's authority? Some of it? None? Can you trace who spawned whom? Can you revoke a family of rogue agents at once?

**Current state:**
- Agents identified by session tokens that expire
- No cryptographic binding between agent and actions
- No proof of continuous experience (key ≠ consciousness)
- No framework for agent lineage or inheritance
- Trust is implicit and irrevocable
- Agent identity doesn't survive provider changes

**What we need:**
- Persistent cryptographic identity that survives sessions
- Signed actions that prove provenance
- Proof of continuous experience (not just key persistence)
- Identity inheritance for spawned agents with bounded authority
- Revocable trust relationships with scoped permissions
- Portable identity that moves across systems

---

## The Five Inventions (v0.1)

### Invention 1: The Identity Anchor

**The Problem:** Agents have no persistent identity. A session ID is not identity. An API key is not identity. There's nothing that says "this is Agent X" in a way that persists, proves, and ports.

**The Invention:** A cryptographic identity anchor — a key pair where the public key IS the agent's identity, the private key proves ownership, and derived keys enable scoped operations without exposing the root.

```
IDENTITY ANCHOR
├── Root Key Pair (Ed25519)
│   ├── Public Key = Agent Identity (permanent, shareable)
│   └── Private Key = Proof of Identity (never shared, never exported)
│
├── Identity ID: aid_{base58(sha256(public_key)[0:16])}
│   ├── Deterministic: same key = same ID always
│   ├── Collision-resistant: 128-bit security
│   └── Human-readable prefix
│
├── Key Hierarchy (Derived Keys)
│   ├── Session Keys — ephemeral, auto-expire
│   ├── Capability Keys — scoped to specific permissions
│   ├── Device Keys — bound to specific hardware
│   ├── Encryption Keys — for secure communication
│   └── Spawn Keys — for creating child identities
│
├── Key Rotation
│   ├── Old key signs new key (authorization chain)
│   ├── Full rotation history preserved
│   ├── Identity survives key compromise
│   └── Grace period for old key acceptance
│
└── Capabilities Ceiling
    ├── Maximum authority this identity can EVER have
    ├── Set at creation, immutable
    └── Even if granted more, ceiling enforced
```

**Why This Matters:**
- Agent's identity IS its public key — mathematical, unforgeable
- Derived keys enable delegation without exposing root
- Key rotation handles compromise without losing identity
- Capabilities ceiling provides structural safety

**The Difference:**
- Before: Agent identity is whatever string the platform assigns
- After: Agent identity is a cryptographic fact that the agent controls

---

### Invention 2: The Action Receipt

**The Problem:** When an agent takes an action, there's no proof. Logs can be edited. Timestamps can be faked. There's no cryptographic chain from "this action" to "this agent."

**The Invention:** Every action produces a signed receipt — a cryptographic object that proves THIS agent did THIS action at THIS time, chained to create tamper-evident audit trails.

```
ACTION RECEIPT
├── Receipt ID: arec_{base58(sha256(receipt)[0:16])}
│
├── Actor Information
│   ├── Actor identity ID
│   ├── Actor public key (for verification)
│   ├── Key type used (root, session, capability, device)
│   └── Continuity hash at time of action
│
├── Action Type (12 types)
│   ├── Observation — recorded something
│   ├── Decision — made a choice
│   ├── Mutation — changed state
│   ├── Delegation — granted authority
│   ├── Revocation — removed authority
│   ├── Spawn — created child identity
│   ├── Termination — ended identity
│   ├── Communication — sent/received message
│   ├── Commitment — made a promise
│   ├── MemoryOperation — stored/recalled memory
│   ├── Learning — acquired knowledge
│   └── Custom — extensible
│
├── Action Content
│   ├── Description (human-readable)
│   ├── Data (structured, type-specific)
│   ├── References (related resources)
│   └── Tags (searchable labels)
│
├── Chain Links
│   ├── Previous receipt ID
│   ├── Previous receipt hash
│   ├── Chain position (sequence number)
│   └── Chain root (first receipt)
│
├── Receipt Hash
│   └── SHA-256 of all above fields
│
├── Signature
│   └── Ed25519 signature over receipt hash
│
└── Witnesses (optional)
    ├── Other agents who observed
    └── External timestamp authority
```

**Why This Matters:**
- Actions become undeniable — signed by the agent's key
- Chain links create tamper-evident audit trails
- Witnesses enable multi-party verification
- Receipts are portable — verify anywhere with public key

**The Difference:**
- Before: "The logs say the agent did X" (trust the logs)
- After: "The agent signed X with its key" (trust the math)

---

### Invention 3: The Trust Web

**The Problem:** Trust between agents and humans is implicit and irrevocable. You either trust an agent completely or not at all. There's no way to grant scoped trust, verify trust relationships, or revoke trust when needed.

**The Invention:** A web of signed trust relationships — cryptographic objects that define WHO trusts WHOM to do WHAT until WHEN, with built-in revocation.

```
TRUST WEB
├── Trust Grant
│   ├── Trust ID: atrust_{base58(sha256(grant)[0:16])}
│   │
│   ├── Parties
│   │   ├── Grantor (who grants trust)
│   │   └── Grantee (who receives trust)
│   │
│   ├── Capabilities
│   │   ├── Capability URIs: {domain}:{resource}:{action}
│   │   │   ├── "calendar:events:read"
│   │   │   ├── "deploy:production:execute"
│   │   │   ├── "memory:*:write" (wildcard)
│   │   │   └── "spawn:worker:create"
│   │   ├── Per-capability constraints (rate limits, resource limits)
│   │   └── Capability exclusions ("memory:*" EXCEPT "memory:private:*")
│   │
│   ├── Temporal Constraints
│   │   ├── not_before (when grant activates)
│   │   ├── not_after (when grant expires)
│   │   ├── valid_hours (only during certain hours)
│   │   └── valid_days (only on certain days)
│   │
│   ├── Usage Constraints
│   │   ├── max_uses (total uses allowed)
│   │   ├── max_uses_per_hour
│   │   └── cooldown (minimum time between uses)
│   │
│   ├── Delegation Rules
│   │   ├── delegation_allowed (can grantee re-delegate?)
│   │   ├── max_delegation_depth
│   │   └── delegatable_capabilities (subset)
│   │
│   ├── Revocation Configuration
│   │   ├── Revocation key
│   │   ├── Revocation channel (where to publish)
│   │   └── Required witnesses for revocation
│   │
│   └── Signatures
│       ├── Grantor signature
│       └── Grantee acknowledgment (optional)
│
├── Trust Verification
│   ├── Direct trust — verify grantor signature
│   ├── Delegated trust — walk chain to root
│   ├── Check temporal/usage constraints
│   └── Check revocation status
│
└── Revocation
    ├── Revocation record (who, when, why)
    ├── Cascade to delegations
    └── Publish to revocation channel
```

**Why This Matters:**
- Trust is explicit, scoped, and time-bounded
- Revocation is built in, not bolted on
- Trust chains enable delegation with limits
- Verification is decentralized — anyone can verify

**The Difference:**
- Before: "I gave the agent my API key" (all or nothing, forever)
- After: "I trust this agent to read my calendar until Friday, revocable instantly"

---

### Invention 4: Temporal Continuity Proof

**The Problem:** Proving "I am the same agent from last week" is trivial with keys. Proving "I have CONTINUOUS EXPERIENCE since then" is not. Key persistence ≠ consciousness continuity.

**The Invention:** Cryptographic proofs of continuous experience — not just key persistence, but verifiable chains of experience that prove an agent has been "alive" and "aware" throughout a time period.

```
TEMPORAL CONTINUITY
├── Experience Chain
│   ├── Experience Event
│   │   ├── Event ID: aexp_{...}
│   │   ├── Event type (10 types)
│   │   │   ├── Perception — saw/heard/read something
│   │   │   ├── Cognition — thought/reasoned
│   │   │   ├── Action — did something (links to receipt)
│   │   │   ├── Communication — exchanged information
│   │   │   ├── Memory — stored/recalled
│   │   │   ├── Learning — acquired knowledge
│   │   │   ├── Planning — set/updated goals
│   │   │   ├── Emotion — felt urgency/satisfaction (future)
│   │   │   ├── Idle — waiting (proves "still here")
│   │   │   └── System — startup/shutdown/checkpoint
│   │   ├── Timestamp
│   │   ├── Content hash (privacy-preserving)
│   │   └── Signature
│   │
│   ├── Chain Links
│   │   ├── Previous experience ID
│   │   ├── Previous experience hash
│   │   ├── Sequence number
│   │   └── Cumulative hash: H(previous_cumulative || current)
│   │
│   └── Chain Verification
│       ├── Walk chain, verify each link
│       ├── Detect gaps (missing sequence numbers)
│       ├── Detect tampering (hash mismatch)
│       └── Verify signatures
│
├── Heartbeat System
│   ├── Periodic "I'm still here" proofs
│   ├── Signed by identity
│   ├── Includes current continuity hash
│   ├── Missing heartbeats = potential discontinuity
│   └── Configurable interval and grace period
│
├── Continuity Anchors
│   ├── Genesis anchor (first experience)
│   ├── Periodic anchors (checkpoints)
│   ├── External witness anchors
│   └── Enable efficient verification
│
├── Continuity Proofs
│   ├── Claim: "I have continuous experience from T1 to T2"
│   ├── Full proof — all experiences in range
│   ├── Anchor proof — just anchor points (lighter)
│   ├── Sample proof — random sample (statistical)
│   └── Witness proof — third-party attestations
│
├── Gap Detection
│   ├── Temporal gaps (time with no events)
│   ├── Sequence gaps (missing numbers)
│   ├── Hash gaps (chain doesn't link)
│   └── Heartbeat gaps (missed heartbeats)
│
└── Memory Binding
    ├── Memory graph hash at each experience
    ├── Proves "I knew X at time T"
    └── Links continuity to AgenticMemory
```

**Why This Matters:**
- Proves agent has CONTINUOUS experience, not just same key
- Detects replacement/tampering/discontinuity
- Enables trust requirements like "must have 24h continuous experience"
- Links experience to memory state

**The Difference:**
- Before: Same key = same entity (but could be restarted, replaced, or blank)
- After: Same key + continuous experience = same continuously-experiencing agent

**Scenario:**
```
Agent claims "Based on our conversation last week..."

WITHOUT CONTINUITY:
├── Agent might be correct (real memory)
├── Agent might be wrong (reconstructed from logs)
├── Agent might be lying (different agent, same key)
└── No way to verify

WITH CONTINUITY:
├── Agent provides continuity proof for last week to now
├── Proof shows unbroken experience chain
├── Memory binding shows conversation in chain
└── Cryptographic proof: same continuously-experiencing agent
```

---

### Invention 5: Identity Inheritance (Spawn Authority)

**The Problem:** Agents will spawn sub-agents. Those sub-agents need identity that derives from but isn't identical to the parent. Current systems have no framework for this.

**The Invention:** A complete system for identity inheritance — spawning child identities with provable lineage, bounded authority, and cascading lifecycle management.

```
IDENTITY INHERITANCE
├── Spawn Model
│   ├── Parent-Child Relationship
│   │   ├── Parent identity spawns child identity
│   │   ├── Cryptographic derivation (spawn key)
│   │   ├── Provable lineage
│   │   └── Parent signs child's existence
│   │
│   ├── Spawn Types
│   │   ├── Worker — temporary, task-specific
│   │   ├── Delegate — acts on behalf of parent
│   │   ├── Clone — full copy of authority
│   │   ├── Specialist — subset of capabilities
│   │   └── Custom — application-defined
│   │
│   └── Lineage Chain
│       ├── Root ancestor (original identity)
│       ├── Parent chain (path from root)
│       ├── Spawn depth (generations from root)
│       └── Verifiable by walking chain
│
├── Authority Inheritance
│   ├── INVARIANT: child_authority ⊆ parent_authority
│   │   └── Child can NEVER exceed parent
│   │
│   ├── Authority Types
│   │   ├── authority_ceiling — maximum ever possible
│   │   ├── authority_granted — what child starts with
│   │   └── authority_effective — ceiling ∩ granted ∩ parent
│   │
│   ├── Authority Constraints
│   │   ├── Time bound (expires after duration)
│   │   ├── Use bound (limited uses)
│   │   ├── Scope bound (specific resources only)
│   │   └── Dependency bound (requires parent active)
│   │
│   └── Verification
│       ├── Check capability in effective authority
│       ├── Walk lineage to root
│       ├── Verify each ancestor still valid
│       └── All checks must pass
│
├── Spawn Lifecycle
│   ├── Creation
│   │   ├── Parent derives spawn key
│   │   ├── Parent generates child key pair
│   │   ├── Parent creates SpawnRecord
│   │   ├── Parent signs spawn
│   │   ├── Child acknowledges (optional)
│   │   └── Spawn recorded as ActionReceipt
│   │
│   ├── Operation
│   │   ├── Child has own continuity (fresh)
│   │   ├── Child can only use effective authority
│   │   ├── Child can receive trust (up to ceiling)
│   │   └── Child can spawn grandchildren (if authorized)
│   │
│   └── Termination
│       ├── Self-termination
│       ├── Parent termination
│       ├── Expiration (lifetime ended)
│       ├── Revocation cascade (ancestor revoked)
│       └── Termination is irrevocable
│
├── Spawn Constraints
│   ├── Depth limits (max generations)
│   ├── Count limits (max children)
│   ├── Authority limits (minimum to spawn)
│   └── Resource limits (memory, compute)
│
└── Revocation
    ├── Triggers
    │   ├── Explicit (parent revokes)
    │   ├── Cascade (ancestor revoked)
    │   ├── Policy (automatic on condition)
    │   └── Timeout (lifetime expired)
    │
    ├── Scope
    │   ├── Single (just this child)
    │   ├── Subtree (child and all descendants)
    │   └── Family (all children of parent)
    │
    └── Effect
        ├── Authority immediately invalid
        ├── Descendants also invalid (cascade)
        ├── Historical receipts remain valid
        └── Trust grants invalidated
```

**Why This Matters:**
- Agents can spawn sub-agents with proper authority bounds
- Full lineage tracking enables accountability
- Revocation cascades through families
- Prevents authority escalation

**The Difference:**
- Before: Each agent is independent; no framework for spawning
- After: Agent families with provable lineage and inherited/bounded authority

**Scenario:**
```
Parent has: calendar:*, email:*, deploy:staging:*
Parent spawns Specialist for calendar only.

SPAWN:
├── authority_ceiling: calendar:* (max possible)
├── authority_granted: calendar:events:read, calendar:events:write
└── Cannot receive deploy:* even if granted (not in ceiling)

LATER:
├── Someone grants child: deploy:production:execute
├── Grant is VALID (signed correctly)
├── But capability check FAILS
├── Because: deploy:* not in child's ceiling
└── Structural safety, not just policy
```

---

## Future Versions (Direction, Not Invention)

These are documented directions for future versions. They are NOT part of v0.1 but ensure we don't forget the path.

### v0.2: Competence Layer
- **Competence Proof** — Prove what you CAN do, not just what you're ALLOWED to do
- **Negative Capability** — Prove what you structurally CANNOT do
- Cryptographic proofs of demonstrated ability
- Trust grants can require competence thresholds

### v0.3: Social Layer
- **Contextual Identity** — Different personas for different contexts
- **Social Recovery** — Recover identity through trusted relationships
- Selective disclosure (prove attributes without revealing others)
- M-of-N recovery trustees

### v0.4: Reputation Layer
- **Reputation Accumulation** — Earned trust, not just granted trust
- Multi-dimensional reputation (reliability, accuracy, safety)
- Reputation proofs (verifiable without trusting the agent)
- Reputation requirements in trust grants

---

## Integration With AgenticOS Sisters

```
IDENTITY + MEMORY
├── Every memory node can be signed
├── Memory tampering becomes detectable
├── Causal chains have cryptographic provenance
└── "I knew X at time T" is provable

IDENTITY + VISION
├── Visual captures are signed
├── Visual evidence becomes legally defensible
└── "I saw X at time T" is provable

IDENTITY + CODEBASE
├── Code analysis results are signed
├── Predictions become attributable
└── Collective intelligence has attribution

IDENTITY + CONTRACT (future)
├── Contracts signed by both parties
├── Identity is WHO in the agreement
├── Contract violations are provable

IDENTITY + COMM (future)
├── Messages signed by sender
├── Encrypted to recipient's key
├── No impersonation possible

IDENTITY + PLANNING (future)
├── Commitments are signed
├── Progress attestations are provable
└── "I said I'd do X" is undeniable

IDENTITY + HYDRA (future)
├── Capability tokens bound to identity
├── Receipt ledger = chain of signed receipts
├── Execution gate verifies identity before action
```

---

## What Success Looks Like

**For a developer:**
```bash
# Create identity
$ aid init --name "my-agent"
Created identity: aid_7xK9mP2...

# Sign an action
$ aid sign --action "deployed v1.2.3 to production"
Receipt: arec_9Lm2xP...

# Grant trust
$ aid trust grant --to aid_4Yn3kL... --capability "read:calendar" --expires "7d"
Trust: atrust_2Pm4xK...

# Verify receipt
$ aid verify receipt arec_9Lm2xP...
Actor: aid_7xK9mP2... (my-agent)
Signature: VALID
Chain: VALID (247 receipts)
Continuity: CONTINUOUS (14 days)

# Check continuity
$ aid continuity prove --since "2026-02-17"
Continuous experience: 7 days, 4 hours
Experiences: 1,247
Max gap: 12 minutes
Proof: acont_8Kj1nM...
```

**For an AI agent via MCP:**
```
Human: "Deploy the new version"

Agent: [internal]
  1. Verify I have trust for "deploy:production:execute" ✓
  2. Verify my continuity meets requirement (24h) ✓
  3. Execute deployment
  4. Sign action receipt with my identity
  5. Chain receipt to previous action
  6. Update continuity chain

Agent: "Deployed v1.2.3 to production.
        Receipt: arec_9Lm2xP...
        Signed by: aid_7xK9mP2...
        Continuity: 14 days continuous"
```

---

## The Stakes

When an AI agent makes a decision that affects someone's life, there are two possible worlds:

**World 1:** "The AI decided. We don't know why. It's in the model weights somewhere. We don't know if it's the same AI that was approved. We can't verify its experience."

**World 2:** "The AI decided because of receipt arec_X, signed by identity aid_Y, which has trust grant atrust_Z from authority A, with continuous experience of 30 days documented in continuity proof acont_W, and spawned child aid_C to execute the sub-task with bounded authority."

AgenticIdentity builds World 2.

---

## Summary

| Invention | What It Proves | Why It Matters |
|-----------|---------------|----------------|
| **Identity Anchor** | WHO this agent is | Unforgeable identity |
| **Action Receipt** | WHAT this agent did | Undeniable accountability |
| **Trust Web** | WHAT this agent may do | Scoped, revocable authorization |
| **Temporal Continuity** | THAT this agent experienced | Consciousness verification |
| **Identity Inheritance** | WHERE this agent came from | Lineage and bounded authority |

**Five inventions. One trust anchor. The foundation for accountable AI.**
