---
status: stable
---

# AgenticIdentity Docs

Cryptographic identity, trust, and accountability for AI agents.

---

## What is AgenticIdentity?

AgenticIdentity gives AI agents a persistent, verifiable identity. Every action is signed, every permission is tracked, and the agent can prove its entire history.

**Core capabilities:**
- Cryptographic identity anchors
- Signed action receipts
- Trust web (permissions)
- Competence proof (demonstrated ability)
- Negative capability proof (what agent CAN'T do)
- Temporal continuity (unbroken experience chain)
- Identity inheritance (spawn lineage)

---

## Quick Install

**MCP (Claude Desktop, Cursor, Windsurf):**

```bash
curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/scripts/install.sh | bash
```

**Python:**

```bash
pip install agentic-identity
```

**Rust:**

```bash
cargo install agentic-identity-cli
```

**JavaScript:**

```bash
npm install @agenticamem/identity
```

---

## Core Capabilities

### 1. Identity Anchor

A cryptographic root identity for the agent.

```bash
aid init --name "my-agent"
```

Creates a keypair. The public key IS the agent's identity. Portable, verifiable, permanent.

### 2. Action Receipts

Every significant action gets signed.

```bash
aid sign --action "deployed v1.2.0 to production"
```

Creates tamper-evident proof: this agent did this action at this time.

### 3. Trust Web

Permissions granted between identities.

```bash
aid trust grant --to agent-123 --capability "deploy:staging" --expires 30d
```

Delegatable, revocable, time-bounded authority.

### 4. Competence Proof

Demonstrated ability, not just authorization.

```bash
aid competence record --domain "rust-development" --outcome success
aid competence prove --domain "rust-development"
```

Tracks success rates, streaks, and generates verifiable competence proofs.

### 5. Negative Capability Proof

Prove what the agent CANNOT do (structural impossibility).

```bash
aid cannot prove --capability "access:production-db"
```

Not policy — structural proof that the agent lacks the keys/authority.

### 6. Temporal Continuity

Unbroken chain of experience since genesis.

```bash
aid experience record --content "completed first deployment"
aid continuity prove
```

Proves continuous existence — no gaps, no imposters.

### 7. Identity Inheritance

Track spawn lineage (parent → child agents).

```bash
aid spawn create --name "worker-agent" --authority "subset"
```

Children inherit bounded authority from parents. Full lineage tracked.

---

## MCP Tools (30 total)

| Category | Tools |
|----------|-------|
| **Anchor** | `identity_create`, `identity_show`, `identity_verify`, `identity_export`, `identity_import` |
| **Receipts** | `action_sign`, `action_verify`, `action_list`, `action_chain`, `action_receipt` |
| **Trust** | `trust_grant`, `trust_revoke`, `trust_verify`, `trust_list`, `trust_delegation` |
| **Competence** | `competence_record`, `competence_show`, `competence_prove`, `competence_verify`, `competence_list` |
| **Negative** | `negative_prove`, `negative_verify`, `negative_declare`, `negative_list`, `negative_check` |
| **Continuity** | `experience_record`, `experience_list`, `continuity_prove`, `continuity_verify`, `continuity_chain` |
| **Spawn** | `spawn_create`, `spawn_list`, `spawn_verify`, `spawn_lineage`, `spawn_authority` |

---

## Use Cases

**Multi-agent systems:** Agents verify each other's identity before collaboration.

**Audit trails:** Every action signed — complete accountability.

**Permission management:** Grant, revoke, delegate authority with cryptographic proof.

**Agent reputation:** Competence proofs build verifiable track record.

**Security boundaries:** Negative proofs show what agent cannot access.

---

## File Format

Identity data stored in `.aid` files — portable, encrypted, user-owned.

```
~/.agentic/identity/
├── anchor.aid       # Root identity
├── receipts.aid     # Action history
├── trust.aid        # Permission grants
└── continuity.aid   # Experience chain
```

---

## Next Steps

- [Installation Guide](/docs/en/identity-installation)
- [Command Surface](/docs/en/identity-command-surface)
- [Core Concepts](/docs/en/identity-concepts)
- [API Reference](/docs/en/identity-api-reference)
