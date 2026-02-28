---
status: stable
---

# Experience: With vs Without AgenticIdentity

## Comparison

| Aspect | Without AgenticIdentity | With AgenticIdentity |
|--------|------------------------|---------------------|
| Action attribution | Anonymous and untraceable | Every action is cryptographically signed with Ed25519 |
| Audit trail | No record of agent decisions | Receipts provide tamper-evident, chained audit trails |
| Trust relationships | Implicit, unenforceable assumptions | Explicit, scoped, time-bounded, and revocable trust grants |
| Agent verification | No way to verify who or what performed an action | Any party with the public key can verify action authenticity |
| Rogue agent response | Cannot identify or isolate compromised agents | Revoke trust grants and terminate spawned children immediately |
| Multi-agent auth | No authentication between collaborating agents | Trust web with delegation chains and capability-scoped permissions |
| Session continuity | Agent state resets between sessions | Continuity engine with cumulative hashing across sessions |
| Agent lineage | No record of who created an agent or why | Parent-child spawn records with verifiable ancestry to root |
| Competence evidence | Claims of ability are unverifiable | Signed competence proofs backed by outcome history |
| Negative guarantees | No way to prove an agent lacks a capability | Negative capability proofs demonstrate structural impossibility |
| Key compromise recovery | No mechanism for identity recovery | Key rotation with signed authorization chain preserving history |
| Team coordination | No collective authorization mechanism | Quorum-based team identities with threshold signing |

## Migration Path

Adopting AgenticIdentity does not require rewriting existing agent systems. The migration follows three stages:

### Stage 1: Identity Only

Create identity anchors for existing agents. No behavioral changes required — agents gain a persistent, verifiable identity but continue operating as before. Install the MCP server and run `identity_create` for each agent.

### Stage 2: Receipt Logging

Add receipt signing to agent actions. Wrap existing tool calls with `action_sign` to produce signed receipts. This adds an audit trail without changing the agent's decision-making logic.

### Stage 3: Trust Enforcement

Introduce trust grants between agents. Use `trust_grant` to define capability scopes and `trust_verify` to check authorization before executing sensitive operations. This stage adds access control to the existing receipt-logged workflow.

Each stage is independently valuable. Stage 1 alone provides identity persistence. Stage 2 adds accountability. Stage 3 adds authorization. There is no requirement to adopt all three simultaneously.
