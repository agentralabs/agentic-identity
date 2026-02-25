---
status: stable
---

# Initial Problem Coverage

## Problem Statement

AI agents lack a persistent, cryptographically verifiable identity. Without identity:
- Actions cannot be attributed
- Trust cannot be formally established
- Audit trails do not exist
- Rogue agents cannot be identified

## Initial Coverage

AgenticIdentity addresses these problems with:

1. **Identity Anchors** — Ed25519 keypair-based persistent identity
2. **Action Receipts** — Signed, timestamped, chainable proof of action
3. **Trust Delegations** — Scoped, time-limited, revocable trust grants
4. **Continuity Engine** — Tamper-evident experience chains across sessions
5. **Child Spawning** — Verifiable agent lineage
