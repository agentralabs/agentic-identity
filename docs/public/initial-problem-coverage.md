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

1. **Identity Anchors** — Ed25519 keypair-based persistent identity with `aid_` prefixed IDs derived from the public key hash
2. **Action Receipts** — Signed, timestamped, chainable proof of action with `arec_` prefixed IDs and optional witness co-signatures
3. **Trust Delegations** — Scoped, time-limited, revocable trust grants with `atrust_` prefixed IDs and configurable delegation depth
4. **Continuity Engine** — Tamper-evident experience chains across sessions with cumulative hashing, heartbeats, and gap detection
5. **Child Spawning** — Verifiable agent lineage with authority ceilings, lifetime policies, and cascade termination

All five primitives are backed by Ed25519 signatures and can be independently verified by any party holding the relevant public key.
