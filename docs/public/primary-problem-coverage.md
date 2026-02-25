---
status: stable
---

# Primary Problem Coverage

## Core Problem

AI agents operate without verifiable identity — actions are anonymous, untraceable, and irrevocable.

## Coverage Matrix

| Problem | Solution | Status |
|---------|----------|--------|
| Anonymous agent actions | Ed25519 signed action receipts | Covered |
| No audit trail | Tamper-evident receipt chains | Covered |
| Implicit trust | Explicit, scoped, revocable trust delegations | Covered |
| Session discontinuity | Continuity engine with cumulative hashing | Covered |
| Unverifiable lineage | Child identity spawning with parent attestation | Covered |
| Key compromise | Key rotation and revocation support | Covered |
| Cross-agent trust | Delegation chains with scope enforcement | Covered |
