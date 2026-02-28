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
| Unverifiable competence | Signed competence proofs with outcome history | Covered |
| No negative guarantees | Negative capability proofs (structural impossibility) | Covered |
| No collective authorization | Quorum-based team identities | Covered |
| Behavioral drift detection | Fingerprint baseline with anomaly detection | Covered |

## Verification Approach

Every solution in the matrix above is backed by cryptographic verification. Receipts, trust grants, competence proofs, negative proofs, and continuity claims all carry Ed25519 signatures that any holder of the public key can independently verify without contacting a central authority.
