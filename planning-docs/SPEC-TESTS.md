# SPEC-TESTS.md

## Unit Tests (per module)

### Crypto (16 scenarios)
1. Key generation produces valid keys
2. Signing with valid key succeeds
3. Verification with correct key succeeds
4. Verification with wrong key fails
5. HKDF derivation is deterministic
6. Different inputs produce different keys
7. Encryption/decryption roundtrip works
8. Wrong passphrase fails decryption
9. Argon2 produces expected output
10. Random bytes are unique
11. Zeroization clears memory
12. Base58 encoding roundtrip
13. SHA-256 matches test vectors
14. Ed25519 test vectors pass
15. X25519 key exchange works
16. ChaCha20 test vectors pass

### Identity (16 scenarios)
1. Identity creation succeeds
2. Identity ID is deterministic from key
3. Same key = same ID
4. Different keys = different IDs
5. Session key derivation works
6. Capability key derivation works
7. Device key derivation works
8. Spawn key derivation works
9. Key rotation creates valid chain
10. Rotated key can still verify old signatures
11. Identity document serializes/deserializes
12. Capabilities ceiling is enforced
13. Attestation verification works
14. Invalid attestation fails
15. Identity type is correct after spawn
16. Name update works

### Receipt (16 scenarios)
1. Receipt creation succeeds
2. Receipt ID is deterministic
3. Signature verification works
4. Tampered receipt fails verification
5. Chain linking works
6. Chain verification catches gaps
7. Chain verification catches tampering
8. All 12 action types work
9. Witness signature works
10. Multiple witnesses work
11. Wrong actor key fails
12. Sequence numbers are monotonic
13. Timestamps are valid
14. Context binding works
15. Continuity binding works
16. Receipt serialization roundtrip

### Trust (16 scenarios)
1. Trust grant creation succeeds
2. Direct trust verification works
3. Delegated trust verification works
4. Inherited trust verification works
5. Expired trust fails verification
6. Revoked trust fails verification
7. Capability wildcard matching works
8. Temporal constraints enforced
9. Usage constraints enforced
10. Context constraints enforced
11. Delegation depth limit enforced
12. Narrowing-only delegation works
13. Revocation cascade works
14. Max uses decrements correctly
15. Rate limiting works
16. Trust chain walking works

### Continuity (16 scenarios)
1. Experience creation succeeds
2. Experience chain links correctly
3. Cumulative hash is deterministic
4. Gap detection works (temporal)
5. Gap detection works (sequence)
6. Gap detection works (hash)
7. Anchor creation works
8. Heartbeat creation works
9. Heartbeat gap detection works
10. Continuity proof (full) works
11. Continuity proof (anchor) works
12. Continuity proof (sample) works
13. Continuity verification works
14. Memory binding works
15. All 10 experience types work
16. Experience intensity is validated

### Spawn (16 scenarios)
1. Spawn creation succeeds
2. Child authority bounded by parent
3. Authority exceeding ceiling fails
4. Lineage chain builds correctly
5. Spawn depth limit enforced
6. Max children limit enforced
7. All 5 spawn types work
8. Spawn termination works
9. Parent termination cascades
10. Revocation cascade works
11. Ancestry walking works
12. Descendant listing works
13. Effective authority calculation works
14. Lifetime expiration works
15. Task completion termination works
16. Spawn receipt is created

## Integration Tests
- Full workflow: create identity → sign actions → grant trust → verify
- Spawn workflow: create → spawn → child acts → terminate
- Continuity workflow: record experiences → create anchors → prove → verify
- CLI integration: all commands work end-to-end
- MCP integration: all tools work via protocol

## Stress Tests
- Multi-identity: 100 concurrent identities
- Chain length: 10,000 receipts in chain
- Trust depth: 20 delegation levels
- Spawn tree: 1000 descendants
- Experience chain: 100,000 events
- Concurrent signing: 100 parallel operations
