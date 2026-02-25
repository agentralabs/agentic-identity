# CLAUDE-CODE-INSTRUCTIONS.md

> **Master build guide for AgenticIdentity**

---

## Overview

You are building AgenticIdentity, the cryptographic trust anchor for the AgenticOS ecosystem. This system provides AI agents with persistent identity, signed action receipts, revocable trust relationships, temporal continuity proofs, and identity inheritance.

**Read the invention document first:** `agentic-identity-invention.md`

---

## Build Order

Read and implement the specs in this order:

```
1.  agentic-identity-invention.md     ← Vision and inventions (READ FIRST)
2.  CLAUDE-CODE-INSTRUCTIONS.md       ← This file
3.  SPEC-PROJECT-STRUCTURE.md         ← Directory layout
4.  SPEC-DEPENDENCIES.md              ← Justified dependencies
5.  SPEC-DATA-STRUCTURES.md           ← All types, structs, enums
6.  SPEC-FILE-FORMAT.md               ← .aid format specification
7.  SPEC-WRITE-ENGINE.md              ← Identity/receipt/trust creation
8.  SPEC-QUERY-ENGINE.md              ← Verification and queries
9.  SPEC-INDEXES.md                   ← Index structures
10. SPEC-CLI.md                       ← Command-line interface
11. SPEC-FFI.md                       ← C bindings
12. SPEC-MCP.md                       ← MCP server specification
13. SPEC-TESTS.md                     ← Test scenarios
14. SPEC-RESEARCH-PAPER.md            ← Publication specification
```

**Plus hardening specs:**
```
15. SPEC-INSTALLER-UNIVERSAL.md       ← Profile-based installer
16. SPEC-RUNTIME-HARDENING.md         ← Security requirements
17. SPEC-RELEASE-PUBLISH.md           ← crates.io + PyPI workflow
18. SPEC-DOCS-PUBLIC-SYNC.md          ← Documentation requirements
19. SPEC-CI-GUARDRAILS.md             ← CI scripts and workflows
```

---

## Phase 1: Foundation (Core Cryptography)

**Goal:** Implement cryptographic primitives.

1. Set up project structure per SPEC-PROJECT-STRUCTURE
2. Add dependencies per SPEC-DEPENDENCIES
3. Implement cryptographic primitives:
   - Ed25519 key generation, signing, verification
   - X25519 key exchange for encryption
   - HKDF-SHA256 key derivation
   - Argon2id password-based key derivation
   - ChaCha20-Poly1305 symmetric encryption
   - Secure random generation
   - Memory zeroization for secrets
4. Write comprehensive tests for all crypto operations

**Success Criteria:**
- [ ] `cargo test crypto` passes
- [ ] Can generate Ed25519 key pairs
- [ ] Can sign and verify messages
- [ ] Can derive keys with HKDF
- [ ] Can encrypt/decrypt with ChaCha20-Poly1305
- [ ] Secrets are zeroized after use

---

## Phase 2: Identity Anchor

**Goal:** Implement identity creation and management.

5. Implement `IdentityId` derivation from public key
6. Implement `IdentityAnchor` struct (private, contains secrets)
7. Implement `IdentityDocument` struct (public, shareable)
8. Implement key hierarchy:
   - Session key derivation
   - Capability key derivation
   - Device key derivation
   - Encryption key derivation
   - Spawn key derivation
9. Implement key rotation with authorization chain
10. Implement attestations
11. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test identity` passes
- [ ] Can create new identity with unique ID
- [ ] Can derive all 5 key types from root
- [ ] Can rotate keys with proper authorization
- [ ] Can serialize/deserialize identity document
- [ ] Key derivation is deterministic

---

## Phase 3: Action Receipts

**Goal:** Implement signed action receipts and chains.

12. Implement `ReceiptId` derivation
13. Implement `ActionType` enum (12 types)
14. Implement `ActionReceipt` struct
15. Implement receipt signing with any key type
16. Implement receipt chaining (hash links)
17. Implement witness co-signing
18. Implement receipt verification
19. Implement chain verification (walk and verify all links)
20. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test receipt` passes
- [ ] Can create receipts for all 12 action types
- [ ] Can sign receipts with root or derived keys
- [ ] Can chain receipts with hash links
- [ ] Can add witness signatures
- [ ] Can verify receipt signatures
- [ ] Can verify entire chains
- [ ] Tampering detection works

---

## Phase 4: Trust Web

**Goal:** Implement trust grants, verification, and revocation.

21. Implement `TrustId` derivation
22. Implement `CapabilityUri` with wildcard matching
23. Implement `TrustGrant` struct with all constraints
24. Implement trust grant signing
25. Implement direct trust verification
26. Implement delegated trust verification (chain walking)
27. Implement inherited trust verification (spawn lineage)
28. Implement revocation records
29. Implement revocation checking
30. Implement delegation with depth limits
31. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test trust` passes
- [ ] Can create trust grants with all constraint types
- [ ] Capability URI wildcard matching works
- [ ] Can verify direct trust
- [ ] Can verify delegated trust (walk chain)
- [ ] Can revoke grants
- [ ] Revocation cascades to delegations
- [ ] Temporal constraints enforced
- [ ] Usage constraints enforced
- [ ] Context constraints enforced

---

## Phase 5: Temporal Continuity

**Goal:** Implement experience chains, heartbeats, and continuity proofs.

32. Implement `ExperienceId` derivation
33. Implement `ExperienceType` enum (10 types)
34. Implement `ExperienceEvent` struct
35. Implement experience chaining (cumulative hash)
36. Implement continuity anchors (checkpoints)
37. Implement heartbeat system
38. Implement continuity claims
39. Implement continuity proofs (full, anchor, sample)
40. Implement continuity verification
41. Implement gap detection
42. Implement memory binding (link to AgenticMemory)
43. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test continuity` passes
- [ ] Can create experiences for all 10 types
- [ ] Experience chain links correctly
- [ ] Cumulative hash is deterministic
- [ ] Can create and verify anchors
- [ ] Heartbeat system works
- [ ] Can create continuity proofs
- [ ] Can verify continuity claims
- [ ] Gap detection works
- [ ] Memory binding links correctly

---

## Phase 6: Identity Inheritance (Spawn)

**Goal:** Implement agent spawning with bounded authority.

44. Implement `SpawnId` derivation
45. Implement `SpawnType` enum (5 types)
46. Implement `SpawnRecord` struct
47. Implement spawn key derivation with authority encoding
48. Implement child identity creation from spawn
49. Implement authority bounding (child ⊆ parent)
50. Implement lineage chain walking
51. Implement spawn lifecycle (create, operate, terminate)
52. Implement spawn revocation with cascade
53. Implement depth and count limits
54. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test spawn` passes
- [ ] Can spawn all 5 types
- [ ] Authority bounding enforced (child cannot exceed parent)
- [ ] Lineage chain is walkable and verifiable
- [ ] Spawn termination works
- [ ] Revocation cascades to descendants
- [ ] Depth limits enforced
- [ ] Count limits enforced

---

## Phase 7: File Format & Persistence

**Goal:** Implement .aid file format and storage.

55. Implement .aid file format per SPEC-FILE-FORMAT
56. Implement encrypted storage for private keys
57. Implement identity file read/write
58. Implement receipt storage
59. Implement trust store
60. Implement experience store
61. Implement spawn store
62. Implement revocation store
63. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test storage` passes
- [ ] Can save/load identity files
- [ ] Private keys are encrypted at rest
- [ ] Correct passphrase decrypts
- [ ] Wrong passphrase fails cleanly
- [ ] All stores work correctly
- [ ] File format is portable across platforms

---

## Phase 8: Indexes & Queries

**Goal:** Implement indexes and query engine.

64. Implement indexes per SPEC-INDEXES
65. Implement query engine per SPEC-QUERY-ENGINE
66. Implement receipt queries (by actor, type, time, chain)
67. Implement trust queries (by grantor, grantee, capability)
68. Implement experience queries (by type, time range)
69. Implement spawn queries (lineage, descendants, authority)
70. Write comprehensive tests

**Success Criteria:**
- [ ] `cargo test query` passes
- [ ] All query types work efficiently
- [ ] Index lookups are O(log n) or better
- [ ] Range queries work correctly
- [ ] Wildcard matching works

---

## Phase 9: CLI

**Goal:** Implement command-line interface.

71. Implement CLI per SPEC-CLI
72. Implement all subcommands:
    - `aid init` — create identity
    - `aid show` — display identity
    - `aid list` — list identities
    - `aid sign` — sign action, create receipt
    - `aid verify` — verify receipt/trust/continuity
    - `aid trust` — grant/revoke/list/verify trust
    - `aid spawn` — create/list/terminate children
    - `aid continuity` — prove/verify continuity
    - `aid rotate` — rotate keys
    - `aid export` — export public identity
    - `aid import` — import identity
73. Write CLI integration tests

**Success Criteria:**
- [ ] `cargo test cli` passes
- [ ] All subcommands work correctly
- [ ] Help text is clear
- [ ] Error messages are helpful
- [ ] Output formats (text, JSON) work

---

## Phase 10: MCP Server

**Goal:** Implement MCP server for AI agent integration.

74. Implement MCP server per SPEC-MCP
75. Implement all tools (14 tools)
76. Implement all resources (8 resources)
77. Implement all prompts (4 prompts)
78. Write MCP integration tests

**Success Criteria:**
- [ ] MCP server starts and handles stdio
- [ ] All tools work via MCP
- [ ] All resources accessible via MCP
- [ ] Claude Desktop integration works
- [ ] Concurrent operations are safe

---

## Phase 11: FFI

**Goal:** Implement C API and Python bindings.

79. Implement C API per SPEC-FFI
80. Generate header file with cbindgen
81. Write FFI tests
82. Create Python bindings
83. Write Python tests

**Success Criteria:**
- [ ] C header compiles
- [ ] Can call from C
- [ ] Can call from Python
- [ ] Memory management is correct
- [ ] Error handling works across FFI boundary

---

## Phase 12: Hardening

**Goal:** Implement production hardening.

84. Implement installer per SPEC-INSTALLER-UNIVERSAL
85. Apply runtime hardening per SPEC-RUNTIME-HARDENING
86. Set up release workflow per SPEC-RELEASE-PUBLISH
87. Create documentation per SPEC-DOCS-PUBLIC-SYNC
88. Add CI guardrails per SPEC-CI-GUARDRAILS

**Success Criteria:**
- [ ] Installer works for desktop/terminal/server profiles
- [ ] MCP config is merge-only (never overwrites)
- [ ] Release publishes to crates.io AND PyPI
- [ ] All stress tests pass
- [ ] CI guardrails block bad PRs

---

## Phase 13: Research Paper

**Goal:** Write and compile research paper.

89. Write research paper per SPEC-RESEARCH-PAPER
90. Include real benchmarks from implementation
91. Generate figures and tables
92. Compile to PDF

**Success Criteria:**
- [ ] Paper is complete and well-structured
- [ ] All figures render
- [ ] Benchmarks are from real measurements
- [ ] PDF compiles cleanly

---

## Rules

1. **Do not add dependencies not listed in SPEC-DEPENDENCIES.** If you need something, implement it or find a way without it.

2. **Do not skip tests.** Every phase has tests. Run them. If they fail, fix the code.

3. **Do not use unsafe Rust unless explicitly required.** Crypto operations via libraries, not hand-rolled.

4. **Every public function must have a doc comment.**

5. **Every module must have a module-level doc comment.**

6. **No `unwrap()` in library code.** All errors must be properly typed and propagated.

7. **No `println!()` in library code.** Use the `log` crate.

8. **Private keys must NEVER be logged, printed, or exposed in errors.**

9. **All timestamps are Unix epoch microseconds (u64).**

10. **All cryptographic operations must be constant-time where relevant.**

11. **All binary formats are little-endian.**

12. **Identity files must be encrypted at rest.**

13. **Secrets must be zeroized after use.** Use the `zeroize` crate.

14. **File operations must use atomic writes** where data integrity matters.

15. **Concurrent access must be handled** with proper locking.

---

## Benchmark Targets

```
Key generation:           < 1 ms
Sign operation:           < 0.5 ms
Verify operation:         < 0.5 ms
Trust chain (depth 10):   < 5 ms
Receipt chain (1000):     < 50 ms
Experience chain (10000): < 100 ms
Continuity proof:         < 10 ms
File load (identity):     < 5 ms
Index lookup:             < 1 ms
```

---

## Success Criteria (Complete Build)

The build is complete when:

- [ ] `cargo test --all` — all tests pass, zero failures
- [ ] `cargo clippy -- -D warnings` — zero warnings
- [ ] `cargo fmt --check` — passes
- [ ] `cargo build --release` — compiles successfully
- [ ] `aid` CLI works for all operations
- [ ] MCP server works with Claude Desktop
- [ ] FFI bindings work from Python
- [ ] Installer works for all profiles
- [ ] Release publishes to crates.io AND PyPI
- [ ] All stress tests pass
- [ ] Research paper PDF generated
- [ ] Documentation complete

---

## Testing Commands

```bash
# Run all tests
cargo test --all

# Run specific test module
cargo test identity
cargo test receipt
cargo test trust
cargo test continuity
cargo test spawn
cargo test storage
cargo test query
cargo test cli
cargo test mcp
cargo test ffi

# Run benchmarks
cargo bench

# Run stress tests
cargo test --test stress -- --ignored

# Check formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings

# Build release
cargo build --release

# Run CLI
./target/release/aid --help
```

---

## File Artifacts

When complete, you will have produced:

```
agentic-identity/
├── Cargo.toml                         ← Workspace root
├── README.md
├── LICENSE (MIT)
├── CHANGELOG.md
├── crates/
│   ├── agentic-identity/              ← Core library → crates.io
│   ├── agentic-identity-mcp/          ← MCP server → crates.io
│   ├── agentic-identity-cli/          ← CLI binary → crates.io
│   └── agentic-identity-ffi/          ← C FFI → crates.io
├── python/                            ← Python package → PyPI
├── tests/
│   ├── integration/
│   └── stress/
├── benches/
├── docs/
├── examples/
├── paper/
├── scripts/
└── .github/workflows/
```

---

## Final Note

AgenticIdentity is the trust anchor for AgenticOS. Every other sister depends on it for:
- Signing data (Memory nodes, Vision captures, Codebase analysis)
- Proving provenance (who created what)
- Establishing trust (who can do what)
- Verifying continuity (same agent over time)
- Managing lineage (spawned agents)

Build it solid. Build it comprehensive. Build it right.
