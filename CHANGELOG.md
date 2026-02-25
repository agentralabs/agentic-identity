# Changelog

All notable changes to AgenticIdentity will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.0 — V2: Grounding & Multi-Context Workspaces

### Added
- **Grounding (anti-hallucination)**: Verify identity claims have trust/receipt backing.
  - `identity_ground`: Verify a claim about agent permissions or actions against trust grants and receipts. Returns verified/ungrounded status with evidence.
  - `identity_evidence`: Search for trust/receipt evidence matching a query.
  - `identity_suggest`: Suggest capabilities or actions based on partial query.
- **Multi-context workspaces**: Load and query across multiple identity stores simultaneously.
  - `identity_workspace_create`: Create a workspace for cross-identity queries.
  - `identity_workspace_add`: Add an identity store directory to a workspace with role.
  - `identity_workspace_list`: List all identity contexts in a workspace.
  - `identity_workspace_query`: Search across all trust grants and receipts.
  - `identity_workspace_compare`: Compare permissions across agent identities.
  - `identity_workspace_xref`: Cross-reference permission distribution with coverage.
- 30 new V2 stress tests (grounding, workspace, integration).

### Changed
- MCP tool count increased from 31 to 40.
- McpServer now includes IdentityWorkspaceManager for multi-context support.

### Fixed
- Recursion limit for JSON macro expansion in MCP tool definitions.

## [0.1.0] - 2025-06-01

Initial release of AgenticIdentity -- cryptographic trust anchor for AI agents.

### Added

**Identity (`agentic-identity` core library)**
- Ed25519 identity anchor creation with deterministic ID generation (`aid_` prefix + base58)
- Public identity document generation with self-signature verification
- Key rotation with signed authorization chain and full rotation history
- Scoped key derivation via HKDF-SHA256: session keys, capability keys, device keys
- `.aid` file format for encrypted identity storage (ChaCha20-Poly1305 + Argon2id)
- Atomic file writes via temp-file-and-rename pattern
- Public document inspection without passphrase
- Zeroization of all private key material on drop and after use

**Action Receipts**
- Signed action receipts with SHA-256 content hash and Ed25519 signature
- Seven action types: Decision, Observation, Mutation, Delegation, Revocation, IdentityOperation, Custom
- Structured action content with description, JSON data, and references
- Receipt chaining via `previous_receipt` for ordered audit trails
- Chain verification with signature and linkage checks
- Witness co-signatures for third-party attestation
- Context hash support for binding receipts to external state

**Trust Web**
- Signed trust grants between identities with capability binding
- Capability URI scheme with wildcard matching (`read:*`, `execute:deploy:*`, `*`)
- Trust constraints: time bounds (`not_before`/`not_after`), maximum use count, geographic and IP restrictions
- Trust delegation with configurable depth limits
- Trust chain verification (end-to-end delegation chain walking)
- Delegation validation (capability coverage, depth, and permission checks)
- Grantee acknowledgment signatures
- Revocation with signed revocation records
- Revocation channels: Local, HTTP, Ledger, Multi
- Revocation cascade through delegation chains

**CLI (`agentic-identity-cli`)**
- `aid init` -- create a new identity with passphrase encryption
- `aid sign` -- sign an action receipt
- `aid verify` -- verify receipts and trust grants
- `aid trust grant` -- grant trust to another identity
- `aid trust revoke` -- revoke a trust grant
- `aid inspect` -- inspect `.aid` files without passphrase
- `aid rotate` -- rotate the root key pair
- `aid export` -- export the public identity document

**MCP Server (`agentic-identity-mcp`)**
- MCP tool server exposing all identity operations to AI agents
- Tools: `identity_create`, `identity_info`, `identity_document`, `identity_rotate`
- Tools: `action_sign`, `action_verify`, `chain_verify`
- Tools: `trust_grant`, `trust_verify`, `trust_chain_verify`, `trust_revoke`
- Tools: `key_derive_session`, `key_derive_capability`
- Configurable identity directory via `--identity-dir`

**FFI (`agentic-identity-ffi`)**
- C-compatible API for all core operations
- Opaque identity anchor handles with explicit free
- Heap-allocated string outputs with explicit free
- Error codes: `AID_OK`, `AID_ERR_NULL_PTR`, `AID_ERR_INVALID_UTF8`, `AID_ERR_CRYPTO`, `AID_ERR_IO`, `AID_ERR_SERIALIZATION`
- File save/load with passphrase encryption

**Python (`agentic-identity` Python package)**
- Python bindings wrapping the C FFI layer
- `Identity`, `Receipt`, `TrustGrant` classes
- File save/load support
- Python 3.10+ compatibility

**Cryptography**
- Ed25519 signing and verification (via `ed25519-dalek`)
- HKDF-SHA256 key derivation (via `hkdf` + `sha2`)
- ChaCha20-Poly1305 authenticated encryption (via `chacha20poly1305`)
- Argon2id passphrase-based key derivation (via `argon2`)
- Cryptographically secure random number generation (via `rand`)
- Base58 and Base64 encoding for IDs and keys

**Temporal Continuity**
- Experience chain with 10 event types: Cognition, Perception, Action, Communication, Learning, Planning, Idle, System, Memory, Custom
- Cumulative SHA-256 hash chain linking experiences
- Continuity anchors with external witness signatures
- Gap detection: temporal, sequence, and hash-based
- Heartbeat monitoring with configurable cadence
- Continuity claims and verification proofs

**Identity Inheritance (Spawn)**
- Child identity spawning with bounded authority
- Five spawn types: Worker, Delegate, Clone, Specialist, Custom
- Authority ceiling enforcement (child cannot exceed parent)
- Spawn depth and max-children limits
- Cascade termination (revoking parent terminates all descendants)
- Lineage verification and ancestor walking
- Effective authority calculation through spawn chain

**Competence Proofs**
- Competence domain tracking with attempt recording
- Success, Failure, and Partial outcome types
- Streak tracking and success rate calculation
- Competence proof generation with configurable requirements
- Signed competence proofs with expiration
- Proof verification with requirement checking

**Negative Capability**
- Prove-cannot: cryptographic proof of impossibility
- Three impossibility reasons: NotInCeiling, NotInLineage, VoluntaryDeclaration
- Voluntary capability declarations with witness support
- Is-impossible queries against ceiling, lineage, and declarations

**Testing and Benchmarks**
- 289 tests across all crates (199 unit + 53 stress + 6 integration + 30 MCP + 9 FFI + 3 CLI - some overlap in counting but all pass)
- Comprehensive stress tests: 10K receipts, 5K continuity experiences, 100 spawn trees
- Concurrency tests: 50 concurrent signers, 100 concurrent trust verifiers
- Resilience tests: corrupted files, wrong passphrases, truncated data
- Criterion benchmarks for all cryptographic operations
- Sub-20-microsecond signing, sub-25-microsecond verification

**Documentation**
- Quickstart guide
- Core concepts documentation
- Integration guide (MCP, Rust, FFI, Python)
- API reference
- Benchmarks with analysis
- FAQ
- `.aid` file format specification

[0.1.0]: https://github.com/agentralabs/agentic-identity/releases/tag/v0.1.0
