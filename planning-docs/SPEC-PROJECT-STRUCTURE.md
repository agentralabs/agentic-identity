# SPEC-PROJECT-STRUCTURE.md

> **Directory layout for AgenticIdentity**

---

## Project Tree

```
agentic-identity/
├── Cargo.toml                          # Workspace root
├── README.md                           # Project overview
├── LICENSE                             # MIT License
├── CHANGELOG.md                        # Version history
├── .gitignore
│
├── crates/
│   │
│   ├── agentic-identity/               # Core library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # Public API, re-exports
│   │       ├── error.rs                # Error types
│   │       │
│   │       ├── crypto/                 # Cryptographic primitives
│   │       │   ├── mod.rs
│   │       │   ├── keys.rs             # Ed25519, X25519 key operations
│   │       │   ├── signing.rs          # Sign/verify operations
│   │       │   ├── encryption.rs       # Encrypt/decrypt operations
│   │       │   ├── derivation.rs       # HKDF key derivation
│   │       │   ├── password.rs         # Argon2id password KDF
│   │       │   ├── random.rs           # Secure random generation
│   │       │   └── hash.rs             # SHA-256 hashing
│   │       │
│   │       ├── identity/               # Identity anchor
│   │       │   ├── mod.rs
│   │       │   ├── anchor.rs           # IdentityAnchor (private)
│   │       │   ├── document.rs         # IdentityDocument (public)
│   │       │   ├── id.rs               # IdentityId derivation
│   │       │   ├── derived_keys.rs     # Key hierarchy
│   │       │   ├── rotation.rs         # Key rotation
│   │       │   ├── attestation.rs      # Attestations
│   │       │   └── types.rs            # Identity-related types
│   │       │
│   │       ├── receipt/                # Action receipts
│   │       │   ├── mod.rs
│   │       │   ├── receipt.rs          # ActionReceipt struct
│   │       │   ├── id.rs               # ReceiptId derivation
│   │       │   ├── action_type.rs      # ActionType enum (12 types)
│   │       │   ├── content.rs          # ActionContent
│   │       │   ├── chain.rs            # Receipt chaining
│   │       │   ├── witness.rs          # Witness signatures
│   │       │   ├── signing.rs          # Receipt signing
│   │       │   └── verify.rs           # Receipt verification
│   │       │
│   │       ├── trust/                  # Trust web
│   │       │   ├── mod.rs
│   │       │   ├── grant.rs            # TrustGrant struct
│   │       │   ├── id.rs               # TrustId derivation
│   │       │   ├── capability.rs       # CapabilityUri, matching
│   │       │   ├── constraints.rs      # All constraint types
│   │       │   ├── delegation.rs       # Delegation rules
│   │       │   ├── revocation.rs       # Revocation records
│   │       │   ├── verify.rs           # Trust verification
│   │       │   └── chain.rs            # Trust chain walking
│   │       │
│   │       ├── continuity/             # Temporal continuity
│   │       │   ├── mod.rs
│   │       │   ├── experience.rs       # ExperienceEvent struct
│   │       │   ├── id.rs               # ExperienceId derivation
│   │       │   ├── types.rs            # ExperienceType enum (10 types)
│   │       │   ├── chain.rs            # Experience chaining
│   │       │   ├── anchor.rs           # Continuity anchors
│   │       │   ├── heartbeat.rs        # Heartbeat system
│   │       │   ├── proof.rs            # Continuity proofs
│   │       │   ├── claim.rs            # Continuity claims
│   │       │   ├── verify.rs           # Continuity verification
│   │       │   ├── gap.rs              # Gap detection
│   │       │   └── memory_binding.rs   # Memory state binding
│   │       │
│   │       ├── spawn/                  # Identity inheritance
│   │       │   ├── mod.rs
│   │       │   ├── record.rs           # SpawnRecord struct
│   │       │   ├── id.rs               # SpawnId derivation
│   │       │   ├── types.rs            # SpawnType enum
│   │       │   ├── authority.rs        # Authority bounding
│   │       │   ├── lineage.rs          # Lineage chain
│   │       │   ├── lifecycle.rs        # Create/operate/terminate
│   │       │   ├── constraints.rs      # Depth/count limits
│   │       │   └── revocation.rs       # Spawn revocation, cascade
│   │       │
│   │       ├── storage/                # File format & persistence
│   │       │   ├── mod.rs
│   │       │   ├── file_format.rs      # .aid file format
│   │       │   ├── encrypted.rs        # Encrypted storage
│   │       │   ├── identity_store.rs   # Identity file I/O
│   │       │   ├── receipt_store.rs    # Receipt storage
│   │       │   ├── trust_store.rs      # Trust grant storage
│   │       │   ├── experience_store.rs # Experience storage
│   │       │   ├── spawn_store.rs      # Spawn record storage
│   │       │   ├── revocation_store.rs # Revocation storage
│   │       │   └── atomic.rs           # Atomic file operations
│   │       │
│   │       ├── index/                  # Indexes
│   │       │   ├── mod.rs
│   │       │   ├── receipt_index.rs    # Receipt indexes
│   │       │   ├── trust_index.rs      # Trust grant indexes
│   │       │   ├── experience_index.rs # Experience indexes
│   │       │   ├── spawn_index.rs      # Spawn indexes
│   │       │   ├── time_index.rs       # Time-based indexes
│   │       │   └── capability_index.rs # Capability matching index
│   │       │
│   │       ├── query/                  # Query engine
│   │       │   ├── mod.rs
│   │       │   ├── receipt_query.rs    # Receipt queries
│   │       │   ├── trust_query.rs      # Trust queries
│   │       │   ├── experience_query.rs # Experience queries
│   │       │   ├── spawn_query.rs      # Spawn/lineage queries
│   │       │   └── verification.rs     # Verification queries
│   │       │
│   │       └── util/                   # Utilities
│   │           ├── mod.rs
│   │           ├── base58.rs           # Base58 encoding
│   │           ├── time.rs             # Timestamp utilities
│   │           ├── serialize.rs        # Canonical serialization
│   │           └── id_prefix.rs        # ID prefix constants
│   │
│   ├── agentic-identity-mcp/           # MCP server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # Entry point
│   │       ├── server.rs               # MCP server implementation
│   │       ├── tools/                  # Tool handlers
│   │       │   ├── mod.rs
│   │       │   ├── identity.rs         # Identity tools
│   │       │   ├── receipt.rs          # Receipt tools
│   │       │   ├── trust.rs            # Trust tools
│   │       │   ├── continuity.rs       # Continuity tools
│   │       │   └── spawn.rs            # Spawn tools
│   │       ├── resources/              # Resource handlers
│   │       │   ├── mod.rs
│   │       │   ├── identity_res.rs
│   │       │   ├── receipt_res.rs
│   │       │   ├── trust_res.rs
│   │       │   └── continuity_res.rs
│   │       ├── prompts/                # Prompt templates
│   │       │   ├── mod.rs
│   │       │   └── templates.rs
│   │       └── config.rs               # Server configuration
│   │
│   ├── agentic-identity-cli/           # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # Entry point
│   │       ├── commands/               # Command implementations
│   │       │   ├── mod.rs
│   │       │   ├── init.rs             # aid init
│   │       │   ├── show.rs             # aid show
│   │       │   ├── list.rs             # aid list
│   │       │   ├── sign.rs             # aid sign
│   │       │   ├── verify.rs           # aid verify
│   │       │   ├── trust.rs            # aid trust (grant/revoke/list/verify)
│   │       │   ├── spawn.rs            # aid spawn (create/list/terminate)
│   │       │   ├── continuity.rs       # aid continuity (prove/verify)
│   │       │   ├── rotate.rs           # aid rotate
│   │       │   ├── export.rs           # aid export
│   │       │   └── import.rs           # aid import
│   │       ├── output.rs               # Output formatting
│   │       └── config.rs               # CLI configuration
│   │
│   └── agentic-identity-ffi/           # C FFI
│       ├── Cargo.toml
│       ├── cbindgen.toml               # Header generation config
│       └── src/
│           ├── lib.rs                  # FFI entry point
│           ├── identity.rs             # Identity FFI
│           ├── receipt.rs              # Receipt FFI
│           ├── trust.rs                # Trust FFI
│           ├── error.rs                # Error handling
│           └── types.rs                # FFI-safe types
│
├── python/                             # Python package
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/
│   │   └── agentic_identity/
│   │       ├── __init__.py
│   │       ├── _ffi.py                 # FFI bindings
│   │       ├── identity.py             # Identity operations
│   │       ├── receipt.py              # Receipt operations
│   │       ├── trust.py                # Trust operations
│   │       ├── continuity.py           # Continuity operations
│   │       └── spawn.py                # Spawn operations
│   └── tests/
│       ├── test_identity.py
│       ├── test_receipt.py
│       ├── test_trust.py
│       ├── test_continuity.py
│       └── test_spawn.py
│
├── tests/
│   ├── integration/
│   │   ├── cli_tests.rs
│   │   ├── mcp_tests.rs
│   │   ├── ffi_tests.rs
│   │   └── full_workflow_tests.rs
│   └── stress/
│       ├── multi_identity.rs
│       ├── concurrent_signing.rs
│       ├── trust_chain_depth.rs
│       ├── receipt_chain_length.rs
│       ├── experience_chain_length.rs
│       ├── spawn_tree_depth.rs
│       └── revocation_cascade.rs
│
├── benches/
│   ├── crypto_bench.rs
│   ├── signing_bench.rs
│   ├── verification_bench.rs
│   ├── chain_bench.rs
│   └── query_bench.rs
│
├── scripts/
│   ├── install.sh                      # Universal installer
│   ├── check-install-commands.sh       # Verify install commands
│   ├── check-canonical-sister.sh       # Verify canonical requirements
│   └── test-primary-problems.sh        # Primary problem regression
│
├── docs/
│   ├── quickstart.md
│   ├── concepts/
│   │   ├── identity.md
│   │   ├── receipts.md
│   │   ├── trust.md
│   │   ├── continuity.md
│   │   └── spawn.md
│   ├── integration-guide.md
│   ├── faq.md
│   ├── benchmarks.md
│   ├── api-reference.md
│   └── file-format.md
│
├── examples/
│   ├── basic_identity.rs
│   ├── sign_action.rs
│   ├── trust_delegation.rs
│   ├── continuity_proof.rs
│   ├── spawn_worker.rs
│   └── python/
│       ├── basic_identity.py
│       └── trust_workflow.py
│
├── paper/
│   ├── agenticidentity-paper.tex
│   ├── references.bib
│   ├── figures/
│   │   ├── architecture.pdf
│   │   ├── identity-anchor.pdf
│   │   ├── receipt-chain.pdf
│   │   ├── trust-web.pdf
│   │   ├── continuity-proof.pdf
│   │   └── spawn-lineage.pdf
│   └── agenticidentity-paper.pdf
│
└── .github/
    └── workflows/
        ├── ci.yml                      # Main CI
        ├── release.yml                 # Release workflow
        ├── install-command-guardrails.yml
        ├── canonical-sister-guardrails.yml
        └── social-release-broadcast.yml
```

---

## Directory Responsibilities

### crates/agentic-identity/
Core library implementing all five inventions:
- **crypto/** — Cryptographic primitives (Ed25519, X25519, HKDF, Argon2, ChaCha20)
- **identity/** — Identity anchor, key hierarchy, rotation, attestations
- **receipt/** — Action receipts, chaining, witnesses, verification
- **trust/** — Trust grants, capabilities, constraints, revocation
- **continuity/** — Experience chain, heartbeats, proofs, verification
- **spawn/** — Identity inheritance, authority bounding, lineage
- **storage/** — File format, encrypted storage, all stores
- **index/** — Index structures for efficient queries
- **query/** — Query engine for all data types

### crates/agentic-identity-mcp/
MCP server for AI agent integration:
- **tools/** — 14 MCP tools for identity, receipts, trust, continuity, spawn
- **resources/** — 8 MCP resources for data access
- **prompts/** — 4 prompt templates

### crates/agentic-identity-cli/
Command-line interface:
- **commands/** — All CLI commands (init, show, sign, verify, trust, spawn, etc.)

### crates/agentic-identity-ffi/
C API for language bindings:
- FFI-safe types
- Error handling across boundary
- Memory management

### python/
Python package using FFI bindings:
- High-level Pythonic API
- Full functionality exposed

---

## File Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Rust source | snake_case | `derived_keys.rs` |
| Rust module | snake_case | `mod.rs` |
| Rust struct | PascalCase | `IdentityAnchor` |
| Rust enum | PascalCase | `ActionType` |
| Rust function | snake_case | `verify_receipt` |
| Rust constant | SCREAMING_SNAKE | `MAX_SPAWN_DEPTH` |
| Python source | snake_case | `identity.py` |
| Python class | PascalCase | `Identity` |
| Markdown | SCREAMING-KEBAB | `SPEC-DATA-STRUCTURES.md` |
| Shell script | kebab-case | `check-install-commands.sh` |

---

## Module Dependencies

```
lib.rs
├── error
├── crypto (no internal deps)
├── util (no internal deps)
├── identity (depends on: crypto, util)
├── receipt (depends on: crypto, identity, util)
├── trust (depends on: crypto, identity, util)
├── continuity (depends on: crypto, identity, receipt, util)
├── spawn (depends on: crypto, identity, trust, util)
├── storage (depends on: all above)
├── index (depends on: all above)
└── query (depends on: all above)
```

---

## Test Organization

```
Unit tests: In each source file (#[cfg(test)] mod tests)
Integration tests: tests/integration/
Stress tests: tests/stress/
Benchmarks: benches/
```

---

## Generated Files

These files are generated, not committed:
```
target/                     # Build artifacts
*.aid                       # Identity files (user data)
*.receipt                   # Receipt files
*.trust                     # Trust grant files
agentic_identity.h          # Generated C header
```
