# AgenticIdentity — Complete Build Specification

> **One file. Full spec. The trust anchor for AgenticOS.**

---

# THE INVENTION

## AgenticIdentity — The Invention Document

> **The fundamental insight:** AI agents have no identity. They can't prove who they are, can't sign their actions, can't establish trust relationships that persist, and can't be held accountable. AgenticIdentity creates the cryptographic foundation that makes agents into accountable entities.

---

## The Problem We're Solving

Every AI agent today is anonymous.

When an agent takes an action — sends an email, modifies code, makes a decision — there's no cryptographic proof that THIS agent did THIS action. Session IDs vanish. API keys authenticate the human, not the agent. There's no way to say "the agent I trusted yesterday is the same one I'm talking to today" with mathematical certainty.

This creates fundamental problems:

**No Accountability:** When something goes wrong, you can't prove which agent did it. Logs can be tampered with. Session IDs are meaningless strings. There's no chain of custody.

**No Trust Delegation:** You can't give an agent limited authority that can be revoked. Today's "permissions" are all-or-nothing API keys. There's no "trust this agent to do X but not Y, and revoke if compromised."

**No Agent-to-Agent Trust:** Agents can't verify each other. When Agent A receives a message from Agent B, there's no proof B sent it. No authentication. No way to establish secure channels.

**No Portability:** An agent's identity is trapped in one system. Move to a new provider, new tool, new environment — you start fresh. No continuity.

**Current state:**
- Agents are identified by session tokens that expire
- No cryptographic binding between agent and actions
- Trust is implicit and irrevocable
- Agent identity doesn't survive provider changes
- No standard for agent-to-agent authentication

**What we need:**
- Persistent cryptographic identity that survives sessions
- Signed actions that prove provenance
- Revocable trust relationships with scoped permissions
- Portable identity that moves across systems
- Agent-to-agent authentication protocol

---

## The Three Inventions

### Invention 1: The Identity Anchor

**The Problem:** Agents have no persistent identity. A session ID is not identity. An API key is not identity. There's nothing that says "this is Agent X" in a way that persists, proves, and ports.

**The Invention:** A cryptographic identity anchor — a key pair where the public key IS the agent's identity, the private key proves ownership, and derived keys enable scoped trust without exposing the root.

```
IDENTITY ANCHOR
├── Root Key Pair (Ed25519)
│   ├── Public Key = Agent Identity (permanent, shareable)
│   └── Private Key = Proof of Identity (never shared, never exported)
│
├── Derived Keys (scoped)
│   ├── Session Keys (ephemeral, auto-expire)
│   ├── Capability Keys (scoped to specific permissions)
│   └── Device Keys (bound to specific hardware)
│
└── Identity Document
    ├── Public key
    ├── Creation timestamp
    ├── Key rotation history
    ├── Attestations from other identities
    └── Signed by root private key
```

**Why This Matters:**
- The agent's identity IS its public key — mathematical, unforgeable, permanent
- Derived keys enable delegation without exposing root
- Key rotation handles compromise without losing identity
- Identity document is portable across systems

**The Difference:**
- Before: Agent identity is whatever string the platform assigns
- After: Agent identity is a cryptographic fact that the agent controls

---

### Invention 2: The Action Receipt

**The Problem:** When an agent takes an action, there's no proof. Logs can be edited. Timestamps can be faked. There's no cryptographic chain from "this action" to "this agent."

**The Invention:** Every action produces a signed receipt — a cryptographic object that proves THIS agent did THIS action at THIS time, with optional witnesses for non-repudiation.

```
ACTION RECEIPT
├── Action Hash (SHA-256 of action content)
├── Actor Identity (agent's public key)
├── Timestamp (RFC 3339, from trusted source)
├── Action Type (enum: decision, observation, mutation, delegation, revocation)
├── Action Content (structured, type-specific)
├── Context Hash (hash of relevant state at time of action)
├── Signature (Ed25519, signs all above fields)
│
├── Optional: Witness Signatures
│   ├── Other agents who observed
│   └── External timestamp authority
│
└── Optional: Chain Link
    ├── Previous receipt hash
    └── Creates auditable sequence
```

**Why This Matters:**
- Actions become undeniable — signed by the agent's key
- Witnesses enable multi-party verification
- Chain links create tamper-evident audit trails
- Receipts are portable — verify anywhere with public key

**The Difference:**
- Before: "The logs say the agent did X" (trust the logs)
- After: "The agent signed X with its key" (trust the math)

---

### Invention 3: The Trust Web

**The Problem:** Trust between agents and humans is implicit and irrevocable. You either trust an agent completely or not at all. There's no way to grant scoped trust, verify trust relationships, or revoke trust when needed.

**The Invention:** A web of signed trust relationships — cryptographic objects that say "Identity A trusts Identity B to do X until time T, and here's the revocation channel."

```
TRUST RELATIONSHIP
├── Grantor (identity granting trust)
├── Grantee (identity receiving trust)
├── Capabilities (what grantee can do)
│   ├── Capability URIs (structured permissions)
│   ├── Constraints (time, scope, count limits)
│   └── Delegation rights (can grantee re-delegate?)
│
├── Validity
│   ├── Not Before (timestamp)
│   ├── Not After (timestamp or "until revoked")
│   └── Max Uses (optional count limit)
│
├── Revocation
│   ├── Revocation Key (derived key for this trust)
│   ├── Revocation Channel (where to publish revocation)
│   └── Revocation Witnesses (who must co-sign revocation)
│
└── Signatures
    ├── Grantor Signature
    └── Grantee Acknowledgment (optional)
```

**Trust Operations:**
```
GRANT:   A signs "I trust B to do {caps} until {time}"
VERIFY:  Anyone can verify A's signature + check revocation
REVOKE:  A signs revocation + publishes to channel
CHAIN:   B can delegate to C if delegation rights allow
```

**Why This Matters:**
- Trust is explicit, scoped, and time-bounded
- Revocation is built in, not bolted on
- Trust chains enable delegation with limits
- Verification is decentralized — anyone with public keys can verify

**The Difference:**
- Before: "I gave the agent my API key" (all or nothing, forever)
- After: "I trust this agent to read my calendar until Friday, revocable instantly"

---

## The Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AgenticIdentity                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │  Identity   │    │   Action    │    │    Trust    │              │
│  │   Anchor    │───▶│   Receipt   │───▶│     Web     │              │
│  │             │    │             │    │             │              │
│  │ • Key pairs │    │ • Signing   │    │ • Grants    │              │
│  │ • Derivation│    │ • Chaining  │    │ • Revokes   │              │
│  │ • Rotation  │    │ • Witnesses │    │ • Verifies  │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
│         │                  │                  │                      │
│         └──────────────────┴──────────────────┘                      │
│                            │                                         │
│                            ▼                                         │
│                    ┌─────────────┐                                   │
│                    │   .aid      │                                   │
│                    │   File      │                                   │
│                    │             │                                   │
│                    │ • Portable  │                                   │
│                    │ • Encrypted │                                   │
│                    │ • Versioned │                                   │
│                    └─────────────┘                                   │
│                            │                                         │
│              ┌─────────────┼─────────────┐                          │
│              ▼             ▼             ▼                          │
│         ┌────────┐   ┌────────┐   ┌────────┐                        │
│         │  CLI   │   │  MCP   │   │  FFI   │                        │
│         │  aid   │   │ Server │   │ C API  │                        │
│         └────────┘   └────────┘   └────────┘                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Integration With AgenticOS

```
AGENTICIDENTITY ENABLES:
│
├── AgenticContract
│   └── Parties identified by public keys
│   └── Agreements signed by both parties
│   └── Revocation triggers contract termination
│
├── AgenticComm
│   └── Messages signed by sender
│   └── Encrypted to recipient's public key
│   └── Trust verification before channel establishment
│
├── AgenticPlanning
│   └── Commitments signed by agent
│   └── Progress attestations are signed receipts
│   └── Goal delegation with trust chains
│
├── Hydra
│   └── Capability tokens bound to identity
│   └── Receipt ledger is chain of action receipts
│   └── Execution gate verifies identity before action
│
└── Federation
    └── Agent-to-agent authentication
    └── Cross-system identity portability
    └── Trust web spans organizations
```

---

## What Success Looks Like

**For a developer using AgenticIdentity:**

```bash
# Create a new agent identity
$ aid init --name "my-agent"
Created identity: aid_7xK9mP2...
Public key: ed25519:3Fk8nQ...
Identity file: ~/.agentic/identity/my-agent.aid

# Sign an action
$ aid sign --action "deployed v1.2.3 to production"
Receipt: arec_9Lm2xP...
Signature: valid
Chain: linked to arec_8Kj1nM...

# Grant trust to another agent
$ aid trust grant --to aid_4Yn3kL... --capability "read:calendar" --expires "2026-03-01"
Trust: atrust_2Pm4xK...
Revocation key: arev_6Jn8mL...

# Verify an action receipt
$ aid verify --receipt arec_9Lm2xP...
Actor: aid_7xK9mP2... (my-agent)
Action: "deployed v1.2.3 to production"
Timestamp: 2026-02-24T15:30:00Z
Signature: VALID
Chain: VALID (3 receipts)

# Revoke trust
$ aid trust revoke --trust atrust_2Pm4xK...
Revoked: atrust_2Pm4xK...
Published to: revocation.agentralabs.tech
```

**For an AI agent using the MCP server:**

```
Human: "Deploy the new version to production"

Agent: [internal]
  1. Verify I have trust grant for "deploy:production" ✓
  2. Execute deployment
  3. Sign action receipt with my identity
  4. Chain receipt to previous action
  5. Store receipt in Hydra ledger

Agent: "Deployed v1.2.3 to production. 
        Receipt: arec_9Lm2xP...
        Signed with my identity: aid_7xK9mP2...
        Chained to previous deployment receipt."
```

---

# CLAUDE-CODE-INSTRUCTIONS

## Build Order

You are building AgenticIdentity, the cryptographic trust anchor for the AgenticOS ecosystem.

**Read the specs in this order:**
```
1. CLAUDE-CODE-INSTRUCTIONS (this section)
2. SPEC-PROJECT-STRUCTURE
3. SPEC-DEPENDENCIES
4. SPEC-DATA-STRUCTURES
5. SPEC-FILE-FORMAT
6. SPEC-WRITE-ENGINE
7. SPEC-QUERY-ENGINE
8. SPEC-INDEXES
9. SPEC-CLI
10. SPEC-FFI
11. SPEC-MCP
12. SPEC-TESTS
13. SPEC-RESEARCH-PAPER
```

**Plus hardening specs:**
```
14. SPEC-INSTALLER-UNIVERSAL
15. SPEC-RUNTIME-HARDENING
16. SPEC-RELEASE-PUBLISH
17. SPEC-DOCS-PUBLIC-SYNC
18. SPEC-CI-GUARDRAILS
```

---

### Phase 1: Foundation (Core Library)

1. Set up project structure per SPEC-PROJECT-STRUCTURE
2. Add dependencies per SPEC-DEPENDENCIES
3. Implement data structures per SPEC-DATA-STRUCTURES
4. Implement cryptographic primitives:
   - Ed25519 key generation, signing, verification
   - X25519 key exchange for encryption
   - Key derivation (HKDF)
   - Secure random generation
5. Write tests for crypto primitives

**Success Criteria:**
- [ ] Can generate Ed25519 key pairs
- [ ] Can sign and verify messages
- [ ] Can derive scoped keys from root
- [ ] All crypto tests pass

---

### Phase 2: Identity Anchor

6. Implement Identity struct and operations
7. Implement key derivation hierarchy
8. Implement key rotation logic
9. Implement identity document generation
10. Write tests for identity operations

**Success Criteria:**
- [ ] Can create new identity
- [ ] Can derive session/capability/device keys
- [ ] Can rotate keys while preserving identity
- [ ] Can serialize/deserialize identity document
- [ ] All identity tests pass

---

### Phase 3: Action Receipts

11. Implement ActionReceipt struct
12. Implement receipt signing
13. Implement receipt chaining (hash links)
14. Implement witness co-signing
15. Implement receipt verification
16. Write tests for receipts

**Success Criteria:**
- [ ] Can create and sign action receipts
- [ ] Can chain receipts with hash links
- [ ] Can add witness signatures
- [ ] Can verify receipt signatures and chains
- [ ] All receipt tests pass

---

### Phase 4: Trust Web

17. Implement TrustGrant struct
18. Implement capability URI parsing
19. Implement trust constraints (time, scope, count)
20. Implement trust verification
21. Implement revocation mechanism
22. Implement trust chain walking
23. Write tests for trust operations

**Success Criteria:**
- [ ] Can create trust grants
- [ ] Can verify trust grants
- [ ] Can revoke trust grants
- [ ] Can walk trust chains
- [ ] Can enforce constraints
- [ ] All trust tests pass

---

### Phase 5: File Format & Persistence

24. Implement .aid file format per SPEC-FILE-FORMAT
25. Implement encrypted storage for private keys
26. Implement identity file read/write
27. Implement receipt storage
28. Implement trust store
29. Write tests for persistence

**Success Criteria:**
- [ ] Can save/load identity files
- [ ] Private keys are encrypted at rest
- [ ] Can store/retrieve receipts
- [ ] Can store/retrieve trust grants
- [ ] All persistence tests pass

---

### Phase 6: Indexes & Queries

30. Implement indexes per SPEC-INDEXES
31. Implement query engine per SPEC-QUERY-ENGINE
32. Write tests for queries

**Success Criteria:**
- [ ] Can query receipts by actor, time, type
- [ ] Can query trust grants by grantor, grantee, capability
- [ ] Can verify trust chains efficiently
- [ ] All query tests pass

---

### Phase 7: CLI

33. Implement CLI per SPEC-CLI
34. Implement all subcommands
35. Write CLI integration tests

**Success Criteria:**
- [ ] `aid init` creates identity
- [ ] `aid sign` creates receipts
- [ ] `aid verify` verifies receipts
- [ ] `aid trust grant` creates trust
- [ ] `aid trust revoke` revokes trust
- [ ] `aid trust verify` checks trust
- [ ] All CLI tests pass

---

### Phase 8: MCP Server

36. Implement MCP server per SPEC-MCP
37. Implement all tools
38. Implement all resources
39. Write MCP integration tests

**Success Criteria:**
- [ ] MCP server starts and handles stdio
- [ ] All tools work via MCP
- [ ] All resources accessible via MCP
- [ ] Claude Desktop integration works
- [ ] All MCP tests pass

---

### Phase 9: FFI

40. Implement C API per SPEC-FFI
41. Generate header file
42. Write FFI tests
43. Create Python bindings example

**Success Criteria:**
- [ ] C header compiles
- [ ] Can call from C
- [ ] Can call from Python
- [ ] All FFI tests pass

---

### Phase 10: Hardening

44. Implement installer per SPEC-INSTALLER-UNIVERSAL
45. Apply runtime hardening per SPEC-RUNTIME-HARDENING
46. Set up release workflow per SPEC-RELEASE-PUBLISH
47. Create documentation per SPEC-DOCS-PUBLIC-SYNC
48. Add CI guardrails per SPEC-CI-GUARDRAILS

**Success Criteria:**
- [ ] Installer works for desktop/terminal/server profiles
- [ ] MCP config is merge-only
- [ ] Release publishes to crates.io AND PyPI
- [ ] All stress tests pass
- [ ] CI guardrails block bad PRs

---

### Phase 11: Research Paper

49. Write research paper per SPEC-RESEARCH-PAPER
50. Include real benchmarks from implementation
51. Generate figures and tables
52. Compile to PDF

**Success Criteria:**
- [ ] Paper is 5-10 pages
- [ ] All figures render
- [ ] Benchmarks are from real measurements
- [ ] PDF compiles cleanly

---

## Rules

1. **Do not add dependencies not listed in SPEC-DEPENDENCIES.** If you think you need something, implement it yourself or find a way without it.

2. **Do not skip tests.** Every phase has tests. Run them. If they fail, fix the code, don't fix the test.

3. **Do not use unsafe Rust unless explicitly required.** Crypto operations via libraries, not hand-rolled unsafe.

4. **Every public function must have a doc comment.**

5. **Every module must have a module-level doc comment.**

6. **No unwrap() in library code.** All errors must be properly typed and propagated.

7. **No println!() in library code.** Use the log crate for diagnostics.

8. **Private keys must NEVER be logged, printed, or exposed in errors.**

9. **All timestamps are Unix epoch microseconds (u64).**

10. **All cryptographic operations must be constant-time where relevant.**

11. **File format must be little-endian on all platforms.**

12. **Identity files must be encrypted at rest with a passphrase-derived key.**

---

## Success Criteria (Complete Build)

The build is complete when:
- [ ] `cargo test` — all tests pass, zero failures
- [ ] `cargo clippy` — zero warnings
- [ ] `cargo fmt --check` — passes
- [ ] `cargo build --release` — compiles successfully
- [ ] The `aid` CLI can create identities, sign receipts, manage trust
- [ ] MCP server works with Claude Desktop
- [ ] FFI bindings compile and work from Python
- [ ] Installer works for all profiles (desktop/terminal/server)
- [ ] Release publishes to crates.io AND PyPI
- [ ] All stress tests pass (multi-identity, concurrent signing, etc.)
- [ ] Research paper PDF generated with real benchmarks

---

# SPEC-PROJECT-STRUCTURE

```
agentic-identity/
├── Cargo.toml                    # Workspace root
├── README.md                     # Project overview
├── LICENSE                       # MIT
├── CHANGELOG.md                  # Version history
├── .gitignore
│
├── crates/
│   ├── agentic-identity/         # Core library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # Public API
│   │       ├── error.rs          # Error types
│   │       ├── crypto/
│   │       │   ├── mod.rs
│   │       │   ├── keys.rs       # Ed25519, X25519
│   │       │   ├── signing.rs    # Sign/verify
│   │       │   ├── encryption.rs # Encrypt/decrypt
│   │       │   ├── derivation.rs # Key derivation
│   │       │   └── random.rs     # Secure random
│   │       ├── identity/
│   │       │   ├── mod.rs
│   │       │   ├── anchor.rs     # Identity anchor
│   │       │   ├── document.rs   # Identity document
│   │       │   ├── rotation.rs   # Key rotation
│   │       │   └── derivation.rs # Derived keys
│   │       ├── receipt/
│   │       │   ├── mod.rs
│   │       │   ├── action.rs     # Action types
│   │       │   ├── receipt.rs    # Receipt struct
│   │       │   ├── chain.rs      # Receipt chaining
│   │       │   ├── witness.rs    # Witness signatures
│   │       │   └── verify.rs     # Verification
│   │       ├── trust/
│   │       │   ├── mod.rs
│   │       │   ├── grant.rs      # Trust grants
│   │       │   ├── capability.rs # Capability URIs
│   │       │   ├── constraint.rs # Constraints
│   │       │   ├── revocation.rs # Revocation
│   │       │   ├── chain.rs      # Trust chains
│   │       │   └── verify.rs     # Trust verification
│   │       ├── storage/
│   │       │   ├── mod.rs
│   │       │   ├── file.rs       # .aid file format
│   │       │   ├── encrypted.rs  # Encrypted storage
│   │       │   ├── receipt_store.rs
│   │       │   └── trust_store.rs
│   │       ├── index/
│   │       │   ├── mod.rs
│   │       │   ├── receipt_index.rs
│   │       │   ├── trust_index.rs
│   │       │   └── time_index.rs
│   │       └── query/
│   │           ├── mod.rs
│   │           ├── receipt_query.rs
│   │           └── trust_query.rs
│   │
│   ├── agentic-identity-mcp/     # MCP server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # Entry point
│   │       ├── server.rs         # MCP server impl
│   │       ├── tools.rs          # Tool handlers
│   │       ├── resources.rs      # Resource handlers
│   │       └── prompts.rs        # Prompt templates
│   │
│   ├── agentic-identity-cli/     # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # Entry point
│   │       ├── commands/
│   │       │   ├── mod.rs
│   │       │   ├── init.rs       # aid init
│   │       │   ├── show.rs       # aid show
│   │       │   ├── sign.rs       # aid sign
│   │       │   ├── verify.rs     # aid verify
│   │       │   ├── trust.rs      # aid trust *
│   │       │   ├── rotate.rs     # aid rotate
│   │       │   └── export.rs     # aid export
│   │       └── output.rs         # Formatting
│   │
│   └── agentic-identity-ffi/     # C FFI
│       ├── Cargo.toml
│       ├── cbindgen.toml
│       └── src/
│           └── lib.rs            # C API
│
├── python/                       # Python package
│   ├── pyproject.toml
│   ├── src/
│   │   └── agentic_identity/
│   │       ├── __init__.py
│   │       └── _ffi.py           # FFI bindings
│   └── tests/
│       └── test_identity.py
│
├── tests/
│   ├── integration/
│   │   ├── cli_tests.rs
│   │   ├── mcp_tests.rs
│   │   └── ffi_tests.rs
│   └── stress/
│       ├── multi_identity.rs
│       ├── concurrent_signing.rs
│       ├── trust_chain_depth.rs
│       └── receipt_chain_length.rs
│
├── benches/
│   ├── crypto_bench.rs
│   ├── signing_bench.rs
│   └── verification_bench.rs
│
├── scripts/
│   ├── install.sh                # Universal installer
│   ├── check-install-commands.sh
│   ├── check-canonical-sister.sh
│   └── test-primary-problems.sh
│
├── docs/
│   ├── quickstart.md
│   ├── concepts.md
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
│   └── python_example.py
│
├── paper/
│   ├── agenticidentity-paper.tex
│   ├── figures/
│   └── agenticidentity-paper.pdf
│
└── .github/
    └── workflows/
        ├── ci.yml
        ├── release.yml
        ├── install-command-guardrails.yml
        ├── canonical-sister-guardrails.yml
        └── social-release-broadcast.yml
```

---

# SPEC-DEPENDENCIES

## Workspace Cargo.toml

```toml
[workspace]
members = [
    "crates/agentic-identity",
    "crates/agentic-identity-mcp",
    "crates/agentic-identity-cli",
    "crates/agentic-identity-ffi",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/agentralabs/agentic-identity"
authors = ["Agentra Labs <contact@agentralabs.tech>"]

[workspace.dependencies]
# Crypto
ed25519-dalek = { version = "2.1", features = ["rand_core", "serde"] }
x25519-dalek = { version = "2.0", features = ["serde"] }
hkdf = "0.12"
sha2 = "0.10"
rand = "0.8"
rand_core = "0.6"
argon2 = "0.5"                    # Password-based key derivation
chacha20poly1305 = "0.10"        # Symmetric encryption for storage
zeroize = { version = "1.7", features = ["derive"] }  # Secure memory clearing

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"
base64 = "0.21"
hex = "0.4"

# Time
chrono = { version = "0.4", features = ["serde"] }

# CLI
clap = { version = "4.4", features = ["derive"] }

# MCP
mcp-core = "0.1"                 # Or implement MCP protocol directly

# Async
tokio = { version = "1.35", features = ["full"] }

# Logging
log = "0.4"
env_logger = "0.10"
tracing = "0.1"
tracing-subscriber = "0.3"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Testing
criterion = "0.5"
tempfile = "3.9"
```

## Core Library (agentic-identity)

```toml
[package]
name = "agentic-identity"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
ed25519-dalek.workspace = true
x25519-dalek.workspace = true
hkdf.workspace = true
sha2.workspace = true
rand.workspace = true
rand_core.workspace = true
argon2.workspace = true
chacha20poly1305.workspace = true
zeroize.workspace = true
serde.workspace = true
serde_json.workspace = true
bincode.workspace = true
base64.workspace = true
hex.workspace = true
chrono.workspace = true
log.workspace = true
thiserror.workspace = true

[dev-dependencies]
tempfile.workspace = true
criterion.workspace = true

[[bench]]
name = "crypto_bench"
harness = false
```

## MCP Server (agentic-identity-mcp)

```toml
[package]
name = "agentic-identity-mcp"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "agentic-identity-mcp"
path = "src/main.rs"

[dependencies]
agentic-identity = { path = "../agentic-identity" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
thiserror.workspace = true
anyhow.workspace = true
```

## CLI (agentic-identity-cli)

```toml
[package]
name = "agentic-identity-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "aid"
path = "src/main.rs"

[dependencies]
agentic-identity = { path = "../agentic-identity" }
clap.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
env_logger.workspace = true
log.workspace = true
thiserror.workspace = true
anyhow.workspace = true
```

## FFI (agentic-identity-ffi)

```toml
[package]
name = "agentic-identity-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "staticlib"]

[dependencies]
agentic-identity = { path = "../agentic-identity" }
libc = "0.2"

[build-dependencies]
cbindgen = "0.26"
```

---

## Dependency Justification

| Dependency | Purpose | Why This One |
|------------|---------|--------------|
| ed25519-dalek | Digital signatures | De facto standard, audited, well-maintained |
| x25519-dalek | Key exchange | Same authors as ed25519, compatible |
| hkdf | Key derivation | RFC 5869 compliant, from RustCrypto |
| sha2 | Hashing | RustCrypto standard, well-audited |
| argon2 | Password KDF | Winner of Password Hashing Competition |
| chacha20poly1305 | Symmetric encryption | Modern AEAD, no AES hardware requirement |
| zeroize | Secure memory | Prevents private keys lingering in memory |
| rand | Randomness | Standard, uses OS entropy |
| serde | Serialization | De facto standard for Rust serialization |
| chrono | Timestamps | Standard time library |
| clap | CLI parsing | Best CLI framework for Rust |
| tokio | Async runtime | Standard async runtime |
| thiserror | Error types | Clean error derive macros |

**No other dependencies allowed without explicit justification.**

---

# SPEC-DATA-STRUCTURES

## Core Types

```rust
//! Core data structures for AgenticIdentity

use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ============================================================================
// IDENTITY TYPES
// ============================================================================

/// Unique identifier for an identity (base58-encoded public key hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub String);  // Format: "aid_" + base58(sha256(public_key)[0..16])

/// The root identity anchor containing key material
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct IdentityAnchor {
    /// The root signing key (private)
    signing_key: SigningKey,
    /// The root verifying key (public)
    pub verifying_key: VerifyingKey,
    /// Creation timestamp (microseconds since epoch)
    pub created_at: u64,
    /// Human-readable name (optional)
    pub name: Option<String>,
    /// Key rotation history
    pub rotation_history: Vec<KeyRotation>,
}

/// Public identity document (shareable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDocument {
    /// Identity ID
    pub id: IdentityId,
    /// Public key (base64)
    pub public_key: String,
    /// Algorithm identifier
    pub algorithm: String,  // "ed25519"
    /// Creation timestamp
    pub created_at: u64,
    /// Human-readable name
    pub name: Option<String>,
    /// Key rotation history (public parts only)
    pub rotation_history: Vec<PublicKeyRotation>,
    /// Attestations from other identities
    pub attestations: Vec<Attestation>,
    /// Self-signature over all fields
    pub signature: String,
}

/// Record of a key rotation
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KeyRotation {
    /// Previous public key
    pub previous_key: String,
    /// New public key
    pub new_key: String,
    /// Rotation timestamp
    pub rotated_at: u64,
    /// Reason for rotation
    pub reason: RotationReason,
    /// Signature by previous key authorizing rotation
    pub authorization_signature: String,
}

/// Public view of key rotation (no private data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRotation {
    pub previous_key: String,
    pub new_key: String,
    pub rotated_at: u64,
    pub reason: RotationReason,
    pub authorization_signature: String,
}

/// Reason for key rotation
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub enum RotationReason {
    Scheduled,
    Compromised,
    DeviceLost,
    PolicyRequired,
    Manual,
}

/// Attestation from another identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Attester's identity ID
    pub attester: IdentityId,
    /// Attester's public key at time of attestation
    pub attester_key: String,
    /// What is being attested
    pub claim: AttestationClaim,
    /// When the attestation was made
    pub attested_at: u64,
    /// Attester's signature
    pub signature: String,
}

/// Types of attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationClaim {
    /// Attests that identity controls a key
    KeyOwnership,
    /// Attests identity with a name
    NameVerification { name: String },
    /// Attests identity is associated with organization
    OrganizationMembership { org: String },
    /// Custom attestation
    Custom { claim_type: String, claim_value: String },
}

// ============================================================================
// DERIVED KEY TYPES
// ============================================================================

/// Purpose of a derived key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Session-specific key (short-lived)
    Session { session_id: String },
    /// Capability-specific key (scoped to permissions)
    Capability { capability_uri: String },
    /// Device-specific key (bound to hardware)
    Device { device_id: String },
    /// Encryption key (for X25519)
    Encryption,
}

/// A derived key with its purpose and constraints
pub struct DerivedKey {
    /// The derived signing key
    signing_key: SigningKey,
    /// The derived verifying key
    pub verifying_key: VerifyingKey,
    /// Purpose of this key
    pub purpose: KeyPurpose,
    /// Parent identity
    pub parent_id: IdentityId,
    /// Derivation path
    pub derivation_path: String,
    /// Validity period
    pub valid_from: u64,
    pub valid_until: Option<u64>,
}

// ============================================================================
// ACTION RECEIPT TYPES
// ============================================================================

/// Unique identifier for a receipt
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);  // Format: "arec_" + base58(sha256(receipt)[0..16])

/// An action receipt proving an agent took an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceipt {
    /// Unique receipt ID
    pub id: ReceiptId,
    /// Actor's identity ID
    pub actor: IdentityId,
    /// Actor's public key used for signing
    pub actor_key: String,
    /// Type of action
    pub action_type: ActionType,
    /// Action content
    pub action: ActionContent,
    /// Timestamp (microseconds since epoch)
    pub timestamp: u64,
    /// Context hash (optional, for linking to state)
    pub context_hash: Option<String>,
    /// Previous receipt in chain (optional)
    pub previous_receipt: Option<ReceiptId>,
    /// Hash of all above fields
    pub receipt_hash: String,
    /// Signature over receipt_hash
    pub signature: String,
    /// Witness signatures (optional)
    pub witnesses: Vec<WitnessSignature>,
}

/// Type of action being recorded
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    /// A decision was made
    Decision,
    /// An observation was recorded
    Observation,
    /// A mutation occurred (state change)
    Mutation,
    /// Trust was delegated
    Delegation,
    /// Trust was revoked
    Revocation,
    /// Identity operation (creation, rotation)
    IdentityOperation,
    /// Custom action type
    Custom(String),
}

/// Content of an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContent {
    /// Human-readable description
    pub description: String,
    /// Structured data (type-specific)
    pub data: Option<serde_json::Value>,
    /// References to related resources
    pub references: Vec<String>,
}

/// A witness signature on a receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// Witness identity ID
    pub witness: IdentityId,
    /// Witness public key
    pub witness_key: String,
    /// Timestamp of witnessing
    pub witnessed_at: u64,
    /// Signature over receipt_hash
    pub signature: String,
}

// ============================================================================
// TRUST TYPES
// ============================================================================

/// Unique identifier for a trust grant
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustId(pub String);  // Format: "atrust_" + base58(sha256(grant)[0..16])

/// A trust relationship between identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Unique trust ID
    pub id: TrustId,
    /// Grantor identity (who is granting trust)
    pub grantor: IdentityId,
    /// Grantor's public key used for signing
    pub grantor_key: String,
    /// Grantee identity (who receives trust)
    pub grantee: IdentityId,
    /// Grantee's public key at time of grant
    pub grantee_key: String,
    /// Capabilities being granted
    pub capabilities: Vec<Capability>,
    /// Constraints on the grant
    pub constraints: TrustConstraints,
    /// Can grantee delegate to others?
    pub delegation_allowed: bool,
    /// Maximum delegation depth (if delegation allowed)
    pub max_delegation_depth: Option<u32>,
    /// Revocation configuration
    pub revocation: RevocationConfig,
    /// Grant timestamp
    pub granted_at: u64,
    /// Hash of all above fields
    pub grant_hash: String,
    /// Grantor's signature
    pub grantor_signature: String,
    /// Grantee's acknowledgment signature (optional)
    pub grantee_acknowledgment: Option<String>,
}

/// A capability being granted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Capability URI (e.g., "read:calendar", "execute:deploy:production")
    pub uri: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Capability-specific constraints
    pub constraints: Option<serde_json::Value>,
}

/// Constraints on a trust grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConstraints {
    /// Not valid before this time
    pub not_before: u64,
    /// Not valid after this time (None = until revoked)
    pub not_after: Option<u64>,
    /// Maximum number of uses (None = unlimited)
    pub max_uses: Option<u64>,
    /// Geographic constraints (optional)
    pub geographic: Option<Vec<String>>,
    /// IP constraints (optional)
    pub ip_allowlist: Option<Vec<String>>,
    /// Custom constraints
    pub custom: Option<serde_json::Value>,
}

/// Configuration for revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationConfig {
    /// Revocation key ID (derived key for revoking)
    pub revocation_key_id: String,
    /// Channel where revocation will be published
    pub revocation_channel: RevocationChannel,
    /// Required witnesses for revocation (optional)
    pub required_witnesses: Vec<IdentityId>,
}

/// Where revocation is published
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationChannel {
    /// Local revocation list
    Local,
    /// HTTP endpoint
    Http { url: String },
    /// Distributed ledger
    Ledger { ledger_id: String },
    /// Multiple channels
    Multi(Vec<RevocationChannel>),
}

/// A revocation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    /// Trust grant being revoked
    pub trust_id: TrustId,
    /// Who is revoking
    pub revoker: IdentityId,
    /// Revocation timestamp
    pub revoked_at: u64,
    /// Reason for revocation
    pub reason: RevocationReason,
    /// Signature with revocation key
    pub signature: String,
    /// Witness signatures (if required)
    pub witnesses: Vec<WitnessSignature>,
}

/// Reason for revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    Expired,
    Compromised,
    PolicyViolation,
    ManualRevocation,
    GranteeRequest,
    Custom(String),
}

// ============================================================================
// VERIFICATION TYPES
// ============================================================================

/// Result of verifying a receipt
#[derive(Debug, Clone)]
pub struct ReceiptVerification {
    /// Is the signature valid?
    pub signature_valid: bool,
    /// Is the chain valid (if chained)?
    pub chain_valid: Option<bool>,
    /// Are witness signatures valid?
    pub witnesses_valid: Vec<bool>,
    /// Overall validity
    pub is_valid: bool,
    /// Verification timestamp
    pub verified_at: u64,
}

/// Result of verifying a trust grant
#[derive(Debug, Clone)]
pub struct TrustVerification {
    /// Is the grant signature valid?
    pub signature_valid: bool,
    /// Is the grant within validity period?
    pub time_valid: bool,
    /// Is the grant not revoked?
    pub not_revoked: bool,
    /// Has max uses been exceeded?
    pub uses_valid: bool,
    /// Is the capability specifically granted?
    pub capability_granted: bool,
    /// Trust chain (if delegated)
    pub trust_chain: Vec<TrustId>,
    /// Overall validity
    pub is_valid: bool,
    /// Verification timestamp
    pub verified_at: u64,
}

// ============================================================================
// STORAGE TYPES
// ============================================================================

/// Encrypted identity file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedIdentityFile {
    /// File format version
    pub version: u32,
    /// Salt for key derivation
    pub salt: String,
    /// Nonce for encryption
    pub nonce: String,
    /// Encrypted identity anchor
    pub encrypted_data: String,
    /// Public identity document (unencrypted)
    pub public_document: IdentityDocument,
}

/// Query filters for receipts
#[derive(Debug, Clone, Default)]
pub struct ReceiptQuery {
    /// Filter by actor
    pub actor: Option<IdentityId>,
    /// Filter by action type
    pub action_type: Option<ActionType>,
    /// Filter by time range
    pub time_range: Option<(u64, u64)>,
    /// Filter by chain (receipts in this chain)
    pub chain_root: Option<ReceiptId>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Sort order
    pub sort: SortOrder,
}

/// Query filters for trust grants
#[derive(Debug, Clone, Default)]
pub struct TrustQuery {
    /// Filter by grantor
    pub grantor: Option<IdentityId>,
    /// Filter by grantee
    pub grantee: Option<IdentityId>,
    /// Filter by capability URI (prefix match)
    pub capability_prefix: Option<String>,
    /// Only valid grants (not expired, not revoked)
    pub valid_only: bool,
    /// Maximum results
    pub limit: Option<usize>,
}

/// Sort order for queries
#[derive(Debug, Clone, Default)]
pub enum SortOrder {
    #[default]
    NewestFirst,
    OldestFirst,
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Identity error types
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Signature verification failed")]
    SignatureInvalid,
    
    #[error("Identity not found: {0}")]
    NotFound(String),
    
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    
    #[error("Trust not granted for capability: {0}")]
    TrustNotGranted(String),
    
    #[error("Trust has been revoked: {0}")]
    TrustRevoked(String),
    
    #[error("Trust expired")]
    TrustExpired,
    
    #[error("Max uses exceeded")]
    MaxUsesExceeded,
    
    #[error("Invalid receipt chain")]
    InvalidChain,
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid file format: {0}")]
    InvalidFileFormat(String),
}
```

---

# SPEC-FILE-FORMAT

## File Format Overview

AgenticIdentity uses the `.aid` extension for identity files.

```
FILE: ~/.agentic/identity/{name}.aid

Format: JSON (encrypted private data) + plaintext public document
        Future: Binary format for performance if needed

Structure:
{
    "version": 1,
    "format": "aid-v1",
    "encryption": {
        "algorithm": "chacha20-poly1305",
        "kdf": "argon2id",
        "salt": "<base64>",
        "nonce": "<base64>"
    },
    "encrypted_anchor": "<base64>",
    "public_document": { ... }
}
```

## Directory Structure

```
~/.agentic/
├── identity/
│   ├── default.aid              # Default identity
│   ├── {name}.aid               # Named identities
│   └── .keys/                   # Derived keys cache (encrypted)
│       ├── sessions/
│       └── capabilities/
│
├── receipts/
│   ├── index.db                 # Receipt index (SQLite or custom)
│   └── chains/
│       └── {chain_root}/
│           └── {receipt_id}.receipt
│
├── trust/
│   ├── granted/                 # Trust grants we've given
│   │   └── {trust_id}.grant
│   ├── received/                # Trust grants we've received
│   │   └── {trust_id}.grant
│   └── revocations/             # Revocation records
│       └── {trust_id}.revoke
│
└── config.toml                  # Configuration
```

## Encryption Scheme

```
KEY DERIVATION:
passphrase (user input)
    │
    ▼
Argon2id(passphrase, salt, m=65536, t=3, p=4)
    │
    ▼
256-bit master_key
    │
    ▼
HKDF-SHA256(master_key, "identity-encryption")
    │
    ▼
256-bit encryption_key

ENCRYPTION:
plaintext_anchor = serialize(IdentityAnchor)
nonce = random(12 bytes)
ciphertext = ChaCha20-Poly1305(encryption_key, nonce, plaintext_anchor)
```

## Receipt File Format

```json
{
    "version": 1,
    "receipt": {
        "id": "arec_...",
        "actor": "aid_...",
        "actor_key": "<base64>",
        "action_type": "Decision",
        "action": {
            "description": "...",
            "data": { ... },
            "references": [ ... ]
        },
        "timestamp": 1708789200000000,
        "context_hash": "<hex>",
        "previous_receipt": "arec_...",
        "receipt_hash": "<hex>",
        "signature": "<base64>",
        "witnesses": [ ... ]
    }
}
```

## Trust Grant File Format

```json
{
    "version": 1,
    "grant": {
        "id": "atrust_...",
        "grantor": "aid_...",
        "grantor_key": "<base64>",
        "grantee": "aid_...",
        "grantee_key": "<base64>",
        "capabilities": [
            {
                "uri": "read:calendar",
                "description": "Read calendar events"
            }
        ],
        "constraints": {
            "not_before": 1708789200000000,
            "not_after": 1711467600000000,
            "max_uses": null
        },
        "delegation_allowed": false,
        "revocation": {
            "revocation_key_id": "...",
            "revocation_channel": { "type": "Local" }
        },
        "granted_at": 1708789200000000,
        "grant_hash": "<hex>",
        "grantor_signature": "<base64>"
    }
}
```

---

# SPEC-CLI

## Command Overview

```
aid — AgenticIdentity CLI

USAGE:
    aid <COMMAND>

COMMANDS:
    init        Create a new identity
    show        Display identity information
    list        List all identities
    sign        Sign an action and create a receipt
    verify      Verify a receipt or trust grant
    trust       Manage trust relationships
    rotate      Rotate identity keys
    export      Export identity (public only)
    import      Import an identity
    derive      Derive a scoped key
    receipt     Manage receipts
    config      Manage configuration
    help        Print help

OPTIONS:
    -h, --help       Print help
    -V, --version    Print version
    -v, --verbose    Verbose output
    -q, --quiet      Quiet output
    --identity       Use specific identity (default: default)
```

## Detailed Commands

### aid init

```
aid init — Create a new identity

USAGE:
    aid init [OPTIONS]

OPTIONS:
    --name <NAME>           Identity name (default: "default")
    --passphrase            Prompt for passphrase (default: prompt)
    --passphrase-file <F>   Read passphrase from file
    --no-passphrase         No encryption (NOT RECOMMENDED)
    --output <PATH>         Output path (default: ~/.agentic/identity/{name}.aid)

EXAMPLES:
    aid init
    aid init --name work
    aid init --name server --passphrase-file /run/secrets/aid-pass
```

### aid show

```
aid show — Display identity information

USAGE:
    aid show [OPTIONS]

OPTIONS:
    --name <NAME>           Identity name (default: "default")
    --public                Show only public information
    --json                  Output as JSON
    --fingerprint           Show only fingerprint

EXAMPLES:
    aid show
    aid show --name work --public
    aid show --fingerprint
```

### aid sign

```
aid sign — Sign an action and create a receipt

USAGE:
    aid sign [OPTIONS] --action <DESCRIPTION>

OPTIONS:
    --action <DESC>         Action description (required)
    --type <TYPE>           Action type (decision|observation|mutation|delegation|revocation|custom)
    --data <JSON>           Action data (JSON)
    --data-file <FILE>      Read action data from file
    --context <HASH>        Context hash
    --chain <RECEIPT_ID>    Chain to previous receipt
    --witness <IDENTITY>    Request witness (can repeat)
    --output <PATH>         Output receipt file
    --json                  Output as JSON

EXAMPLES:
    aid sign --action "Deployed v1.2.3 to production" --type mutation
    aid sign --action "Approved budget request" --type decision --chain arec_...
    aid sign --action "Observed error rate spike" --type observation --data '{"rate": 0.05}'
```

### aid verify

```
aid verify — Verify a receipt or trust grant

USAGE:
    aid verify <COMMAND>

COMMANDS:
    receipt     Verify an action receipt
    trust       Verify a trust grant
    chain       Verify a receipt chain

EXAMPLES:
    aid verify receipt arec_7xK9mP2...
    aid verify receipt --file /path/to/receipt.json
    aid verify trust atrust_4Yn3kL...
    aid verify chain --root arec_7xK9mP2... --depth 10
```

### aid trust

```
aid trust — Manage trust relationships

USAGE:
    aid trust <COMMAND>

COMMANDS:
    grant       Grant trust to another identity
    revoke      Revoke a trust grant
    list        List trust grants
    verify      Verify trust for a capability
    show        Show details of a trust grant

EXAMPLES:
    aid trust grant --to aid_4Yn3kL... --capability "read:calendar" --expires "2026-03-01"
    aid trust grant --to aid_4Yn3kL... --capability "execute:*" --max-uses 10
    aid trust revoke --trust atrust_2Pm4xK... --reason "No longer needed"
    aid trust list --granted
    aid trust list --received
    aid trust verify --identity aid_4Yn3kL... --capability "read:calendar"
```

### aid rotate

```
aid rotate — Rotate identity keys

USAGE:
    aid rotate [OPTIONS]

OPTIONS:
    --reason <REASON>       Rotation reason (scheduled|compromised|policy|manual)
    --force                 Force rotation even if recent
    --backup <PATH>         Backup old key to path

EXAMPLES:
    aid rotate --reason scheduled
    aid rotate --reason compromised --backup /secure/old-key.bak
```

### aid export

```
aid export — Export identity (public document only)

USAGE:
    aid export [OPTIONS]

OPTIONS:
    --name <NAME>           Identity name
    --output <PATH>         Output file (default: stdout)
    --format <FMT>          Format (json|base64)

EXAMPLES:
    aid export --name default --output my-identity.json
    aid export --format base64
```

### aid derive

```
aid derive — Derive a scoped key

USAGE:
    aid derive <COMMAND>

COMMANDS:
    session     Derive a session key
    capability  Derive a capability-scoped key
    device      Derive a device-bound key

EXAMPLES:
    aid derive session --id "session-123" --expires "1h"
    aid derive capability --uri "read:calendar" --expires "7d"
    aid derive device --device-id "macbook-pro-2024"
```

---

# SPEC-MCP

## MCP Server Overview

The AgenticIdentity MCP server exposes identity operations to AI agents via the Model Context Protocol.

**Server Name:** `agentic-identity-mcp`

**Transport:** stdio (default), HTTP (server mode)

---

## Tools

### identity_create

Create a new identity.

```json
{
    "name": "identity_create",
    "description": "Create a new cryptographic identity for the agent",
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Human-readable name for the identity"
            }
        },
        "required": []
    }
}
```

### identity_show

Display identity information.

```json
{
    "name": "identity_show",
    "description": "Show the current identity's public information",
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Identity name (default: current)"
            }
        }
    }
}
```

### action_sign

Sign an action and create a receipt.

```json
{
    "name": "action_sign",
    "description": "Sign an action with the agent's identity, creating a verifiable receipt",
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "Description of the action being taken"
            },
            "action_type": {
                "type": "string",
                "enum": ["decision", "observation", "mutation", "delegation", "revocation"],
                "description": "Type of action"
            },
            "data": {
                "type": "object",
                "description": "Structured data about the action"
            },
            "chain_to": {
                "type": "string",
                "description": "Receipt ID to chain this action to"
            }
        },
        "required": ["action"]
    }
}
```

### receipt_verify

Verify an action receipt.

```json
{
    "name": "receipt_verify",
    "description": "Verify that a receipt is valid and was signed by the claimed identity",
    "inputSchema": {
        "type": "object",
        "properties": {
            "receipt_id": {
                "type": "string",
                "description": "Receipt ID to verify"
            }
        },
        "required": ["receipt_id"]
    }
}
```

### trust_grant

Grant trust to another identity.

```json
{
    "name": "trust_grant",
    "description": "Grant trust to another identity for specific capabilities",
    "inputSchema": {
        "type": "object",
        "properties": {
            "grantee": {
                "type": "string",
                "description": "Identity ID receiving trust"
            },
            "capabilities": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Capability URIs to grant (e.g., 'read:calendar')"
            },
            "expires": {
                "type": "string",
                "description": "Expiration (ISO 8601 or duration like '7d')"
            },
            "max_uses": {
                "type": "integer",
                "description": "Maximum number of uses"
            },
            "allow_delegation": {
                "type": "boolean",
                "description": "Can grantee delegate to others?"
            }
        },
        "required": ["grantee", "capabilities"]
    }
}
```

### trust_revoke

Revoke a trust grant.

```json
{
    "name": "trust_revoke",
    "description": "Revoke a previously granted trust",
    "inputSchema": {
        "type": "object",
        "properties": {
            "trust_id": {
                "type": "string",
                "description": "Trust grant ID to revoke"
            },
            "reason": {
                "type": "string",
                "description": "Reason for revocation"
            }
        },
        "required": ["trust_id"]
    }
}
```

### trust_verify

Verify trust for a capability.

```json
{
    "name": "trust_verify",
    "description": "Verify that an identity has trust for a specific capability",
    "inputSchema": {
        "type": "object",
        "properties": {
            "identity": {
                "type": "string",
                "description": "Identity ID to check"
            },
            "capability": {
                "type": "string",
                "description": "Capability URI to verify"
            }
        },
        "required": ["identity", "capability"]
    }
}
```

### trust_list

List trust grants.

```json
{
    "name": "trust_list",
    "description": "List trust grants (given or received)",
    "inputSchema": {
        "type": "object",
        "properties": {
            "direction": {
                "type": "string",
                "enum": ["granted", "received"],
                "description": "Filter by direction"
            },
            "valid_only": {
                "type": "boolean",
                "description": "Only show valid (non-expired, non-revoked) grants"
            }
        }
    }
}
```

### receipt_list

List action receipts.

```json
{
    "name": "receipt_list",
    "description": "List action receipts",
    "inputSchema": {
        "type": "object",
        "properties": {
            "actor": {
                "type": "string",
                "description": "Filter by actor identity"
            },
            "action_type": {
                "type": "string",
                "description": "Filter by action type"
            },
            "since": {
                "type": "string",
                "description": "Only receipts after this time (ISO 8601)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results"
            }
        }
    }
}
```

### identity_health

Check identity system health.

```json
{
    "name": "identity_health",
    "description": "Check health of the identity system",
    "inputSchema": {
        "type": "object",
        "properties": {}
    }
}
```

---

## Resources

### aid://identity/{name}

Identity document.

```
URI: aid://identity/default
Returns: IdentityDocument (JSON)
```

### aid://receipt/{id}

Action receipt.

```
URI: aid://receipt/arec_7xK9mP2...
Returns: ActionReceipt (JSON)
```

### aid://trust/{id}

Trust grant.

```
URI: aid://trust/atrust_4Yn3kL...
Returns: TrustGrant (JSON)
```

### aid://receipts/recent

Recent receipts.

```
URI: aid://receipts/recent?limit=10
Returns: Array of ActionReceipt
```

### aid://trust/granted

Trust grants given by current identity.

```
URI: aid://trust/granted
Returns: Array of TrustGrant
```

### aid://trust/received

Trust grants received by current identity.

```
URI: aid://trust/received
Returns: Array of TrustGrant
```

---

## Prompts

### prove_action

```json
{
    "name": "prove_action",
    "description": "Create a signed proof that you took an action",
    "arguments": [
        {
            "name": "action",
            "description": "What action did you take?",
            "required": true
        }
    ]
}
```

### verify_identity

```json
{
    "name": "verify_identity",
    "description": "Verify another agent's identity",
    "arguments": [
        {
            "name": "identity_id",
            "description": "The identity to verify",
            "required": true
        }
    ]
}
```

### delegate_trust

```json
{
    "name": "delegate_trust",
    "description": "Delegate specific capabilities to another agent",
    "arguments": [
        {
            "name": "to",
            "description": "Who to delegate to?",
            "required": true
        },
        {
            "name": "capabilities",
            "description": "What capabilities to delegate?",
            "required": true
        }
    ]
}
```

---

## Claude Desktop Configuration

```json
{
    "mcpServers": {
        "agentic-identity": {
            "command": "/usr/local/bin/agentic-identity-mcp",
            "args": ["--identity", "default"],
            "env": {}
        }
    }
}
```

---

# SPEC-TESTS

## Test Organization

```
tests/
├── unit/                    # Unit tests (in crates/*/src/)
├── integration/             # Integration tests
│   ├── cli_tests.rs
│   ├── mcp_tests.rs
│   └── ffi_tests.rs
└── stress/                  # Stress tests
    ├── multi_identity.rs
    ├── concurrent_signing.rs
    ├── trust_chain_depth.rs
    └── receipt_chain_length.rs
```

---

## Phase 1 Tests: Cryptography

```
test_ed25519_key_generation
  - Generate key pair
  - Public key is 32 bytes
  - Private key is 32 bytes

test_ed25519_sign_verify
  - Sign message with private key
  - Verify with public key
  - Passes

test_ed25519_sign_verify_wrong_key
  - Sign with key A
  - Verify with key B
  - Fails

test_ed25519_sign_verify_tampered
  - Sign message
  - Tamper with message
  - Verification fails

test_x25519_key_exchange
  - Generate two key pairs
  - Both derive same shared secret

test_hkdf_derivation
  - Derive key with context
  - Same inputs = same output
  - Different context = different output

test_argon2_passphrase_derivation
  - Derive key from passphrase
  - Correct passphrase = correct key
  - Wrong passphrase = different key

test_chacha20poly1305_encrypt_decrypt
  - Encrypt plaintext
  - Decrypt ciphertext
  - Matches original

test_chacha20poly1305_tamper_detection
  - Encrypt plaintext
  - Tamper with ciphertext
  - Decryption fails
```

---

## Phase 2 Tests: Identity

```
test_identity_create
  - Create identity
  - Has valid public key
  - Has valid ID format (aid_...)

test_identity_document_self_signed
  - Create identity document
  - Signature is valid

test_identity_derive_session_key
  - Derive session key
  - Can sign with derived key
  - Signature verifies with derived public key

test_identity_derive_capability_key
  - Derive capability key for "read:calendar"
  - Different capability = different key

test_identity_derive_device_key
  - Derive device key
  - Different device ID = different key

test_identity_rotation
  - Create identity
  - Rotate key
  - Old public key in history
  - New key is active
  - Authorization signature is valid

test_identity_rotation_chain
  - Rotate multiple times
  - Full history preserved
  - Can verify chain of rotations
```

---

## Phase 3 Tests: Receipts

```
test_receipt_create
  - Create receipt for action
  - Has valid ID format (arec_...)
  - Has signature

test_receipt_verify
  - Create receipt
  - Verify signature
  - Passes

test_receipt_verify_wrong_actor
  - Create receipt
  - Verify with different public key
  - Fails

test_receipt_chain_link
  - Create receipt A
  - Create receipt B chained to A
  - B.previous_receipt = A.id
  - B.receipt_hash includes A.id

test_receipt_chain_verify
  - Create chain of 5 receipts
  - Verify chain integrity
  - All links valid

test_receipt_chain_tamper
  - Create chain
  - Tamper with middle receipt
  - Chain verification fails

test_receipt_witness_add
  - Create receipt
  - Add witness signature
  - Both signatures valid

test_receipt_witness_verify
  - Receipt with 3 witnesses
  - All witness signatures valid

test_receipt_types
  - Create receipt for each ActionType
  - All serialize/deserialize correctly
```

---

## Phase 4 Tests: Trust

```
test_trust_grant_create
  - Create trust grant
  - Has valid ID format (atrust_...)
  - Signature is valid

test_trust_grant_verify_valid
  - Create grant with future expiry
  - Verify now
  - Is valid

test_trust_grant_verify_expired
  - Create grant with past expiry
  - Verify now
  - Is not valid (expired)

test_trust_grant_verify_not_yet_valid
  - Create grant with future not_before
  - Verify now
  - Is not valid (not yet active)

test_trust_grant_verify_max_uses
  - Create grant with max_uses = 3
  - Use 3 times
  - 4th verification fails

test_trust_revoke
  - Create grant
  - Revoke grant
  - Verification fails (revoked)

test_trust_capability_matching
  - Grant "read:*"
  - Verify "read:calendar" = valid
  - Verify "write:calendar" = invalid

test_trust_delegation_allowed
  - A grants to B with delegation
  - B grants to C
  - C can verify through chain

test_trust_delegation_not_allowed
  - A grants to B without delegation
  - B cannot grant to C

test_trust_chain_depth_limit
  - Set max delegation depth = 2
  - A → B → C valid
  - A → B → C → D invalid (depth exceeded)

test_trust_revoke_cascades
  - A → B → C chain
  - Revoke A → B
  - C's trust is also invalid
```

---

## Phase 5 Tests: Persistence

```
test_identity_file_save_load
  - Create identity
  - Save to file
  - Load from file
  - Keys match

test_identity_file_encryption
  - Save with passphrase
  - File content is encrypted
  - Can decrypt with correct passphrase

test_identity_file_wrong_passphrase
  - Save with passphrase A
  - Try to load with passphrase B
  - Fails with InvalidPassphrase

test_receipt_store_save_load
  - Store 100 receipts
  - Load by ID
  - All match

test_trust_store_save_load
  - Store 50 trust grants
  - Load by ID
  - All match

test_revocation_store
  - Store revocation
  - Query by trust ID
  - Revocation found
```

---

## Phase 6 Tests: Queries

```
test_receipt_query_by_actor
  - Create receipts from 3 actors
  - Query by actor A
  - Only A's receipts returned

test_receipt_query_by_type
  - Create receipts of different types
  - Query by Decision
  - Only Decision receipts returned

test_receipt_query_by_time_range
  - Create receipts at different times
  - Query range [T1, T2]
  - Only receipts in range returned

test_receipt_query_sort_order
  - Create receipts
  - Query with NewestFirst
  - Ordered correctly
  - Query with OldestFirst
  - Ordered correctly

test_trust_query_by_grantor
  - Create grants from multiple grantors
  - Query by grantor A
  - Only A's grants returned

test_trust_query_by_capability
  - Create grants with different capabilities
  - Query by "read:*"
  - Only matching grants returned

test_trust_query_valid_only
  - Create valid and expired grants
  - Query with valid_only = true
  - Only valid grants returned
```

---

## Stress Tests

```
test_stress_multi_identity
  - Create 100 identities concurrently
  - All have unique IDs
  - All can sign/verify

test_stress_concurrent_signing
  - Single identity
  - 1000 concurrent sign operations
  - All receipts valid
  - No race conditions

test_stress_receipt_chain_length
  - Create chain of 10,000 receipts
  - Verify chain
  - Complete in < 1 second

test_stress_trust_chain_depth
  - Create trust chain of depth 100
  - Verify terminal trust
  - Complete in < 100ms

test_stress_large_receipt_store
  - Store 100,000 receipts
  - Query by actor
  - Complete in < 100ms
```

---

## MCP Integration Tests

```
test_mcp_server_startup
  - Start MCP server
  - Responds to initialize
  - Lists tools correctly

test_mcp_identity_create
  - Call identity_create via MCP
  - Returns valid identity

test_mcp_action_sign
  - Call action_sign via MCP
  - Returns valid receipt

test_mcp_trust_grant_verify
  - Grant trust via MCP
  - Verify via MCP
  - Succeeds

test_mcp_concurrent_operations
  - Multiple concurrent MCP calls
  - All succeed
  - No corruption
```

---

# SPEC-RESEARCH-PAPER

## Paper Structure

```
Title: AgenticIdentity: A Cryptographic Trust Anchor for AI Agent Systems

Abstract (150 words)
- Problem: AI agents lack cryptographic identity and accountability
- Solution: Identity anchors, signed receipts, revocable trust
- Results: Key metrics from implementation
- Impact: Foundation for accountable AI systems

1. Introduction (1 page)
- AI agents are taking actions in the world
- No cryptographic proof of identity or accountability
- The trust problem in multi-agent systems
- Our contributions

2. Background (0.5 page)
- Existing identity systems (PKI, DID, WebAuthn)
- Why they don't work for AI agents
- Requirements for agent identity

3. Architecture (2 pages)
3.1 Identity Anchor
    - Key hierarchy
    - Derivation scheme
    - Rotation mechanism
3.2 Action Receipts
    - Receipt structure
    - Chaining mechanism
    - Witness signatures
3.3 Trust Web
    - Grant structure
    - Capability URIs
    - Revocation channels

4. Implementation (1 page)
- Rust implementation
- Cryptographic primitives used
- File format design
- MCP integration

5. Evaluation (1.5 pages)
5.1 Performance Benchmarks
    - Key generation time
    - Signing throughput
    - Verification throughput
    - Trust chain verification
5.2 Security Analysis
    - Threat model
    - Security properties
    - Limitations

6. Use Cases (0.5 page)
- Agent accountability
- Multi-agent coordination
- Delegated authority
- Audit trails

7. Related Work (0.5 page)
- SPIFFE/SPIRE
- DID methods
- Blockchain-based identity
- How AgenticIdentity differs

8. Conclusion (0.25 page)
- Summary
- Future work
- Availability

References
```

## Key Figures

```
Figure 1: Identity Anchor Key Hierarchy
Figure 2: Receipt Chain Structure  
Figure 3: Trust Web Example
Figure 4: Performance Benchmarks (bar chart)
Figure 5: Integration with AgenticOS
```

## Key Tables

```
Table 1: Comparison with Existing Identity Systems
Table 2: Cryptographic Primitives Used
Table 3: Performance Metrics
Table 4: Security Properties
```

## Benchmark Targets

```
Key generation:        < 1 ms
Sign operation:        < 0.5 ms  
Verify operation:      < 0.5 ms
Trust chain (depth 10): < 5 ms
Receipt chain (1000):  < 50 ms
File size (identity):  < 10 KB
```

---

# SPEC-INSTALLER-UNIVERSAL

## Installer Script

Follow the exact pattern from AgenticMemory/Vision/Codebase:

```bash
#!/usr/bin/env bash
# install.sh — AgenticIdentity Universal Installer

# Profile detection: desktop|terminal|server
# Release artifact download with fallback to source build
# MCP config merge (NEVER overwrite)
# Completion block with restart guidance
# Optional feedback prompt
```

## Install Profiles

```
DESKTOP PROFILE (default)
├── Install binaries to ~/.local/bin
├── Auto-merge MCP config for Claude/Cursor/VS Code/Windsurf
├── Create default identity (prompt for passphrase)
└── Print restart guidance

TERMINAL PROFILE
├── Install binaries to ~/.local/bin
├── No MCP config changes
└── Print manual setup instructions

SERVER PROFILE
├── Install binaries to /usr/local/bin (if permission) or ~/.local/bin
├── No MCP config changes
├── Auth gate enabled (requires AGENTIC_TOKEN)
└── Print server setup instructions
```

## MCP Config Merge

```bash
# NEVER overwrite existing config
# Merge agentic-identity into mcpServers object
# Preserve all existing servers
```

---

# SPEC-RUNTIME-HARDENING

## Requirements

1. **Strict MCP input validation** — no silent fallbacks
2. **Per-identity file isolation** — identities cannot access each other's keys
3. **Secure memory handling** — zeroize private keys after use
4. **Concurrent operation safety** — file locking for identity operations
5. **Stale lock recovery** — detect and clean stale locks
6. **Server auth gate** — AGENTIC_TOKEN required for server mode

## Passphrase Handling

```
NEVER:
- Log passphrases
- Store passphrases in memory longer than needed
- Pass passphrases via command line arguments (use stdin or file)

ALWAYS:
- Zeroize passphrase memory after use
- Use constant-time comparison for passphrase verification
- Rate limit passphrase attempts
```

---

# SPEC-RELEASE-PUBLISH

## Publish Targets

```
MANDATORY:
├── crates.io
│   ├── agentic-identity
│   ├── agentic-identity-mcp
│   ├── agentic-identity-cli
│   └── agentic-identity-ffi
└── PyPI
    └── agentic-identity

WORKFLOW:
1. Tag release (vX.Y.Z)
2. CI builds all targets
3. Publish to crates.io
4. Build Python wheel
5. Publish to PyPI
6. Create GitHub release with artifacts
7. Update install script version
```

## Duplicate Publish Handling

```bash
# Handle both crates.io response patterns:
# - "already uploaded"
# - "already exists on crates.io index"
# Treat as success, not failure
```

---

# SPEC-DOCS-PUBLIC-SYNC

## Required Documentation

```
docs/
├── quickstart.md          # Get started in 5 minutes
├── concepts.md            # Identity, receipts, trust explained
├── integration-guide.md   # How to integrate with your agent
├── faq.md                 # Common questions
├── benchmarks.md          # Performance data
├── api-reference.md       # Full API docs
└── file-format.md         # .aid format specification
```

## Web Docs Wiring

```
- Must be discoverable from agentralabs.tech/docs
- Include in docs:sync generation
- Add to sister-docs-catalog
```

---

# SPEC-CI-GUARDRAILS

## Required Scripts

```
scripts/
├── check-install-commands.sh    # Verify README install commands work
├── check-canonical-sister.sh    # Verify canonical requirements met
└── test-primary-problems.sh     # Primary problem regression tests
```

## Required Workflows

```
.github/workflows/
├── ci.yml                              # Main CI (test, clippy, fmt)
├── release.yml                         # Release to crates.io + PyPI
├── install-command-guardrails.yml      # Block PRs with broken install
├── canonical-sister-guardrails.yml     # Block PRs missing requirements
└── social-release-broadcast.yml        # Announce releases
```

## CI Checks

```
ON EVERY PR:
├── cargo test --all
├── cargo clippy -- -D warnings
├── cargo fmt --check
├── ./scripts/check-install-commands.sh
├── ./scripts/check-canonical-sister.sh
└── ./scripts/test-primary-problems.sh

ON RELEASE TAG:
├── All above checks
├── Build release artifacts
├── Publish to crates.io
├── Publish to PyPI
├── Create GitHub release
└── Trigger social broadcast
```

---

# SUMMARY

## What You're Building

```
AgenticIdentity
├── Cryptographic identity anchor for AI agents
├── Signed action receipts for accountability
├── Revocable trust web for delegation
├── Portable across tools and systems
└── Foundation for AgenticContract, AgenticComm, Hydra
```

## Key Files to Produce

```
19 specification areas covered
├── 14 core specs (invention through research paper)
└── 5 hardening specs (installer through CI)

Output artifacts:
├── Rust workspace with 4 crates
├── Python package
├── CLI tool (aid)
├── MCP server
├── FFI bindings
├── Documentation
├── Research paper
└── Universal installer
```

## Success Metrics

```
FUNCTIONAL:
├── Can create and manage identities
├── Can sign and verify actions
├── Can grant and revoke trust
├── MCP integration works with Claude Desktop

PERFORMANCE:
├── Key generation < 1ms
├── Sign/verify < 0.5ms
├── Trust chain verification < 5ms (depth 10)

QUALITY:
├── 300+ tests
├── Zero clippy warnings
├── Research paper with real benchmarks
├── Published to crates.io AND PyPI
```

---

**Build AgenticIdentity. The trust anchor for the AI era.**
