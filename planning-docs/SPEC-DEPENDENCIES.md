# SPEC-DEPENDENCIES.md

> **Justified dependencies for AgenticIdentity**

---

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
description = "Cryptographic identity anchor for AI agents"
keywords = ["ai", "agents", "identity", "cryptography", "trust"]
categories = ["cryptography", "authentication"]

[workspace.dependencies]
# ============================================================================
# CRYPTOGRAPHY
# ============================================================================

# Ed25519 digital signatures
# Why: De facto standard for fast, secure signing. Audited. Well-maintained.
# Used for: Identity keys, receipt signing, trust grant signing
ed25519-dalek = { version = "2.1", features = ["rand_core", "serde", "zeroize"] }

# X25519 key exchange
# Why: Same authors as ed25519-dalek, compatible curve, enables encryption
# Used for: Encrypted communication keys, key exchange with other identities
x25519-dalek = { version = "2.0", features = ["serde", "zeroize"] }

# HKDF key derivation
# Why: RFC 5869 compliant, from RustCrypto project, well-audited
# Used for: Deriving session/capability/device/spawn keys from root
hkdf = "0.12"

# SHA-256 hashing
# Why: RustCrypto standard implementation, hardware acceleration support
# Used for: Receipt hashes, identity ID derivation, continuity hashes
sha2 = "0.10"

# Argon2id password-based KDF
# Why: Winner of Password Hashing Competition, memory-hard, side-channel resistant
# Used for: Deriving encryption key from passphrase for identity file
argon2 = "0.5"

# ChaCha20-Poly1305 authenticated encryption
# Why: Modern AEAD cipher, no AES hardware requirement, fast in software
# Used for: Encrypting private keys at rest
chacha20poly1305 = "0.10"

# Secure memory clearing
# Why: Prevents private keys from lingering in memory after use
# Used for: All secret key material
zeroize = { version = "1.7", features = ["derive"] }

# Cryptographic random number generation
# Why: Standard secure random, uses OS entropy
# Used for: Key generation, nonce generation
rand = "0.8"
rand_core = "0.6"

# ============================================================================
# SERIALIZATION
# ============================================================================

# Serde serialization framework
# Why: De facto standard for Rust serialization, derive macros
# Used for: All data structure serialization
serde = { version = "1.0", features = ["derive"] }

# JSON serialization
# Why: Human-readable format for documents, MCP protocol
# Used for: Identity documents, MCP messages, configuration
serde_json = "1.0"

# Binary serialization
# Why: Compact binary format for storage and transmission
# Used for: Encrypted identity files, receipt storage
bincode = "1.3"

# Base64 encoding
# Why: Standard encoding for binary data in text formats
# Used for: Public keys in JSON, signatures in documents
base64 = "0.22"

# Hex encoding
# Why: Human-readable encoding for hashes
# Used for: Receipt hashes, continuity hashes
hex = "0.4"

# ============================================================================
# TIME
# ============================================================================

# Date/time handling
# Why: Standard time library, timezone support, serde integration
# Used for: Timestamp formatting, temporal constraint validation
chrono = { version = "0.4", features = ["serde"] }

# ============================================================================
# CLI
# ============================================================================

# Command-line argument parsing
# Why: Best CLI framework for Rust, derive macros, excellent UX
# Used for: aid CLI tool
clap = { version = "4.5", features = ["derive", "env"] }

# ============================================================================
# ASYNC
# ============================================================================

# Async runtime
# Why: Standard async runtime for Rust, full-featured
# Used for: MCP server, async I/O
tokio = { version = "1.36", features = ["full"] }

# ============================================================================
# LOGGING
# ============================================================================

# Logging facade
# Why: Standard logging interface
# Used for: Library logging (not println!)
log = "0.4"

# Environment-based logging
# Why: Simple log configuration via RUST_LOG
# Used for: CLI logging setup
env_logger = "0.11"

# Structured logging
# Why: Better logging for async applications
# Used for: MCP server logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# ============================================================================
# ERROR HANDLING
# ============================================================================

# Error derive macro
# Why: Clean, ergonomic error type definitions
# Used for: All error types
thiserror = "1.0"

# Error context
# Why: Easy error context addition
# Used for: CLI and MCP error handling
anyhow = "1.0"

# ============================================================================
# TESTING
# ============================================================================

# Benchmarking
# Why: Statistical benchmarking framework
# Used for: Performance benchmarks
criterion = "0.5"

# Temporary files
# Why: Clean temp file handling for tests
# Used for: Storage tests
tempfile = "3.10"

# Property-based testing
# Why: Generate test cases automatically
# Used for: Crypto and serialization tests
proptest = "1.4"

# ============================================================================
# FFI
# ============================================================================

# C types
# Why: FFI type compatibility
# Used for: C API
libc = "0.2"

# ============================================================================
# BUILD DEPENDENCIES
# ============================================================================

[workspace.build-dependencies]
# C header generation
# Why: Generate C header from Rust code
# Used for: FFI crate
cbindgen = "0.26"
```

---

## Core Library (agentic-identity)

```toml
[package]
name = "agentic-identity"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description.workspace = true

[dependencies]
# Crypto
ed25519-dalek.workspace = true
x25519-dalek.workspace = true
hkdf.workspace = true
sha2.workspace = true
argon2.workspace = true
chacha20poly1305.workspace = true
zeroize.workspace = true
rand.workspace = true
rand_core.workspace = true

# Serialization
serde.workspace = true
serde_json.workspace = true
bincode.workspace = true
base64.workspace = true
hex.workspace = true

# Time
chrono.workspace = true

# Logging
log.workspace = true

# Error handling
thiserror.workspace = true

[dev-dependencies]
tempfile.workspace = true
criterion.workspace = true
proptest.workspace = true

[[bench]]
name = "crypto_bench"
harness = false

[[bench]]
name = "signing_bench"
harness = false

[[bench]]
name = "verification_bench"
harness = false

[[bench]]
name = "chain_bench"
harness = false
```

---

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

# Async
tokio.workspace = true

# Serialization
serde.workspace = true
serde_json.workspace = true

# Logging
tracing.workspace = true
tracing-subscriber.workspace = true

# Error handling
thiserror.workspace = true
anyhow.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

---

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

# CLI
clap.workspace = true

# Serialization
serde.workspace = true
serde_json.workspace = true

# Time
chrono.workspace = true

# Logging
log.workspace = true
env_logger.workspace = true

# Error handling
thiserror.workspace = true
anyhow.workspace = true

[dev-dependencies]
tempfile.workspace = true
assert_cmd = "2.0"
predicates = "3.1"
```

---

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
libc.workspace = true

[build-dependencies]
cbindgen.workspace = true
```

---

## Dependency Justification Matrix

| Dependency | Purpose | Why This One | Alternatives Rejected |
|------------|---------|--------------|----------------------|
| **ed25519-dalek** | Digital signatures | Audited, fast, standard | ring (heavier), sodiumoxide (deprecated) |
| **x25519-dalek** | Key exchange | Same authors, compatible | ring (heavier) |
| **hkdf** | Key derivation | RFC 5869, RustCrypto | Custom (security risk) |
| **sha2** | Hashing | RustCrypto, hardware accel | ring (heavier) |
| **argon2** | Password KDF | PHC winner, memory-hard | bcrypt (weaker), scrypt (less flexible) |
| **chacha20poly1305** | Symmetric encryption | Modern AEAD, fast | AES-GCM (needs hardware) |
| **zeroize** | Secret clearing | Standard approach | Custom (easy to get wrong) |
| **rand** | Randomness | Standard, OS entropy | Custom (security risk) |
| **serde** | Serialization | De facto standard | Manual (tedious, error-prone) |
| **serde_json** | JSON | Standard with serde | simd-json (overkill) |
| **bincode** | Binary | Compact, fast | postcard (less mature) |
| **chrono** | Time | Full-featured, serde | time (less complete) |
| **clap** | CLI | Best UX, derive macros | structopt (deprecated) |
| **tokio** | Async | Standard runtime | async-std (less ecosystem) |
| **thiserror** | Errors | Clean derive macros | Custom (verbose) |

---

## Dependency Count

| Crate | Direct Dependencies | Total (with transitive) |
|-------|--------------------|-----------------------|
| agentic-identity | 16 | ~45 |
| agentic-identity-mcp | 7 | ~55 |
| agentic-identity-cli | 7 | ~50 |
| agentic-identity-ffi | 2 | ~46 |

---

## Security-Relevant Dependencies

These dependencies handle sensitive operations and must be kept updated:

| Dependency | Security Role | Update Priority |
|------------|---------------|-----------------|
| ed25519-dalek | Signing keys | CRITICAL |
| x25519-dalek | Encryption keys | CRITICAL |
| chacha20poly1305 | Symmetric encryption | CRITICAL |
| argon2 | Password hashing | CRITICAL |
| hkdf | Key derivation | HIGH |
| sha2 | Hashing | HIGH |
| zeroize | Secret clearing | HIGH |
| rand | Randomness | HIGH |

---

## Version Pinning Policy

1. **Security dependencies**: Pin to minor version, update regularly
2. **Serialization**: Pin to minor version for compatibility
3. **CLI/tooling**: Pin to minor version
4. **Dev dependencies**: Can use latest

---

## Audit Status

| Dependency | Audited | Last Audit |
|------------|---------|------------|
| ed25519-dalek | ✅ | 2023 |
| x25519-dalek | ✅ | 2023 |
| chacha20poly1305 | ✅ | 2023 |
| argon2 | ✅ | 2022 |
| hkdf | ✅ | 2022 |
| sha2 | ✅ | 2022 |

---

## Forbidden Dependencies

Do NOT add these dependencies:
- **ring** — Too heavy, C code, build complexity
- **openssl** — External dependency, security burden
- **sodiumoxide** — Deprecated
- **Any web framework** — Not needed for this use case
- **Database crates** — File-based storage only
- **Network crates** — Beyond tokio for async

If you think you need something not listed, implement it yourself or find an alternative approach.
