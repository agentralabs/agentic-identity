---
status: stable
---

# Architecture

AgenticIdentity is a 4-crate Rust workspace with additional language bindings.

## Workspace Structure

```
agentic-identity/
  Cargo.toml                    (workspace root)
  crates/
    agentic-identity/           (core library)
    agentic-identity-mcp/       (MCP server)
    agentic-identity-cli/       (CLI binary: aid)
    agentic-identity-ffi/       (C FFI shared library)
  npm/wasm/                     (npm WASM package)
```

## Crate Responsibilities

### agentic-identity

The core library. All cryptographic identity logic lives here.

- Identity management: create, load, save, rotate keys (Ed25519)
- Action receipts: sign actions, verify signatures, chain receipts
- Trust management: grant capabilities, revoke trust, verify grants
- Continuity: experience chain, anchors, heartbeats, gap detection
- Spawn: child identity creation with bounded authority and lineage
- Competence: track domain proficiency, generate and verify proofs
- Negative proofs: prove structural impossibility of capabilities
- Storage: directory-based `.aid` format with encrypted identity files
- Cryptography: Ed25519 signing, X25519 key exchange, Argon2 key derivation, ChaCha20-Poly1305 encryption
- No I/O dependencies beyond file system access
- No MCP, CLI, or FFI concerns

### agentic-identity-mcp

The MCP server binary (`agentic-identity-mcp`).

- JSON-RPC 2.0 over stdio
- 35+ MCP tools spanning identity, trust, receipts, continuity, spawn, competence, negative proofs, grounding, and workspaces
- Additional invention modules: trust dynamics, accountability, federation, resilience
- MCP resources via `aid://` URI scheme
- Auto-session lifecycle management with operation logging
- Content-Length framing with JSON-RPC request routing
- Input validation: no silent fallback for invalid parameters

### agentic-identity-cli

The command-line interface binary (`aid`).

- Human-friendly terminal output
- All core operations exposed as subcommands
- Interactive passphrase entry for identity operations
- Subcommand groups: init, info, sign, verify, trust, rotate, export, query, ground, evidence, suggest, workspace, receipt, continuity, spawn, competence, cannot

### agentic-identity-ffi

C-compatible shared library for cross-language integration.

- Opaque handle pattern for identity anchors
- JSON-based data exchange for complex types (receipts, trust grants)
- Error propagation via return codes (`AID_OK`, `AID_ERR_*`)
- Memory contract: caller frees strings with `aid_free_string()`
- Thread-safe per-handle access

## Data Flow

```
Agent (Claude/GPT/etc.)
  |
  | MCP protocol (JSON-RPC 2.0 over stdio)
  v
agentic-identity-mcp
  |
  | Rust function calls
  v
agentic-identity (core)
  |
  | Encrypted file I/O
  v
~/.agentic/identity/*.aid   (identity files)
~/.agentic/receipts/        (action receipts)
~/.agentic/trust/           (trust grants)
~/.agentic/spawn/           (spawn records)
```

## Storage Format

AgenticIdentity uses a directory-based storage layout:

| Directory | Contents |
|-----------|----------|
| `~/.agentic/identity/` | Encrypted `.aid` identity files (one per identity) |
| `~/.agentic/receipts/` | JSON action receipt files (one per receipt) |
| `~/.agentic/trust/` | JSON trust grant files (granted and received) |
| `~/.agentic/spawn/` | JSON spawn records for child identities |

Each `.aid` file contains an encrypted `IdentityAnchor` with:
- Ed25519 signing keypair
- X25519 key exchange keypair
- Identity metadata (ID, name, creation timestamp)
- Key rotation history
- Public document with self-signature

## Cryptographic Primitives

| Primitive | Library | Purpose |
|-----------|---------|---------|
| Ed25519 | `ed25519-dalek` | Action signing, receipt verification |
| X25519 | `x25519-dalek` | Key exchange for encrypted channels |
| Argon2 | `argon2` | Passphrase-based key derivation |
| ChaCha20-Poly1305 | `chacha20poly1305` | Identity file encryption |
| SHA-256 | `sha2` | Content hashing, receipt chaining |
| HKDF | `hkdf` | Key derivation for sub-keys |

## Cross-Sister Integration

AgenticIdentity integrates with other Agentra sisters:

- **AgenticMemory**: Decision receipts link to memory nodes. Trust grants provide access control for shared memories.
- **AgenticVision**: Visual observations are signed with identity receipts for audit trails.
- **AgenticCodebase**: Code analysis operations are signed. Competence proofs track code review accuracy.
- **AgenticTime**: Temporal operations are signed with identity receipts. Trust grants have time-bounded expiry.

## Runtime Isolation

Each identity gets its own `.aid` file within `~/.agentic/identity/`. The MCP server uses a fixed passphrase (`"agentic"`) for automated contexts where agents cannot interactively enter passphrases. The identity file itself is protected by the host environment's file permissions.
