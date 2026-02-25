<p align="center">
  <strong>AgenticIdentity</strong>
</p>

<p align="center">
  Cryptographic trust anchor for AI agents -- persistent identity, signed action receipts, and revocable trust grants.
</p>

<p align="center">
  <a href="#install"><img src="https://img.shields.io/badge/cargo_install-agentic--identity-F59E0B?style=for-the-badge&logo=rust&logoColor=white" alt="cargo install"></a>
  <a href="#install"><img src="https://img.shields.io/badge/pip_install-agentic--identity-3B82F6?style=for-the-badge&logo=python&logoColor=white" alt="pip install"></a>
  <a href="#mcp-server"><img src="https://img.shields.io/badge/MCP_Server-agentic--identity--mcp-10B981?style=for-the-badge" alt="MCP Server"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="MIT License"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &#183; <a href="#problems-solved">Problems Solved</a> &#183; <a href="#architecture">Architecture</a> &#183; <a href="#mcp-server">MCP Server</a> &#183; <a href="#benchmarks">Benchmarks</a> &#183; <a href="#install">Install</a> &#183; <a href="docs/public/api-reference.md">API</a> &#183; <a href="docs/public/faq.md">FAQ</a>
</p>

---

## AI agents have no identity.

Your agent makes decisions, calls APIs, deploys code, and accesses sensitive data. But there is no cryptographic proof it did any of it. No way to verify which agent acted. No way to audit what happened. No way to scope what an agent is allowed to do.

API keys are not identity -- they are shared secrets with no audit trail. OAuth tokens are not identity -- they expire and carry no action history. Logging is not identity -- logs can be tampered with and carry no signatures.

**AgenticIdentity** gives every AI agent a permanent, cryptographic identity rooted in Ed25519 key pairs. Agents sign every action they take, producing tamper-evident receipts. Trust between agents is granted, scoped, delegated, and revoked through signed trust grants. Everything is verifiable by anyone with the public key.

<a name="problems-solved"></a>

## Problems Solved

- **Problem:** no way to prove which agent took an action.
  **Solved:** Ed25519 identity anchors produce non-repudiable signed receipts for every action.
- **Problem:** agents share API keys with no individual accountability.
  **Solved:** each agent has its own key pair; derived session and capability keys isolate operations.
- **Problem:** no audit trail survives agent restarts or model switches.
  **Solved:** chained receipts create a persistent, cryptographically linked history.
- **Problem:** no scoped permissions for multi-agent systems.
  **Solved:** trust grants with capability URIs, time bounds, use limits, and delegation depth.
- **Problem:** revoking agent access requires rotating shared secrets.
  **Solved:** individual trust grants are revoked independently without affecting other agents.
- **Problem:** private key material stored in plaintext.
  **Solved:** `.aid` files encrypt keys at rest with ChaCha20-Poly1305 + Argon2id.

<a name="quickstart"></a>

## Quickstart

### CLI

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/install.sh | bash

# Create an identity
aid init --name my-agent

# Sign an action
aid sign --type decision --description "Approved deployment to production"

# Verify a receipt
aid verify receipt arec_7xK9mP2...

# Grant trust
aid trust grant --to aid_4Yn3kL... --capability "read:calendar" --expires 7d
```

### Rust

```rust
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;

// Create identity
let agent = IdentityAnchor::new(Some("my-agent".to_string()));

// Sign an action
let receipt = ReceiptBuilder::new(
    agent.id(),
    ActionType::Decision,
    ActionContent::new("Approved deployment to production"),
)
.sign(agent.signing_key())
.unwrap();

// Verify
let result = verify_receipt(&receipt).unwrap();
assert!(result.is_valid);
```

### Python

```python
from agentic_identity import Identity, Receipt

identity = Identity(name="my-agent")
receipt = Receipt.sign(identity, action_type="decision", description="Approved deployment")
assert receipt.verify()
```

<a name="architecture"></a>

## Architecture

AgenticIdentity is built as a Rust workspace with four crates:

```
agentic-identity/
  crates/
    agentic-identity/        Core library (identity, receipts, trust, crypto, storage)
    agentic-identity-cli/    CLI tool (aid)
    agentic-identity-mcp/    MCP server for AI agent integration
    agentic-identity-ffi/    C FFI bindings for cross-language use
  python/                    Python package (wraps FFI)
  benches/                   Criterion benchmarks
  tests/                     Integration tests
```

**289 tests. Zero unsafe in the core library.**

### Core Primitives

| Primitive | Purpose | Cryptography |
|:---|:---|:---|
| **Identity Anchor** | Permanent agent identity | Ed25519 key pair |
| **Action Receipt** | Signed proof of action | Ed25519 signature over SHA-256 hash |
| **Trust Grant** | Scoped permission delegation | Ed25519 signed capability grant |
| **Key Derivation** | Session/capability/device keys | HKDF-SHA256 |
| **File Storage** | Encrypted key persistence | ChaCha20-Poly1305 + Argon2id |

### Identity Lifecycle

```
IdentityAnchor::new("my-agent")
    |
    ├── .id()                  -> aid_7xK9mP2...
    ├── .public_key_base64()   -> Ed25519 public key
    ├── .derive_session_key()  -> scoped signing key
    ├── .derive_capability_key() -> scoped signing key
    ├── .rotate(Scheduled)     -> new anchor with rotation history
    └── .to_document()         -> shareable public document
```

### Receipt Chain

```
[Observation] ──chain_to──> [Decision] ──chain_to──> [Mutation]
  "Error spike"              "Rollback"               "Deployed v2.3"
   signed                     signed                    signed
```

### Trust Delegation

```
Alice ──trust──> Bob ──delegate──> Carol
  "read:*"        "read:calendar"
  depth: 2        depth: 1
```

<a name="mcp-server"></a>

## MCP Server

The MCP server exposes all identity operations as tools for AI agents. Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "agentic-identity": {
      "command": "agentic-identity-mcp",
      "args": ["--identity-dir", "~/.agentic-identity"]
    }
  }
}
```

Available tools: `identity_create`, `identity_info`, `action_sign`, `action_verify`, `chain_verify`, `trust_grant`, `trust_verify`, `trust_revoke`, `key_derive_session`, `key_derive_capability`.

<a name="benchmarks"></a>

## Benchmarks

Rust core. Ed25519 + HKDF-SHA256. Real numbers from Criterion statistical benchmarks:

| Operation | Time |
|:---|---:|
| Ed25519 key generation | **8.80 us** |
| Ed25519 sign | **9.17 us** |
| Ed25519 verify | **19.34 us** |
| HKDF derivation | **972 ns** |
| Identity creation | **8.78 us** |
| Receipt sign | **11.55 us** |
| Receipt verify | **21.77 us** |
| Trust grant sign | **12.41 us** |
| Trust grant verify | **21.84 us** |
| Trust chain verify (depth 2) | **43.51 us** |
| Receipt chain (10 receipts) | **123.77 us** |

Single-threaded. All operations are independent and scale linearly with cores.

<a name="install"></a>

## Install

### One-Line Install (CLI + MCP)

```bash
curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/install.sh | bash
```

### From Source

```bash
git clone https://github.com/agentralabs/agentic-identity.git
cd agentic-identity
cargo build --release
```

### Rust Library

```toml
[dependencies]
agentic-identity = "0.1"
```

### Python

```bash
pip install agentic-identity
```

## Cryptography

| Purpose | Algorithm | Standard |
|:---|:---|:---|
| Identity keys & signing | Ed25519 | RFC 8032 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Private key encryption | ChaCha20-Poly1305 | RFC 8439 |
| Passphrase stretching | Argon2id | RFC 9106 |
| Content hashing | SHA-256 | FIPS 180-4 |
| ID encoding | Base58, Base64 | -- |

No custom cryptography. All primitives are from audited, widely-used Rust crates (`ed25519-dalek`, `hkdf`, `chacha20poly1305`, `argon2`).

## Documentation

| Document | Description |
|:---|:---|
| [Quickstart](docs/public/quickstart.md) | Get started in 5 minutes |
| [Core Concepts](docs/public/concepts.md) | Identity anchors, receipts, trust web |
| [Integration Guide](docs/public/integration-guide.md) | MCP, Rust, FFI, Python integration |
| [API Reference](docs/public/api-reference.md) | Complete API documentation |
| [Benchmarks](docs/public/benchmarks.md) | Performance data and analysis |
| [FAQ](docs/public/faq.md) | Common questions answered |
| [File Format](docs/public/file-format.md) | `.aid` file format specification |

## Examples

```bash
cargo run --example basic_identity -p agentic-identity      # Create identity, derive keys, rotate
cargo run --example sign_action -p agentic-identity         # Sign actions, chain receipts, verify
cargo run --example trust_delegation -p agentic-identity    # Grant trust, delegate, verify chains
```

## Privacy and Security

- All identity data stays local in `.aid` files -- no telemetry, no cloud sync by default.
- Private keys are encrypted at rest with ChaCha20-Poly1305 + Argon2id passphrase derivation.
- Key material is zeroized in memory on drop -- intermediate keys are never retained.
- No custom cryptography: Ed25519, HKDF-SHA256, ChaCha20-Poly1305, Argon2id (all RFC-standard, audited Rust crates).
- Server mode requires an explicit `AGENTIC_TOKEN` environment variable for bearer auth.
- Error messages never include private key material.

## Project Status

**v0.1.0** -- initial release. Core library, CLI, MCP server, FFI bindings, and Python package.

## License

MIT -- see [LICENSE](LICENSE).

## Part of the AgenticOS Ecosystem

AgenticIdentity is the cryptographic trust anchor for the [Agentra Labs](https://github.com/agentralabs) AgenticOS ecosystem, alongside [AgenticMemory](https://github.com/agentralabs/agentic-memory), [AgenticCodebase](https://github.com/agentralabs/agentic-codebase), and [AgenticVision](https://github.com/agentralabs/agentic-vision).
