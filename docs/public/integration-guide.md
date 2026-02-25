---
title: Integration Guide
description: Integrate AgenticIdentity with AI agent frameworks, MCP servers, and applications
order: 3
status: stable
---

# Integration Guide

AgenticIdentity can be integrated into your stack at four levels: MCP server (zero-code), Rust library (native), C FFI (any language with C bindings), or Python package. Choose the level that fits your architecture.

## MCP Server Integration

The MCP server (`agentic-identity-mcp`) exposes all identity operations as MCP tools. This is the simplest integration path for AI agents running inside MCP-compatible hosts like Claude Desktop, Cursor, or Windsurf.

### Claude Desktop Configuration

Add to your Claude Desktop MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

### Cursor / Windsurf Configuration

Add to your project's `.cursor/mcp.json` or equivalent:

```json
{
  "mcpServers": {
    "agentic-identity": {
      "command": "agentic-identity-mcp",
      "args": ["--identity-dir", "./.agentic-identity"]
    }
  }
}
```

### Available MCP Tools

Once configured, the agent has access to these tools:

| Tool | Description |
|:---|:---|
| `identity_create` | Create a new identity anchor |
| `identity_info` | Get identity ID and public key |
| `identity_document` | Export the public identity document |
| `identity_rotate` | Rotate the root key pair |
| `action_sign` | Sign an action receipt |
| `action_verify` | Verify an action receipt |
| `chain_verify` | Verify a chain of receipts |
| `trust_grant` | Grant trust to another identity |
| `trust_verify` | Verify a trust grant |
| `trust_chain_verify` | Verify a delegation chain |
| `trust_revoke` | Revoke a trust grant |
| `key_derive_session` | Derive a scoped session key |
| `key_derive_capability` | Derive a scoped capability key |

### Agent Prompt Example

Once the MCP server is running, prompt your agent:

> Create an identity for this project, then sign a receipt recording your decision to refactor the database module.

The agent will call `identity_create` followed by `action_sign` automatically.

---

## Rust Library Integration

Add the core library to your `Cargo.toml`:

```toml
[dependencies]
agentic-identity = "0.1"
```

### Identity Lifecycle

```rust
use agentic_identity::identity::{IdentityAnchor, RotationReason};

// Create
let anchor = IdentityAnchor::new(Some("my-agent".to_string()));
let id = anchor.id();
let pub_key = anchor.public_key_base64();

// Derive scoped keys
let session_key = anchor.derive_session_key("session-001")?;
let cap_key = anchor.derive_capability_key("read:calendar")?;

// Rotate
let rotated = anchor.rotate(RotationReason::Scheduled)?;

// Export public document
let doc = anchor.to_document();
doc.verify_signature()?;
```

### Action Receipts

```rust
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::receipt::action::{ActionContent, ActionType};
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::receipt::chain::verify_chain;

let anchor = IdentityAnchor::new(None);

// Sign an action
let receipt = ReceiptBuilder::new(
    anchor.id(),
    ActionType::Decision,
    ActionContent::new("Approved deployment"),
)
.sign(anchor.signing_key())?;

// Verify
let result = verify_receipt(&receipt)?;
assert!(result.is_valid);

// Chain receipts
let r2 = ReceiptBuilder::new(
    anchor.id(),
    ActionType::Mutation,
    ActionContent::new("Executed deployment"),
)
.chain_to(receipt.id.clone())
.sign(anchor.signing_key())?;

verify_chain(&[receipt, r2])?;
```

### Trust Grants

```rust
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::trust::capability::Capability;
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::verify::verify_trust_grant;
use agentic_identity::trust::chain::verify_trust_chain;

let grantor = IdentityAnchor::new(None);
let grantee = IdentityAnchor::new(None);

// Grant trust
let grant = TrustGrantBuilder::new(
    grantor.id(),
    grantee.id(),
    grantee.public_key_base64(),
)
.capability(Capability::new("read:calendar"))
.allow_delegation(2)
.sign(grantor.signing_key())?;

// Verify
let v = verify_trust_grant(&grant, "read:calendar", 0, &[])?;
assert!(v.is_valid);
```

### File Storage

```rust
use agentic_identity::identity::IdentityAnchor;
use agentic_identity::storage::{save_identity, load_identity, read_public_document};
use std::path::Path;

let anchor = IdentityAnchor::new(Some("stored-agent".to_string()));
let path = Path::new("my-agent.aid");

// Save (encrypts private key with passphrase)
save_identity(&anchor, path, "my-passphrase")?;

// Load (decrypts with passphrase)
let loaded = load_identity(path, "my-passphrase")?;

// Inspect without decryption
let doc = read_public_document(path)?;
```

---

## C FFI Integration

The `agentic-identity-ffi` crate provides a C-compatible API for use from any language with C FFI support (Swift, Go, Ruby, Java/JNI, C#, etc.).

### Building the Shared Library

```bash
cargo build --release -p agentic-identity-ffi
# Output: target/release/libagentic_identity_ffi.{dylib,so,dll}
```

### C Header (Partial)

```c
// Error codes
#define AID_OK               0
#define AID_ERR_NULL_PTR    -1
#define AID_ERR_INVALID_UTF8 -2
#define AID_ERR_CRYPTO      -3
#define AID_ERR_IO          -4
#define AID_ERR_SERIALIZATION -5

// Identity management
int aid_identity_create(const char *name, void **out_anchor);
int aid_identity_id(const void *anchor, char **out_id);
int aid_identity_public_key(const void *anchor, char **out_key);
void aid_identity_free(void *anchor);
void aid_free_string(char *s);

// Action signing
int aid_receipt_sign(const void *anchor, const char *action_type,
                     const char *description, char **out_json);
int aid_receipt_verify(const char *receipt_json, int *out_valid);

// Trust grants
int aid_trust_grant(const void *grantor, const char *grantee_id,
                    const char *grantee_key, const char *capability,
                    char **out_json);
int aid_trust_verify(const char *grant_json, const char *capability,
                     int *out_valid);

// File I/O
int aid_save(const void *anchor, const char *path, const char *passphrase);
int aid_load(const char *path, const char *passphrase, void **out_anchor);

// Version
const char *aid_version(void);
```

### Memory Contract

- All `char *` output strings are heap-allocated and **must** be freed with `aid_free_string()`.
- Opaque `void *` anchors are heap-allocated and **must** be freed with `aid_identity_free()`.
- The string returned by `aid_version()` is a static string and must **not** be freed.

---

## Python Integration

The Python package wraps the C FFI layer with a Pythonic API.

### Install

```bash
pip install agentic-identity
```

### Usage

```python
from agentic_identity import Identity, Receipt, TrustGrant

# Create identity
identity = Identity(name="my-agent")
print(identity.id)         # aid_7xK9mP2...
print(identity.public_key) # base64 encoded

# Sign an action
receipt = Receipt.sign(
    identity,
    action_type="decision",
    description="Approved deployment to production",
)
assert receipt.verify()

# Grant trust
grant = TrustGrant.create(
    grantor=alice,
    grantee=bob,
    capability="read:calendar",
)
assert grant.verify("read:calendar")

# Save / load
identity.save("my-agent.aid", passphrase="secret")
loaded = Identity.load("my-agent.aid", passphrase="secret")
```

---

## Integration Patterns

### Agent Framework Integration

For agents built on frameworks like LangChain, AutoGen, or CrewAI, the recommended pattern is:

1. **One identity per agent** -- create an `IdentityAnchor` when the agent is initialized.
2. **Sign decisions** -- wrap the agent's decision-making calls with `ReceiptBuilder` to produce audit trails.
3. **Trust for tool access** -- use `TrustGrant` to scope what tools/APIs each agent can access.
4. **Session keys for isolation** -- derive a session key per conversation to avoid exposing the root key.

### Multi-Agent Systems

For multi-agent orchestration:

1. **Orchestrator identity** -- the orchestrator agent holds the root identity.
2. **Delegate via trust grants** -- grant each worker agent scoped capabilities.
3. **Chain receipts across agents** -- link receipts from different agents using `chain_to()`.
4. **Revoke on completion** -- revoke worker grants when the task is finished.

### CI/CD Integration

For automated pipelines:

1. **Pipeline identity** -- each pipeline has its own `.aid` file.
2. **Sign deployment decisions** -- sign receipts for each deployment step.
3. **Verify before promote** -- verify the receipt chain before promoting to the next environment.
4. **Rotate on schedule** -- use `RotationReason::Scheduled` for periodic key rotation.
