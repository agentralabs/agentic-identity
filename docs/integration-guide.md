
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
