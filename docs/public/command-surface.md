---
status: stable
---

# Command Surface

## CLI Commands (`aid`)

| Command | Description |
|---------|-------------|
| `aid create` | Create a new identity anchor |
| `aid sign` | Sign an action and produce a receipt |
| `aid verify` | Verify a receipt signature |
| `aid trust grant` | Grant trust delegation |
| `aid trust revoke` | Revoke a trust delegation |
| `aid trust list` | List active delegations |
| `aid export` | Export identity document |
| `aid continuity start` | Start a continuity session |
| `aid continuity status` | Show continuity chain status |
| `aid spawn` | Create a child identity |

## MCP Tools (`agentic-identity-mcp`)

| Tool | Description |
|------|-------------|
| `create_identity` | Create a new identity anchor |
| `sign_action` | Sign an action with an identity |
| `verify_receipt` | Verify receipt authenticity |
| `trust_grant` | Grant trust to another identity |
| `trust_revoke` | Revoke a trust delegation |
| `trust_list` | List active trust delegations |
| `export_identity` | Export identity document |
| `list_identities` | List all identities |
| `continuity_start` | Start continuity session |
| `continuity_status` | Get continuity chain status |
| `spawn_identity` | Spawn a child identity |
| `action_context` | Record why an identity action is being performed |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AID_IDENTITY_DIR` | `~/.agentic-identity/identities` | Identity storage directory |
| `AID_RECEIPT_DIR` | `~/.agentic-identity/receipts` | Receipt storage directory |
| `AID_TRUST_DIR` | `~/.agentic-identity/trust` | Trust delegation storage |
| `AID_LOG_LEVEL` | `info` | Logging verbosity |
| `AGENTIC_TOKEN` | — | Server-mode auth token |
