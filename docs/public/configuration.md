---
status: stable
---

# Configuration

AgenticIdentity configuration options for all runtime modes.

## Environment Variables

| Variable | Default | Allowed Values | Effect |
|----------|---------|----------------|--------|
| `HOME` | System default | Directory path | Root for `~/.agentic/` data directory |
| `AGENTIC_TOKEN` | None | String | Auth token for server profile |
| `AGENTIC_TOKEN_FILE` | None | File path | Auth token file for server profile |
| `RUST_LOG` | `info` | `trace`, `debug`, `info`, `warn`, `error` | Logging verbosity (via `env_logger`) |

## MCP Server Configuration

The MCP server (`agentic-identity-mcp`) accepts an optional `serve` subcommand:

```json
{
  "mcpServers": {
    "agentic-identity": {
      "command": "~/.local/bin/agentic-identity-mcp-agentra",
      "args": ["serve"]
    }
  }
}
```

## Default Passphrase

The MCP server uses a fixed passphrase `"agentic"` for all identity operations. This is intentional: agents cannot interactively enter passphrases, and the MCP server is designed for use in automated contexts where the identity file is already protected by the host environment.

Identities created via the CLI with a custom passphrase will not be loadable by the MCP server. Use `identity_create` through the MCP server to create MCP-compatible identities.

## Data Directory Layout

All data is stored under `~/.agentic/`:

```
~/.agentic/
  identity/
    default.aid              (default identity file)
    my-agent.aid             (named identity file)
    workspaces.json          (workspace state)
  receipts/
    arec_abc123.json         (action receipt)
    arec_def456.json
  trust/
    atrust_abc123.json       (trust grant)
  spawn/
    aspawn_abc123.json       (spawn record)
```

## Identity File Format

Each `.aid` file is an encrypted binary file containing:

- Ed25519 signing keypair
- X25519 key exchange keypair
- Identity metadata (ID, name, creation timestamp)
- Key rotation history
- Public document with self-signature

The file is encrypted with ChaCha20-Poly1305 using a key derived from the passphrase via Argon2.

## Identity ID Format

Identity IDs use the prefix `aid_` followed by a base58-encoded hash of the public key:

```
aid_7xKj3mNp2Qr5sT8vW1yZ4aB6cD9eF
```

## Receipt ID Format

Receipt IDs use the prefix `arec_` followed by a hex-encoded hash:

```
arec_a1b2c3d4e5f6...
```

## Trust Grant ID Format

Trust grant IDs use the prefix `atrust_`:

```
atrust_a1b2c3d4e5f6...
```

## Spawn Record ID Format

Spawn record IDs use the prefix `aspawn_`:

```
aspawn_a1b2c3d4e5f6...
```

## Duration Strings

Several operations accept duration strings in the format:

| Unit | Suffix | Example |
|------|--------|---------|
| Hours | `h` | `24h` |
| Days | `d` | `7d` |
| Minutes | `m` | `30m` |
| Seconds | `s` | `3600s` |
| Combined | | `1h30m` |

A bare integer is interpreted as hours for backward compatibility.

## Action Types

Built-in action types for signing receipts:

| Type | Description |
|------|-------------|
| `decision` | A decision was made (default) |
| `observation` | An observation was recorded |
| `mutation` | A state change was performed |
| `delegation` | Authority was delegated |
| `revocation` | A privilege was revoked |
| `identity_operation` | An identity management operation |
| Custom string | Any other action type |

## Revocation Reasons

Built-in revocation reasons for trust grants:

| Reason | Description |
|--------|-------------|
| `manual_revocation` | Manually revoked (default) |
| `expired` | Grant expired naturally |
| `compromised` | Grantee's identity was compromised |
| `policy_violation` | Grantee violated policy |
| `grantee_request` | Grantee requested revocation |
| `custom:<text>` | Custom reason with description |
