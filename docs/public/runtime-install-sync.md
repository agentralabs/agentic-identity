---
status: stable
---

# Runtime and Install Sync

## Install Profiles

AgenticIdentity supports three install profiles:

- **desktop** — CLI + MCP server, configures Claude Desktop
- **terminal** — CLI + MCP server, configures Claude Code
- **server** — CLI + MCP server with token-based authentication

## MCP Configuration

The installer performs merge-only updates to MCP client configuration files. Existing entries are preserved; only the `agentic-identity-mcp` server entry is added or updated.

## Post-Install Verification

```bash
aid --version
agentic-identity-mcp --help
```

## Server Mode

Server mode requires an authentication token:

```bash
export AGENTIC_TOKEN="your-token-here"
agentic-identity-mcp --mode server
```

## Data Directory Structure

All identity data is stored under `~/.agentic/`:

```
~/.agentic/
  identity/    # .aid files (encrypted private keys + public documents)
  receipts/    # Action receipt JSON files
  trust/       # Trust grant JSON files
  spawn/       # Spawn record JSON files
```

## Sync Behavior

The MCP server reads and writes to the `~/.agentic/` directory on every operation. There is no in-memory cache that could become stale — each tool call loads the current state from disk, performs the operation, and writes the result back. This design ensures that:

- Multiple MCP clients pointing at the same directory see consistent state
- Crash recovery is automatic — partial writes are detected by signature verification failures
- No background sync process is needed

## Multi-Device Operation

AgenticIdentity supports multi-device use through its key derivation hierarchy. From a single root identity, device-scoped signing keys are derived using HKDF-SHA256:

```bash
# Each device gets a deterministic but unique signing key
# derived from: HKDF(root_key, context="device:<device_id>")
```

To operate the same identity across multiple devices:

1. Copy the `.aid` file to each device (it contains the encrypted root key)
2. Each device derives its own device key via `derive_device_key`
3. Receipts signed with device keys are traceable back to the root identity

The root private key is encrypted with ChaCha20-Poly1305 and protected by a passphrase-derived key (Argon2id), so the `.aid` file is safe to transfer across devices.

## Conflict Resolution

Because the data directory uses append-only JSON files for receipts, trust grants, and spawn records, there are no write conflicts in normal operation. Each receipt, grant, and spawn record has a unique ID and is written to its own file.

Identity file conflicts (e.g., two devices rotating the root key simultaneously) are resolved by the key rotation chain: each rotation includes a signed authorization from the old key, so the valid chain is deterministic. If two conflicting rotations exist, only the one with a valid signature chain from the original genesis key is accepted.

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `HOME` | Locates `~/.agentic/` data directory | Yes |
| `AGENTIC_TOKEN` | Authentication token for server mode | Server mode only |
| `AGENTIC_DIR` | Override default data directory location | No (defaults to `~/.agentic/`) |
| `RUST_LOG` | Control log verbosity (e.g., `debug`, `info`) | No |
