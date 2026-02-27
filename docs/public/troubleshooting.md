---
status: stable
---

# Troubleshooting

Common issues and solutions for AgenticIdentity.

## Installation Issues

### Binary not found after install

Ensure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

### Install script fails with "jq not found"

The installer needs `jq` or `python3` for MCP config merging:

```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt install jq

# Or use python3 (usually pre-installed)
python3 --version
```

### Cargo build fails

Ensure you have the latest stable Rust toolchain:

```bash
rustup update stable
```

AgenticIdentity requires Rust 2021 edition and several cryptographic crates. If builds fail on `ed25519-dalek` or `chacha20poly1305`, ensure your toolchain is up to date.

## MCP Server Issues

### Server not appearing in MCP client

1. Verify the binary exists: `ls ~/.local/bin/agentic-identity-mcp-agentra`
2. Check config was merged: look for `agentic-identity` in your MCP client config
3. Restart your MCP client completely (not just reload)
4. Run manually to check for errors: `agentic-identity-mcp serve`

### "identity not found" error on first use

The MCP server does not auto-create identities. Create one first:

```json
{
  "method": "tools/call",
  "params": {
    "name": "identity_create",
    "arguments": {"name": "default"}
  }
}
```

Or via CLI:

```bash
aid init --name default
```

Note: Identities created via the CLI use an interactive passphrase. The MCP server uses the fixed passphrase `"agentic"`. Identities created with a different passphrase will not be loadable by the MCP server.

### "failed to load identity" with passphrase mismatch

The MCP server uses the fixed passphrase `"agentic"`. If the identity was created via the CLI with a custom passphrase, you have two options:

1. Create a new MCP-compatible identity using the `identity_create` tool
2. Create the identity via CLI using `aid init` and entering `agentic` as the passphrase

### Server crashes on startup

Check for missing directories:

```bash
mkdir -p ~/.agentic/identity ~/.agentic/receipts ~/.agentic/trust ~/.agentic/spawn
```

## Identity File Issues

### "identity already exists" error

An identity with that name already exists in `~/.agentic/identity/`. Either:

1. Use `identity_show` to inspect the existing identity
2. Delete the file manually if you want to start fresh:

```bash
rm ~/.agentic/identity/default.aid
```

### Corrupted identity file

If an identity file is corrupted and cannot be loaded, remove it and create a new one:

```bash
mv ~/.agentic/identity/corrupted.aid ~/.agentic/identity/corrupted.aid.bak
aid init --name corrupted
```

Note: A new identity will have a different ID and keypair. Trust grants and receipts linked to the old identity will reference the old ID.

### Key rotation fails

Key rotation requires loading the identity with the current passphrase. Ensure you know the passphrase. If using the MCP server, the passphrase is always `"agentic"`.

```bash
aid --identity my-agent rotate --reason scheduled
```

## Trust Management Issues

### Trust grant verification fails

Check these common causes:

1. **Expired grant**: Verify the grant has not expired:
   ```bash
   aid verify trust atrust_abc123
   ```

2. **Revoked grant**: Check if the grant was revoked:
   ```bash
   aid trust list --granted
   ```

3. **Wrong capability**: The capability URI must match exactly. `read:calendar` does not match `read:*`:
   ```bash
   aid verify trust atrust_abc123 --capability read:calendar
   ```

### Cannot find grantee public key

Trust grants require the grantee's public key. Obtain it from the grantee's public document:

```bash
# The grantee exports their public document
aid --identity grantee export

# The grantor uses the public key from the exported document
```

## Receipt Issues

### Receipt verification fails

1. **Tampered receipt**: The receipt content was modified after signing
2. **Wrong public key**: The public key in the receipt does not match the signer
3. **Corrupt JSON**: The receipt JSON file may be corrupted

Verify manually:

```bash
aid verify receipt arec_abc123
```

### Receipt store grows too large

Receipt files are individual JSON files in `~/.agentic/receipts/`. To clean up old receipts:

```bash
# Count receipts
ls ~/.agentic/receipts/ | wc -l

# Remove receipts older than 90 days (careful!)
find ~/.agentic/receipts/ -name "arec_*.json" -mtime +90 -delete
```

## Continuity Issues

### Gaps detected in experience chain

Gaps occur when the agent was not running or did not record experience events. This is expected during restarts.

```bash
# Check gaps with a 5-minute grace period
aid continuity gaps --grace-period 300
```

To reduce gaps, ensure the agent records heartbeats regularly.

### Continuity chain not found

The continuity system stores data within the identity directory. Ensure the identity exists:

```bash
aid info
```

## Spawn Issues

### Child identity has no authority

Child identities receive authority bounded by the parent's authority. If the parent lacks a capability, the child cannot have it either.

```bash
# Check parent's effective authority
aid spawn authority

# Check child's effective authority
aid --identity child spawn authority
```

### Cascade termination not working

Cascade termination follows the spawn lineage. It only terminates direct descendants, not identities spawned by other parents:

```bash
aid spawn terminate aspawn_abc123 --cascade --reason "cleanup"
```

## Competence Issues

### Competence proof generation fails

Proofs require a minimum number of attempts and success rate:

```bash
# Check current competence record
aid competence show --domain deploy

# Ensure enough attempts exist
aid competence list
```

## Getting Help

- GitHub Issues: https://github.com/agentralabs/agentic-identity/issues
- Documentation: https://agentralabs.tech/docs/identity
