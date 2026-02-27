---
status: stable
---

# CLI Reference

The `aid` CLI provides command-line access to AgenticIdentity operations.

## Global Options

| Option | Description |
|--------|-------------|
| `--identity <name>` | Use specific identity (default: `default`) |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Print help information |
| `-V, --version` | Print version |

## Commands

### `aid init`

Create a new identity.

```bash
# Create an identity with a name
aid init --name "my-agent"

# Create default identity (interactive passphrase prompt)
aid init
```

| Option | Description |
|--------|-------------|
| `--name <name>` | Human-readable name for the identity |

### `aid info`

Display identity information (alias: `aid show`).

```bash
# Show default identity
aid info

# Show a specific identity
aid info --identity my-agent
```

| Option | Description |
|--------|-------------|
| `--identity <name>` | Identity name to show (overrides global `--identity`) |

### `aid list`

List all identities.

```bash
aid list
# Output:
#   default    aid_abc123...  2026-02-20 10:00:00 UTC
#   my-agent   aid_def456...  2026-02-21 14:30:00 UTC
```

### `aid sign`

Sign an action and create a receipt.

```bash
# Sign a decision
aid sign --type decision --description "Approved deployment to production"

# Sign with JSON data
aid sign --type mutation --description "Updated config" --data '{"key":"retries","value":5}'

# Chain to a previous receipt
aid sign --type observation --description "Noticed high memory" --chain-to arec_abc123
```

| Option | Description |
|--------|-------------|
| `--type <type>` | Action type: `decision`, `observation`, `mutation`, `delegation`, `revocation`, `identity_operation`, or custom |
| `--description <text>` | Human-readable description of the action |
| `--data <json>` | Optional JSON data payload |
| `--chain-to <receipt_id>` | Chain this receipt to a previous receipt ID |

### `aid verify`

Verify a receipt or trust grant.

```bash
# Verify a receipt
aid verify receipt arec_abc123

# Verify a trust grant
aid verify trust atrust_def456

# Verify a trust grant for a specific capability
aid verify trust atrust_def456 --capability read:calendar
```

### `aid trust`

Manage trust relationships.

```bash
# Grant trust to another identity
aid trust grant --to aid_grantee123 --capability read:calendar --expires 7d

# Grant with delegation allowed
aid trust grant --to aid_grantee123 --capability write:notes --allow-delegation --max-depth 2

# Revoke a trust grant
aid trust revoke atrust_def456 --reason compromised

# List granted trust
aid trust list --granted

# List received trust
aid trust list --received
```

### `aid rotate`

Rotate identity keys.

```bash
# Manual key rotation
aid rotate

# Rotate with reason
aid rotate --reason compromised
```

| Option | Description |
|--------|-------------|
| `--reason <reason>` | Reason: `manual`, `scheduled`, `compromised`, `device_lost`, `policy_required` |

### `aid export`

Export identity public document as JSON.

```bash
# Export to stdout
aid export

# Export to file
aid export --output identity.json

# Export a specific identity
aid export --identity my-agent
```

| Option | Description |
|--------|-------------|
| `--identity <name>` | Identity name to export |
| `-o, --output <path>` | Output file path (default: stdout) |

### `aid query`

Query receipts and trust records by text.

```bash
aid query "deployment approval" --limit 10
```

| Option | Description |
|--------|-------------|
| `--limit <n>` | Maximum results (default: 20) |

### `aid ground`

Verify a claim against identity evidence.

```bash
aid ground "agent has deploy permission" --threshold 0.3
```

| Option | Description |
|--------|-------------|
| `--threshold <f>` | Minimum score threshold (default: 0.3) |

### `aid evidence`

Return matching evidence for a query.

```bash
aid evidence "calendar access" --limit 20
```

### `aid suggest`

Suggest similar receipts or grants for a phrase.

```bash
aid suggest "deploy" --limit 10
```

### `aid receipt`

Manage receipts.

```bash
# List receipts
aid receipt list

# Filter by actor
aid receipt list --actor aid_abc123

# Filter by action type
aid receipt list --type decision --limit 10
```

### `aid continuity`

Manage temporal continuity (experience chain, anchors, heartbeats).

```bash
# Record an experience event
aid continuity record --type cognition --content-hash abc123 --intensity 0.8

# Create a continuity anchor (checkpoint)
aid continuity anchor --type manual

# Create a heartbeat
aid continuity heartbeat --status active

# Get continuity status
aid continuity status

# Detect gaps in the experience chain
aid continuity gaps --grace-period 300
```

### `aid spawn`

Manage identity inheritance (spawn child identities).

```bash
# Spawn a child identity
aid spawn create --type worker --purpose "Handle deployments" --authority "deploy:staging,deploy:prod" --lifetime 7d

# List spawned children
aid spawn list
aid spawn list --active

# Terminate a child
aid spawn terminate aspawn_abc123 --reason "task complete" --cascade

# Show lineage
aid spawn lineage

# Show effective authority
aid spawn authority
```

### `aid competence`

Manage competence proofs (demonstrated ability).

```bash
# Record a competence attempt
aid competence record --domain deploy --outcome success --receipt arec_abc123

# Record a failure
aid competence record --domain deploy --outcome failure --reason "timeout" --receipt arec_def456

# Show competence record
aid competence show --domain deploy

# Generate a competence proof
aid competence prove --domain deploy --min-rate 0.8 --min-attempts 10

# List all competence domains
aid competence list
```

### `aid cannot`

Manage negative capability proofs (structural impossibility).

```bash
# Prove an identity cannot do something
aid cannot prove "delete:production-data"

# Verify a negative proof
aid cannot verify aneg_abc123

# Declare a voluntary restriction
aid cannot declare --capabilities "write:financial,delete:user-data" --reason "policy compliance" --permanent

# List all negative declarations
aid cannot list

# Quick check if a capability is impossible
aid cannot check "delete:production-data"
```

### `aid workspace`

Workspace operations across multiple identity paths.

```bash
# Create a workspace
aid workspace create "multi-agent"

# Add identity directories
aid workspace add multi-agent /path/to/agent-a --role primary --label "Agent A"
aid workspace add multi-agent /path/to/agent-b --role secondary --label "Agent B"

# List workspace contexts
aid workspace list multi-agent

# Query across contexts
aid workspace query multi-agent "deploy permission" --limit 10

# Compare an item across contexts
aid workspace compare multi-agent "deploy" --limit 10

# Cross-reference
aid workspace xref multi-agent "read:calendar"
```
