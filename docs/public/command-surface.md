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

All tools exposed by the `agentic-identity-mcp` MCP server:

### Identity Core

| Tool | Description |
|------|-------------|
| `identity_create` | Create a new identity anchor |
| `identity_show` | Show identity information (public document) |
| `identity_health` | Check system health: identity files, receipt store, trust store |

### Actions & Receipts

| Tool | Description |
|------|-------------|
| `action_sign` | Sign an action and create a verifiable receipt |
| `action_context` | Log the intent and context behind identity actions |
| `receipt_verify` | Verify the cryptographic signature on a receipt |
| `receipt_list` | List action receipts with optional filters |

### Trust

| Tool | Description |
|------|-------------|
| `trust_grant` | Grant trust (capabilities) to another identity |
| `trust_revoke` | Revoke a trust grant |
| `trust_verify` | Verify whether a trust grant is currently valid |
| `trust_list` | List trust grants (granted by or received by identity) |

### Continuity

| Tool | Description |
|------|-------------|
| `continuity_record` | Record an experience event in the continuity chain |
| `continuity_anchor` | Create a continuity anchor (checkpoint) |
| `continuity_heartbeat` | Create a heartbeat record indicating the agent is alive |
| `continuity_status` | Get the continuity status for an identity |
| `continuity_gaps` | Detect gaps in the experience chain |

### Spawning

| Tool | Description |
|------|-------------|
| `spawn_create` | Spawn a child identity with bounded authority |
| `spawn_terminate` | Terminate a spawned child identity |
| `spawn_list` | List spawned child identities |
| `spawn_lineage` | Get lineage information for an identity |
| `spawn_authority` | Get effective authority (bounded by lineage) |

### Competence

| Tool | Description |
|------|-------------|
| `competence_record` | Record a competence attempt outcome (success/failure/partial) |
| `competence_show` | Get competence record for a domain |
| `competence_prove` | Generate a competence proof for a domain |
| `competence_verify` | Verify a competence proof |
| `competence_list` | List all competence domains for the identity |

### Negative Capabilities

| Tool | Description |
|------|-------------|
| `negative_prove` | Generate a negative capability proof (prove impossibility) |
| `negative_verify` | Verify a negative capability proof |
| `negative_declare` | Create a voluntary negative declaration (self-imposed restriction) |
| `negative_list` | List all negative declarations for the identity |
| `negative_check` | Quick check if a capability is structurally impossible |

### Grounding Tools (v0.2)

| Tool | Description |
|------|-------------|
| `identity_ground` | Verify authority/action claim has backing in trust grants |
| `identity_evidence` | Get detailed evidence for an identity claim |
| `identity_suggest` | Find similar grants, receipts, or competence records |

### Workspace Tools (v0.2)

| Tool | Description |
|------|-------------|
| `identity_workspace_create` | Create a multi-identity workspace |
| `identity_workspace_add` | Add an identity directory to a workspace |
| `identity_workspace_list` | List loaded identity contexts in a workspace |
| `identity_workspace_query` | Query across all identity contexts |
| `identity_workspace_compare` | Compare permissions across identity contexts |
| `identity_workspace_xref` | Cross-reference a permission across contexts |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AID_IDENTITY_DIR` | `~/.agentic-identity/identities` | Identity storage directory |
| `AID_RECEIPT_DIR` | `~/.agentic-identity/receipts` | Receipt storage directory |
| `AID_TRUST_DIR` | `~/.agentic-identity/trust` | Trust delegation storage |
| `AID_LOG_LEVEL` | `info` | Logging verbosity |
| `AGENTIC_TOKEN` | — | Server-mode auth token |
