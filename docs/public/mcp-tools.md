---
status: stable
---

# MCP Tools

AgenticIdentity exposes 35+ core tools through the MCP protocol via `agentic-identity-mcp`, plus additional invention modules for trust dynamics, accountability, federation, and resilience.

## Identity Tools

### `identity_create`

Create a new AgenticIdentity. Uses the default MCP passphrase.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | No | Human-readable name for the identity (default: `"default"`) |

**Returns:** Identity ID, public key, creation timestamp, and file path.

### `identity_show`

Show identity information (public document, no passphrase required).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | No | Identity name (default: `"default"`) |

**Returns:** Identity ID, algorithm, public key, creation timestamp, signature status, key rotation history, and attestations.

### `identity_health`

Check system health: identity files, receipt store, trust store.

No parameters.

**Returns:** Health status of identity directory, receipt store, and trust store.

## Action Receipt Tools

### `action_sign`

Sign an action and create a verifiable receipt.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | Human-readable description of the action |
| `action_type` | string | No | `decision`, `observation`, `mutation`, `delegation`, `revocation`, `identity_operation`, or custom string (default: `"decision"`) |
| `data` | object | No | Optional structured data payload |
| `chain_to` | string | No | Previous receipt ID to chain to (`arec_...`) |
| `identity` | string | No | Identity name to sign with (default: `"default"`) |

**Returns:** Receipt ID, actor, action type, timestamp, and signature.

### `receipt_verify`

Verify the cryptographic signature on a receipt.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `receipt_id` | string | Yes | Receipt ID (`arec_...`) |

**Returns:** Verification result: valid/invalid with details.

### `receipt_list`

List action receipts with optional filters.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `actor` | string | No | Filter by actor identity ID (`aid_...`) |
| `action_type` | string | No | Filter by action type |
| `limit` | number | No | Maximum number of receipts to return (default: 20) |

## Trust Tools

### `trust_grant`

Grant trust (capabilities) to another identity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grantee` | string | Yes | Grantee identity ID (`aid_...`) |
| `capabilities` | array | Yes | Capability URIs to grant (e.g., `["read:calendar", "write:notes"]`) |
| `expires` | string | No | Expiry duration string (e.g., `"24h"`, `"7d"`, `"30d"`) |
| `max_uses` | number | No | Maximum number of uses (null = unlimited) |
| `allow_delegation` | boolean | No | Whether the grantee can delegate trust to others (default: false) |
| `identity` | string | No | Grantor identity name (default: `"default"`) |

**Returns:** Trust grant ID, grantor, grantee, capabilities, and constraints.

### `trust_revoke`

Revoke a trust grant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `trust_id` | string | Yes | Trust grant ID (`atrust_...`) |
| `reason` | string | No | Reason: `manual_revocation`, `expired`, `compromised`, `policy_violation`, `grantee_request`, or `custom:<text>` (default: `"manual_revocation"`) |
| `identity` | string | No | Identity name performing the revocation (default: `"default"`) |

### `trust_verify`

Verify whether a trust grant is currently valid for a capability.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `trust_id` | string | Yes | Trust grant ID (`atrust_...`) |
| `capability` | string | No | Capability URI to check (default: `"*"` checks overall validity) |

**Returns:** Verification result including signature, expiry, use count, and capability match.

### `trust_list`

List trust grants (granted by or received by this identity).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `direction` | string | No | `"granted"`, `"received"`, or `"both"` (default: `"both"`) |
| `valid_only` | boolean | No | Only show non-revoked grants (default: false) |

## Continuity Tools

### `continuity_record`

Record an experience event in the continuity chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content_hash` | string | Yes | Hash of the experience content |
| `experience_type` | string | No | `perception`, `cognition`, `action`, `memory`, `learning`, `planning`, `emotion`, `idle`, `system` (default: `"cognition"`) |
| `intensity` | number | No | Intensity of the experience, 0.0 to 1.0 (default: 0.5) |
| `identity` | string | No | Identity name (default: `"default"`) |

### `continuity_anchor`

Create a continuity anchor (checkpoint) at the current state.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `anchor_type` | string | No | `genesis`, `manual`, `time_based`, `experience_count` (default: `"manual"`) |
| `identity` | string | No | Identity name (default: `"default"`) |

### `continuity_heartbeat`

Create a heartbeat record indicating the agent is alive.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | `active`, `idle`, `suspended`, `degraded` (default: `"active"`) |
| `identity` | string | No | Identity name (default: `"default"`) |

### `continuity_status`

Get the continuity status for an identity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `identity` | string | No | Identity name (default: `"default"`) |

**Returns:** Experience chain length, last event timestamp, anchor count, heartbeat status.

### `continuity_gaps`

Detect gaps in the experience chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grace_period_seconds` | number | No | Grace period in seconds; gaps shorter are ignored (default: 300) |
| `identity` | string | No | Identity name (default: `"default"`) |

**Returns:** List of detected gaps with start/end timestamps and duration.

## Spawn Tools

### `spawn_create`

Spawn a child identity with bounded authority.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `purpose` | string | Yes | Purpose of the spawned identity |
| `authority` | array | Yes | Capability URIs to grant to the child |
| `spawn_type` | string | No | `worker`, `delegate`, `clone`, `specialist` (default: `"worker"`) |
| `lifetime` | string | No | `indefinite`, `parent_termination`, or duration in seconds (default: `"indefinite"`) |
| `identity` | string | No | Parent identity name (default: `"default"`) |

**Returns:** Spawn record ID, child identity ID, purpose, authority, and lifetime.

### `spawn_terminate`

Terminate a spawned child identity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `spawn_id` | string | Yes | Spawn record ID (`aspawn_...`) |
| `reason` | string | No | Reason for termination |
| `cascade` | boolean | No | Whether to cascade termination to descendants (default: false) |
| `identity` | string | No | Parent identity name (default: `"default"`) |

### `spawn_list`

List spawned child identities.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `active_only` | boolean | No | Only show active (non-terminated) spawns (default: false) |
| `identity` | string | No | Parent identity name (default: `"default"`) |

### `spawn_lineage`

Get lineage information for an identity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `identity` | string | No | Identity name (default: `"default"`) |

**Returns:** Lineage chain from root to current identity, including spawn types and authority at each level.

### `spawn_authority`

Get effective authority for an identity (bounded by lineage).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `identity` | string | No | Identity name (default: `"default"`) |

**Returns:** Effective capabilities after applying all lineage constraints.

## Competence Tools

### `competence_record`

Record a competence attempt outcome (success, failure, partial).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | Yes | Competence domain (e.g., `"deploy"`, `"code_review"`) |
| `outcome` | string | Yes | `success`, `failure`, or `partial` |
| `receipt_id` | string | Yes | Receipt ID linking to the action |
| `reason` | string | No | Failure reason (for outcome=failure) |
| `score` | number | No | Partial score 0.0-1.0 (for outcome=partial) |

### `competence_show`

Get competence record for a domain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | No | Competence domain |

**Returns:** Success rate, attempt count, recent outcomes, and trend.

### `competence_prove`

Generate a competence proof for a domain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | Yes | Competence domain |
| `min_rate` | number | No | Minimum success rate, 0.0-1.0 |
| `min_attempts` | number | No | Minimum number of attempts |

**Returns:** Signed competence proof with domain, success rate, attempt count, and cryptographic signature.

### `competence_verify`

Verify a competence proof.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `proof_id` | string | Yes | Proof ID to verify |

**Returns:** Verification result: valid/invalid with domain and rate details.

### `competence_list`

List all competence domains for the identity.

No parameters.

**Returns:** Array of domain names with summary statistics.

## Negative Proof Tools

### `negative_prove`

Generate a negative capability proof (prove agent cannot do something).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `capability` | string | Yes | Capability URI to prove impossible |

**Returns:** Signed negative proof with capability, reason, and cryptographic signature.

### `negative_verify`

Verify a negative capability proof.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `proof_id` | string | Yes | Negative proof ID to verify |

**Returns:** Verification result: valid/invalid.

### `negative_declare`

Create a voluntary negative declaration (self-imposed restriction).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `capabilities` | string | Yes | Comma-separated capability URIs to declare impossible |
| `reason` | string | Yes | Reason for the declaration |
| `permanent` | boolean | No | If true, cannot be undone |

### `negative_list`

List all negative declarations for the identity.

No parameters.

**Returns:** Array of negative declarations with capabilities, reasons, and permanence.

### `negative_check`

Quick check if a capability is structurally impossible.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `capability` | string | Yes | Capability URI to check |

**Returns:** Boolean indicating whether the capability is declared impossible.

## Context Tool

### `action_context`

Log the intent and context behind identity actions. Call this to record WHY you are performing identity operations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `intent` | string | Yes | Why you are performing identity actions (e.g., `"establishing trust with new collaborator"`) |
| `decision` | string | No | What was decided or concluded |
| `significance` | string | No | `"routine"`, `"important"`, or `"critical"` |
| `topic` | string | No | Optional topic or category (e.g., `"trust-management"`, `"spawn-setup"`) |

## Grounding Tools (Anti-Hallucination)

### `identity_ground`

Verify an authority/action claim has backing in trust grants, receipts, or competence records. Prevents hallucination about permissions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `claim` | string | Yes | The claim to verify (e.g., `"agent has deploy permission"`) |
| `identity` | string | No | Identity name (default: `"default"`) |

**Returns:** Grounding status: `verified`, `partial`, or `ungrounded`.

### `identity_evidence`

Get detailed evidence for an identity claim from trust grants, receipts, and competence records.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | The query to search evidence for |
| `identity` | string | No | Identity name (default: `"default"`) |
| `max_results` | number | No | Maximum number of results (default: 10) |

**Returns:** Array of matching evidence items with kind, ID, text, and relevance score.

### `identity_suggest`

Find similar grants, receipts, or competence records when a claim doesn't match exactly.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | The query to find suggestions for |
| `identity` | string | No | Identity name (default: `"default"`) |
| `limit` | number | No | Maximum number of suggestions (default: 5) |

## Workspace Tools

### `identity_workspace_create`

Create a multi-identity workspace for comparing permissions across agents.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Workspace name |

**Returns:** Workspace ID.

### `identity_workspace_add`

Add an identity directory to a workspace for cross-identity comparison.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workspace_id` | string | Yes | Workspace ID |
| `path` | string | Yes | Path to identity directory |
| `role` | string | No | `"primary"`, `"secondary"`, `"reference"`, `"archive"` (default: `"primary"`) |
| `label` | string | No | Human-readable label for this context |

### `identity_workspace_list`

List loaded identity contexts in a workspace.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workspace_id` | string | Yes | Workspace ID |

**Returns:** Array of contexts with path, role, and label.

### `identity_workspace_query`

Query across all identity contexts in a workspace.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workspace_id` | string | Yes | Workspace ID |
| `query` | string | Yes | Text query to search across all contexts |
| `max_per_context` | number | No | Maximum matches per context (default: 10) |

**Returns:** Matches from each loaded context.

### `identity_workspace_compare`

Compare permissions or capabilities across identity contexts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workspace_id` | string | Yes | Workspace ID |
| `item` | string | Yes | Topic/concept to compare across contexts |
| `max_per_context` | number | No | Maximum matches per context (default: 5) |

### `identity_workspace_xref`

Cross-reference a permission across identity contexts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workspace_id` | string | Yes | Workspace ID |
| `item` | string | Yes | Topic/concept to cross-reference |

**Returns:** Which contexts contain the item and which do not.
