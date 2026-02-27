---
status: stable
---

# MCP Resources

AgenticIdentity exposes identity data through the `aid://` URI scheme in the MCP Resources API.

## URI Scheme

All resources use the `aid://` prefix.

## Available Resources

### `aid://identity/{name}`

Returns the public identity document for a named identity.

**Format:** JSON object with identity metadata.

```json
{
  "id": "aid_7xKj3mNp2Qr5sT8vW1yZ4aB6cD9eF",
  "name": "default",
  "algorithm": "Ed25519",
  "public_key": "base64-encoded-public-key",
  "created_at": 1740000000000000,
  "rotation_history": [],
  "attestations": [],
  "signature": "base64-encoded-self-signature"
}
```

### `aid://identity/default`

Returns the public identity document for the default identity. This is listed as a static resource in `resources/list`.

### `aid://receipts/recent`

Returns the most recent action receipts (up to 20), sorted by timestamp descending.

**Format:** JSON array of receipt objects.

```json
[
  {
    "id": "arec_a1b2c3d4...",
    "actor": "aid_7xKj3mNp...",
    "actor_key": "base64-key",
    "action_type": "Decision",
    "action": {
      "description": "Approved deployment",
      "data": null,
      "references": []
    },
    "timestamp": 1740000000000000,
    "signature": "base64-signature"
  }
]
```

### `aid://receipt/{receipt_id}`

Returns a single action receipt by its ID.

**URI example:** `aid://receipt/arec_a1b2c3d4e5f6`

### `aid://trust/granted`

Returns all trust grants issued by this identity.

**Format:** JSON array of trust grant objects.

```json
[
  {
    "id": "atrust_a1b2c3d4...",
    "grantor": "aid_grantor...",
    "grantee": "aid_grantee...",
    "capabilities": [
      {"uri": "read:calendar"},
      {"uri": "write:notes"}
    ],
    "constraints": {
      "expires_at": 1740086400000000,
      "max_uses": null,
      "allow_delegation": false
    },
    "signature": "base64-signature"
  }
]
```

### `aid://trust/received`

Returns all trust grants received by this identity.

### `aid://trust/{trust_id}`

Returns a single trust grant by its ID.

**URI example:** `aid://trust/atrust_a1b2c3d4e5f6`

## Resource Templates

### `aid://identity/{name}`

Access the public document for any named identity. Replace `{name}` with the identity name (e.g., `"default"`, `"my-agent"`).

### `aid://receipt/{receipt_id}`

Access any receipt by its full ID. Replace `{receipt_id}` with the receipt ID (e.g., `"arec_a1b2c3d4..."`).

### `aid://trust/{trust_id}`

Access any trust grant by its full ID. Replace `{trust_id}` with the trust ID (e.g., `"atrust_a1b2c3d4..."`).

## Cross-Sister Resources

When running alongside other Agentra sisters, AgenticIdentity resources can be referenced in other contexts:

- Memory nodes can link to `aid://receipt/{id}` for audit trail context
- Codebase analysis can reference `aid://trust/{id}` for access control verification
- Vision captures can link to `aid://identity/{name}` for attributing observations to specific agents
- Time operations can reference `aid://receipt/{id}` for signed temporal events
