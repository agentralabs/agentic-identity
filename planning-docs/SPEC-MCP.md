# SPEC-MCP.md

## Tools (14)

### Identity Tools
- `identity_create`: Create new identity
- `identity_show`: Get identity details
- `identity_list`: List identities

### Receipt Tools
- `receipt_sign`: Sign action, create receipt
- `receipt_verify`: Verify receipt signature and chain
- `receipt_list`: List receipts by actor/type/time

### Trust Tools
- `trust_grant`: Create trust grant
- `trust_revoke`: Revoke trust grant
- `trust_verify`: Check if identity has capability
- `trust_list`: List trust grants

### Continuity Tools
- `continuity_prove`: Generate continuity proof
- `continuity_verify`: Verify continuity claim
- `continuity_status`: Get current continuity state

### Spawn Tools
- `spawn_create`: Spawn child identity
- `spawn_terminate`: Terminate child
- `spawn_lineage`: Get lineage information

## Resources (8)
- `identity://{id}`: Identity document
- `receipt://{id}`: Receipt details
- `trust://{id}`: Trust grant details
- `continuity://{id}`: Continuity state
- `spawn://{id}`: Spawn record
- `receipts://{identity}`: Receipt list
- `grants://{identity}`: Trust grants
- `children://{identity}`: Spawn children

## Prompts (4)
- `sign_action`: Guide action signing
- `grant_trust`: Guide trust creation
- `verify_identity`: Guide verification
- `spawn_agent`: Guide spawning

## Parameter Validation
- Strict validation, no silent fallbacks
- Clear error messages
- Input sanitization for all string params
