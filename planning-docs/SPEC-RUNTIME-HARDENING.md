# SPEC-RUNTIME-HARDENING.md

## MCP Input Validation
- Strict parameter validation (no silent fallbacks)
- Type checking on all inputs
- Length limits on strings
- ID format validation (prefix_base58)

## Per-Project Isolation
- Identity store keyed by canonical project path
- Hash project path for storage directory name
- Never share identities across projects
- No "latest cache" cross-project fallback

## Concurrent Safety
- File locking on all stores
- Stale lock recovery (>5 min old locks)
- Atomic file writes
- Process-level mutex for key operations

## Secret Protection
- Private keys encrypted at rest
- Zeroize secrets after use
- Never log secrets
- Never include secrets in errors

## Server Mode Auth
- Token required via AID_AUTH_TOKEN
- Token validated before any operation
- Clear error on missing/invalid token
