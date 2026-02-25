---
status: stable
---

# Implementation Status (2026-02-22)

## Core Library (`agentic-identity`)

- Ed25519 identity anchors with key derivation
- Action receipt signing and verification
- Trust delegation (grant, revoke, list, validate)
- Continuity engine (experience chains, cumulative hashing, tamper detection)
- Child identity spawning with parent attestation
- Encrypted storage with Argon2 + ChaCha20-Poly1305
- Binary `.aid` identity file format

## CLI (`aid`)

- `create`, `sign`, `verify`, `export`
- `trust grant`, `trust revoke`, `trust list`
- `continuity start`, `continuity status`
- `spawn`

## MCP Server (`agentic-identity-mcp`)

- 30 tools exposing full identity surface
- `action_context` tool for capturing intent behind operations
- Auto-logging of all tool calls
- stdio transport

## SDKs

- Python SDK (`agentic-identity` on PyPI)
- WASM bindings (`@agentralabss/identity` on npm)

## Test Coverage

- 229+ tests across unit, integration, and stress categories
