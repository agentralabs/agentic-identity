---
status: stable
---

# Installation

## One-Command Install

```bash
curl -fsSL https://agentralabs.tech/install/identity | bash
```

## Profile Install

```bash
# Desktop (default) — installs CLI + MCP, configures Claude Desktop
curl -fsSL https://agentralabs.tech/install/identity/desktop | bash

# Terminal — installs CLI + MCP, configures Claude Code
curl -fsSL https://agentralabs.tech/install/identity/terminal | bash

# Server — installs CLI + MCP with token auth
curl -fsSL https://agentralabs.tech/install/identity/server | bash
```

## From Source

```bash
cargo install agentic-identity-cli
cargo install agentic-identity-mcp
```

## Python SDK

```bash
pip install agentic-identity
```

## npm

```bash
npm install @agenticamem/identity
```

## Verify Installation

```bash
aid --version
```
