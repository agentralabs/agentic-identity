
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
