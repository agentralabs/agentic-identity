# SPEC-INSTALLER-UNIVERSAL.md

## Profiles
- `desktop`: Claude Desktop, Cursor, VS Code MCP integration
- `terminal`: CLI only, no MCP config
- `server`: Headless, token auth required

## Install Command
```bash
curl -fsSL https://agentralabs.tech/install/identity.sh | bash -s -- --profile desktop
```

## Behavior
1. Detect OS (macOS/Linux/Windows)
2. Download correct binary
3. Install to ~/.local/bin (or equivalent)
4. If desktop profile:
   - Detect MCP clients (Claude Desktop, Cursor, etc.)
   - MERGE MCP config (never overwrite)
   - Show restart instruction
5. Optional feedback prompt
6. Verify installation

## MCP Config Merge
- Read existing config
- Add agentic-identity-mcp entry if not present
- Preserve all other entries
- Write back atomically

## Server Mode
- Requires AID_AUTH_TOKEN environment variable
- Token validation before any operation
- Rate limiting enabled
