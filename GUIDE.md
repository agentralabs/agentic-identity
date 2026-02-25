# GUIDE.md

## Create an Identity

```bash
aid create --name "my-agent"
```

## Sign an Action

```bash
aid sign --action "Approved deployment" --type decision
```

## Verify a Receipt

```bash
aid verify --receipt receipt.json
```

## Trust Management

```bash
aid trust grant --to <agent-id> --scope read
aid trust list
aid trust revoke --id <delegation-id>
```

## MCP Server

```bash
agentic-identity-mcp
```

Exposes identity operations to AI agents via the Model Context Protocol.
