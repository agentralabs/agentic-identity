
# AgenticIdentity Quickstart

Get cryptographic identity for your AI agents in under 5 minutes.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/agentralabs/agentic-identity/main/install.sh | bash
```

## Create Your First Identity

```bash
aid init --name my-agent
```

You'll be prompted for a passphrase. This encrypts the private key at rest.

## Sign an Action

```bash
aid sign --type decision --description "Approved deployment to production"
```

This creates a cryptographically signed receipt proving your agent took this action.

## Verify a Receipt

```bash
aid verify receipt arec_7xK9mP2...
```

## Grant Trust

```bash
aid trust grant --to aid_4Yn3kL... --capability "read:calendar" --expires 7d
```

## MCP Integration

If you installed with the desktop profile, AgenticIdentity is already available to your AI agent via MCP. Ask your agent:

> "Create an identity and sign a receipt for reviewing this code."

The agent will use the `identity_create` and `action_sign` MCP tools automatically.
