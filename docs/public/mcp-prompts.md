---
status: stable
---

# MCP Prompts

AgenticIdentity does not currently expose any MCP prompts.

## Why No Prompts

AgenticIdentity is a cryptographic infrastructure layer. Its operations (signing, verification, trust management) are deterministic and do not benefit from prompt-based reasoning workflows. The MCP server advertises `tools` and `resources` capabilities but does not register a `prompts` capability.

## Capabilities Advertised

The server's `initialize` response declares:

```json
{
  "capabilities": {
    "tools": {},
    "resources": {}
  }
}
```

## Future Considerations

If prompt-based workflows are added in the future, likely candidates include:

- **Trust audit**: Structured prompt for reviewing trust relationships, expired grants, and delegation chains
- **Identity review**: Prompt for evaluating identity health, key rotation status, and continuity gaps
- **Competence assessment**: Prompt for analyzing competence records across domains and recommending capability adjustments

For now, agents should use the `action_context` tool to log intent before performing identity operations, and the `identity_ground` tool to verify claims before acting on them.
