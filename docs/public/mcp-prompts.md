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

The `prompts` key is intentionally omitted. MCP clients that check for prompt support will correctly see that this server does not offer any.

## Design Rationale

Prompts in MCP are intended for workflows where the server guides the client through a multi-step reasoning process with templated text and user-provided arguments. AgenticIdentity operations are better served by direct tool calls because:

1. **Deterministic outputs**: Signing a receipt or verifying a trust grant produces a fixed cryptographic result, not a reasoning chain that benefits from prompt templating.
2. **No user interaction**: Identity operations run in automated agent contexts where there is no human to fill in prompt arguments interactively.
3. **Tool composability**: Agents compose identity tools with their own reasoning rather than following server-prescribed prompt flows.

## Context-Capture Tools Instead

Rather than prompts, AgenticIdentity provides context-capture tools that agents call before performing identity operations:

- **`action_context`**: Log the intent and reasoning behind identity actions. Accepts `intent` (required), `topic`, `decision`, and `significance` (routine, important, critical). Call this to record WHY you are performing identity operations.
- **`identity_ground`**: Verify a claim has backing in trust grants, receipts, or competence records before acting on it. Prevents hallucination about permissions.
- **`identity_evidence`**: Retrieve detailed evidence for an identity claim from trust grants, receipts, and competence records.

These tools serve a similar role to prompts — providing structured reasoning context — but are invoked by the agent as needed rather than pushed by the server.

## Future Considerations

If prompt-based workflows are added in the future, likely candidates include:

- **Trust audit**: Structured prompt for reviewing trust relationships, expired grants, and delegation chains
- **Identity review**: Prompt for evaluating identity health, key rotation status, and continuity gaps
- **Competence assessment**: Prompt for analyzing competence records across domains and recommending capability adjustments
- **Spawn planning**: Prompt for designing a child identity hierarchy with appropriate authority ceilings and lifetime policies

For now, agents should use the `action_context` tool to log intent before performing identity operations, and the `identity_ground` tool to verify claims before acting on them.
