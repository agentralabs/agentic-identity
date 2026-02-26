# Installing AgenticIdentity

## Quick Install (Recommended)

```bash
curl -fsSL https://agentralabs.tech/install/identity | bash
```

This installs the `aid` CLI and `agentic-identity-mcp` server.

## Install Profiles

```bash
curl -fsSL https://agentralabs.tech/install/identity/desktop | bash
curl -fsSL https://agentralabs.tech/install/identity/terminal | bash
curl -fsSL https://agentralabs.tech/install/identity/server | bash
```

## From crates.io

```bash
# CLI tool
cargo install agentic-identity-cli

# MCP server
cargo install agentic-identity-mcp
```

## From Source

```bash
git clone https://github.com/agentralabs/agentic-identity.git
cd agentic-identity

# Build everything
cargo build --workspace --release

# Install CLI and MCP server
cargo install --path crates/agentic-identity-cli
cargo install --path crates/agentic-identity-mcp
```

## Python SDK

```bash
pip install agentic-identity
```

Or from source:

```bash
cd python/
pip install -e ".[dev]"
```

## Verify Installation

```bash
# CLI
aid --version
aid identity create my-agent

# MCP server
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | agentic-identity-mcp

# Python
python -c "import agentic_identity; print(agentic_identity.__version__)"
```

## MCP Integration

### Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentic-identity": {
      "command": "agentic-identity-mcp",
      "args": []
    }
  }
}
```

### Programmatic

```python
import subprocess, json

proc = subprocess.Popen(
    ["agentic-identity-mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE
)
```

## System Requirements

- **Rust**: 1.75+ (for building from source)
- **Python**: 3.10+ (for Python SDK)
- **OS**: Linux (x86_64, aarch64), macOS (x86_64, aarch64)
