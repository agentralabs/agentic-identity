# AgenticIdentity Examples

Runnable examples demonstrating the AgenticIdentity Rust and Python APIs.

## Prerequisites

```bash
pip install agentic-identity
```

Or from source:

```bash
cargo install agentic-identity-cli
```

## Examples

| File | Description |
|------|-------------|
| `basic_identity.rs` | Create an identity anchor, inspect its public key and ID. |
| `sign_action.rs` | Sign an action and produce a verifiable receipt. |
| `trust_delegation.rs` | Grant and revoke trust between identities. |
| `python_example.py` | Python SDK usage: create identity, sign actions, verify receipts. |

## Running Rust Examples

```bash
cargo run --example basic_identity
cargo run --example sign_action
cargo run --example trust_delegation
```

## Running Python Examples

```bash
python examples/python_example.py
```
