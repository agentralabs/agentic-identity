# agentic-identity

Python bindings for the [AgenticIdentity](https://github.com/agentralabs/agentic-identity) cryptographic trust anchor.

## Install

```bash
pip install agentic-identity
```

> **Note:** The native shared library must be built first:
> ```bash
> cargo build --release -p agentic-identity-ffi
> ```

## Quick Start

```python
from agentic_identity import Identity, verify_receipt, version

print(f"Library version: {version()}")

# Create a new identity
identity_id = Identity.create(
    path="agent.aid",
    passphrase="strong-passphrase",
    name="my-agent",
)
print(f"Created: {identity_id}")

# Load and use the identity
with Identity.load("agent.aid", "strong-passphrase") as identity:
    print(f"ID: {identity.identity_id}")
    print(f"Public key: {identity.public_key}")

    # Sign an action
    receipt = identity.sign_action(
        action_type="decision",
        description="Approved deployment to production",
    )

    # Verify the receipt
    assert verify_receipt(receipt)
    print("Receipt verified!")
```

## Features

- **Zero dependencies** — only Python stdlib (`ctypes`, `json`, `dataclasses`)
- **Ed25519 signatures** — identity anchors, action receipts, trust grants
- **Type-safe models** — frozen dataclasses for all domain types
- **Context manager** — automatic cleanup of native handles
- **Full FFI coverage** — all 11 C API functions bound

## Requirements

- Python >= 3.10
- Native library: `cargo build --release -p agentic-identity-ffi`

## License

MIT
