#!/usr/bin/env python3
"""Standalone example demonstrating the AgenticIdentity Python bindings.

Prerequisites
-------------
1. Build the native shared library::

       cargo build --release -p agentic-identity-ffi

2. Install the Python package (from the repository root)::

       pip install -e python/

   Alternatively, point the loader to the library manually::

       export AGENTIC_IDENTITY_LIB=target/release/libagentic_identity_ffi.dylib

3. Run this script::

       python examples/python_example.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentic_identity import (
    Identity,
    verify_receipt,
    verify_trust_grant,
    version,
)


def main() -> None:
    print("=" * 60)
    print("AgenticIdentity Python Bindings -- Example")
    print("=" * 60)

    # ── Library version ───────────────────────────────────────────────────
    print(f"\nLibrary version: {version()}")

    # We use a temporary directory so the example is self-contained and
    # does not leave files behind.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        passphrase = "example-passphrase-do-not-reuse"

        # ── Create identities ────────────────────────────────────────────
        alice_path = tmp_dir / "alice.aid"
        bob_path = tmp_dir / "bob.aid"

        print("\n--- Identity Creation ---")

        alice_id = Identity.create(
            path=str(alice_path),
            passphrase=passphrase,
            name="alice",
        )
        print(f"Created Alice: {alice_id}")

        bob_id = Identity.create(
            path=str(bob_path),
            passphrase=passphrase,
            name="bob",
        )
        print(f"Created Bob:   {bob_id}")

        # ── Load identities ──────────────────────────────────────────────
        print("\n--- Identity Loading ---")

        with Identity.load(str(alice_path), passphrase) as alice:
            print(f"Loaded Alice:  {alice.identity_id}")
            print(f"  Public key:  {alice.public_key[:40]}...")

            with Identity.load(str(bob_path), passphrase) as bob:
                print(f"Loaded Bob:    {bob.identity_id}")
                print(f"  Public key:  {bob.public_key[:40]}...")

                # ── Action signing ────────────────────────────────────────
                print("\n--- Action Signing ---")

                receipt_json = alice.sign_action(
                    action_type="decision",
                    description="Approved deployment of v2.1.0 to production",
                )
                receipt = json.loads(receipt_json)
                print(f"Receipt ID:    {receipt['id']}")
                print(f"Signature:     {receipt['signature'][:40]}...")

                # Sign an action with structured data attached.
                data_receipt_json = alice.sign_action(
                    action_type="mutation",
                    description="Updated retry configuration",
                    data={"key": "max_retries", "old_value": 3, "new_value": 5},
                )
                data_receipt = json.loads(data_receipt_json)
                print(f"Data receipt:  {data_receipt['id']}")

                # ── Receipt verification ──────────────────────────────────
                print("\n--- Receipt Verification ---")

                is_valid = verify_receipt(receipt_json)
                print(f"Valid receipt:  {is_valid}")

                is_valid_data = verify_receipt(data_receipt_json)
                print(f"Data receipt:  {is_valid_data}")

                # ── Trust grants ──────────────────────────────────────────
                print("\n--- Trust Grants ---")

                grant_json = alice.create_trust_grant(
                    grantee_id=bob.identity_id,
                    grantee_key=bob.public_key,
                    capabilities=["read:calendar", "write:email", "execute:deploy"],
                )
                grant = json.loads(grant_json)
                print(f"Grant ID:      {grant['id']}")
                print(f"Capabilities:  {[c['uri'] for c in grant.get('capabilities', [])]}")

                # ── Trust verification ────────────────────────────────────
                print("\n--- Trust Verification ---")

                for cap in ("read:calendar", "write:email", "execute:deploy", "delete:everything"):
                    valid = verify_trust_grant(grant_json, cap)
                    status = "GRANTED" if valid else "DENIED"
                    print(f"  {cap:<25s} -> {status}")

    print("\n" + "=" * 60)
    print("Example completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
