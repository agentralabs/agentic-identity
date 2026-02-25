"""Unit tests for the agentic_identity Python bindings.

These tests exercise the full round-trip through the native FFI library:
identity creation, loading, action signing, receipt verification, trust
grants, and trust verification.

Requirements
------------
* The native shared library must be built before running::

      cargo build --release -p agentic-identity-ffi

* Install the Python package in development mode::

      pip install -e python/[dev]

* Run with::

      pytest python/tests/
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from agentic_identity import (
    AgenticIdentityError,
    Identity,
    verify_receipt,
    verify_trust_grant,
    version,
)
from agentic_identity._ffi import (
    AID_ERR_CRYPTO,
    AID_ERR_IO,
    AID_ERR_NULL_PTR,
    AID_ERR_SERIALIZATION,
    AID_OK,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_dir():
    """Yield a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture()
def identity_path(tmp_dir: Path) -> Path:
    """Return a path inside *tmp_dir* suitable for an ``.aid`` file."""
    return tmp_dir / "test-agent.aid"


PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture()
def created_identity(identity_path: Path) -> tuple[str, Path]:
    """Create a fresh identity and return ``(identity_id, path)``."""
    identity_id = Identity.create(
        path=str(identity_path),
        passphrase=PASSPHRASE,
        name="test-agent",
    )
    return identity_id, identity_path


@pytest.fixture()
def loaded_identity(created_identity: tuple[str, Path]) -> Identity:
    """Load the identity created by *created_identity* and yield it."""
    _, path = created_identity
    identity = Identity.load(path=str(path), passphrase=PASSPHRASE)
    yield identity
    identity.close()


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_returns_string(self) -> None:
        v = version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_version_format(self) -> None:
        v = version()
        parts = v.split(".")
        assert len(parts) == 3, f"Expected semver, got {v!r}"
        for part in parts:
            assert part.isdigit(), f"Non-numeric semver component: {part!r}"


# ---------------------------------------------------------------------------
# Identity creation
# ---------------------------------------------------------------------------


class TestIdentityCreate:
    def test_create_returns_id(self, identity_path: Path) -> None:
        identity_id = Identity.create(
            path=str(identity_path),
            passphrase=PASSPHRASE,
            name="create-test",
        )
        assert identity_id.startswith("aid_")

    def test_create_without_name(self, tmp_dir: Path) -> None:
        path = tmp_dir / "no-name.aid"
        identity_id = Identity.create(
            path=str(path),
            passphrase=PASSPHRASE,
            name=None,
        )
        assert identity_id.startswith("aid_")

    def test_create_writes_file(self, identity_path: Path) -> None:
        Identity.create(
            path=str(identity_path),
            passphrase=PASSPHRASE,
        )
        assert identity_path.exists()
        assert identity_path.stat().st_size > 0


# ---------------------------------------------------------------------------
# Identity loading
# ---------------------------------------------------------------------------


class TestIdentityLoad:
    def test_load_roundtrip_id(
        self,
        created_identity: tuple[str, Path],
    ) -> None:
        created_id, path = created_identity
        with Identity.load(str(path), PASSPHRASE) as identity:
            assert identity.identity_id == created_id

    def test_load_public_key(self, loaded_identity: Identity) -> None:
        pk = loaded_identity.public_key
        assert isinstance(pk, str)
        assert len(pk) > 0

    def test_load_wrong_passphrase(
        self,
        created_identity: tuple[str, Path],
    ) -> None:
        _, path = created_identity
        with pytest.raises(AgenticIdentityError):
            Identity.load(str(path), "wrong-passphrase")

    def test_load_nonexistent_file(self, tmp_dir: Path) -> None:
        with pytest.raises(AgenticIdentityError):
            Identity.load(str(tmp_dir / "does-not-exist.aid"), PASSPHRASE)


# ---------------------------------------------------------------------------
# Context manager / close
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_context_manager(
        self,
        created_identity: tuple[str, Path],
    ) -> None:
        _, path = created_identity
        with Identity.load(str(path), PASSPHRASE) as identity:
            assert identity.identity_id.startswith("aid_")
        # After exiting the context, the handle is closed.
        with pytest.raises(AgenticIdentityError):
            _ = identity.identity_id

    def test_double_close_is_safe(
        self,
        loaded_identity: Identity,
    ) -> None:
        loaded_identity.close()
        loaded_identity.close()  # Must not crash or raise.


# ---------------------------------------------------------------------------
# Action signing
# ---------------------------------------------------------------------------


class TestActionSign:
    def test_sign_decision(self, loaded_identity: Identity) -> None:
        receipt_json = loaded_identity.sign_action(
            action_type="decision",
            description="Approved deployment to production",
        )
        receipt = json.loads(receipt_json)
        assert "id" in receipt
        assert receipt["id"].startswith("arec_")
        assert "signature" in receipt
        assert len(receipt["signature"]) > 0

    def test_sign_with_data(self, loaded_identity: Identity) -> None:
        data = {"key": "retries", "value": 5}
        receipt_json = loaded_identity.sign_action(
            action_type="mutation",
            description="Updated config",
            data=data,
        )
        receipt = json.loads(receipt_json)
        assert "id" in receipt

    def test_sign_custom_action_type(self, loaded_identity: Identity) -> None:
        receipt_json = loaded_identity.sign_action(
            action_type="audit",
            description="Audit event recorded",
        )
        receipt = json.loads(receipt_json)
        assert "id" in receipt

    def test_sign_all_standard_types(self, loaded_identity: Identity) -> None:
        for atype in (
            "decision",
            "observation",
            "mutation",
            "delegation",
            "revocation",
            "identity_operation",
        ):
            receipt_json = loaded_identity.sign_action(
                action_type=atype,
                description=f"Test {atype} action",
            )
            assert json.loads(receipt_json)["id"].startswith("arec_")


# ---------------------------------------------------------------------------
# Receipt verification
# ---------------------------------------------------------------------------


class TestReceiptVerify:
    def test_verify_valid_receipt(self, loaded_identity: Identity) -> None:
        receipt_json = loaded_identity.sign_action(
            action_type="observation",
            description="Observed high memory usage",
        )
        assert verify_receipt(receipt_json) is True

    def test_verify_tampered_receipt(self) -> None:
        tampered = json.dumps({
            "id": "arec_tampered",
            "actor": "aid_fake",
            "actor_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "action_type": "Decision",
            "action": {
                "description": "fake",
                "data": None,
                "references": [],
            },
            "timestamp": 1,
            "context_hash": None,
            "previous_receipt": None,
            "receipt_hash": "0" * 64,
            "signature": "A" * 88,
            "witnesses": [],
        })
        # Either returns False or raises an error -- both are acceptable
        # since the receipt is garbage.
        try:
            result = verify_receipt(tampered)
            assert result is False
        except AgenticIdentityError:
            pass  # Parsing/crypto error is also acceptable.

    def test_verify_invalid_json(self) -> None:
        with pytest.raises(AgenticIdentityError):
            verify_receipt("this is not json")


# ---------------------------------------------------------------------------
# Trust grants
# ---------------------------------------------------------------------------


class TestTrustGrant:
    @pytest.fixture()
    def grantor_and_grantee(
        self,
        tmp_dir: Path,
    ) -> tuple[Identity, Identity]:
        """Create two identities: a grantor and a grantee."""
        grantor_path = tmp_dir / "grantor.aid"
        grantee_path = tmp_dir / "grantee.aid"

        Identity.create(str(grantor_path), PASSPHRASE, name="grantor")
        Identity.create(str(grantee_path), PASSPHRASE, name="grantee")

        grantor = Identity.load(str(grantor_path), PASSPHRASE)
        grantee = Identity.load(str(grantee_path), PASSPHRASE)
        yield grantor, grantee
        grantor.close()
        grantee.close()

    def test_create_trust_grant(
        self,
        grantor_and_grantee: tuple[Identity, Identity],
    ) -> None:
        grantor, grantee = grantor_and_grantee
        grant_json = grantor.create_trust_grant(
            grantee_id=grantee.identity_id,
            grantee_key=grantee.public_key,
            capabilities=["read:calendar", "write:email"],
        )
        grant = json.loads(grant_json)
        assert "id" in grant
        assert "grantor_signature" in grant
        assert len(grant["grantor_signature"]) > 0

    def test_verify_covered_capability(
        self,
        grantor_and_grantee: tuple[Identity, Identity],
    ) -> None:
        grantor, grantee = grantor_and_grantee
        grant_json = grantor.create_trust_grant(
            grantee_id=grantee.identity_id,
            grantee_key=grantee.public_key,
            capabilities=["read:calendar", "write:email"],
        )
        assert verify_trust_grant(grant_json, "read:calendar") is True
        assert verify_trust_grant(grant_json, "write:email") is True

    def test_verify_uncovered_capability(
        self,
        grantor_and_grantee: tuple[Identity, Identity],
    ) -> None:
        grantor, grantee = grantor_and_grantee
        grant_json = grantor.create_trust_grant(
            grantee_id=grantee.identity_id,
            grantee_key=grantee.public_key,
            capabilities=["read:calendar"],
        )
        assert verify_trust_grant(grant_json, "delete:everything") is False


# ---------------------------------------------------------------------------
# Error class
# ---------------------------------------------------------------------------


class TestAgenticIdentityError:
    def test_error_has_code(self) -> None:
        err = AgenticIdentityError(AID_ERR_CRYPTO, "crypto failed")
        assert err.code == AID_ERR_CRYPTO
        assert "crypto failed" in str(err)
        assert str(AID_ERR_CRYPTO) in str(err)

    def test_error_is_exception(self) -> None:
        with pytest.raises(AgenticIdentityError):
            raise AgenticIdentityError(AID_ERR_IO, "test")
