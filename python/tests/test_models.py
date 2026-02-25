"""Tests for the agentic_identity.models module.

Validates frozen dataclasses, enums, and parsing helpers.
"""

from __future__ import annotations

import dataclasses

import pytest

from agentic_identity.models import (
    ActionReceipt,
    ActionType,
    IdentityInfo,
    TrustGrant,
    TrustScope,
    VerificationResult,
    parse_receipt,
    parse_trust_grant,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestActionType:
    def test_values(self) -> None:
        assert ActionType.DECISION == "decision"
        assert ActionType.OBSERVATION == "observation"
        assert ActionType.MUTATION == "mutation"
        assert ActionType.DELEGATION == "delegation"
        assert ActionType.REVOCATION == "revocation"
        assert ActionType.IDENTITY_OPERATION == "identity_operation"
        assert ActionType.CUSTOM == "custom"

    def test_is_str(self) -> None:
        assert isinstance(ActionType.DECISION, str)

    def test_from_string(self) -> None:
        assert ActionType("decision") == ActionType.DECISION

    def test_all_members(self) -> None:
        assert len(ActionType) == 7


class TestTrustScope:
    def test_values(self) -> None:
        assert TrustScope.READ == "read"
        assert TrustScope.WRITE == "write"
        assert TrustScope.EXECUTE == "execute"
        assert TrustScope.ADMIN == "admin"
        assert TrustScope.ALL == "*"

    def test_is_str(self) -> None:
        assert isinstance(TrustScope.READ, str)


# ---------------------------------------------------------------------------
# IdentityInfo
# ---------------------------------------------------------------------------


class TestIdentityInfo:
    def test_create(self) -> None:
        info = IdentityInfo(
            identity_id="aid_test123",
            public_key="AAAA==",
            name="test-agent",
            created_at="2026-01-01T00:00:00Z",
        )
        assert info.identity_id == "aid_test123"
        assert info.public_key == "AAAA=="
        assert info.name == "test-agent"
        assert info.created_at == "2026-01-01T00:00:00Z"

    def test_defaults(self) -> None:
        info = IdentityInfo(identity_id="aid_x", public_key="key")
        assert info.name is None
        assert info.created_at == ""

    def test_frozen(self) -> None:
        info = IdentityInfo(identity_id="aid_x", public_key="key")
        with pytest.raises(dataclasses.FrozenInstanceError):
            info.identity_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ActionReceipt
# ---------------------------------------------------------------------------


class TestActionReceipt:
    def test_create(self) -> None:
        receipt = ActionReceipt(
            id="arec_abc",
            actor="aid_actor",
            actor_key="key==",
            action_type="decision",
            description="test action",
            timestamp=1000,
            signature="sig==",
            receipt_hash="abc123",
        )
        assert receipt.id == "arec_abc"
        assert receipt.actor == "aid_actor"

    def test_is_chained_false(self) -> None:
        receipt = ActionReceipt(
            id="arec_1",
            actor="aid_a",
            actor_key="k",
            action_type="decision",
            description="d",
            timestamp=0,
            signature="s",
            receipt_hash="h",
        )
        assert receipt.is_chained is False

    def test_is_chained_true(self) -> None:
        receipt = ActionReceipt(
            id="arec_2",
            actor="aid_a",
            actor_key="k",
            action_type="decision",
            description="d",
            timestamp=0,
            signature="s",
            receipt_hash="h",
            previous_receipt="arec_1",
        )
        assert receipt.is_chained is True

    def test_frozen(self) -> None:
        receipt = ActionReceipt(
            id="arec_x",
            actor="aid_a",
            actor_key="k",
            action_type="decision",
            description="d",
            timestamp=0,
            signature="s",
            receipt_hash="h",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            receipt.id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustGrant
# ---------------------------------------------------------------------------


class TestTrustGrant:
    def test_create(self) -> None:
        grant = TrustGrant(
            id="atrust_abc",
            grantor="aid_grantor",
            grantee="aid_grantee",
            capabilities=("read:calendar", "write:email"),
            signature="sig==",
        )
        assert grant.id == "atrust_abc"
        assert len(grant.capabilities) == 2

    def test_defaults(self) -> None:
        grant = TrustGrant(
            id="atrust_x",
            grantor="aid_g1",
            grantee="aid_g2",
            capabilities=("read:*",),
            signature="s",
        )
        assert grant.delegation_allowed is False
        assert grant.max_delegation_depth == 0
        assert grant.not_before is None
        assert grant.not_after is None
        assert grant.max_uses is None

    def test_frozen(self) -> None:
        grant = TrustGrant(
            id="atrust_x",
            grantor="aid_g1",
            grantee="aid_g2",
            capabilities=("read:*",),
            signature="s",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            grant.id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_valid(self) -> None:
        result = VerificationResult(valid=True, actor="aid_a")
        assert result.valid is True
        assert result.actor == "aid_a"

    def test_invalid(self) -> None:
        result = VerificationResult(valid=False, detail="signature mismatch")
        assert result.valid is False
        assert result.detail == "signature mismatch"

    def test_defaults(self) -> None:
        result = VerificationResult(valid=True)
        assert result.actor == ""
        assert result.detail == ""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


class TestParseReceipt:
    def test_full_data(self) -> None:
        data = {
            "id": "arec_test",
            "actor": "aid_actor",
            "actor_key": "pk==",
            "action_type": "Decision",
            "action": {
                "description": "deploy v2",
                "data": {"version": 2},
            },
            "timestamp": 12345,
            "signature": "sig==",
            "receipt_hash": "hash123",
            "previous_receipt": "arec_prev",
        }
        receipt = parse_receipt(data)
        assert receipt.id == "arec_test"
        assert receipt.action_type == "decision"
        assert receipt.description == "deploy v2"
        assert receipt.data == {"version": 2}
        assert receipt.is_chained is True

    def test_minimal_data(self) -> None:
        receipt = parse_receipt({})
        assert receipt.id == ""
        assert receipt.actor == ""
        assert receipt.timestamp == 0
        assert receipt.is_chained is False


class TestParseTrustGrant:
    def test_full_data(self) -> None:
        data = {
            "id": "atrust_test",
            "grantor": "aid_g1",
            "grantee": "aid_g2",
            "capabilities": ["read:*", "write:*"],
            "signature": "sig==",
            "created_at": "2026-01-01",
            "constraints": {
                "not_before": "2026-01-01",
                "not_after": "2026-12-31",
                "max_uses": 100,
            },
            "delegation": {
                "allowed": True,
                "max_depth": 3,
            },
        }
        grant = parse_trust_grant(data)
        assert grant.id == "atrust_test"
        assert grant.capabilities == ("read:*", "write:*")
        assert grant.delegation_allowed is True
        assert grant.max_delegation_depth == 3
        assert grant.max_uses == 100

    def test_minimal_data(self) -> None:
        grant = parse_trust_grant({})
        assert grant.id == ""
        assert grant.capabilities == ()
        assert grant.delegation_allowed is False
