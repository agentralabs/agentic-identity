"""Typed data models for the AgenticIdentity SDK.

All models are frozen dataclasses — immutable after creation. This
prevents accidental mutation and makes them safe to share across
threads.

Enums use ``str, Enum`` so they serialize naturally to JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ===================================================================
# Enums
# ===================================================================


class ActionType(str, Enum):
    """Type of signed action receipt."""

    DECISION = "decision"
    OBSERVATION = "observation"
    MUTATION = "mutation"
    DELEGATION = "delegation"
    REVOCATION = "revocation"
    IDENTITY_OPERATION = "identity_operation"
    CUSTOM = "custom"


class TrustScope(str, Enum):
    """Well-known capability URI prefixes."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    ALL = "*"


# ===================================================================
# Core Models
# ===================================================================


@dataclass(frozen=True)
class IdentityInfo:
    """Summary information about a loaded identity.

    Attributes:
        identity_id: The identity ID string (e.g. ``"aid_..."``).
        public_key: Base64-encoded Ed25519 public key.
        name: Optional human-readable name.
        created_at: Creation timestamp (ISO 8601 string).
    """

    identity_id: str
    public_key: str
    name: Optional[str] = None
    created_at: str = ""


@dataclass(frozen=True)
class ActionReceipt:
    """A parsed action receipt.

    Attributes:
        id: Receipt ID string (e.g. ``"arec_..."``).
        actor: Actor's identity ID.
        actor_key: Actor's base64 public key.
        action_type: Type of action (decision, observation, etc.).
        description: Human-readable description.
        data: Optional structured data payload.
        timestamp: Unix timestamp of signing.
        signature: Base64-encoded Ed25519 signature.
        previous_receipt: Optional ID of previous receipt in chain.
        receipt_hash: SHA-256 hex hash of the receipt content.
    """

    id: str
    actor: str
    actor_key: str
    action_type: str
    description: str
    timestamp: int
    signature: str
    receipt_hash: str
    data: Optional[dict] = None  # type: ignore[type-arg]
    previous_receipt: Optional[str] = None

    @property
    def is_chained(self) -> bool:
        """Whether this receipt is part of a chain."""
        return self.previous_receipt is not None


@dataclass(frozen=True)
class TrustGrant:
    """A parsed trust grant.

    Attributes:
        id: Grant ID string (e.g. ``"atrust_..."``).
        grantor: Grantor's identity ID.
        grantee: Grantee's identity ID.
        capabilities: Tuple of capability URI strings.
        signature: Base64-encoded Ed25519 signature.
        created_at: Creation timestamp.
        not_before: Optional activation time.
        not_after: Optional expiration time.
        max_uses: Optional maximum use count.
        delegation_allowed: Whether grantee can delegate.
        max_delegation_depth: Maximum delegation chain depth.
    """

    id: str
    grantor: str
    grantee: str
    capabilities: tuple[str, ...]
    signature: str
    created_at: str = ""
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    max_uses: Optional[int] = None
    delegation_allowed: bool = False
    max_delegation_depth: int = 0


@dataclass(frozen=True)
class VerificationResult:
    """Result of a receipt or trust verification.

    Attributes:
        valid: Whether the cryptographic verification succeeded.
        actor: The identity ID that produced the signature.
        detail: Optional human-readable detail.
    """

    valid: bool
    actor: str = ""
    detail: str = ""


# ===================================================================
# Parsing Helpers (internal — used to convert FFI JSON output)
# ===================================================================


def parse_receipt(data: dict) -> ActionReceipt:  # type: ignore[type-arg]
    """Parse a JSON receipt dict into an ActionReceipt."""
    action = data.get("action", {})
    return ActionReceipt(
        id=data.get("id", ""),
        actor=data.get("actor", ""),
        actor_key=data.get("actor_key", ""),
        action_type=data.get("action_type", "custom").lower(),
        description=action.get("description", ""),
        timestamp=data.get("timestamp", 0),
        signature=data.get("signature", ""),
        receipt_hash=data.get("receipt_hash", ""),
        data=action.get("data"),
        previous_receipt=data.get("previous_receipt"),
    )


def parse_trust_grant(data: dict) -> TrustGrant:  # type: ignore[type-arg]
    """Parse a JSON grant dict into a TrustGrant."""
    constraints = data.get("constraints", {})
    delegation = data.get("delegation", {})
    return TrustGrant(
        id=data.get("id", ""),
        grantor=data.get("grantor", ""),
        grantee=data.get("grantee", ""),
        capabilities=tuple(data.get("capabilities", [])),
        signature=data.get("signature", ""),
        created_at=data.get("created_at", ""),
        not_before=constraints.get("not_before"),
        not_after=constraints.get("not_after"),
        max_uses=constraints.get("max_uses"),
        delegation_allowed=delegation.get("allowed", False),
        max_delegation_depth=delegation.get("max_depth", 0),
    )
