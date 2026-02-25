"""Python bindings for the AgenticIdentity cryptographic identity library.

Typical usage::

    from agentic_identity import Identity, version

    print(version())

    # Create a new identity and persist it to disk.
    identity_id = Identity.create(
        path="agent.aid",
        passphrase="strong-passphrase",
        name="my-agent",
    )

    # Load an existing identity from an encrypted ``.aid`` file.
    identity = Identity.load(path="agent.aid", passphrase="strong-passphrase")
    print(identity.identity_id)
    print(identity.public_key)

    # Sign an action and obtain a verifiable receipt.
    receipt_json = identity.sign_action(
        action_type="decision",
        description="Approved deployment to production",
    )

    # Verify a receipt.
    assert Identity.verify_receipt(receipt_json)
"""

from __future__ import annotations

import ctypes
import json
from typing import Any, Optional

from ._ffi import (
    AID_OK,
    AgenticIdentityError,
    _check,
    _lib,
    _take_string,
)
from .errors import (
    AidError,
    CryptoError,
    IdentityNotFoundError,
    LibraryNotFoundError,
    PassphraseError,
    SerializationError,
    ValidationError,
)
from .models import (
    ActionReceipt,
    ActionType,
    IdentityInfo,
    TrustGrant,
    TrustScope,
    VerificationResult,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Core class
    "Identity",
    # Module-level functions
    "verify_receipt",
    "verify_trust_grant",
    "version",
    # Error types (legacy)
    "AgenticIdentityError",
    # Error hierarchy
    "AidError",
    "CryptoError",
    "IdentityNotFoundError",
    "LibraryNotFoundError",
    "PassphraseError",
    "SerializationError",
    "ValidationError",
    # Models
    "ActionReceipt",
    "ActionType",
    "IdentityInfo",
    "TrustGrant",
    "TrustScope",
    "VerificationResult",
]


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def version() -> str:
    """Return the library version string (e.g. ``"0.1.0"``)."""
    raw = _lib.aid_version()
    if not raw:
        raise AgenticIdentityError(-1, "aid_version returned null")
    # aid_version returns a static pointer -- do NOT free it.
    return raw.decode("utf-8")


def verify_receipt(receipt_json: str) -> bool:
    """Verify the cryptographic signature on a JSON-encoded action receipt.

    Parameters
    ----------
    receipt_json:
        The JSON string of the receipt as produced by
        :meth:`Identity.sign_action`.

    Returns
    -------
    bool
        ``True`` if the receipt signature is valid, ``False`` otherwise.

    Raises
    ------
    AgenticIdentityError
        If an internal error prevented verification from running (e.g. the
        JSON could not be parsed).
    """
    is_valid = ctypes.c_int(0)
    rc = _lib.aid_receipt_verify(
        receipt_json.encode("utf-8"),
        ctypes.byref(is_valid),
    )
    _check(rc)
    return is_valid.value == 1


def verify_trust_grant(grant_json: str, capability: str) -> bool:
    """Verify whether a JSON-encoded trust grant covers a specific capability.

    Checks the grant's cryptographic signature, time validity, use count,
    and capability match.

    Parameters
    ----------
    grant_json:
        The JSON string of the grant as produced by
        :meth:`Identity.create_trust_grant`.
    capability:
        Capability URI string to check (e.g. ``"read:calendar"``).

    Returns
    -------
    bool
        ``True`` if the grant is valid for the requested capability.

    Raises
    ------
    AgenticIdentityError
        If an internal error prevented verification from running.
    """
    is_valid = ctypes.c_int(0)
    rc = _lib.aid_trust_verify(
        grant_json.encode("utf-8"),
        capability.encode("utf-8"),
        ctypes.byref(is_valid),
    )
    _check(rc)
    return is_valid.value == 1


# ---------------------------------------------------------------------------
# Identity wrapper
# ---------------------------------------------------------------------------


class Identity:
    """Handle to a loaded AgenticIdentity anchor.

    Wraps an opaque pointer to the Rust ``IdentityAnchor`` struct.  The
    underlying native memory is freed automatically when this object is
    garbage-collected or when :meth:`close` is called.

    Do **not** instantiate this class directly -- use :meth:`load` instead.
    """

    def __init__(self, handle: ctypes.c_void_p) -> None:
        if not handle:
            raise AgenticIdentityError(-1, "Cannot create Identity with a null handle")
        self._handle: ctypes.c_void_p | None = handle

    # -- lifecycle ----------------------------------------------------------

    @staticmethod
    def create(
        path: str,
        passphrase: str,
        name: str | None = None,
    ) -> str:
        """Create a new identity, encrypt it, and write it to *path*.

        Parameters
        ----------
        path:
            Filesystem path for the ``.aid`` file.
        passphrase:
            Passphrase used to encrypt the identity file.
        name:
            Optional human-readable name for the identity.

        Returns
        -------
        str
            The identity ID string (e.g. ``"aid_..."``).

        Raises
        ------
        AgenticIdentityError
            If identity creation or file I/O fails.
        """
        id_out = ctypes.c_char_p()
        rc = _lib.aid_identity_create(
            name.encode("utf-8") if name else None,
            passphrase.encode("utf-8"),
            path.encode("utf-8"),
            ctypes.byref(id_out),
        )
        _check(rc)
        return _take_string(id_out)

    @classmethod
    def load(cls, path: str, passphrase: str) -> Identity:
        """Load an identity from an encrypted ``.aid`` file.

        Parameters
        ----------
        path:
            Filesystem path to the ``.aid`` file.
        passphrase:
            Passphrase to decrypt the file.

        Returns
        -------
        Identity
            A handle to the loaded identity.

        Raises
        ------
        AgenticIdentityError
            If loading or decryption fails.
        """
        anchor_out = ctypes.c_void_p()
        rc = _lib.aid_identity_load(
            path.encode("utf-8"),
            passphrase.encode("utf-8"),
            ctypes.byref(anchor_out),
        )
        _check(rc)
        return cls(anchor_out)

    def close(self) -> None:
        """Release the underlying native identity handle.

        Safe to call multiple times.  After calling this method, all other
        methods on this object will raise :class:`AgenticIdentityError`.
        """
        if self._handle is not None:
            _lib.aid_identity_free(self._handle)
            self._handle = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> Identity:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _require_handle(self) -> ctypes.c_void_p:
        if self._handle is None:
            raise AgenticIdentityError(-1, "Identity handle has been closed")
        return self._handle

    # -- properties ---------------------------------------------------------

    @property
    def identity_id(self) -> str:
        """The identity ID string (e.g. ``"aid_..."``).

        The returned string is a fresh copy each time -- the native memory
        is freed immediately after reading.
        """
        handle = self._require_handle()
        id_out = ctypes.c_char_p()
        rc = _lib.aid_identity_get_id(handle, ctypes.byref(id_out))
        _check(rc)
        return _take_string(id_out)

    @property
    def public_key(self) -> str:
        """The base64-encoded Ed25519 public key."""
        handle = self._require_handle()
        pk_out = ctypes.c_char_p()
        rc = _lib.aid_identity_get_public_key(handle, ctypes.byref(pk_out))
        _check(rc)
        return _take_string(pk_out)

    # -- action signing -----------------------------------------------------

    def sign_action(
        self,
        action_type: str,
        description: str,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Sign an action and produce a JSON receipt.

        Parameters
        ----------
        action_type:
            One of ``"decision"``, ``"observation"``, ``"mutation"``,
            ``"delegation"``, ``"revocation"``,
            ``"identity_operation"``, or any custom string.
        description:
            Human-readable description of the action.
        data:
            Optional structured data to attach to the receipt.

        Returns
        -------
        str
            The JSON-serialised action receipt.

        Raises
        ------
        AgenticIdentityError
            If signing fails.
        """
        handle = self._require_handle()
        data_json: bytes | None = None
        if data is not None:
            data_json = json.dumps(data).encode("utf-8")

        receipt_out = ctypes.c_char_p()
        rc = _lib.aid_action_sign(
            handle,
            action_type.encode("utf-8"),
            description.encode("utf-8"),
            data_json,
            ctypes.byref(receipt_out),
        )
        _check(rc)
        return _take_string(receipt_out)

    # -- trust grants -------------------------------------------------------

    def create_trust_grant(
        self,
        grantee_id: str,
        grantee_key: str,
        capabilities: list[str],
    ) -> str:
        """Create and sign a trust grant from this identity to a grantee.

        Parameters
        ----------
        grantee_id:
            Identity ID string of the grantee (e.g. ``"aid_..."``).
        grantee_key:
            Base64-encoded Ed25519 public key of the grantee.
        capabilities:
            List of capability URI strings (e.g.
            ``["read:calendar", "write:email"]``).

        Returns
        -------
        str
            The JSON-serialised trust grant.

        Raises
        ------
        AgenticIdentityError
            If grant creation or signing fails.
        """
        handle = self._require_handle()
        caps_json = json.dumps(capabilities).encode("utf-8")
        grant_out = ctypes.c_char_p()
        rc = _lib.aid_trust_grant(
            handle,
            grantee_id.encode("utf-8"),
            grantee_key.encode("utf-8"),
            caps_json,
            ctypes.byref(grant_out),
        )
        _check(rc)
        return _take_string(grant_out)

    # -- repr ---------------------------------------------------------------

    def __repr__(self) -> str:
        if self._handle is None:
            return "Identity(<closed>)"
        try:
            return f"Identity(id={self.identity_id!r})"
        except AgenticIdentityError:
            return "Identity(<error reading id>)"
