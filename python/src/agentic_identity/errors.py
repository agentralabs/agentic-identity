"""Custom exceptions for the AgenticIdentity SDK.

Hierarchy::

    AidError
    ├── IdentityNotFoundError  — .aid file doesn't exist
    ├── CryptoError            — cryptographic operation failed
    ├── PassphraseError        — wrong passphrase / decryption failed
    ├── LibraryNotFoundError   — native shared library not found
    ├── SerializationError     — JSON serialization/deserialization failed
    └── ValidationError        — invalid input (e.g. empty capability list)
"""

from __future__ import annotations


class AidError(Exception):
    """Base exception for all AgenticIdentity errors."""

    def __init__(self, message: str, code: int = -1) -> None:
        self.code = code
        super().__init__(message)


class IdentityNotFoundError(AidError):
    """The .aid identity file does not exist.

    Raised when loading an identity from a path that doesn't exist.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Identity file not found: {path}", code=-4)


class CryptoError(AidError):
    """A cryptographic operation failed.

    Covers signature verification failures, key derivation errors,
    and invalid key material.
    """

    def __init__(self, detail: str = "Cryptographic operation failed") -> None:
        super().__init__(detail, code=-3)


class PassphraseError(AidError):
    """Wrong passphrase or decryption failed.

    Raised when attempting to load an .aid file with an incorrect
    passphrase.
    """

    def __init__(self, path: str = "") -> None:
        msg = "Wrong passphrase or decryption failed"
        if path:
            msg = f"{msg}: {path}"
        super().__init__(msg, code=-3)


class LibraryNotFoundError(AidError):
    """The native shared library could not be found.

    This means the Rust FFI crate has not been built. Build with::

        cargo build --release -p agentic-identity-ffi
    """

    def __init__(self, searched: list[str] | None = None) -> None:
        self.searched = searched or []
        locations = ", ".join(self.searched) if self.searched else "default paths"
        super().__init__(
            f"Native library not found. Searched: {locations}. "
            "Build with: cargo build --release -p agentic-identity-ffi",
            code=-1,
        )


class SerializationError(AidError):
    """JSON serialization or deserialization failed."""

    def __init__(self, detail: str = "Serialization failed") -> None:
        super().__init__(detail, code=-5)


class ValidationError(AidError):
    """Invalid input to an identity operation.

    Examples: empty capability list, invalid action type,
    null identity handle.
    """
