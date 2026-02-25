"""Tests for the agentic_identity.errors module.

Validates the error hierarchy and attributes.
"""

from __future__ import annotations

import pytest

from agentic_identity.errors import (
    AidError,
    CryptoError,
    IdentityNotFoundError,
    LibraryNotFoundError,
    PassphraseError,
    SerializationError,
    ValidationError,
)


class TestAidError:
    def test_base_error(self) -> None:
        err = AidError("test error")
        assert str(err) == "test error"
        assert err.code == -1

    def test_custom_code(self) -> None:
        err = AidError("fail", code=-42)
        assert err.code == -42

    def test_is_exception(self) -> None:
        assert issubclass(AidError, Exception)


class TestIdentityNotFoundError:
    def test_stores_path(self) -> None:
        err = IdentityNotFoundError("/tmp/agent.aid")
        assert err.path == "/tmp/agent.aid"
        assert "/tmp/agent.aid" in str(err)
        assert err.code == -4

    def test_is_aid_error(self) -> None:
        assert issubclass(IdentityNotFoundError, AidError)


class TestCryptoError:
    def test_default_message(self) -> None:
        err = CryptoError()
        assert "Cryptographic operation failed" in str(err)
        assert err.code == -3

    def test_custom_message(self) -> None:
        err = CryptoError("bad signature")
        assert "bad signature" in str(err)

    def test_is_aid_error(self) -> None:
        assert issubclass(CryptoError, AidError)


class TestPassphraseError:
    def test_without_path(self) -> None:
        err = PassphraseError()
        assert "Wrong passphrase" in str(err)
        assert err.code == -3

    def test_with_path(self) -> None:
        err = PassphraseError("/tmp/agent.aid")
        assert "/tmp/agent.aid" in str(err)

    def test_is_aid_error(self) -> None:
        assert issubclass(PassphraseError, AidError)


class TestLibraryNotFoundError:
    def test_default(self) -> None:
        err = LibraryNotFoundError()
        assert "Native library not found" in str(err)
        assert err.searched == []
        assert err.code == -1

    def test_with_locations(self) -> None:
        err = LibraryNotFoundError(["/usr/lib", "/opt/lib"])
        assert "/usr/lib" in str(err)
        assert "/opt/lib" in str(err)
        assert err.searched == ["/usr/lib", "/opt/lib"]

    def test_is_aid_error(self) -> None:
        assert issubclass(LibraryNotFoundError, AidError)


class TestSerializationError:
    def test_default(self) -> None:
        err = SerializationError()
        assert "Serialization failed" in str(err)
        assert err.code == -5

    def test_custom(self) -> None:
        err = SerializationError("invalid JSON")
        assert "invalid JSON" in str(err)

    def test_is_aid_error(self) -> None:
        assert issubclass(SerializationError, AidError)


class TestValidationError:
    def test_is_aid_error(self) -> None:
        assert issubclass(ValidationError, AidError)

    def test_raise(self) -> None:
        with pytest.raises(AidError):
            raise ValidationError("empty capability list")


class TestHierarchy:
    """All errors should be subclasses of both AidError and Exception."""

    @pytest.mark.parametrize(
        "cls",
        [
            IdentityNotFoundError,
            CryptoError,
            PassphraseError,
            LibraryNotFoundError,
            SerializationError,
            ValidationError,
        ],
    )
    def test_is_subclass_of_aid_error(self, cls: type) -> None:
        assert issubclass(cls, AidError)

    @pytest.mark.parametrize(
        "cls",
        [
            AidError,
            IdentityNotFoundError,
            CryptoError,
            PassphraseError,
            LibraryNotFoundError,
            SerializationError,
            ValidationError,
        ],
    )
    def test_is_subclass_of_exception(self, cls: type) -> None:
        assert issubclass(cls, Exception)
