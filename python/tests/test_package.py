"""Tests for package-level imports and metadata.

These tests verify that the public API surface is correctly exported
and that the package metadata (version, __all__) is valid.
"""

from __future__ import annotations


class TestImports:
    def test_import_package(self) -> None:
        import agentic_identity

        assert hasattr(agentic_identity, "__version__")

    def test_version_is_semver(self) -> None:
        from agentic_identity import __version__

        parts = __version__.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_identity_importable(self) -> None:
        from agentic_identity import Identity

        assert Identity is not None

    def test_action_type_importable(self) -> None:
        from agentic_identity import ActionType

        assert ActionType.DECISION == "decision"

    def test_aid_error_importable(self) -> None:
        from agentic_identity import AidError

        assert issubclass(AidError, Exception)

    def test_trust_scope_importable(self) -> None:
        from agentic_identity import TrustScope

        assert TrustScope.READ == "read"

    def test_models_importable(self) -> None:
        from agentic_identity import (
            ActionReceipt,
            IdentityInfo,
            TrustGrant,
            VerificationResult,
        )

        assert ActionReceipt is not None
        assert IdentityInfo is not None
        assert TrustGrant is not None
        assert VerificationResult is not None

    def test_errors_importable(self) -> None:
        from agentic_identity import (
            AidError,
            CryptoError,
            IdentityNotFoundError,
            LibraryNotFoundError,
            PassphraseError,
            SerializationError,
            ValidationError,
        )

        assert AidError is not None
        assert CryptoError is not None
        assert IdentityNotFoundError is not None

    def test_legacy_error_importable(self) -> None:
        from agentic_identity import AgenticIdentityError

        assert issubclass(AgenticIdentityError, Exception)


class TestAll:
    def test_all_items_are_importable(self) -> None:
        import agentic_identity

        for name in agentic_identity.__all__:
            assert hasattr(agentic_identity, name), f"{name} in __all__ but not importable"

    def test_all_is_nonempty(self) -> None:
        import agentic_identity

        assert len(agentic_identity.__all__) > 10
