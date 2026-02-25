"""Low-level ctypes bindings for ``libagentic_identity_ffi``.

This module loads the shared library and declares the C function signatures
exactly as exported by the Rust ``agentic-identity-ffi`` crate.  All memory
management rules documented in the Rust crate apply here:

* Strings returned via ``*mut c_char`` output parameters **must** be freed
  with :func:`aid_free_string`.
* Opaque identity handles returned via ``*mut c_void`` output parameters
  **must** be freed with :func:`aid_identity_free`.
* The pointer returned by :func:`aid_version` is a static string baked into
  the binary and **must not** be freed.

Higher-level, Pythonic wrappers live in :mod:`agentic_identity`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Error codes (mirrored from the Rust FFI crate)
# ---------------------------------------------------------------------------

AID_OK: int = 0
AID_ERR_NULL_PTR: int = -1
AID_ERR_INVALID_UTF8: int = -2
AID_ERR_CRYPTO: int = -3
AID_ERR_IO: int = -4
AID_ERR_SERIALIZATION: int = -5

_ERROR_MESSAGES: dict[int, str] = {
    AID_ERR_NULL_PTR: "A required pointer argument was null",
    AID_ERR_INVALID_UTF8: "A string argument contained invalid UTF-8",
    AID_ERR_CRYPTO: "A cryptographic operation failed",
    AID_ERR_IO: "A filesystem I/O operation failed",
    AID_ERR_SERIALIZATION: "JSON serialization or deserialization failed",
}

# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------


def _lib_filename() -> str:
    """Return the platform-specific shared library filename."""
    system = platform.system()
    if system == "Darwin":
        return "libagentic_identity_ffi.dylib"
    elif system == "Windows":
        return "agentic_identity_ffi.dll"
    else:
        return "libagentic_identity_ffi.so"


def _find_library() -> str:
    """Locate the native shared library.

    Search order:

    1. ``AGENTIC_IDENTITY_LIB`` environment variable (explicit path).
    2. ``../target/release/`` relative to this package (development build).
    3. ``../target/debug/`` relative to this package (development build).
    4. System library search path via :func:`ctypes.util.find_library`.
    """
    # 1. Explicit env var.
    env_path = os.environ.get("AGENTIC_IDENTITY_LIB")
    if env_path and os.path.isfile(env_path):
        return env_path

    lib_name = _lib_filename()

    # 2-3. Relative to the repository root (assumes python/ is a sibling of
    #      target/).
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / lib_name
        if candidate.is_file():
            return str(candidate)

    # 4. System search path.
    found = ctypes.util.find_library("agentic_identity_ffi")
    if found:
        return found

    raise OSError(
        f"Cannot locate {lib_name}. Set the AGENTIC_IDENTITY_LIB environment "
        "variable to the absolute path of the shared library, or build the "
        "Rust crate with `cargo build --release -p agentic-identity-ffi`."
    )


def _load_library() -> ctypes.CDLL:
    """Load the shared library and declare all C function signatures."""
    lib = ctypes.CDLL(_find_library())

    # -- aid_version --------------------------------------------------------
    lib.aid_version.argtypes = []
    lib.aid_version.restype = ctypes.c_char_p

    # -- aid_identity_create ------------------------------------------------
    lib.aid_identity_create.argtypes = [
        ctypes.c_char_p,                        # name (nullable)
        ctypes.c_char_p,                        # passphrase
        ctypes.c_char_p,                        # path
        ctypes.POINTER(ctypes.c_char_p),        # identity_id_out
    ]
    lib.aid_identity_create.restype = ctypes.c_int

    # -- aid_identity_load --------------------------------------------------
    lib.aid_identity_load.argtypes = [
        ctypes.c_char_p,                        # path
        ctypes.c_char_p,                        # passphrase
        ctypes.POINTER(ctypes.c_void_p),        # anchor_out
    ]
    lib.aid_identity_load.restype = ctypes.c_int

    # -- aid_identity_free --------------------------------------------------
    lib.aid_identity_free.argtypes = [ctypes.c_void_p]
    lib.aid_identity_free.restype = None

    # -- aid_identity_get_id ------------------------------------------------
    lib.aid_identity_get_id.argtypes = [
        ctypes.c_void_p,                        # anchor
        ctypes.POINTER(ctypes.c_char_p),        # id_out
    ]
    lib.aid_identity_get_id.restype = ctypes.c_int

    # -- aid_identity_get_public_key ----------------------------------------
    lib.aid_identity_get_public_key.argtypes = [
        ctypes.c_void_p,                        # anchor
        ctypes.POINTER(ctypes.c_char_p),        # pubkey_out
    ]
    lib.aid_identity_get_public_key.restype = ctypes.c_int

    # -- aid_action_sign ----------------------------------------------------
    lib.aid_action_sign.argtypes = [
        ctypes.c_void_p,                        # anchor
        ctypes.c_char_p,                        # action_type
        ctypes.c_char_p,                        # description
        ctypes.c_char_p,                        # data_json (nullable)
        ctypes.POINTER(ctypes.c_char_p),        # receipt_json_out
    ]
    lib.aid_action_sign.restype = ctypes.c_int

    # -- aid_receipt_verify -------------------------------------------------
    lib.aid_receipt_verify.argtypes = [
        ctypes.c_char_p,                        # receipt_json
        ctypes.POINTER(ctypes.c_int),           # is_valid_out
    ]
    lib.aid_receipt_verify.restype = ctypes.c_int

    # -- aid_trust_grant ----------------------------------------------------
    lib.aid_trust_grant.argtypes = [
        ctypes.c_void_p,                        # grantor_anchor
        ctypes.c_char_p,                        # grantee_id
        ctypes.c_char_p,                        # grantee_key
        ctypes.c_char_p,                        # capabilities_json
        ctypes.POINTER(ctypes.c_char_p),        # grant_json_out
    ]
    lib.aid_trust_grant.restype = ctypes.c_int

    # -- aid_trust_verify ---------------------------------------------------
    lib.aid_trust_verify.argtypes = [
        ctypes.c_char_p,                        # grant_json
        ctypes.c_char_p,                        # capability
        ctypes.POINTER(ctypes.c_int),           # is_valid_out
    ]
    lib.aid_trust_verify.restype = ctypes.c_int

    # -- aid_free_string ----------------------------------------------------
    lib.aid_free_string.argtypes = [ctypes.c_char_p]
    lib.aid_free_string.restype = None

    return lib


# Singleton: loaded once on first import.
_lib: ctypes.CDLL = _load_library()


# ---------------------------------------------------------------------------
# Thin helpers used by the public wrapper
# ---------------------------------------------------------------------------


def _check(rc: int) -> None:
    """Raise :class:`AgenticIdentityError` if *rc* is not ``AID_OK``."""
    if rc != AID_OK:
        msg = _ERROR_MESSAGES.get(rc, f"Unknown FFI error code {rc}")
        raise AgenticIdentityError(rc, msg)


def _take_string(ptr: ctypes.c_char_p) -> str:
    """Read a library-owned ``*mut c_char`` as a Python string, then free it.

    The pointer **must** have been allocated by one of the ``aid_*`` functions.
    After this call the pointer is invalid.
    """
    if not ptr:
        raise AgenticIdentityError(AID_ERR_NULL_PTR, "Received null string pointer from FFI")
    value: str = ptr.value.decode("utf-8")  # type: ignore[union-attr]
    _lib.aid_free_string(ptr)
    return value


class AgenticIdentityError(Exception):
    """Exception raised when an FFI call returns a non-zero error code."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(f"[AID error {code}] {message}")
