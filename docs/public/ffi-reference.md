---
status: stable
---

# FFI Reference

AgenticIdentity exposes a C-compatible FFI layer through the `agentic-identity-ffi` crate. This enables integration from any language that supports C function calls (Python ctypes, Node.js ffi-napi, Ruby FFI, Go cgo, etc.).

## Shared Library

Build the shared library:

```bash
cargo build --release -p agentic-identity-ffi
# Output: target/release/libagentic_identity_ffi.{so,dylib,dll}
```

## Error Codes

| Constant | Value | Meaning |
|----------|-------|---------|
| `AID_OK` | 0 | Success |
| `AID_ERR_NULL_PTR` | -1 | A required pointer was null |
| `AID_ERR_INVALID_UTF8` | -2 | A string was not valid UTF-8 |
| `AID_ERR_CRYPTO` | -3 | Cryptographic operation failed |
| `AID_ERR_IO` | -4 | Filesystem I/O failure |
| `AID_ERR_SERIALIZATION` | -5 | JSON serialization/parse failure |

## Memory Contract

- All `*mut c_char` output strings are heap-allocated and **must** be freed by the caller using `aid_free_string()`
- Opaque `*mut c_void` identity anchors are heap-allocated and **must** be freed using `aid_identity_free()`
- The static string returned by `aid_version()` is baked into the binary and must **not** be freed

## Functions

### `aid_version`

Return the library version string.

```c
const char* aid_version(void);
```

**Returns:** Static version string (e.g., `"0.1.0"`). Caller must NOT free.

### `aid_identity_create`

Create a new identity, save it encrypted with a passphrase.

```c
int aid_identity_create(
    const char* name,
    const char* passphrase,
    const char* path,
    char** identity_id_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `const char*` | Human-readable name (NULL for none) |
| `passphrase` | `const char*` | Passphrase to encrypt the identity file |
| `path` | `const char*` | Filesystem path for the `.aid` file |
| `identity_id_out` | `char**` | Receives the identity ID string (caller must free) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_identity_load`

Load an identity anchor from a `.aid` file.

```c
int aid_identity_load(
    const char* path,
    const char* passphrase,
    void** anchor_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `const char*` | Filesystem path of the `.aid` file |
| `passphrase` | `const char*` | Passphrase to decrypt the file |
| `anchor_out` | `void**` | Receives opaque anchor pointer (free with `aid_identity_free`) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_identity_free`

Free an opaque identity anchor.

```c
void aid_identity_free(void* anchor);
```

Passing `NULL` is a safe no-op.

### `aid_identity_get_id`

Retrieve the identity ID string from an opaque anchor.

```c
int aid_identity_get_id(
    const void* anchor,
    char** id_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `anchor` | `const void*` | Opaque anchor from `aid_identity_load` |
| `id_out` | `char**` | Receives the identity ID string (caller must free) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_identity_get_public_key`

Retrieve the base64-encoded Ed25519 public key from an anchor.

```c
int aid_identity_get_public_key(
    const void* anchor,
    char** pubkey_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `anchor` | `const void*` | Opaque anchor from `aid_identity_load` |
| `pubkey_out` | `char**` | Receives the base64 public key (caller must free) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_action_sign`

Sign an action and produce a JSON receipt.

```c
int aid_action_sign(
    const void* anchor,
    const char* action_type,
    const char* description,
    const char* data_json,
    char** receipt_json_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `anchor` | `const void*` | Opaque anchor from `aid_identity_load` |
| `action_type` | `const char*` | One of: `"decision"`, `"observation"`, `"mutation"`, `"delegation"`, `"revocation"`, `"identity_operation"`, or custom |
| `description` | `const char*` | Human-readable description of the action |
| `data_json` | `const char*` | Optional JSON value (NULL to omit) |
| `receipt_json_out` | `char**` | Receives the JSON receipt (caller must free) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_receipt_verify`

Verify the cryptographic signature on a JSON-encoded action receipt.

```c
int aid_receipt_verify(
    const char* receipt_json,
    int* is_valid_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `receipt_json` | `const char*` | JSON string of the receipt |
| `is_valid_out` | `int*` | Receives `1` if valid, `0` if not |

**Returns:** `AID_OK` if verification completed; one of `AID_ERR_*` on internal error.

### `aid_trust_grant`

Create and sign a trust grant from a grantor to a grantee.

```c
int aid_trust_grant(
    const void* grantor_anchor,
    const char* grantee_id,
    const char* grantee_key,
    const char* capabilities_json,
    char** grant_json_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `grantor_anchor` | `const void*` | Opaque anchor of the grantor |
| `grantee_id` | `const char*` | Identity ID of the grantee (e.g., `"aid_..."`) |
| `grantee_key` | `const char*` | Base64-encoded Ed25519 public key of the grantee |
| `capabilities_json` | `const char*` | JSON array of capability URIs (e.g., `["read:calendar"]`) |
| `grant_json_out` | `char**` | Receives the JSON trust grant (caller must free) |

**Returns:** `AID_OK` on success; one of `AID_ERR_*` on failure.

### `aid_trust_verify`

Verify whether a JSON-encoded trust grant covers a specific capability.

```c
int aid_trust_verify(
    const char* grant_json,
    const char* capability,
    int* is_valid_out
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `grant_json` | `const char*` | JSON string of the grant |
| `capability` | `const char*` | Capability URI to check (e.g., `"read:calendar"`) |
| `is_valid_out` | `int*` | Receives `1` if valid, `0` if not |

**Returns:** `AID_OK` if verification ran; one of `AID_ERR_*` on internal error.

### `aid_free_string`

Free a string that was allocated by this library.

```c
void aid_free_string(char* s);
```

Passing `NULL` is a safe no-op. All `*mut c_char` values written by functions in this crate must be freed through this function.

## Example: Python ctypes

```python
import ctypes
import json

lib = ctypes.CDLL("libagentic_identity_ffi.dylib")

# aid_version
lib.aid_version.restype = ctypes.c_char_p
print(lib.aid_version())  # b"0.1.0"

# Create identity
lib.aid_identity_create.restype = ctypes.c_int
lib.aid_identity_create.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p)
]

id_out = ctypes.c_char_p()
rc = lib.aid_identity_create(
    b"my-agent", b"my-passphrase", b"/tmp/test.aid",
    ctypes.byref(id_out)
)
assert rc == 0
print(f"Created: {id_out.value.decode()}")

# Load identity
lib.aid_identity_load.restype = ctypes.c_int
lib.aid_identity_load.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_void_p)
]

anchor = ctypes.c_void_p()
rc = lib.aid_identity_load(
    b"/tmp/test.aid", b"my-passphrase",
    ctypes.byref(anchor)
)
assert rc == 0

# Sign an action
lib.aid_action_sign.restype = ctypes.c_int
receipt_out = ctypes.c_char_p()
rc = lib.aid_action_sign(
    anchor, b"decision", b"Approved release",
    None,  # no data
    ctypes.byref(receipt_out)
)
assert rc == 0
receipt = json.loads(receipt_out.value)
print(f"Receipt ID: {receipt['id']}")

# Clean up
lib.aid_free_string(id_out)
lib.aid_free_string(receipt_out)
lib.aid_identity_free(anchor)
```

## Thread Safety

All FFI functions are thread-safe when called with different anchors. Concurrent access to the same anchor from multiple threads requires external synchronization.
