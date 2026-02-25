//! AgenticIdentity C FFI bindings.
//!
//! Provides a C-compatible API for the core AgenticIdentity operations:
//! identity management, action signing, receipt verification, and trust grants.
//!
#![allow(clippy::doc_overindented_list_items)]
//! # Memory contract
//!
//! - All `*mut c_char` output strings are heap-allocated via [`CString`] and
//!   **must** be freed by the caller using [`aid_free_string`].
//! - Opaque `*mut c_void` identity anchors are heap-allocated Rust `Box`es and
//!   **must** be freed using [`aid_identity_free`].
//! - The static string returned by [`aid_version`] is a `'static` Rust `&str`
//!   baked into the binary; it must **not** be freed.
//!
//! # Error codes
//!
//! | Constant              | Value | Meaning                          |
//! |-----------------------|-------|----------------------------------|
//! | `AID_OK`              | 0     | Success                          |
//! | `AID_ERR_NULL_PTR`    | -1    | A required pointer was null      |
//! | `AID_ERR_INVALID_UTF8`| -2    | A string was not valid UTF-8     |
//! | `AID_ERR_CRYPTO`      | -3    | Cryptographic operation failed   |
//! | `AID_ERR_IO`          | -4    | Filesystem I/O failure           |
//! | `AID_ERR_SERIALIZATION` | -5  | JSON serialization/parse failure |

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

use agentic_identity::{
    error::IdentityError,
    receipt::{receipt::ReceiptBuilder, verify::verify_receipt},
    storage::{load_identity, save_identity},
    trust::{verify::verify_trust_grant, Capability, TrustGrantBuilder},
    ActionContent, ActionType, IdentityAnchor,
};

// ── Error codes ───────────────────────────────────────────────────────────────

/// Success.
pub const AID_OK: i32 = 0;
/// A required pointer argument was null.
pub const AID_ERR_NULL_PTR: i32 = -1;
/// A string argument contained invalid UTF-8.
pub const AID_ERR_INVALID_UTF8: i32 = -2;
/// A cryptographic operation failed (key derivation, signing, encryption, …).
pub const AID_ERR_CRYPTO: i32 = -3;
/// A filesystem I/O operation failed.
pub const AID_ERR_IO: i32 = -4;
/// A JSON serialization or deserialization operation failed.
pub const AID_ERR_SERIALIZATION: i32 = -5;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Convert a `*const c_char` to a `&str`, returning an error code on failure.
///
/// # Safety
///
/// `ptr` must either be null (handled gracefully) or point to a valid,
/// null-terminated C string that remains valid for the duration of `'a`.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(AID_ERR_NULL_PTR);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| AID_ERR_INVALID_UTF8)
}

/// Allocate a `CString` and write it into `*out`, returning an error code on
/// failure.
///
/// # Safety
///
/// `out` must be non-null.
unsafe fn write_string_out(s: String, out: *mut *mut c_char) -> i32 {
    if out.is_null() {
        return AID_ERR_NULL_PTR;
    }
    match CString::new(s) {
        Ok(cs) => {
            *out = cs.into_raw();
            AID_OK
        }
        Err(_) => AID_ERR_SERIALIZATION,
    }
}

/// Map an [`IdentityError`] to one of the `AID_ERR_*` constants.
fn map_error(e: &IdentityError) -> i32 {
    match e {
        IdentityError::Io(_) => AID_ERR_IO,
        IdentityError::SerializationError(_) | IdentityError::InvalidFileFormat(_) => {
            AID_ERR_SERIALIZATION
        }
        IdentityError::InvalidKey(_)
        | IdentityError::SignatureInvalid
        | IdentityError::DerivationFailed(_)
        | IdentityError::EncryptionFailed(_)
        | IdentityError::DecryptionFailed(_)
        | IdentityError::InvalidPassphrase => AID_ERR_CRYPTO,
        _ => AID_ERR_CRYPTO,
    }
}

// ── Version ───────────────────────────────────────────────────────────────────

/// Return the library version string as a null-terminated C string.
///
/// The returned pointer points to a `'static` Rust string literal embedded in
/// the binary.  The caller **must not** free this pointer.
///
/// # Safety
///
/// Always safe to call.
#[no_mangle]
pub extern "C" fn aid_version() -> *const c_char {
    // SAFETY: the literal contains no interior nul bytes and has static lifetime.
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// ── Identity management ───────────────────────────────────────────────────────

/// Create a new identity, save it to `path` encrypted with `passphrase`, and
/// write the identity ID string into `*identity_id_out`.
///
/// # Parameters
///
/// - `name`             — optional human-readable name; pass `NULL` for none.
/// - `passphrase`       — passphrase used to encrypt the identity file.
/// - `path`             — filesystem path for the `.aid` file.
/// - `identity_id_out`  — on success, receives an owned `*mut c_char` that the
///                        caller must free with [`aid_free_string`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// All pointer arguments (except `name`) must be non-null, valid C strings.
#[no_mangle]
pub unsafe extern "C" fn aid_identity_create(
    name: *const c_char,
    passphrase: *const c_char,
    path: *const c_char,
    identity_id_out: *mut *mut c_char,
) -> i32 {
    // `name` is nullable — treat null as "no name".
    let opt_name: Option<String> = if name.is_null() {
        None
    } else {
        match cstr_to_str(name) {
            Ok(s) => Some(s.to_owned()),
            Err(e) => return e,
        }
    };

    let passphrase_str = match cstr_to_str(passphrase) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let path_str = match cstr_to_str(path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if identity_id_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let anchor = IdentityAnchor::new(opt_name);
    let id_string = anchor.id().0.clone();

    match save_identity(&anchor, Path::new(path_str), passphrase_str) {
        Ok(()) => write_string_out(id_string, identity_id_out),
        Err(e) => map_error(&e),
    }
}

/// Load an identity anchor from a `.aid` file, returning an opaque pointer.
///
/// # Parameters
///
/// - `path`       — filesystem path of the `.aid` file.
/// - `passphrase` — passphrase to decrypt the file.
/// - `anchor_out` — on success, receives an opaque `*mut c_void` that wraps a
///                  heap-allocated [`IdentityAnchor`].  The caller is
///                  responsible for releasing this with [`aid_identity_free`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// `path`, `passphrase`, and `anchor_out` must all be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_identity_load(
    path: *const c_char,
    passphrase: *const c_char,
    anchor_out: *mut *mut std::ffi::c_void,
) -> i32 {
    let path_str = match cstr_to_str(path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let passphrase_str = match cstr_to_str(passphrase) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if anchor_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    match load_identity(Path::new(path_str), passphrase_str) {
        Ok(anchor) => {
            *anchor_out = Box::into_raw(Box::new(anchor)) as *mut std::ffi::c_void;
            AID_OK
        }
        Err(e) => map_error(&e),
    }
}

/// Free an opaque identity anchor previously returned by [`aid_identity_load`].
///
/// Passing `NULL` is a no-op.
///
/// # Safety
///
/// `anchor` must be either null or a pointer returned by [`aid_identity_load`]
/// that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn aid_identity_free(anchor: *mut std::ffi::c_void) {
    if !anchor.is_null() {
        drop(Box::from_raw(anchor as *mut IdentityAnchor));
    }
}

/// Retrieve the identity ID string from an opaque anchor.
///
/// # Parameters
///
/// - `anchor`  — opaque anchor from [`aid_identity_load`].
/// - `id_out`  — on success, receives an owned `*mut c_char` that the caller
///               must free with [`aid_free_string`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// `anchor` and `id_out` must both be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_identity_get_id(
    anchor: *const std::ffi::c_void,
    id_out: *mut *mut c_char,
) -> i32 {
    if anchor.is_null() {
        return AID_ERR_NULL_PTR;
    }
    if id_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let anchor_ref = &*(anchor as *const IdentityAnchor);
    write_string_out(anchor_ref.id().0.clone(), id_out)
}

/// Retrieve the base64-encoded public key from an opaque anchor.
///
/// # Parameters
///
/// - `anchor`     — opaque anchor from [`aid_identity_load`].
/// - `pubkey_out` — on success, receives an owned `*mut c_char` that the
///                  caller must free with [`aid_free_string`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// `anchor` and `pubkey_out` must both be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_identity_get_public_key(
    anchor: *const std::ffi::c_void,
    pubkey_out: *mut *mut c_char,
) -> i32 {
    if anchor.is_null() {
        return AID_ERR_NULL_PTR;
    }
    if pubkey_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let anchor_ref = &*(anchor as *const IdentityAnchor);
    write_string_out(anchor_ref.public_key_base64(), pubkey_out)
}

// ── Action receipts ───────────────────────────────────────────────────────────

/// Sign an action and produce a JSON receipt.
///
/// # Parameters
///
/// - `anchor`           — opaque anchor from [`aid_identity_load`].
/// - `action_type`      — one of: `"decision"`, `"observation"`, `"mutation"`,
///                        `"delegation"`, `"revocation"`,
///                        `"identity_operation"`, or any custom string.
/// - `description`      — human-readable description of the action.
/// - `data_json`        — optional JSON value attached to the receipt; pass
///                        `NULL` to omit.
/// - `receipt_json_out` — on success, receives the JSON-serialised receipt as
///                        an owned `*mut c_char`.  Must be freed with
///                        [`aid_free_string`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// `anchor`, `action_type`, `description`, and `receipt_json_out` must be
/// non-null.  `data_json` may be null.
#[no_mangle]
pub unsafe extern "C" fn aid_action_sign(
    anchor: *const std::ffi::c_void,
    action_type: *const c_char,
    description: *const c_char,
    data_json: *const c_char, // nullable
    receipt_json_out: *mut *mut c_char,
) -> i32 {
    if anchor.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let action_type_str = match cstr_to_str(action_type) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let description_str = match cstr_to_str(description) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if receipt_json_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let anchor_ref = &*(anchor as *const IdentityAnchor);

    // Parse the action type.
    let atype = match action_type_str {
        "decision" => ActionType::Decision,
        "observation" => ActionType::Observation,
        "mutation" => ActionType::Mutation,
        "delegation" => ActionType::Delegation,
        "revocation" => ActionType::Revocation,
        "identity_operation" => ActionType::IdentityOperation,
        other => ActionType::Custom(other.to_owned()),
    };

    // Build action content, optionally with structured JSON data.
    let content = if data_json.is_null() {
        ActionContent::new(description_str)
    } else {
        let data_str = match cstr_to_str(data_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match serde_json::from_str::<serde_json::Value>(data_str) {
            Ok(value) => ActionContent::with_data(description_str, value),
            Err(_) => return AID_ERR_SERIALIZATION,
        }
    };

    let receipt =
        match ReceiptBuilder::new(anchor_ref.id(), atype, content).sign(anchor_ref.signing_key()) {
            Ok(r) => r,
            Err(e) => return map_error(&e),
        };

    let json = match serde_json::to_string(&receipt) {
        Ok(j) => j,
        Err(_) => return AID_ERR_SERIALIZATION,
    };

    write_string_out(json, receipt_json_out)
}

// ── Receipt verification ──────────────────────────────────────────────────────

/// Verify the cryptographic signature on a JSON-encoded action receipt.
///
/// # Parameters
///
/// - `receipt_json`  — JSON string of the receipt (as produced by
///                     [`aid_action_sign`]).
/// - `is_valid_out`  — on success, receives `1` if the receipt is valid or `0`
///                     if it is not.
///
/// # Returns
///
/// `AID_OK` if verification completed without internal errors (the result is
/// then in `*is_valid_out`); one of `AID_ERR_*` if an error prevented
/// verification from running.
///
/// # Safety
///
/// `receipt_json` and `is_valid_out` must both be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_receipt_verify(
    receipt_json: *const c_char,
    is_valid_out: *mut libc::c_int,
) -> i32 {
    let json_str = match cstr_to_str(receipt_json) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if is_valid_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let receipt: agentic_identity::ActionReceipt = match serde_json::from_str(json_str) {
        Ok(r) => r,
        Err(_) => return AID_ERR_SERIALIZATION,
    };

    match verify_receipt(&receipt) {
        Ok(v) => {
            *is_valid_out = if v.is_valid { 1 } else { 0 };
            AID_OK
        }
        Err(e) => map_error(&e),
    }
}

// ── Trust grants ──────────────────────────────────────────────────────────────

/// Create and sign a trust grant from `grantor_anchor` to a grantee.
///
/// # Parameters
///
/// - `grantor_anchor`   — opaque anchor from [`aid_identity_load`] (the party
///                        granting trust).
/// - `grantee_id`       — identity ID string of the grantee (e.g.
///                        `"aid_…"`).
/// - `grantee_key`      — base64-encoded Ed25519 public key of the grantee.
/// - `capabilities_json`— JSON array of capability URI strings, e.g.
///                        `["read:calendar","write:email"]`.
/// - `grant_json_out`   — on success, receives the JSON-serialised
///                        [`TrustGrant`] as an owned `*mut c_char`.  Must be
///                        freed with [`aid_free_string`].
///
/// # Returns
///
/// `AID_OK` on success; one of `AID_ERR_*` on failure.
///
/// # Safety
///
/// All pointer arguments must be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_trust_grant(
    grantor_anchor: *const std::ffi::c_void,
    grantee_id: *const c_char,
    grantee_key: *const c_char,
    capabilities_json: *const c_char,
    grant_json_out: *mut *mut c_char,
) -> i32 {
    if grantor_anchor.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let grantee_id_str = match cstr_to_str(grantee_id) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let grantee_key_str = match cstr_to_str(grantee_key) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let capabilities_str = match cstr_to_str(capabilities_json) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if grant_json_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let anchor_ref = &*(grantor_anchor as *const IdentityAnchor);

    // Parse capabilities JSON array of URI strings.
    let cap_uris: Vec<String> = match serde_json::from_str(capabilities_str) {
        Ok(v) => v,
        Err(_) => return AID_ERR_SERIALIZATION,
    };

    if cap_uris.is_empty() {
        return AID_ERR_SERIALIZATION;
    }

    let capabilities: Vec<Capability> = cap_uris.into_iter().map(Capability::new).collect();

    let grantee_identity_id = agentic_identity::IdentityId(grantee_id_str.to_owned());

    let grant = match TrustGrantBuilder::new(
        anchor_ref.id(),
        grantee_identity_id,
        grantee_key_str.to_owned(),
    )
    .capabilities(capabilities)
    .sign(anchor_ref.signing_key())
    {
        Ok(g) => g,
        Err(e) => return map_error(&e),
    };

    let json = match serde_json::to_string(&grant) {
        Ok(j) => j,
        Err(_) => return AID_ERR_SERIALIZATION,
    };

    write_string_out(json, grant_json_out)
}

// ── Trust verification ────────────────────────────────────────────────────────

/// Verify whether a JSON-encoded trust grant covers a specific capability.
///
/// This checks the grant's cryptographic signature, time validity, use count,
/// and capability match.  Revocation is checked against an empty revocation
/// list (no persistence layer is consulted).
///
/// # Parameters
///
/// - `grant_json`   — JSON string of the grant (as produced by
///                    [`aid_trust_grant`]).
/// - `capability`   — capability URI string to check (e.g. `"read:calendar"`).
/// - `is_valid_out` — on success, receives `1` if the grant is valid for the
///                    requested capability, or `0` otherwise.
///
/// # Returns
///
/// `AID_OK` if verification ran (result in `*is_valid_out`); one of
/// `AID_ERR_*` on internal error.
///
/// # Safety
///
/// `grant_json`, `capability`, and `is_valid_out` must all be non-null.
#[no_mangle]
pub unsafe extern "C" fn aid_trust_verify(
    grant_json: *const c_char,
    capability: *const c_char,
    is_valid_out: *mut libc::c_int,
) -> i32 {
    let json_str = match cstr_to_str(grant_json) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let capability_str = match cstr_to_str(capability) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if is_valid_out.is_null() {
        return AID_ERR_NULL_PTR;
    }

    let grant: agentic_identity::TrustGrant = match serde_json::from_str(json_str) {
        Ok(g) => g,
        Err(_) => return AID_ERR_SERIALIZATION,
    };

    match verify_trust_grant(&grant, capability_str, 0, &[]) {
        Ok(v) => {
            *is_valid_out = if v.is_valid { 1 } else { 0 };
            AID_OK
        }
        Err(e) => map_error(&e),
    }
}

// ── String cleanup ────────────────────────────────────────────────────────────

/// Free a string that was allocated by this library.
///
/// All `*mut c_char` values written by functions in this crate (e.g.,
/// `identity_id_out`, `receipt_json_out`, …) must be freed through this
/// function.  Passing `NULL` is a no-op.
///
/// # Safety
///
/// `s` must be either null or a pointer that was returned by one of the
/// `aid_*` functions in this crate and that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn aid_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn cstring(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Read a library-owned `*mut c_char` as a Rust `String`, then free it.
    unsafe fn take_string(ptr: *mut c_char) -> String {
        let s = CStr::from_ptr(ptr).to_str().unwrap().to_owned();
        aid_free_string(ptr);
        s
    }

    // ── version ───────────────────────────────────────────────────────────────

    #[test]
    fn test_version() {
        let v = aid_version();
        assert!(!v.is_null());
        let s = unsafe { CStr::from_ptr(v) }.to_str().unwrap();
        assert_eq!(s, "0.1.0");
    }

    // ── create & load ─────────────────────────────────────────────────────────

    #[test]
    fn test_create_and_load_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.aid");
        let path_cstr = cstring(path.to_str().unwrap());
        let name_cstr = cstring("ffi-test-agent");
        let pass_cstr = cstring("correct-horse-battery-staple");

        // Create the identity.
        let mut id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_create(
                name_cstr.as_ptr(),
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                &mut id_out,
            )
        };
        assert_eq!(rc, AID_OK, "aid_identity_create should succeed");
        assert!(!id_out.is_null());

        let created_id = unsafe { take_string(id_out) };
        assert!(created_id.starts_with("aid_"), "ID must start with aid_");

        // Load the identity back.
        let mut anchor_out: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc =
            unsafe { aid_identity_load(path_cstr.as_ptr(), pass_cstr.as_ptr(), &mut anchor_out) };
        assert_eq!(rc, AID_OK, "aid_identity_load should succeed");
        assert!(!anchor_out.is_null());

        // Verify the ID matches what was stored.
        let mut loaded_id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { aid_identity_get_id(anchor_out as *const _, &mut loaded_id_out) };
        assert_eq!(rc, AID_OK, "aid_identity_get_id should succeed");
        let loaded_id = unsafe { take_string(loaded_id_out) };
        assert_eq!(
            created_id, loaded_id,
            "identity ID must round-trip through save/load"
        );

        // Public key should be non-empty base64.
        let mut pk_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { aid_identity_get_public_key(anchor_out as *const _, &mut pk_out) };
        assert_eq!(rc, AID_OK, "aid_identity_get_public_key should succeed");
        let pk = unsafe { take_string(pk_out) };
        assert!(!pk.is_empty(), "public key must not be empty");

        unsafe { aid_identity_free(anchor_out) };
    }

    #[test]
    fn test_create_identity_null_name() {
        // NULL name should be accepted (interpreted as "no name").
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-name.aid");
        let path_cstr = cstring(path.to_str().unwrap());
        let pass_cstr = cstring("passphrase");

        let mut id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(), // name = NULL
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                &mut id_out,
            )
        };
        assert_eq!(rc, AID_OK, "null name should be accepted");
        unsafe { aid_free_string(id_out) };
    }

    // ── action sign ───────────────────────────────────────────────────────────

    #[test]
    fn test_action_sign() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sign-test.aid");
        let path_cstr = cstring(path.to_str().unwrap());
        let pass_cstr = cstring("sign-test-passphrase");

        // Create & load.
        let mut _id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(),
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                &mut _id_out,
            )
        };
        assert_eq!(rc, AID_OK);
        unsafe { aid_free_string(_id_out) };

        let mut anchor_out: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc =
            unsafe { aid_identity_load(path_cstr.as_ptr(), pass_cstr.as_ptr(), &mut anchor_out) };
        assert_eq!(rc, AID_OK);

        // Sign a decision action without extra data.
        let action_type_cstr = cstring("decision");
        let description_cstr = cstring("Approved deployment to production");
        let mut receipt_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_action_sign(
                anchor_out as *const _,
                action_type_cstr.as_ptr(),
                description_cstr.as_ptr(),
                std::ptr::null(), // data_json = NULL
                &mut receipt_out,
            )
        };
        assert_eq!(rc, AID_OK, "aid_action_sign should succeed");
        assert!(!receipt_out.is_null());

        let receipt_json = unsafe { take_string(receipt_out) };

        // The receipt JSON must be parseable and contain the expected fields.
        let parsed: serde_json::Value =
            serde_json::from_str(&receipt_json).expect("receipt must be valid JSON");
        assert!(
            parsed["id"].as_str().unwrap_or("").starts_with("arec_"),
            "receipt id must start with arec_"
        );
        assert!(!parsed["signature"].as_str().unwrap_or("").is_empty());

        // Sign a mutation action WITH JSON data.
        let data_cstr = cstring(r#"{"key":"retries","value":5}"#);
        let action_type_cstr2 = cstring("mutation");
        let desc_cstr2 = cstring("Updated config");
        let mut receipt_out2: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_action_sign(
                anchor_out as *const _,
                action_type_cstr2.as_ptr(),
                desc_cstr2.as_ptr(),
                data_cstr.as_ptr(),
                &mut receipt_out2,
            )
        };
        assert_eq!(rc, AID_OK, "aid_action_sign with data should succeed");
        unsafe { aid_free_string(receipt_out2) };

        // Sign a custom action type.
        let custom_type_cstr = cstring("audit");
        let custom_desc_cstr = cstring("Audit event recorded");
        let mut receipt_out3: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_action_sign(
                anchor_out as *const _,
                custom_type_cstr.as_ptr(),
                custom_desc_cstr.as_ptr(),
                std::ptr::null(),
                &mut receipt_out3,
            )
        };
        assert_eq!(rc, AID_OK, "custom action type should be accepted");
        unsafe { aid_free_string(receipt_out3) };

        unsafe { aid_identity_free(anchor_out) };
    }

    // ── receipt verify ────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-test.aid");
        let path_cstr = cstring(path.to_str().unwrap());
        let pass_cstr = cstring("verify-passphrase");

        let mut _id_out: *mut c_char = std::ptr::null_mut();
        unsafe {
            aid_identity_create(
                std::ptr::null(),
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                &mut _id_out,
            );
            aid_free_string(_id_out);
        }

        let mut anchor_out: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            aid_identity_load(path_cstr.as_ptr(), pass_cstr.as_ptr(), &mut anchor_out);
        }

        // Sign an action to get a receipt.
        let action_type_cstr = cstring("observation");
        let desc_cstr = cstring("Observed high memory usage");
        let mut receipt_out: *mut c_char = std::ptr::null_mut();
        unsafe {
            aid_action_sign(
                anchor_out as *const _,
                action_type_cstr.as_ptr(),
                desc_cstr.as_ptr(),
                std::ptr::null(),
                &mut receipt_out,
            );
        }
        assert!(!receipt_out.is_null());

        // Verify the valid receipt.
        let receipt_cstr = unsafe { CString::from_raw(receipt_out) }; // take ownership for inspection
        let mut is_valid: libc::c_int = 0;
        let rc = unsafe { aid_receipt_verify(receipt_cstr.as_ptr(), &mut is_valid) };
        // Re-leak so drop doesn't double-free (aid_free_string is not called here
        // since we already took ownership via from_raw; we just let it drop normally).
        assert_eq!(rc, AID_OK, "aid_receipt_verify should succeed");
        assert_eq!(is_valid, 1, "freshly-signed receipt must be valid");

        // Tamper with the receipt and verify it is rejected.
        let tampered = r#"{"id":"arec_tampered","actor":"aid_fake","actor_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","action_type":"Decision","action":{"description":"fake","data":null,"references":[]},"timestamp":1,"context_hash":null,"previous_receipt":null,"receipt_hash":"0000000000000000000000000000000000000000000000000000000000000000","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","witnesses":[]}"#;
        let tampered_cstr = cstring(tampered);
        let mut is_valid2: libc::c_int = 1;
        let rc2 = unsafe { aid_receipt_verify(tampered_cstr.as_ptr(), &mut is_valid2) };
        // Either returns an error code OR sets is_valid to 0.
        assert!(
            rc2 != AID_OK || is_valid2 == 0,
            "tampered receipt must not verify as valid"
        );

        unsafe { aid_identity_free(anchor_out) };
    }

    // ── trust grant & verify ──────────────────────────────────────────────────

    #[test]
    fn test_trust_grant_and_verify() {
        let dir = tempfile::tempdir().unwrap();

        // Create grantor identity.
        let grantor_path = dir.path().join("grantor.aid");
        let grantor_path_cstr = cstring(grantor_path.to_str().unwrap());
        let grantor_pass_cstr = cstring("grantor-pass");
        let mut _id_out: *mut c_char = std::ptr::null_mut();
        unsafe {
            aid_identity_create(
                std::ptr::null(),
                grantor_pass_cstr.as_ptr(),
                grantor_path_cstr.as_ptr(),
                &mut _id_out,
            );
            aid_free_string(_id_out);
        }
        let mut grantor_anchor: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            aid_identity_load(
                grantor_path_cstr.as_ptr(),
                grantor_pass_cstr.as_ptr(),
                &mut grantor_anchor,
            );
        }

        // Create grantee identity.
        let grantee_path = dir.path().join("grantee.aid");
        let grantee_path_cstr = cstring(grantee_path.to_str().unwrap());
        let grantee_pass_cstr = cstring("grantee-pass");
        let mut _grantee_id_out: *mut c_char = std::ptr::null_mut();
        unsafe {
            aid_identity_create(
                std::ptr::null(),
                grantee_pass_cstr.as_ptr(),
                grantee_path_cstr.as_ptr(),
                &mut _grantee_id_out,
            );
        }
        let grantee_id_str = unsafe { take_string(_grantee_id_out) };

        let mut grantee_anchor: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            aid_identity_load(
                grantee_path_cstr.as_ptr(),
                grantee_pass_cstr.as_ptr(),
                &mut grantee_anchor,
            );
        }

        // Get grantee public key.
        let mut grantee_pk_out: *mut c_char = std::ptr::null_mut();
        unsafe { aid_identity_get_public_key(grantee_anchor as *const _, &mut grantee_pk_out) };
        let grantee_pk_str = unsafe { take_string(grantee_pk_out) };

        // Build the grant.
        let grantee_id_cstr = cstring(&grantee_id_str);
        let grantee_pk_cstr = cstring(&grantee_pk_str);
        let caps_cstr = cstring(r#"["read:calendar","write:email"]"#);
        let mut grant_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_trust_grant(
                grantor_anchor as *const _,
                grantee_id_cstr.as_ptr(),
                grantee_pk_cstr.as_ptr(),
                caps_cstr.as_ptr(),
                &mut grant_out,
            )
        };
        assert_eq!(rc, AID_OK, "aid_trust_grant should succeed");
        assert!(!grant_out.is_null());

        let grant_json_str = unsafe { CStr::from_ptr(grant_out).to_str().unwrap().to_owned() };

        // Verify a covered capability.
        let grant_cstr = cstring(&grant_json_str);
        let cap_cstr = cstring("read:calendar");
        let mut is_valid: libc::c_int = 0;
        let rc = unsafe { aid_trust_verify(grant_cstr.as_ptr(), cap_cstr.as_ptr(), &mut is_valid) };
        assert_eq!(rc, AID_OK);
        assert_eq!(is_valid, 1, "read:calendar must be covered");

        // Verify a NOT-covered capability.
        let bad_cap_cstr = cstring("delete:everything");
        let mut is_valid2: libc::c_int = 1;
        let rc =
            unsafe { aid_trust_verify(grant_cstr.as_ptr(), bad_cap_cstr.as_ptr(), &mut is_valid2) };
        assert_eq!(rc, AID_OK);
        assert_eq!(is_valid2, 0, "delete:everything must NOT be covered");

        unsafe { aid_free_string(grant_out) };
        unsafe { aid_identity_free(grantor_anchor) };
        unsafe { aid_identity_free(grantee_anchor) };
    }

    // ── free string ───────────────────────────────────────────────────────────

    #[test]
    fn test_free_string() {
        // Obtain a library-allocated string and free it without crashing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("free-test.aid");
        let path_cstr = cstring(path.to_str().unwrap());
        let pass_cstr = cstring("free-test-pass");

        let mut id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(),
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                &mut id_out,
            )
        };
        assert_eq!(rc, AID_OK);
        // This must not crash or double-free.
        unsafe { aid_free_string(id_out) };
    }

    #[test]
    fn test_free_null_string() {
        // Freeing a null pointer must be a safe no-op.
        unsafe { aid_free_string(std::ptr::null_mut()) };
    }

    // ── null pointer handling ─────────────────────────────────────────────────

    #[test]
    fn test_null_pointer_handling() {
        let pass_cstr = cstring("pass");
        let path_cstr = cstring("/tmp/dummy.aid");

        // aid_identity_create: null passphrase
        let mut id_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(),
                std::ptr::null(), // null passphrase
                path_cstr.as_ptr(),
                &mut id_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_create: null path
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(),
                pass_cstr.as_ptr(),
                std::ptr::null(), // null path
                &mut id_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_create: null output pointer
        let rc = unsafe {
            aid_identity_create(
                std::ptr::null(),
                pass_cstr.as_ptr(),
                path_cstr.as_ptr(),
                std::ptr::null_mut(), // null out
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_load: null path
        let mut anchor_out: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc = unsafe {
            aid_identity_load(
                std::ptr::null(), // null path
                pass_cstr.as_ptr(),
                &mut anchor_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_load: null passphrase
        let rc = unsafe {
            aid_identity_load(
                path_cstr.as_ptr(),
                std::ptr::null(), // null passphrase
                &mut anchor_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_load: null anchor_out
        let rc = unsafe {
            aid_identity_load(
                path_cstr.as_ptr(),
                pass_cstr.as_ptr(),
                std::ptr::null_mut(), // null out
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_get_id: null anchor
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { aid_identity_get_id(std::ptr::null(), &mut out) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_get_id: null output
        let fake_anchor: u8 = 0; // we only test the null-check, not dereference
        let rc = unsafe {
            aid_identity_get_id(
                &fake_anchor as *const u8 as *const std::ffi::c_void,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_identity_get_public_key: null anchor
        let rc = unsafe { aid_identity_get_public_key(std::ptr::null(), &mut out) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_action_sign: null anchor
        let desc_cstr = cstring("test");
        let atype_cstr = cstring("decision");
        let mut r_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_action_sign(
                std::ptr::null(),
                atype_cstr.as_ptr(),
                desc_cstr.as_ptr(),
                std::ptr::null(),
                &mut r_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_action_sign: null action_type
        let rc = unsafe {
            aid_action_sign(
                &fake_anchor as *const u8 as *const std::ffi::c_void,
                std::ptr::null(), // null action_type
                desc_cstr.as_ptr(),
                std::ptr::null(),
                &mut r_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_receipt_verify: null json
        let mut v: libc::c_int = 0;
        let rc = unsafe { aid_receipt_verify(std::ptr::null(), &mut v) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_receipt_verify: null is_valid_out
        let json_cstr = cstring("{}");
        let rc = unsafe { aid_receipt_verify(json_cstr.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_trust_grant: null grantor
        let grantee_id_cstr = cstring("aid_test");
        let grantee_key_cstr = cstring("AAAA");
        let caps_cstr = cstring(r#"["read:*"]"#);
        let mut g_out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            aid_trust_grant(
                std::ptr::null(),
                grantee_id_cstr.as_ptr(),
                grantee_key_cstr.as_ptr(),
                caps_cstr.as_ptr(),
                &mut g_out,
            )
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_trust_verify: null grant_json
        let cap_cstr = cstring("read:calendar");
        let mut v2: libc::c_int = 0;
        let rc = unsafe { aid_trust_verify(std::ptr::null(), cap_cstr.as_ptr(), &mut v2) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_trust_verify: null capability
        let rc = unsafe { aid_trust_verify(json_cstr.as_ptr(), std::ptr::null(), &mut v2) };
        assert_eq!(rc, AID_ERR_NULL_PTR);

        // aid_trust_verify: null is_valid_out
        let rc = unsafe {
            aid_trust_verify(json_cstr.as_ptr(), cap_cstr.as_ptr(), std::ptr::null_mut())
        };
        assert_eq!(rc, AID_ERR_NULL_PTR);
    }
}
