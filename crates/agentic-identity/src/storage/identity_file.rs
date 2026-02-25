//! .aid file format — encrypted identity storage.
//!
//! An `.aid` file stores an identity anchor's private key material
//! encrypted with ChaCha20-Poly1305 under a key derived from a
//! user passphrase via Argon2id, alongside the public identity document
//! in plaintext for inspection without decryption.
//!
//! File format (JSON):
//! ```json
//! {
//!     "version": 1,
//!     "format": "aid-v1",
//!     "encryption": {
//!         "algorithm": "chacha20-poly1305",
//!         "kdf": "argon2id",
//!         "salt": "<base64-16-bytes>",
//!         "nonce": "<base64-12-bytes>"
//!     },
//!     "encrypted_anchor": "<base64-ciphertext>",
//!     "public_document": { ... IdentityDocument ... }
//! }
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{derivation, encryption};
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityAnchor, IdentityDocument, KeyRotation};

// ── File format constants ─────────────────────────────────────────────────────

const AID_VERSION: u32 = 1;
const AID_FORMAT: &str = "aid-v1";
const AID_ALGORITHM: &str = "chacha20-poly1305";
const AID_KDF: &str = "argon2id";

/// HKDF context string for deriving the identity encryption key from the
/// Argon2id master key. Must remain stable across versions.
const IDENTITY_ENCRYPTION_CONTEXT: &str = "identity-encryption";

// ── On-disk structures ────────────────────────────────────────────────────────

/// Top-level structure written to disk as a `.aid` file.
#[derive(Debug, Serialize, Deserialize)]
pub struct AidFile {
    /// Format version number.
    pub version: u32,
    /// Format identifier string.
    pub format: String,
    /// Encryption parameters needed for decryption.
    pub encryption: EncryptionMetadata,
    /// Base64-encoded ciphertext of the encrypted anchor private data.
    pub encrypted_anchor: String,
    /// Public identity document (no private key material).
    pub public_document: IdentityDocument,
}

/// Encryption metadata stored alongside the ciphertext.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Symmetric cipher used.
    pub algorithm: String,
    /// Key derivation function used.
    pub kdf: String,
    /// Base64-encoded Argon2id salt (16 bytes).
    pub salt: String,
    /// Base64-encoded ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: String,
}

/// Private data serialized into the encrypted anchor blob.
///
/// This struct is serialized to JSON and then encrypted. It contains
/// everything required to reconstruct an `IdentityAnchor` via
/// `IdentityAnchor::from_parts`.
#[derive(Debug, Serialize, Deserialize, Zeroize)]
struct AnchorPrivateData {
    /// Ed25519 signing key bytes encoded as base64.
    signing_key_b64: String,
    /// Creation timestamp (microseconds since Unix epoch).
    created_at: u64,
    /// Human-readable identity name.
    name: Option<String>,
    /// Key rotation history.
    rotation_history: Vec<KeyRotation>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Save an `IdentityAnchor` to a `.aid` file, encrypting private key material
/// with the given passphrase.
///
/// The file is written atomically: the serialized JSON is written to a
/// temporary file in the same directory and then renamed, so a concurrent
/// reader never sees a partial write.
///
/// # Errors
///
/// Returns `IdentityError::DerivationFailed` if key derivation fails,
/// `IdentityError::EncryptionFailed` if encryption fails, or
/// `IdentityError::Io` for filesystem errors.
pub fn save_identity(anchor: &IdentityAnchor, path: &Path, passphrase: &str) -> Result<()> {
    // 1. Collect private data.
    let mut signing_bytes = anchor.signing_key_bytes();
    let signing_key_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing_bytes);
    signing_bytes.zeroize();

    let private_data = AnchorPrivateData {
        signing_key_b64,
        created_at: anchor.created_at,
        name: anchor.name.clone(),
        rotation_history: anchor.rotation_history.clone(),
    };

    // 2. Serialize private data to JSON bytes.
    let mut plaintext = serde_json::to_vec(&private_data)
        .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

    // 3. Derive encryption key from passphrase.
    //    passphrase → Argon2id(passphrase, salt) → master_key
    //    HKDF-SHA256(master_key, "identity-encryption") → encryption_key
    let salt = crate::crypto::random::random_salt_16();
    let mut master_key = encryption::derive_passphrase_key(passphrase.as_bytes(), &salt)?;
    let mut encryption_key = derivation::derive_key(&master_key, IDENTITY_ENCRYPTION_CONTEXT)?;
    master_key.zeroize();

    // 4. Encrypt with ChaCha20-Poly1305. The `encrypt` function generates a
    //    fresh nonce internally and returns it alongside the ciphertext.
    let (nonce_bytes, ciphertext) = encryption::encrypt(&encryption_key, &plaintext)?;
    encryption_key.zeroize();
    plaintext.zeroize();

    // 5. Build the AidFile struct.
    let aid_file = AidFile {
        version: AID_VERSION,
        format: AID_FORMAT.to_string(),
        encryption: EncryptionMetadata {
            algorithm: AID_ALGORITHM.to_string(),
            kdf: AID_KDF.to_string(),
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes),
        },
        encrypted_anchor: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext,
        ),
        public_document: anchor.to_document(),
    };

    // 6. Write JSON to disk (atomic via temp-file-then-rename).
    let json = serde_json::to_string_pretty(&aid_file)
        .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

    write_atomic(path, json.as_bytes())?;

    Ok(())
}

/// Load an `IdentityAnchor` from a `.aid` file, decrypting with the given
/// passphrase.
///
/// # Errors
///
/// Returns `IdentityError::InvalidPassphrase` if the passphrase is wrong
/// (ChaCha20-Poly1305 authentication will fail), `IdentityError::InvalidFileFormat`
/// for malformed files, or `IdentityError::Io` for filesystem errors.
pub fn load_identity(path: &Path, passphrase: &str) -> Result<IdentityAnchor> {
    // 1. Read and parse the file.
    let bytes = std::fs::read(path)?;
    let aid_file: AidFile = serde_json::from_slice(&bytes)
        .map_err(|e| IdentityError::InvalidFileFormat(format!("failed to parse .aid file: {e}")))?;

    // 2. Validate version and format.
    if aid_file.version != AID_VERSION || aid_file.format != AID_FORMAT {
        return Err(IdentityError::InvalidFileFormat(format!(
            "unsupported .aid file version={} format={}",
            aid_file.version, aid_file.format,
        )));
    }

    // 3. Decode salt, nonce, and ciphertext from base64.
    let salt_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &aid_file.encryption.salt,
    )
    .map_err(|e| IdentityError::InvalidFileFormat(format!("invalid salt base64: {e}")))?;

    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidFileFormat("salt must be 16 bytes".to_string()))?;

    let nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &aid_file.encryption.nonce,
    )
    .map_err(|e| IdentityError::InvalidFileFormat(format!("invalid nonce base64: {e}")))?;

    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &aid_file.encrypted_anchor,
    )
    .map_err(|e| IdentityError::InvalidFileFormat(format!("invalid ciphertext base64: {e}")))?;

    // 4. Derive the encryption key using the same KDF chain as save_identity.
    let mut master_key = encryption::derive_passphrase_key(passphrase.as_bytes(), &salt)?;
    let mut encryption_key = derivation::derive_key(&master_key, IDENTITY_ENCRYPTION_CONTEXT)?;
    master_key.zeroize();

    // 5. Decrypt. InvalidPassphrase is returned if AEAD authentication fails.
    let mut plaintext = encryption::decrypt(&encryption_key, &nonce_bytes, &ciphertext)?;
    encryption_key.zeroize();

    // 6. Deserialize the private data.
    let private_data: AnchorPrivateData = serde_json::from_slice(&plaintext)
        .map_err(|e| IdentityError::SerializationError(format!("anchor data: {e}")))?;
    plaintext.zeroize();

    // 7. Decode the signing key bytes from base64.
    let key_bytes_vec = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &private_data.signing_key_b64,
    )
    .map_err(|e| IdentityError::InvalidKey(format!("invalid signing key base64: {e}")))?;

    let mut key_bytes: [u8; 32] = key_bytes_vec
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("signing key must be 32 bytes".to_string()))?;

    // 8. Reconstruct the anchor.
    let anchor = IdentityAnchor::from_parts(
        &key_bytes,
        private_data.created_at,
        private_data.name,
        private_data.rotation_history,
    )?;
    key_bytes.zeroize();

    Ok(anchor)
}

/// Read only the public identity document from a `.aid` file.
///
/// This does not require the passphrase because the public document is stored
/// in plaintext. Useful for inspecting an identity file without decrypting it.
///
/// # Errors
///
/// Returns `IdentityError::InvalidFileFormat` for malformed files or
/// `IdentityError::Io` for filesystem errors.
pub fn read_public_document(path: &Path) -> Result<IdentityDocument> {
    let bytes = std::fs::read(path)?;
    let aid_file: AidFile = serde_json::from_slice(&bytes)
        .map_err(|e| IdentityError::InvalidFileFormat(format!("failed to parse .aid file: {e}")))?;
    Ok(aid_file.public_document)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Write `data` to `path` atomically using a sibling temporary file.
///
/// Creates the parent directory if it does not exist. The write uses a
/// sibling temp file and `std::fs::rename` so that a crash during the write
/// cannot leave a partially-written file visible to readers.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to a sibling temp file first.
    let tmp_path = path.with_extension("aid.tmp");
    std::fs::write(&tmp_path, data)?;

    // Rename into place.
    std::fs::rename(&tmp_path, path)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    /// Create a test anchor with a known name.
    fn make_anchor(name: &str) -> IdentityAnchor {
        IdentityAnchor::new(Some(name.to_string()))
    }

    #[test]
    fn test_identity_file_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.aid");
        let passphrase = "correct-horse-battery-staple";

        let original = make_anchor("save-load-test");
        let original_id = original.id();
        let original_pub = original.verifying_key_bytes();

        save_identity(&original, &path, passphrase).expect("save failed");
        assert!(path.exists(), "file should exist after save");

        let loaded = load_identity(&path, passphrase).expect("load failed");

        assert_eq!(loaded.id(), original_id, "identity id must match");
        assert_eq!(
            loaded.verifying_key_bytes(),
            original_pub,
            "public keys must match"
        );
        assert_eq!(
            loaded.signing_key_bytes(),
            original.signing_key_bytes(),
            "signing keys must match"
        );
        assert_eq!(loaded.created_at, original.created_at);
        assert_eq!(loaded.name, original.name);
    }

    #[test]
    fn test_identity_file_encryption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted.aid");
        let passphrase = "my-secret-passphrase";

        let anchor = make_anchor("encryption-test");
        save_identity(&anchor, &path, passphrase).expect("save failed");

        // Read the raw file bytes.
        let raw = std::fs::read(&path).unwrap();

        // The file is JSON so parse it back.
        let aid_file: AidFile = serde_json::from_slice(&raw).expect("file should be valid JSON");

        // The encrypted_anchor field must exist and must not contain the
        // plaintext signing key.
        let signing_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anchor.signing_key_bytes(),
        );
        assert!(
            !aid_file.encrypted_anchor.contains(&signing_b64),
            "ciphertext must not contain plaintext signing key"
        );

        // The ciphertext must be non-empty.
        assert!(
            !aid_file.encrypted_anchor.is_empty(),
            "encrypted_anchor must not be empty"
        );

        // Verify that we can decrypt it correctly.
        let loaded = load_identity(&path, passphrase).expect("load failed");
        assert_eq!(loaded.verifying_key_bytes(), anchor.verifying_key_bytes());
    }

    #[test]
    fn test_identity_file_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong-pass.aid");

        let anchor = make_anchor("wrong-pass-test");
        save_identity(&anchor, &path, "correct-passphrase").expect("save failed");

        let result = load_identity(&path, "wrong-passphrase");
        assert!(result.is_err(), "loading with wrong passphrase must fail");
        // Should be InvalidPassphrase, not some other error.
        assert!(
            matches!(result, Err(IdentityError::InvalidPassphrase)),
            "error must be InvalidPassphrase"
        );
    }

    #[test]
    fn test_identity_file_read_public_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public.aid");

        let anchor = make_anchor("public-doc-test");
        save_identity(&anchor, &path, "passphrase").expect("save failed");

        // Read the public document without a passphrase.
        let doc = read_public_document(&path).expect("read_public_document failed");

        assert_eq!(doc.id, anchor.id());
        assert_eq!(doc.name.as_deref(), Some("public-doc-test"));
        assert!(
            doc.verify_signature().is_ok(),
            "document signature must verify"
        );
    }

    #[test]
    fn test_identity_file_rotation_history_preserved() {
        use crate::identity::RotationReason;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotated.aid");

        let anchor = make_anchor("rotation-test");
        let rotated = anchor.rotate(RotationReason::Manual).unwrap();
        let rotated2 = rotated.rotate(RotationReason::Scheduled).unwrap();

        save_identity(&rotated2, &path, "pass").expect("save failed");
        let loaded = load_identity(&path, "pass").expect("load failed");

        assert_eq!(loaded.rotation_history.len(), 2);
        assert_eq!(loaded.rotation_history[0].reason, RotationReason::Manual);
        assert_eq!(loaded.rotation_history[1].reason, RotationReason::Scheduled);
    }

    #[test]
    fn test_identity_file_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("test.aid");

        let anchor = make_anchor("nested-dir-test");
        save_identity(&anchor, &path, "pass").expect("save with nested dir failed");
        assert!(path.exists());
    }

    #[test]
    fn test_identity_file_name_none_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-name.aid");

        // Anchor with no name
        let anchor = IdentityAnchor::new(None);
        save_identity(&anchor, &path, "pass").expect("save failed");

        let loaded = load_identity(&path, "pass").expect("load failed");
        assert_eq!(loaded.name, None);
    }

    #[test]
    fn test_identity_file_format_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("format.aid");

        let anchor = make_anchor("format-test");
        save_identity(&anchor, &path, "pass").unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let aid: AidFile = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(aid.version, AID_VERSION);
        assert_eq!(aid.format, AID_FORMAT);
        assert_eq!(aid.encryption.algorithm, AID_ALGORITHM);
        assert_eq!(aid.encryption.kdf, AID_KDF);

        // Salt must decode to 16 bytes.
        let salt = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &aid.encryption.salt,
        )
        .unwrap();
        assert_eq!(salt.len(), 16);

        // Nonce must decode to 12 bytes.
        let nonce = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &aid.encryption.nonce,
        )
        .unwrap();
        assert_eq!(nonce.len(), 12);
    }
}
