//! Trust grant and revocation persistence.
//!
//! Stores `TrustGrant` and `Revocation` records as JSON files under a
//! directory tree:
//!
//! ```text
//! {base_dir}/
//! ├── granted/          — grants issued by this identity
//! │   └── {trust_id}.json
//! ├── received/         — grants received by this identity
//! │   └── {trust_id}.json
//! └── revocations/      — revoked grants (either direction)
//!     └── {trust_id}.json
//! ```
//!
//! File format for grants:
//! ```json
//! { "version": 1, "grant": { ... TrustGrant ... } }
//! ```
//!
//! File format for revocations:
//! ```json
//! { "version": 1, "revocation": { ... Revocation ... } }
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::trust::{Revocation, TrustGrant, TrustId};

// ── File format constants ─────────────────────────────────────────────────────

const TRUST_FILE_VERSION: u32 = 1;

// ── On-disk structures ────────────────────────────────────────────────────────

/// Wrapper written to disk for each trust grant.
#[derive(Debug, Serialize, Deserialize)]
struct TrustGrantFile {
    /// Format version number.
    version: u32,
    /// The stored grant.
    grant: TrustGrant,
}

/// Wrapper written to disk for each revocation.
#[derive(Debug, Serialize, Deserialize)]
struct RevocationFile {
    /// Format version number.
    version: u32,
    /// The stored revocation.
    revocation: Revocation,
}

// ── Sub-directory names ───────────────────────────────────────────────────────

const GRANTED_DIR: &str = "granted";
const RECEIVED_DIR: &str = "received";
const REVOCATIONS_DIR: &str = "revocations";

// ── TrustStore ────────────────────────────────────────────────────────────────

/// Filesystem-backed store for `TrustGrant` and `Revocation` records.
///
/// Grants are separated into "granted" (issued by this identity) and
/// "received" (issued to this identity) sub-directories. A single grant ID
/// may exist in both directories (grantor and grantee on the same machine).
pub struct TrustStore {
    base_dir: PathBuf,
}

impl TrustStore {
    /// Create a new `TrustStore` rooted at `base_dir`.
    ///
    /// Creates `granted/`, `received/`, and `revocations/` sub-directories if
    /// they do not already exist.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if any directory cannot be created.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(base_dir.join(GRANTED_DIR))?;
        std::fs::create_dir_all(base_dir.join(RECEIVED_DIR))?;
        std::fs::create_dir_all(base_dir.join(REVOCATIONS_DIR))?;
        Ok(Self { base_dir })
    }

    // ── Grant persistence ─────────────────────────────────────────────────────

    /// Persist a trust grant issued by this identity to `granted/`.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::SerializationError` if serialization fails, or
    /// `IdentityError::Io` for filesystem errors.
    pub fn save_granted(&self, grant: &TrustGrant) -> Result<()> {
        self.write_grant(grant, GRANTED_DIR)
    }

    /// Persist a trust grant received by this identity to `received/`.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::SerializationError` if serialization fails, or
    /// `IdentityError::Io` for filesystem errors.
    pub fn save_received(&self, grant: &TrustGrant) -> Result<()> {
        self.write_grant(grant, RECEIVED_DIR)
    }

    /// Load a trust grant by ID, checking `granted/` first then `received/`.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::NotFound` if the grant is not in either
    /// directory, `IdentityError::InvalidFileFormat` for malformed files, or
    /// `IdentityError::Io` for filesystem errors.
    pub fn load_grant(&self, id: &TrustId) -> Result<TrustGrant> {
        // Check granted/ first.
        let granted_path = self.grant_path(id, GRANTED_DIR);
        if granted_path.exists() {
            return self.read_grant(&granted_path);
        }

        // Fall back to received/.
        let received_path = self.grant_path(id, RECEIVED_DIR);
        if received_path.exists() {
            return self.read_grant(&received_path);
        }

        Err(IdentityError::NotFound(format!(
            "trust grant not found: {}",
            id
        )))
    }

    /// List the IDs of all grants stored in `granted/`.
    ///
    /// The returned list is not sorted in any particular order.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if the directory cannot be read.
    pub fn list_granted(&self) -> Result<Vec<TrustId>> {
        self.list_ids(GRANTED_DIR)
    }

    /// List the IDs of all grants stored in `received/`.
    ///
    /// The returned list is not sorted in any particular order.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if the directory cannot be read.
    pub fn list_received(&self) -> Result<Vec<TrustId>> {
        self.list_ids(RECEIVED_DIR)
    }

    // ── Revocation persistence ────────────────────────────────────────────────

    /// Persist a revocation record to `revocations/`.
    ///
    /// The file is named by the revoked `TrustId` so that `is_revoked` and
    /// `load_revocation` can look it up in O(1) filesystem operations.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::SerializationError` if serialization fails, or
    /// `IdentityError::Io` for filesystem errors.
    pub fn save_revocation(&self, revocation: &Revocation) -> Result<()> {
        let file = RevocationFile {
            version: TRUST_FILE_VERSION,
            revocation: revocation.clone(),
        };

        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        let path = self.revocation_path(&revocation.trust_id);
        std::fs::write(&path, json.as_bytes())?;

        Ok(())
    }

    /// Load a revocation by the trust grant ID it revokes.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::NotFound` if no revocation exists for `id`,
    /// `IdentityError::InvalidFileFormat` for malformed files, or
    /// `IdentityError::Io` for filesystem errors.
    pub fn load_revocation(&self, id: &TrustId) -> Result<Revocation> {
        let path = self.revocation_path(id);

        if !path.exists() {
            return Err(IdentityError::NotFound(format!(
                "revocation not found for trust id: {}",
                id
            )));
        }

        let bytes = std::fs::read(&path)?;
        let file: RevocationFile = serde_json::from_slice(&bytes).map_err(|e| {
            IdentityError::InvalidFileFormat(format!(
                "failed to parse revocation file {}: {e}",
                path.display()
            ))
        })?;

        Ok(file.revocation)
    }

    /// List the IDs of all revocations stored in `revocations/`.
    ///
    /// The returned list is not sorted in any particular order.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if the directory cannot be read.
    pub fn list_revocations(&self) -> Result<Vec<TrustId>> {
        self.list_ids(REVOCATIONS_DIR)
    }

    /// Return `true` if a revocation file exists for the given trust ID.
    ///
    /// This is a purely filesystem-level existence check; it does not read
    /// or validate the revocation record.
    pub fn is_revoked(&self, id: &TrustId) -> bool {
        self.revocation_path(id).exists()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Serialize and write a grant to `{base_dir}/{sub_dir}/{id}.json`.
    fn write_grant(&self, grant: &TrustGrant, sub_dir: &str) -> Result<()> {
        let file = TrustGrantFile {
            version: TRUST_FILE_VERSION,
            grant: grant.clone(),
        };

        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        let path = self.grant_path(&grant.id, sub_dir);
        std::fs::write(&path, json.as_bytes())?;

        Ok(())
    }

    /// Read and deserialize a grant from an absolute path.
    fn read_grant(&self, path: &std::path::Path) -> Result<TrustGrant> {
        let bytes = std::fs::read(path)?;
        let file: TrustGrantFile = serde_json::from_slice(&bytes).map_err(|e| {
            IdentityError::InvalidFileFormat(format!(
                "failed to parse trust grant file {}: {e}",
                path.display()
            ))
        })?;
        Ok(file.grant)
    }

    /// Build the filesystem path for a trust grant: `{base_dir}/{sub}/{id}.json`.
    fn grant_path(&self, id: &TrustId, sub_dir: &str) -> PathBuf {
        self.base_dir.join(sub_dir).join(format!("{}.json", id.0))
    }

    /// Build the filesystem path for a revocation: `{base_dir}/revocations/{id}.json`.
    fn revocation_path(&self, id: &TrustId) -> PathBuf {
        self.base_dir
            .join(REVOCATIONS_DIR)
            .join(format!("{}.json", id.0))
    }

    /// Read a directory listing and extract IDs from `{id}.json` filenames.
    fn list_ids(&self, sub_dir: &str) -> Result<Vec<TrustId>> {
        let dir = self.base_dir.join(sub_dir);
        let mut ids = Vec::new();

        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(stem) = name_str.strip_suffix(".json") {
                ids.push(TrustId(stem.to_string()));
            }
        }

        Ok(ids)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::trust::{Capability, Revocation, RevocationReason, TrustGrantBuilder};

    /// Build a signed trust grant between two anchors.
    fn make_grant(grantor: &IdentityAnchor, grantee: &IdentityAnchor) -> TrustGrant {
        let grantee_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            grantee.verifying_key_bytes(),
        );
        TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee_key)
            .capability(Capability::new("read:calendar"))
            .sign(grantor.signing_key())
            .expect("signing grant failed")
    }

    /// Build a revocation for a given grant.
    fn make_revocation(anchor: &IdentityAnchor, grant: &TrustGrant) -> Revocation {
        Revocation::create(
            grant.id.clone(),
            anchor.id(),
            RevocationReason::ManualRevocation,
            anchor.signing_key(),
        )
    }

    #[test]
    fn test_trust_store_creates_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let _store = TrustStore::new(dir.path()).unwrap();

        assert!(dir.path().join("granted").is_dir());
        assert!(dir.path().join("received").is_dir());
        assert!(dir.path().join("revocations").is_dir());
    }

    #[test]
    fn test_trust_store_save_load_granted() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(Some("grantor".to_string()));
        let grantee = IdentityAnchor::new(Some("grantee".to_string()));
        let grant = make_grant(&grantor, &grantee);
        let id = grant.id.clone();

        store.save_granted(&grant).expect("save_granted failed");

        let loaded = store.load_grant(&id).expect("load_grant failed");
        assert_eq!(loaded.id, grant.id);
        assert_eq!(loaded.grantor, grant.grantor);
        assert_eq!(loaded.grantee, grant.grantee);
        assert_eq!(loaded.grant_hash, grant.grant_hash);
        assert_eq!(loaded.grantor_signature, grant.grantor_signature);
    }

    #[test]
    fn test_trust_store_save_load_received() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee);
        let id = grant.id.clone();

        store.save_received(&grant).expect("save_received failed");

        let loaded = store.load_grant(&id).expect("load_grant failed");
        assert_eq!(loaded.id, id);
    }

    #[test]
    fn test_trust_store_load_grant_checks_both_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);

        // Grant only in received/
        let grant = make_grant(&grantor, &grantee);
        let id = grant.id.clone();
        store.save_received(&grant).unwrap();

        // Must be found even though it is not in granted/.
        assert!(store.load_grant(&id).is_ok());

        // Grant only in granted/
        let grant2 = make_grant(&grantee, &grantor); // reversed roles
        let id2 = grant2.id.clone();
        store.save_granted(&grant2).unwrap();

        // Must be found even though it is not in received/.
        assert!(store.load_grant(&id2).is_ok());
    }

    #[test]
    fn test_trust_store_save_load_50_grants() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let mut grants = Vec::with_capacity(50);

        for _ in 0..50 {
            let grantee = IdentityAnchor::new(None);
            let grant = make_grant(&grantor, &grantee);
            store.save_granted(&grant).unwrap();
            grants.push(grant);
        }

        for original in &grants {
            let loaded = store.load_grant(&original.id).expect("load failed");
            assert_eq!(loaded.id, original.id);
            assert_eq!(loaded.grant_hash, original.grant_hash);
        }
    }

    #[test]
    fn test_trust_store_list_granted() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let mut ids = Vec::new();

        for _ in 0..5 {
            let grantee = IdentityAnchor::new(None);
            let grant = make_grant(&grantor, &grantee);
            store.save_granted(&grant).unwrap();
            ids.push(grant.id);
        }

        let listed = store.list_granted().unwrap();
        assert_eq!(listed.len(), 5);
        for id in &ids {
            assert!(listed.contains(id));
        }
    }

    #[test]
    fn test_trust_store_list_received() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let mut ids = Vec::new();

        for _ in 0..3 {
            let grantee = IdentityAnchor::new(None);
            let grant = make_grant(&grantor, &grantee);
            store.save_received(&grant).unwrap();
            ids.push(grant.id);
        }

        let listed = store.list_received().unwrap();
        assert_eq!(listed.len(), 3);
        for id in &ids {
            assert!(listed.contains(id));
        }
    }

    #[test]
    fn test_revocation_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee);
        let trust_id = grant.id.clone();

        // Grant must not be revoked initially.
        assert!(!store.is_revoked(&trust_id));

        let revocation = make_revocation(&grantor, &grant);
        store
            .save_revocation(&revocation)
            .expect("save_revocation failed");

        // Must be found after saving.
        assert!(store.is_revoked(&trust_id));

        let loaded = store
            .load_revocation(&trust_id)
            .expect("load_revocation failed");
        assert_eq!(loaded.trust_id, trust_id);
        assert_eq!(loaded.revoker, grantor.id());
        assert_eq!(loaded.reason, RevocationReason::ManualRevocation);
    }

    #[test]
    fn test_revocation_store_list_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let mut revoked_ids = Vec::new();

        for _ in 0..4 {
            let grantee = IdentityAnchor::new(None);
            let grant = make_grant(&grantor, &grantee);
            let rev = make_revocation(&grantor, &grant);
            store.save_revocation(&rev).unwrap();
            revoked_ids.push(grant.id);
        }

        let listed = store.list_revocations().unwrap();
        assert_eq!(listed.len(), 4);
        for id in &revoked_ids {
            assert!(listed.contains(id));
        }
    }

    #[test]
    fn test_trust_store_load_grant_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let missing = TrustId("atrust_doesnotexist".to_string());
        let result = store.load_grant(&missing);
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn test_trust_store_load_revocation_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let missing = TrustId("atrust_nope".to_string());
        let result = store.load_revocation(&missing);
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn test_trust_store_is_not_revoked_without_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee);

        store.save_granted(&grant).unwrap();

        // Saving as granted must not set the revoked flag.
        assert!(!store.is_revoked(&grant.id));
    }

    #[test]
    fn test_trust_grant_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee);

        store.save_granted(&grant).unwrap();

        let path = dir
            .path()
            .join("granted")
            .join(format!("{}.json", grant.id.0));
        let bytes = std::fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["version"], TRUST_FILE_VERSION);
        assert!(value["grant"].is_object());
        assert_eq!(value["grant"]["id"].as_str().unwrap(), grant.id.0);
    }

    #[test]
    fn test_revocation_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(dir.path()).unwrap();

        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee);
        let revocation = make_revocation(&grantor, &grant);

        store.save_revocation(&revocation).unwrap();

        let path = dir
            .path()
            .join("revocations")
            .join(format!("{}.json", grant.id.0));
        let bytes = std::fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["version"], TRUST_FILE_VERSION);
        assert!(value["revocation"].is_object());
        assert_eq!(
            value["revocation"]["trust_id"].as_str().unwrap(),
            grant.id.0
        );
    }
}
