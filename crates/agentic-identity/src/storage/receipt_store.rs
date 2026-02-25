//! Receipt persistence — store and retrieve `ActionReceipt` records.
//!
//! Each receipt is stored as a single JSON file named `{receipt_id}.json`
//! inside the configured base directory.
//!
//! File format:
//! ```json
//! {
//!     "version": 1,
//!     "receipt": { ... ActionReceipt ... }
//! }
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::receipt::{ActionReceipt, ReceiptId};

// ── File format constants ─────────────────────────────────────────────────────

const RECEIPT_FILE_VERSION: u32 = 1;

// ── On-disk structure ─────────────────────────────────────────────────────────

/// Wrapper written to disk for each receipt.
#[derive(Debug, Serialize, Deserialize)]
struct ReceiptFile {
    /// Format version number.
    version: u32,
    /// The stored receipt.
    receipt: ActionReceipt,
}

// ── ReceiptStore ──────────────────────────────────────────────────────────────

/// Filesystem-backed store for `ActionReceipt` records.
///
/// Each receipt is written to a dedicated JSON file named by its ID.
/// The store is safe for single-process use; concurrent writes from
/// multiple processes are not coordinated.
pub struct ReceiptStore {
    base_dir: PathBuf,
}

impl ReceiptStore {
    /// Create a new `ReceiptStore` rooted at `base_dir`.
    ///
    /// The directory and any missing parents are created if they do not exist.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if the directory cannot be created.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Persist a receipt to disk.
    ///
    /// Writes `{base_dir}/{receipt_id}.json`. Any existing file with the same
    /// ID is overwritten.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::SerializationError` if JSON serialization fails,
    /// or `IdentityError::Io` for filesystem errors.
    pub fn save(&self, receipt: &ActionReceipt) -> Result<()> {
        let file = ReceiptFile {
            version: RECEIPT_FILE_VERSION,
            receipt: receipt.clone(),
        };

        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        let path = self.receipt_path(&receipt.id);
        std::fs::write(&path, json.as_bytes())?;

        Ok(())
    }

    /// Load a receipt by its ID.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::NotFound` if no file exists for `id`,
    /// `IdentityError::InvalidFileFormat` if the file cannot be parsed, or
    /// `IdentityError::Io` for other filesystem errors.
    pub fn load(&self, id: &ReceiptId) -> Result<ActionReceipt> {
        let path = self.receipt_path(id);

        if !path.exists() {
            return Err(IdentityError::NotFound(format!(
                "receipt not found: {}",
                id
            )));
        }

        let bytes = std::fs::read(&path)?;
        let file: ReceiptFile = serde_json::from_slice(&bytes).map_err(|e| {
            IdentityError::InvalidFileFormat(format!(
                "failed to parse receipt file {}: {e}",
                path.display()
            ))
        })?;

        Ok(file.receipt)
    }

    /// List the IDs of all receipts stored in this store.
    ///
    /// The returned list is not sorted in any particular order.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<ReceiptId>> {
        let mut ids = Vec::new();

        for entry in std::fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(stem) = name_str.strip_suffix(".json") {
                ids.push(ReceiptId(stem.to_string()));
            }
        }

        Ok(ids)
    }

    /// Delete the file for a receipt by its ID.
    ///
    /// If no file exists for `id`, this is a no-op (returns `Ok`).
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::Io` for filesystem errors other than
    /// "not found".
    pub fn delete(&self, id: &ReceiptId) -> Result<()> {
        let path = self.receipt_path(id);

        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(IdentityError::Io(e)),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build the filesystem path for a receipt ID.
    fn receipt_path(&self, id: &ReceiptId) -> PathBuf {
        self.base_dir.join(format!("{}.json", id.0))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::receipt::ReceiptBuilder;
    use crate::receipt::{ActionContent, ActionType};

    /// Build a signed receipt for use in tests.
    fn make_receipt(anchor: &IdentityAnchor, description: &str) -> ActionReceipt {
        ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(description),
        )
        .sign(anchor.signing_key())
        .expect("signing receipt failed")
    }

    #[test]
    fn test_receipt_store_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(Some("store-test".to_string()));

        let receipt = make_receipt(&anchor, "deployed v1.0");
        let id = receipt.id.clone();

        store.save(&receipt).expect("save failed");
        let loaded = store.load(&id).expect("load failed");

        assert_eq!(loaded.id, receipt.id);
        assert_eq!(loaded.receipt_hash, receipt.receipt_hash);
        assert_eq!(loaded.signature, receipt.signature);
        assert_eq!(loaded.actor, receipt.actor);
    }

    #[test]
    fn test_receipt_store_save_load_100() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(None);

        // Store 100 receipts.
        let mut receipts = Vec::with_capacity(100);
        for i in 0..100 {
            let r = make_receipt(&anchor, &format!("action-{i}"));
            store.save(&r).unwrap();
            receipts.push(r);
        }

        // Load each one back and verify identity.
        for original in &receipts {
            let loaded = store.load(&original.id).expect("load failed");
            assert_eq!(loaded.id, original.id);
            assert_eq!(loaded.receipt_hash, original.receipt_hash);
        }
    }

    #[test]
    fn test_receipt_store_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(None);

        let r1 = make_receipt(&anchor, "action 1");
        let r2 = make_receipt(&anchor, "action 2");
        let r3 = make_receipt(&anchor, "action 3");

        store.save(&r1).unwrap();
        store.save(&r2).unwrap();
        store.save(&r3).unwrap();

        let mut ids = store.list().unwrap();
        ids.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&r1.id));
        assert!(ids.contains(&r2.id));
        assert!(ids.contains(&r3.id));
    }

    #[test]
    fn test_receipt_store_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(None);

        let receipt = make_receipt(&anchor, "to delete");
        let id = receipt.id.clone();

        store.save(&receipt).unwrap();
        assert!(store.load(&id).is_ok());

        store.delete(&id).unwrap();
        assert!(store.load(&id).is_err());
    }

    #[test]
    fn test_receipt_store_delete_nonexistent_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();

        // Deleting an ID that was never saved must succeed silently.
        let phantom = ReceiptId("arec_doesnotexist".to_string());
        assert!(store.delete(&phantom).is_ok());
    }

    #[test]
    fn test_receipt_store_load_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();

        let missing = ReceiptId("arec_missing".to_string());
        let result = store.load(&missing);
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn test_receipt_store_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(None);

        let receipt = make_receipt(&anchor, "original");
        let id = receipt.id.clone();

        // Save once.
        store.save(&receipt).unwrap();

        // Saving again with same ID (e.g. adding a witness) must not error.
        let mut modified = receipt.clone();
        modified.witnesses.clear(); // just mutate something benign
        store.save(&modified).unwrap();

        let loaded = store.load(&id).unwrap();
        assert_eq!(loaded.id, id);
    }

    #[test]
    fn test_receipt_store_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("receipts").join("v1");

        // Directory does not exist yet.
        assert!(!nested.exists());

        let _store = ReceiptStore::new(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn test_receipt_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path()).unwrap();
        let anchor = IdentityAnchor::new(None);

        let receipt = make_receipt(&anchor, "format check");
        store.save(&receipt).unwrap();

        // Read the raw file and verify it has the expected wrapper.
        let path = dir.path().join(format!("{}.json", receipt.id.0));
        let bytes = std::fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["version"], RECEIPT_FILE_VERSION);
        assert!(value["receipt"].is_object());
        assert_eq!(value["receipt"]["id"].as_str().unwrap(), receipt.id.0);
    }
}
