//! Spawn record persistence — store and retrieve `SpawnRecord` records.
//!
//! Each spawn record is stored as a single JSON file named `{spawn_id}.json`
//! inside the configured base directory.
//!
//! File format:
//! ```json
//! {
//!     "version": 1,
//!     "record": { ... SpawnRecord ... }
//! }
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::spawn::{SpawnId, SpawnRecord};

// ── File format constants ─────────────────────────────────────────────────────

const SPAWN_FILE_VERSION: u32 = 1;

// ── On-disk structure ─────────────────────────────────────────────────────────

/// Wrapper written to disk for each spawn record.
#[derive(Debug, Serialize, Deserialize)]
struct SpawnFile {
    /// Format version number.
    version: u32,
    /// The stored spawn record.
    record: SpawnRecord,
}

// ── SpawnStore ────────────────────────────────────────────────────────────────

/// Filesystem-backed store for `SpawnRecord` records.
///
/// Each record is written to a dedicated JSON file named by its ID.
/// The store is safe for single-process use; concurrent writes from
/// multiple processes are not coordinated.
pub struct SpawnStore {
    base_dir: PathBuf,
}

impl SpawnStore {
    /// Create a new `SpawnStore` rooted at `base_dir`.
    ///
    /// The directory and any missing parents are created if they do not exist.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Persist a spawn record to disk.
    ///
    /// Writes `{base_dir}/{spawn_id}.json`. Any existing file with the same
    /// ID is overwritten.
    pub fn save(&self, record: &SpawnRecord) -> Result<()> {
        let file = SpawnFile {
            version: SPAWN_FILE_VERSION,
            record: record.clone(),
        };

        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        let path = self.record_path(&record.id);
        std::fs::write(&path, json.as_bytes())?;

        Ok(())
    }

    /// Load a spawn record by its ID.
    pub fn load(&self, id: &SpawnId) -> Result<SpawnRecord> {
        let path = self.record_path(id);

        if !path.exists() {
            return Err(IdentityError::NotFound(format!(
                "spawn record not found: {}",
                id
            )));
        }

        let bytes = std::fs::read(&path)?;
        let file: SpawnFile = serde_json::from_slice(&bytes).map_err(|e| {
            IdentityError::InvalidFileFormat(format!(
                "failed to parse spawn file {}: {e}",
                path.display()
            ))
        })?;

        Ok(file.record)
    }

    /// List the IDs of all spawn records stored in this store.
    pub fn list(&self) -> Result<Vec<SpawnId>> {
        let mut ids = Vec::new();

        for entry in std::fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(stem) = name_str.strip_suffix(".json") {
                ids.push(SpawnId(stem.to_string()));
            }
        }

        Ok(ids)
    }

    /// Load all spawn records from the store.
    pub fn load_all(&self) -> Result<Vec<SpawnRecord>> {
        let ids = self.list()?;
        let mut records = Vec::with_capacity(ids.len());

        for id in &ids {
            match self.load(id) {
                Ok(record) => records.push(record),
                Err(_) => continue, // Skip corrupt files
            }
        }

        Ok(records)
    }

    /// Delete the file for a spawn record by its ID.
    ///
    /// If no file exists for `id`, this is a no-op (returns `Ok`).
    pub fn delete(&self, id: &SpawnId) -> Result<()> {
        let path = self.record_path(id);

        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(IdentityError::Io(e)),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build the filesystem path for a spawn ID.
    fn record_path(&self, id: &SpawnId) -> PathBuf {
        self.base_dir.join(format!("{}.json", id.0))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::spawn::{spawn_child, SpawnConstraints, SpawnLifetime, SpawnType};
    use crate::trust::Capability;

    fn make_record() -> SpawnRecord {
        let parent = IdentityAnchor::new(Some("parent".to_string()));
        let (_, record, _) = spawn_child(
            &parent,
            SpawnType::Worker,
            "test-spawn",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            SpawnConstraints::default(),
            None,
            &[],
        )
        .unwrap();
        record
    }

    #[test]
    fn test_spawn_store_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();
        let record = make_record();
        let id = record.id.clone();

        store.save(&record).expect("save failed");
        let loaded = store.load(&id).expect("load failed");

        assert_eq!(loaded.id.0, record.id.0);
        assert_eq!(loaded.parent_id, record.parent_id);
        assert_eq!(loaded.child_id, record.child_id);
        assert!(!loaded.terminated);
    }

    #[test]
    fn test_spawn_store_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();

        let r1 = make_record();
        let r2 = make_record();

        store.save(&r1).unwrap();
        store.save(&r2).unwrap();

        let ids = store.list().unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_spawn_store_load_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();

        let r1 = make_record();
        let r2 = make_record();

        store.save(&r1).unwrap();
        store.save(&r2).unwrap();

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_spawn_store_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();
        let record = make_record();
        let id = record.id.clone();

        store.save(&record).unwrap();
        assert!(store.load(&id).is_ok());

        store.delete(&id).unwrap();
        assert!(store.load(&id).is_err());
    }

    #[test]
    fn test_spawn_store_load_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();

        let missing = SpawnId("aspawn_missing".to_string());
        let result = store.load(&missing);
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn test_spawn_store_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("spawn").join("v1");
        assert!(!nested.exists());

        let _store = SpawnStore::new(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn test_spawn_store_overwrite_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpawnStore::new(dir.path()).unwrap();
        let mut record = make_record();
        let id = record.id.clone();

        store.save(&record).unwrap();

        // Terminate and re-save
        record.terminated = true;
        record.terminated_at = Some(crate::time::now_micros());
        record.termination_reason = Some("test".to_string());
        store.save(&record).unwrap();

        let loaded = store.load(&id).unwrap();
        assert!(loaded.terminated);
        assert_eq!(loaded.termination_reason.as_deref(), Some("test"));
    }
}
