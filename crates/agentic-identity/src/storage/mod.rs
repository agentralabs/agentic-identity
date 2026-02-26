//! Storage layer for identity files, receipts, and trust grants.
//!
//! Handles `.aid` file format, encrypted private key storage, and
//! persistence for receipts and trust grants.
//!
//! # Directory layout
//!
//! By convention the default root is `~/.agentic/`, with sub-directories
//! created by each store:
//!
//! ```text
//! ~/.agentic/
//! ├── identity/
//! │   ├── default.aid
//! │   └── {name}.aid
//! ├── receipts/
//! │   └── {receipt_id}.json
//! ├── spawn/
//! │   └── {spawn_id}.json
//! └── trust/
//!     ├── granted/
//!     │   └── {trust_id}.json
//!     ├── received/
//!     │   └── {trust_id}.json
//!     └── revocations/
//!         └── {trust_id}.json
//! ```
//!
//! # Modules
//!
//! - [`identity_file`] — `.aid` file save/load with passphrase encryption.
//! - [`receipt_store`] — CRUD for `ActionReceipt` records.
//! - [`spawn_store`] — CRUD for `SpawnRecord` records.
//! - [`trust_store`] — CRUD for `TrustGrant` and `Revocation` records.

pub mod identity_file;
pub mod receipt_store;
pub mod spawn_store;
pub mod trust_store;

// Re-export the primary types so callers can write `storage::ReceiptStore`
// without reaching into sub-modules.
pub use identity_file::{
    load_identity, read_public_document, save_identity, AidFile, EncryptionMetadata,
};
pub use receipt_store::ReceiptStore;
pub use spawn_store::SpawnStore;
pub use trust_store::TrustStore;
