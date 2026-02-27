//! Agentic-contracts trait implementations for AgenticIdentity.
//!
//! Implements: Sister, SessionManagement, Grounding, Queryable
//! Does NOT implement: FileFormatReader/Writer (directory-based JSON storage),
//!                     WorkspaceManagement (sessions, not workspaces)

use std::path::PathBuf;
use std::time::Instant;

use agentic_contracts::prelude::*;
use chrono::Utc;

use crate::error::IdentityError;
use crate::identity::IdentityId;
use crate::receipt::{ActionReceipt, ReceiptId};
use crate::storage::{ReceiptStore, TrustStore};
use crate::trust::TrustGrant;

// ═══════════════════════════════════════════════════════════════════
// ERROR BRIDGE
// ═══════════════════════════════════════════════════════════════════

impl From<IdentityError> for SisterError {
    fn from(e: IdentityError) -> Self {
        match &e {
            IdentityError::NotFound(name) => {
                SisterError::not_found(format!("identity item not found: {name}"))
            }
            IdentityError::InvalidKey(msg) => SisterError::invalid_input(msg.clone()),
            IdentityError::InvalidPassphrase => SisterError::new(
                ErrorCode::PermissionDenied,
                "Invalid passphrase".to_string(),
            ),
            IdentityError::SignatureInvalid => SisterError::new(
                ErrorCode::PermissionDenied,
                "Signature verification failed".to_string(),
            ),
            IdentityError::TrustNotGranted(msg) => SisterError::new(
                ErrorCode::PermissionDenied,
                format!("Trust not granted: {msg}"),
            ),
            IdentityError::TrustRevoked(msg) => {
                SisterError::new(ErrorCode::PermissionDenied, format!("Trust revoked: {msg}"))
            }
            IdentityError::TrustExpired => {
                SisterError::new(ErrorCode::InvalidState, "Trust expired".to_string())
            }
            IdentityError::TrustNotYetValid => {
                SisterError::new(ErrorCode::InvalidState, "Trust not yet valid".to_string())
            }
            IdentityError::MaxUsesExceeded => {
                SisterError::new(ErrorCode::InvalidState, "Max uses exceeded".to_string())
            }
            IdentityError::DelegationNotAllowed => SisterError::new(
                ErrorCode::PermissionDenied,
                "Delegation not allowed".to_string(),
            ),
            IdentityError::DelegationDepthExceeded => SisterError::new(
                ErrorCode::PermissionDenied,
                "Delegation depth exceeded".to_string(),
            ),
            IdentityError::InvalidChain => {
                SisterError::new(ErrorCode::InvalidState, "Invalid receipt chain".to_string())
            }
            IdentityError::StorageError(msg) => {
                SisterError::new(ErrorCode::StorageError, format!("Storage error: {msg}"))
            }
            IdentityError::SerializationError(msg) => SisterError::new(
                ErrorCode::StorageError,
                format!("Serialization error: {msg}"),
            ),
            IdentityError::InvalidFileFormat(msg) => SisterError::new(
                ErrorCode::VersionMismatch,
                format!("Invalid file format: {msg}"),
            ),
            IdentityError::Io(err) => {
                SisterError::new(ErrorCode::StorageError, format!("IO error: {err}"))
            }
            // Competence, negative, crypto, and remaining errors → IdentityError
            _ => SisterError::new(ErrorCode::IdentityError, e.to_string()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SESSION RECORD (internal tracking)
// ═══════════════════════════════════════════════════════════════════

/// Internal record tracking a session for audit continuity.
struct SessionRecord {
    id: ContextId,
    name: String,
    started_at: chrono::DateTime<Utc>,
    ended_at: Option<chrono::DateTime<Utc>>,
    receipt_ids: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// FACADE
// ═══════════════════════════════════════════════════════════════════

/// Contract facade wrapping identity stores.
///
/// Provides a unified Sister interface over the directory-based
/// identity storage (ReceiptStore, TrustStore, IdentityAnchor).
pub struct IdentitySister {
    /// Path to the identity storage directory
    #[allow(dead_code)]
    storage_dir: PathBuf,

    /// Receipt store
    receipt_store: Option<ReceiptStore>,

    /// Trust store
    trust_store: Option<TrustStore>,

    /// Loaded identity ID (optional — may not exist yet)
    #[allow(dead_code)]
    identity_id: Option<IdentityId>,

    /// Startup time for uptime tracking
    started_at: Instant,

    /// Current session
    current_session: Option<SessionRecord>,

    /// Session history
    sessions: Vec<SessionRecord>,

    /// Session counter for naming
    session_counter: u64,
}

impl IdentitySister {
    /// Create a new IdentitySister from a storage directory path.
    fn from_storage_dir(dir: PathBuf) -> SisterResult<Self> {
        let receipt_store = ReceiptStore::new(dir.join("receipts")).map_err(SisterError::from)?;
        let trust_store = TrustStore::new(dir.join("trust")).map_err(SisterError::from)?;

        // Try to discover identity ID from existing .aid files
        let identity_id = Self::discover_identity(&dir);

        Ok(Self {
            storage_dir: dir,
            receipt_store: Some(receipt_store),
            trust_store: Some(trust_store),
            identity_id,
            started_at: Instant::now(),
            current_session: None,
            sessions: Vec::new(),
            session_counter: 0,
        })
    }

    /// Try to discover an existing identity from .aid files.
    fn discover_identity(dir: &std::path::Path) -> Option<IdentityId> {
        let identity_dir = dir.join("identity");
        if !identity_dir.exists() {
            return None;
        }
        let default_path = identity_dir.join("default.aid");
        if default_path.exists() {
            if let Ok(doc) = crate::storage::read_public_document(&default_path) {
                return Some(doc.id);
            }
        }
        None
    }

    /// Get a reference to the receipt store.
    fn receipt_store(&self) -> SisterResult<&ReceiptStore> {
        self.receipt_store.as_ref().ok_or_else(|| {
            SisterError::new(
                ErrorCode::InvalidState,
                "Receipt store not initialized".to_string(),
            )
        })
    }

    /// Get a reference to the trust store.
    fn trust_store(&self) -> SisterResult<&TrustStore> {
        self.trust_store.as_ref().ok_or_else(|| {
            SisterError::new(
                ErrorCode::InvalidState,
                "Trust store not initialized".to_string(),
            )
        })
    }

    /// Load all receipts from the store.
    fn load_all_receipts(&self) -> SisterResult<Vec<ActionReceipt>> {
        let store = self.receipt_store()?;
        let ids = store.list().map_err(SisterError::from)?;
        let mut receipts = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Ok(receipt) = store.load(id) {
                receipts.push(receipt);
            }
        }
        Ok(receipts)
    }

    /// Load all trust grants (granted + received).
    fn load_all_grants(&self) -> SisterResult<Vec<TrustGrant>> {
        let store = self.trust_store()?;
        let mut grants = Vec::new();

        let granted_ids = store.list_granted().map_err(SisterError::from)?;
        for id in &granted_ids {
            if let Ok(grant) = store.load_grant(id) {
                grants.push(grant);
            }
        }

        let received_ids = store.list_received().map_err(SisterError::from)?;
        for id in &received_ids {
            if !granted_ids.contains(id) {
                if let Ok(grant) = store.load_grant(id) {
                    grants.push(grant);
                }
            }
        }

        Ok(grants)
    }

    /// Simple word-overlap score between a query and text.
    fn word_overlap_score(query: &str, text: &str) -> f64 {
        let query_words: std::collections::HashSet<String> = query
            .to_lowercase()
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|w| !w.is_empty())
            .collect();

        if query_words.is_empty() {
            return 0.0;
        }

        let text_lower = text.to_lowercase();
        let matched = query_words
            .iter()
            .filter(|w| text_lower.contains(w.as_str()))
            .count();

        matched as f64 / query_words.len() as f64
    }

    /// Convert a microsecond timestamp to DateTime<Utc>.
    fn micros_to_datetime(micros: u64) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(
            (micros / 1_000_000) as i64,
            ((micros % 1_000_000) * 1000) as u32,
        )
        .unwrap_or_else(Utc::now)
    }
}

// ═══════════════════════════════════════════════════════════════════
// SISTER TRAIT
// ═══════════════════════════════════════════════════════════════════

impl Sister for IdentitySister {
    const SISTER_TYPE: SisterType = SisterType::Identity;
    const FILE_EXTENSION: &'static str = "aid";

    fn init(config: SisterConfig) -> SisterResult<Self>
    where
        Self: Sized,
    {
        let dir = config.data_path.unwrap_or_else(|| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".agentic")
        });

        if config.create_if_missing {
            std::fs::create_dir_all(&dir).map_err(|e| {
                SisterError::new(
                    ErrorCode::StorageError,
                    format!("Failed to create identity storage dir: {e}"),
                )
            })?;
        }

        Self::from_storage_dir(dir)
    }

    fn health(&self) -> HealthStatus {
        let uptime = self.started_at.elapsed();

        let receipt_count = self
            .receipt_store()
            .and_then(|s| s.list().map_err(SisterError::from))
            .map(|ids| ids.len())
            .unwrap_or(0);

        let grant_count = self
            .trust_store()
            .and_then(|s| s.list_granted().map_err(SisterError::from))
            .map(|ids| ids.len())
            .unwrap_or(0);

        HealthStatus {
            healthy: true,
            status: Status::Ready,
            uptime,
            resources: ResourceUsage {
                memory_bytes: 0,
                disk_bytes: 0,
                open_handles: receipt_count + grant_count,
            },
            warnings: vec![],
            last_error: None,
        }
    }

    fn version(&self) -> Version {
        Version::new(0, 3, 0)
    }

    fn shutdown(&mut self) -> SisterResult<()> {
        // End any active session
        if self.current_session.is_some() {
            let _ = self.end_session();
        }
        self.receipt_store = None;
        self.trust_store = None;
        Ok(())
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::new("action_sign", "Sign actions with cryptographic receipts"),
            Capability::new("receipt_verify", "Verify receipt signatures"),
            Capability::new("receipt_list", "List action receipts"),
            Capability::new("trust_grant", "Grant trust between identities"),
            Capability::new("trust_verify", "Verify trust grants"),
            Capability::new("trust_revoke", "Revoke trust grants"),
            Capability::new("trust_list", "List trust grants"),
            Capability::new("identity_create", "Create new identity"),
            Capability::new("identity_show", "Show identity information"),
            Capability::new("identity_ground", "Verify claims against identity evidence"),
            Capability::new("identity_evidence", "Get detailed identity evidence"),
            Capability::new("identity_suggest", "Find similar identity items"),
            Capability::new("competence_record", "Record competence attempts"),
            Capability::new("competence_prove", "Generate competence proofs"),
            Capability::new("negative_prove", "Prove negative capabilities"),
            Capability::new("negative_declare", "Declare negative capabilities"),
            Capability::new("spawn_create", "Create child identities"),
            Capability::new("spawn_terminate", "Terminate child identities"),
            Capability::new("continuity_record", "Record continuity events"),
            Capability::new("continuity_anchor", "Create continuity checkpoints"),
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════

impl SessionManagement for IdentitySister {
    fn start_session(&mut self, name: &str) -> SisterResult<ContextId> {
        // End any active session first
        if self.current_session.is_some() {
            self.end_session()?;
        }

        self.session_counter += 1;
        let id = ContextId::new();

        self.current_session = Some(SessionRecord {
            id,
            name: name.to_string(),
            started_at: Utc::now(),
            ended_at: None,
            receipt_ids: Vec::new(),
        });

        Ok(id)
    }

    fn end_session(&mut self) -> SisterResult<()> {
        let mut session = self.current_session.take().ok_or_else(|| {
            SisterError::new(ErrorCode::InvalidState, "No active session".to_string())
        })?;

        session.ended_at = Some(Utc::now());
        self.sessions.push(session);
        Ok(())
    }

    fn current_session(&self) -> Option<ContextId> {
        self.current_session.as_ref().map(|s| s.id)
    }

    fn current_session_info(&self) -> SisterResult<ContextInfo> {
        let session = self.current_session.as_ref().ok_or_else(|| {
            SisterError::new(ErrorCode::InvalidState, "No active session".to_string())
        })?;

        Ok(ContextInfo {
            id: session.id,
            name: session.name.clone(),
            created_at: session.started_at,
            updated_at: Utc::now(),
            item_count: session.receipt_ids.len(),
            size_bytes: 0,
            metadata: Metadata::new(),
        })
    }

    fn list_sessions(&self) -> SisterResult<Vec<ContextSummary>> {
        let mut summaries: Vec<ContextSummary> = self
            .sessions
            .iter()
            .map(|s| ContextSummary {
                id: s.id,
                name: s.name.clone(),
                created_at: s.started_at,
                updated_at: s.ended_at.unwrap_or(s.started_at),
                item_count: s.receipt_ids.len(),
                size_bytes: 0,
            })
            .collect();

        // Include current session if active
        if let Some(ref s) = self.current_session {
            summaries.push(ContextSummary {
                id: s.id,
                name: s.name.clone(),
                created_at: s.started_at,
                updated_at: Utc::now(),
                item_count: s.receipt_ids.len(),
                size_bytes: 0,
            });
        }

        Ok(summaries)
    }

    fn export_session(&self, session_id: ContextId) -> SisterResult<ContextSnapshot> {
        // Find the session
        let session = self
            .sessions
            .iter()
            .chain(self.current_session.as_ref())
            .find(|s| s.id == session_id)
            .ok_or_else(|| SisterError::not_found(format!("session {session_id}")))?;

        // Collect receipt data for the session
        let receipt_data: Vec<serde_json::Value> = session
            .receipt_ids
            .iter()
            .filter_map(|id| {
                let receipt_id = ReceiptId(id.clone());
                self.receipt_store()
                    .ok()
                    .and_then(|store| store.load(&receipt_id).ok())
                    .and_then(|r| serde_json::to_value(&r).ok())
            })
            .collect();

        let data = serde_json::to_vec(&receipt_data).unwrap_or_default();
        let checksum = *blake3::hash(&data).as_bytes();

        let context_info = ContextInfo {
            id: session.id,
            name: session.name.clone(),
            created_at: session.started_at,
            updated_at: session.ended_at.unwrap_or_else(Utc::now),
            item_count: session.receipt_ids.len(),
            size_bytes: data.len(),
            metadata: Metadata::new(),
        };

        Ok(ContextSnapshot {
            sister_type: SisterType::Identity,
            version: Version::new(0, 3, 0),
            context_info,
            data,
            checksum,
            snapshot_at: Utc::now(),
        })
    }

    fn import_session(&mut self, snapshot: ContextSnapshot) -> SisterResult<ContextId> {
        // Verify checksum
        if !snapshot.verify() {
            return Err(SisterError::new(
                ErrorCode::ChecksumMismatch,
                "Snapshot checksum verification failed".to_string(),
            ));
        }

        // Parse the receipt data
        let receipts: Vec<ActionReceipt> = serde_json::from_slice(&snapshot.data)
            .map_err(|e| SisterError::invalid_input(format!("Invalid snapshot data: {e}")))?;

        // Save imported receipts
        let store = self.receipt_store()?;
        let mut receipt_ids = Vec::new();
        for receipt in &receipts {
            store.save(receipt).map_err(SisterError::from)?;
            receipt_ids.push(receipt.id.0.clone());
        }

        // Create a session record for the import
        let id = ContextId::new();
        self.sessions.push(SessionRecord {
            id,
            name: format!("imported-{}", self.sessions.len()),
            started_at: snapshot.context_info.created_at,
            ended_at: Some(Utc::now()),
            receipt_ids,
        });

        Ok(id)
    }
}

// ═══════════════════════════════════════════════════════════════════
// GROUNDING
// ═══════════════════════════════════════════════════════════════════

impl Grounding for IdentitySister {
    fn ground(&self, claim: &str) -> SisterResult<GroundingResult> {
        let claim_lower = claim.to_lowercase();
        let mut best_score = 0.0_f64;
        let mut evidence_items = Vec::new();

        // Search receipts
        let receipts = self.load_all_receipts()?;
        for receipt in &receipts {
            let desc_score = Self::word_overlap_score(claim, &receipt.action.description);
            let type_score = if claim_lower.contains(receipt.action_type.as_tag()) {
                0.3
            } else {
                0.0
            };
            let score = (desc_score + type_score).min(1.0);

            if score > 0.3 {
                evidence_items.push(GroundingEvidence::new(
                    "receipt",
                    &receipt.id.0,
                    score,
                    format!(
                        "[{}] {}",
                        receipt.action_type.as_tag(),
                        receipt.action.description
                    ),
                ));
                best_score = best_score.max(score);
            }
        }

        // Search trust grants
        let grants = self.load_all_grants()?;
        for grant in &grants {
            let cap_text: String = grant
                .capabilities
                .iter()
                .map(|c| c.uri.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let combined = format!("{} {} {}", grant.grantor.0, grant.grantee.0, cap_text);
            let score = Self::word_overlap_score(claim, &combined);

            if score > 0.3 {
                evidence_items.push(GroundingEvidence::new(
                    "trust_grant",
                    &grant.id.0,
                    score,
                    format!(
                        "Trust: {} -> {} [{}]",
                        grant.grantor.0, grant.grantee.0, cap_text
                    ),
                ));
                best_score = best_score.max(score);
            }
        }

        // Determine status
        let (status, confidence) = if best_score >= 0.7 {
            (GroundingStatus::Verified, best_score)
        } else if best_score >= 0.4 {
            (GroundingStatus::Partial, best_score)
        } else {
            (GroundingStatus::Ungrounded, 0.0)
        };

        // Sort evidence by score descending
        evidence_items.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        evidence_items.truncate(10);

        let reason = match status {
            GroundingStatus::Verified => {
                format!("Found {} supporting evidence items", evidence_items.len())
            }
            GroundingStatus::Partial => {
                format!("Found {} partially matching items", evidence_items.len())
            }
            GroundingStatus::Ungrounded => "No matching receipts or trust grants found".into(),
        };

        Ok(GroundingResult {
            status,
            claim: claim.to_string(),
            confidence,
            evidence: evidence_items,
            reason,
            suggestions: vec![],
            timestamp: Utc::now(),
        })
    }

    fn evidence(&self, query: &str, max_results: usize) -> SisterResult<Vec<EvidenceDetail>> {
        let mut details = Vec::new();

        // Search receipts
        let receipts = self.load_all_receipts()?;
        for receipt in &receipts {
            let score = Self::word_overlap_score(query, &receipt.action.description);
            if score > 0.2 {
                let timestamp = Self::micros_to_datetime(receipt.timestamp);

                let mut data = Metadata::new();
                data.insert(
                    "action_type".into(),
                    serde_json::json!(receipt.action_type.as_tag()),
                );
                data.insert("actor".into(), serde_json::json!(receipt.actor.0));

                details.push(EvidenceDetail {
                    evidence_type: "receipt".into(),
                    id: receipt.id.0.clone(),
                    score,
                    created_at: timestamp,
                    source_sister: SisterType::Identity,
                    content: receipt.action.description.clone(),
                    data,
                });
            }
        }

        // Search trust grants
        let grants = self.load_all_grants()?;
        for grant in &grants {
            let cap_text: String = grant
                .capabilities
                .iter()
                .map(|c| c.uri.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let combined = format!("{} {} {}", grant.grantor.0, grant.grantee.0, cap_text);
            let score = Self::word_overlap_score(query, &combined);

            if score > 0.2 {
                let timestamp = Self::micros_to_datetime(grant.granted_at);

                let mut data = Metadata::new();
                data.insert("grantor".into(), serde_json::json!(grant.grantor.0));
                data.insert("grantee".into(), serde_json::json!(grant.grantee.0));
                data.insert("capabilities".into(), serde_json::json!(cap_text));

                details.push(EvidenceDetail {
                    evidence_type: "trust_grant".into(),
                    id: grant.id.0.clone(),
                    score,
                    created_at: timestamp,
                    source_sister: SisterType::Identity,
                    content: format!(
                        "Trust: {} -> {} [{}]",
                        grant.grantor.0, grant.grantee.0, cap_text
                    ),
                    data,
                });
            }
        }

        details.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        details.truncate(max_results);
        Ok(details)
    }

    fn suggest(&self, query: &str, limit: usize) -> SisterResult<Vec<GroundingSuggestion>> {
        let mut suggestions = Vec::new();

        let receipts = self.load_all_receipts()?;
        for receipt in &receipts {
            let score = Self::word_overlap_score(query, &receipt.action.description);
            if score > 0.1 {
                suggestions.push(GroundingSuggestion {
                    item_type: "receipt".into(),
                    id: receipt.id.0.clone(),
                    relevance_score: score,
                    description: format!(
                        "[{}] {}",
                        receipt.action_type.as_tag(),
                        receipt.action.description
                    ),
                    data: Metadata::new(),
                });
            }
        }

        let grants = self.load_all_grants()?;
        for grant in &grants {
            let cap_text: String = grant
                .capabilities
                .iter()
                .map(|c| c.uri.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let combined = format!("{} {} {}", grant.grantor.0, grant.grantee.0, cap_text);
            let score = Self::word_overlap_score(query, &combined);

            if score > 0.1 {
                suggestions.push(GroundingSuggestion {
                    item_type: "trust_grant".into(),
                    id: grant.id.0.clone(),
                    relevance_score: score,
                    description: format!(
                        "Trust: {} -> {} [{}]",
                        grant.grantor.0, grant.grantee.0, cap_text
                    ),
                    data: Metadata::new(),
                });
            }
        }

        suggestions.sort_by(|a, b| {
            b.relevance_score
                .partial_cmp(&a.relevance_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        suggestions.truncate(limit);
        Ok(suggestions)
    }
}

// ═══════════════════════════════════════════════════════════════════
// QUERYABLE
// ═══════════════════════════════════════════════════════════════════

impl Queryable for IdentitySister {
    fn query(&self, query: Query) -> SisterResult<QueryResult> {
        let start = Instant::now();

        match query.query_type.as_str() {
            "list" => {
                let receipts = self.load_all_receipts()?;
                let limit = query.limit.unwrap_or(50);
                let offset = query.offset.unwrap_or(0);

                let results: Vec<serde_json::Value> = receipts
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id.0,
                            "type": "receipt",
                            "action_type": r.action_type.as_tag(),
                            "description": r.action.description,
                            "actor": r.actor.0,
                            "timestamp": r.timestamp,
                        })
                    })
                    .collect();

                Ok(QueryResult::new(query, results, start.elapsed())
                    .with_pagination(receipts.len(), offset + limit < receipts.len()))
            }
            "search" => {
                let query_text = query.get_string("text").unwrap_or_default();
                let limit = query.limit.unwrap_or(20);

                let receipts = self.load_all_receipts()?;
                let grants = self.load_all_grants()?;

                let mut scored: Vec<(f64, serde_json::Value)> = Vec::new();

                // Search receipts
                for r in &receipts {
                    let score = Self::word_overlap_score(&query_text, &r.action.description);
                    if score > 0.2 {
                        scored.push((
                            score,
                            serde_json::json!({
                                "id": r.id.0,
                                "type": "receipt",
                                "action_type": r.action_type.as_tag(),
                                "description": r.action.description,
                                "actor": r.actor.0,
                                "score": score,
                            }),
                        ));
                    }
                }

                // Search grants
                for g in &grants {
                    let cap_text: String = g
                        .capabilities
                        .iter()
                        .map(|c| c.uri.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let combined = format!("{} {} {}", g.grantor.0, g.grantee.0, cap_text);
                    let score = Self::word_overlap_score(&query_text, &combined);

                    if score > 0.2 {
                        scored.push((
                            score,
                            serde_json::json!({
                                "id": g.id.0,
                                "type": "trust_grant",
                                "grantor": g.grantor.0,
                                "grantee": g.grantee.0,
                                "capabilities": cap_text,
                                "score": score,
                            }),
                        ));
                    }
                }

                scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                let total = scored.len();
                scored.truncate(limit);

                let results: Vec<serde_json::Value> = scored.into_iter().map(|(_, v)| v).collect();

                Ok(QueryResult::new(query, results, start.elapsed())
                    .with_pagination(total, total > limit))
            }
            "recent" => {
                let limit = query.limit.unwrap_or(10);
                let mut receipts = self.load_all_receipts()?;
                receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

                let total = receipts.len();
                let results: Vec<serde_json::Value> = receipts
                    .iter()
                    .take(limit)
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id.0,
                            "type": "receipt",
                            "action_type": r.action_type.as_tag(),
                            "description": r.action.description,
                            "timestamp": r.timestamp,
                        })
                    })
                    .collect();

                Ok(QueryResult::new(query, results, start.elapsed())
                    .with_pagination(total, total > limit))
            }
            "get" => {
                let id = query.get_string("id").ok_or_else(|| {
                    SisterError::invalid_input("'get' query requires 'id' parameter")
                })?;

                let receipt_id = ReceiptId(id);
                let store = self.receipt_store()?;

                match store.load(&receipt_id) {
                    Ok(receipt) => {
                        let result = serde_json::json!({
                            "id": receipt.id.0,
                            "type": "receipt",
                            "action_type": receipt.action_type.as_tag(),
                            "description": receipt.action.description,
                            "actor": receipt.actor.0,
                            "timestamp": receipt.timestamp,
                            "receipt_hash": receipt.receipt_hash,
                            "signature": receipt.signature,
                            "previous_receipt": receipt.previous_receipt.as_ref().map(|p| &p.0),
                        });

                        Ok(QueryResult::new(query, vec![result], start.elapsed())
                            .with_pagination(1, false))
                    }
                    Err(e) => Err(SisterError::from(e)),
                }
            }
            other => Err(SisterError::invalid_input(format!(
                "Unknown query type: {other}. Supported: list, search, recent, get"
            ))),
        }
    }

    fn supports_query(&self, query_type: &str) -> bool {
        matches!(query_type, "list" | "search" | "recent" | "get")
    }

    fn query_types(&self) -> Vec<QueryTypeInfo> {
        vec![
            QueryTypeInfo::new("list", "List all receipts with pagination"),
            QueryTypeInfo::new("search", "Search receipts and grants by text")
                .required(vec!["text"]),
            QueryTypeInfo::new("recent", "Get most recent receipts"),
            QueryTypeInfo::new("get", "Get a specific receipt by ID").required(vec!["id"]),
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::{ActionContent, ActionType};
    use tempfile::TempDir;

    /// Create a test IdentitySister backed by a temp directory.
    fn test_sister() -> (IdentitySister, TempDir) {
        let dir = TempDir::new().unwrap();
        let config = SisterConfig {
            data_path: Some(dir.path().to_path_buf()),
            create_if_missing: true,
            ..SisterConfig::stateless()
        };
        let sister = IdentitySister::init(config).unwrap();
        (sister, dir)
    }

    /// Create a test receipt and save it.
    fn save_test_receipt(sister: &IdentitySister, description: &str) -> ActionReceipt {
        let anchor = IdentityAnchor::new(Some("test".into()));
        let receipt = crate::receipt::receipt::ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new(description),
        )
        .sign(anchor.signing_key())
        .unwrap();

        sister.receipt_store().unwrap().save(&receipt).unwrap();
        receipt
    }

    #[test]
    fn test_sister_trait() {
        let (sister, _dir) = test_sister();

        assert_eq!(IdentitySister::SISTER_TYPE, SisterType::Identity);
        assert_eq!(IdentitySister::FILE_EXTENSION, "aid");

        let health = sister.health();
        assert!(health.healthy);
        assert_eq!(health.status, Status::Ready);

        let version = sister.version();
        assert_eq!(version.major, 0);
        assert_eq!(version.minor, 3);
        assert_eq!(version.patch, 0);

        let caps = sister.capabilities();
        assert!(caps.iter().any(|c| c.name == "action_sign"));
        assert!(caps.iter().any(|c| c.name == "identity_ground"));
    }

    #[test]
    fn test_session_management() {
        let (mut sister, _dir) = test_sister();

        // No session initially
        assert!(sister.current_session().is_none());

        // Start session
        let id = sister.start_session("test-session").unwrap();
        assert!(sister.current_session().is_some());
        assert_eq!(sister.current_session().unwrap(), id);

        // Session info
        let info = sister.current_session_info().unwrap();
        assert_eq!(info.id, id);
        assert_eq!(info.name, "test-session");

        // End session
        sister.end_session().unwrap();
        assert!(sister.current_session().is_none());

        // List sessions — ended session should be listed
        let sessions = sister.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
    }

    #[test]
    fn test_grounding_with_receipts() {
        let (sister, _dir) = test_sister();

        save_test_receipt(&sister, "Approved deployment to production");

        let result = sister.ground("deployment production approved").unwrap();
        assert!(result.confidence > 0.0);
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_grounding_ungrounded() {
        let (sister, _dir) = test_sister();

        let result = sister
            .ground("something completely unrelated xyz123")
            .unwrap();
        assert_eq!(result.status, GroundingStatus::Ungrounded);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_queryable_list() {
        let (sister, _dir) = test_sister();

        save_test_receipt(&sister, "Action one");
        save_test_receipt(&sister, "Action two");
        save_test_receipt(&sister, "Action three");

        let result = sister.query(Query::list()).unwrap();
        assert_eq!(result.total_count, Some(3));
        assert_eq!(result.results.len(), 3);
    }

    #[test]
    fn test_queryable_search() {
        let (sister, _dir) = test_sister();

        save_test_receipt(&sister, "Deployed application to production");
        save_test_receipt(&sister, "Fixed authentication bug in login");
        save_test_receipt(&sister, "Updated deployment pipeline");

        let result = sister.query(Query::search("deployment")).unwrap();
        assert!(!result.results.is_empty());
        assert!(result.results.iter().any(|r| {
            r.get("description")
                .and_then(|d| d.as_str())
                .map(|d| d.to_lowercase().contains("deploy"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn test_queryable_get() {
        let (sister, _dir) = test_sister();

        let receipt = save_test_receipt(&sister, "Test receipt for get");

        let result = sister.query(Query::get(&receipt.id.0)).unwrap();
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0]["id"].as_str().unwrap(), receipt.id.0);
    }

    #[test]
    fn test_error_bridge() {
        let err: SisterError = IdentityError::NotFound("test-id".into()).into();
        assert_eq!(err.code, ErrorCode::NotFound);

        let err: SisterError = IdentityError::SignatureInvalid.into();
        assert_eq!(err.code, ErrorCode::PermissionDenied);

        let err: SisterError = IdentityError::TrustExpired.into();
        assert_eq!(err.code, ErrorCode::InvalidState);

        let err: SisterError = IdentityError::StorageError("disk full".into()).into();
        assert_eq!(err.code, ErrorCode::StorageError);

        let err: SisterError = IdentityError::InvalidFileFormat("bad header".into()).into();
        assert_eq!(err.code, ErrorCode::VersionMismatch);
    }

    #[test]
    fn test_shutdown() {
        let (mut sister, _dir) = test_sister();

        sister.start_session("before-shutdown").unwrap();
        sister.shutdown().unwrap();

        assert!(sister.receipt_store.is_none());
        assert!(sister.trust_store.is_none());
        assert!(sister.current_session.is_none());
    }

    #[test]
    fn test_config_patterns() {
        let config = SisterConfig::stateless();
        assert!(config.data_path.is_none());
        assert!(config.create_if_missing);

        let dir = TempDir::new().unwrap();
        let config = SisterConfig::new(dir.path().to_path_buf());
        assert!(config.data_path.is_some());
    }

    #[test]
    fn test_session_export_import() {
        let (mut sister, _dir) = test_sister();

        let session_id = sister.start_session("export-test").unwrap();

        let receipt = save_test_receipt(&sister, "Receipt during session");
        if let Some(ref mut session) = sister.current_session {
            session.receipt_ids.push(receipt.id.0.clone());
        }

        let snapshot = sister.export_session(session_id).unwrap();
        assert!(!snapshot.data.is_empty());
        assert!(snapshot.verify());

        // Import into a fresh sister
        let dir2 = TempDir::new().unwrap();
        let config2 = SisterConfig {
            data_path: Some(dir2.path().to_path_buf()),
            create_if_missing: true,
            ..SisterConfig::stateless()
        };
        let mut sister2 = IdentitySister::init(config2).unwrap();
        let imported_id = sister2.import_session(snapshot).unwrap();

        let sessions = sister2.list_sessions().unwrap();
        assert!(sessions.iter().any(|s| s.id == imported_id));
    }

    #[test]
    fn test_supports_query() {
        let (sister, _dir) = test_sister();
        assert!(sister.supports_query("list"));
        assert!(sister.supports_query("search"));
        assert!(sister.supports_query("recent"));
        assert!(sister.supports_query("get"));
        assert!(!sister.supports_query("aggregate"));
    }
}
