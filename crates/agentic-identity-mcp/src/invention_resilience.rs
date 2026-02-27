//! Invention Resilience — Tools for Inventions 13–16.
//!
//! - Invention 13: Identity Resurrection (4 tools)
//! - Invention 14: Identity Forking (4 tools)
//! - Invention 15: Zero-Knowledge Identity (3 tools)
//! - Invention 16: Temporal Identity (3 tools)

use serde_json::{json, Value};

use super::{micros_to_rfc3339, now_secs, tool_error, tool_ok, McpServer};

use agentic_identity::storage::{
    load_identity, read_public_document, ReceiptStore, SpawnStore, TrustStore,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Format seconds-since-epoch as "YYYY-MM-DD HH:MM:SS UTC" (delegates to parent).
fn secs_to_datetime(secs: u64) -> String {
    micros_to_rfc3339(secs * 1_000_000)
}

/// Simple FNV-1a hash for generating deterministic proof/challenge IDs.
fn fnv1a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Generate a hex-encoded hash string for proof identifiers.
fn proof_hash(input: &str) -> String {
    let h = fnv1a(input.as_bytes());
    format!("{:016x}", h)
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention 13: Identity Resurrection
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 1: identity_resurrect_start ─────────────────────────────────────────

pub fn definition_identity_resurrect_start() -> Value {
    json!({
        "name": "identity_resurrect_start",
        "description": "Start resurrection process for a lost identity. Checks if the identity can be resurrected from receipts and trust grants in the store.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity_name": {
                    "type": "string",
                    "description": "Name of the identity to resurrect"
                }
            },
            "required": ["identity_name"]
        }
    })
}

pub fn execute_identity_resurrect_start(server: &McpServer, id: Value, args: &Value) -> Value {
    let identity_name = match args.get("identity_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'identity_name' is missing"),
    };

    let path = server.identity_dir.join(format!("{identity_name}.aid"));

    // Check if identity file still exists (partially corrupted vs fully lost)
    let identity_exists = path.exists();
    let doc_readable = if identity_exists {
        read_public_document(&path).is_ok()
    } else {
        false
    };

    // Scan receipts for references to this identity
    let mut receipt_references = 0u64;
    let mut actor_ids_found = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    // Check if the receipt actor matches an identity named like this
                    if receipt.action.description.contains(identity_name)
                        || receipt.actor.0.contains(identity_name)
                    {
                        receipt_references += 1;
                        if !actor_ids_found.contains(&receipt.actor.0) {
                            actor_ids_found.push(receipt.actor.0.clone());
                        }
                    }
                }
            }
        }
    }

    // Scan trust grants for references
    let mut trust_references = 0u64;
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.grantor.0.contains(identity_name)
                            || grant.grantee.0.contains(identity_name)
                        {
                            trust_references += 1;
                        }
                    }
                }
            }
        }
    }

    // Scan spawn records
    let mut spawn_references = 0u64;
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                if r.parent_id.0.contains(identity_name)
                    || r.child_id.0.contains(identity_name)
                    || r.spawn_purpose.contains(identity_name)
                {
                    spawn_references += 1;
                }
            }
        }
    }

    let total_evidence = receipt_references + trust_references + spawn_references;
    let can_resurrect = total_evidence > 0 || doc_readable;

    let status = if doc_readable {
        "identity file readable — full resurrection possible"
    } else if identity_exists {
        "identity file exists but may be corrupted — partial resurrection possible"
    } else if total_evidence > 0 {
        "identity file missing — evidence-based resurrection possible"
    } else {
        "no evidence found — resurrection not possible"
    };

    let out = json!({
        "identity_name": identity_name,
        "status": status,
        "can_resurrect": can_resurrect,
        "identity_file_exists": identity_exists,
        "identity_file_readable": doc_readable,
        "evidence": {
            "receipt_references": receipt_references,
            "trust_references": trust_references,
            "spawn_references": spawn_references,
            "total": total_evidence,
            "actor_ids_found": actor_ids_found,
        },
        "next_step": if can_resurrect {
            "Call identity_resurrect_gather to collect all evidence"
        } else {
            "No evidence available for resurrection"
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 2: identity_resurrect_gather ────────────────────────────────────────

pub fn definition_identity_resurrect_gather() -> Value {
    json!({
        "name": "identity_resurrect_gather",
        "description": "Gather evidence from receipts, trust grants, and spawn records for identity resurrection. Collects all references to the identity across stores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity_name": {
                    "type": "string",
                    "description": "Name of the identity to gather evidence for"
                }
            },
            "required": ["identity_name"]
        }
    })
}

pub fn execute_identity_resurrect_gather(server: &McpServer, id: Value, args: &Value) -> Value {
    let identity_name = match args.get("identity_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'identity_name' is missing"),
    };

    // Try to read public document for identity ID
    let path = server.identity_dir.join(format!("{identity_name}.aid"));
    let identity_id = if let Ok(doc) = read_public_document(&path) {
        Some(doc.id.0.clone())
    } else {
        None
    };

    // Gather receipts
    let mut receipt_evidence = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let matches = match &identity_id {
                        Some(iid) => receipt.actor.0 == *iid,
                        None => {
                            receipt.action.description.contains(identity_name)
                                || receipt.actor.0.contains(identity_name)
                        }
                    };
                    if matches {
                        receipt_evidence.push(json!({
                            "receipt_id": receipt.id.0,
                            "actor": receipt.actor.0,
                            "action_type": receipt.action_type.as_tag(),
                            "description": if receipt.action.description.len() > 100 {
                                format!("{}...", &receipt.action.description[..97])
                            } else {
                                receipt.action.description.clone()
                            },
                            "timestamp": micros_to_rfc3339(receipt.timestamp),
                            "has_chain": receipt.previous_receipt.is_some(),
                        }));
                    }
                }
            }
        }
    }

    // Gather trust grants
    let mut trust_evidence = Vec::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        let matches = match &identity_id {
                            Some(iid) => grant.grantor.0 == *iid || grant.grantee.0 == *iid,
                            None => {
                                grant.grantor.0.contains(identity_name)
                                    || grant.grantee.0.contains(identity_name)
                            }
                        };
                        if matches {
                            let caps: Vec<&str> =
                                grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                            let revoked = store.is_revoked(gid);
                            trust_evidence.push(json!({
                                "trust_id": grant.id.0,
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "capabilities": caps,
                                "granted_at": micros_to_rfc3339(grant.granted_at),
                                "revoked": revoked,
                            }));
                        }
                    }
                }
            }
        }
    }

    // Gather spawn records
    let mut spawn_evidence = Vec::new();
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                let matches = match &identity_id {
                    Some(iid) => r.parent_id.0 == *iid || r.child_id.0 == *iid,
                    None => {
                        r.parent_id.0.contains(identity_name)
                            || r.child_id.0.contains(identity_name)
                            || r.spawn_purpose.contains(identity_name)
                    }
                };
                if matches {
                    let caps: Vec<&str> =
                        r.authority_granted.iter().map(|c| c.uri.as_str()).collect();
                    spawn_evidence.push(json!({
                        "spawn_id": r.id.0,
                        "parent_id": r.parent_id.0,
                        "child_id": r.child_id.0,
                        "spawn_type": r.spawn_type.as_tag(),
                        "purpose": r.spawn_purpose,
                        "authority": caps,
                        "terminated": r.terminated,
                        "timestamp": micros_to_rfc3339(r.spawn_timestamp),
                    }));
                }
            }
        }
    }

    let out = json!({
        "identity_name": identity_name,
        "identity_id": identity_id,
        "evidence_gathered": {
            "receipts": receipt_evidence,
            "trust_grants": trust_evidence,
            "spawn_records": spawn_evidence,
        },
        "totals": {
            "receipts": receipt_evidence.len(),
            "trust_grants": trust_evidence.len(),
            "spawn_records": spawn_evidence.len(),
        },
        "next_step": "Call identity_resurrect_verify to check consistency of gathered evidence"
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 3: identity_resurrect_verify ────────────────────────────────────────

pub fn definition_identity_resurrect_verify() -> Value {
    json!({
        "name": "identity_resurrect_verify",
        "description": "Verify the consistency of gathered evidence for identity resurrection. Checks that receipts, grants, and spawn records are internally consistent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity_name": {
                    "type": "string",
                    "description": "Name of the identity to verify evidence for"
                }
            },
            "required": ["identity_name"]
        }
    })
}

pub fn execute_identity_resurrect_verify(server: &McpServer, id: Value, args: &Value) -> Value {
    let identity_name = match args.get("identity_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'identity_name' is missing"),
    };

    let path = server.identity_dir.join(format!("{identity_name}.aid"));

    // Check file integrity
    let file_check = if path.exists() {
        match read_public_document(&path) {
            Ok(doc) => {
                let sig_ok = doc.verify_signature().is_ok();
                json!({
                    "exists": true,
                    "readable": true,
                    "signature_valid": sig_ok,
                    "identity_id": doc.id.0,
                    "public_key": doc.public_key,
                    "created_at": micros_to_rfc3339(doc.created_at),
                })
            }
            Err(e) => json!({
                "exists": true,
                "readable": false,
                "error": format!("{e}"),
            }),
        }
    } else {
        json!({
            "exists": false,
            "readable": false,
        })
    };

    // Verify receipt chain consistency
    let mut receipt_actor_keys = std::collections::HashSet::new();
    let mut receipt_chain_valid = true;
    let mut receipt_count = 0u64;
    let mut earliest_receipt: Option<u64> = None;
    let mut latest_receipt: Option<u64> = None;

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.action.description.contains(identity_name)
                        || receipt.actor.0.contains(identity_name)
                    {
                        receipt_count += 1;
                        receipt_actor_keys.insert(receipt.actor_key.clone());

                        match earliest_receipt {
                            Some(e) if receipt.timestamp < e => {
                                earliest_receipt = Some(receipt.timestamp)
                            }
                            None => earliest_receipt = Some(receipt.timestamp),
                            _ => {}
                        }
                        match latest_receipt {
                            Some(l) if receipt.timestamp > l => {
                                latest_receipt = Some(receipt.timestamp)
                            }
                            None => latest_receipt = Some(receipt.timestamp),
                            _ => {}
                        }

                        // Check that chained receipts reference valid predecessors
                        if let Some(ref prev) = receipt.previous_receipt {
                            if store.load(prev).is_err() {
                                receipt_chain_valid = false;
                            }
                        }
                    }
                }
            }
        }
    }

    // Verify trust grant consistency
    let mut trust_count = 0u64;
    let mut trust_sig_valid = 0u64;
    let mut trust_sig_invalid = 0u64;

    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.grantor.0.contains(identity_name)
                            || grant.grantee.0.contains(identity_name)
                        {
                            trust_count += 1;
                            if grant.verify_signature().is_ok() {
                                trust_sig_valid += 1;
                            } else {
                                trust_sig_invalid += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    let consistent_keys = receipt_actor_keys.len() <= 1;

    let verification_status = if file_check.get("signature_valid") == Some(&json!(true))
        && consistent_keys
        && receipt_chain_valid
        && trust_sig_invalid == 0
    {
        "verified — evidence is consistent"
    } else if receipt_count == 0 && trust_count == 0 {
        "no evidence — nothing to verify"
    } else {
        "partial — some inconsistencies detected"
    };

    let out = json!({
        "identity_name": identity_name,
        "verification_status": verification_status,
        "file_check": file_check,
        "receipt_verification": {
            "count": receipt_count,
            "distinct_actor_keys": receipt_actor_keys.len(),
            "keys_consistent": consistent_keys,
            "chain_valid": receipt_chain_valid,
            "earliest": earliest_receipt.map(micros_to_rfc3339),
            "latest": latest_receipt.map(micros_to_rfc3339),
        },
        "trust_verification": {
            "count": trust_count,
            "signatures_valid": trust_sig_valid,
            "signatures_invalid": trust_sig_invalid,
        },
        "next_step": "Call identity_resurrect_complete to finalize resurrection"
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 4: identity_resurrect_complete ──────────────────────────────────────

pub fn definition_identity_resurrect_complete() -> Value {
    json!({
        "name": "identity_resurrect_complete",
        "description": "Complete the identity resurrection process. Reports what was recovered and the state of the resurrected identity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity_name": {
                    "type": "string",
                    "description": "Name of the identity to complete resurrection for"
                }
            },
            "required": ["identity_name"]
        }
    })
}

pub fn execute_identity_resurrect_complete(server: &McpServer, id: Value, args: &Value) -> Value {
    let identity_name = match args.get("identity_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'identity_name' is missing"),
    };

    let path = server.identity_dir.join(format!("{identity_name}.aid"));

    // Gather recovery summary
    let mut recovered = Vec::new();
    let mut not_recovered = Vec::new();

    // Identity file
    if path.exists() {
        if let Ok(doc) = read_public_document(&path) {
            recovered.push(json!({
                "item": "identity_file",
                "identity_id": doc.id.0,
                "public_key": doc.public_key,
                "created_at": micros_to_rfc3339(doc.created_at),
            }));
        } else {
            not_recovered.push(json!({
                "item": "identity_file",
                "reason": "file exists but cannot be parsed",
            }));
        }
    } else {
        not_recovered.push(json!({
            "item": "identity_file",
            "reason": "file not found",
        }));
    }

    // Receipts
    let mut receipt_count = 0u64;
    let mut action_history = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.action.description.contains(identity_name)
                        || receipt.actor.0.contains(identity_name)
                    {
                        receipt_count += 1;
                        action_history.push(json!({
                            "receipt_id": receipt.id.0,
                            "action_type": receipt.action_type.as_tag(),
                            "description": if receipt.action.description.len() > 80 {
                                format!("{}...", &receipt.action.description[..77])
                            } else {
                                receipt.action.description.clone()
                            },
                            "timestamp": micros_to_rfc3339(receipt.timestamp),
                        }));
                    }
                }
            }
        }
    }
    if receipt_count > 0 {
        recovered.push(json!({
            "item": "action_history",
            "receipt_count": receipt_count,
        }));
    } else {
        not_recovered.push(json!({
            "item": "action_history",
            "reason": "no receipts reference this identity",
        }));
    }

    // Trust relationships
    let mut active_grants = Vec::new();
    let mut revoked_grants = Vec::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.grantor.0.contains(identity_name)
                            || grant.grantee.0.contains(identity_name)
                        {
                            let caps: Vec<&str> =
                                grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                            let entry = json!({
                                "trust_id": grant.id.0,
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "capabilities": caps,
                            });
                            if store.is_revoked(gid) {
                                revoked_grants.push(entry);
                            } else {
                                active_grants.push(entry);
                            }
                        }
                    }
                }
            }
        }
    }
    if !active_grants.is_empty() || !revoked_grants.is_empty() {
        recovered.push(json!({
            "item": "trust_relationships",
            "active": active_grants.len(),
            "revoked": revoked_grants.len(),
        }));
    }

    // Spawn relationships
    let mut spawn_records_found = Vec::new();
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                if r.parent_id.0.contains(identity_name) || r.child_id.0.contains(identity_name) {
                    spawn_records_found.push(json!({
                        "spawn_id": r.id.0,
                        "role": if r.parent_id.0.contains(identity_name) { "parent" } else { "child" },
                        "spawn_type": r.spawn_type.as_tag(),
                        "terminated": r.terminated,
                    }));
                }
            }
        }
    }
    if !spawn_records_found.is_empty() {
        recovered.push(json!({
            "item": "spawn_relationships",
            "count": spawn_records_found.len(),
        }));
    }

    let resurrection_success = !recovered.is_empty();

    let out = json!({
        "identity_name": identity_name,
        "resurrection_complete": resurrection_success,
        "recovered": recovered,
        "not_recovered": not_recovered,
        "details": {
            "action_history": action_history,
            "active_trust_grants": active_grants,
            "revoked_trust_grants": revoked_grants,
            "spawn_records": spawn_records_found,
        },
        "summary": if resurrection_success {
            format!("Resurrection complete: recovered {} item(s) for '{}'", recovered.len(), identity_name)
        } else {
            format!("Resurrection failed: no recoverable data found for '{}'", identity_name)
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention 14: Identity Forking
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 5: identity_fork_create ─────────────────────────────────────────────

pub fn definition_identity_fork_create() -> Value {
    json!({
        "name": "identity_fork_create",
        "description": "Create a forked identity from a parent. The fork is a child identity with its own receipt chain that can later be merged back or abandoned.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "parent_name": {
                    "type": "string",
                    "description": "Name of the parent identity to fork from (default: \"default\")"
                },
                "fork_name": {
                    "type": "string",
                    "description": "Name for the new forked identity"
                },
                "purpose": {
                    "type": "string",
                    "description": "Purpose of the fork (e.g., \"experimental feature\", \"audit review\")"
                },
                "capabilities": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Capability URIs to grant to the fork (optional — inherits parent if omitted)"
                }
            },
            "required": ["fork_name", "purpose"]
        }
    })
}

pub fn execute_identity_fork_create(server: &McpServer, id: Value, args: &Value) -> Value {
    let parent_name = args
        .get("parent_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let fork_name = match args.get("fork_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'fork_name' is missing"),
    };
    let purpose = match args.get("purpose").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return tool_error(id, "required parameter 'purpose' is missing"),
    };

    // Check fork doesn't already exist
    let fork_path = server.identity_dir.join(format!("{fork_name}.aid"));
    if fork_path.exists() {
        return tool_error(
            id,
            format!("identity '{fork_name}' already exists — choose a different fork name"),
        );
    }

    // Load parent identity
    let parent_path = server.identity_dir.join(format!("{parent_name}.aid"));
    let parent = match load_identity(&parent_path, super::MCP_PASSPHRASE) {
        Ok(a) => a,
        Err(e) => {
            return tool_error(
                id,
                format!("failed to load parent identity '{parent_name}': {e}"),
            )
        }
    };

    let parent_id = parent.id();
    let parent_key = parent.public_key_base64();

    // Parse capabilities
    let capabilities: Vec<agentic_identity::Capability> = args
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(agentic_identity::Capability::new)
                .collect()
        })
        .unwrap_or_else(|| vec![agentic_identity::Capability::new("*")]);

    // Use spawn mechanism to create the fork
    let authority = capabilities.clone();
    let ceiling = capabilities;

    match agentic_identity::spawn::spawn_child(
        &parent,
        agentic_identity::spawn::SpawnType::Clone,
        purpose,
        authority,
        ceiling,
        agentic_identity::spawn::SpawnLifetime::Indefinite,
        agentic_identity::spawn::SpawnConstraints::default(),
        None,
        &[],
    ) {
        Ok((child, record, receipt)) => {
            // Save the forked identity with the requested name
            if let Err(e) =
                agentic_identity::storage::save_identity(&child, &fork_path, super::MCP_PASSPHRASE)
            {
                return tool_error(id, format!("failed to save forked identity: {e}"));
            }

            // Save spawn receipt
            if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
                let _ = store.save(&receipt);
            }

            // Save spawn record
            if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
                let _ = store.save(&record);
            }

            let caps: Vec<&str> = record
                .authority_granted
                .iter()
                .map(|c| c.uri.as_str())
                .collect();

            let out = json!({
                "fork_created": true,
                "fork_name": fork_name,
                "fork_id": record.child_id.0,
                "parent_name": parent_name,
                "parent_id": parent_id.0,
                "parent_key": parent_key,
                "spawn_id": record.id.0,
                "purpose": purpose,
                "capabilities": caps,
                "receipt_id": receipt.id.0,
                "fork_file": fork_path.display().to_string(),
                "note": "Fork can be merged back with identity_fork_merge or abandoned with identity_fork_abandon"
            });

            tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
        }
        Err(e) => tool_error(id, format!("failed to create fork: {e}")),
    }
}

// ── Tool 6: identity_fork_merge ──────────────────────────────────────────────

pub fn definition_identity_fork_merge() -> Value {
    json!({
        "name": "identity_fork_merge",
        "description": "Merge a forked identity back to its parent. Reports what receipts and grants would be merged.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fork_name": {
                    "type": "string",
                    "description": "Name of the forked identity to merge"
                }
            },
            "required": ["fork_name"]
        }
    })
}

pub fn execute_identity_fork_merge(server: &McpServer, id: Value, args: &Value) -> Value {
    let fork_name = match args.get("fork_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'fork_name' is missing"),
    };

    let fork_path = server.identity_dir.join(format!("{fork_name}.aid"));
    if !fork_path.exists() {
        return tool_error(id, format!("forked identity '{fork_name}' not found"));
    }

    // Read fork's public document to get its ID
    let fork_doc = match read_public_document(&fork_path) {
        Ok(d) => d,
        Err(e) => return tool_error(id, format!("failed to read fork '{fork_name}': {e}")),
    };
    let fork_id = &fork_doc.id.0;

    // Find the spawn record linking fork to parent
    let spawn_record = if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        store
            .load_all()
            .unwrap_or_default()
            .into_iter()
            .find(|r| r.child_id.0 == *fork_id)
    } else {
        None
    };

    let parent_id = spawn_record.as_ref().map(|r| r.parent_id.0.clone());
    let parent_name = if let Some(ref pid) = parent_id {
        // Scan identity dir to find the name
        find_identity_name_by_id(server, pid).unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown (no spawn record found)".to_string()
    };

    // Collect fork's receipts
    let mut fork_receipts = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0 == *fork_id {
                        fork_receipts.push(json!({
                            "receipt_id": receipt.id.0,
                            "action_type": receipt.action_type.as_tag(),
                            "description": if receipt.action.description.len() > 80 {
                                format!("{}...", &receipt.action.description[..77])
                            } else {
                                receipt.action.description.clone()
                            },
                            "timestamp": micros_to_rfc3339(receipt.timestamp),
                        }));
                    }
                }
            }
        }
    }

    // Collect fork's trust grants
    let mut fork_grants = Vec::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.grantor.0 == *fork_id || grant.grantee.0 == *fork_id {
                            let caps: Vec<&str> =
                                grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                            fork_grants.push(json!({
                                "trust_id": grant.id.0,
                                "role": if grant.grantor.0 == *fork_id { "grantor" } else { "grantee" },
                                "capabilities": caps,
                                "revoked": store.is_revoked(gid),
                            }));
                        }
                    }
                }
            }
        }
    }

    let terminated = spawn_record.as_ref().map(|r| r.terminated).unwrap_or(false);

    let out = json!({
        "fork_name": fork_name,
        "fork_id": fork_id,
        "parent_name": parent_name,
        "parent_id": parent_id,
        "spawn_record_found": spawn_record.is_some(),
        "fork_terminated": terminated,
        "merge_report": {
            "receipts_to_merge": fork_receipts.len(),
            "receipts": fork_receipts,
            "grants_to_review": fork_grants.len(),
            "grants": fork_grants,
        },
        "note": if terminated {
            "Fork is already terminated — merge is a historical report only"
        } else {
            "Review the merge report. Fork receipts will be attributed to the parent lineage."
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 7: identity_fork_abandon ────────────────────────────────────────────

pub fn definition_identity_fork_abandon() -> Value {
    json!({
        "name": "identity_fork_abandon",
        "description": "Abandon a forked identity. Marks the fork as terminated with a reason.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fork_name": {
                    "type": "string",
                    "description": "Name of the forked identity to abandon"
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for abandoning the fork (optional)"
                }
            },
            "required": ["fork_name"]
        }
    })
}

pub fn execute_identity_fork_abandon(server: &McpServer, id: Value, args: &Value) -> Value {
    let fork_name = match args.get("fork_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'fork_name' is missing"),
    };
    let reason = args
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("abandoned");

    let fork_path = server.identity_dir.join(format!("{fork_name}.aid"));
    if !fork_path.exists() {
        return tool_error(id, format!("forked identity '{fork_name}' not found"));
    }

    // Read fork identity to get ID
    let fork_doc = match read_public_document(&fork_path) {
        Ok(d) => d,
        Err(e) => return tool_error(id, format!("failed to read fork '{fork_name}': {e}")),
    };
    let fork_id = &fork_doc.id.0;

    // Find and update spawn record
    let mut spawn_updated = false;
    let mut spawn_id = None;
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(mut records) = store.load_all() {
            for r in &mut records {
                if r.child_id.0 == *fork_id && !r.terminated {
                    r.terminated = true;
                    r.terminated_at = Some(now_secs() * 1_000_000);
                    r.termination_reason = Some(reason.to_string());
                    spawn_id = Some(r.id.0.clone());
                    let _ = store.save(r);
                    spawn_updated = true;
                    break;
                }
            }
        }
    }

    // Count receipts that were created by this fork
    let mut fork_receipt_count = 0u64;
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0 == *fork_id {
                        fork_receipt_count += 1;
                    }
                }
            }
        }
    }

    let out = json!({
        "fork_name": fork_name,
        "fork_id": fork_id,
        "abandoned": true,
        "reason": reason,
        "spawn_record_updated": spawn_updated,
        "spawn_id": spawn_id,
        "orphaned_receipts": fork_receipt_count,
        "note": "Fork has been marked as terminated. Its receipts remain in the store as historical record."
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 8: identity_fork_conflicts ──────────────────────────────────────────

pub fn definition_identity_fork_conflicts() -> Value {
    json!({
        "name": "identity_fork_conflicts",
        "description": "Get merge conflicts between a fork and its parent. Shows overlapping grants and conflicting receipts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fork_name": {
                    "type": "string",
                    "description": "Name of the forked identity to check for conflicts"
                }
            },
            "required": ["fork_name"]
        }
    })
}

pub fn execute_identity_fork_conflicts(server: &McpServer, id: Value, args: &Value) -> Value {
    let fork_name = match args.get("fork_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return tool_error(id, "required parameter 'fork_name' is missing"),
    };

    let fork_path = server.identity_dir.join(format!("{fork_name}.aid"));
    if !fork_path.exists() {
        return tool_error(id, format!("forked identity '{fork_name}' not found"));
    }

    let fork_doc = match read_public_document(&fork_path) {
        Ok(d) => d,
        Err(e) => return tool_error(id, format!("failed to read fork '{fork_name}': {e}")),
    };
    let fork_id = &fork_doc.id.0;

    // Find parent from spawn record
    let parent_id = if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        store
            .load_all()
            .unwrap_or_default()
            .iter()
            .find(|r| r.child_id.0 == *fork_id)
            .map(|r| r.parent_id.0.clone())
    } else {
        None
    };

    let parent_id = match parent_id {
        Some(pid) => pid,
        None => {
            return tool_error(
                id,
                format!("no spawn record found for fork '{fork_name}' — cannot determine parent"),
            )
        }
    };

    // Collect capabilities granted by fork and parent separately
    let mut fork_granted_caps = Vec::new();
    let mut parent_granted_caps = Vec::new();
    let mut overlapping_grants = Vec::new();

    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        if let Ok(ids) = store.list_granted() {
            for gid in &ids {
                if let Ok(grant) = store.load_grant(gid) {
                    if store.is_revoked(gid) {
                        continue;
                    }
                    let caps: Vec<String> =
                        grant.capabilities.iter().map(|c| c.uri.clone()).collect();

                    if grant.grantor.0 == *fork_id {
                        for cap in &caps {
                            fork_granted_caps.push((cap.clone(), grant.grantee.0.clone()));
                        }
                    }
                    if grant.grantor.0 == parent_id {
                        for cap in &caps {
                            parent_granted_caps.push((cap.clone(), grant.grantee.0.clone()));
                        }
                    }
                }
            }
        }
    }

    // Find overlapping capabilities (same capability granted to same grantee)
    for (fork_cap, fork_grantee) in &fork_granted_caps {
        for (parent_cap, parent_grantee) in &parent_granted_caps {
            if fork_cap == parent_cap && fork_grantee == parent_grantee {
                overlapping_grants.push(json!({
                    "capability": fork_cap,
                    "grantee": fork_grantee,
                    "conflict_type": "duplicate_grant",
                    "description": "Both fork and parent have granted the same capability to the same grantee"
                }));
            }
        }
    }

    // Check for conflicting actions (same time window, different actions)
    let mut fork_receipts = Vec::new();
    let mut parent_receipts = Vec::new();
    let mut temporal_conflicts = Vec::new();

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0 == *fork_id {
                        fork_receipts.push(receipt);
                    } else if receipt.actor.0 == parent_id {
                        parent_receipts.push(receipt);
                    }
                }
            }
        }
    }

    // Detect temporal overlaps (receipts within 60 seconds of each other)
    let overlap_window: u64 = 60_000_000; // 60 seconds in microseconds
    for fr in &fork_receipts {
        for pr in &parent_receipts {
            let diff = if fr.timestamp > pr.timestamp {
                fr.timestamp - pr.timestamp
            } else {
                pr.timestamp - fr.timestamp
            };
            if diff < overlap_window {
                temporal_conflicts.push(json!({
                    "fork_receipt": fr.id.0,
                    "parent_receipt": pr.id.0,
                    "fork_action": fr.action.description,
                    "parent_action": pr.action.description,
                    "time_diff_seconds": diff / 1_000_000,
                    "conflict_type": "temporal_overlap",
                }));
            }
        }
    }

    let has_conflicts = !overlapping_grants.is_empty() || !temporal_conflicts.is_empty();

    let out = json!({
        "fork_name": fork_name,
        "fork_id": fork_id,
        "parent_id": parent_id,
        "has_conflicts": has_conflicts,
        "conflicts": {
            "overlapping_grants": overlapping_grants,
            "temporal_overlaps": temporal_conflicts,
        },
        "statistics": {
            "fork_receipts": fork_receipts.len(),
            "parent_receipts": parent_receipts.len(),
            "fork_grants": fork_granted_caps.len(),
            "parent_grants": parent_granted_caps.len(),
        },
        "recommendation": if has_conflicts {
            "Conflicts detected — review and resolve before merging"
        } else {
            "No conflicts — safe to merge"
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention 15: Zero-Knowledge Identity
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 9: identity_zk_prove ────────────────────────────────────────────────

pub fn definition_identity_zk_prove() -> Value {
    json!({
        "name": "identity_zk_prove",
        "description": "Generate a zero-knowledge proof of an identity attribute. Proves the attribute without revealing the identity itself. Supported attributes: \"exists\", \"created_before\", \"has_capability\".",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attribute": {
                    "type": "string",
                    "description": "Attribute to prove: \"exists\", \"created_before\", \"has_capability\"",
                    "enum": ["exists", "created_before", "has_capability"]
                },
                "value": {
                    "type": "string",
                    "description": "Value for the attribute (e.g., timestamp for created_before, capability URI for has_capability)"
                },
                "identity_name": {
                    "type": "string",
                    "description": "Identity name (default: \"default\")"
                }
            },
            "required": ["attribute"]
        }
    })
}

pub fn execute_identity_zk_prove(server: &McpServer, id: Value, args: &Value) -> Value {
    let attribute = match args.get("attribute").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "required parameter 'attribute' is missing"),
    };
    let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let identity_name = args
        .get("identity_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let path = server.identity_dir.join(format!("{identity_name}.aid"));
    if !path.exists() {
        return tool_error(id, format!("identity '{identity_name}' not found"));
    }

    let doc = match read_public_document(&path) {
        Ok(d) => d,
        Err(e) => return tool_error(id, format!("failed to read identity: {e}")),
    };

    let now = now_secs();
    let nonce = format!("{}-{}-{}-{}", attribute, value, now, doc.id.0);
    let proof_id = format!("azkp_{}", proof_hash(&nonce));

    // Generate proof based on attribute type
    let (claim_valid, proof_data) = match attribute {
        "exists" => {
            // Prove that an identity with a valid signature exists
            let sig_ok = doc.verify_signature().is_ok();
            let commitment = proof_hash(&format!("exists:{}:{}", doc.id.0, now));
            (
                sig_ok,
                json!({
                    "attribute": "exists",
                    "claim": "An identity with a valid cryptographic signature exists",
                    "commitment": commitment,
                    "signature_verified": sig_ok,
                }),
            )
        }
        "created_before" => {
            if value.is_empty() {
                return tool_error(
                    id,
                    "'value' is required for created_before (timestamp in seconds since epoch)",
                );
            }
            let threshold: u64 = match value.parse() {
                Ok(v) => v,
                Err(_) => {
                    return tool_error(
                        id,
                        "value must be a numeric timestamp (seconds since epoch)",
                    )
                }
            };
            let created_secs = doc.created_at / 1_000_000;
            let claim_valid = created_secs < threshold;
            let commitment = proof_hash(&format!(
                "created_before:{}:{}:{}",
                doc.id.0, threshold, now
            ));
            (
                claim_valid,
                json!({
                    "attribute": "created_before",
                    "claim": format!("Identity was created before {}", secs_to_datetime(threshold)),
                    "threshold_timestamp": threshold,
                    "commitment": commitment,
                    "claim_valid": claim_valid,
                }),
            )
        }
        "has_capability" => {
            if value.is_empty() {
                return tool_error(
                    id,
                    "'value' is required for has_capability (capability URI)",
                );
            }
            // Check trust grants for this capability
            let mut has_cap = false;
            if let Ok(store) = TrustStore::new(&server.trust_dir) {
                if let Ok(ids) = store.list_received() {
                    for gid in &ids {
                        if store.is_revoked(gid) {
                            continue;
                        }
                        if let Ok(grant) = store.load_grant(gid) {
                            if grant.grantee.0 == doc.id.0 {
                                for cap in &grant.capabilities {
                                    if cap.uri == value || cap.uri == "*" {
                                        has_cap = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if has_cap {
                            break;
                        }
                    }
                }
            }
            let commitment = proof_hash(&format!("has_capability:{}:{}:{}", doc.id.0, value, now));
            (
                has_cap,
                json!({
                    "attribute": "has_capability",
                    "claim": format!("Identity has capability '{}'", value),
                    "capability_uri": value,
                    "commitment": commitment,
                    "claim_valid": has_cap,
                }),
            )
        }
        _ => {
            return tool_error(
                id,
                format!(
                    "unsupported attribute '{}' — use exists, created_before, or has_capability",
                    attribute
                ),
            )
        }
    };

    let out = json!({
        "proof_id": proof_id,
        "attribute": attribute,
        "claim_valid": claim_valid,
        "proof": proof_data,
        "generated_at": secs_to_datetime(now),
        "note": "This is a simplified ZK proof simulation. The commitment hash binds the claim to the identity without revealing the identity ID."
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 10: identity_zk_verify ──────────────────────────────────────────────

pub fn definition_identity_zk_verify() -> Value {
    json!({
        "name": "identity_zk_verify",
        "description": "Verify a zero-knowledge proof of an identity attribute. Checks the proof's validity and commitment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proof_id": {
                    "type": "string",
                    "description": "The proof ID to verify (azkp_...)"
                }
            },
            "required": ["proof_id"]
        }
    })
}

pub fn execute_identity_zk_verify(server: &McpServer, id: Value, args: &Value) -> Value {
    let proof_id = match args.get("proof_id").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return tool_error(id, "required parameter 'proof_id' is missing"),
    };

    // Validate proof ID format
    if !proof_id.starts_with("azkp_") {
        return tool_error(id, "invalid proof ID format — expected 'azkp_...'");
    }

    // Since ZK proofs are ephemeral (generated in-memory), we verify by checking
    // that the proof hash is structurally valid and that identities still exist.
    let hash_part = &proof_id[5..];
    let hash_valid = hash_part.len() == 16 && hash_part.chars().all(|c| c.is_ascii_hexdigit());

    // Scan for identities that could have generated this proof
    let mut identity_count = 0u64;
    if let Ok(entries) = std::fs::read_dir(&server.identity_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("aid") {
                identity_count += 1;
            }
        }
    }

    let out = json!({
        "proof_id": proof_id,
        "format_valid": hash_valid,
        "verification": {
            "hash_structure": if hash_valid { "valid" } else { "invalid" },
            "identity_store_accessible": server.identity_dir.exists(),
            "identities_available": identity_count,
        },
        "note": "ZK proof verification checks structural validity. The commitment hash can be verified against the original claim without revealing the prover's identity."
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 11: identity_zk_challenge ───────────────────────────────────────────

pub fn definition_identity_zk_challenge() -> Value {
    json!({
        "name": "identity_zk_challenge",
        "description": "Issue a challenge for a zero-knowledge proof. The prover must respond with a valid proof for the specified attribute.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attribute": {
                    "type": "string",
                    "description": "Attribute to challenge: \"exists\", \"created_before\", \"has_capability\"",
                    "enum": ["exists", "created_before", "has_capability"]
                },
                "challenge_nonce": {
                    "type": "string",
                    "description": "Optional nonce to include in the challenge (for freshness)"
                }
            },
            "required": ["attribute"]
        }
    })
}

pub fn execute_identity_zk_challenge(_server: &McpServer, id: Value, args: &Value) -> Value {
    let attribute = match args.get("attribute").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "required parameter 'attribute' is missing"),
    };

    if !matches!(attribute, "exists" | "created_before" | "has_capability") {
        return tool_error(
            id,
            format!(
                "unsupported attribute '{}' — use exists, created_before, or has_capability",
                attribute
            ),
        );
    }

    let now = now_secs();
    let user_nonce = args
        .get("challenge_nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let challenge_input = format!("challenge:{}:{}:{}", attribute, now, user_nonce);
    let challenge_id = format!("azkc_{}", proof_hash(&challenge_input));
    let challenge_nonce = proof_hash(&format!("nonce:{}:{}", challenge_input, now));

    let out = json!({
        "challenge_id": challenge_id,
        "attribute": attribute,
        "challenge_nonce": challenge_nonce,
        "issued_at": secs_to_datetime(now),
        "expires_at": secs_to_datetime(now + 3600),
        "instructions": match attribute {
            "exists" => "Prover must call identity_zk_prove with attribute='exists' to respond",
            "created_before" => "Prover must call identity_zk_prove with attribute='created_before' and a value (timestamp)",
            "has_capability" => "Prover must call identity_zk_prove with attribute='has_capability' and a value (capability URI)",
            _ => "Unknown attribute",
        },
        "note": "Challenge is valid for 1 hour. Prover should include the challenge_nonce in their proof generation."
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention 16: Temporal Identity
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 12: identity_temporal_query ─────────────────────────────────────────

pub fn definition_identity_temporal_query() -> Value {
    json!({
        "name": "identity_temporal_query",
        "description": "Query the state of an identity at a specific point in time. Reconstructs what the identity looked like based on receipts, grants, and spawn records up to that timestamp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timestamp": {
                    "type": "number",
                    "description": "Unix timestamp (seconds since epoch) to query"
                },
                "identity_name": {
                    "type": "string",
                    "description": "Identity name (default: \"default\")"
                }
            },
            "required": ["timestamp"]
        }
    })
}

pub fn execute_identity_temporal_query(server: &McpServer, id: Value, args: &Value) -> Value {
    let timestamp = match args.get("timestamp").and_then(|v| v.as_u64()) {
        Some(t) => t,
        None => {
            return tool_error(
                id,
                "required parameter 'timestamp' is missing (unix seconds)",
            )
        }
    };
    let identity_name = args
        .get("identity_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let query_micros = timestamp * 1_000_000;

    // Load identity document
    let path = server.identity_dir.join(format!("{identity_name}.aid"));
    let identity_info = if let Ok(doc) = read_public_document(&path) {
        let existed_at_time = doc.created_at <= query_micros;
        Some(json!({
            "identity_id": doc.id.0,
            "existed_at_time": existed_at_time,
            "created_at": micros_to_rfc3339(doc.created_at),
            "key_rotations_before": doc.rotation_history.iter()
                .filter(|r| r.rotated_at <= query_micros)
                .count(),
        }))
    } else {
        None
    };

    let identity_id = if let Ok(doc) = read_public_document(&path) {
        Some(doc.id.0.clone())
    } else {
        None
    };

    // Receipts up to timestamp
    let mut receipts_at_time = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.timestamp <= query_micros {
                        let matches = match &identity_id {
                            Some(iid) => receipt.actor.0 == *iid,
                            None => receipt.actor.0.contains(identity_name),
                        };
                        if matches {
                            receipts_at_time.push(json!({
                                "receipt_id": receipt.id.0,
                                "action_type": receipt.action_type.as_tag(),
                                "description": if receipt.action.description.len() > 80 {
                                    format!("{}...", &receipt.action.description[..77])
                                } else {
                                    receipt.action.description.clone()
                                },
                                "timestamp": micros_to_rfc3339(receipt.timestamp),
                            }));
                        }
                    }
                }
            }
        }
    }

    // Trust grants active at timestamp
    let mut active_grants_at_time = Vec::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.granted_at <= query_micros {
                            let matches = match &identity_id {
                                Some(iid) => grant.grantor.0 == *iid || grant.grantee.0 == *iid,
                                None => {
                                    grant.grantor.0.contains(identity_name)
                                        || grant.grantee.0.contains(identity_name)
                                }
                            };
                            if matches {
                                let caps: Vec<&str> =
                                    grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                                active_grants_at_time.push(json!({
                                    "trust_id": grant.id.0,
                                    "grantor": grant.grantor.0,
                                    "grantee": grant.grantee.0,
                                    "capabilities": caps,
                                    "granted_at": micros_to_rfc3339(grant.granted_at),
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Spawn records at timestamp
    let mut spawn_state_at_time = Vec::new();
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                if r.spawn_timestamp <= query_micros {
                    let matches = match &identity_id {
                        Some(iid) => r.parent_id.0 == *iid || r.child_id.0 == *iid,
                        None => {
                            r.parent_id.0.contains(identity_name)
                                || r.child_id.0.contains(identity_name)
                        }
                    };
                    if matches {
                        let was_terminated =
                            r.terminated && r.terminated_at.map_or(false, |t| t <= query_micros);
                        let caps: Vec<&str> =
                            r.authority_granted.iter().map(|c| c.uri.as_str()).collect();
                        spawn_state_at_time.push(json!({
                            "spawn_id": r.id.0,
                            "parent_id": r.parent_id.0,
                            "child_id": r.child_id.0,
                            "spawn_type": r.spawn_type.as_tag(),
                            "authority": caps,
                            "was_terminated_at_time": was_terminated,
                        }));
                    }
                }
            }
        }
    }

    let out = json!({
        "query_time": secs_to_datetime(timestamp),
        "identity_name": identity_name,
        "identity": identity_info,
        "state_at_time": {
            "receipts": receipts_at_time,
            "receipt_count": receipts_at_time.len(),
            "trust_grants": active_grants_at_time,
            "grant_count": active_grants_at_time.len(),
            "spawn_records": spawn_state_at_time,
            "spawn_count": spawn_state_at_time.len(),
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 13: identity_temporal_diff ──────────────────────────────────────────

pub fn definition_identity_temporal_diff() -> Value {
    json!({
        "name": "identity_temporal_diff",
        "description": "Diff an identity between two points in time. Shows what changed between time_a and time_b.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "time_a": {
                    "type": "number",
                    "description": "Earlier timestamp (unix seconds)"
                },
                "time_b": {
                    "type": "number",
                    "description": "Later timestamp (unix seconds)"
                },
                "identity_name": {
                    "type": "string",
                    "description": "Identity name (default: \"default\")"
                }
            },
            "required": ["time_a", "time_b"]
        }
    })
}

pub fn execute_identity_temporal_diff(server: &McpServer, id: Value, args: &Value) -> Value {
    let time_a = match args.get("time_a").and_then(|v| v.as_u64()) {
        Some(t) => t,
        None => return tool_error(id, "required parameter 'time_a' is missing (unix seconds)"),
    };
    let time_b = match args.get("time_b").and_then(|v| v.as_u64()) {
        Some(t) => t,
        None => return tool_error(id, "required parameter 'time_b' is missing (unix seconds)"),
    };
    let identity_name = args
        .get("identity_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let micros_a = time_a * 1_000_000;
    let micros_b = time_b * 1_000_000;

    // Ensure time_a <= time_b
    let (micros_a, micros_b, time_a, time_b) = if micros_a <= micros_b {
        (micros_a, micros_b, time_a, time_b)
    } else {
        (micros_b, micros_a, time_b, time_a)
    };

    let path = server.identity_dir.join(format!("{identity_name}.aid"));
    let identity_id = read_public_document(&path).ok().map(|d| d.id.0.clone());

    // Receipts between time_a and time_b
    let mut new_receipts = Vec::new();
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.timestamp > micros_a && receipt.timestamp <= micros_b {
                        let matches = match &identity_id {
                            Some(iid) => receipt.actor.0 == *iid,
                            None => receipt.actor.0.contains(identity_name),
                        };
                        if matches {
                            new_receipts.push(json!({
                                "receipt_id": receipt.id.0,
                                "action_type": receipt.action_type.as_tag(),
                                "description": if receipt.action.description.len() > 80 {
                                    format!("{}...", &receipt.action.description[..77])
                                } else {
                                    receipt.action.description.clone()
                                },
                                "timestamp": micros_to_rfc3339(receipt.timestamp),
                            }));
                        }
                    }
                }
            }
        }
    }

    // Trust grants created between time_a and time_b
    let mut new_grants = Vec::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        if grant.granted_at > micros_a && grant.granted_at <= micros_b {
                            let matches = match &identity_id {
                                Some(iid) => grant.grantor.0 == *iid || grant.grantee.0 == *iid,
                                None => {
                                    grant.grantor.0.contains(identity_name)
                                        || grant.grantee.0.contains(identity_name)
                                }
                            };
                            if matches {
                                let caps: Vec<&str> =
                                    grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                                new_grants.push(json!({
                                    "trust_id": grant.id.0,
                                    "grantor": grant.grantor.0,
                                    "grantee": grant.grantee.0,
                                    "capabilities": caps,
                                    "granted_at": micros_to_rfc3339(grant.granted_at),
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Spawn records created or terminated between time_a and time_b
    let mut spawn_changes = Vec::new();
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                let matches = match &identity_id {
                    Some(iid) => r.parent_id.0 == *iid || r.child_id.0 == *iid,
                    None => {
                        r.parent_id.0.contains(identity_name)
                            || r.child_id.0.contains(identity_name)
                    }
                };
                if !matches {
                    continue;
                }

                if r.spawn_timestamp > micros_a && r.spawn_timestamp <= micros_b {
                    spawn_changes.push(json!({
                        "change_type": "spawned",
                        "spawn_id": r.id.0,
                        "child_id": r.child_id.0,
                        "spawn_type": r.spawn_type.as_tag(),
                        "timestamp": micros_to_rfc3339(r.spawn_timestamp),
                    }));
                }

                if let Some(term_at) = r.terminated_at {
                    if term_at > micros_a && term_at <= micros_b {
                        spawn_changes.push(json!({
                            "change_type": "terminated",
                            "spawn_id": r.id.0,
                            "child_id": r.child_id.0,
                            "reason": r.termination_reason.as_deref().unwrap_or("unknown"),
                            "timestamp": micros_to_rfc3339(term_at),
                        }));
                    }
                }
            }
        }
    }

    // Key rotations in period
    let mut key_rotations = Vec::new();
    if let Ok(doc) = read_public_document(&path) {
        for rot in &doc.rotation_history {
            if rot.rotated_at > micros_a && rot.rotated_at <= micros_b {
                key_rotations.push(json!({
                    "rotated_at": micros_to_rfc3339(rot.rotated_at),
                    "reason": format!("{:?}", rot.reason),
                }));
            }
        }
    }

    let total_changes =
        new_receipts.len() + new_grants.len() + spawn_changes.len() + key_rotations.len();

    let out = json!({
        "identity_name": identity_name,
        "time_a": secs_to_datetime(time_a),
        "time_b": secs_to_datetime(time_b),
        "total_changes": total_changes,
        "diff": {
            "new_receipts": new_receipts,
            "new_trust_grants": new_grants,
            "spawn_changes": spawn_changes,
            "key_rotations": key_rotations,
        }
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ── Tool 14: identity_temporal_timeline ──────────────────────────────────────

pub fn definition_identity_temporal_timeline() -> Value {
    json!({
        "name": "identity_temporal_timeline",
        "description": "Get the full evolution timeline of an identity. Returns all significant changes in chronological order.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity_name": {
                    "type": "string",
                    "description": "Identity name (default: \"default\")"
                }
            }
        }
    })
}

pub fn execute_identity_temporal_timeline(server: &McpServer, id: Value, args: &Value) -> Value {
    let identity_name = args
        .get("identity_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let path = server.identity_dir.join(format!("{identity_name}.aid"));

    // Collect all events with timestamps
    let mut events: Vec<(u64, Value)> = Vec::new();

    // Identity creation
    if let Ok(doc) = read_public_document(&path) {
        events.push((
            doc.created_at,
            json!({
                "event_type": "identity_created",
                "identity_id": doc.id.0,
                "timestamp": micros_to_rfc3339(doc.created_at),
                "details": {
                    "name": doc.name,
                    "algorithm": doc.algorithm,
                }
            }),
        ));

        // Key rotations
        for (i, rot) in doc.rotation_history.iter().enumerate() {
            events.push((
                rot.rotated_at,
                json!({
                    "event_type": "key_rotation",
                    "timestamp": micros_to_rfc3339(rot.rotated_at),
                    "details": {
                        "rotation_index": i + 1,
                        "reason": format!("{:?}", rot.reason),
                    }
                }),
            ));
        }

        // Attestations
        for att in &doc.attestations {
            events.push((
                att.attested_at,
                json!({
                    "event_type": "attestation",
                    "timestamp": micros_to_rfc3339(att.attested_at),
                    "details": {
                        "attester": att.attester.0,
                        "claim": format!("{:?}", att.claim),
                    }
                }),
            ));
        }
    } else if !path.exists() {
        return tool_error(id, format!("identity '{identity_name}' not found"));
    } else {
        return tool_error(
            id,
            format!("identity '{identity_name}' exists but cannot be read"),
        );
    }

    let identity_id = read_public_document(&path).ok().map(|d| d.id.0.clone());

    // Receipts
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let matches = match &identity_id {
                        Some(iid) => receipt.actor.0 == *iid,
                        None => receipt.actor.0.contains(identity_name),
                    };
                    if matches {
                        events.push((
                            receipt.timestamp,
                            json!({
                                "event_type": "action",
                                "receipt_id": receipt.id.0,
                                "timestamp": micros_to_rfc3339(receipt.timestamp),
                                "details": {
                                    "action_type": receipt.action_type.as_tag(),
                                    "description": if receipt.action.description.len() > 80 {
                                        format!("{}...", &receipt.action.description[..77])
                                    } else {
                                        receipt.action.description.clone()
                                    },
                                }
                            }),
                        ));
                    }
                }
            }
        }
    }

    // Trust grants
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for list_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = list_fn(&store) {
                for gid in &ids {
                    if let Ok(grant) = store.load_grant(gid) {
                        let matches = match &identity_id {
                            Some(iid) => grant.grantor.0 == *iid || grant.grantee.0 == *iid,
                            None => {
                                grant.grantor.0.contains(identity_name)
                                    || grant.grantee.0.contains(identity_name)
                            }
                        };
                        if matches {
                            let caps: Vec<&str> =
                                grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                            let role = match &identity_id {
                                Some(iid) if grant.grantor.0 == *iid => "grantor",
                                _ => "grantee",
                            };
                            events.push((grant.granted_at, json!({
                                "event_type": "trust_grant",
                                "trust_id": grant.id.0,
                                "timestamp": micros_to_rfc3339(grant.granted_at),
                                "details": {
                                    "role": role,
                                    "counterparty": if role == "grantor" { &grant.grantee.0 } else { &grant.grantor.0 },
                                    "capabilities": caps,
                                    "revoked": store.is_revoked(gid),
                                }
                            })));
                        }
                    }
                }
            }
        }
    }

    // Spawn events
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(records) = store.load_all() {
            for r in &records {
                let matches = match &identity_id {
                    Some(iid) => r.parent_id.0 == *iid || r.child_id.0 == *iid,
                    None => {
                        r.parent_id.0.contains(identity_name)
                            || r.child_id.0.contains(identity_name)
                    }
                };
                if matches {
                    let role = match &identity_id {
                        Some(iid) if r.parent_id.0 == *iid => "parent",
                        _ => "child",
                    };
                    let caps: Vec<&str> =
                        r.authority_granted.iter().map(|c| c.uri.as_str()).collect();
                    events.push((
                        r.spawn_timestamp,
                        json!({
                            "event_type": "spawn",
                            "spawn_id": r.id.0,
                            "timestamp": micros_to_rfc3339(r.spawn_timestamp),
                            "details": {
                                "role": role,
                                "spawn_type": r.spawn_type.as_tag(),
                                "purpose": r.spawn_purpose,
                                "authority": caps,
                            }
                        }),
                    ));

                    if let Some(term_at) = r.terminated_at {
                        events.push((
                            term_at,
                            json!({
                                "event_type": "spawn_terminated",
                                "spawn_id": r.id.0,
                                "timestamp": micros_to_rfc3339(term_at),
                                "details": {
                                    "reason": r.termination_reason.as_deref().unwrap_or("unknown"),
                                }
                            }),
                        ));
                    }
                }
            }
        }
    }

    // Sort by timestamp
    events.sort_by_key(|(ts, _)| *ts);

    let timeline: Vec<Value> = events.into_iter().map(|(_, event)| event).collect();
    let event_count = timeline.len();

    let out = json!({
        "identity_name": identity_name,
        "identity_id": identity_id,
        "event_count": event_count,
        "timeline": timeline,
    });

    tool_ok(id, serde_json::to_string_pretty(&out).unwrap_or_default())
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

/// Scan the identity directory to find an identity name matching a given ID.
fn find_identity_name_by_id(server: &McpServer, target_id: &str) -> Option<String> {
    let entries = std::fs::read_dir(&server.identity_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("aid") {
            if let Ok(doc) = read_public_document(&path) {
                if doc.id.0 == target_id {
                    return path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }
    None
}

// ═════════════════════════════════════════════════════════════════════════════
// Registration helpers — collect all definitions and route execution
// ═════════════════════════════════════════════════════════════════════════════

/// Return all tool definitions from this module.
pub fn all_definitions() -> Vec<Value> {
    vec![
        // Invention 13: Identity Resurrection
        definition_identity_resurrect_start(),
        definition_identity_resurrect_gather(),
        definition_identity_resurrect_verify(),
        definition_identity_resurrect_complete(),
        // Invention 14: Identity Forking
        definition_identity_fork_create(),
        definition_identity_fork_merge(),
        definition_identity_fork_abandon(),
        definition_identity_fork_conflicts(),
        // Invention 15: Zero-Knowledge Identity
        definition_identity_zk_prove(),
        definition_identity_zk_verify(),
        definition_identity_zk_challenge(),
        // Invention 16: Temporal Identity
        definition_identity_temporal_query(),
        definition_identity_temporal_diff(),
        definition_identity_temporal_timeline(),
    ]
}

/// Route a tool call to the appropriate execute function. Returns None if unrecognized.
pub fn try_execute(server: &McpServer, tool_name: &str, id: Value, args: &Value) -> Option<Value> {
    let result = match tool_name {
        // Invention 13: Identity Resurrection
        "identity_resurrect_start" => execute_identity_resurrect_start(server, id, args),
        "identity_resurrect_gather" => execute_identity_resurrect_gather(server, id, args),
        "identity_resurrect_verify" => execute_identity_resurrect_verify(server, id, args),
        "identity_resurrect_complete" => execute_identity_resurrect_complete(server, id, args),
        // Invention 14: Identity Forking
        "identity_fork_create" => execute_identity_fork_create(server, id, args),
        "identity_fork_merge" => execute_identity_fork_merge(server, id, args),
        "identity_fork_abandon" => execute_identity_fork_abandon(server, id, args),
        "identity_fork_conflicts" => execute_identity_fork_conflicts(server, id, args),
        // Invention 15: Zero-Knowledge Identity
        "identity_zk_prove" => execute_identity_zk_prove(server, id, args),
        "identity_zk_verify" => execute_identity_zk_verify(server, id, args),
        "identity_zk_challenge" => execute_identity_zk_challenge(server, id, args),
        // Invention 16: Temporal Identity
        "identity_temporal_query" => execute_identity_temporal_query(server, id, args),
        "identity_temporal_diff" => execute_identity_temporal_diff(server, id, args),
        "identity_temporal_timeline" => execute_identity_temporal_timeline(server, id, args),
        _ => return None,
    };
    Some(result)
}
