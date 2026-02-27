//! Invention Federation — Tools for Inventions 9-12 (Federation layer).
//!
//! Invention 9: Trust Inference — transitive trust discovery through the network.
//! Invention 10: Revocation Cascade — preview and execute cascading revocations.
//! Invention 11: Capability Negotiation — negotiate and inspect capability access.
//! Invention 12: Identity Entanglement — team identities with quorum-based actions.

use serde_json::{json, Value};

use super::{now_secs, tool_error, tool_ok, McpServer, DEFAULT_IDENTITY, MCP_PASSPHRASE};

use agentic_identity::storage::{load_identity, SpawnStore, TrustStore};
use agentic_identity::trust::{Revocation, RevocationReason, TrustGrant, TrustId};

// ── Helper: word overlap scoring ─────────────────────────────────────────────

/// Compute a simple word-overlap score between two strings.
/// Returns 0.0 when either is empty, 1.0 when every word in `a` appears in `b`.
fn word_overlap(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_words: Vec<&str> = a_lower.split_whitespace().collect();
    let b_words: Vec<&str> = b_lower.split_whitespace().collect();
    if a_words.is_empty() || b_words.is_empty() {
        return 0.0;
    }
    let hits = a_words
        .iter()
        .filter(|w| {
            let w = *w; // borrow fix: bind to local before closure captures
            b_words.iter().any(|bw| bw.contains(w) || w.contains(bw))
        })
        .count();
    hits as f64 / a_words.len() as f64
}

// ── Helper: load all grants from both granted + received ─────────────────────

fn load_all_grants(trust_dir: &std::path::Path) -> Vec<TrustGrant> {
    let mut grants = Vec::new();
    if let Ok(store) = TrustStore::new(trust_dir) {
        // Load from granted/
        if let Ok(ids) = store.list_granted() {
            for gid in ids.iter().take(500) {
                if let Ok(g) = store.load_grant(gid) {
                    grants.push(g);
                }
            }
        }
        // Load from received/ (may overlap with granted, dedup by id)
        if let Ok(ids) = store.list_received() {
            for gid in ids.iter().take(500) {
                if !grants.iter().any(|g| g.id == *gid) {
                    if let Ok(g) = store.load_grant(gid) {
                        grants.push(g);
                    }
                }
            }
        }
    }
    grants
}

/// Check whether a grant is revoked.
fn is_revoked(trust_dir: &std::path::Path, id: &TrustId) -> bool {
    if let Ok(store) = TrustStore::new(trust_dir) {
        store.is_revoked(id)
    } else {
        false
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// INVENTION 9: Trust Inference
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 1: identity_trust_infer ─────────────────────────────────────────────

pub fn definition_identity_trust_infer() -> Value {
    json!({
        "name": "identity_trust_infer",
        "description": "Infer trust between agents by finding transitive trust paths through the trust network.",
        "inputSchema": {
            "type": "object",
            "required": ["from_agent", "to_agent"],
            "properties": {
                "from_agent": {
                    "type": "string",
                    "description": "Source agent identity ID (aid_...)"
                },
                "to_agent": {
                    "type": "string",
                    "description": "Target agent identity ID (aid_...)"
                }
            }
        }
    })
}

pub fn execute_identity_trust_infer(server: &McpServer, id: Value, args: &Value) -> Value {
    let from_agent = match args.get("from_agent").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'from_agent' is required"),
    };
    let to_agent = match args.get("to_agent").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'to_agent' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);

    if grants.is_empty() {
        return tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "inferred": false,
                "from_agent": from_agent,
                "to_agent": to_agent,
                "reason": "No trust grants found in store",
                "paths": [],
                "confidence": 0.0,
            }))
            .unwrap(),
        );
    }

    // BFS for paths from from_agent to to_agent (max depth 5)
    let paths = bfs_trust_paths(&grants, &from_agent, &to_agent, 5, &server.trust_dir);

    let inferred = !paths.is_empty();
    // Confidence: direct = 1.0, each hop reduces by 0.3
    let confidence = if paths.is_empty() {
        0.0
    } else {
        let shortest = paths.iter().map(|p| p.len()).min().unwrap_or(1);
        (1.0_f64 - (shortest as f64 - 1.0) * 0.3).max(0.1)
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "inferred": inferred,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "paths_found": paths.len(),
            "shortest_path_length": paths.iter().map(|p| p.len()).min().unwrap_or(0),
            "confidence": confidence,
            "paths": paths.iter().take(5).collect::<Vec<_>>(),
        }))
        .unwrap(),
    )
}

/// BFS to find trust paths (grantor->grantee edges) from `from` to `to`.
fn bfs_trust_paths(
    grants: &[TrustGrant],
    from: &str,
    to: &str,
    max_depth: usize,
    trust_dir: &std::path::Path,
) -> Vec<Vec<Value>> {
    use std::collections::{HashSet, VecDeque};

    let mut results: Vec<Vec<Value>> = Vec::new();
    // (current_agent, path_so_far)
    let mut queue: VecDeque<(String, Vec<Value>)> = VecDeque::new();
    queue.push_back((from.to_string(), vec![json!(from)]));
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(from.to_string());

    while let Some((current, path)) = queue.pop_front() {
        if path.len() > max_depth + 1 {
            continue;
        }
        // Find all grants where current is grantor
        for grant in grants {
            if grant.grantor.0 == current && !is_revoked(trust_dir, &grant.id) {
                let next = grant.grantee.0.clone();
                let mut new_path = path.clone();
                new_path.push(json!({
                    "via_grant": grant.id.0,
                    "to": next,
                    "capabilities": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                }));

                if next == to {
                    results.push(new_path);
                    if results.len() >= 10 {
                        return results;
                    }
                } else if !visited.contains(&next) && new_path.len() <= max_depth + 1 {
                    visited.insert(next.clone());
                    queue.push_back((next, new_path));
                }
            }
        }
    }

    results
}

// ── Tool 2: identity_trust_paths ─────────────────────────────────────────────

pub fn definition_identity_trust_paths() -> Value {
    json!({
        "name": "identity_trust_paths",
        "description": "Find all trust paths between two agents with configurable depth.",
        "inputSchema": {
            "type": "object",
            "required": ["from_agent", "to_agent"],
            "properties": {
                "from_agent": {
                    "type": "string",
                    "description": "Source agent identity ID (aid_...)"
                },
                "to_agent": {
                    "type": "string",
                    "description": "Target agent identity ID (aid_...)"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum path depth to search (default: 3)",
                    "default": 3
                }
            }
        }
    })
}

pub fn execute_identity_trust_paths(server: &McpServer, id: Value, args: &Value) -> Value {
    let from_agent = match args.get("from_agent").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'from_agent' is required"),
    };
    let to_agent = match args.get("to_agent").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'to_agent' is required"),
    };
    let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

    let grants = load_all_grants(&server.trust_dir);
    let paths = bfs_trust_paths(
        &grants,
        &from_agent,
        &to_agent,
        max_depth,
        &server.trust_dir,
    );

    // Also compute reverse paths (to_agent -> from_agent) for bidirectional analysis
    let reverse_paths = bfs_trust_paths(
        &grants,
        &to_agent,
        &from_agent,
        max_depth,
        &server.trust_dir,
    );

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "from_agent": from_agent,
            "to_agent": to_agent,
            "max_depth": max_depth,
            "forward_paths": paths.len(),
            "reverse_paths": reverse_paths.len(),
            "bidirectional": !paths.is_empty() && !reverse_paths.is_empty(),
            "paths": paths.iter().take(10).collect::<Vec<_>>(),
            "reverse": reverse_paths.iter().take(10).collect::<Vec<_>>(),
            "total_grants_in_network": grants.len(),
        }))
        .unwrap(),
    )
}

// ── Tool 3: identity_trust_recommend ─────────────────────────────────────────

pub fn definition_identity_trust_recommend() -> Value {
    json!({
        "name": "identity_trust_recommend",
        "description": "Get trust recommendation for granting a capability to an agent based on network analysis.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id", "capability"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to evaluate (aid_...)"
                },
                "capability": {
                    "type": "string",
                    "description": "Capability URI to evaluate (e.g. 'deploy:production')"
                }
            }
        }
    })
}

pub fn execute_identity_trust_recommend(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'agent_id' is required"),
    };
    let capability = match args.get("capability").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'capability' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);

    // Analysis factors:
    // 1. Does agent already have this capability?
    // 2. How many grantors trust this agent?
    // 3. Does agent have similar capabilities?
    // 4. Is agent part of the spawn hierarchy?

    let mut already_has = false;
    let mut grantors_count = 0;
    let mut similar_caps: Vec<String> = Vec::new();
    let mut revoked_count = 0;

    for grant in &grants {
        if grant.grantee.0 == agent_id {
            if is_revoked(&server.trust_dir, &grant.id) {
                revoked_count += 1;
                continue;
            }
            grantors_count += 1;
            for cap in &grant.capabilities {
                if cap.uri == capability {
                    already_has = true;
                }
                let overlap = word_overlap(&cap.uri, &capability);
                if overlap > 0.3 && cap.uri != capability {
                    similar_caps.push(cap.uri.clone());
                }
            }
        }
    }
    similar_caps.sort();
    similar_caps.dedup();

    // Check spawn hierarchy
    let mut is_spawned = false;
    if let Ok(spawn_store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(spawns) = spawn_store.load_all() {
            for spawn in &spawns {
                if spawn.child_id.0 == agent_id && !spawn.terminated {
                    is_spawned = true;
                    break;
                }
            }
        }
    }

    // Compute recommendation score
    let mut score: f64 = 0.0;
    let mut reasons: Vec<String> = Vec::new();

    if already_has {
        score += 0.4;
        reasons.push("Agent already holds this capability".to_string());
    }
    if grantors_count > 0 {
        score += (grantors_count as f64 * 0.15).min(0.3);
        reasons.push(format!("{} active trust grants received", grantors_count));
    }
    if !similar_caps.is_empty() {
        score += 0.2;
        reasons.push(format!(
            "Agent holds {} similar capabilities",
            similar_caps.len()
        ));
    }
    if is_spawned {
        score += 0.1;
        reasons.push("Agent is an active spawn in hierarchy".to_string());
    }
    if revoked_count > 0 {
        score -= revoked_count as f64 * 0.1;
        reasons.push(format!("{} grants have been revoked", revoked_count));
    }

    let recommendation = if score >= 0.7 {
        "strongly_recommend"
    } else if score >= 0.4 {
        "recommend"
    } else if score >= 0.2 {
        "neutral"
    } else {
        "not_recommended"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "capability": capability,
            "recommendation": recommendation,
            "score": (score * 100.0).round() / 100.0,
            "already_has_capability": already_has,
            "active_grants_received": grantors_count,
            "similar_capabilities": similar_caps,
            "is_spawned_agent": is_spawned,
            "revoked_grants": revoked_count,
            "reasons": reasons,
        }))
        .unwrap(),
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// INVENTION 10: Revocation Cascade
// ═════════════════════════════════════════════════════════════════════════════

/// Find all grants that depend on a given trust_id (via parent_grant chain).
fn find_dependent_grants(
    grants: &[TrustGrant],
    root_id: &str,
    trust_dir: &std::path::Path,
) -> Vec<Value> {
    let mut dependents = Vec::new();
    let mut queue = vec![root_id.to_string()];
    let mut seen = std::collections::HashSet::new();
    seen.insert(root_id.to_string());

    while let Some(current_id) = queue.pop() {
        for grant in grants {
            if let Some(ref parent) = grant.parent_grant {
                if parent.0 == current_id && !seen.contains(&grant.id.0) {
                    seen.insert(grant.id.0.clone());
                    let already_revoked = is_revoked(trust_dir, &grant.id);
                    dependents.push(json!({
                        "grant_id": grant.id.0,
                        "grantor": grant.grantor.0,
                        "grantee": grant.grantee.0,
                        "capabilities": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                        "delegation_depth": grant.delegation_depth,
                        "already_revoked": already_revoked,
                    }));
                    queue.push(grant.id.0.clone());
                }
            }
        }
    }

    dependents
}

// ── Tool 4: identity_revoke_cascade_preview ──────────────────────────────────

pub fn definition_identity_revoke_cascade_preview() -> Value {
    json!({
        "name": "identity_revoke_cascade_preview",
        "description": "Preview cascade effects of revoking a trust grant. Shows all dependent grants that would be affected.",
        "inputSchema": {
            "type": "object",
            "required": ["trust_id"],
            "properties": {
                "trust_id": {
                    "type": "string",
                    "description": "Trust grant ID to preview revocation for (atrust_...)"
                }
            }
        }
    })
}

pub fn execute_identity_revoke_cascade_preview(
    server: &McpServer,
    id: Value,
    args: &Value,
) -> Value {
    let trust_id = match args.get("trust_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'trust_id' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);

    // Find the root grant
    let root_grant = grants.iter().find(|g| g.id.0 == trust_id);
    let root_info = match root_grant {
        Some(g) => json!({
            "grant_id": g.id.0,
            "grantor": g.grantor.0,
            "grantee": g.grantee.0,
            "capabilities": g.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
            "already_revoked": is_revoked(&server.trust_dir, &g.id),
        }),
        None => json!({ "grant_id": trust_id, "status": "not_found" }),
    };

    let dependents = find_dependent_grants(&grants, &trust_id, &server.trust_dir);
    let active_dependents = dependents
        .iter()
        .filter(|d| {
            !d.get("already_revoked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .count();

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "trust_id": trust_id,
            "root_grant": root_info,
            "total_affected": dependents.len(),
            "active_affected": active_dependents,
            "dependents": dependents,
            "warning": if active_dependents > 0 {
                format!("Revoking this grant will cascade to {} active dependent grants", active_dependents)
            } else {
                "No active dependent grants will be affected".to_string()
            },
        }))
        .unwrap(),
    )
}

// ── Tool 5: identity_revoke_cascade_execute ──────────────────────────────────

pub fn definition_identity_revoke_cascade_execute() -> Value {
    json!({
        "name": "identity_revoke_cascade_execute",
        "description": "Execute revocation with cascade. Revokes the specified grant and all dependent delegated grants.",
        "inputSchema": {
            "type": "object",
            "required": ["trust_id"],
            "properties": {
                "trust_id": {
                    "type": "string",
                    "description": "Trust grant ID to revoke with cascade (atrust_...)"
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for revocation (default: cascade_revocation)"
                }
            }
        }
    })
}

pub fn execute_identity_revoke_cascade_execute(
    server: &McpServer,
    id: Value,
    args: &Value,
) -> Value {
    let trust_id = match args.get("trust_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'trust_id' is required"),
    };
    let reason = args
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("cascade_revocation");

    // Load the default identity for signing revocations
    let identity_path = server
        .identity_dir
        .join(format!("{}.aid", DEFAULT_IDENTITY));
    let anchor = match load_identity(&identity_path, MCP_PASSPHRASE) {
        Ok(a) => a,
        Err(e) => {
            return tool_error(
                id,
                format!("Failed to load identity for signing revocations: {}", e),
            )
        }
    };

    let grants = load_all_grants(&server.trust_dir);
    let dependents = find_dependent_grants(&grants, &trust_id, &server.trust_dir);

    // Collect all IDs to revoke (root + dependents)
    let mut to_revoke: Vec<String> = vec![trust_id.clone()];
    for dep in &dependents {
        if let Some(gid) = dep.get("grant_id").and_then(|v| v.as_str()) {
            to_revoke.push(gid.to_string());
        }
    }

    let mut revoked = Vec::new();
    let mut failed = Vec::new();

    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for rid in &to_revoke {
            let tid = TrustId(rid.clone());
            if store.is_revoked(&tid) {
                revoked.push(json!({ "grant_id": rid, "status": "already_revoked" }));
                continue;
            }

            // Verify the grant exists before revoking
            match store.load_grant(&tid) {
                Ok(_grant) => {
                    let revocation_reason = RevocationReason::Custom(reason.to_string());
                    let revocation = Revocation::create(
                        tid.clone(),
                        anchor.id(),
                        revocation_reason,
                        anchor.signing_key(),
                    );
                    match store.save_revocation(&revocation) {
                        Ok(()) => {
                            revoked.push(
                                json!({ "grant_id": rid, "status": "revoked", "reason": reason }),
                            );
                        }
                        Err(e) => {
                            failed.push(json!({ "grant_id": rid, "error": format!("{}", e) }));
                        }
                    }
                }
                Err(e) => {
                    failed.push(json!({ "grant_id": rid, "error": format!("{}", e) }));
                }
            }
        }
    } else {
        return tool_error(id, "Failed to open trust store");
    }

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "trust_id": trust_id,
            "reason": reason,
            "total_processed": to_revoke.len(),
            "revoked": revoked,
            "failed": failed,
            "timestamp": now_secs(),
        }))
        .unwrap(),
    )
}

// ── Tool 6: identity_revoke_cascade_recover ──────────────────────────────────

pub fn definition_identity_revoke_cascade_recover() -> Value {
    json!({
        "name": "identity_revoke_cascade_recover",
        "description": "Analyze recovery options after a cascade revocation. Shows which grants could potentially be re-established.",
        "inputSchema": {
            "type": "object",
            "required": ["trust_id"],
            "properties": {
                "trust_id": {
                    "type": "string",
                    "description": "Trust grant ID that was cascade-revoked (atrust_...)"
                }
            }
        }
    })
}

pub fn execute_identity_revoke_cascade_recover(
    server: &McpServer,
    id: Value,
    args: &Value,
) -> Value {
    let trust_id = match args.get("trust_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'trust_id' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);
    let dependents = find_dependent_grants(&grants, &trust_id, &server.trust_dir);

    // For recovery: identify which revoked dependents could be re-established
    // by creating new direct grants from their original grantors.
    let mut recoverable = Vec::new();

    // Check the root grant
    let root_tid = TrustId(trust_id.clone());
    let root_revoked = is_revoked(&server.trust_dir, &root_tid);
    if root_revoked {
        if let Some(root_grant) = grants.iter().find(|g| g.id.0 == trust_id) {
            recoverable.push(json!({
                "grant_id": trust_id,
                "grantor": root_grant.grantor.0,
                "grantee": root_grant.grantee.0,
                "capabilities": root_grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                "recovery_action": "Re-issue direct grant from original grantor",
                "was_delegated": root_grant.parent_grant.is_some(),
            }));
        }
    }

    for dep in &dependents {
        let dep_revoked = dep
            .get("already_revoked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if dep_revoked {
            recoverable.push(json!({
                "grant_id": dep.get("grant_id"),
                "grantor": dep.get("grantor"),
                "grantee": dep.get("grantee"),
                "capabilities": dep.get("capabilities"),
                "recovery_action": "Re-issue as direct grant (removes delegation dependency)",
                "delegation_depth": dep.get("delegation_depth"),
            }));
        }
    }

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "trust_id": trust_id,
            "root_revoked": root_revoked,
            "total_dependents": dependents.len(),
            "recoverable_count": recoverable.len(),
            "recoverable_grants": recoverable,
            "recommendation": if recoverable.is_empty() {
                "No revoked grants found to recover"
            } else {
                "Re-issue affected grants as direct grants to eliminate delegation chain dependency"
            },
        }))
        .unwrap(),
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// INVENTION 11: Capability Negotiation
// ═════════════════════════════════════════════════════════════════════════════

// ── Tool 7: identity_capability_negotiate ────────────────────────────────────

pub fn definition_identity_capability_negotiate() -> Value {
    json!({
        "name": "identity_capability_negotiate",
        "description": "Negotiate capability access for an agent. Checks if negotiation is possible based on existing grants and delegation paths.",
        "inputSchema": {
            "type": "object",
            "required": ["capability", "agent_id"],
            "properties": {
                "capability": {
                    "type": "string",
                    "description": "Capability URI to negotiate (e.g. 'deploy:production')"
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID requesting the capability (aid_...)"
                }
            }
        }
    })
}

pub fn execute_identity_capability_negotiate(server: &McpServer, id: Value, args: &Value) -> Value {
    let capability = match args.get("capability").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'capability' is required"),
    };
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'agent_id' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);

    // Check if agent already has this capability
    let mut has_direct = false;
    let mut has_similar: Vec<String> = Vec::new();
    let mut potential_delegators: Vec<Value> = Vec::new();

    for grant in &grants {
        if is_revoked(&server.trust_dir, &grant.id) {
            continue;
        }

        // Check if agent already has it
        if grant.grantee.0 == agent_id {
            for cap in &grant.capabilities {
                if cap.uri == capability {
                    has_direct = true;
                }
                let overlap = word_overlap(&cap.uri, &capability);
                if overlap > 0.3 && cap.uri != capability {
                    has_similar.push(cap.uri.clone());
                }
            }
        }

        // Find agents that have this capability AND can delegate
        if grant.delegation_allowed {
            for cap in &grant.capabilities {
                if cap.uri == capability {
                    // Check delegation depth still allows it
                    let max_depth = grant.max_delegation_depth.unwrap_or(u32::MAX);
                    if grant.delegation_depth < max_depth {
                        potential_delegators.push(json!({
                            "delegator": grant.grantee.0,
                            "via_grant": grant.id.0,
                            "remaining_depth": max_depth.saturating_sub(grant.delegation_depth + 1),
                        }));
                    }
                }
            }
        }
    }
    has_similar.sort();
    has_similar.dedup();

    let negotiation_possible = has_direct || !potential_delegators.is_empty();
    let status = if has_direct {
        "already_granted"
    } else if !potential_delegators.is_empty() {
        "delegation_available"
    } else if !has_similar.is_empty() {
        "similar_capabilities_exist"
    } else {
        "no_path_found"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "capability": capability,
            "agent_id": agent_id,
            "status": status,
            "negotiation_possible": negotiation_possible,
            "has_direct_grant": has_direct,
            "similar_capabilities": has_similar,
            "potential_delegators": potential_delegators,
            "suggestion": match status {
                "already_granted" => "Agent already holds this capability",
                "delegation_available" => "Request delegation from one of the potential delegators",
                "similar_capabilities_exist" => "Agent has similar capabilities; request an upgrade or new grant",
                _ => "No delegation path exists; request a direct grant from an authority",
            },
        }))
        .unwrap(),
    )
}

// ── Tool 8: identity_capability_available ────────────────────────────────────

pub fn definition_identity_capability_available() -> Value {
    json!({
        "name": "identity_capability_available",
        "description": "Check what capabilities are available to an agent or across the entire network.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to check (aid_...). If omitted, lists all capabilities in network."
                }
            }
        }
    })
}

pub fn execute_identity_capability_available(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = args.get("agent_id").and_then(|v| v.as_str());

    let grants = load_all_grants(&server.trust_dir);

    let mut capabilities: Vec<Value> = Vec::new();
    let mut cap_set = std::collections::HashMap::new();

    for grant in &grants {
        let revoked = is_revoked(&server.trust_dir, &grant.id);

        // If agent_id specified, only include grants to that agent
        if let Some(aid) = agent_id {
            if grant.grantee.0 != aid {
                continue;
            }
        }

        for cap in &grant.capabilities {
            let entry = cap_set.entry(cap.uri.clone()).or_insert_with(|| {
                json!({
                    "capability": cap.uri,
                    "grant_count": 0,
                    "active_count": 0,
                    "revoked_count": 0,
                    "delegatable": false,
                    "grantors": [],
                })
            });

            if let Some(obj) = entry.as_object_mut() {
                let gc = obj.get("grant_count").and_then(|v| v.as_u64()).unwrap_or(0);
                obj.insert("grant_count".to_string(), json!(gc + 1));

                if revoked {
                    let rc = obj
                        .get("revoked_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    obj.insert("revoked_count".to_string(), json!(rc + 1));
                } else {
                    let ac = obj
                        .get("active_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    obj.insert("active_count".to_string(), json!(ac + 1));
                }

                if grant.delegation_allowed {
                    obj.insert("delegatable".to_string(), json!(true));
                }

                if let Some(arr) = obj.get_mut("grantors") {
                    if let Some(grantors) = arr.as_array_mut() {
                        let grantor_str = json!(grant.grantor.0);
                        if !grantors.contains(&grantor_str) && grantors.len() < 10 {
                            grantors.push(grantor_str);
                        }
                    }
                }
            }
        }
    }

    for v in cap_set.values() {
        capabilities.push(v.clone());
    }
    capabilities.sort_by(|a, b| {
        let a_name = a.get("capability").and_then(|v| v.as_str()).unwrap_or("");
        let b_name = b.get("capability").and_then(|v| v.as_str()).unwrap_or("");
        a_name.cmp(b_name)
    });

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id.unwrap_or("*"),
            "total_capabilities": capabilities.len(),
            "capabilities": capabilities,
        }))
        .unwrap(),
    )
}

// ── Tool 9: identity_capability_terms ────────────────────────────────────────

pub fn definition_identity_capability_terms() -> Value {
    json!({
        "name": "identity_capability_terms",
        "description": "Get the terms and constraints for a specific capability across all grants.",
        "inputSchema": {
            "type": "object",
            "required": ["capability"],
            "properties": {
                "capability": {
                    "type": "string",
                    "description": "Capability URI to inspect (e.g. 'deploy:production')"
                }
            }
        }
    })
}

pub fn execute_identity_capability_terms(server: &McpServer, id: Value, args: &Value) -> Value {
    let capability = match args.get("capability").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'capability' is required"),
    };

    let grants = load_all_grants(&server.trust_dir);
    let mut terms: Vec<Value> = Vec::new();

    for grant in &grants {
        let has_cap = grant.capabilities.iter().any(|c| c.uri == capability);
        if !has_cap {
            // Also check partial match
            let overlap = grant
                .capabilities
                .iter()
                .map(|c| word_overlap(&c.uri, &capability))
                .fold(0.0_f64, f64::max);
            if overlap < 0.5 {
                continue;
            }
        }

        let revoked = is_revoked(&server.trust_dir, &grant.id);

        terms.push(json!({
            "grant_id": grant.id.0,
            "grantor": grant.grantor.0,
            "grantee": grant.grantee.0,
            "active": !revoked,
            "constraints": {
                "not_before": grant.constraints.not_before,
                "not_after": grant.constraints.not_after,
                "max_uses": grant.constraints.max_uses,
                "geographic": grant.constraints.geographic,
                "ip_allowlist": grant.constraints.ip_allowlist,
                "custom": grant.constraints.custom,
            },
            "delegation_allowed": grant.delegation_allowed,
            "max_delegation_depth": grant.max_delegation_depth,
            "current_delegation_depth": grant.delegation_depth,
            "capabilities_in_grant": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
        }));
    }

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "capability": capability,
            "grants_found": terms.len(),
            "terms": terms,
        }))
        .unwrap(),
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// INVENTION 12: Identity Entanglement (Team Identities)
// ═════════════════════════════════════════════════════════════════════════════

/// Teams are stored as JSON files in {spawn_dir}/teams/{team_id}.json.
fn teams_dir(server: &McpServer) -> std::path::PathBuf {
    server.spawn_dir.join("teams")
}

fn load_team(server: &McpServer, team_id: &str) -> Option<Value> {
    let path = teams_dir(server).join(format!("{}.json", team_id));
    if path.exists() {
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    } else {
        None
    }
}

fn save_team(server: &McpServer, team: &Value) -> Result<(), String> {
    let dir = teams_dir(server);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create teams dir: {}", e))?;
    let team_id = team
        .get("team_id")
        .and_then(|v| v.as_str())
        .ok_or("team has no team_id")?;
    let path = dir.join(format!("{}.json", team_id));
    let json =
        serde_json::to_string_pretty(team).map_err(|e| format!("Serialization error: {}", e))?;
    std::fs::write(&path, json.as_bytes()).map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

fn generate_team_id() -> String {
    format!("ateam_{:016x}", {
        use std::time::SystemTime;
        let d = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        d.as_nanos() as u64
    })
}

fn generate_action_id() -> String {
    format!("aact_{:016x}", {
        use std::time::SystemTime;
        let d = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // Add a small offset to distinguish from team IDs generated in same ns
        (d.as_nanos() as u64).wrapping_add(1)
    })
}

// ── Tool 10: identity_team_create ────────────────────────────────────────────

pub fn definition_identity_team_create() -> Value {
    json!({
        "name": "identity_team_create",
        "description": "Create an entangled team identity. Members share authority and can act collectively with quorum.",
        "inputSchema": {
            "type": "object",
            "required": ["name", "members"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Human-readable team name"
                },
                "members": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of member agent identity IDs (aid_...)"
                },
                "quorum": {
                    "type": "integer",
                    "description": "Minimum number of signers required for team actions (default: majority)"
                }
            }
        }
    })
}

pub fn execute_identity_team_create(server: &McpServer, id: Value, args: &Value) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'name' is required"),
    };
    let members = match args.get("members").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => {
            let m: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if m.is_empty() {
                return tool_error(id, "'members' must contain at least one agent ID");
            }
            m
        }
        _ => return tool_error(id, "'members' is required and must be a non-empty array"),
    };

    let default_quorum = (members.len() / 2) + 1;
    let quorum = args
        .get("quorum")
        .and_then(|v| v.as_u64())
        .map(|q| q as usize)
        .unwrap_or(default_quorum);

    let quorum = quorum.min(members.len()).max(1);

    let team_id = generate_team_id();

    let member_records: Vec<Value> = members
        .iter()
        .map(|m| {
            json!({
                "agent_id": m,
                "role": "member",
                "joined_at": now_secs(),
            })
        })
        .collect();

    let team = json!({
        "team_id": team_id,
        "name": name,
        "members": member_records,
        "quorum": quorum,
        "created_at": now_secs(),
        "actions": [],
    });

    if let Err(e) = save_team(server, &team) {
        return tool_error(id, format!("Failed to save team: {}", e));
    }

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "team_id": team_id,
            "name": name,
            "member_count": members.len(),
            "quorum": quorum,
            "members": members,
            "created_at": now_secs(),
        }))
        .unwrap(),
    )
}

// ── Tool 11: identity_team_add_member ────────────────────────────────────────

pub fn definition_identity_team_add_member() -> Value {
    json!({
        "name": "identity_team_add_member",
        "description": "Add a member to an existing team identity.",
        "inputSchema": {
            "type": "object",
            "required": ["team_id", "member_id"],
            "properties": {
                "team_id": {
                    "type": "string",
                    "description": "Team identity ID (ateam_...)"
                },
                "member_id": {
                    "type": "string",
                    "description": "New member agent identity ID (aid_...)"
                },
                "role": {
                    "type": "string",
                    "description": "Role for the new member: admin, member, observer (default: member)",
                    "enum": ["admin", "member", "observer"],
                    "default": "member"
                }
            }
        }
    })
}

pub fn execute_identity_team_add_member(server: &McpServer, id: Value, args: &Value) -> Value {
    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'team_id' is required"),
    };
    let member_id = match args.get("member_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'member_id' is required"),
    };
    let role = args
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("member");

    let mut team = match load_team(server, &team_id) {
        Some(t) => t,
        None => return tool_error(id, format!("Team not found: {}", team_id)),
    };

    // Check if member already exists
    if let Some(members) = team.get("members").and_then(|v| v.as_array()) {
        for m in members {
            if m.get("agent_id").and_then(|v| v.as_str()) == Some(&member_id) {
                return tool_error(
                    id,
                    format!(
                        "Agent {} is already a member of team {}",
                        member_id, team_id
                    ),
                );
            }
        }
    }

    // Add the new member
    if let Some(members) = team.get_mut("members").and_then(|v| v.as_array_mut()) {
        members.push(json!({
            "agent_id": member_id,
            "role": role,
            "joined_at": now_secs(),
        }));
    }

    if let Err(e) = save_team(server, &team) {
        return tool_error(id, format!("Failed to save team: {}", e));
    }

    let member_count = team
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "team_id": team_id,
            "added_member": member_id,
            "role": role,
            "total_members": member_count,
            "quorum": team.get("quorum"),
        }))
        .unwrap(),
    )
}

// ── Tool 12: identity_team_act ───────────────────────────────────────────────

pub fn definition_identity_team_act() -> Value {
    json!({
        "name": "identity_team_act",
        "description": "Take an action as a team. Requires signatures from team members meeting the quorum threshold.",
        "inputSchema": {
            "type": "object",
            "required": ["team_id", "action", "signers"],
            "properties": {
                "team_id": {
                    "type": "string",
                    "description": "Team identity ID (ateam_...)"
                },
                "action": {
                    "type": "string",
                    "description": "Description of the action to take"
                },
                "signers": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of agent IDs signing this action (must be team members)"
                }
            }
        }
    })
}

pub fn execute_identity_team_act(server: &McpServer, id: Value, args: &Value) -> Value {
    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'team_id' is required"),
    };
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'action' is required"),
    };
    let signers = match args.get("signers").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => {
            let s: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if s.is_empty() {
                return tool_error(id, "'signers' must contain at least one agent ID");
            }
            s
        }
        _ => return tool_error(id, "'signers' is required and must be a non-empty array"),
    };

    let mut team = match load_team(server, &team_id) {
        Some(t) => t,
        None => return tool_error(id, format!("Team not found: {}", team_id)),
    };

    let quorum = team.get("quorum").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

    // Validate all signers are team members
    let members: Vec<String> = team
        .get("members")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("agent_id").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut valid_signers = Vec::new();
    let mut invalid_signers = Vec::new();
    for s in &signers {
        if members.contains(s) {
            valid_signers.push(s.clone());
        } else {
            invalid_signers.push(s.clone());
        }
    }

    if !invalid_signers.is_empty() {
        return tool_error(
            id,
            format!(
                "The following signers are not team members: {}",
                invalid_signers.join(", ")
            ),
        );
    }

    // Dedup signers
    valid_signers.sort();
    valid_signers.dedup();

    let quorum_met = valid_signers.len() >= quorum;

    let action_id = generate_action_id();
    let action_record = json!({
        "action_id": action_id,
        "action": action,
        "signers": valid_signers,
        "quorum_required": quorum,
        "quorum_met": quorum_met,
        "timestamp": now_secs(),
        "status": if quorum_met { "executed" } else { "pending_quorum" },
    });

    // Append to team actions
    if let Some(actions) = team.get_mut("actions").and_then(|v| v.as_array_mut()) {
        actions.push(action_record.clone());
    } else {
        team.as_object_mut()
            .map(|obj| obj.insert("actions".to_string(), json!([action_record.clone()])));
    }

    if let Err(e) = save_team(server, &team) {
        return tool_error(id, format!("Failed to save team action: {}", e));
    }

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "team_id": team_id,
            "action_id": action_id,
            "action": action,
            "signers": valid_signers,
            "quorum_required": quorum,
            "signers_count": valid_signers.len(),
            "quorum_met": quorum_met,
            "status": if quorum_met { "executed" } else { "pending_quorum" },
            "additional_signers_needed": if quorum_met { 0 } else { quorum - valid_signers.len() },
        }))
        .unwrap(),
    )
}

// ── Tool 13: identity_team_verify ────────────────────────────────────────────

pub fn definition_identity_team_verify() -> Value {
    json!({
        "name": "identity_team_verify",
        "description": "Verify that a team action met the quorum requirement.",
        "inputSchema": {
            "type": "object",
            "required": ["team_id", "action_id"],
            "properties": {
                "team_id": {
                    "type": "string",
                    "description": "Team identity ID (ateam_...)"
                },
                "action_id": {
                    "type": "string",
                    "description": "Action ID to verify (aact_...)"
                }
            }
        }
    })
}

pub fn execute_identity_team_verify(server: &McpServer, id: Value, args: &Value) -> Value {
    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'team_id' is required"),
    };
    let action_id = match args.get("action_id").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return tool_error(id, "'action_id' is required"),
    };

    let team = match load_team(server, &team_id) {
        Some(t) => t,
        None => return tool_error(id, format!("Team not found: {}", team_id)),
    };

    let quorum = team.get("quorum").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

    let total_members = team
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // Find the action
    let action_record = team
        .get("actions")
        .and_then(|v| v.as_array())
        .and_then(|actions| {
            actions
                .iter()
                .find(|a| a.get("action_id").and_then(|v| v.as_str()) == Some(&action_id))
        });

    match action_record {
        Some(action) => {
            let signers = action
                .get("signers")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let quorum_met = signers >= quorum;

            // Verify all signers are still members
            let signer_list: Vec<String> = action
                .get("signers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let member_list: Vec<String> = team
                .get("members")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            m.get("agent_id").and_then(|v| v.as_str()).map(String::from)
                        })
                        .collect()
                })
                .unwrap_or_default();

            let still_members: Vec<&String> = signer_list
                .iter()
                .filter(|s| member_list.contains(s))
                .collect();
            let effective_quorum_met = still_members.len() >= quorum;

            tool_ok(
                id,
                serde_json::to_string_pretty(&json!({
                    "team_id": team_id,
                    "action_id": action_id,
                    "action": action.get("action"),
                    "verification": {
                        "quorum_required": quorum,
                        "total_members": total_members,
                        "signers_at_time": signers,
                        "signers_still_members": still_members.len(),
                        "quorum_met_at_time": quorum_met,
                        "quorum_met_current": effective_quorum_met,
                        "valid": effective_quorum_met,
                    },
                    "signers": signer_list,
                    "timestamp": action.get("timestamp"),
                    "status": action.get("status"),
                }))
                .unwrap(),
            )
        }
        None => tool_error(
            id,
            format!("Action {} not found in team {}", action_id, team_id),
        ),
    }
}

// ── Convenience wrappers ─────────────────────────────────────────────────────

pub fn all_definitions() -> Vec<Value> {
    vec![
        definition_identity_trust_infer(),
        definition_identity_trust_paths(),
        definition_identity_trust_recommend(),
        definition_identity_revoke_cascade_preview(),
        definition_identity_revoke_cascade_execute(),
        definition_identity_revoke_cascade_recover(),
        definition_identity_capability_negotiate(),
        definition_identity_capability_available(),
        definition_identity_capability_terms(),
        definition_identity_team_create(),
        definition_identity_team_add_member(),
        definition_identity_team_act(),
        definition_identity_team_verify(),
    ]
}

pub fn try_execute(server: &McpServer, tool_name: &str, id: Value, args: &Value) -> Option<Value> {
    Some(match tool_name {
        "identity_trust_infer" => execute_identity_trust_infer(server, id, args),
        "identity_trust_paths" => execute_identity_trust_paths(server, id, args),
        "identity_trust_recommend" => execute_identity_trust_recommend(server, id, args),
        "identity_revoke_cascade_preview" => {
            execute_identity_revoke_cascade_preview(server, id, args)
        }
        "identity_revoke_cascade_execute" => {
            execute_identity_revoke_cascade_execute(server, id, args)
        }
        "identity_revoke_cascade_recover" => {
            execute_identity_revoke_cascade_recover(server, id, args)
        }
        "identity_capability_negotiate" => execute_identity_capability_negotiate(server, id, args),
        "identity_capability_available" => execute_identity_capability_available(server, id, args),
        "identity_capability_terms" => execute_identity_capability_terms(server, id, args),
        "identity_team_create" => execute_identity_team_create(server, id, args),
        "identity_team_add_member" => execute_identity_team_add_member(server, id, args),
        "identity_team_act" => execute_identity_team_act(server, id, args),
        "identity_team_verify" => execute_identity_team_verify(server, id, args),
        _ => return None,
    })
}
