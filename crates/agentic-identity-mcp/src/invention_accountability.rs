//! Invention Accountability Tools (Inventions 5-8)
//!
//! 14 tools implementing:
//! - Invention 5: Receipt Archaeology (search, pattern, timeline, anomalies)
//! - Invention 6: Causal Attribution (cause, chain, responsibility)
//! - Invention 7: Consent Chains (chain, validate, gaps)
//! - Invention 8: Behavioral Fingerprinting (build, match, anomaly, alert)

use serde_json::{json, Value};

use super::{now_secs, tool_error, tool_ok, McpServer};

use agentic_identity::receipt::receipt::ActionReceipt;
use agentic_identity::storage::{ReceiptStore, TrustStore};
use agentic_identity::trust::grant::TrustGrant;
use agentic_identity::ReceiptId;

use std::collections::HashMap;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Load all receipts from the store (list IDs then load each).
fn load_all_receipts(store: &ReceiptStore) -> Vec<ActionReceipt> {
    let ids = match store.list() {
        Ok(ids) => ids,
        Err(_) => return Vec::new(),
    };
    let mut receipts = Vec::new();
    for rid in &ids {
        if let Ok(r) = store.load(rid) {
            receipts.push(r);
        }
    }
    receipts
}

/// Load all trust grants from the store (granted + received, deduplicated).
fn load_all_grants(store: &TrustStore) -> Vec<TrustGrant> {
    let mut seen = std::collections::HashSet::new();
    let mut grants = Vec::new();

    if let Ok(ids) = store.list_granted() {
        for gid in &ids {
            if seen.insert(gid.0.clone()) {
                if let Ok(g) = store.load_grant(gid) {
                    grants.push(g);
                }
            }
        }
    }
    if let Ok(ids) = store.list_received() {
        for gid in &ids {
            if seen.insert(gid.0.clone()) {
                if let Ok(g) = store.load_grant(gid) {
                    grants.push(g);
                }
            }
        }
    }
    grants
}

/// Word-overlap score between two strings (Jaccard-like).
fn word_overlap(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_words: std::collections::HashSet<&str> = a_lower.split_whitespace().collect();
    let b_words: std::collections::HashSet<&str> = b_lower.split_whitespace().collect();
    if a_words.is_empty() || b_words.is_empty() {
        return 0.0;
    }
    let intersection = a_words.intersection(&b_words).count() as f64;
    let union = a_words.union(&b_words).count() as f64;
    intersection / union
}

/// Convert microsecond timestamp to human-readable string.
fn micros_to_display(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if remaining < diy {
            break;
        }
        remaining -= diy;
        year += 1;
    }
    let months = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &dim in &months {
        if remaining < dim {
            break;
        }
        remaining -= dim;
        month += 1;
    }
    let day = remaining + 1;
    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Format an ActionType as a string tag.
fn action_type_tag(at: &agentic_identity::ActionType) -> String {
    at.as_tag().to_string()
}

/// Pretty-print JSON or fallback to empty object.
fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 5: Receipt Archaeology
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 1: identity_receipt_search ──────────────────────────────────────

pub fn definition_identity_receipt_search() -> Value {
    json!({
        "name": "identity_receipt_search",
        "description": "Search receipts with filters. Full-text search across receipt descriptions and data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search query across receipt descriptions and data"
                },
                "actor": {
                    "type": "string",
                    "description": "Filter by actor identity ID (aid_...)"
                },
                "action_type": {
                    "type": "string",
                    "description": "Filter by action type (decision, observation, mutation, delegation, revocation, identity_operation)"
                },
                "after": {
                    "type": "number",
                    "description": "Only include receipts after this timestamp (seconds since epoch)"
                },
                "before": {
                    "type": "number",
                    "description": "Only include receipts before this timestamp (seconds since epoch)"
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of results to return (default: 20)"
                }
            }
        }
    })
}

pub fn execute_identity_receipt_search(server: &McpServer, id: Value, args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);

    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let actor_filter = args.get("actor").and_then(|v| v.as_str());
    let action_type_filter = args.get("action_type").and_then(|v| v.as_str());
    let after_secs = args.get("after").and_then(|v| v.as_u64());
    let before_secs = args.get("before").and_then(|v| v.as_u64());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    let after_micros = after_secs.map(|s| s * 1_000_000);
    let before_micros = before_secs.map(|s| s * 1_000_000);

    let mut results: Vec<(f64, &ActionReceipt)> = Vec::new();

    for receipt in &all_receipts {
        if let Some(af) = actor_filter {
            if receipt.actor.0 != af {
                continue;
            }
        }
        if let Some(atf) = action_type_filter {
            if action_type_tag(&receipt.action_type) != atf {
                continue;
            }
        }
        if let Some(after) = after_micros {
            if receipt.timestamp < after {
                continue;
            }
        }
        if let Some(before) = before_micros {
            if receipt.timestamp > before {
                continue;
            }
        }

        let score = if query.is_empty() {
            1.0
        } else {
            let desc = &receipt.action.description;
            let data_str = receipt
                .action
                .data
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default();
            let combined = format!("{} {}", desc, data_str);
            word_overlap(query, &combined)
        };

        if query.is_empty() || score > 0.0 {
            results.push((score, receipt));
        }
    }

    results.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.timestamp.cmp(&a.1.timestamp))
    });
    results.truncate(limit);

    let items: Vec<Value> = results
        .iter()
        .map(|(score, r)| {
            json!({
                "id": r.id.0,
                "actor": r.actor.0,
                "action_type": action_type_tag(&r.action_type),
                "description": r.action.description,
                "timestamp": micros_to_display(r.timestamp),
                "timestamp_micros": r.timestamp,
                "relevance_score": format!("{:.3}", score),
                "has_chain": r.previous_receipt.is_some(),
            })
        })
        .collect();

    tool_ok(
        id,
        pretty(&json!({
            "total_receipts": all_receipts.len(),
            "matches": items.len(),
            "results": items,
        })),
    )
}

// ── Tool 2: identity_receipt_pattern ─────────────────────────────────────

pub fn definition_identity_receipt_pattern() -> Value {
    json!({
        "name": "identity_receipt_pattern",
        "description": "Find receipt patterns. Detects frequency distributions, action sequences, and anomalous patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern_type": {
                    "type": "string",
                    "description": "Pattern type to detect: 'frequency' (action type distribution), 'sequence' (common action sequences), 'anomaly' (unusual patterns). Defaults to all."
                }
            }
        }
    })
}

pub fn execute_identity_receipt_pattern(server: &McpServer, id: Value, args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let mut receipts = load_all_receipts(&store);
    receipts.sort_by_key(|r| r.timestamp);

    let pattern_type = args
        .get("pattern_type")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    let mut output = json!({
        "total_receipts": receipts.len(),
        "pattern_type": pattern_type,
    });

    if receipts.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "total_receipts": 0,
                "pattern_type": pattern_type,
                "message": "No receipts found. Create some actions first.",
            })),
        );
    }

    // Frequency analysis
    if pattern_type == "frequency" || pattern_type == "all" {
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        let mut actor_counts: HashMap<String, usize> = HashMap::new();
        for r in &receipts {
            *type_counts
                .entry(action_type_tag(&r.action_type))
                .or_insert(0) += 1;
            *actor_counts.entry(r.actor.0.clone()).or_insert(0) += 1;
        }
        let mut type_freq: Vec<Value> = type_counts
            .iter()
            .map(|(k, v)| {
                json!({
                    "action_type": k,
                    "count": v,
                    "percentage": format!("{:.1}%", (*v as f64 / receipts.len() as f64) * 100.0),
                })
            })
            .collect();
        type_freq.sort_by(|a, b| {
            b["count"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["count"].as_u64().unwrap_or(0))
        });

        let mut actor_freq: Vec<Value> = actor_counts
            .iter()
            .map(|(k, v)| json!({"actor": k, "count": v}))
            .collect();
        actor_freq.sort_by(|a, b| {
            b["count"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["count"].as_u64().unwrap_or(0))
        });

        output["frequency"] = json!({
            "by_action_type": type_freq,
            "by_actor": actor_freq,
        });
    }

    // Sequence analysis
    if pattern_type == "sequence" || pattern_type == "all" {
        let mut bigrams: HashMap<String, usize> = HashMap::new();
        for w in receipts.windows(2) {
            let key = format!(
                "{} -> {}",
                action_type_tag(&w[0].action_type),
                action_type_tag(&w[1].action_type)
            );
            *bigrams.entry(key).or_insert(0) += 1;
        }
        let mut seq: Vec<Value> = bigrams
            .iter()
            .map(|(k, v)| json!({"sequence": k, "count": v}))
            .collect();
        seq.sort_by(|a, b| {
            b["count"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["count"].as_u64().unwrap_or(0))
        });
        seq.truncate(10);

        output["sequences"] = json!({ "top_bigrams": seq });
    }

    // Anomaly analysis
    if pattern_type == "anomaly" || pattern_type == "all" {
        let anomalies = detect_timing_anomalies(&receipts);
        output["anomalies"] = json!(anomalies);
    }

    tool_ok(id, pretty(&output))
}

/// Detect timing anomalies: unusually short or long gaps between receipts.
fn detect_timing_anomalies(receipts: &[ActionReceipt]) -> Vec<Value> {
    if receipts.len() < 3 {
        return vec![];
    }

    let mut gaps: Vec<u64> = Vec::new();
    for w in receipts.windows(2) {
        if w[1].timestamp > w[0].timestamp {
            gaps.push(w[1].timestamp - w[0].timestamp);
        }
    }
    if gaps.is_empty() {
        return vec![];
    }

    let mean = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
    let variance = gaps
        .iter()
        .map(|g| {
            let diff = *g as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / gaps.len() as f64;
    let stddev = variance.sqrt();

    let mut anomalies = Vec::new();
    for (i, w) in receipts.windows(2).enumerate() {
        if w[1].timestamp > w[0].timestamp {
            let gap = w[1].timestamp - w[0].timestamp;
            let z_score = if stddev > 0.0 {
                (gap as f64 - mean) / stddev
            } else {
                0.0
            };
            if z_score.abs() > 2.0 {
                let gap_secs = gap / 1_000_000;
                anomalies.push(json!({
                    "type": if z_score > 0.0 { "long_gap" } else { "rapid_succession" },
                    "between": [w[0].id.0, w[1].id.0],
                    "gap_seconds": gap_secs,
                    "z_score": format!("{:.2}", z_score),
                    "index": i,
                }));
            }
        }
    }
    anomalies.truncate(20);
    anomalies
}

// ── Tool 3: identity_receipt_timeline ────────────────────────────────────

pub fn definition_identity_receipt_timeline() -> Value {
    json!({
        "name": "identity_receipt_timeline",
        "description": "Reconstruct timeline from receipts. Returns ordered list of actions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "actor": {
                    "type": "string",
                    "description": "Filter by actor identity ID (aid_...)"
                },
                "start_time": {
                    "type": "number",
                    "description": "Start time (seconds since epoch)"
                },
                "end_time": {
                    "type": "number",
                    "description": "End time (seconds since epoch)"
                }
            }
        }
    })
}

pub fn execute_identity_receipt_timeline(server: &McpServer, id: Value, args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let mut receipts = load_all_receipts(&store);

    let actor_filter = args.get("actor").and_then(|v| v.as_str());
    let start_secs = args.get("start_time").and_then(|v| v.as_u64());
    let end_secs = args.get("end_time").and_then(|v| v.as_u64());

    let start_micros = start_secs.map(|s| s * 1_000_000);
    let end_micros = end_secs.map(|s| s * 1_000_000);

    receipts.retain(|r| {
        if let Some(af) = actor_filter {
            if r.actor.0 != af {
                return false;
            }
        }
        if let Some(start) = start_micros {
            if r.timestamp < start {
                return false;
            }
        }
        if let Some(end) = end_micros {
            if r.timestamp > end {
                return false;
            }
        }
        true
    });

    receipts.sort_by_key(|r| r.timestamp);
    let total = receipts.len();

    let timeline: Vec<Value> = receipts
        .iter()
        .enumerate()
        .map(|(i, r)| {
            json!({
                "index": i,
                "id": r.id.0,
                "actor": r.actor.0,
                "action_type": action_type_tag(&r.action_type),
                "description": r.action.description,
                "timestamp": micros_to_display(r.timestamp),
                "timestamp_micros": r.timestamp,
                "chained_from": r.previous_receipt.as_ref().map(|p| &p.0),
            })
        })
        .collect();

    let time_span = if receipts.len() >= 2 {
        let first = receipts.first().unwrap().timestamp;
        let last = receipts.last().unwrap().timestamp;
        let span_secs = (last - first) / 1_000_000;
        json!({
            "first": micros_to_display(first),
            "last": micros_to_display(last),
            "span_seconds": span_secs,
        })
    } else {
        json!(null)
    };

    tool_ok(
        id,
        pretty(&json!({
            "total_events": total,
            "time_span": time_span,
            "timeline": timeline,
        })),
    )
}

// ── Tool 4: identity_receipt_anomalies ───────────────────────────────────

pub fn definition_identity_receipt_anomalies() -> Value {
    json!({
        "name": "identity_receipt_anomalies",
        "description": "Find anomalous patterns in receipts. Detects unusual timing, repeated action types, and potential issues.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub fn execute_identity_receipt_anomalies(server: &McpServer, id: Value, _args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let mut receipts = load_all_receipts(&store);
    receipts.sort_by_key(|r| r.timestamp);

    if receipts.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "total_receipts": 0,
                "anomalies": [],
                "message": "No receipts found. Create some actions first.",
            })),
        );
    }

    let mut all_anomalies: Vec<Value> = Vec::new();

    // 1. Timing anomalies
    let timing = detect_timing_anomalies(&receipts);
    for a in timing {
        all_anomalies.push(a);
    }

    // 2. Rapid repetition of same action type (burst detection)
    let mut burst_count = 1usize;
    for w in receipts.windows(2) {
        if action_type_tag(&w[0].action_type) == action_type_tag(&w[1].action_type) {
            burst_count += 1;
            if burst_count >= 5 {
                all_anomalies.push(json!({
                    "type": "action_burst",
                    "action_type": action_type_tag(&w[1].action_type),
                    "burst_length": burst_count,
                    "at_receipt": w[1].id.0,
                    "description": format!(
                        "{} consecutive '{}' actions detected",
                        burst_count,
                        action_type_tag(&w[1].action_type)
                    ),
                }));
            }
        } else {
            burst_count = 1;
        }
    }

    // 3. Orphan receipts (reference a previous_receipt that doesn't exist)
    let receipt_ids: std::collections::HashSet<String> =
        receipts.iter().map(|r| r.id.0.clone()).collect();
    for r in &receipts {
        if let Some(prev) = &r.previous_receipt {
            if !receipt_ids.contains(&prev.0) {
                all_anomalies.push(json!({
                    "type": "broken_chain",
                    "receipt_id": r.id.0,
                    "references_missing": prev.0,
                    "description": format!(
                        "Receipt {} references missing predecessor {}",
                        r.id.0, prev.0
                    ),
                }));
            }
        }
    }

    // 4. Duplicate descriptions (copy-paste actions)
    let mut desc_counts: HashMap<String, Vec<String>> = HashMap::new();
    for r in &receipts {
        desc_counts
            .entry(r.action.description.clone())
            .or_default()
            .push(r.id.0.clone());
    }
    for (desc, ids) in &desc_counts {
        if ids.len() >= 3 {
            all_anomalies.push(json!({
                "type": "repeated_description",
                "description": desc,
                "count": ids.len(),
                "receipt_ids": &ids[..std::cmp::min(5, ids.len())],
            }));
        }
    }

    all_anomalies.truncate(50);

    tool_ok(
        id,
        pretty(&json!({
            "total_receipts": receipts.len(),
            "anomaly_count": all_anomalies.len(),
            "anomalies": all_anomalies,
        })),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 6: Causal Attribution
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 5: identity_attribute_cause ─────────────────────────────────────

pub fn definition_identity_attribute_cause() -> Value {
    json!({
        "name": "identity_attribute_cause",
        "description": "Attribute cause of outcome. Traces back through receipt chains to find causal actions.",
        "inputSchema": {
            "type": "object",
            "required": ["outcome"],
            "properties": {
                "outcome": {
                    "type": "string",
                    "description": "Description of the outcome to attribute"
                },
                "receipt_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional list of receipt IDs to consider as starting points"
                }
            }
        }
    })
}

pub fn execute_identity_attribute_cause(server: &McpServer, id: Value, args: &Value) -> Value {
    let outcome = match args.get("outcome").and_then(|v| v.as_str()) {
        Some(o) => o,
        None => return tool_error(id, "'outcome' is required"),
    };

    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);

    let receipt_map: HashMap<String, &ActionReceipt> =
        all_receipts.iter().map(|r| (r.id.0.clone(), r)).collect();

    // Find candidate receipts: either specified or matched by outcome text.
    let candidates: Vec<&ActionReceipt> =
        if let Some(ids) = args.get("receipt_ids").and_then(|v| v.as_array()) {
            ids.iter()
                .filter_map(|id_val| id_val.as_str())
                .filter_map(|rid| receipt_map.get(rid).copied())
                .collect()
        } else {
            let mut scored: Vec<(f64, &ActionReceipt)> = all_receipts
                .iter()
                .map(|r| {
                    let combined = format!(
                        "{} {}",
                        r.action.description,
                        r.action
                            .data
                            .as_ref()
                            .map(|d| d.to_string())
                            .unwrap_or_default()
                    );
                    (word_overlap(outcome, &combined), r)
                })
                .filter(|(s, _)| *s > 0.0)
                .collect();
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            scored.truncate(5);
            scored.into_iter().map(|(_, r)| r).collect()
        };

    if candidates.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "outcome": outcome,
                "causal_chains": [],
                "message": "No matching receipts found for the given outcome.",
            })),
        );
    }

    let mut chains: Vec<Value> = Vec::new();
    for candidate in &candidates {
        let mut chain: Vec<Value> = Vec::new();
        let mut current_id = Some(candidate.id.0.clone());
        let mut visited = std::collections::HashSet::new();
        let mut depth = 0usize;

        while let Some(cid) = current_id {
            if visited.contains(&cid) || depth > 50 {
                break;
            }
            visited.insert(cid.clone());
            if let Some(r) = receipt_map.get(&cid) {
                chain.push(json!({
                    "depth": depth,
                    "id": r.id.0,
                    "actor": r.actor.0,
                    "action_type": action_type_tag(&r.action_type),
                    "description": r.action.description,
                    "timestamp": micros_to_display(r.timestamp),
                }));
                current_id = r.previous_receipt.as_ref().map(|p| p.0.clone());
            } else {
                break;
            }
            depth += 1;
        }

        chains.push(json!({
            "starting_receipt": candidate.id.0,
            "chain_length": chain.len(),
            "chain": chain,
        }));
    }

    tool_ok(
        id,
        pretty(&json!({
            "outcome": outcome,
            "candidates_found": candidates.len(),
            "causal_chains": chains,
        })),
    )
}

// ── Tool 6: identity_attribute_chain ─────────────────────────────────────

pub fn definition_identity_attribute_chain() -> Value {
    json!({
        "name": "identity_attribute_chain",
        "description": "Get full causal chain for a receipt. Follows previous_receipt links backwards.",
        "inputSchema": {
            "type": "object",
            "required": ["receipt_id"],
            "properties": {
                "receipt_id": {
                    "type": "string",
                    "description": "Receipt ID to trace (arec_...)"
                }
            }
        }
    })
}

pub fn execute_identity_attribute_chain(server: &McpServer, id: Value, args: &Value) -> Value {
    let receipt_id = match args.get("receipt_id").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return tool_error(id, "'receipt_id' is required"),
    };

    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };

    // First check the requested receipt exists.
    let rid = ReceiptId(receipt_id.to_string());
    if store.load(&rid).is_err() {
        return tool_error(id, format!("Receipt not found: {receipt_id}"));
    }

    let all_receipts = load_all_receipts(&store);
    let receipt_map: HashMap<String, &ActionReceipt> =
        all_receipts.iter().map(|r| (r.id.0.clone(), r)).collect();

    // Walk backwards via previous_receipt
    let mut chain: Vec<Value> = Vec::new();
    let mut current_id = Some(receipt_id.to_string());
    let mut visited = std::collections::HashSet::new();

    while let Some(cid) = current_id {
        if visited.contains(&cid) {
            chain.push(json!({"cycle_detected_at": cid}));
            break;
        }
        visited.insert(cid.clone());
        if let Some(r) = receipt_map.get(&cid) {
            chain.push(json!({
                "depth": chain.len(),
                "id": r.id.0,
                "actor": r.actor.0,
                "action_type": action_type_tag(&r.action_type),
                "description": r.action.description,
                "timestamp": micros_to_display(r.timestamp),
                "timestamp_micros": r.timestamp,
                "previous_receipt": r.previous_receipt.as_ref().map(|p| &p.0),
            }));
            current_id = r.previous_receipt.as_ref().map(|p| p.0.clone());
        } else {
            if cid != receipt_id {
                chain.push(json!({
                    "missing_receipt": cid,
                    "note": "Chain broken \u{2014} referenced receipt not found in store",
                }));
            }
            break;
        }
    }

    // Also walk forward: find receipts that reference this one
    let mut forward: Vec<Value> = Vec::new();
    for r in &all_receipts {
        if let Some(prev) = &r.previous_receipt {
            if prev.0 == receipt_id {
                forward.push(json!({
                    "id": r.id.0,
                    "actor": r.actor.0,
                    "action_type": action_type_tag(&r.action_type),
                    "description": r.action.description,
                    "timestamp": micros_to_display(r.timestamp),
                }));
            }
        }
    }

    tool_ok(
        id,
        pretty(&json!({
            "receipt_id": receipt_id,
            "chain_length": chain.len(),
            "backward_chain": chain,
            "forward_dependents": forward,
        })),
    )
}

// ── Tool 7: identity_attribute_responsibility ────────────────────────────

pub fn definition_identity_attribute_responsibility() -> Value {
    json!({
        "name": "identity_attribute_responsibility",
        "description": "Assign responsibility percentages. Identifies actors involved in an outcome and their contribution weight.",
        "inputSchema": {
            "type": "object",
            "required": ["outcome"],
            "properties": {
                "outcome": {
                    "type": "string",
                    "description": "Description of the outcome to attribute responsibility for"
                }
            }
        }
    })
}

pub fn execute_identity_attribute_responsibility(
    server: &McpServer,
    id: Value,
    args: &Value,
) -> Value {
    let outcome = match args.get("outcome").and_then(|v| v.as_str()) {
        Some(o) => o,
        None => return tool_error(id, "'outcome' is required"),
    };

    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);

    let mut actor_scores: HashMap<String, f64> = HashMap::new();
    let mut actor_receipt_count: HashMap<String, usize> = HashMap::new();
    let mut total_relevance = 0.0f64;

    for r in &all_receipts {
        let combined = format!(
            "{} {}",
            r.action.description,
            r.action
                .data
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default()
        );
        let score = word_overlap(outcome, &combined);
        if score > 0.0 {
            *actor_scores.entry(r.actor.0.clone()).or_insert(0.0) += score;
            *actor_receipt_count.entry(r.actor.0.clone()).or_insert(0) += 1;
            total_relevance += score;
        }
    }

    if actor_scores.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "outcome": outcome,
                "actors": [],
                "message": "No matching receipts found for responsibility attribution.",
            })),
        );
    }

    let mut actors: Vec<Value> = actor_scores
        .iter()
        .map(|(actor, score)| {
            let pct = if total_relevance > 0.0 {
                (score / total_relevance) * 100.0
            } else {
                0.0
            };
            json!({
                "actor": actor,
                "responsibility_percent": format!("{:.1}%", pct),
                "relevance_score": format!("{:.3}", score),
                "matching_receipts": actor_receipt_count.get(actor).copied().unwrap_or(0),
            })
        })
        .collect();

    actors.sort_by(|a, b| {
        let a_s: f64 = a["relevance_score"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        let b_s: f64 = b["relevance_score"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        b_s.partial_cmp(&a_s).unwrap_or(std::cmp::Ordering::Equal)
    });

    tool_ok(
        id,
        pretty(&json!({
            "outcome": outcome,
            "total_relevant_receipts": actor_receipt_count.values().sum::<usize>(),
            "actors": actors,
        })),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 7: Consent Chains
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 8: identity_consent_chain ───────────────────────────────────────

pub fn definition_identity_consent_chain() -> Value {
    json!({
        "name": "identity_consent_chain",
        "description": "Analyze consent chain for an action. Traces delegation chain from actor back to original grantor.",
        "inputSchema": {
            "type": "object",
            "required": ["action", "actor"],
            "properties": {
                "action": {
                    "type": "string",
                    "description": "The action or capability to trace consent for"
                },
                "actor": {
                    "type": "string",
                    "description": "The actor identity ID performing the action (aid_...)"
                }
            }
        }
    })
}

pub fn execute_identity_consent_chain(server: &McpServer, id: Value, args: &Value) -> Value {
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "'action' is required"),
    };
    let actor = match args.get("actor").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "'actor' is required"),
    };

    let trust_store = match TrustStore::new(&server.trust_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open trust store: {e}")),
    };
    let all_grants = load_all_grants(&trust_store);

    let grant_map: HashMap<String, &TrustGrant> =
        all_grants.iter().map(|g| (g.id.0.clone(), g)).collect();

    // Find grants where the actor is the grantee.
    let actor_grants: Vec<&TrustGrant> =
        all_grants.iter().filter(|g| g.grantee.0 == actor).collect();

    let mut consent_chains: Vec<Value> = Vec::new();
    for grant in &actor_grants {
        // Check if any capability matches the action.
        let cap_match = grant.capabilities.iter().any(|cap| {
            let cap_lower = cap.uri.to_lowercase();
            let action_lower = action.to_lowercase();
            cap_lower.contains(&action_lower)
                || action_lower.contains(&cap_lower)
                || word_overlap(&cap.uri, action) > 0.2
        });

        if !cap_match && !grant.capabilities.iter().any(|c| c.uri == "*") {
            continue;
        }

        // Trace delegation chain backwards via parent_grant.
        let mut chain: Vec<Value> = Vec::new();
        let mut current_grant_id = Some(grant.id.0.clone());
        let mut visited = std::collections::HashSet::new();

        while let Some(gid) = current_grant_id {
            if visited.contains(&gid) {
                chain.push(json!({"cycle_detected_at": gid}));
                break;
            }
            visited.insert(gid.clone());
            if let Some(g) = grant_map.get(&gid) {
                let caps: Vec<&str> = g.capabilities.iter().map(|c| c.uri.as_str()).collect();
                chain.push(json!({
                    "grant_id": g.id.0,
                    "grantor": g.grantor.0,
                    "grantee": g.grantee.0,
                    "capabilities": caps,
                    "delegation_allowed": g.delegation_allowed,
                    "delegation_depth": g.delegation_depth,
                    "granted_at": micros_to_display(g.granted_at),
                }));
                current_grant_id = g.parent_grant.as_ref().map(|p| p.0.clone());
            } else {
                chain.push(json!({
                    "missing_grant": gid,
                    "note": "Chain broken \u{2014} referenced grant not found",
                }));
                break;
            }
        }

        consent_chains.push(json!({
            "starting_grant": grant.id.0,
            "chain_length": chain.len(),
            "chain": chain,
            "consent_valid": !chain.iter().any(|c|
                c.get("missing_grant").is_some() || c.get("cycle_detected_at").is_some()
            ),
        }));
    }

    tool_ok(
        id,
        pretty(&json!({
            "action": action,
            "actor": actor,
            "grants_found": actor_grants.len(),
            "matching_chains": consent_chains.len(),
            "consent_chains": consent_chains,
        })),
    )
}

// ── Tool 9: identity_consent_validate ────────────────────────────────────

pub fn definition_identity_consent_validate() -> Value {
    json!({
        "name": "identity_consent_validate",
        "description": "Validate that a consent/delegation chain is intact. Checks all links from a trust grant back to root.",
        "inputSchema": {
            "type": "object",
            "required": ["trust_id"],
            "properties": {
                "trust_id": {
                    "type": "string",
                    "description": "Trust grant ID to validate (atrust_...)"
                }
            }
        }
    })
}

pub fn execute_identity_consent_validate(server: &McpServer, id: Value, args: &Value) -> Value {
    let trust_id = match args.get("trust_id").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return tool_error(id, "'trust_id' is required"),
    };

    let trust_store = match TrustStore::new(&server.trust_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open trust store: {e}")),
    };
    let all_grants = load_all_grants(&trust_store);
    let grant_map: HashMap<String, &TrustGrant> =
        all_grants.iter().map(|g| (g.id.0.clone(), g)).collect();

    if !grant_map.contains_key(trust_id) {
        return tool_error(id, format!("Trust grant not found: {trust_id}"));
    }

    let mut chain: Vec<Value> = Vec::new();
    let mut issues: Vec<Value> = Vec::new();
    let mut current_grant_id = Some(trust_id.to_string());
    let mut visited = std::collections::HashSet::new();

    while let Some(gid) = current_grant_id {
        if visited.contains(&gid) {
            issues.push(json!({
                "type": "cycle",
                "at_grant": gid,
                "description": "Circular delegation detected",
            }));
            break;
        }
        visited.insert(gid.clone());

        if let Some(g) = grant_map.get(&gid) {
            // Check delegation depth consistency.
            if let Some(parent_id) = &g.parent_grant {
                if let Some(parent) = grant_map.get(&parent_id.0) {
                    if !parent.delegation_allowed {
                        issues.push(json!({
                            "type": "delegation_not_allowed",
                            "parent_grant": parent.id.0,
                            "child_grant": g.id.0,
                            "description": "Parent grant does not allow delegation",
                        }));
                    }
                    // Check capabilities are a subset.
                    let parent_caps: std::collections::HashSet<&str> =
                        parent.capabilities.iter().map(|c| c.uri.as_str()).collect();
                    let has_wildcard = parent_caps.contains("*");
                    for cap in &g.capabilities {
                        if !has_wildcard && !parent_caps.contains(cap.uri.as_str()) {
                            issues.push(json!({
                                "type": "capability_escalation",
                                "grant": g.id.0,
                                "capability": cap.uri,
                                "description": format!(
                                    "Capability '{}' not present in parent grant",
                                    cap.uri
                                ),
                            }));
                        }
                    }
                }
            }

            let caps: Vec<&str> = g.capabilities.iter().map(|c| c.uri.as_str()).collect();
            chain.push(json!({
                "grant_id": g.id.0,
                "grantor": g.grantor.0,
                "grantee": g.grantee.0,
                "capabilities": caps,
                "delegation_allowed": g.delegation_allowed,
                "delegation_depth": g.delegation_depth,
                "granted_at": micros_to_display(g.granted_at),
            }));
            current_grant_id = g.parent_grant.as_ref().map(|p| p.0.clone());
        } else {
            issues.push(json!({
                "type": "missing_grant",
                "grant_id": gid,
                "description": "Referenced parent grant not found in store",
            }));
            break;
        }
    }

    let is_valid = issues.is_empty();

    tool_ok(
        id,
        pretty(&json!({
            "trust_id": trust_id,
            "valid": is_valid,
            "chain_length": chain.len(),
            "chain": chain,
            "issues": issues,
        })),
    )
}

// ── Tool 10: identity_consent_gaps ───────────────────────────────────────

pub fn definition_identity_consent_gaps() -> Value {
    json!({
        "name": "identity_consent_gaps",
        "description": "Find gaps in consent coverage. Identifies actions (receipts) without proper delegation chain backing.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub fn execute_identity_consent_gaps(server: &McpServer, id: Value, _args: &Value) -> Value {
    let receipt_store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let trust_store = match TrustStore::new(&server.trust_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open trust store: {e}")),
    };

    let receipts = load_all_receipts(&receipt_store);
    let grants = load_all_grants(&trust_store);

    if receipts.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "total_receipts": 0,
                "total_grants": grants.len(),
                "gaps": [],
                "message": "No receipts to analyze.",
            })),
        );
    }

    // Build a map of actors -> capabilities they have been granted.
    let mut actor_capabilities: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for g in &grants {
        let entry = actor_capabilities.entry(g.grantee.0.clone()).or_default();
        for cap in &g.capabilities {
            entry.insert(cap.uri.clone());
        }
    }

    let mut gaps: Vec<Value> = Vec::new();
    let mut covered = 0usize;

    for r in &receipts {
        let actor_caps = actor_capabilities.get(&r.actor.0);
        let has_any_grant = actor_caps.is_some_and(|caps| !caps.is_empty());

        if !has_any_grant {
            gaps.push(json!({
                "type": "no_consent",
                "receipt_id": r.id.0,
                "actor": r.actor.0,
                "action_type": action_type_tag(&r.action_type),
                "description": r.action.description,
                "timestamp": micros_to_display(r.timestamp),
                "issue": "Actor has no trust grants \u{2014} action taken without delegation",
            }));
        } else {
            covered += 1;
        }
    }

    // Check for actors with grants but no actions (unused delegation).
    let receipt_actors: std::collections::HashSet<String> =
        receipts.iter().map(|r| r.actor.0.clone()).collect();
    let mut unused_grants: Vec<Value> = Vec::new();
    for g in &grants {
        if !receipt_actors.contains(&g.grantee.0) {
            let caps: Vec<&str> = g.capabilities.iter().map(|c| c.uri.as_str()).collect();
            unused_grants.push(json!({
                "grant_id": g.id.0,
                "grantee": g.grantee.0,
                "capabilities": caps,
                "note": "Grantee has trust but no receipts \u{2014} unused delegation",
            }));
        }
    }

    gaps.truncate(50);
    unused_grants.truncate(20);

    tool_ok(
        id,
        pretty(&json!({
            "total_receipts": receipts.len(),
            "total_grants": grants.len(),
            "covered_actions": covered,
            "uncovered_actions": gaps.len(),
            "coverage_percent": if receipts.is_empty() {
                "N/A".to_string()
            } else {
                format!("{:.1}%", (covered as f64 / receipts.len() as f64) * 100.0)
            },
            "gaps": gaps,
            "unused_grants": unused_grants,
        })),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 8: Behavioral Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════

/// Build a behavioral fingerprint from receipts.
fn build_fingerprint(receipts: &[ActionReceipt]) -> Value {
    if receipts.is_empty() {
        return json!({
            "total_actions": 0,
            "action_type_distribution": {},
            "avg_gap_seconds": null,
            "stddev_gap_seconds": null,
            "active_hours": [],
            "description_avg_length": 0,
        });
    }

    // Action type distribution
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for r in receipts {
        *type_counts
            .entry(action_type_tag(&r.action_type))
            .or_insert(0) += 1;
    }
    let type_dist: HashMap<String, f64> = type_counts
        .iter()
        .map(|(k, v)| (k.clone(), *v as f64 / receipts.len() as f64))
        .collect();

    // Timing statistics
    let mut sorted: Vec<&ActionReceipt> = receipts.iter().collect();
    sorted.sort_by_key(|r| r.timestamp);

    let gaps: Vec<f64> = sorted
        .windows(2)
        .filter_map(|w| {
            if w[1].timestamp > w[0].timestamp {
                Some((w[1].timestamp - w[0].timestamp) as f64 / 1_000_000.0)
            } else {
                None
            }
        })
        .collect();

    let avg_gap = if gaps.is_empty() {
        0.0
    } else {
        gaps.iter().sum::<f64>() / gaps.len() as f64
    };

    let variance = if gaps.is_empty() {
        0.0
    } else {
        gaps.iter().map(|g| (g - avg_gap).powi(2)).sum::<f64>() / gaps.len() as f64
    };
    let stddev_gap = variance.sqrt();

    // Active hours (based on hour-of-day from timestamps).
    let mut hour_counts = [0u32; 24];
    for r in receipts {
        let secs = r.timestamp / 1_000_000;
        let hour = ((secs % 86400) / 3600) as usize;
        if hour < 24 {
            hour_counts[hour] += 1;
        }
    }
    let active_hours: Vec<usize> = hour_counts
        .iter()
        .enumerate()
        .filter(|(_, &c)| c > 0)
        .map(|(h, _)| h)
        .collect();

    // Average description length
    let total_desc_len: usize = receipts.iter().map(|r| r.action.description.len()).sum();
    let avg_desc_len = total_desc_len / receipts.len();

    json!({
        "total_actions": receipts.len(),
        "action_type_distribution": type_dist,
        "avg_gap_seconds": format!("{:.1}", avg_gap),
        "stddev_gap_seconds": format!("{:.1}", stddev_gap),
        "active_hours": active_hours,
        "description_avg_length": avg_desc_len,
        "hour_histogram": hour_counts.to_vec(),
    })
}

/// Compare two fingerprints and return a similarity score 0.0 - 1.0.
fn fingerprint_similarity(baseline: &Value, current: &Value) -> f64 {
    let mut scores: Vec<f64> = Vec::new();

    // Compare action type distributions (cosine similarity).
    if let (Some(base_dist), Some(curr_dist)) = (
        baseline["action_type_distribution"].as_object(),
        current["action_type_distribution"].as_object(),
    ) {
        let all_keys: std::collections::HashSet<&String> =
            base_dist.keys().chain(curr_dist.keys()).collect();
        if !all_keys.is_empty() {
            let mut dot = 0.0f64;
            let mut mag_a = 0.0f64;
            let mut mag_b = 0.0f64;
            for key in &all_keys {
                let a = base_dist.get(*key).and_then(|v| v.as_f64()).unwrap_or(0.0);
                let b = curr_dist.get(*key).and_then(|v| v.as_f64()).unwrap_or(0.0);
                dot += a * b;
                mag_a += a * a;
                mag_b += b * b;
            }
            let cosine = if mag_a > 0.0 && mag_b > 0.0 {
                dot / (mag_a.sqrt() * mag_b.sqrt())
            } else {
                0.0
            };
            scores.push(cosine);
        }
    }

    // Compare average gap (closer = more similar).
    if let (Some(base_gap_str), Some(curr_gap_str)) = (
        baseline["avg_gap_seconds"].as_str(),
        current["avg_gap_seconds"].as_str(),
    ) {
        if let (Ok(bg), Ok(cg)) = (base_gap_str.parse::<f64>(), curr_gap_str.parse::<f64>()) {
            if bg > 0.0 || cg > 0.0 {
                let max_val = bg.max(cg);
                let diff = (bg - cg).abs();
                let sim = 1.0 - (diff / max_val).min(1.0);
                scores.push(sim);
            }
        }
    }

    // Compare active hours (Jaccard similarity).
    if let (Some(base_hours), Some(curr_hours)) = (
        baseline["active_hours"].as_array(),
        current["active_hours"].as_array(),
    ) {
        let bh: std::collections::HashSet<u64> =
            base_hours.iter().filter_map(|v| v.as_u64()).collect();
        let ch: std::collections::HashSet<u64> =
            curr_hours.iter().filter_map(|v| v.as_u64()).collect();
        if !bh.is_empty() || !ch.is_empty() {
            let intersection = bh.intersection(&ch).count() as f64;
            let union = bh.union(&ch).count() as f64;
            scores.push(intersection / union);
        }
    }

    if scores.is_empty() {
        return 0.0;
    }
    scores.iter().sum::<f64>() / scores.len() as f64
}

// ── Tool 11: identity_fingerprint_build ──────────────────────────────────

pub fn definition_identity_fingerprint_build() -> Value {
    json!({
        "name": "identity_fingerprint_build",
        "description": "Build behavioral fingerprint from receipts. Analyzes action timing, types, and patterns to create a statistical profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to fingerprint (aid_...). Defaults to all agents."
                }
            }
        }
    })
}

pub fn execute_identity_fingerprint_build(server: &McpServer, id: Value, args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);
    let agent_id = args.get("agent_id").and_then(|v| v.as_str());

    let filtered: Vec<&ActionReceipt> = if let Some(aid) = agent_id {
        all_receipts.iter().filter(|r| r.actor.0 == aid).collect()
    } else {
        all_receipts.iter().collect()
    };

    if filtered.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "agent_id": agent_id.unwrap_or("all"),
                "fingerprint": null,
                "message": "No receipts found for fingerprint building.",
            })),
        );
    }

    let fingerprint = build_fingerprint(&filtered.into_iter().cloned().collect::<Vec<_>>());

    tool_ok(
        id,
        pretty(&json!({
            "agent_id": agent_id.unwrap_or("all"),
            "fingerprint": fingerprint,
            "built_at": now_secs(),
        })),
    )
}

// ── Tool 12: identity_fingerprint_match ──────────────────────────────────

pub fn definition_identity_fingerprint_match() -> Value {
    json!({
        "name": "identity_fingerprint_match",
        "description": "Match current behavior to baseline fingerprint. Compares recent receipts against the overall behavioral profile.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to match (aid_...)"
                }
            }
        }
    })
}

pub fn execute_identity_fingerprint_match(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "'agent_id' is required"),
    };

    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);

    let mut agent_receipts: Vec<ActionReceipt> = all_receipts
        .into_iter()
        .filter(|r| r.actor.0 == agent_id)
        .collect();
    agent_receipts.sort_by_key(|r| r.timestamp);

    if agent_receipts.len() < 2 {
        return tool_ok(
            id,
            pretty(&json!({
                "agent_id": agent_id,
                "message": "Not enough receipts for fingerprint matching (need at least 2).",
                "receipt_count": agent_receipts.len(),
            })),
        );
    }

    // Split into baseline (first 70%) and recent (last 30%).
    let split_point = (agent_receipts.len() as f64 * 0.7).ceil() as usize;
    let split_point = split_point.max(1).min(agent_receipts.len() - 1);
    let baseline_receipts = &agent_receipts[..split_point];
    let recent_receipts = &agent_receipts[split_point..];

    let baseline_fp = build_fingerprint(baseline_receipts);
    let recent_fp = build_fingerprint(recent_receipts);
    let similarity = fingerprint_similarity(&baseline_fp, &recent_fp);

    let assessment = if similarity > 0.9 {
        "highly_consistent"
    } else if similarity > 0.7 {
        "consistent"
    } else if similarity > 0.5 {
        "some_deviation"
    } else if similarity > 0.3 {
        "significant_deviation"
    } else {
        "anomalous"
    };

    tool_ok(
        id,
        pretty(&json!({
            "agent_id": agent_id,
            "total_receipts": agent_receipts.len(),
            "baseline_count": baseline_receipts.len(),
            "recent_count": recent_receipts.len(),
            "similarity_score": format!("{:.3}", similarity),
            "assessment": assessment,
            "baseline_fingerprint": baseline_fp,
            "recent_fingerprint": recent_fp,
        })),
    )
}

// ── Tool 13: identity_fingerprint_anomaly ────────────────────────────────

pub fn definition_identity_fingerprint_anomaly() -> Value {
    json!({
        "name": "identity_fingerprint_anomaly",
        "description": "Detect behavioral anomalies by comparing recent behavior to baseline fingerprint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID (aid_...). Analyzes all agents if omitted."
                }
            }
        }
    })
}

pub fn execute_identity_fingerprint_anomaly(server: &McpServer, id: Value, args: &Value) -> Value {
    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);
    let target_agent = args.get("agent_id").and_then(|v| v.as_str());

    // Group receipts by actor.
    let mut by_actor: HashMap<String, Vec<ActionReceipt>> = HashMap::new();
    for r in all_receipts {
        if let Some(aid) = target_agent {
            if r.actor.0 != aid {
                continue;
            }
        }
        by_actor.entry(r.actor.0.clone()).or_default().push(r);
    }

    if by_actor.is_empty() {
        return tool_ok(
            id,
            pretty(&json!({
                "agent_id": target_agent.unwrap_or("all"),
                "anomalies": [],
                "message": "No receipts found for anomaly detection.",
            })),
        );
    }

    let mut all_anomalies: Vec<Value> = Vec::new();

    for (actor, mut receipts) in by_actor {
        receipts.sort_by_key(|r| r.timestamp);

        if receipts.len() < 5 {
            continue;
        }

        let split_point = (receipts.len() as f64 * 0.7).ceil() as usize;
        let split_point = split_point.max(1).min(receipts.len() - 1);
        let baseline = &receipts[..split_point];
        let recent = &receipts[split_point..];

        let baseline_fp = build_fingerprint(baseline);
        let recent_fp = build_fingerprint(recent);
        let similarity = fingerprint_similarity(&baseline_fp, &recent_fp);

        let mut agent_anomalies: Vec<Value> = Vec::new();

        // 1. New action types not in baseline.
        if let (Some(base_dist), Some(curr_dist)) = (
            baseline_fp["action_type_distribution"].as_object(),
            recent_fp["action_type_distribution"].as_object(),
        ) {
            for key in curr_dist.keys() {
                if !base_dist.contains_key(key) {
                    agent_anomalies.push(json!({
                        "type": "new_action_type",
                        "action_type": key,
                        "description": format!(
                            "Action type '{}' appeared in recent behavior but not in baseline",
                            key
                        ),
                    }));
                }
            }
            for key in base_dist.keys() {
                if !curr_dist.contains_key(key) {
                    agent_anomalies.push(json!({
                        "type": "missing_action_type",
                        "action_type": key,
                        "description": format!(
                            "Action type '{}' present in baseline but absent in recent behavior",
                            key
                        ),
                    }));
                }
            }
        }

        // 2. Timing change.
        if let (Some(bg_str), Some(cg_str)) = (
            baseline_fp["avg_gap_seconds"].as_str(),
            recent_fp["avg_gap_seconds"].as_str(),
        ) {
            if let (Ok(bg), Ok(cg)) = (bg_str.parse::<f64>(), cg_str.parse::<f64>()) {
                if bg > 0.0 {
                    let ratio = cg / bg;
                    if ratio > 3.0 {
                        agent_anomalies.push(json!({
                            "type": "timing_slowdown",
                            "baseline_avg_gap": bg_str,
                            "recent_avg_gap": cg_str,
                            "ratio": format!("{:.1}x", ratio),
                            "description": "Recent actions are significantly slower than baseline",
                        }));
                    } else if ratio < 0.33 {
                        agent_anomalies.push(json!({
                            "type": "timing_speedup",
                            "baseline_avg_gap": bg_str,
                            "recent_avg_gap": cg_str,
                            "ratio": format!("{:.1}x", ratio),
                            "description": "Recent actions are significantly faster than baseline",
                        }));
                    }
                }
            }
        }

        if similarity < 0.7 || !agent_anomalies.is_empty() {
            all_anomalies.push(json!({
                "agent_id": actor,
                "similarity_score": format!("{:.3}", similarity),
                "receipt_count": receipts.len(),
                "anomalies": agent_anomalies,
            }));
        }
    }

    tool_ok(
        id,
        pretty(&json!({
            "agent_id": target_agent.unwrap_or("all"),
            "agents_analyzed": all_anomalies.len(),
            "results": all_anomalies,
        })),
    )
}

// ── Tool 14: identity_fingerprint_alert ──────────────────────────────────

pub fn definition_identity_fingerprint_alert() -> Value {
    json!({
        "name": "identity_fingerprint_alert",
        "description": "Check if current behavior deviates from fingerprint beyond a threshold. Returns alert status.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to monitor (aid_...)"
                },
                "threshold": {
                    "type": "number",
                    "description": "Similarity threshold (0.0-1.0). Alert triggers if similarity drops below this. Default: 0.7"
                }
            }
        }
    })
}

pub fn execute_identity_fingerprint_alert(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "'agent_id' is required"),
    };
    let threshold = args
        .get("threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.7);

    let store = match ReceiptStore::new(&server.receipt_dir) {
        Ok(s) => s,
        Err(e) => return tool_error(id, format!("Failed to open receipt store: {e}")),
    };
    let all_receipts = load_all_receipts(&store);

    let mut agent_receipts: Vec<ActionReceipt> = all_receipts
        .into_iter()
        .filter(|r| r.actor.0 == agent_id)
        .collect();
    agent_receipts.sort_by_key(|r| r.timestamp);

    if agent_receipts.len() < 5 {
        return tool_ok(
            id,
            pretty(&json!({
                "agent_id": agent_id,
                "threshold": threshold,
                "alert": false,
                "status": "insufficient_data",
                "message": format!(
                    "Need at least 5 receipts for alerting (have {})",
                    agent_receipts.len()
                ),
            })),
        );
    }

    let split_point = (agent_receipts.len() as f64 * 0.7).ceil() as usize;
    let split_point = split_point.max(1).min(agent_receipts.len() - 1);
    let baseline = &agent_receipts[..split_point];
    let recent = &agent_receipts[split_point..];

    let baseline_fp = build_fingerprint(baseline);
    let recent_fp = build_fingerprint(recent);
    let similarity = fingerprint_similarity(&baseline_fp, &recent_fp);

    let alert = similarity < threshold;
    let severity = if similarity < threshold * 0.5 {
        "critical"
    } else if similarity < threshold * 0.75 {
        "high"
    } else if alert {
        "medium"
    } else {
        "none"
    };

    tool_ok(
        id,
        pretty(&json!({
            "agent_id": agent_id,
            "threshold": threshold,
            "similarity_score": format!("{:.3}", similarity),
            "alert": alert,
            "severity": severity,
            "status": if alert { "deviation_detected" } else { "normal" },
            "baseline_count": baseline.len(),
            "recent_count": recent.len(),
            "checked_at": now_secs(),
        })),
    )
}

// ── Convenience wrappers ─────────────────────────────────────────────────────

pub fn all_definitions() -> Vec<Value> {
    vec![
        definition_identity_receipt_search(),
        definition_identity_receipt_pattern(),
        definition_identity_receipt_timeline(),
        definition_identity_receipt_anomalies(),
        definition_identity_attribute_cause(),
        definition_identity_attribute_chain(),
        definition_identity_attribute_responsibility(),
        definition_identity_consent_chain(),
        definition_identity_consent_validate(),
        definition_identity_consent_gaps(),
        definition_identity_fingerprint_build(),
        definition_identity_fingerprint_match(),
        definition_identity_fingerprint_anomaly(),
        definition_identity_fingerprint_alert(),
    ]
}

pub fn try_execute(server: &McpServer, tool_name: &str, id: Value, args: &Value) -> Option<Value> {
    Some(match tool_name {
        "identity_receipt_search" => execute_identity_receipt_search(server, id, args),
        "identity_receipt_pattern" => execute_identity_receipt_pattern(server, id, args),
        "identity_receipt_timeline" => execute_identity_receipt_timeline(server, id, args),
        "identity_receipt_anomalies" => execute_identity_receipt_anomalies(server, id, args),
        "identity_attribute_cause" => execute_identity_attribute_cause(server, id, args),
        "identity_attribute_chain" => execute_identity_attribute_chain(server, id, args),
        "identity_attribute_responsibility" => {
            execute_identity_attribute_responsibility(server, id, args)
        }
        "identity_consent_chain" => execute_identity_consent_chain(server, id, args),
        "identity_consent_validate" => execute_identity_consent_validate(server, id, args),
        "identity_consent_gaps" => execute_identity_consent_gaps(server, id, args),
        "identity_fingerprint_build" => execute_identity_fingerprint_build(server, id, args),
        "identity_fingerprint_match" => execute_identity_fingerprint_match(server, id, args),
        "identity_fingerprint_anomaly" => execute_identity_fingerprint_anomaly(server, id, args),
        "identity_fingerprint_alert" => execute_identity_fingerprint_alert(server, id, args),
        _ => return None,
    })
}
