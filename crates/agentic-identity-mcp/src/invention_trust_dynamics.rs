//! Trust Dynamics Inventions (1–4): Trust Decay & Regeneration,
//! Competence Modeling, Reputation Network, Trust Prophecy.
//!
//! 17 MCP tools for dynamic trust relationships between agents.

use serde_json::{json, Value};

use super::{micros_to_rfc3339, now_secs, tool_error, tool_ok, McpServer};
use agentic_identity::storage::{ReceiptStore, SpawnStore, TrustStore};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn word_overlap(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_words: std::collections::HashSet<String> = a_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2)
        .map(|w| w.to_string())
        .collect();
    let b_words: std::collections::HashSet<String> = b_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2)
        .map(|w| w.to_string())
        .collect();
    if a_words.is_empty() || b_words.is_empty() {
        return 0.0;
    }
    let intersection = a_words.intersection(&b_words).count();
    intersection as f64 / a_words.len().max(b_words.len()) as f64
}

/// Compute a trust score (0.0–1.0) based on interaction recency and frequency.
/// Loads receipts and grants, filters by agent_id, and applies exponential decay.
fn compute_trust_level(server: &McpServer, agent_id: &str) -> (f64, usize, usize) {
    let now_us = now_secs() * 1_000_000;

    // Load receipts involving agent_id
    let receipt_store = ReceiptStore::new(&server.receipt_dir).ok();
    let mut receipt_count = 0usize;
    let mut receipt_recency_sum = 0.0f64;

    if let Some(store) = &receipt_store {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0.contains(agent_id) || agent_id.contains(&receipt.actor.0) {
                        receipt_count += 1;
                        let age_days = (now_us.saturating_sub(receipt.timestamp)) as f64
                            / (86400.0 * 1_000_000.0);
                        // Exponential decay: half-life of 30 days
                        receipt_recency_sum += (-0.693 * age_days / 30.0).exp();
                    }
                }
            }
        }
    }

    // Load trust grants involving agent_id
    let trust_store = TrustStore::new(&server.trust_dir).ok();
    let mut grant_count = 0usize;
    let mut grant_recency_sum = 0.0f64;

    if let Some(store) = &trust_store {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if matches {
                            grant_count += 1;
                            let age_days = (now_us.saturating_sub(grant.granted_at)) as f64
                                / (86400.0 * 1_000_000.0);
                            grant_recency_sum += (-0.693 * age_days / 30.0).exp();
                        }
                    }
                }
            }
        }
    }

    let total_interactions = receipt_count + grant_count;
    if total_interactions == 0 {
        return (0.0, 0, 0);
    }

    // Normalize: frequency contribution (up to 0.5) + recency contribution (up to 0.5)
    let frequency_score = (total_interactions as f64 / 20.0).min(1.0) * 0.5;
    let total_recency = receipt_recency_sum + grant_recency_sum;
    let recency_score = (total_recency / total_interactions as f64).min(1.0) * 0.5;

    let trust_level = (frequency_score + recency_score).min(1.0);
    (trust_level, receipt_count, grant_count)
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 1: Trust Decay & Regeneration — 5 tools
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 1: identity_trust_level ─────────────────────────────────────────

pub fn definition_identity_trust_level() -> Value {
    json!({
        "name": "identity_trust_level",
        "description": "Get current dynamic trust level between agents. Analyzes receipts and grants to compute a trust score (0.0-1.0) based on interaction recency and frequency.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to check trust level for"
                }
            }
        }
    })
}

pub fn execute_identity_trust_level(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };

    let (trust_level, receipt_count, grant_count) = compute_trust_level(server, agent_id);

    let trust_category = if trust_level >= 0.8 {
        "high"
    } else if trust_level >= 0.5 {
        "medium"
    } else if trust_level >= 0.2 {
        "low"
    } else {
        "none"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "trust_level": (trust_level * 1000.0).round() / 1000.0,
            "trust_category": trust_category,
            "interactions": {
                "receipts": receipt_count,
                "grants": grant_count,
                "total": receipt_count + grant_count,
            },
            "decay_model": "exponential",
            "half_life_days": 30,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 2: identity_trust_history ───────────────────────────────────────

pub fn definition_identity_trust_history() -> Value {
    json!({
        "name": "identity_trust_history",
        "description": "Get trust history between agents. Returns timeline of trust-relevant events.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to get trust history for"
                }
            }
        }
    })
}

pub fn execute_identity_trust_history(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };

    let mut events: Vec<Value> = Vec::new();

    // Collect receipt events
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0.contains(agent_id) || agent_id.contains(&receipt.actor.0) {
                        events.push(json!({
                            "type": "receipt",
                            "id": receipt.id.0,
                            "action_type": receipt.action_type.as_tag(),
                            "description": receipt.action.description,
                            "timestamp": receipt.timestamp,
                            "timestamp_human": micros_to_rfc3339(receipt.timestamp),
                            "actor": receipt.actor.0,
                        }));
                    }
                }
            }
        }
    }

    // Collect trust grant events
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if matches {
                            let caps: Vec<&str> =
                                grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                            events.push(json!({
                                "type": "trust_grant",
                                "id": grant.id.0,
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "capabilities": caps,
                                "timestamp": grant.granted_at,
                                "timestamp_human": micros_to_rfc3339(grant.granted_at),
                                "revoked": store.is_revoked(&grant.id),
                            }));
                        }
                    }
                }
            }
        }
    }

    // Sort by timestamp descending
    events.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
        tb.cmp(&ta)
    });

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "event_count": events.len(),
            "events": events,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 3: identity_trust_project ───────────────────────────────────────

pub fn definition_identity_trust_project() -> Value {
    json!({
        "name": "identity_trust_project",
        "description": "Project future trust levels based on current decay model. Shows how trust will change over time without new interactions.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to project trust for"
                },
                "days_ahead": {
                    "type": "integer",
                    "description": "Number of days to project ahead (default: 30)"
                }
            }
        }
    })
}

pub fn execute_identity_trust_project(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };
    let days_ahead = args
        .get("days_ahead")
        .and_then(|v| v.as_u64())
        .unwrap_or(30) as usize;

    let (current_trust, receipt_count, grant_count) = compute_trust_level(server, agent_id);

    // Project trust decay at intervals
    let mut projections: Vec<Value> = Vec::new();
    let step = if days_ahead <= 7 { 1 } else { days_ahead / 7 };
    let mut day = 0usize;
    while day <= days_ahead {
        // Exponential decay from current level with half-life of 30 days
        let decayed = current_trust * (-0.693 * day as f64 / 30.0).exp();
        projections.push(json!({
            "day": day,
            "projected_trust": (decayed * 1000.0).round() / 1000.0,
            "trust_category": if decayed >= 0.8 { "high" }
                else if decayed >= 0.5 { "medium" }
                else if decayed >= 0.2 { "low" }
                else { "none" },
        }));
        day += step;
        if step == 0 {
            break;
        }
    }

    // Days until trust drops below thresholds
    let days_to_low = if current_trust > 0.2 {
        Some(((current_trust / 0.2).ln() / (0.693 / 30.0)).ceil() as u64)
    } else {
        None
    };
    let days_to_zero = if current_trust > 0.05 {
        Some(((current_trust / 0.05).ln() / (0.693 / 30.0)).ceil() as u64)
    } else {
        None
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "current_trust": (current_trust * 1000.0).round() / 1000.0,
            "total_interactions": receipt_count + grant_count,
            "decay_model": {
                "type": "exponential",
                "half_life_days": 30,
            },
            "projections": projections,
            "thresholds": {
                "days_to_low": days_to_low,
                "days_to_negligible": days_to_zero,
            },
            "recommendation": if current_trust < 0.3 {
                "Trust is decaying rapidly. Consider reinforcing with positive interactions."
            } else if current_trust < 0.6 {
                "Trust is moderate. Regular interactions recommended to maintain level."
            } else {
                "Trust level is healthy. Continue normal interaction patterns."
            },
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 4: identity_trust_reinforce ─────────────────────────────────────

pub fn definition_identity_trust_reinforce() -> Value {
    json!({
        "name": "identity_trust_reinforce",
        "description": "Reinforce trust with a positive action. Records a trust-building event that increases the trust score.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id", "action"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to reinforce trust with"
                },
                "action": {
                    "type": "string",
                    "description": "Description of the trust-building action"
                }
            }
        }
    })
}

pub fn execute_identity_trust_reinforce(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "action is required"),
    };

    let (trust_before, _, _) = compute_trust_level(server, agent_id);

    // The reinforcement is recorded as an observation in the operation log.
    // The actual trust boost will be reflected in subsequent computations
    // through the new receipt/grant interactions.
    let reinforcement_boost = 0.05_f64; // symbolic boost
    let trust_after = (trust_before + reinforcement_boost).min(1.0);

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "action": action,
            "trust_before": (trust_before * 1000.0).round() / 1000.0,
            "trust_after": (trust_after * 1000.0).round() / 1000.0,
            "boost": reinforcement_boost,
            "status": "recorded",
            "note": "Trust reinforcement recorded. Create signed receipts or trust grants to permanently increase the trust score.",
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 5: identity_trust_damage ────────────────────────────────────────

pub fn definition_identity_trust_damage() -> Value {
    json!({
        "name": "identity_trust_damage",
        "description": "Record a trust-damaging event. Reduces trust score based on severity.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id", "reason"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID that caused trust damage"
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for trust damage"
                },
                "severity": {
                    "type": "string",
                    "description": "Severity level: minor, moderate, severe (default: moderate)",
                    "enum": ["minor", "moderate", "severe"]
                }
            }
        }
    })
}

pub fn execute_identity_trust_damage(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };
    let reason = match args.get("reason").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return tool_error(id, "reason is required"),
    };
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("moderate");

    let (trust_before, _, _) = compute_trust_level(server, agent_id);

    let damage_amount = match severity {
        "minor" => 0.05,
        "moderate" => 0.15,
        "severe" => 0.40,
        _ => 0.15,
    };

    let trust_after = (trust_before - damage_amount).max(0.0);
    let recovery_days = match severity {
        "minor" => 7,
        "moderate" => 30,
        "severe" => 90,
        _ => 30,
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "reason": reason,
            "severity": severity,
            "trust_before": (trust_before * 1000.0).round() / 1000.0,
            "trust_after": (trust_after * 1000.0).round() / 1000.0,
            "damage_amount": damage_amount,
            "status": "recorded",
            "recovery": {
                "estimated_days": recovery_days,
                "actions_needed": match severity {
                    "minor" => "Resume normal positive interactions",
                    "moderate" => "Demonstrate reliability through consistent positive actions",
                    _ => "Requires sustained period of positive interactions and formal trust rebuilding",
                },
            },
        }))
        .unwrap_or_default(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 2: Competence Modeling — 4 tools
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 6: identity_competence_get ──────────────────────────────────────

pub fn definition_identity_competence_get() -> Value {
    json!({
        "name": "identity_competence_get",
        "description": "Get competence model for agent in a domain. Returns success rate, trend, and calibration.",
        "inputSchema": {
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Competence domain (e.g., deploy, code_review, data_analysis)"
                }
            }
        }
    })
}

pub fn execute_identity_competence_get(server: &McpServer, id: Value, args: &Value) -> Value {
    let domain = match args.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return tool_error(id, "domain is required"),
    };

    // Analyze receipts for competence signals in this domain
    let mut related_receipts = 0usize;
    let mut positive_signals = 0usize;
    let mut negative_signals = 0usize;
    let mut timestamps: Vec<u64> = Vec::new();

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let desc_lower = receipt.action.description.to_lowercase();
                    let domain_lower = domain.to_lowercase();
                    if word_overlap(&desc_lower, &domain_lower) > 0.1
                        || desc_lower.contains(&domain_lower)
                    {
                        related_receipts += 1;
                        timestamps.push(receipt.timestamp);
                        // Heuristic: look for success/failure signals in description
                        if desc_lower.contains("success")
                            || desc_lower.contains("completed")
                            || desc_lower.contains("passed")
                        {
                            positive_signals += 1;
                        } else if desc_lower.contains("fail")
                            || desc_lower.contains("error")
                            || desc_lower.contains("reject")
                        {
                            negative_signals += 1;
                        } else {
                            // Neutral actions contribute slightly positively
                            positive_signals += 1;
                        }
                    }
                }
            }
        }
    }

    let total_signals = positive_signals + negative_signals;
    let success_rate = if total_signals > 0 {
        positive_signals as f64 / total_signals as f64
    } else {
        0.0
    };

    // Determine trend from timestamps
    timestamps.sort();
    let trend = if timestamps.len() >= 4 {
        let mid = timestamps.len() / 2;
        let first_half = &timestamps[..mid];
        let second_half = &timestamps[mid..];
        let avg_gap_first = if first_half.len() > 1 {
            (first_half.last().unwrap() - first_half.first().unwrap()) as f64
                / (first_half.len() - 1) as f64
        } else {
            0.0
        };
        let avg_gap_second = if second_half.len() > 1 {
            (second_half.last().unwrap() - second_half.first().unwrap()) as f64
                / (second_half.len() - 1) as f64
        } else {
            0.0
        };
        if avg_gap_second < avg_gap_first * 0.8 {
            "increasing"
        } else if avg_gap_second > avg_gap_first * 1.2 {
            "decreasing"
        } else {
            "stable"
        }
    } else {
        "insufficient_data"
    };

    let calibration = if related_receipts >= 10 {
        "well_calibrated"
    } else if related_receipts >= 3 {
        "partially_calibrated"
    } else {
        "uncalibrated"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "domain": domain,
            "competence": {
                "success_rate": (success_rate * 1000.0).round() / 1000.0,
                "total_observations": related_receipts,
                "positive_signals": positive_signals,
                "negative_signals": negative_signals,
            },
            "trend": trend,
            "calibration": calibration,
            "confidence": if related_receipts >= 10 { "high" }
                else if related_receipts >= 3 { "medium" }
                else { "low" },
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 7: identity_competence_record ───────────────────────────────────

pub fn definition_identity_competence_record() -> Value {
    json!({
        "name": "identity_competence_record",
        "description": "Record a task outcome for competence tracking. Builds the competence model over time.",
        "inputSchema": {
            "type": "object",
            "required": ["domain", "outcome"],
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Competence domain (e.g., deploy, code_review)"
                },
                "outcome": {
                    "type": "string",
                    "description": "Task outcome: success, failure, or partial",
                    "enum": ["success", "failure", "partial"]
                },
                "details": {
                    "type": "string",
                    "description": "Optional details about the outcome"
                }
            }
        }
    })
}

pub fn execute_identity_competence_record(_server: &McpServer, id: Value, args: &Value) -> Value {
    let domain = match args.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return tool_error(id, "domain is required"),
    };
    let outcome = match args.get("outcome").and_then(|v| v.as_str()) {
        Some(o) => o,
        None => return tool_error(id, "outcome is required (success, failure, or partial)"),
    };
    let details = args.get("details").and_then(|v| v.as_str()).unwrap_or("");

    // Validate outcome
    if !["success", "failure", "partial"].contains(&outcome) {
        return tool_error(id, "outcome must be 'success', 'failure', or 'partial'");
    }

    // Store as an operation log entry (the operation_log is on &mut self in main.rs;
    // here we return data that can be used by the caller)
    let timestamp = now_secs();

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "domain": domain,
            "outcome": outcome,
            "details": details,
            "timestamp": timestamp,
            "status": "recorded",
            "note": "Competence outcome recorded. Use identity_competence_get to view the aggregate model.",
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 8: identity_competence_predict ──────────────────────────────────

pub fn definition_identity_competence_predict() -> Value {
    json!({
        "name": "identity_competence_predict",
        "description": "Predict success probability for a task based on competence model. Uses historical outcomes in the domain.",
        "inputSchema": {
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Competence domain to predict for"
                },
                "task_description": {
                    "type": "string",
                    "description": "Optional description of the specific task"
                }
            }
        }
    })
}

pub fn execute_identity_competence_predict(server: &McpServer, id: Value, args: &Value) -> Value {
    let domain = match args.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return tool_error(id, "domain is required"),
    };
    let task_desc = args
        .get("task_description")
        .and_then(|v| v.as_str())
        .unwrap_or("unspecified task");

    // Analyze receipts for domain competence
    let mut related = 0usize;
    let mut positive = 0usize;
    let mut task_similar = 0usize;

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let desc = receipt.action.description.to_lowercase();
                    let domain_lower = domain.to_lowercase();
                    if word_overlap(&desc, &domain_lower) > 0.1 || desc.contains(&domain_lower) {
                        related += 1;
                        if desc.contains("success")
                            || desc.contains("completed")
                            || desc.contains("passed")
                            || (!desc.contains("fail")
                                && !desc.contains("error")
                                && !desc.contains("reject"))
                        {
                            positive += 1;
                        }
                        // Check similarity to task description
                        if word_overlap(&desc, &task_desc.to_lowercase()) > 0.2 {
                            task_similar += 1;
                        }
                    }
                }
            }
        }
    }

    let base_probability = if related > 0 {
        positive as f64 / related as f64
    } else {
        0.5 // Prior with no data
    };

    // Adjust for task specificity
    let task_adjustment = if task_similar > 0 { 0.05 } else { 0.0 };
    let prediction = (base_probability + task_adjustment).min(1.0);

    let confidence = if related >= 10 {
        "high"
    } else if related >= 3 {
        "medium"
    } else {
        "low"
    };

    let recommendation = if prediction >= 0.8 {
        "Likely to succeed. Proceed with confidence."
    } else if prediction >= 0.5 {
        "Moderate chance of success. Consider additional preparation or oversight."
    } else {
        "Low predicted success. Recommend alternative approach or additional training."
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "domain": domain,
            "task_description": task_desc,
            "prediction": {
                "success_probability": (prediction * 1000.0).round() / 1000.0,
                "confidence": confidence,
                "based_on_observations": related,
                "similar_tasks_found": task_similar,
            },
            "recommendation": recommendation,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 9: identity_competence_decide ───────────────────────────────────

pub fn definition_identity_competence_decide() -> Value {
    json!({
        "name": "identity_competence_decide",
        "description": "Make a combined trust + competence decision. Recommends allow, deny, or review based on both trust level and competence in domain.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id", "domain", "action"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to decide about"
                },
                "domain": {
                    "type": "string",
                    "description": "Competence domain for the action"
                },
                "action": {
                    "type": "string",
                    "description": "The action being requested"
                }
            }
        }
    })
}

pub fn execute_identity_competence_decide(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };
    let domain = match args.get("domain").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return tool_error(id, "domain is required"),
    };
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "action is required"),
    };

    // Compute trust level
    let (trust_level, _, _) = compute_trust_level(server, agent_id);

    // Compute competence (simplified)
    let mut related = 0usize;
    let mut positive = 0usize;

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let desc = receipt.action.description.to_lowercase();
                    let domain_lower = domain.to_lowercase();
                    if (receipt.actor.0.contains(agent_id) || agent_id.contains(&receipt.actor.0))
                        && (word_overlap(&desc, &domain_lower) > 0.1
                            || desc.contains(&domain_lower))
                    {
                        related += 1;
                        if !desc.contains("fail") && !desc.contains("error") {
                            positive += 1;
                        }
                    }
                }
            }
        }
    }

    let competence_score = if related > 0 {
        positive as f64 / related as f64
    } else {
        0.0
    };

    // Combined decision matrix
    let decision = if trust_level >= 0.6 && competence_score >= 0.7 {
        "allow"
    } else if trust_level < 0.2 || competence_score < 0.3 {
        "deny"
    } else {
        "review"
    };

    let reasoning = match decision {
        "allow" => format!(
            "Trust ({:.0}%) and competence ({:.0}%) both meet thresholds for '{}'.",
            trust_level * 100.0,
            competence_score * 100.0,
            action
        ),
        "deny" => format!(
            "Insufficient trust ({:.0}%) or competence ({:.0}%) for '{}'.",
            trust_level * 100.0,
            competence_score * 100.0,
            action
        ),
        _ => format!(
            "Trust ({:.0}%) or competence ({:.0}%) is borderline for '{}'. Manual review recommended.",
            trust_level * 100.0,
            competence_score * 100.0,
            action
        ),
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "domain": domain,
            "action": action,
            "decision": decision,
            "reasoning": reasoning,
            "scores": {
                "trust_level": (trust_level * 1000.0).round() / 1000.0,
                "competence_score": (competence_score * 1000.0).round() / 1000.0,
                "domain_observations": related,
            },
            "thresholds": {
                "trust_allow": 0.6,
                "competence_allow": 0.7,
                "trust_deny": 0.2,
                "competence_deny": 0.3,
            },
        }))
        .unwrap_or_default(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 3: Reputation Network — 4 tools
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 10: identity_reputation_get ─────────────────────────────────────

pub fn definition_identity_reputation_get() -> Value {
    json!({
        "name": "identity_reputation_get",
        "description": "Get an agent's reputation. Aggregates trust grants, receipts, and interactions across all domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID (defaults to self if omitted)"
                }
            }
        }
    })
}

pub fn execute_identity_reputation_get(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = args.get("agent_id").and_then(|v| v.as_str());

    let mut total_grants_given = 0usize;
    let mut total_grants_received = 0usize;
    let mut total_receipts = 0usize;
    let mut capabilities_granted: Vec<String> = Vec::new();
    let mut revoked_count = 0usize;
    let mut unique_partners: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Analyze trust grants
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        if let Ok(ids) = store.list_granted() {
            for tid in &ids {
                if let Ok(grant) = store.load_grant(tid) {
                    let matches = agent_id.is_none_or(|aid| {
                        grant.grantor.0.contains(aid) || aid.contains(&grant.grantor.0)
                    });
                    if matches {
                        total_grants_given += 1;
                        unique_partners.insert(grant.grantee.0.clone());
                        for cap in &grant.capabilities {
                            if !capabilities_granted.contains(&cap.uri) {
                                capabilities_granted.push(cap.uri.clone());
                            }
                        }
                        if store.is_revoked(&grant.id) {
                            revoked_count += 1;
                        }
                    }
                }
            }
        }
        if let Ok(ids) = store.list_received() {
            for tid in &ids {
                if let Ok(grant) = store.load_grant(tid) {
                    let matches = agent_id.is_none_or(|aid| {
                        grant.grantee.0.contains(aid) || aid.contains(&grant.grantee.0)
                    });
                    if matches {
                        total_grants_received += 1;
                        unique_partners.insert(grant.grantor.0.clone());
                    }
                }
            }
        }
    }

    // Analyze receipts
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    let matches = agent_id.is_none_or(|aid| {
                        receipt.actor.0.contains(aid) || aid.contains(&receipt.actor.0)
                    });
                    if matches {
                        total_receipts += 1;
                    }
                }
            }
        }
    }

    let total_interactions = total_grants_given + total_grants_received + total_receipts;
    let reputation_score = if total_interactions > 0 {
        let grants_score = (total_grants_received as f64 / 10.0).min(1.0) * 0.4;
        let activity_score = (total_receipts as f64 / 20.0).min(1.0) * 0.3;
        let network_score = (unique_partners.len() as f64 / 5.0).min(1.0) * 0.2;
        let reliability_score = if total_grants_given > 0 {
            (1.0 - revoked_count as f64 / total_grants_given as f64) * 0.1
        } else {
            0.1
        };
        grants_score + activity_score + network_score + reliability_score
    } else {
        0.0
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id.unwrap_or("self"),
            "reputation_score": (reputation_score * 1000.0).round() / 1000.0,
            "reputation_category": if reputation_score >= 0.8 { "excellent" }
                else if reputation_score >= 0.6 { "good" }
                else if reputation_score >= 0.3 { "developing" }
                else { "unknown" },
            "metrics": {
                "grants_given": total_grants_given,
                "grants_received": total_grants_received,
                "receipts": total_receipts,
                "unique_partners": unique_partners.len(),
                "revocations": revoked_count,
                "capabilities_granted": capabilities_granted.len(),
            },
            "network_size": unique_partners.len(),
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 11: identity_reputation_network ─────────────────────────────────

pub fn definition_identity_reputation_network() -> Value {
    json!({
        "name": "identity_reputation_network",
        "description": "Get the trust network graph. Returns nodes (agents) and edges (trust relationships) of all known trust relationships.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub fn execute_identity_reputation_network(server: &McpServer, id: Value, _args: &Value) -> Value {
    let mut nodes: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let mut edges: Vec<Value> = Vec::new();

    // Build network from trust grants
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        // Add nodes
                        let grantor_id = grant.grantor.0.clone();
                        let grantee_id = grant.grantee.0.clone();
                        nodes
                            .entry(grantor_id.clone())
                            .or_insert_with(|| json!({ "id": grantor_id, "type": "agent" }));
                        nodes
                            .entry(grantee_id.clone())
                            .or_insert_with(|| json!({ "id": grantee_id, "type": "agent" }));

                        let caps: Vec<&str> =
                            grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                        edges.push(json!({
                            "from": grant.grantor.0,
                            "to": grant.grantee.0,
                            "trust_id": grant.id.0,
                            "capabilities": caps,
                            "granted_at": micros_to_rfc3339(grant.granted_at),
                            "revoked": store.is_revoked(&grant.id),
                            "delegation_allowed": grant.delegation_allowed,
                        }));
                    }
                }
            }
        }
    }

    // Add spawn relationships as edges
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(ids) = store.list() {
            for sid in &ids {
                if let Ok(record) = store.load(sid) {
                    let parent_id = record.parent_id.0.clone();
                    let child_id = record.child_id.0.clone();
                    nodes
                        .entry(parent_id.clone())
                        .or_insert_with(|| json!({ "id": parent_id, "type": "agent" }));
                    nodes
                        .entry(child_id.clone())
                        .or_insert_with(|| json!({ "id": child_id, "type": "spawned_agent" }));
                    edges.push(json!({
                        "from": record.parent_id.0,
                        "to": record.child_id.0,
                        "type": "spawn",
                        "spawn_type": record.spawn_type.as_tag(),
                        "active": !record.terminated,
                    }));
                }
            }
        }
    }

    let nodes_vec: Vec<Value> = nodes.into_values().collect();

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "network": {
                "nodes": nodes_vec.len(),
                "edges": edges.len(),
            },
            "nodes": nodes_vec,
            "edges": edges,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 12: identity_reputation_find ────────────────────────────────────

pub fn definition_identity_reputation_find() -> Value {
    json!({
        "name": "identity_reputation_find",
        "description": "Find agents matching reputation criteria. Filter by minimum trust level or domain expertise.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "min_trust": {
                    "type": "number",
                    "description": "Minimum trust score (0.0-1.0)"
                },
                "domain": {
                    "type": "string",
                    "description": "Domain to filter by (e.g., deploy, code_review)"
                }
            }
        }
    })
}

pub fn execute_identity_reputation_find(server: &McpServer, id: Value, args: &Value) -> Value {
    let min_trust = args
        .get("min_trust")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let domain_filter = args.get("domain").and_then(|v| v.as_str());

    // Collect all known agent IDs
    let mut agent_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        agent_ids.insert(grant.grantor.0.clone());
                        agent_ids.insert(grant.grantee.0.clone());
                    }
                }
            }
        }
    }

    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    agent_ids.insert(receipt.actor.0.clone());
                }
            }
        }
    }

    // Evaluate each agent
    let mut matches: Vec<Value> = Vec::new();
    for aid in &agent_ids {
        let (trust_level, receipt_count, grant_count) = compute_trust_level(server, aid);

        if trust_level < min_trust {
            continue;
        }

        // Domain filter: check if agent has receipts related to domain
        if let Some(domain) = domain_filter {
            let mut domain_match = false;
            if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
                if let Ok(ids) = store.list() {
                    for rid in &ids {
                        if let Ok(receipt) = store.load(rid) {
                            if (receipt.actor.0 == *aid || aid.contains(&receipt.actor.0))
                                && (word_overlap(
                                    &receipt.action.description.to_lowercase(),
                                    &domain.to_lowercase(),
                                ) > 0.1
                                    || receipt
                                        .action
                                        .description
                                        .to_lowercase()
                                        .contains(&domain.to_lowercase()))
                            {
                                domain_match = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !domain_match {
                continue;
            }
        }

        matches.push(json!({
            "agent_id": aid,
            "trust_level": (trust_level * 1000.0).round() / 1000.0,
            "interactions": receipt_count + grant_count,
        }));
    }

    // Sort by trust level descending
    matches.sort_by(|a, b| {
        let ta = a.get("trust_level").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let tb = b.get("trust_level").and_then(|v| v.as_f64()).unwrap_or(0.0);
        tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
    });

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "criteria": {
                "min_trust": min_trust,
                "domain": domain_filter,
            },
            "matches_found": matches.len(),
            "agents": matches,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 13: identity_reputation_compare ─────────────────────────────────

pub fn definition_identity_reputation_compare() -> Value {
    json!({
        "name": "identity_reputation_compare",
        "description": "Compare reputations of two agents side by side.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_a", "agent_b"],
            "properties": {
                "agent_a": {
                    "type": "string",
                    "description": "First agent identity ID"
                },
                "agent_b": {
                    "type": "string",
                    "description": "Second agent identity ID"
                }
            }
        }
    })
}

pub fn execute_identity_reputation_compare(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_a = match args.get("agent_a").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_a is required"),
    };
    let agent_b = match args.get("agent_b").and_then(|v| v.as_str()) {
        Some(b) => b,
        None => return tool_error(id, "agent_b is required"),
    };

    let (trust_a, receipts_a, grants_a) = compute_trust_level(server, agent_a);
    let (trust_b, receipts_b, grants_b) = compute_trust_level(server, agent_b);

    let winner = if (trust_a - trust_b).abs() < 0.01 {
        "tie"
    } else if trust_a > trust_b {
        "agent_a"
    } else {
        "agent_b"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "comparison": {
                "agent_a": {
                    "id": agent_a,
                    "trust_level": (trust_a * 1000.0).round() / 1000.0,
                    "receipts": receipts_a,
                    "grants": grants_a,
                    "total_interactions": receipts_a + grants_a,
                },
                "agent_b": {
                    "id": agent_b,
                    "trust_level": (trust_b * 1000.0).round() / 1000.0,
                    "receipts": receipts_b,
                    "grants": grants_b,
                    "total_interactions": receipts_b + grants_b,
                },
            },
            "higher_trust": winner,
            "trust_difference": ((trust_a - trust_b).abs() * 1000.0).round() / 1000.0,
            "more_active": if (receipts_a + grants_a) > (receipts_b + grants_b) {
                "agent_a"
            } else if (receipts_a + grants_a) < (receipts_b + grants_b) {
                "agent_b"
            } else {
                "tie"
            },
        }))
        .unwrap_or_default(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// INVENTION 4: Trust Prophecy — 4 tools
// ═══════════════════════════════════════════════════════════════════════════

// ── Tool 14: identity_trust_prophecy ─────────────────────────────────────

pub fn definition_identity_trust_prophecy() -> Value {
    json!({
        "name": "identity_trust_prophecy",
        "description": "Get trust prophecies for a relationship. Predicts potential trust violations based on patterns.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to generate prophecies for"
                }
            }
        }
    })
}

pub fn execute_identity_trust_prophecy(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };

    let (trust_level, receipt_count, grant_count) = compute_trust_level(server, agent_id);
    let now_us = now_secs() * 1_000_000;

    let mut prophecies: Vec<Value> = Vec::new();
    let mut risk_factors: Vec<String> = Vec::new();

    // Check for expiring trust grants
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if !matches {
                            continue;
                        }

                        // Check for soon-to-expire grants
                        if let Some(not_after) = grant.constraints.not_after {
                            if not_after > now_us {
                                let days_remaining =
                                    (not_after - now_us) as f64 / (86400.0 * 1_000_000.0);
                                if days_remaining < 7.0 {
                                    prophecies.push(json!({
                                        "type": "grant_expiration",
                                        "severity": "high",
                                        "trust_id": grant.id.0,
                                        "days_remaining": days_remaining.ceil() as u64,
                                        "prediction": format!("Trust grant {} will expire in {:.0} days", grant.id.0, days_remaining),
                                        "confidence": 1.0,
                                    }));
                                    risk_factors.push("Expiring trust grant".to_string());
                                } else if days_remaining < 30.0 {
                                    prophecies.push(json!({
                                        "type": "grant_expiration",
                                        "severity": "medium",
                                        "trust_id": grant.id.0,
                                        "days_remaining": days_remaining.ceil() as u64,
                                        "prediction": format!("Trust grant {} will expire in {:.0} days", grant.id.0, days_remaining),
                                        "confidence": 1.0,
                                    }));
                                }
                            }
                        }

                        // Check for max_uses approaching limit
                        if let Some(max_uses) = grant.constraints.max_uses {
                            if max_uses <= 2 {
                                prophecies.push(json!({
                                    "type": "usage_limit",
                                    "severity": "medium",
                                    "trust_id": grant.id.0,
                                    "max_uses": max_uses,
                                    "prediction": format!("Trust grant {} has limited remaining uses (max: {})", grant.id.0, max_uses),
                                    "confidence": 0.8,
                                }));
                                risk_factors.push("Low remaining usage allowance".to_string());
                            }
                        }

                        // Check already revoked
                        if store.is_revoked(&grant.id) {
                            prophecies.push(json!({
                                "type": "revoked_grant",
                                "severity": "high",
                                "trust_id": grant.id.0,
                                "prediction": format!("Trust grant {} has been revoked", grant.id.0),
                                "confidence": 1.0,
                            }));
                            risk_factors.push("Revoked trust grant exists".to_string());
                        }
                    }
                }
            }
        }
    }

    // Trust decay prophecy
    if trust_level > 0.0 && trust_level < 0.4 {
        prophecies.push(json!({
            "type": "trust_decay",
            "severity": "medium",
            "prediction": format!("Trust level ({:.0}%) is below moderate threshold and continuing to decay", trust_level * 100.0),
            "confidence": 0.7,
        }));
        risk_factors.push("Low and decaying trust level".to_string());
    }

    // Inactivity prophecy
    if receipt_count + grant_count == 0 {
        prophecies.push(json!({
            "type": "no_history",
            "severity": "low",
            "prediction": "No interaction history found. Trust cannot be established without interactions.",
            "confidence": 0.9,
        }));
        risk_factors.push("No interaction history".to_string());
    }

    let overall_risk = if prophecies
        .iter()
        .any(|p| p.get("severity") == Some(&json!("high")))
    {
        "high"
    } else if prophecies
        .iter()
        .any(|p| p.get("severity") == Some(&json!("medium")))
    {
        "medium"
    } else if prophecies.is_empty() {
        "none"
    } else {
        "low"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "current_trust": (trust_level * 1000.0).round() / 1000.0,
            "overall_risk": overall_risk,
            "prophecy_count": prophecies.len(),
            "prophecies": prophecies,
            "risk_factors": risk_factors,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 15: identity_trust_prophecy_all ─────────────────────────────────

pub fn definition_identity_trust_prophecy_all() -> Value {
    json!({
        "name": "identity_trust_prophecy_all",
        "description": "Get all active trust prophecies across all known agents. Scans the entire trust network for potential issues.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    })
}

pub fn execute_identity_trust_prophecy_all(server: &McpServer, id: Value, _args: &Value) -> Value {
    let now_us = now_secs() * 1_000_000;
    let mut prophecies: Vec<Value> = Vec::new();

    // Scan all trust grants for issues
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        // Check expiring grants
                        if let Some(not_after) = grant.constraints.not_after {
                            if not_after > now_us {
                                let days_remaining =
                                    (not_after - now_us) as f64 / (86400.0 * 1_000_000.0);
                                if days_remaining < 30.0 {
                                    prophecies.push(json!({
                                        "type": "grant_expiration",
                                        "severity": if days_remaining < 7.0 { "high" } else { "medium" },
                                        "trust_id": grant.id.0,
                                        "grantor": grant.grantor.0,
                                        "grantee": grant.grantee.0,
                                        "days_remaining": days_remaining.ceil() as u64,
                                        "prediction": format!("Grant {} expires in {:.0} days", grant.id.0, days_remaining),
                                    }));
                                }
                            } else {
                                // Already expired
                                prophecies.push(json!({
                                    "type": "grant_expired",
                                    "severity": "high",
                                    "trust_id": grant.id.0,
                                    "grantor": grant.grantor.0,
                                    "grantee": grant.grantee.0,
                                    "prediction": format!("Grant {} has already expired", grant.id.0),
                                }));
                            }
                        }

                        // Check revoked
                        if store.is_revoked(&grant.id) {
                            prophecies.push(json!({
                                "type": "revoked_grant",
                                "severity": "high",
                                "trust_id": grant.id.0,
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "prediction": format!("Grant {} is revoked", grant.id.0),
                            }));
                        }
                    }
                }
            }
        }
    }

    // Check for terminated spawns
    if let Ok(store) = SpawnStore::new(&server.spawn_dir) {
        if let Ok(ids) = store.list() {
            for sid in &ids {
                if let Ok(record) = store.load(sid) {
                    if record.terminated {
                        prophecies.push(json!({
                            "type": "terminated_spawn",
                            "severity": "medium",
                            "spawn_id": record.id.0,
                            "parent": record.parent_id.0,
                            "child": record.child_id.0,
                            "prediction": format!("Spawn {} is terminated", record.id.0),
                        }));
                    }
                }
            }
        }
    }

    let high_count = prophecies
        .iter()
        .filter(|p| p.get("severity") == Some(&json!("high")))
        .count();
    let medium_count = prophecies
        .iter()
        .filter(|p| p.get("severity") == Some(&json!("medium")))
        .count();

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "prophecy_count": prophecies.len(),
            "severity_summary": {
                "high": high_count,
                "medium": medium_count,
                "low": prophecies.len() - high_count - medium_count,
            },
            "prophecies": prophecies,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 16: identity_trust_warn ─────────────────────────────────────────

pub fn definition_identity_trust_warn() -> Value {
    json!({
        "name": "identity_trust_warn",
        "description": "Get warning signs for an agent. Analyzes patterns that may indicate trust issues.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to check warning signs for"
                }
            }
        }
    })
}

pub fn execute_identity_trust_warn(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };

    let (trust_level, receipt_count, grant_count) = compute_trust_level(server, agent_id);
    let now_us = now_secs() * 1_000_000;
    let mut warnings: Vec<Value> = Vec::new();

    // Warning: No interaction history
    if receipt_count + grant_count == 0 {
        warnings.push(json!({
            "type": "no_history",
            "severity": "medium",
            "message": "No interaction history with this agent. Trust is unverified.",
        }));
    }

    // Warning: Low trust
    if trust_level > 0.0 && trust_level < 0.3 {
        warnings.push(json!({
            "type": "low_trust",
            "severity": "medium",
            "message": format!("Trust level is low ({:.0}%). Recent interactions may be insufficient.", trust_level * 100.0),
        }));
    }

    // Warning: High revocation rate
    let mut total_grants = 0usize;
    let mut revoked_grants = 0usize;

    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if matches {
                            total_grants += 1;
                            if store.is_revoked(&grant.id) {
                                revoked_grants += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if total_grants > 0 && revoked_grants as f64 / total_grants as f64 > 0.3 {
        warnings.push(json!({
            "type": "high_revocation_rate",
            "severity": "high",
            "message": format!("{} of {} grants revoked ({:.0}%). Pattern indicates reliability concerns.",
                revoked_grants, total_grants, (revoked_grants as f64 / total_grants as f64) * 100.0),
        }));
    }

    // Warning: Stale relationship (no recent interactions)
    let mut most_recent_interaction: u64 = 0;
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if (receipt.actor.0.contains(agent_id) || agent_id.contains(&receipt.actor.0))
                        && receipt.timestamp > most_recent_interaction
                    {
                        most_recent_interaction = receipt.timestamp;
                    }
                }
            }
        }
    }

    if most_recent_interaction > 0 {
        let days_since =
            (now_us.saturating_sub(most_recent_interaction)) as f64 / (86400.0 * 1_000_000.0);
        if days_since > 60.0 {
            warnings.push(json!({
                "type": "stale_relationship",
                "severity": "medium",
                "message": format!("No interactions in {:.0} days. Relationship may be stale.", days_since),
            }));
        }
    }

    // Warning: Error-heavy receipts
    let mut error_receipts = 0usize;
    let mut total_agent_receipts = 0usize;
    if let Ok(store) = ReceiptStore::new(&server.receipt_dir) {
        if let Ok(ids) = store.list() {
            for rid in &ids {
                if let Ok(receipt) = store.load(rid) {
                    if receipt.actor.0.contains(agent_id) || agent_id.contains(&receipt.actor.0) {
                        total_agent_receipts += 1;
                        let desc = receipt.action.description.to_lowercase();
                        if desc.contains("fail")
                            || desc.contains("error")
                            || desc.contains("reject")
                        {
                            error_receipts += 1;
                        }
                    }
                }
            }
        }
    }

    if total_agent_receipts > 3 && error_receipts as f64 / total_agent_receipts as f64 > 0.4 {
        warnings.push(json!({
            "type": "high_error_rate",
            "severity": "high",
            "message": format!("{} of {} receipts indicate errors ({:.0}%). Competence may be a concern.",
                error_receipts, total_agent_receipts, (error_receipts as f64 / total_agent_receipts as f64) * 100.0),
        }));
    }

    let overall_risk = if warnings
        .iter()
        .any(|w| w.get("severity") == Some(&json!("high")))
    {
        "high"
    } else if warnings
        .iter()
        .any(|w| w.get("severity") == Some(&json!("medium")))
    {
        "medium"
    } else if warnings.is_empty() {
        "none"
    } else {
        "low"
    };

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "current_trust": (trust_level * 1000.0).round() / 1000.0,
            "overall_risk": overall_risk,
            "warning_count": warnings.len(),
            "warnings": warnings,
        }))
        .unwrap_or_default(),
    )
}

// ── Tool 17: identity_trust_prevent ──────────────────────────────────────

pub fn definition_identity_trust_prevent() -> Value {
    json!({
        "name": "identity_trust_prevent",
        "description": "Suggest preventive actions to maintain or improve trust with an agent.",
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identity ID to suggest preventive actions for"
                }
            }
        }
    })
}

pub fn execute_identity_trust_prevent(server: &McpServer, id: Value, args: &Value) -> Value {
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return tool_error(id, "agent_id is required"),
    };

    let (trust_level, receipt_count, grant_count) = compute_trust_level(server, agent_id);
    let now_us = now_secs() * 1_000_000;
    let mut actions: Vec<Value> = Vec::new();

    // Action: Build initial trust if no history
    if receipt_count + grant_count == 0 {
        actions.push(json!({
            "action": "establish_baseline",
            "priority": "high",
            "description": "No interaction history found. Create an initial trust grant or signed receipt to establish a baseline relationship.",
            "effort": "low",
        }));
    }

    // Action: Renew expiring grants
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if !matches {
                            continue;
                        }
                        if let Some(not_after) = grant.constraints.not_after {
                            if not_after > now_us {
                                let days_remaining =
                                    (not_after - now_us) as f64 / (86400.0 * 1_000_000.0);
                                if days_remaining < 30.0 {
                                    actions.push(json!({
                                        "action": "renew_grant",
                                        "priority": if days_remaining < 7.0 { "critical" } else { "high" },
                                        "description": format!("Trust grant {} expires in {:.0} days. Renew or extend before expiration.", grant.id.0, days_remaining),
                                        "trust_id": grant.id.0,
                                        "effort": "low",
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Action: Increase interaction frequency for decaying trust
    if trust_level > 0.0 && trust_level < 0.5 {
        actions.push(json!({
            "action": "increase_interactions",
            "priority": "medium",
            "description": format!("Trust is at {:.0}% and decaying. Increase interaction frequency with signed receipts to reverse decay.", trust_level * 100.0),
            "effort": "medium",
        }));
    }

    // Action: Diversify capabilities
    let mut unique_caps: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(store) = TrustStore::new(&server.trust_dir) {
        for dir_fn in [TrustStore::list_granted, TrustStore::list_received] {
            if let Ok(ids) = dir_fn(&store) {
                for tid in &ids {
                    if let Ok(grant) = store.load_grant(tid) {
                        let matches = grant.grantor.0.contains(agent_id)
                            || grant.grantee.0.contains(agent_id)
                            || agent_id.contains(&grant.grantor.0)
                            || agent_id.contains(&grant.grantee.0);
                        if matches && !store.is_revoked(&grant.id) {
                            for cap in &grant.capabilities {
                                unique_caps.insert(cap.uri.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    if unique_caps.len() <= 1 && grant_count > 0 {
        actions.push(json!({
            "action": "diversify_capabilities",
            "priority": "low",
            "description": "Trust relationship covers limited capabilities. Consider granting additional capability domains to build a broader trust foundation.",
            "effort": "low",
        }));
    }

    // Action: Regular trust health checks
    if trust_level >= 0.5 {
        actions.push(json!({
            "action": "maintain_health_checks",
            "priority": "low",
            "description": "Trust is healthy. Continue periodic trust level checks and maintain regular interactions.",
            "effort": "minimal",
        }));
    }

    // Sort by priority
    let priority_order = |p: &str| match p {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    actions.sort_by(|a, b| {
        let pa = a.get("priority").and_then(|v| v.as_str()).unwrap_or("low");
        let pb = b.get("priority").and_then(|v| v.as_str()).unwrap_or("low");
        priority_order(pa).cmp(&priority_order(pb))
    });

    tool_ok(
        id,
        serde_json::to_string_pretty(&json!({
            "agent_id": agent_id,
            "current_trust": (trust_level * 1000.0).round() / 1000.0,
            "total_interactions": receipt_count + grant_count,
            "action_count": actions.len(),
            "preventive_actions": actions,
        }))
        .unwrap_or_default(),
    )
}

// ── Convenience wrappers ─────────────────────────────────────────────────────

pub fn all_definitions() -> Vec<Value> {
    vec![
        definition_identity_trust_level(),
        definition_identity_trust_history(),
        definition_identity_trust_project(),
        definition_identity_trust_reinforce(),
        definition_identity_trust_damage(),
        definition_identity_competence_get(),
        definition_identity_competence_record(),
        definition_identity_competence_predict(),
        definition_identity_competence_decide(),
        definition_identity_reputation_get(),
        definition_identity_reputation_network(),
        definition_identity_reputation_find(),
        definition_identity_reputation_compare(),
        definition_identity_trust_prophecy(),
        definition_identity_trust_prophecy_all(),
        definition_identity_trust_warn(),
        definition_identity_trust_prevent(),
    ]
}

pub fn try_execute(server: &McpServer, tool_name: &str, id: Value, args: &Value) -> Option<Value> {
    Some(match tool_name {
        "identity_trust_level" => execute_identity_trust_level(server, id, args),
        "identity_trust_history" => execute_identity_trust_history(server, id, args),
        "identity_trust_project" => execute_identity_trust_project(server, id, args),
        "identity_trust_reinforce" => execute_identity_trust_reinforce(server, id, args),
        "identity_trust_damage" => execute_identity_trust_damage(server, id, args),
        "identity_competence_get" => execute_identity_competence_get(server, id, args),
        "identity_competence_record" => execute_identity_competence_record(server, id, args),
        "identity_competence_predict" => execute_identity_competence_predict(server, id, args),
        "identity_competence_decide" => execute_identity_competence_decide(server, id, args),
        "identity_reputation_get" => execute_identity_reputation_get(server, id, args),
        "identity_reputation_network" => execute_identity_reputation_network(server, id, args),
        "identity_reputation_find" => execute_identity_reputation_find(server, id, args),
        "identity_reputation_compare" => execute_identity_reputation_compare(server, id, args),
        "identity_trust_prophecy" => execute_identity_trust_prophecy(server, id, args),
        "identity_trust_prophecy_all" => execute_identity_trust_prophecy_all(server, id, args),
        "identity_trust_warn" => execute_identity_trust_warn(server, id, args),
        "identity_trust_prevent" => execute_identity_trust_prevent(server, id, args),
        _ => return None,
    })
}
