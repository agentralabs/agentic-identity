#![recursion_limit = "256"]
//! AgenticIdentity MCP Server.
//!
//! Implements a stdio-based Model Context Protocol server that exposes
//! AgenticIdentity operations to AI agents via JSON-RPC 2.0.
//!
//! # Protocol
//!
//! Reads newline-delimited JSON-RPC 2.0 requests from stdin and writes
//! responses to stdout. Each request and response is a single line.
//!
//! # Default passphrase
//!
//! All operations that require a passphrase use the fixed passphrase `"agentic"`.
//! This is intentional: agents cannot interactively enter passphrases, and the
//! MCP server is designed for use in automated contexts where the identity file
//! is already protected by the host environment.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::storage::{
    load_identity, read_public_document, save_identity, ReceiptStore, SpawnStore, TrustStore,
};
use agentic_identity::trust::grant::TrustGrantBuilder;
use agentic_identity::trust::revocation::{Revocation, RevocationReason};
use agentic_identity::trust::verify::verify_trust_grant;
use agentic_identity::{
    ActionContent, ActionType, Capability, IdentityAnchor, IdentityId, ReceiptId, TrustConstraints,
    TrustId,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default passphrase for MCP mode. Agents cannot enter passphrases interactively.
const MCP_PASSPHRASE: &str = "agentic";

/// Default identity name when none is specified.
const DEFAULT_IDENTITY: &str = "default";

/// MCP protocol version supported.
const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Parser, Debug)]
#[command(
    name = "agentic-identity-mcp",
    about = "MCP server for AgenticIdentity — expose identity operations to AI agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run MCP server over stdio (default).
    Serve,
}

// ── Directory helpers ─────────────────────────────────────────────────────────

fn agentic_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".agentic")
}

fn identity_dir() -> PathBuf {
    agentic_dir().join("identity")
}

fn receipt_dir() -> PathBuf {
    agentic_dir().join("receipts")
}

fn trust_dir() -> PathBuf {
    agentic_dir().join("trust")
}

fn spawn_dir() -> PathBuf {
    agentic_dir().join("spawn")
}

// ── Time formatting ───────────────────────────────────────────────────────────

fn micros_to_rfc3339(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    // Format as ISO 8601 without pulling in chrono (it's not in MCP deps).
    // Use a simple manual conversion for a human-readable timestamp.
    // Seconds since epoch → approximate date string.
    // We use the well-known epoch offset arithmetic.

    epoch_to_datetime(secs)
}

/// Minimal epoch→datetime formatter that avoids external date crates.
/// Outputs "YYYY-MM-DD HH:MM:SS UTC".
fn epoch_to_datetime(secs: i64) -> String {
    if secs < 0 {
        return "before-epoch".to_string();
    }
    let s = secs as u64;

    // Days since epoch
    let days = s / 86400;
    let time_of_day = s % 86400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    // Gregorian calendar calculation
    let mut year = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
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
        if remaining_days < dim {
            break;
        }
        remaining_days -= dim;
        month += 1;
    }
    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

// ── Action type parsing ───────────────────────────────────────────────────────

fn parse_action_type(s: &str) -> ActionType {
    match s.to_lowercase().as_str() {
        "decision" => ActionType::Decision,
        "observation" => ActionType::Observation,
        "mutation" => ActionType::Mutation,
        "delegation" => ActionType::Delegation,
        "revocation" => ActionType::Revocation,
        "identity_operation" | "identityoperation" => ActionType::IdentityOperation,
        other => ActionType::Custom(other.to_string()),
    }
}

fn parse_revocation_reason(s: &str) -> RevocationReason {
    match s.to_lowercase().as_str() {
        "expired" => RevocationReason::Expired,
        "compromised" => RevocationReason::Compromised,
        "policy_violation" | "policyviolation" => RevocationReason::PolicyViolation,
        "grantee_request" | "granteerequest" => RevocationReason::GranteeRequest,
        other if other.starts_with("custom:") => RevocationReason::Custom(other[7..].to_string()),
        _ => RevocationReason::ManualRevocation,
    }
}

// ── JSON-RPC helpers ──────────────────────────────────────────────────────────

fn ok_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn tool_ok(id: Value, text: impl Into<String>) -> Value {
    ok_result(
        id,
        json!({
            "content": [{"type": "text", "text": text.into()}]
        }),
    )
}

fn tool_error(id: Value, text: impl Into<String>) -> Value {
    ok_result(
        id,
        json!({
            "content": [{"type": "text", "text": text.into()}],
            "isError": true
        }),
    )
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

// ── MCP Server ────────────────────────────────────────────────────────────────

/// Record of an identity operation with context.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct IdentityOperationRecord {
    tool_name: String,
    intent: Option<String>,
    summary: String,
    timestamp: u64,
}

struct McpServer {
    identity_dir: PathBuf,
    receipt_dir: PathBuf,
    trust_dir: PathBuf,
    spawn_dir: PathBuf,
    /// Log of identity operations with context for this session.
    operation_log: Vec<IdentityOperationRecord>,
    /// Timestamp when this session started.
    session_start_time: Option<u64>,
    /// Multi-context workspace manager for cross-identity queries.
    workspace_manager: IdentityWorkspaceManager,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl McpServer {
    fn new() -> Self {
        Self {
            identity_dir: identity_dir(),
            receipt_dir: receipt_dir(),
            trust_dir: trust_dir(),
            spawn_dir: spawn_dir(),
            operation_log: Vec::new(),
            session_start_time: None,
            workspace_manager: IdentityWorkspaceManager::new(),
        }
    }

    /// Route a JSON-RPC request to the appropriate handler.
    fn handle_request(&mut self, request: Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = match request.get("method").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => return rpc_error(id, -32600, "missing method"),
        };
        let params = request
            .get("params")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));

        match method.as_str() {
            "initialize" => {
                self.session_start_time = Some(now_secs());
                self.operation_log.clear();
                self.handle_initialize(id)
            }
            "initialized" | "notifications/initialized" => {
                // Notification — no response needed, return null sentinel
                Value::Null
            }
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, &params),
            "resources/list" => self.handle_resources_list(id),
            "resources/read" => self.handle_resources_read(id, &params),
            "ping" => ok_result(id, json!({})),
            // All other notifications — silently ignore (no response)
            m if m.starts_with("notifications/") => Value::Null,
            _ => rpc_error(id, -32601, format!("method not found: {method}")),
        }
    }

    // ── initialize ────────────────────────────────────────────────────────────

    fn handle_initialize(&self, id: Value) -> Value {
        ok_result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": "agentic-identity-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    // ── tools/list ────────────────────────────────────────────────────────────

    fn handle_tools_list(&self, id: Value) -> Value {
        ok_result(
            id,
            json!({
                "tools": [
                    {
                        "name": "identity_create",
                        "description": "Create a new AgenticIdentity. Uses the default MCP passphrase.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Human-readable name for the identity (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "identity_show",
                        "description": "Show identity information (public document, no passphrase required).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "action_sign",
                        "description": "Sign an action and create a verifiable receipt.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["action"],
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "Human-readable description of the action"
                                },
                                "action_type": {
                                    "type": "string",
                                    "description": "Action type: decision, observation, mutation, delegation, revocation, identity_operation, or custom string",
                                    "default": "decision"
                                },
                                "data": {
                                    "type": "object",
                                    "description": "Optional structured data payload"
                                },
                                "chain_to": {
                                    "type": "string",
                                    "description": "Previous receipt ID to chain to (arec_...)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name to sign with (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "receipt_verify",
                        "description": "Verify the cryptographic signature on a receipt.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["receipt_id"],
                            "properties": {
                                "receipt_id": {
                                    "type": "string",
                                    "description": "Receipt ID (arec_...)"
                                }
                            }
                        }
                    },
                    {
                        "name": "trust_grant",
                        "description": "Grant trust (capabilities) to another identity.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["grantee", "capabilities"],
                            "properties": {
                                "grantee": {
                                    "type": "string",
                                    "description": "Grantee identity ID (aid_...)"
                                },
                                "capabilities": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Capability URIs to grant (e.g. [\"read:calendar\", \"write:notes\"])"
                                },
                                "expires": {
                                    "type": "string",
                                    "description": "Expiry duration string (e.g. \"24h\", \"7d\", \"30d\")"
                                },
                                "max_uses": {
                                    "type": "integer",
                                    "description": "Maximum number of uses (null = unlimited)"
                                },
                                "allow_delegation": {
                                    "type": "boolean",
                                    "description": "Whether the grantee can delegate trust to others",
                                    "default": false
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Grantor identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "trust_revoke",
                        "description": "Revoke a trust grant.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["trust_id"],
                            "properties": {
                                "trust_id": {
                                    "type": "string",
                                    "description": "Trust grant ID (atrust_...)"
                                },
                                "reason": {
                                    "type": "string",
                                    "description": "Reason for revocation (manual_revocation, expired, compromised, policy_violation, grantee_request, or custom:<text>)",
                                    "default": "manual_revocation"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name performing the revocation (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "trust_verify",
                        "description": "Verify whether a trust grant is currently valid for a capability.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["trust_id"],
                            "properties": {
                                "trust_id": {
                                    "type": "string",
                                    "description": "Trust grant ID (atrust_...)"
                                },
                                "capability": {
                                    "type": "string",
                                    "description": "Capability URI to check (default: \"*\" checks overall validity)"
                                }
                            }
                        }
                    },
                    {
                        "name": "trust_list",
                        "description": "List trust grants (granted by or received by this identity).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "direction": {
                                    "type": "string",
                                    "enum": ["granted", "received", "both"],
                                    "description": "Which grants to list (default: \"both\")"
                                },
                                "valid_only": {
                                    "type": "boolean",
                                    "description": "Only show non-revoked grants (default: false)"
                                }
                            }
                        }
                    },
                    {
                        "name": "receipt_list",
                        "description": "List action receipts with optional filters.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "actor": {
                                    "type": "string",
                                    "description": "Filter by actor identity ID (aid_...)"
                                },
                                "action_type": {
                                    "type": "string",
                                    "description": "Filter by action type"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Maximum number of receipts to return (default: 20)"
                                }
                            }
                        }
                    },
                    {
                        "name": "identity_health",
                        "description": "Check system health: identity files, receipt store, trust store.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "continuity_record",
                        "description": "Record an experience event in the continuity chain.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["content_hash"],
                            "properties": {
                                "experience_type": {
                                    "type": "string",
                                    "description": "Experience type: perception, cognition, action, memory, learning, planning, emotion, idle, system (default: cognition)"
                                },
                                "content_hash": {
                                    "type": "string",
                                    "description": "Hash of the experience content"
                                },
                                "intensity": {
                                    "type": "number",
                                    "description": "Intensity of the experience (0.0 - 1.0, default: 0.5)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "continuity_anchor",
                        "description": "Create a continuity anchor (checkpoint) at the current state.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "anchor_type": {
                                    "type": "string",
                                    "description": "Anchor type: genesis, manual, time_based, experience_count (default: manual)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "continuity_heartbeat",
                        "description": "Create a heartbeat record indicating the agent is alive.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "status": {
                                    "type": "string",
                                    "description": "Heartbeat status: active, idle, suspended, degraded (default: active)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "continuity_status",
                        "description": "Get the continuity status for an identity.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "continuity_gaps",
                        "description": "Detect gaps in the experience chain.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "grace_period_seconds": {
                                    "type": "integer",
                                    "description": "Grace period in seconds (gaps shorter are ignored, default: 300)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "spawn_create",
                        "description": "Spawn a child identity with bounded authority.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["purpose", "authority"],
                            "properties": {
                                "spawn_type": {
                                    "type": "string",
                                    "description": "Spawn type: worker, delegate, clone, specialist (default: worker)"
                                },
                                "purpose": {
                                    "type": "string",
                                    "description": "Purpose of the spawned identity"
                                },
                                "authority": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Capability URIs to grant to the child"
                                },
                                "lifetime": {
                                    "type": "string",
                                    "description": "Lifetime: indefinite, parent_termination, or duration in seconds (default: indefinite)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Parent identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "spawn_terminate",
                        "description": "Terminate a spawned child identity.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["spawn_id"],
                            "properties": {
                                "spawn_id": {
                                    "type": "string",
                                    "description": "Spawn record ID (aspawn_...)"
                                },
                                "reason": {
                                    "type": "string",
                                    "description": "Reason for termination"
                                },
                                "cascade": {
                                    "type": "boolean",
                                    "description": "Whether to cascade termination to descendants (default: false)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Parent identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "spawn_list",
                        "description": "List spawned child identities.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "active_only": {
                                    "type": "boolean",
                                    "description": "Only show active (non-terminated) spawns (default: false)"
                                },
                                "identity": {
                                    "type": "string",
                                    "description": "Parent identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "spawn_lineage",
                        "description": "Get lineage information for an identity.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "spawn_authority",
                        "description": "Get effective authority for an identity (bounded by lineage).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "identity": {
                                    "type": "string",
                                    "description": "Identity name (default: \"default\")"
                                }
                            }
                        }
                    },
                    {
                        "name": "competence_record",
                        "description": "Record a competence attempt outcome (success, failure, partial).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "domain": { "type": "string", "description": "Competence domain (e.g., deploy, code_review)" },
                                "outcome": { "type": "string", "description": "Outcome: success, failure, or partial" },
                                "receipt_id": { "type": "string", "description": "Receipt ID linking to the action" },
                                "reason": { "type": "string", "description": "Failure reason (for outcome=failure)" },
                                "score": { "type": "number", "description": "Partial score 0.0-1.0 (for outcome=partial)" }
                            },
                            "required": ["domain", "outcome", "receipt_id"]
                        }
                    },
                    {
                        "name": "competence_show",
                        "description": "Get competence record for a domain.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "domain": { "type": "string", "description": "Competence domain" }
                            }
                        }
                    },
                    {
                        "name": "competence_prove",
                        "description": "Generate a competence proof for a domain.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "domain": { "type": "string", "description": "Competence domain" },
                                "min_rate": { "type": "number", "description": "Minimum success rate (0.0-1.0)" },
                                "min_attempts": { "type": "integer", "description": "Minimum number of attempts" }
                            },
                            "required": ["domain"]
                        }
                    },
                    {
                        "name": "competence_verify",
                        "description": "Verify a competence proof.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "proof_id": { "type": "string", "description": "Proof ID to verify" }
                            },
                            "required": ["proof_id"]
                        }
                    },
                    {
                        "name": "competence_list",
                        "description": "List all competence domains for the identity.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "negative_prove",
                        "description": "Generate a negative capability proof (prove agent cannot do something).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "capability": { "type": "string", "description": "Capability URI to prove impossible" }
                            },
                            "required": ["capability"]
                        }
                    },
                    {
                        "name": "negative_verify",
                        "description": "Verify a negative capability proof.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "proof_id": { "type": "string", "description": "Negative proof ID to verify" }
                            },
                            "required": ["proof_id"]
                        }
                    },
                    {
                        "name": "negative_declare",
                        "description": "Create a voluntary negative declaration (self-imposed restriction).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "capabilities": { "type": "string", "description": "Comma-separated capability URIs to declare impossible" },
                                "reason": { "type": "string", "description": "Reason for the declaration" },
                                "permanent": { "type": "boolean", "description": "If true, cannot be undone" }
                            },
                            "required": ["capabilities", "reason"]
                        }
                    },
                    {
                        "name": "negative_list",
                        "description": "List all negative declarations for the identity.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    },
                    {
                        "name": "negative_check",
                        "description": "Quick check if a capability is structurally impossible.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "capability": { "type": "string", "description": "Capability URI to check" }
                            },
                            "required": ["capability"]
                        }
                    },
                    {
                        "name": "action_context",
                        "description": "Log the intent and context behind identity actions. Call this to record WHY you are performing identity operations.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "intent": {
                                    "type": "string",
                                    "description": "Why you are performing identity actions (e.g., 'establishing trust with new collaborator')"
                                },
                                "decision": {
                                    "type": "string",
                                    "description": "What was decided or concluded"
                                },
                                "significance": {
                                    "type": "string",
                                    "enum": ["routine", "important", "critical"],
                                    "description": "How significant this action is"
                                },
                                "topic": {
                                    "type": "string",
                                    "description": "Optional topic or category (e.g., 'trust-management', 'spawn-setup')"
                                }
                            },
                            "required": ["intent"]
                        }
                    },
                    // ── V2: Grounding (anti-hallucination) ─────────────────────────
                    {
                        "name": "identity_ground",
                        "description": "Verify an authority/action claim has backing in trust grants, receipts, or competence records. Prevents hallucination about permissions.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["claim"],
                            "properties": {
                                "claim": { "type": "string", "description": "The claim to verify (e.g., 'agent has deploy permission')" },
                                "identity": { "type": "string", "description": "Identity name (default: \"default\")" }
                            }
                        }
                    },
                    {
                        "name": "identity_evidence",
                        "description": "Get detailed evidence for an identity claim from trust grants, receipts, and competence records.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["query"],
                            "properties": {
                                "query": { "type": "string", "description": "The query to search evidence for" },
                                "identity": { "type": "string", "description": "Identity name (default: \"default\")" },
                                "max_results": { "type": "integer", "default": 10 }
                            }
                        }
                    },
                    {
                        "name": "identity_suggest",
                        "description": "Find similar grants, receipts, or competence records when a claim doesn't match exactly.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["query"],
                            "properties": {
                                "query": { "type": "string", "description": "The query to find suggestions for" },
                                "identity": { "type": "string", "description": "Identity name (default: \"default\")" },
                                "limit": { "type": "integer", "default": 5 }
                            }
                        }
                    },
                    // ── V2: Multi-context workspaces ──────────────────────────────
                    {
                        "name": "identity_workspace_create",
                        "description": "Create a multi-identity workspace for comparing permissions across agents.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string", "description": "Workspace name" }
                            }
                        }
                    },
                    {
                        "name": "identity_workspace_add",
                        "description": "Add an identity directory to a workspace for cross-identity comparison.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["workspace_id", "path"],
                            "properties": {
                                "workspace_id": { "type": "string" },
                                "path": { "type": "string", "description": "Path to identity directory" },
                                "role": { "type": "string", "enum": ["primary", "secondary", "reference", "archive"], "default": "primary" },
                                "label": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "identity_workspace_list",
                        "description": "List loaded identity contexts in a workspace.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["workspace_id"],
                            "properties": {
                                "workspace_id": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "identity_workspace_query",
                        "description": "Query across all identity contexts in a workspace.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["workspace_id", "query"],
                            "properties": {
                                "workspace_id": { "type": "string" },
                                "query": { "type": "string" },
                                "max_per_context": { "type": "integer", "default": 10 }
                            }
                        }
                    },
                    {
                        "name": "identity_workspace_compare",
                        "description": "Compare permissions or capabilities across identity contexts.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["workspace_id", "item"],
                            "properties": {
                                "workspace_id": { "type": "string" },
                                "item": { "type": "string" },
                                "max_per_context": { "type": "integer", "default": 5 }
                            }
                        }
                    },
                    {
                        "name": "identity_workspace_xref",
                        "description": "Cross-reference a permission across identity contexts.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["workspace_id", "item"],
                            "properties": {
                                "workspace_id": { "type": "string" },
                                "item": { "type": "string" }
                            }
                        }
                    }
                ]
            }),
        )
    }

    // ── tools/call ────────────────────────────────────────────────────────────

    fn handle_tools_call(&mut self, id: Value, params: &Value) -> Value {
        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => return rpc_error(id, -32602, "missing tool name"),
        };
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        // Handle action_context separately (it mutates operation_log directly).
        if tool_name == "action_context" {
            return self.tool_action_context(id, &args);
        }

        let result = match tool_name.as_str() {
            "identity_create" => self.tool_identity_create(id.clone(), &args),
            "identity_show" => self.tool_identity_show(id.clone(), &args),
            "action_sign" => self.tool_action_sign(id.clone(), &args),
            "receipt_verify" => self.tool_receipt_verify(id.clone(), &args),
            "trust_grant" => self.tool_trust_grant(id.clone(), &args),
            "trust_revoke" => self.tool_trust_revoke(id.clone(), &args),
            "trust_verify" => self.tool_trust_verify(id.clone(), &args),
            "trust_list" => self.tool_trust_list(id.clone(), &args),
            "receipt_list" => self.tool_receipt_list(id.clone(), &args),
            "identity_health" => self.tool_identity_health(id.clone(), &args),
            "continuity_record" => self.tool_continuity_record(id.clone(), &args),
            "continuity_anchor" => self.tool_continuity_anchor(id.clone(), &args),
            "continuity_heartbeat" => self.tool_continuity_heartbeat(id.clone(), &args),
            "continuity_status" => self.tool_continuity_status(id.clone(), &args),
            "continuity_gaps" => self.tool_continuity_gaps(id.clone(), &args),
            "spawn_create" => self.tool_spawn_create(id.clone(), &args),
            "spawn_terminate" => self.tool_spawn_terminate(id.clone(), &args),
            "spawn_list" => self.tool_spawn_list(id.clone(), &args),
            "spawn_lineage" => self.tool_spawn_lineage(id.clone(), &args),
            "spawn_authority" => self.tool_spawn_authority(id.clone(), &args),
            "competence_record" => self.tool_competence_record(id.clone(), &args),
            "competence_show" => self.tool_competence_show(id.clone(), &args),
            "competence_prove" => self.tool_competence_prove(id.clone(), &args),
            "competence_verify" => self.tool_competence_verify(id.clone(), &args),
            "competence_list" => self.tool_competence_list(id.clone(), &args),
            "negative_prove" => self.tool_negative_prove(id.clone(), &args),
            "negative_verify" => self.tool_negative_verify(id.clone(), &args),
            "negative_declare" => self.tool_negative_declare(id.clone(), &args),
            "negative_list" => self.tool_negative_list(id.clone(), &args),
            "negative_check" => self.tool_negative_check(id.clone(), &args),
            // V2: Grounding
            "identity_ground" => self.tool_identity_ground(id.clone(), &args),
            "identity_evidence" => self.tool_identity_evidence(id.clone(), &args),
            "identity_suggest" => self.tool_identity_suggest(id.clone(), &args),
            // V2: Workspaces
            "identity_workspace_create" => self.tool_identity_workspace_create(id.clone(), &args),
            "identity_workspace_add" => self.tool_identity_workspace_add(id.clone(), &args),
            "identity_workspace_list" => self.tool_identity_workspace_list(id.clone(), &args),
            "identity_workspace_query" => self.tool_identity_workspace_query(id.clone(), &args),
            "identity_workspace_compare" => self.tool_identity_workspace_compare(id.clone(), &args),
            "identity_workspace_xref" => self.tool_identity_workspace_xref(id.clone(), &args),
            _ => return rpc_error(id, -32602, format!("unknown tool: {tool_name}")),
        };

        // Auto-log the tool call.
        let summary = {
            let s = args.to_string();
            if s.len() <= 200 {
                s
            } else {
                format!("{}...", &s[..200])
            }
        };
        self.operation_log.push(IdentityOperationRecord {
            tool_name,
            intent: None,
            summary,
            timestamp: now_secs(),
        });

        result
    }

    // ── Tool: action_context ───────────────────────────────────────────────────

    fn tool_action_context(&mut self, id: Value, args: &Value) -> Value {
        let intent = match args.get("intent").and_then(|v| v.as_str()) {
            Some(i) if !i.trim().is_empty() => i.to_string(),
            _ => return tool_error(id, "'intent' is required and must not be empty"),
        };

        let decision = args.get("decision").and_then(|v| v.as_str());
        let significance = args.get("significance").and_then(|v| v.as_str());
        let topic = args.get("topic").and_then(|v| v.as_str());

        let mut summary_parts = vec![format!("intent: {intent}")];
        if let Some(d) = decision {
            summary_parts.push(format!("decision: {d}"));
        }
        if let Some(s) = significance {
            summary_parts.push(format!("significance: {s}"));
        }
        if let Some(t) = topic {
            summary_parts.push(format!("topic: {t}"));
        }

        let record = IdentityOperationRecord {
            tool_name: "action_context".to_string(),
            intent: Some(intent),
            summary: summary_parts.join(" | "),
            timestamp: now_secs(),
        };

        let index = self.operation_log.len();
        self.operation_log.push(record);

        tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "log_index": index,
                "message": "Action context logged"
            }))
            .unwrap_or_default(),
        )
    }

    // ── Tool: identity_create ─────────────────────────────────────────────────

    fn tool_identity_create(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY)
            .to_string();

        let path = self.identity_dir.join(format!("{name}.aid"));

        if path.exists() {
            return tool_error(
                id,
                format!("identity '{name}' already exists — use identity_show to inspect it"),
            );
        }

        if let Err(e) = std::fs::create_dir_all(&self.identity_dir) {
            return tool_error(id, format!("failed to create identity directory: {e}"));
        }

        let anchor = IdentityAnchor::new(Some(name.clone()));
        let identity_id = anchor.id();
        let pub_key = anchor.public_key_base64();
        let created_at = anchor.created_at;

        if let Err(e) = save_identity(&anchor, &path, MCP_PASSPHRASE) {
            return tool_error(id, format!("failed to save identity: {e}"));
        }

        tool_ok(
            id,
            format!(
                "Created identity '{name}'\n\
                 ID:         {identity_id}\n\
                 Public Key: {pub_key}\n\
                 Created:    {}\n\
                 File:       {}",
                micros_to_rfc3339(created_at),
                path.display()
            ),
        )
    }

    // ── Tool: identity_show ───────────────────────────────────────────────────

    fn tool_identity_show(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        let path = self.identity_dir.join(format!("{name}.aid"));

        if !path.exists() {
            return tool_error(
                id,
                format!("identity '{name}' not found — use identity_create to create it"),
            );
        }

        let doc = match read_public_document(&path) {
            Ok(d) => d,
            Err(e) => return tool_error(id, format!("failed to read identity file: {e}")),
        };

        let sig_status = if doc.verify_signature().is_ok() {
            "valid"
        } else {
            "INVALID"
        };

        let mut out = format!(
            "Identity: {name}\n\
             ID:         {}\n\
             Algorithm:  {}\n\
             Public Key: {}\n\
             Created:    {}\n\
             Signature:  {}",
            doc.id,
            doc.algorithm,
            doc.public_key,
            micros_to_rfc3339(doc.created_at),
            sig_status,
        );

        if let Some(ref n) = doc.name {
            out.push_str(&format!("\nName:       {n}"));
        }

        if !doc.rotation_history.is_empty() {
            out.push_str(&format!("\nKey Rotations: {}", doc.rotation_history.len()));
            for (i, rot) in doc.rotation_history.iter().enumerate() {
                out.push_str(&format!(
                    "\n  [{}] {} — {:?}",
                    i + 1,
                    micros_to_rfc3339(rot.rotated_at),
                    rot.reason
                ));
            }
        } else {
            out.push_str("\nKey Rotations: none");
        }

        if !doc.attestations.is_empty() {
            out.push_str(&format!("\nAttestations: {}", doc.attestations.len()));
        }

        tool_ok(id, out)
    }

    // ── Tool: action_sign ─────────────────────────────────────────────────────

    fn tool_action_sign(&self, id: Value, args: &Value) -> Value {
        let action_desc = match args.get("action").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return tool_error(id, "required parameter 'action' is missing"),
        };

        let identity_name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        let path = self.identity_dir.join(format!("{identity_name}.aid"));

        if !path.exists() {
            return tool_error(
                id,
                format!("identity '{identity_name}' not found — use identity_create first"),
            );
        }

        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => {
                return tool_error(
                    id,
                    format!(
                        "failed to load identity '{identity_name}': {e}. \
                         Note: MCP server uses passphrase 'agentic'. \
                         If this identity was created with a different passphrase, \
                         use 'identity_create' to create a new MCP-compatible identity."
                    ),
                )
            }
        };

        let action_type_str = args
            .get("action_type")
            .and_then(|v| v.as_str())
            .unwrap_or("decision");
        let action_type = parse_action_type(action_type_str);

        let action_content = if let Some(data_val) = args.get("data") {
            ActionContent::with_data(action_desc.clone(), data_val.clone())
        } else {
            ActionContent::new(action_desc.clone())
        };

        let mut builder = ReceiptBuilder::new(anchor.id(), action_type.clone(), action_content);

        if let Some(prev_id_str) = args.get("chain_to").and_then(|v| v.as_str()) {
            builder = builder.chain_to(ReceiptId(prev_id_str.to_string()));
        }

        let receipt = match builder.sign(anchor.signing_key()) {
            Ok(r) => r,
            Err(e) => return tool_error(id, format!("failed to sign receipt: {e}")),
        };

        let receipt_store = match ReceiptStore::new(&self.receipt_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open receipt store: {e}")),
        };

        if let Err(e) = receipt_store.save(&receipt) {
            return tool_error(id, format!("failed to save receipt: {e}"));
        }

        let mut out = format!(
            "Receipt created\n\
             ID:        {}\n\
             Type:      {}\n\
             Actor:     {}\n\
             Timestamp: {}\n\
             Action:    {}",
            receipt.id,
            receipt.action_type.as_tag(),
            receipt.actor,
            micros_to_rfc3339(receipt.timestamp),
            action_desc,
        );

        if let Some(ref prev) = receipt.previous_receipt {
            out.push_str(&format!("\nChained to: {prev}"));
        }

        tool_ok(id, out)
    }

    // ── Tool: receipt_verify ──────────────────────────────────────────────────

    fn tool_receipt_verify(&self, id: Value, args: &Value) -> Value {
        let receipt_id_str = match args.get("receipt_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return tool_error(id, "required parameter 'receipt_id' is missing"),
        };

        let store = match ReceiptStore::new(&self.receipt_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open receipt store: {e}")),
        };

        let receipt_id = ReceiptId(receipt_id_str.clone());
        let receipt = match store.load(&receipt_id) {
            Ok(r) => r,
            Err(e) => return tool_error(id, format!("receipt '{receipt_id_str}' not found: {e}")),
        };

        let verification = match verify_receipt(&receipt) {
            Ok(v) => v,
            Err(e) => return tool_error(id, format!("verification error: {e}")),
        };

        let result_str = if verification.is_valid {
            "VALID"
        } else {
            "INVALID"
        };
        let sig_str = if verification.signature_valid {
            "valid"
        } else {
            "INVALID"
        };

        let mut out = format!(
            "Receipt: {}\n\
             Actor:     {}\n\
             Type:      {}\n\
             Timestamp: {}\n\
             Action:    {}\n\n\
             Verification:\n\
             Signature: {}\n\
             Result:    {}",
            receipt.id,
            receipt.actor,
            receipt.action_type.as_tag(),
            micros_to_rfc3339(receipt.timestamp),
            receipt.action.description,
            sig_str,
            result_str,
        );

        if !receipt.witnesses.is_empty() {
            out.push_str(&format!("\nWitnesses ({}):", receipt.witnesses.len()));
            for (i, valid) in verification.witnesses_valid.iter().enumerate() {
                out.push_str(&format!(
                    "\n  [{}] {}",
                    i + 1,
                    if *valid { "valid" } else { "INVALID" }
                ));
            }
        }

        if let Some(ref prev) = receipt.previous_receipt {
            out.push_str(&format!("\nChained to: {prev}"));
        }

        tool_ok(id, out)
    }

    // ── Tool: trust_grant ─────────────────────────────────────────────────────

    fn tool_trust_grant(&self, id: Value, args: &Value) -> Value {
        let grantee_str = match args.get("grantee").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return tool_error(id, "required parameter 'grantee' is missing"),
        };

        let caps_arr = match args.get("capabilities").and_then(|v| v.as_array()) {
            Some(a) => a.clone(),
            None => {
                return tool_error(
                    id,
                    "required parameter 'capabilities' is missing or not an array",
                )
            }
        };

        if caps_arr.is_empty() {
            return tool_error(id, "capabilities array must not be empty");
        }

        let identity_name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        let path = self.identity_dir.join(format!("{identity_name}.aid"));

        if !path.exists() {
            return tool_error(
                id,
                format!("identity '{identity_name}' not found — use identity_create first"),
            );
        }

        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => {
                return tool_error(
                    id,
                    format!("failed to load identity '{identity_name}': {e}"),
                )
            }
        };

        let grantee_id = IdentityId(grantee_str.clone());
        // Use grantor's own key as grantee key placeholder (no key registry).
        let grantee_key = anchor.public_key_base64();

        let capabilities: Vec<Capability> = caps_arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(Capability::new)
            .collect();

        let now_micros = agentic_identity::time::now_micros();
        let mut constraints = TrustConstraints::open();

        if let Some(expires_str) = args.get("expires").and_then(|v| v.as_str()) {
            match parse_duration_to_micros(expires_str) {
                Ok(dur) => constraints.not_after = Some(now_micros + dur),
                Err(e) => return tool_error(id, format!("invalid 'expires' value: {e}")),
            }
        }

        if let Some(max_uses_val) = args.get("max_uses").and_then(|v| v.as_u64()) {
            constraints = constraints.with_max_uses(max_uses_val);
        }

        let allow_delegation = args
            .get("allow_delegation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut builder = TrustGrantBuilder::new(anchor.id(), grantee_id.clone(), grantee_key)
            .capabilities(capabilities.clone())
            .constraints(constraints);

        if allow_delegation {
            builder = builder.allow_delegation(1);
        }

        let grant = match builder.sign(anchor.signing_key()) {
            Ok(g) => g,
            Err(e) => return tool_error(id, format!("failed to sign trust grant: {e}")),
        };

        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open trust store: {e}")),
        };

        if let Err(e) = store.save_granted(&grant) {
            return tool_error(id, format!("failed to save trust grant: {e}"));
        }

        let cap_uris: Vec<&str> = capabilities.iter().map(|c| c.uri.as_str()).collect();
        let expiry_str = grant
            .constraints
            .not_after
            .map(micros_to_rfc3339)
            .unwrap_or_else(|| "never".to_string());

        let delegation_str = if grant.delegation_allowed {
            "allowed"
        } else {
            "not allowed"
        };

        let max_uses_str = grant
            .constraints
            .max_uses
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unlimited".to_string());

        tool_ok(
            id,
            format!(
                "Trust grant created\n\
                 Trust ID:    {}\n\
                 Grantor:     {}\n\
                 Grantee:     {}\n\
                 Capabilities: {}\n\
                 Expires:     {}\n\
                 Max Uses:    {}\n\
                 Delegation:  {}",
                grant.id,
                grant.grantor,
                grant.grantee,
                cap_uris.join(", "),
                expiry_str,
                max_uses_str,
                delegation_str,
            ),
        )
    }

    // ── Tool: trust_revoke ────────────────────────────────────────────────────

    fn tool_trust_revoke(&self, id: Value, args: &Value) -> Value {
        let trust_id_str = match args.get("trust_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return tool_error(id, "required parameter 'trust_id' is missing"),
        };

        let identity_name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        let path = self.identity_dir.join(format!("{identity_name}.aid"));

        if !path.exists() {
            return tool_error(
                id,
                format!("identity '{identity_name}' not found — use identity_create first"),
            );
        }

        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => {
                return tool_error(
                    id,
                    format!("failed to load identity '{identity_name}': {e}"),
                )
            }
        };

        let trust_id = TrustId(trust_id_str.clone());

        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open trust store: {e}")),
        };

        // Verify the grant exists before revoking.
        if let Err(e) = store.load_grant(&trust_id) {
            return tool_error(id, format!("trust grant '{trust_id_str}' not found: {e}"));
        }

        let reason_str = args
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("manual_revocation");
        let reason = parse_revocation_reason(reason_str);

        let revocation = Revocation::create(
            trust_id.clone(),
            anchor.id(),
            reason.clone(),
            anchor.signing_key(),
        );

        if let Err(e) = store.save_revocation(&revocation) {
            return tool_error(id, format!("failed to save revocation: {e}"));
        }

        tool_ok(
            id,
            format!(
                "Trust grant revoked\n\
                 Trust ID:   {trust_id}\n\
                 Revoker:    {}\n\
                 Revoked At: {}\n\
                 Reason:     {}",
                revocation.revoker,
                micros_to_rfc3339(revocation.revoked_at),
                reason.as_str(),
            ),
        )
    }

    // ── Tool: trust_verify ────────────────────────────────────────────────────

    fn tool_trust_verify(&self, id: Value, args: &Value) -> Value {
        let trust_id_str = match args.get("trust_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return tool_error(id, "required parameter 'trust_id' is missing"),
        };

        let capability = args
            .get("capability")
            .and_then(|v| v.as_str())
            .unwrap_or("*");

        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open trust store: {e}")),
        };

        let trust_id = TrustId(trust_id_str.clone());
        let grant = match store.load_grant(&trust_id) {
            Ok(g) => g,
            Err(e) => {
                return tool_error(id, format!("trust grant '{trust_id_str}' not found: {e}"))
            }
        };

        let revocations = if store.is_revoked(&trust_id) {
            match store.load_revocation(&trust_id) {
                Ok(rev) => vec![rev],
                Err(_) => vec![],
            }
        } else {
            vec![]
        };

        let verification = match verify_trust_grant(&grant, capability, 0, &revocations) {
            Ok(v) => v,
            Err(e) => return tool_error(id, format!("verification error: {e}")),
        };

        let result_str = if verification.is_valid {
            "VALID"
        } else {
            "INVALID"
        };
        let cap_uris: Vec<&str> = grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
        let expiry_str = grant
            .constraints
            .not_after
            .map(micros_to_rfc3339)
            .unwrap_or_else(|| "never".to_string());

        tool_ok(
            id,
            format!(
                "Trust Grant: {}\n\
                 Grantor:      {}\n\
                 Grantee:      {}\n\
                 Granted At:   {}\n\
                 Capabilities: {}\n\
                 Expires:      {}\n\n\
                 Verification (capability: {capability}):\n\
                 Signature:    {}\n\
                 Time:         {}\n\
                 Not Revoked:  {}\n\
                 Uses:         {}\n\
                 Capability:   {}\n\
                 Result:       {}",
                grant.id,
                grant.grantor,
                grant.grantee,
                micros_to_rfc3339(grant.granted_at),
                cap_uris.join(", "),
                expiry_str,
                if verification.signature_valid {
                    "valid"
                } else {
                    "INVALID"
                },
                if verification.time_valid {
                    "valid"
                } else {
                    "expired/not-yet-valid"
                },
                if verification.not_revoked {
                    "yes"
                } else {
                    "REVOKED"
                },
                if verification.uses_valid {
                    "within limit"
                } else {
                    "exceeded"
                },
                if verification.capability_granted {
                    "granted"
                } else {
                    "not granted"
                },
                result_str,
            ),
        )
    }

    // ── Tool: trust_list ──────────────────────────────────────────────────────

    fn tool_trust_list(&self, id: Value, args: &Value) -> Value {
        let direction = args
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("both");
        let valid_only = args
            .get("valid_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open trust store: {e}")),
        };

        let show_granted = matches!(direction, "granted" | "both");
        let show_received = matches!(direction, "received" | "both");

        let mut out = String::new();

        if show_granted {
            let ids = match store.list_granted() {
                Ok(i) => i,
                Err(e) => return tool_error(id, format!("failed to list granted grants: {e}")),
            };

            let mut count = 0;
            let mut entries = Vec::new();

            for gid in &ids {
                let revoked = store.is_revoked(gid);
                if valid_only && revoked {
                    continue;
                }
                if let Ok(grant) = store.load_grant(gid) {
                    let caps: Vec<&str> =
                        grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                    let status = if revoked { " [REVOKED]" } else { "" };
                    entries.push(format!(
                        "  {} → {}: {}{}",
                        grant.grantor,
                        grant.grantee,
                        caps.join(", "),
                        status,
                    ));
                    count += 1;
                }
            }

            out.push_str(&format!("Granted ({count}):\n"));
            if entries.is_empty() {
                out.push_str("  (none)\n");
            } else {
                for e in &entries {
                    out.push_str(e);
                    out.push('\n');
                }
            }
        }

        if show_received {
            let ids = match store.list_received() {
                Ok(i) => i,
                Err(e) => return tool_error(id, format!("failed to list received grants: {e}")),
            };

            let mut count = 0;
            let mut entries = Vec::new();

            for gid in &ids {
                let revoked = store.is_revoked(gid);
                if valid_only && revoked {
                    continue;
                }
                if let Ok(grant) = store.load_grant(gid) {
                    let caps: Vec<&str> =
                        grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                    let status = if revoked { " [REVOKED]" } else { "" };
                    entries.push(format!(
                        "  {} → {}: {}{}",
                        grant.grantor,
                        grant.grantee,
                        caps.join(", "),
                        status,
                    ));
                    count += 1;
                }
            }

            if show_granted {
                out.push('\n');
            }
            out.push_str(&format!("Received ({count}):\n"));
            if entries.is_empty() {
                out.push_str("  (none)\n");
            } else {
                for e in &entries {
                    out.push_str(e);
                    out.push('\n');
                }
            }
        }

        tool_ok(id, out.trim_end().to_string())
    }

    // ── Tool: receipt_list ────────────────────────────────────────────────────

    fn tool_receipt_list(&self, id: Value, args: &Value) -> Value {
        let actor_filter = args
            .get("actor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let type_filter = args
            .get("action_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

        let store = match ReceiptStore::new(&self.receipt_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open receipt store: {e}")),
        };

        let all_ids = match store.list() {
            Ok(i) => i,
            Err(e) => return tool_error(id, format!("failed to list receipts: {e}")),
        };

        let mut receipts = Vec::new();
        for rid in &all_ids {
            if let Ok(receipt) = store.load(rid) {
                if let Some(ref actor) = actor_filter {
                    if receipt.actor.0 != *actor {
                        continue;
                    }
                }
                if let Some(ref type_str) = type_filter {
                    if receipt.action_type.as_tag() != type_str.as_str() {
                        continue;
                    }
                }
                receipts.push(receipt);
            }
        }

        // Sort by timestamp descending (newest first).
        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        let total = receipts.len();
        receipts.truncate(limit);

        let mut out = format!("Receipts ({} shown, {} total):\n", receipts.len(), total);

        if receipts.is_empty() {
            out.push_str("  (none match filters)");
        } else {
            for receipt in &receipts {
                let desc = if receipt.action.description.len() > 60 {
                    format!("{}...", &receipt.action.description[..57])
                } else {
                    receipt.action.description.clone()
                };
                out.push_str(&format!(
                    "  {} [{}] {} — {}\n",
                    receipt.id,
                    receipt.action_type.as_tag(),
                    micros_to_rfc3339(receipt.timestamp),
                    desc,
                ));
            }
        }

        tool_ok(id, out.trim_end().to_string())
    }

    // ── Tool: identity_health ─────────────────────────────────────────────────

    fn tool_identity_health(&self, id: Value, _args: &Value) -> Value {
        let mut out = String::from("AgenticIdentity Health Check\n\n");

        // Identity directory
        let id_dir_exists = self.identity_dir.exists();
        out.push_str(&format!(
            "Identity Directory: {}\n  Path: {}\n",
            if id_dir_exists { "OK" } else { "MISSING" },
            self.identity_dir.display()
        ));

        // Count identity files
        let identity_count = if id_dir_exists {
            std::fs::read_dir(&self.identity_dir)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().map(|x| x == "aid").unwrap_or(false))
                        .count()
                })
                .unwrap_or(0)
        } else {
            0
        };
        out.push_str(&format!("  Identities: {identity_count}\n"));

        // Default identity
        let default_path = self.identity_dir.join(format!("{DEFAULT_IDENTITY}.aid"));
        let default_exists = default_path.exists();
        out.push_str(&format!(
            "  Default identity: {}\n",
            if default_exists {
                "present"
            } else {
                "NOT FOUND (run identity_create)"
            }
        ));

        // Receipt store
        out.push('\n');
        let receipt_dir_exists = self.receipt_dir.exists();
        out.push_str(&format!(
            "Receipt Store: {}\n  Path: {}\n",
            if receipt_dir_exists { "OK" } else { "MISSING" },
            self.receipt_dir.display()
        ));

        let receipt_count = if receipt_dir_exists {
            match ReceiptStore::new(&self.receipt_dir) {
                Ok(store) => store.list().map(|ids| ids.len()).unwrap_or(0),
                Err(_) => 0,
            }
        } else {
            0
        };
        out.push_str(&format!("  Receipts: {receipt_count}\n"));

        // Trust store
        out.push('\n');
        let trust_dir_exists = self.trust_dir.exists();
        out.push_str(&format!(
            "Trust Store: {}\n  Path: {}\n",
            if trust_dir_exists { "OK" } else { "MISSING" },
            self.trust_dir.display()
        ));

        let (granted_count, received_count, revocation_count) = if trust_dir_exists {
            match TrustStore::new(&self.trust_dir) {
                Ok(store) => {
                    let g = store.list_granted().map(|i| i.len()).unwrap_or(0);
                    let r = store.list_received().map(|i| i.len()).unwrap_or(0);
                    let rev = store.list_revocations().map(|i| i.len()).unwrap_or(0);
                    (g, r, rev)
                }
                Err(_) => (0, 0, 0),
            }
        } else {
            (0, 0, 0)
        };

        out.push_str(&format!("  Granted:     {granted_count}\n"));
        out.push_str(&format!("  Received:    {received_count}\n"));
        out.push_str(&format!("  Revocations: {revocation_count}\n"));

        // Overall status
        out.push('\n');
        let ok = id_dir_exists && default_exists;
        out.push_str(&format!(
            "Overall: {}",
            if ok {
                "HEALTHY"
            } else {
                "NEEDS SETUP — run identity_create"
            }
        ));

        tool_ok(id, out)
    }

    // ── Tool: continuity_record ──────────────────────────────────────────────

    fn tool_continuity_record(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let content_hash = match args.get("content_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return tool_error(id, "content_hash is required"),
        };
        let intensity = args
            .get("intensity")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5) as f32;
        let exp_type_str = args
            .get("experience_type")
            .and_then(|v| v.as_str())
            .unwrap_or("cognition");

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let event_type = match exp_type_str {
            "perception" => agentic_identity::continuity::ExperienceType::Perception {
                source: agentic_identity::continuity::PerceptionSource::Text,
            },
            "cognition" => agentic_identity::continuity::ExperienceType::Cognition {
                cognition_type: agentic_identity::continuity::CognitionType::Thought,
            },
            "idle" => agentic_identity::continuity::ExperienceType::Idle {
                reason: "awaiting input".into(),
            },
            "system" => agentic_identity::continuity::ExperienceType::System {
                event: agentic_identity::continuity::SystemEvent::Checkpoint,
            },
            "memory" => agentic_identity::continuity::ExperienceType::Memory {
                operation: agentic_identity::continuity::MemoryOpType::Store,
            },
            "planning" => agentic_identity::continuity::ExperienceType::Planning {
                planning_type: agentic_identity::continuity::PlanningType::GoalSetting,
            },
            "emotion" => agentic_identity::continuity::ExperienceType::Emotion {
                emotion_type: "neutral".into(),
            },
            _ => agentic_identity::continuity::ExperienceType::Cognition {
                cognition_type: agentic_identity::continuity::CognitionType::Thought,
            },
        };

        match agentic_identity::continuity::record_experience(
            &anchor,
            event_type,
            content_hash,
            intensity,
            None,
        ) {
            Ok(exp) => {
                let out = format!(
                    "Experience recorded\n  ID: {}\n  Type: {}\n  Sequence: {}\n  Timestamp: {}\n  Intensity: {:.1}\n  Hash: {}",
                    exp.id, exp.event_type.as_tag(), exp.sequence_number, micros_to_rfc3339(exp.timestamp), exp.intensity, exp.cumulative_hash
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to record experience: {e}")),
        }
    }

    // ── Tool: continuity_anchor ───────────────────────────────────────────────

    fn tool_continuity_anchor(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let anchor_type_str = args
            .get("anchor_type")
            .and_then(|v| v.as_str())
            .unwrap_or("manual");

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let anchor_type = match anchor_type_str {
            "genesis" => agentic_identity::continuity::AnchorType::Genesis,
            "time_based" => {
                agentic_identity::continuity::AnchorType::TimeBased { interval_hours: 24 }
            }
            "experience_count" => {
                agentic_identity::continuity::AnchorType::ExperienceCount { interval: 1000 }
            }
            _ => agentic_identity::continuity::AnchorType::Manual,
        };

        // Create a checkpoint experience to anchor to
        let exp = match agentic_identity::continuity::record_experience(
            &anchor,
            agentic_identity::continuity::ExperienceType::System {
                event: agentic_identity::continuity::SystemEvent::Checkpoint,
            },
            &format!("anchor_{anchor_type_str}"),
            1.0,
            None,
        ) {
            Ok(e) => e,
            Err(e) => return tool_error(id, format!("failed to create experience: {e}")),
        };

        match agentic_identity::continuity::create_anchor(&anchor, anchor_type, &exp, None, None) {
            Ok(ca) => {
                let out = format!(
                    "Continuity anchor created\n  ID: {}\n  Type: {}\n  Experience: {}\n  Count: {}\n  Hash: {}",
                    ca.id, ca.anchor_type.as_tag(), ca.experience_id, ca.experience_count, ca.cumulative_hash
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to create anchor: {e}")),
        }
    }

    // ── Tool: continuity_heartbeat ────────────────────────────────────────────

    fn tool_continuity_heartbeat(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let status_str = args
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active");

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let status = match status_str {
            "idle" => agentic_identity::continuity::HeartbeatStatus::Idle,
            "suspended" => agentic_identity::continuity::HeartbeatStatus::Suspended,
            "degraded" => agentic_identity::continuity::HeartbeatStatus::Degraded,
            _ => agentic_identity::continuity::HeartbeatStatus::Active,
        };

        let health = agentic_identity::continuity::HealthMetrics {
            memory_usage_bytes: 0,
            experience_rate_per_hour: 0.0,
            error_count: 0,
            latency_ms: 0,
        };

        match agentic_identity::continuity::create_heartbeat(
            &anchor,
            0,
            "mcp_heartbeat",
            0,
            0,
            status,
            health,
        ) {
            Ok(hb) => {
                let out = format!(
                    "Heartbeat created\n  ID: {}\n  Status: {}\n  Timestamp: {}",
                    hb.id,
                    hb.status.as_tag(),
                    micros_to_rfc3339(hb.timestamp)
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to create heartbeat: {e}")),
        }
    }

    // ── Tool: continuity_status ───────────────────────────────────────────────

    fn tool_continuity_status(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let out = format!(
            "Continuity status for identity '{}'\n  No experiences recorded yet (use continuity_record to start)",
            name
        );
        tool_ok(id, out)
    }

    // ── Tool: continuity_gaps ─────────────────────────────────────────────────

    fn tool_continuity_gaps(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let grace = args
            .get("grace_period_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(300);
        let out = format!(
            "Gap analysis for identity '{}' (grace: {}s)\n  No experiences recorded yet",
            name, grace
        );
        tool_ok(id, out)
    }

    // ── Tool: spawn_create ────────────────────────────────────────────────────

    fn tool_spawn_create(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let purpose = match args.get("purpose").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return tool_error(id, "purpose is required"),
        };
        let authority_arr = match args.get("authority").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => return tool_error(id, "authority is required (array of capability URIs)"),
        };
        let spawn_type_str = args
            .get("spawn_type")
            .and_then(|v| v.as_str())
            .unwrap_or("worker");

        let path = self.identity_dir.join(format!("{name}.aid"));
        let parent = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let spawn_type = match spawn_type_str {
            "delegate" => agentic_identity::spawn::SpawnType::Delegate,
            "clone" => agentic_identity::spawn::SpawnType::Clone,
            "specialist" => agentic_identity::spawn::SpawnType::Specialist,
            _ => agentic_identity::spawn::SpawnType::Worker,
        };

        let authority: Vec<Capability> = authority_arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(Capability::new)
            .collect();
        let ceiling = authority.clone();

        match agentic_identity::spawn::spawn_child(
            &parent,
            spawn_type,
            purpose,
            authority,
            ceiling,
            agentic_identity::spawn::SpawnLifetime::Indefinite,
            agentic_identity::spawn::SpawnConstraints::default(),
            None,
            &[],
        ) {
            Ok((child, record, receipt)) => {
                // Save child identity
                let child_name = format!("{}-{}", name, record.spawn_type.as_tag());
                let child_path = self.identity_dir.join(format!("{child_name}.aid"));
                if let Err(e) = save_identity(&child, &child_path, MCP_PASSPHRASE) {
                    return tool_error(id, format!("failed to save child identity: {e}"));
                }

                // Save spawn receipt
                if let Ok(store) = ReceiptStore::new(&self.receipt_dir) {
                    let _ = store.save(&receipt);
                }

                // Save spawn record for terminate/list/lineage
                if let Ok(store) = SpawnStore::new(&self.spawn_dir) {
                    let _ = store.save(&record);
                }

                let caps: Vec<&str> = record
                    .authority_granted
                    .iter()
                    .map(|c| c.uri.as_str())
                    .collect();
                let out = format!(
                    "Child identity spawned\n  Spawn ID: {}\n  Parent: {}\n  Child ID: {}\n  Type: {}\n  Purpose: {}\n  Authority: {}\n  Receipt: {}\n  Child file: {}",
                    record.id, record.parent_id, record.child_id, record.spawn_type.as_tag(),
                    record.spawn_purpose, caps.join(", "), receipt.id, child_path.display()
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to spawn child: {e}")),
        }
    }

    // ── Tool: spawn_terminate ─────────────────────────────────────────────────

    fn tool_spawn_terminate(&self, id: Value, args: &Value) -> Value {
        let spawn_id_str = match args.get("spawn_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return tool_error(id, "spawn_id is required"),
        };
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("terminated");
        let cascade = args
            .get("cascade")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let parent_name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        // Load parent identity
        let parent_path = self.identity_dir.join(format!("{parent_name}.aid"));
        let parent = match load_identity(&parent_path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => {
                return tool_error(id, format!("failed to load identity '{parent_name}': {e}"))
            }
        };

        // Open spawn store
        let store = match SpawnStore::new(&self.spawn_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open spawn store: {e}")),
        };

        // Load the target spawn record
        let spawn_id = agentic_identity::spawn::SpawnId(spawn_id_str.to_string());
        let mut record = match store.load(&spawn_id) {
            Ok(r) => r,
            Err(e) => {
                return tool_error(id, format!("failed to load spawn record '{spawn_id}': {e}"))
            }
        };

        if record.terminated {
            return tool_error(id, format!("spawn {} is already terminated", spawn_id));
        }

        // Load all records for cascade
        let mut all_records = match store.load_all() {
            Ok(r) => r,
            Err(e) => return tool_error(id, format!("failed to load spawn records: {e}")),
        };

        // Terminate using the engine
        match agentic_identity::spawn::terminate_spawn(
            &parent,
            &mut record,
            reason,
            cascade,
            &mut all_records,
        ) {
            Ok((receipt, terminated_ids)) => {
                // Persist updated record
                if let Err(e) = store.save(&record) {
                    return tool_error(id, format!("failed to save terminated spawn record: {e}"));
                }

                // Persist cascade-terminated records
                if cascade {
                    for rec in &all_records {
                        if rec.terminated && terminated_ids.iter().any(|tid| tid.0 == rec.id.0) {
                            let _ = store.save(rec);
                        }
                    }
                }

                // Save termination receipt
                if let Ok(rstore) = ReceiptStore::new(&self.receipt_dir) {
                    let _ = rstore.save(&receipt);
                }

                let out = format!(
                    "Spawn terminated\n  Spawn ID: {}\n  Child ID: {}\n  Reason: {}\n  Cascade: {}\n  Records terminated: {}\n  Receipt: {}",
                    record.id,
                    record.child_id,
                    record.termination_reason.as_deref().unwrap_or("unknown"),
                    cascade,
                    terminated_ids.len(),
                    receipt.id
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("termination failed: {e}")),
        }
    }

    // ── Tool: spawn_list ──────────────────────────────────────────────────────

    fn tool_spawn_list(&self, id: Value, args: &Value) -> Value {
        let active_only = args
            .get("active_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let store = match SpawnStore::new(&self.spawn_dir) {
            Ok(s) => s,
            Err(e) => return tool_error(id, format!("failed to open spawn store: {e}")),
        };

        let records = match store.load_all() {
            Ok(r) => r,
            Err(e) => return tool_error(id, format!("failed to load spawn records: {e}")),
        };

        let filtered: Vec<&agentic_identity::spawn::SpawnRecord> = if active_only {
            records.iter().filter(|r| !r.terminated).collect()
        } else {
            records.iter().collect()
        };

        if filtered.is_empty() {
            return tool_ok(
                id,
                "No spawned identities found (use spawn_create to spawn a child)".to_string(),
            );
        }

        let mut lines = Vec::new();
        lines.push(format!("Spawned identities ({}):", filtered.len()));
        for r in &filtered {
            let status = if r.terminated { "terminated" } else { "active" };
            let caps: Vec<&str> = r.authority_granted.iter().map(|c| c.uri.as_str()).collect();
            lines.push(format!(
                "  {} [{}] {} — {} ({})",
                r.id,
                r.spawn_type.as_tag(),
                status,
                r.spawn_purpose,
                caps.join(", ")
            ));
        }
        tool_ok(id, lines.join("\n"))
    }

    // ── Tool: spawn_lineage ───────────────────────────────────────────────────

    fn tool_spawn_lineage(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        // Load all spawn records
        let store = match SpawnStore::new(&self.spawn_dir) {
            Ok(s) => s,
            Err(_) => {
                // No spawn store means root identity
                let out = format!(
                    "Lineage for identity '{}'\n  Root (no spawn record — this is a root identity)\n  Depth: 0\n  Authority: * (full)",
                    name
                );
                return tool_ok(id, out);
            }
        };

        let records = store.load_all().unwrap_or_default();

        // Load the identity to get its ID
        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let identity_id = anchor.id();

        // Check if this identity appears as a child in any spawn record
        let as_child = records.iter().find(|r| r.child_id == identity_id);

        match as_child {
            None => {
                // Root identity
                let out = format!(
                    "Lineage for identity '{}'\n  Root (no spawn record — this is a root identity)\n  Depth: 0\n  Authority: * (full)",
                    name
                );
                tool_ok(id, out)
            }
            Some(record) => {
                let ancestors = agentic_identity::spawn::get_ancestors(&identity_id, &records)
                    .unwrap_or_default();
                let authority =
                    agentic_identity::spawn::get_effective_authority(&identity_id, &records)
                        .unwrap_or_default();
                let caps: Vec<&str> = authority.iter().map(|c| c.uri.as_str()).collect();
                let status = if record.terminated {
                    "TERMINATED"
                } else {
                    "active"
                };

                let out = format!(
                    "Lineage for identity '{}'\n  Status: {}\n  Parent: {}\n  Spawn ID: {}\n  Type: {}\n  Depth: {}\n  Authority: {}",
                    name,
                    status,
                    record.parent_id,
                    record.id,
                    record.spawn_type.as_tag(),
                    ancestors.len(),
                    caps.join(", ")
                );
                tool_ok(id, out)
            }
        }
    }

    // ── Tool: spawn_authority ─────────────────────────────────────────────────

    fn tool_spawn_authority(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);

        // Load the identity
        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let identity_id = anchor.id();
        let records = SpawnStore::new(&self.spawn_dir)
            .ok()
            .and_then(|s| s.load_all().ok())
            .unwrap_or_default();

        let authority = agentic_identity::spawn::get_effective_authority(&identity_id, &records)
            .unwrap_or_default();

        let caps: Vec<&str> = authority.iter().map(|c| c.uri.as_str()).collect();
        let label = if caps.len() == 1 && caps[0] == "*" {
            format!("{} (root identity — full authority)", caps.join(", "))
        } else if caps.is_empty() {
            "none (terminated or expired)".to_string()
        } else {
            caps.join(", ")
        };

        let out = format!("Effective authority for identity '{}'\n  {}", name, label);
        tool_ok(id, out)
    }

    // ── Tool: competence_record ─────────────────────────────────────────────

    fn tool_competence_record(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let domain_str = match args.get("domain").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => return tool_error(id, "domain is required"),
        };
        let outcome_str = match args.get("outcome").and_then(|v| v.as_str()) {
            Some(o) => o,
            None => return tool_error(id, "outcome is required (success, failure, or partial)"),
        };
        let receipt_id_str = match args.get("receipt_id").and_then(|v| v.as_str()) {
            Some(r) => r,
            None => return tool_error(id, "receipt_id is required"),
        };

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let domain = agentic_identity::competence::CompetenceDomain::new(domain_str);
        let outcome = match outcome_str {
            "success" => agentic_identity::competence::AttemptOutcome::Success,
            "failure" => {
                let reason = args
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unspecified")
                    .to_string();
                agentic_identity::competence::AttemptOutcome::Failure { reason }
            }
            "partial" => {
                let score = args.get("score").and_then(|v| v.as_f64()).unwrap_or(0.5) as f32;
                agentic_identity::competence::AttemptOutcome::Partial { score }
            }
            _ => return tool_error(id, "outcome must be 'success', 'failure', or 'partial'"),
        };
        let receipt_id = ReceiptId(receipt_id_str.to_string());

        match agentic_identity::competence::record_attempt(
            &anchor,
            domain,
            outcome.clone(),
            receipt_id.clone(),
            None,
            None,
        ) {
            Ok(attempt) => {
                let out = format!(
                    "Competence attempt recorded\n  Attempt ID: {}\n  Domain: {}\n  Outcome: {:?}\n  Receipt: {}\n  Timestamp: {}",
                    attempt.attempt_id.0, attempt.domain.0, attempt.outcome, receipt_id.0, micros_to_rfc3339(attempt.timestamp)
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to record attempt: {e}")),
        }
    }

    // ── Tool: competence_show ────────────────────────────────────────────────

    fn tool_competence_show(&self, id: Value, args: &Value) -> Value {
        let domain_str = args.get("domain").and_then(|v| v.as_str()).unwrap_or("*");
        let out = format!(
            "Competence record for domain '{}'\n  No attempts recorded yet\n  (Use competence_record to track outcomes)",
            domain_str
        );
        tool_ok(id, out)
    }

    // ── Tool: competence_prove ───────────────────────────────────────────────

    fn tool_competence_prove(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let domain_str = match args.get("domain").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => return tool_error(id, "domain is required"),
        };
        let min_rate = args.get("min_rate").and_then(|v| v.as_f64()).unwrap_or(0.8) as f32;
        let min_attempts = args
            .get("min_attempts")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let domain = agentic_identity::competence::CompetenceDomain::new(domain_str);
        let _requirement = agentic_identity::competence::CompetenceRequirement {
            domain: domain.clone(),
            min_success_rate: min_rate,
            min_attempts: min_attempts as u64,
            min_streak: None,
            max_age_seconds: None,
        };

        // For now, we have no persistent attempt store yet — return a descriptive message
        let out = format!(
            "Competence proof generation for domain '{}'\n  Identity: {}\n  Required success rate: {:.0}%\n  Min attempts: {}\n  Status: No attempts recorded yet — use competence_record first",
            domain_str, anchor.id(), min_rate * 100.0, min_attempts
        );
        tool_ok(id, out)
    }

    // ── Tool: competence_verify ──────────────────────────────────────────────

    fn tool_competence_verify(&self, id: Value, args: &Value) -> Value {
        let proof_id = match args.get("proof_id").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return tool_error(id, "proof_id is required"),
        };
        let out = format!(
            "Competence proof verification\n  Proof ID: {}\n  Status: Proof not found (competence proofs are not yet persisted to disk)",
            proof_id
        );
        tool_ok(id, out)
    }

    // ── Tool: competence_list ────────────────────────────────────────────────

    fn tool_competence_list(&self, id: Value, _args: &Value) -> Value {
        tool_ok(id, "Competence domains: (none recorded yet)\n  Use competence_record to begin tracking outcomes.".to_string())
    }

    // ── Tool: negative_prove ─────────────────────────────────────────────────

    fn tool_negative_prove(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let capability = match args.get("capability").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return tool_error(id, "capability is required"),
        };

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        // Root identities have full authority — check against ceiling (which for root is everything)
        let ceiling: Vec<String> = vec![];
        let spawn_records: Vec<agentic_identity::spawn::SpawnRecord> = vec![];

        match agentic_identity::negative::prove_cannot(
            &anchor,
            capability,
            &ceiling,
            &spawn_records,
        ) {
            Ok(proof) => {
                let out = format!(
                    "Negative capability proof generated\n  Proof ID: {}\n  Capability: {}\n  Reason: {:?}\n  Timestamp: {}",
                    proof.proof_id.0, proof.cannot_do, proof.reason, micros_to_rfc3339(proof.generated_at)
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("cannot prove impossibility: {e}")),
        }
    }

    // ── Tool: negative_verify ────────────────────────────────────────────────

    fn tool_negative_verify(&self, id: Value, args: &Value) -> Value {
        let proof_id = match args.get("proof_id").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return tool_error(id, "proof_id is required"),
        };
        let out = format!(
            "Negative proof verification\n  Proof ID: {}\n  Status: Proof not found (negative proofs are not yet persisted to disk)",
            proof_id
        );
        tool_ok(id, out)
    }

    // ── Tool: negative_declare ───────────────────────────────────────────────

    fn tool_negative_declare(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let caps_str = match args.get("capabilities").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return tool_error(id, "capabilities is required (comma-separated URIs)"),
        };
        let reason = match args.get("reason").and_then(|v| v.as_str()) {
            Some(r) => r,
            None => return tool_error(id, "reason is required"),
        };
        let permanent = args
            .get("permanent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let capabilities: Vec<String> = caps_str.split(',').map(|s| s.trim().to_string()).collect();

        match agentic_identity::negative::declare_cannot(
            &anchor,
            capabilities.clone(),
            reason,
            permanent,
            vec![],
        ) {
            Ok(declaration) => {
                let out = format!(
                    "Negative declaration created\n  Declaration ID: {}\n  Capabilities: {}\n  Reason: {}\n  Permanent: {}\n  Timestamp: {}",
                    declaration.declaration_id.0, capabilities.join(", "), reason, permanent, micros_to_rfc3339(declaration.declared_at)
                );
                tool_ok(id, out)
            }
            Err(e) => tool_error(id, format!("failed to create declaration: {e}")),
        }
    }

    // ── Tool: negative_list ──────────────────────────────────────────────────

    fn tool_negative_list(&self, id: Value, _args: &Value) -> Value {
        tool_ok(id, "Negative declarations: (none recorded yet)\n  Use negative_declare to add self-imposed restrictions.".to_string())
    }

    // ── Tool: negative_check ─────────────────────────────────────────────────

    fn tool_negative_check(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let capability = match args.get("capability").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return tool_error(id, "capability is required"),
        };

        let path = self.identity_dir.join(format!("{name}.aid"));
        let anchor = match load_identity(&path, MCP_PASSPHRASE) {
            Ok(a) => a,
            Err(e) => return tool_error(id, format!("failed to load identity '{name}': {e}")),
        };

        let ceiling: Vec<String> = vec![];
        let declarations: Vec<agentic_identity::negative::NegativeDeclaration> = vec![];
        let spawn_records: Vec<agentic_identity::spawn::SpawnRecord> = vec![];

        let result = agentic_identity::negative::is_impossible(
            &anchor.id(),
            capability,
            &ceiling,
            &spawn_records,
            &declarations,
        );

        match result {
            Some(reason) => {
                let out = format!(
                    "Capability '{}' is IMPOSSIBLE\n  Reason: {:?}",
                    capability, reason
                );
                tool_ok(id, out)
            }
            None => {
                let out = format!(
                    "Capability '{}' is POSSIBLE (not structurally excluded)",
                    capability
                );
                tool_ok(id, out)
            }
        }
    }

    // ── resources/list ────────────────────────────────────────────────────────

    fn handle_resources_list(&self, id: Value) -> Value {
        ok_result(
            id,
            json!({
                "resources": [
                    {
                        "uri": "aid://identity/default",
                        "name": "Default Identity Document",
                        "description": "Public identity document for the default identity",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aid://receipts/recent",
                        "name": "Recent Receipts",
                        "description": "Most recent action receipts (up to 20)",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aid://trust/granted",
                        "name": "Granted Trust",
                        "description": "Trust grants issued by this identity",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aid://trust/received",
                        "name": "Received Trust",
                        "description": "Trust grants received by this identity",
                        "mimeType": "application/json"
                    }
                ]
            }),
        )
    }

    // ── resources/read ────────────────────────────────────────────────────────

    fn handle_resources_read(&self, id: Value, params: &Value) -> Value {
        let uri = match params.get("uri").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => return rpc_error(id, -32602, "missing resource uri"),
        };

        // Route based on URI scheme.
        if let Some(rest) = uri.strip_prefix("aid://identity/") {
            self.resource_identity(id, rest)
        } else if let Some(rest) = uri.strip_prefix("aid://receipt/") {
            self.resource_receipt(id, rest)
        } else if let Some(rest) = uri.strip_prefix("aid://trust/") {
            match rest {
                "granted" => self.resource_trust_list(id, "granted"),
                "received" => self.resource_trust_list(id, "received"),
                trust_id => self.resource_trust_grant(id, trust_id),
            }
        } else if uri == "aid://receipts/recent" {
            self.resource_receipts_recent(id)
        } else {
            rpc_error(id, -32602, format!("unknown resource URI: {uri}"))
        }
    }

    fn resource_identity(&self, id: Value, name: &str) -> Value {
        let path = self.identity_dir.join(format!("{name}.aid"));

        if !path.exists() {
            return rpc_error(id, -32602, format!("identity '{name}' not found"));
        }

        match read_public_document(&path) {
            Ok(doc) => {
                let text = serde_json::to_string_pretty(&doc)
                    .unwrap_or_else(|e| format!("serialization error: {e}"));
                ok_result(
                    id,
                    json!({
                        "contents": [{
                            "uri": format!("aid://identity/{name}"),
                            "mimeType": "application/json",
                            "text": text
                        }]
                    }),
                )
            }
            Err(e) => rpc_error(id, -32602, format!("failed to read identity: {e}")),
        }
    }

    fn resource_receipt(&self, id: Value, receipt_id: &str) -> Value {
        let store = match ReceiptStore::new(&self.receipt_dir) {
            Ok(s) => s,
            Err(e) => return rpc_error(id, -32602, format!("receipt store error: {e}")),
        };

        let rid = ReceiptId(receipt_id.to_string());
        match store.load(&rid) {
            Ok(receipt) => {
                let text = serde_json::to_string_pretty(&receipt)
                    .unwrap_or_else(|e| format!("serialization error: {e}"));
                ok_result(
                    id,
                    json!({
                        "contents": [{
                            "uri": format!("aid://receipt/{receipt_id}"),
                            "mimeType": "application/json",
                            "text": text
                        }]
                    }),
                )
            }
            Err(e) => rpc_error(id, -32602, format!("receipt not found: {e}")),
        }
    }

    fn resource_trust_grant(&self, id: Value, trust_id: &str) -> Value {
        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return rpc_error(id, -32602, format!("trust store error: {e}")),
        };

        let tid = TrustId(trust_id.to_string());
        match store.load_grant(&tid) {
            Ok(grant) => {
                let text = serde_json::to_string_pretty(&grant)
                    .unwrap_or_else(|e| format!("serialization error: {e}"));
                ok_result(
                    id,
                    json!({
                        "contents": [{
                            "uri": format!("aid://trust/{trust_id}"),
                            "mimeType": "application/json",
                            "text": text
                        }]
                    }),
                )
            }
            Err(e) => rpc_error(id, -32602, format!("trust grant not found: {e}")),
        }
    }

    fn resource_trust_list(&self, id: Value, direction: &str) -> Value {
        let store = match TrustStore::new(&self.trust_dir) {
            Ok(s) => s,
            Err(e) => return rpc_error(id, -32602, format!("trust store error: {e}")),
        };

        let ids = match direction {
            "granted" => store.list_granted(),
            "received" => store.list_received(),
            _ => store.list_granted(),
        };

        let ids = match ids {
            Ok(i) => i,
            Err(e) => return rpc_error(id, -32602, format!("failed to list grants: {e}")),
        };

        let grants: Vec<Value> = ids
            .iter()
            .filter_map(|gid| store.load_grant(gid).ok())
            .map(|g| serde_json::to_value(&g).unwrap_or(Value::Null))
            .collect();

        let text = serde_json::to_string_pretty(&grants)
            .unwrap_or_else(|e| format!("serialization error: {e}"));

        ok_result(
            id,
            json!({
                "contents": [{
                    "uri": format!("aid://trust/{direction}"),
                    "mimeType": "application/json",
                    "text": text
                }]
            }),
        )
    }

    fn resource_receipts_recent(&self, id: Value) -> Value {
        let store = match ReceiptStore::new(&self.receipt_dir) {
            Ok(s) => s,
            Err(e) => return rpc_error(id, -32602, format!("receipt store error: {e}")),
        };

        let all_ids = match store.list() {
            Ok(i) => i,
            Err(e) => return rpc_error(id, -32602, format!("failed to list receipts: {e}")),
        };

        let mut receipts: Vec<_> = all_ids
            .iter()
            .filter_map(|rid| store.load(rid).ok())
            .collect();

        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        receipts.truncate(20);

        let values: Vec<Value> = receipts
            .iter()
            .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
            .collect();

        let text = serde_json::to_string_pretty(&values)
            .unwrap_or_else(|e| format!("serialization error: {e}"));

        ok_result(
            id,
            json!({
                "contents": [{
                    "uri": "aid://receipts/recent",
                    "mimeType": "application/json",
                    "text": text
                }]
            }),
        )
    }

    // ── V2: Grounding tools ──────────────────────────────────────────────────

    fn tool_identity_ground(&self, id: Value, args: &Value) -> Value {
        let claim = match args.get("claim").and_then(|v| v.as_str()) {
            Some(c) if !c.trim().is_empty() => c,
            _ => return tool_error(id, "'claim' is required"),
        };

        let claim_lower = claim.to_lowercase();
        let claim_words: Vec<&str> = claim_lower.split_whitespace().collect();
        let mut evidence = Vec::new();

        // Search trust grants
        if let Ok(store) = TrustStore::new(&self.trust_dir) {
            for grant_ids in [store.list_granted().ok(), store.list_received().ok()]
                .into_iter()
                .flatten()
            {
                for gid in grant_ids.iter().take(100) {
                    if let Ok(grant) = store.load_grant(gid) {
                        let mut score = 0.0f32;
                        for cap in &grant.capabilities {
                            if claim_lower.contains(&cap.uri.to_lowercase()) {
                                score += 1.0;
                            }
                            let cap_lower = cap.uri.to_lowercase();
                            let cap_words: Vec<&str> = cap_lower
                                .split(':')
                                .flat_map(|s| s.split_whitespace())
                                .collect();
                            let overlap = claim_words
                                .iter()
                                .filter(|w| {
                                    cap_words
                                        .iter()
                                        .any(|cw| cw.contains(**w) || w.contains(cw))
                                })
                                .count();
                            score += overlap as f32 * 0.3;
                        }
                        if score > 0.0 {
                            evidence.push(json!({
                                "type": "trust_grant",
                                "id": grant.id.0,
                                "capabilities": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "score": score,
                            }));
                        }
                    }
                }
            }
        }

        // Search receipts
        if let Ok(store) = ReceiptStore::new(&self.receipt_dir) {
            if let Ok(receipt_ids) = store.list() {
                for rid in receipt_ids.iter().take(100) {
                    if let Ok(receipt) = store.load(rid) {
                        let action_lower = receipt.action.description.to_lowercase();
                        let overlap = claim_words
                            .iter()
                            .filter(|w| action_lower.contains(**w))
                            .count();
                        if overlap > 0 {
                            let score = overlap as f32 / claim_words.len().max(1) as f32;
                            evidence.push(json!({
                                "type": "receipt",
                                "id": receipt.id.0,
                                "action_type": format!("{:?}", receipt.action_type),
                                "action": receipt.action.description,
                                "score": score,
                            }));
                        }
                    }
                }
            }
        }

        if evidence.is_empty() {
            return tool_ok(
                id,
                serde_json::to_string_pretty(&json!({
                    "status": "ungrounded",
                    "claim": claim,
                    "reason": "No trust grants, receipts, or competence records match this claim",
                    "suggestions": []
                }))
                .unwrap(),
            );
        }

        tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "status": "verified",
                "claim": claim,
                "evidence_count": evidence.len(),
                "evidence": evidence
            }))
            .unwrap(),
        )
    }

    fn tool_identity_evidence(&self, id: Value, args: &Value) -> Value {
        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(q) if !q.trim().is_empty() => q,
            _ => return tool_error(id, "'query' is required"),
        };
        let max_results = args
            .get("max_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();
        let mut evidence: Vec<(f32, Value)> = Vec::new();

        // Search trust grants
        if let Ok(store) = TrustStore::new(&self.trust_dir) {
            for grant_ids in [store.list_granted().ok(), store.list_received().ok()]
                .into_iter()
                .flatten()
            {
                for gid in grant_ids.iter().take(100) {
                    if let Ok(grant) = store.load_grant(gid) {
                        let cap_str: String = grant
                            .capabilities
                            .iter()
                            .map(|c| c.uri.to_lowercase())
                            .collect::<Vec<_>>()
                            .join(" ");
                        let overlap = query_words.iter().filter(|w| cap_str.contains(**w)).count();
                        if overlap > 0 {
                            let score = overlap as f32 / query_words.len().max(1) as f32;
                            evidence.push((score, json!({
                                "type": "trust_grant",
                                "id": grant.id.0,
                                "grantor": grant.grantor.0,
                                "grantee": grant.grantee.0,
                                "capabilities": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                                "granted_at": micros_to_rfc3339(grant.granted_at),
                                "score": score,
                            })));
                        }
                    }
                }
            }
        }

        // Search receipts
        if let Ok(store) = ReceiptStore::new(&self.receipt_dir) {
            if let Ok(receipt_ids) = store.list() {
                for rid in receipt_ids.iter().take(200) {
                    if let Ok(receipt) = store.load(rid) {
                        let action_lower = receipt.action.description.to_lowercase();
                        let overlap = query_words
                            .iter()
                            .filter(|w| action_lower.contains(**w))
                            .count();
                        if overlap > 0 {
                            let score = overlap as f32 / query_words.len().max(1) as f32;
                            evidence.push((
                                score,
                                json!({
                                    "type": "receipt",
                                    "id": receipt.id.0,
                                    "actor": receipt.actor.0,
                                    "action_type": format!("{:?}", receipt.action_type),
                                    "action": receipt.action.description,
                                    "timestamp": micros_to_rfc3339(receipt.timestamp),
                                    "score": score,
                                }),
                            ));
                        }
                    }
                }
            }
        }

        evidence.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        evidence.truncate(max_results);
        let items: Vec<Value> = evidence.into_iter().map(|(_, v)| v).collect();

        tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "query": query,
                "count": items.len(),
                "evidence": items
            }))
            .unwrap(),
        )
    }

    fn tool_identity_suggest(&self, id: Value, args: &Value) -> Value {
        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(q) if !q.trim().is_empty() => q,
            _ => return tool_error(id, "'query' is required"),
        };
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

        let query_lower = query.to_lowercase();
        let mut suggestions: Vec<Value> = Vec::new();

        // Suggest from trust grant capabilities
        if let Ok(store) = TrustStore::new(&self.trust_dir) {
            for grant_ids in [store.list_granted().ok(), store.list_received().ok()]
                .into_iter()
                .flatten()
            {
                for gid in grant_ids.iter().take(50) {
                    if let Ok(grant) = store.load_grant(gid) {
                        for cap in &grant.capabilities {
                            if cap.uri.to_lowercase().contains(&query_lower)
                                || query_lower.contains(&cap.uri.to_lowercase())
                            {
                                suggestions.push(json!({
                                    "type": "capability",
                                    "capability": cap.uri,
                                    "grant_id": grant.id.0,
                                }));
                            }
                        }
                    }
                }
            }
        }

        // Suggest from receipt actions
        if let Ok(store) = ReceiptStore::new(&self.receipt_dir) {
            if let Ok(receipt_ids) = store.list() {
                for rid in receipt_ids.iter().take(50) {
                    if let Ok(receipt) = store.load(rid) {
                        let desc_lower = receipt.action.description.to_lowercase();
                        if desc_lower.contains(&query_lower) || query_lower.contains(&desc_lower) {
                            suggestions.push(json!({
                                "type": "action",
                                "action": receipt.action.description,
                                "receipt_id": receipt.id.0,
                            }));
                        }
                    }
                }
            }
        }

        suggestions.truncate(limit);

        tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "query": query,
                "count": suggestions.len(),
                "suggestions": suggestions
            }))
            .unwrap(),
        )
    }

    // ── V2: Workspace tools ──────────────────────────────────────────────────

    fn tool_identity_workspace_create(&mut self, id: Value, args: &Value) -> Value {
        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.trim().is_empty() => n,
            _ => return tool_error(id, "'name' is required"),
        };
        let ws_id = self.workspace_manager.create(name);
        tool_ok(
            id,
            serde_json::to_string_pretty(&json!({
                "workspace_id": ws_id, "name": name, "status": "created"
            }))
            .unwrap(),
        )
    }

    fn tool_identity_workspace_add(&mut self, id: Value, args: &Value) -> Value {
        let workspace_id = match args.get("workspace_id").and_then(|v| v.as_str()) {
            Some(w) => w,
            _ => return tool_error(id, "'workspace_id' is required"),
        };
        let path = match args.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            _ => return tool_error(id, "'path' is required"),
        };
        let role = args
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("primary");
        let label = args
            .get("label")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        match self.workspace_manager.add_context(workspace_id, path, role, label) {
            Ok(ctx_id) => tool_ok(id, serde_json::to_string_pretty(&json!({
                "context_id": ctx_id, "workspace_id": workspace_id, "role": role, "status": "added"
            })).unwrap()),
            Err(e) => tool_error(id, e),
        }
    }

    fn tool_identity_workspace_list(&self, id: Value, args: &Value) -> Value {
        let workspace_id = match args.get("workspace_id").and_then(|v| v.as_str()) {
            Some(w) => w,
            _ => return tool_error(id, "'workspace_id' is required"),
        };
        match self.workspace_manager.list(workspace_id) {
            Ok(items) => tool_ok(
                id,
                serde_json::to_string_pretty(&json!({
                    "workspace_id": workspace_id,
                    "count": items.len(),
                    "contexts": items
                }))
                .unwrap(),
            ),
            Err(e) => tool_error(id, e),
        }
    }

    fn tool_identity_workspace_query(&self, id: Value, args: &Value) -> Value {
        let workspace_id = match args.get("workspace_id").and_then(|v| v.as_str()) {
            Some(w) => w,
            _ => return tool_error(id, "'workspace_id' is required"),
        };
        let query = match args.get("query").and_then(|v| v.as_str()) {
            Some(q) => q,
            _ => return tool_error(id, "'query' is required"),
        };
        let max_per = args
            .get("max_per_context")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        match self
            .workspace_manager
            .query_all(workspace_id, query, max_per)
        {
            Ok(results) => {
                let total: usize = results
                    .iter()
                    .map(|r| r["matches"].as_array().map(|a| a.len()).unwrap_or(0))
                    .sum();
                tool_ok(id, serde_json::to_string_pretty(&json!({
                    "workspace_id": workspace_id, "query": query, "total_matches": total, "results": results
                })).unwrap())
            }
            Err(e) => tool_error(id, e),
        }
    }

    fn tool_identity_workspace_compare(&self, id: Value, args: &Value) -> Value {
        let workspace_id = match args.get("workspace_id").and_then(|v| v.as_str()) {
            Some(w) => w,
            _ => return tool_error(id, "'workspace_id' is required"),
        };
        let item = match args.get("item").and_then(|v| v.as_str()) {
            Some(i) => i,
            _ => return tool_error(id, "'item' is required"),
        };
        let max_per = args
            .get("max_per_context")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as usize;

        match self.workspace_manager.compare(workspace_id, item, max_per) {
            Ok(result) => tool_ok(id, serde_json::to_string_pretty(&result).unwrap()),
            Err(e) => tool_error(id, e),
        }
    }

    fn tool_identity_workspace_xref(&self, id: Value, args: &Value) -> Value {
        let workspace_id = match args.get("workspace_id").and_then(|v| v.as_str()) {
            Some(w) => w,
            _ => return tool_error(id, "'workspace_id' is required"),
        };
        let item = match args.get("item").and_then(|v| v.as_str()) {
            Some(i) => i,
            _ => return tool_error(id, "'item' is required"),
        };

        match self.workspace_manager.cross_reference(workspace_id, item) {
            Ok(result) => tool_ok(id, serde_json::to_string_pretty(&result).unwrap()),
            Err(e) => tool_error(id, e),
        }
    }
}

// ── Identity Workspace Manager ───────────────────────────────────────────────

struct IdentityWorkspaceContext {
    id: String,
    role: String,
    path: String,
    label: Option<String>,
    trust_dir: PathBuf,
    receipt_dir: PathBuf,
}

#[allow(dead_code)]
struct IdentityWorkspace {
    id: String,
    name: String,
    contexts: Vec<IdentityWorkspaceContext>,
}

struct IdentityWorkspaceManager {
    workspaces: std::collections::HashMap<String, IdentityWorkspace>,
    next_id: u64,
}

impl IdentityWorkspaceManager {
    fn new() -> Self {
        Self {
            workspaces: std::collections::HashMap::new(),
            next_id: 1,
        }
    }

    fn create(&mut self, name: &str) -> String {
        let id = format!("iws_{}", self.next_id);
        self.next_id += 1;
        self.workspaces.insert(
            id.clone(),
            IdentityWorkspace {
                id: id.clone(),
                name: name.to_string(),
                contexts: Vec::new(),
            },
        );
        id
    }

    fn add_context(
        &mut self,
        workspace_id: &str,
        path: &str,
        role: &str,
        label: Option<String>,
    ) -> Result<String, String> {
        let workspace = self
            .workspaces
            .get_mut(workspace_id)
            .ok_or_else(|| format!("Workspace not found: {workspace_id}"))?;

        let dir = PathBuf::from(path);
        if !dir.exists() {
            return Err(format!("Path not found: {path}"));
        }

        let ctx_id = format!("ictx_{}_{}", workspace.contexts.len() + 1, workspace_id);
        workspace.contexts.push(IdentityWorkspaceContext {
            id: ctx_id.clone(),
            role: role.to_string(),
            path: path.to_string(),
            label: label.or_else(|| {
                dir.file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            }),
            trust_dir: dir.join("trust"),
            receipt_dir: dir.join("receipts"),
        });

        Ok(ctx_id)
    }

    fn list(&self, workspace_id: &str) -> Result<Vec<Value>, String> {
        let workspace = self
            .workspaces
            .get(workspace_id)
            .ok_or_else(|| format!("Workspace not found: {workspace_id}"))?;
        Ok(workspace
            .contexts
            .iter()
            .map(|ctx| {
                json!({
                    "context_id": ctx.id,
                    "role": ctx.role,
                    "path": ctx.path,
                    "label": ctx.label,
                    "has_trust_store": ctx.trust_dir.exists(),
                    "has_receipt_store": ctx.receipt_dir.exists(),
                })
            })
            .collect())
    }

    fn query_all(
        &self,
        workspace_id: &str,
        query: &str,
        max_per_context: usize,
    ) -> Result<Vec<Value>, String> {
        let workspace = self
            .workspaces
            .get(workspace_id)
            .ok_or_else(|| format!("Workspace not found: {workspace_id}"))?;

        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();
        let mut results = Vec::new();

        for ctx in &workspace.contexts {
            let mut matches: Vec<Value> = Vec::new();

            // Search trust grants
            if let Ok(ts) = TrustStore::new(&ctx.trust_dir) {
                let mut grant_ids = Vec::new();
                if let Ok(ids) = ts.list_granted() {
                    grant_ids.extend(ids);
                }
                if let Ok(ids) = ts.list_received() {
                    grant_ids.extend(ids);
                }
                for gid in grant_ids.iter().take(max_per_context * 2) {
                    if let Ok(grant) = ts.load_grant(gid) {
                        let cap_str: String = grant
                            .capabilities
                            .iter()
                            .map(|c| c.uri.to_lowercase())
                            .collect::<Vec<_>>()
                            .join(" ");
                        let overlap = query_words.iter().filter(|w| cap_str.contains(**w)).count();
                        if overlap > 0 {
                            matches.push(json!({
                                "type": "trust_grant",
                                "id": grant.id.0,
                                "capabilities": grant.capabilities.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                                "score": overlap as f32 / query_words.len().max(1) as f32,
                            }));
                        }
                    }
                }
            }

            // Search receipts
            if let Ok(rs) = ReceiptStore::new(&ctx.receipt_dir) {
                if let Ok(receipt_ids) = rs.list() {
                    for rid in receipt_ids.iter().take(max_per_context * 2) {
                        if let Ok(receipt) = rs.load(rid) {
                            let action_lower = receipt.action.description.to_lowercase();
                            let overlap = query_words
                                .iter()
                                .filter(|w| action_lower.contains(**w))
                                .count();
                            if overlap > 0 {
                                matches.push(json!({
                                    "type": "receipt",
                                    "id": receipt.id.0,
                                    "action": receipt.action.description,
                                    "score": overlap as f32 / query_words.len().max(1) as f32,
                                }));
                            }
                        }
                    }
                }
            }

            matches.truncate(max_per_context);
            results.push(json!({
                "context_id": ctx.id,
                "context_role": ctx.role,
                "label": ctx.label,
                "match_count": matches.len(),
                "matches": matches,
            }));
        }

        Ok(results)
    }

    fn compare(
        &self,
        workspace_id: &str,
        item: &str,
        max_per_context: usize,
    ) -> Result<Value, String> {
        let results = self.query_all(workspace_id, item, max_per_context)?;
        let workspace = self.workspaces.get(workspace_id).unwrap();

        let mut found_in = Vec::new();
        let mut missing_from = Vec::new();

        for (i, r) in results.iter().enumerate() {
            let label = workspace.contexts[i]
                .label
                .clone()
                .unwrap_or_else(|| r["context_id"].as_str().unwrap_or("unknown").to_string());
            let count = r["match_count"].as_u64().unwrap_or(0);
            if count > 0 {
                found_in.push(label);
            } else {
                missing_from.push(label);
            }
        }

        Ok(json!({
            "item": item,
            "found_in": found_in,
            "missing_from": missing_from,
            "details": results,
        }))
    }

    fn cross_reference(&self, workspace_id: &str, item: &str) -> Result<Value, String> {
        let cmp = self.compare(workspace_id, item, 5)?;
        Ok(json!({
            "item": item,
            "present_in": cmp["found_in"],
            "absent_from": cmp["missing_from"],
            "coverage": format!("{}/{}", cmp["found_in"].as_array().map(|a| a.len()).unwrap_or(0),
                cmp["found_in"].as_array().map(|a| a.len()).unwrap_or(0) + cmp["missing_from"].as_array().map(|a| a.len()).unwrap_or(0))
        }))
    }
}

// ── Duration parsing ──────────────────────────────────────────────────────────

/// Parse a duration string like "24h", "7d", "30d", "1h30m".
/// Returns duration as microseconds.
fn parse_duration_to_micros(s: &str) -> Result<u64, String> {
    let s = s.trim();

    // Bare integer treated as hours.
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n * 3600 * 1_000_000);
    }

    let mut total_micros: u64 = 0;
    let mut current = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else {
            let val: u64 = current
                .parse()
                .map_err(|_| format!("invalid number in duration: {s}"))?;
            current.clear();
            match ch {
                'h' => total_micros += val * 3600 * 1_000_000,
                'd' => total_micros += val * 86400 * 1_000_000,
                'm' => total_micros += val * 60 * 1_000_000,
                's' => total_micros += val * 1_000_000,
                _ => return Err(format!("unknown duration unit '{ch}' in '{s}'")),
            }
        }
    }

    if !current.is_empty() {
        return Err(format!("duration '{s}' is missing a unit (h/d/m/s)"));
    }

    if total_micros == 0 {
        return Err("duration must be > 0".to_string());
    }

    Ok(total_micros)
}

// ── main ──────────────────────────────────────────────────────────────────────

fn run_stdio_server() {
    // Log to stderr (stdout is reserved for JSON-RPC responses).
    // Use a minimal subscriber without the env-filter feature (not enabled in workspace).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();

    let mut server = McpServer::new();
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                // Emit a parse error response with null id.
                let err = rpc_error(Value::Null, -32700, format!("parse error: {e}"));
                let mut out = stdout.lock();
                let _ = serde_json::to_writer(&mut out, &err);
                let _ = out.write_all(b"\n");
                let _ = out.flush();
                continue;
            }
        };

        let response = server.handle_request(request);

        // Notifications return Value::Null — don't write a response.
        if response.is_null() {
            continue;
        }

        let mut out = stdout.lock();
        if let Err(e) = serde_json::to_writer(&mut out, &response) {
            eprintln!("failed to write response: {e}");
            break;
        }
        if let Err(e) = out.write_all(b"\n") {
            eprintln!("failed to write newline: {e}");
            break;
        }
        if let Err(e) = out.flush() {
            eprintln!("failed to flush stdout: {e}");
            break;
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => run_stdio_server(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Once;

    static TRACING_INIT: Once = Once::new();

    fn init() {
        TRACING_INIT.call_once(|| {
            // suppress tracing output in tests
        });
    }

    /// Create a temporary McpServer wired to temp directories.
    fn test_server() -> (McpServer, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let server = McpServer {
            identity_dir: tmp.path().join("identity"),
            receipt_dir: tmp.path().join("receipts"),
            trust_dir: tmp.path().join("trust"),
            spawn_dir: tmp.path().join("spawn"),
            operation_log: Vec::new(),
            session_start_time: None,
            workspace_manager: IdentityWorkspaceManager::new(),
        };
        (server, tmp)
    }

    // ── JSON-RPC helpers ──────────────────────────────────────────────────────

    fn is_ok(resp: &Value) -> bool {
        resp.get("result").is_some() && resp.get("error").is_none()
    }

    fn is_tool_error(resp: &Value) -> bool {
        resp.get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    }

    fn tool_text(resp: &Value) -> String {
        resp.get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string()
    }

    // ── initialize ────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        let result = resp.get("result").unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
        assert_eq!(result["serverInfo"]["name"], "agentic-identity-mcp");
    }

    // ── ping ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_ping() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}});
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
    }

    // ── tools/list ────────────────────────────────────────────────────────────

    #[test]
    fn test_tools_list() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}});
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"identity_create"));
        assert!(names.contains(&"identity_show"));
        assert!(names.contains(&"action_sign"));
        assert!(names.contains(&"receipt_verify"));
        assert!(names.contains(&"trust_grant"));
        assert!(names.contains(&"trust_revoke"));
        assert!(names.contains(&"trust_verify"));
        assert!(names.contains(&"trust_list"));
        assert!(names.contains(&"receipt_list"));
        assert!(names.contains(&"identity_health"));
        // Continuity tools
        assert!(names.contains(&"continuity_record"));
        assert!(names.contains(&"continuity_anchor"));
        assert!(names.contains(&"continuity_heartbeat"));
        assert!(names.contains(&"continuity_status"));
        assert!(names.contains(&"continuity_gaps"));
        // Spawn tools
        assert!(names.contains(&"spawn_create"));
        assert!(names.contains(&"spawn_terminate"));
        assert!(names.contains(&"spawn_list"));
        assert!(names.contains(&"spawn_lineage"));
        assert!(names.contains(&"spawn_authority"));
        // Competence tools
        assert!(names.contains(&"competence_record"));
        assert!(names.contains(&"competence_show"));
        assert!(names.contains(&"competence_prove"));
        assert!(names.contains(&"competence_verify"));
        assert!(names.contains(&"competence_list"));
        // Negative tools
        assert!(names.contains(&"negative_prove"));
        assert!(names.contains(&"negative_verify"));
        assert!(names.contains(&"negative_declare"));
        assert!(names.contains(&"negative_list"));
        assert!(names.contains(&"negative_check"));
        assert!(names.contains(&"action_context"));
        // V2: Grounding tools
        assert!(names.contains(&"identity_ground"));
        assert!(names.contains(&"identity_evidence"));
        assert!(names.contains(&"identity_suggest"));
        // V2: Workspace tools
        assert!(names.contains(&"identity_workspace_create"));
        assert!(names.contains(&"identity_workspace_add"));
        assert!(names.contains(&"identity_workspace_list"));
        assert!(names.contains(&"identity_workspace_query"));
        assert!(names.contains(&"identity_workspace_compare"));
        assert!(names.contains(&"identity_workspace_xref"));
        // 30 original + 1 action_context + 3 grounding + 6 workspace = 40
        assert_eq!(tools.len(), 40);
    }

    // ── resources/list ────────────────────────────────────────────────────────

    #[test]
    fn test_resources_list() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}});
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        let resources = resp["result"]["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
        let uris: Vec<&str> = resources.iter().filter_map(|r| r["uri"].as_str()).collect();
        assert!(uris.contains(&"aid://identity/default"));
        assert!(uris.contains(&"aid://receipts/recent"));
    }

    // ── identity_create ───────────────────────────────────────────────────────

    #[test]
    fn test_identity_create_default() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        });
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("Created identity"));
        assert!(text.contains("aid_"));
    }

    #[test]
    fn test_identity_create_named() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"test-agent"}}
        });
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("test-agent"));
    }

    #[test]
    fn test_identity_create_duplicate_fails() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":7,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"dup"}}
        });
        // Create once — should succeed.
        let resp1 = server.handle_request(req.clone());
        assert!(!is_tool_error(&resp1));

        // Create again — should fail.
        let req2 = json!({
            "jsonrpc":"2.0","id":8,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"dup"}}
        });
        let resp2 = server.handle_request(req2);
        assert!(is_tool_error(&resp2));
        let text = tool_text(&resp2);
        assert!(text.contains("already exists"));
    }

    // ── identity_show ─────────────────────────────────────────────────────────

    #[test]
    fn test_identity_show_after_create() {
        init();
        let (mut server, _tmp) = test_server();

        // Create first.
        let create_req = json!({
            "jsonrpc":"2.0","id":9,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"show-test"}}
        });
        let _ = server.handle_request(create_req);

        // Now show.
        let show_req = json!({
            "jsonrpc":"2.0","id":10,
            "method":"tools/call",
            "params":{"name":"identity_show","arguments":{"name":"show-test"}}
        });
        let resp = server.handle_request(show_req);
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("Identity: show-test"));
        assert!(text.contains("aid_"));
        assert!(text.contains("Signature:  valid"));
    }

    #[test]
    fn test_identity_show_not_found() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":11,
            "method":"tools/call",
            "params":{"name":"identity_show","arguments":{"name":"nonexistent"}}
        });
        let resp = server.handle_request(req);
        assert!(is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("not found"));
    }

    // ── action_sign ───────────────────────────────────────────────────────────

    #[test]
    fn test_action_sign() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity first.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":12,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        let req = json!({
            "jsonrpc":"2.0","id":13,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{
                    "action": "Deployed service to production",
                    "action_type": "mutation"
                }
            }
        });
        let resp = server.handle_request(req);
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("Receipt created"));
        assert!(text.contains("arec_"));
        assert!(text.contains("mutation"));
    }

    #[test]
    fn test_action_sign_with_chain() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":14,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        // First receipt.
        let resp1 = server.handle_request(json!({
            "jsonrpc":"2.0","id":15,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"Observed error spike","action_type":"observation"}
            }
        }));
        let text1 = tool_text(&resp1);
        // Extract receipt ID.
        let receipt_id: String = text1
            .lines()
            .find(|l| l.contains("arec_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("arec_")))
            .unwrap_or("arec_unknown")
            .to_string();

        // Second receipt chained to first.
        let resp2 = server.handle_request(json!({
            "jsonrpc":"2.0","id":16,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{
                    "action":"Decided to rollback",
                    "action_type":"decision",
                    "chain_to": receipt_id
                }
            }
        }));
        assert!(!is_tool_error(&resp2));
        let text2 = tool_text(&resp2);
        assert!(text2.contains("Chained to:"));
    }

    #[test]
    fn test_action_sign_no_action_fails() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":17,
            "method":"tools/call",
            "params":{"name":"action_sign","arguments":{}}
        });
        let resp = server.handle_request(req);
        assert!(is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("action"));
    }

    // ── receipt_verify ────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_verify_valid() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity and sign action.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":18,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        let sign_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":19,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"Test action","action_type":"decision"}
            }
        }));

        let sign_text = tool_text(&sign_resp);
        let receipt_id: String = sign_text
            .lines()
            .find(|l| l.contains("arec_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("arec_")))
            .unwrap_or("arec_unknown")
            .to_string();

        // Verify the receipt.
        let verify_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{
                "name":"receipt_verify",
                "arguments":{"receipt_id": receipt_id}
            }
        }));
        assert!(!is_tool_error(&verify_resp));
        let text = tool_text(&verify_resp);
        assert!(text.contains("VALID"));
    }

    #[test]
    fn test_receipt_verify_not_found() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":21,
            "method":"tools/call",
            "params":{
                "name":"receipt_verify",
                "arguments":{"receipt_id":"arec_doesnotexist"}
            }
        });
        let resp = server.handle_request(req);
        assert!(is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("not found"));
    }

    // ── trust_grant / trust_verify / trust_revoke ─────────────────────────────

    #[test]
    fn test_trust_grant_and_verify() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":22,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        // Grant trust.
        let grant_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":23,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee":"aid_testgrantee",
                    "capabilities":["read:calendar","write:notes"]
                }
            }
        }));
        assert!(!is_tool_error(&grant_resp));
        let grant_text = tool_text(&grant_resp);
        assert!(grant_text.contains("Trust grant created"));
        assert!(grant_text.contains("atrust_"));

        // Extract trust ID.
        let trust_id: String = grant_text
            .lines()
            .find(|l| l.contains("atrust_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("atrust_")))
            .unwrap_or("atrust_unknown")
            .to_string();

        // Verify the grant.
        let verify_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":24,
            "method":"tools/call",
            "params":{
                "name":"trust_verify",
                "arguments":{
                    "trust_id": trust_id,
                    "capability":"read:calendar"
                }
            }
        }));
        assert!(!is_tool_error(&verify_resp));
        let verify_text = tool_text(&verify_resp);
        assert!(verify_text.contains("VALID"));
    }

    #[test]
    fn test_trust_revoke() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":25,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        // Grant trust.
        let grant_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":26,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee":"aid_toberevoked",
                    "capabilities":["execute:deploy"]
                }
            }
        }));
        let grant_text = tool_text(&grant_resp);
        let trust_id: String = grant_text
            .lines()
            .find(|l| l.contains("atrust_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("atrust_")))
            .unwrap_or("atrust_unknown")
            .to_string();

        // Revoke it.
        let revoke_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":27,
            "method":"tools/call",
            "params":{
                "name":"trust_revoke",
                "arguments":{"trust_id": trust_id}
            }
        }));
        assert!(!is_tool_error(&revoke_resp));
        let revoke_text = tool_text(&revoke_resp);
        assert!(revoke_text.contains("Trust grant revoked"));

        // Verify should now be INVALID (revoked).
        let verify_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":28,
            "method":"tools/call",
            "params":{
                "name":"trust_verify",
                "arguments":{"trust_id": trust_id}
            }
        }));
        let verify_text = tool_text(&verify_resp);
        assert!(verify_text.contains("INVALID") || verify_text.contains("REVOKED"));
    }

    // ── trust_list ────────────────────────────────────────────────────────────

    #[test]
    fn test_trust_list() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":29,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        // Grant trust to two different grantees.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":30,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{"grantee":"aid_alice","capabilities":["read:*"]}
            }
        }));
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":31,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{"grantee":"aid_bob","capabilities":["write:notes"]}
            }
        }));

        // List granted.
        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":32,
            "method":"tools/call",
            "params":{
                "name":"trust_list",
                "arguments":{"direction":"granted"}
            }
        }));
        assert!(!is_tool_error(&list_resp));
        let text = tool_text(&list_resp);
        assert!(text.contains("Granted (2)"));
    }

    // ── receipt_list ──────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_list() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":33,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        // Sign three actions.
        for i in 0..3 {
            let _ = server.handle_request(json!({
                "jsonrpc":"2.0","id": 34 + i,
                "method":"tools/call",
                "params":{
                    "name":"action_sign",
                    "arguments":{
                        "action": format!("Action {i}"),
                        "action_type":"decision"
                    }
                }
            }));
        }

        // List receipts.
        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":37,
            "method":"tools/call",
            "params":{"name":"receipt_list","arguments":{}}
        }));
        assert!(!is_tool_error(&list_resp));
        let text = tool_text(&list_resp);
        assert!(text.contains("3 total"));
    }

    // ── identity_health ───────────────────────────────────────────────────────

    #[test]
    fn test_identity_health_before_setup() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({
            "jsonrpc":"2.0","id":38,
            "method":"tools/call",
            "params":{"name":"identity_health","arguments":{}}
        });
        let resp = server.handle_request(req);
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("NEEDS SETUP") || text.contains("HEALTHY"));
    }

    #[test]
    fn test_identity_health_after_setup() {
        init();
        let (mut server, _tmp) = test_server();

        // Create default identity.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":39,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        let req = json!({
            "jsonrpc":"2.0","id":40,
            "method":"tools/call",
            "params":{"name":"identity_health","arguments":{}}
        });
        let resp = server.handle_request(req);
        assert!(!is_tool_error(&resp));
        let text = tool_text(&resp);
        assert!(text.contains("HEALTHY"));
    }

    // ── unknown method ────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_method() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":41,"method":"no_such_method","params":{}});
        let resp = server.handle_request(req);
        assert!(resp.get("error").is_some());
        assert_eq!(resp["error"]["code"], -32601);
    }

    // ── notification (no response) ────────────────────────────────────────────

    #[test]
    fn test_initialized_notification_returns_null() {
        init();
        let (mut server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","method":"initialized","params":{}});
        let resp = server.handle_request(req);
        assert!(resp.is_null());
    }

    // ── resources/read ────────────────────────────────────────────────────────

    #[test]
    fn test_resource_identity_read() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity first.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":42,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        let req = json!({
            "jsonrpc":"2.0","id":43,
            "method":"resources/read",
            "params":{"uri":"aid://identity/default"}
        });
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        let contents = resp["result"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], "aid://identity/default");
    }

    #[test]
    fn test_resource_receipts_recent() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity and a receipt.
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":44,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));
        let _ = server.handle_request(json!({
            "jsonrpc":"2.0","id":45,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"test for resource","action_type":"observation"}
            }
        }));

        let req = json!({
            "jsonrpc":"2.0","id":46,
            "method":"resources/read",
            "params":{"uri":"aid://receipts/recent"}
        });
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
        let text = resp["result"]["contents"][0]["text"]
            .as_str()
            .unwrap_or("[]");
        // Should be a JSON array containing at least one receipt.
        let arr: Value = serde_json::from_str(text).unwrap_or(json!([]));
        assert!(arr.as_array().map(|a| !a.is_empty()).unwrap_or(false));
    }

    // ── duration parser ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(
            parse_duration_to_micros("24h").unwrap(),
            24 * 3600 * 1_000_000
        );
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(
            parse_duration_to_micros("7d").unwrap(),
            7 * 86400 * 1_000_000
        );
    }

    #[test]
    fn test_parse_duration_mixed() {
        let expected = 3600 * 1_000_000 + 30 * 60 * 1_000_000;
        assert_eq!(parse_duration_to_micros("1h30m").unwrap(), expected);
    }

    #[test]
    fn test_parse_duration_bare_number() {
        // Bare number treated as hours.
        assert_eq!(parse_duration_to_micros("2").unwrap(), 2 * 3600 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration_to_micros("invalid").is_err());
        assert!(parse_duration_to_micros("5x").is_err());
    }

    // ── datetime formatter ────────────────────────────────────────────────────

    #[test]
    fn test_epoch_to_datetime_known() {
        // Unix epoch 0 → 1970-01-01 00:00:00 UTC
        assert_eq!(epoch_to_datetime(0), "1970-01-01 00:00:00 UTC");
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(epoch_to_datetime(1704067200), "2024-01-01 00:00:00 UTC");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Phase 0 Stress Tests: Context Capture
    // ════════════════════════════════════════════════════════════════════════

    // ── action_context tool ──────────────────────────────────────────────

    #[test]
    fn test_action_context_basic() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":100,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": "Establishing trust with new collaborator",
                    "decision": "Grant read-only access",
                    "significance": "important",
                    "topic": "trust-management"
                }
            }
        }));
        assert!(
            !is_tool_error(&resp),
            "action_context should succeed: {resp}"
        );
        let text = tool_text(&resp);
        assert!(text.contains("logged") || text.contains("log_index"));
    }

    #[test]
    fn test_action_context_intent_only() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":101,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": "Reviewing identity health status"
                }
            }
        }));
        assert!(!is_tool_error(&resp));
    }

    #[test]
    fn test_action_context_empty_intent_fails() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":102,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": ""
                }
            }
        }));
        // Should be an error
        assert!(
            resp.get("error").is_some() || is_tool_error(&resp),
            "Empty intent should be rejected: {resp}"
        );
    }

    #[test]
    fn test_action_context_missing_intent_fails() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":103,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "decision": "Some decision without intent"
                }
            }
        }));
        assert!(
            resp.get("error").is_some() || is_tool_error(&resp),
            "Missing intent should be rejected: {resp}"
        );
    }

    #[test]
    fn test_action_context_all_significance_levels() {
        init();
        for level in &["routine", "important", "critical"] {
            let (mut server, _tmp) = test_server();
            let resp = server.handle_request(json!({
                "jsonrpc":"2.0","id":104,
                "method":"tools/call",
                "params":{
                    "name":"action_context",
                    "arguments":{
                        "intent": format!("Test {level} significance"),
                        "significance": level
                    }
                }
            }));
            assert!(!is_tool_error(&resp), "significance={level} should succeed");
        }
    }

    // ── operation log auto-capture ───────────────────────────────────────

    #[test]
    fn test_operation_log_captures_tool_calls() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity and sign an action
        server.handle_request(json!({
            "jsonrpc":"2.0","id":110,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":111,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"Test action","action_type":"observation"}
            }
        }));

        // Operation log should have entries
        assert!(
            server.operation_log.len() >= 2,
            "Should have at least 2 operation log entries, got {}",
            server.operation_log.len()
        );
        assert!(server
            .operation_log
            .iter()
            .any(|r| r.tool_name == "identity_create"));
        assert!(server
            .operation_log
            .iter()
            .any(|r| r.tool_name == "action_sign"));
    }

    #[test]
    fn test_action_context_stores_in_operation_log() {
        init();
        let (mut server, _tmp) = test_server();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":112,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{"intent":"Test intent"}
            }
        }));

        // action_context stores its own record — verify it exists
        assert!(
            server
                .operation_log
                .iter()
                .any(|r| r.tool_name == "action_context"),
            "action_context should store its own log entry"
        );
        // But it should only appear once (not double-logged by auto-capture)
        let count = server
            .operation_log
            .iter()
            .filter(|r| r.tool_name == "action_context")
            .count();
        assert_eq!(count, 1, "action_context should appear exactly once");
    }

    #[test]
    fn test_session_tracking_on_initialize() {
        init();
        let (mut server, _tmp) = test_server();

        assert!(server.session_start_time.is_none());

        server.handle_request(json!({
            "jsonrpc":"2.0","id":113,
            "method":"initialize",
            "params":{
                "protocolVersion":"2024-11-05",
                "capabilities":{},
                "clientInfo":{"name":"stress-test","version":"1.0"}
            }
        }));

        assert!(
            server.session_start_time.is_some(),
            "Should set session_start_time on initialize"
        );
    }

    // ── scale tests ─────────────────────────────────────────────────────

    #[test]
    fn test_scale_100_action_contexts() {
        init();
        let (mut server, _tmp) = test_server();

        let start = std::time::Instant::now();
        for i in 0..100 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 200 + i,
                "method":"tools/call",
                "params":{
                    "name":"action_context",
                    "arguments":{
                        "intent": format!("Scale test intent {i}"),
                        "decision": format!("Decision {i}"),
                        "significance": if i % 3 == 0 { "routine" } else if i % 3 == 1 { "important" } else { "critical" },
                        "topic": format!("topic-{}", i % 10)
                    }
                }
            }));
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 10,
            "100 action_context calls took {:?} — too slow",
            elapsed
        );
    }

    #[test]
    fn test_scale_10_identity_operations() {
        init();
        let (mut server, _tmp) = test_server();

        // Create identity once
        server.handle_request(json!({
            "jsonrpc":"2.0","id":300,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        let start = std::time::Instant::now();
        for i in 0..10 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 301 + i,
                "method":"tools/call",
                "params":{
                    "name":"action_sign",
                    "arguments":{
                        "action": format!("Scale action {i}"),
                        "action_type":"observation"
                    }
                }
            }));
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 60,
            "10 action_sign calls took {:?} — too slow",
            elapsed
        );

        // Operation log should have 11 entries (1 create + 10 signs)
        assert!(
            server.operation_log.len() >= 11,
            "Expected at least 11 log entries, got {}",
            server.operation_log.len()
        );
    }

    // ── edge cases ──────────────────────────────────────────────────────

    #[test]
    fn test_action_context_unicode() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":400,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": "建立与新合作者的信任",
                    "decision": "付与読み取り専用アクセス",
                    "topic": "국제화-테스트"
                }
            }
        }));
        assert!(!is_tool_error(&resp));
    }

    #[test]
    fn test_action_context_special_chars() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":401,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": "Check \"quotes\" and 'apostrophes' & <angle> brackets",
                    "decision": "Found: \\ backslash, \t tab"
                }
            }
        }));
        assert!(!is_tool_error(&resp));
    }

    #[test]
    fn test_action_context_long_intent() {
        init();
        let (mut server, _tmp) = test_server();

        let long_intent = "Y".repeat(10_000);
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":402,
            "method":"tools/call",
            "params":{
                "name":"action_context",
                "arguments":{
                    "intent": long_intent
                }
            }
        }));
        assert!(!is_tool_error(&resp));
    }

    // ── regression ──────────────────────────────────────────────────────

    #[test]
    fn test_tools_list_includes_action_context() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":500,
            "method":"tools/list",
            "params":{}
        }));

        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(
            names.contains(&"action_context"),
            "Tool list must include action_context, found: {:?}",
            names
        );
    }

    #[test]
    fn test_operation_log_timestamps_nonzero() {
        init();
        let (mut server, _tmp) = test_server();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":501,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{}}
        }));

        assert!(!server.operation_log.is_empty());
        assert!(
            server.operation_log[0].timestamp > 0,
            "Timestamp should be non-zero"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // V2 Stress Tests: Grounding, Workspaces, Integration
    // ════════════════════════════════════════════════════════════════════════

    /// Helper: extract identity ID (aid_...) from identity_create response text.
    fn extract_identity_id(text: &str) -> String {
        text.lines()
            .find(|l| l.contains("aid_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("aid_")))
            .unwrap_or("aid_unknown")
            .to_string()
    }

    /// Helper: extract trust ID (atrust_...) from trust_grant response text.
    #[allow(dead_code)]
    fn extract_trust_id(text: &str) -> String {
        text.lines()
            .find(|l| l.contains("atrust_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("atrust_")))
            .unwrap_or("atrust_unknown")
            .to_string()
    }

    /// Helper: extract receipt ID (arec_...) from action_sign response text.
    #[allow(dead_code)]
    fn extract_receipt_id(text: &str) -> String {
        text.lines()
            .find(|l| l.contains("arec_"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("arec_")))
            .unwrap_or("arec_unknown")
            .to_string()
    }

    /// Helper: parse the text content of a tool response as JSON.
    fn tool_json(resp: &Value) -> Value {
        let text = tool_text(resp);
        serde_json::from_str(&text).unwrap_or(json!({}))
    }

    /// Helper: create identity and return server + identity ID.
    fn setup_identity() -> (McpServer, tempfile::TempDir, String) {
        let (mut server, tmp) = test_server();
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"default"}}
        }));
        let id = extract_identity_id(&tool_text(&resp));
        (server, tmp, id)
    }

    /// Helper: set up a workspace context directory with trust and receipt subdirectories.
    fn setup_context_dir(base: &std::path::Path, name: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(dir.join("trust/granted")).unwrap();
        std::fs::create_dir_all(dir.join("trust/received")).unwrap();
        std::fs::create_dir_all(dir.join("trust/revocations")).unwrap();
        std::fs::create_dir_all(dir.join("receipts")).unwrap();
        dir
    }

    // ── Grounding tests ──────────────────────────────────────────────────

    #[test]
    fn test_v2_grounding_verified_trust_grant() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Issue a trust grant with a specific capability.
        let grant_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:files", "write:files"]
                }
            }
        }));
        assert!(!is_tool_error(&grant_resp), "trust_grant should succeed");

        // Ground a claim about that capability.
        let ground_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"agent can read files"}
            }
        }));
        assert!(is_ok(&ground_resp));
        assert!(!is_tool_error(&ground_resp));
        let j = tool_json(&ground_resp);
        assert_eq!(
            j["status"], "verified",
            "Claim matching trust grant should be verified"
        );
        assert!(j["evidence"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn test_v2_grounding_verified_receipt() {
        init();
        let (mut server, _tmp, _identity_id) = setup_identity();

        // Sign an action to create a receipt.
        let sign_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{
                    "action":"Deployed service to production",
                    "action_type":"mutation"
                }
            }
        }));
        assert!(!is_tool_error(&sign_resp));

        // Ground a claim about that action.
        let ground_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"deployed service production"}
            }
        }));
        assert!(is_ok(&ground_resp));
        let j = tool_json(&ground_resp);
        assert_eq!(
            j["status"], "verified",
            "Claim matching receipt action should be verified"
        );
        assert!(j["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "receipt"));
    }

    #[test]
    fn test_v2_grounding_ungrounded_empty() {
        init();
        let (mut server, _tmp) = test_server();

        // No identity, no grants, no receipts — claim should be ungrounded.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"agent has admin privileges"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert_eq!(j["status"], "ungrounded");
    }

    #[test]
    fn test_v2_grounding_ungrounded_wrong_capability() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant read capability only.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:calendar"]
                }
            }
        }));

        // Claim about write — should be ungrounded.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"write deploy execute admin"}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        assert_eq!(
            j["status"], "ungrounded",
            "Claim about unrelated capability should be ungrounded"
        );
    }

    #[test]
    fn test_v2_grounding_empty_claim() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":""}
            }
        }));
        assert!(is_tool_error(&resp), "Empty claim should be rejected");
    }

    #[test]
    fn test_v2_grounding_long_claim() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant a capability.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:files"]
                }
            }
        }));

        // Very long claim — should not panic or hang.
        let long_claim = format!(
            "agent can read files {}",
            "and perform many operations ".repeat(50)
        );
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim": long_claim}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        // Should either be verified (contains "read" and "files") or ungrounded — no crash.
        let j = tool_json(&resp);
        assert!(j["status"] == "verified" || j["status"] == "ungrounded");
    }

    #[test]
    fn test_v2_grounding_case_insensitive() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant with mixed case.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["Read:Calendar"]
                }
            }
        }));

        // Claim with different case.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"READ CALENDAR access"}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        assert_eq!(
            j["status"], "verified",
            "Grounding should be case-insensitive"
        );
    }

    #[test]
    fn test_v2_grounding_multiple_evidence() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Multiple grants.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["deploy:production"]
                }
            }
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee":"aid_other",
                    "capabilities": ["deploy:staging"]
                }
            }
        }));

        // Sign a receipt about deployment.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{
                    "action":"Executed deploy to staging",
                    "action_type":"mutation"
                }
            }
        }));

        // Ground claim about deploy — should find multiple evidence items.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"deploy production staging"}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        assert_eq!(j["status"], "verified");
        let evidence_count = j["evidence_count"].as_u64().unwrap_or(0);
        assert!(
            evidence_count >= 2,
            "Should have multiple pieces of evidence, got {evidence_count}"
        );
    }

    #[test]
    fn test_v2_evidence_basic() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant trust.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["write:notes"]
                }
            }
        }));

        // Query evidence.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_evidence",
                "arguments":{"query":"write notes"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert_eq!(j["query"], "write notes");
        assert!(
            j["count"].as_u64().unwrap_or(0) >= 1,
            "Should find at least one evidence item"
        );
        assert!(j["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "trust_grant"));
    }

    #[test]
    fn test_v2_evidence_max_results() {
        init();
        let (mut server, _tmp, _identity_id) = setup_identity();

        // Create multiple grants that all match "deploy".
        for i in 0..5 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i,
                "method":"tools/call",
                "params":{
                    "name":"trust_grant",
                    "arguments":{
                        "grantee": format!("aid_agent_{i}"),
                        "capabilities": [format!("deploy:env_{i}")]
                    }
                }
            }));
        }

        // Evidence with max_results=2.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{
                "name":"identity_evidence",
                "arguments":{"query":"deploy", "max_results": 2}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        assert!(
            j["count"].as_u64().unwrap_or(0) <= 2,
            "max_results=2 should limit output"
        );
    }

    #[test]
    fn test_v2_suggest_basic() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Create a trust grant to suggest from.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:calendar", "write:notes"]
                }
            }
        }));

        // Suggest based on partial match.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"identity_suggest",
                "arguments":{"query":"read"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert_eq!(j["query"], "read");
        assert!(
            j["count"].as_u64().unwrap_or(0) >= 1,
            "Should suggest at least one capability"
        );
    }

    #[test]
    fn test_v2_suggest_limit() {
        init();
        let (mut server, _tmp, _identity_id) = setup_identity();

        // Create multiple grants.
        for i in 0..5 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i,
                "method":"tools/call",
                "params":{
                    "name":"trust_grant",
                    "arguments":{
                        "grantee": format!("aid_agent_{i}"),
                        "capabilities": [format!("deploy:{i}")]
                    }
                }
            }));
        }

        // Suggest with limit=2.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{
                "name":"identity_suggest",
                "arguments":{"query":"deploy", "limit": 2}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        assert!(
            j["count"].as_u64().unwrap_or(0) <= 2,
            "limit=2 should cap suggestions"
        );
    }

    // ── Workspace tests ──────────────────────────────────────────────────

    #[test]
    fn test_v2_workspace_create() {
        init();
        let (mut server, _tmp) = test_server();

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_create",
                "arguments":{"name":"test-workspace"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert!(j["workspace_id"].as_str().unwrap().starts_with("iws_"));
        assert_eq!(j["status"], "created");
        assert_eq!(j["name"], "test-workspace");
    }

    #[test]
    fn test_v2_workspace_create_multiple() {
        init();
        let (mut server, _tmp) = test_server();

        let mut ws_ids = Vec::new();
        for i in 0..3 {
            let resp = server.handle_request(json!({
                "jsonrpc":"2.0","id": 1 + i,
                "method":"tools/call",
                "params":{
                    "name":"identity_workspace_create",
                    "arguments":{"name": format!("ws-{i}")}
                }
            }));
            assert!(!is_tool_error(&resp));
            let j = tool_json(&resp);
            ws_ids.push(j["workspace_id"].as_str().unwrap().to_string());
        }

        // All IDs should be distinct.
        ws_ids.sort();
        ws_ids.dedup();
        assert_eq!(ws_ids.len(), 3, "All workspace IDs should be unique");
    }

    #[test]
    fn test_v2_workspace_add() {
        init();
        let (mut server, _tmp) = test_server();
        let ctx_tmp = tempfile::tempdir().unwrap();
        let dir_a = setup_context_dir(ctx_tmp.path(), "agent-a");

        // Create workspace.
        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_create",
                "arguments":{"name":"ws-add"}
            }
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Add context.
        let add_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": dir_a.to_str().unwrap()
                }
            }
        }));
        assert!(is_ok(&add_resp));
        assert!(!is_tool_error(&add_resp));
        let j = tool_json(&add_resp);
        assert!(j["context_id"].as_str().unwrap().starts_with("ictx_"));
        assert_eq!(j["status"], "added");
    }

    #[test]
    fn test_v2_workspace_add_multiple() {
        init();
        let (mut server, _tmp) = test_server();
        let ctx_tmp = tempfile::tempdir().unwrap();
        let dir_a = setup_context_dir(ctx_tmp.path(), "agent-a");
        let dir_b = setup_context_dir(ctx_tmp.path(), "agent-b");
        let dir_c = setup_context_dir(ctx_tmp.path(), "agent-c");

        // Create workspace.
        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_create",
                "arguments":{"name":"ws-multi"}
            }
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Add 3 contexts with different roles.
        for (i, (dir, role)) in [
            (dir_a, "primary"),
            (dir_b, "secondary"),
            (dir_c, "reference"),
        ]
        .iter()
        .enumerate()
        {
            let resp = server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i as i64,
                "method":"tools/call",
                "params":{
                    "name":"identity_workspace_add",
                    "arguments":{
                        "workspace_id": ws_id,
                        "path": dir.to_str().unwrap(),
                        "role": role,
                        "label": format!("Agent-{}", (b'A' + i as u8) as char)
                    }
                }
            }));
            assert!(!is_tool_error(&resp), "Adding context {i} should succeed");
        }

        // List to confirm all 3 are added.
        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_list",
                "arguments":{"workspace_id": ws_id}
            }
        }));
        let j = tool_json(&list_resp);
        assert_eq!(j["count"].as_u64().unwrap(), 3);
    }

    #[test]
    fn test_v2_workspace_list() {
        init();
        let (mut server, _tmp) = test_server();
        let ctx_tmp = tempfile::tempdir().unwrap();
        let dir_a = setup_context_dir(ctx_tmp.path(), "agent-a");

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-list"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": dir_a.to_str().unwrap(),
                    "role":"primary",
                    "label":"Agent-A"
                }
            }
        }));

        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_workspace_list","arguments":{"workspace_id": ws_id}}
        }));
        assert!(is_ok(&list_resp));
        assert!(!is_tool_error(&list_resp));
        let j = tool_json(&list_resp);
        assert_eq!(j["count"].as_u64().unwrap(), 1);
        let contexts = j["contexts"].as_array().unwrap();
        assert_eq!(contexts[0]["label"], "Agent-A");
        assert_eq!(contexts[0]["role"], "primary");
    }

    #[test]
    fn test_v2_workspace_query_single() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();
        let _ctx_tmp = tempfile::tempdir().unwrap();

        // Set up a context directory that uses the server's trust dir.
        // We need grants in a context directory. Use the server's own directories.
        let ctx_dir = _tmp.path().to_path_buf();

        // We already have an identity. Grant trust (stored in server's trust_dir).
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:files"]
                }
            }
        }));

        // Create workspace and add the server's temp directory as context.
        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-query-single"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": ctx_dir.to_str().unwrap(),
                    "label":"main-agent"
                }
            }
        }));

        // Query for "read files".
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_query",
                "arguments":{
                    "workspace_id": ws_id,
                    "query":"read files"
                }
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert!(
            j["total_matches"].as_u64().unwrap_or(0) >= 1,
            "Should find at least one match"
        );
    }

    #[test]
    fn test_v2_workspace_query_across() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant two capabilities — both stored in the server's trust dir.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["deploy:production"]
                }
            }
        }));

        // Sign an action — stored in server's receipt dir.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"Deployed to production","action_type":"mutation"}
            }
        }));

        // Create workspace and add the server dir as two separate "contexts"
        // (they share the same path, but this tests multi-context query).
        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-across"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Add same dir twice with different labels (simulates two agents sharing store).
        server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": _tmp.path().to_str().unwrap(),
                    "label":"context-1"
                }
            }
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": _tmp.path().to_str().unwrap(),
                    "label":"context-2"
                }
            }
        }));

        // Query across both contexts.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":7,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_query",
                "arguments":{
                    "workspace_id": ws_id,
                    "query":"deploy production"
                }
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        let results = j["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "Should have results for both contexts");
        // Both should find matches since they share the same underlying store.
        assert!(results[0]["match_count"].as_u64().unwrap_or(0) >= 1);
        assert!(results[1]["match_count"].as_u64().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_v2_workspace_compare_found() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant deploy capability.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["deploy:production"]
                }
            }
        }));

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-cmp-found"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Add the same data directory twice (both should find "deploy").
        for i in 0..2 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i,
                "method":"tools/call",
                "params":{
                    "name":"identity_workspace_add",
                    "arguments":{
                        "workspace_id": ws_id,
                        "path": _tmp.path().to_str().unwrap(),
                        "label": format!("ctx-{i}")
                    }
                }
            }));
        }

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_compare",
                "arguments":{
                    "workspace_id": ws_id,
                    "item":"deploy"
                }
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        let found_in = j["found_in"].as_array().unwrap();
        assert_eq!(found_in.len(), 2, "Item should be found in both contexts");
        let missing_from = j["missing_from"].as_array().unwrap();
        assert!(missing_from.is_empty(), "Nothing should be missing");
    }

    #[test]
    fn test_v2_workspace_compare_missing() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant deploy capability in main store.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["deploy:production"]
                }
            }
        }));

        // Create empty context dir (no grants/receipts).
        let ctx_tmp = tempfile::tempdir().unwrap();
        let empty_dir = setup_context_dir(ctx_tmp.path(), "empty-agent");

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-cmp-missing"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Context 1: has deploy grant.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": _tmp.path().to_str().unwrap(),
                    "label":"has-deploy"
                }
            }
        }));

        // Context 2: empty store.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path": empty_dir.to_str().unwrap(),
                    "label":"no-deploy"
                }
            }
        }));

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_compare",
                "arguments":{"workspace_id": ws_id, "item":"deploy"}
            }
        }));
        assert!(is_ok(&resp));
        let j = tool_json(&resp);
        let found_in = j["found_in"].as_array().unwrap();
        let missing_from = j["missing_from"].as_array().unwrap();
        assert_eq!(found_in.len(), 1, "Deploy should only be in one context");
        assert_eq!(
            missing_from.len(),
            1,
            "Deploy should be missing from one context"
        );
        assert!(found_in
            .iter()
            .any(|v| v.as_str().unwrap().contains("has-deploy")));
        assert!(missing_from
            .iter()
            .any(|v| v.as_str().unwrap().contains("no-deploy")));
    }

    #[test]
    fn test_v2_workspace_xref() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:files", "write:logs"]
                }
            }
        }));

        let ctx_tmp = tempfile::tempdir().unwrap();
        let empty_dir = setup_context_dir(ctx_tmp.path(), "empty-agent");

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-xref"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Two contexts: one with data, one empty.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": _tmp.path().to_str().unwrap(), "label":"full"}
            }
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": empty_dir.to_str().unwrap(), "label":"empty"}
            }
        }));

        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_xref",
                "arguments":{"workspace_id": ws_id, "item":"read files"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert!(!j["present_in"].as_array().unwrap().is_empty());
        assert!(!j["absent_from"].as_array().unwrap().is_empty());
        assert!(
            j["coverage"].as_str().unwrap().contains("/"),
            "Coverage should be in N/M format"
        );
    }

    #[test]
    fn test_v2_workspace_empty() {
        init();
        let (mut server, _tmp) = test_server();

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-empty"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Query empty workspace (no contexts added).
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_query",
                "arguments":{"workspace_id": ws_id, "query":"anything"}
            }
        }));
        assert!(is_ok(&resp));
        assert!(!is_tool_error(&resp));
        let j = tool_json(&resp);
        assert_eq!(j["total_matches"].as_u64().unwrap(), 0);
        assert_eq!(j["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_v2_workspace_missing_id() {
        init();
        let (mut server, _tmp) = test_server();

        // List a non-existent workspace.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_list",
                "arguments":{"workspace_id":"iws_nonexistent"}
            }
        }));
        assert!(
            is_tool_error(&resp),
            "Non-existent workspace should return error"
        );
        let text = tool_text(&resp);
        assert!(text.contains("not found") || text.contains("Workspace not found"));
    }

    #[test]
    fn test_v2_workspace_invalid_path() {
        init();
        let (mut server, _tmp) = test_server();

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-bad-path"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Add a path that does not exist.
        let resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{
                    "workspace_id": ws_id,
                    "path":"/tmp/nonexistent_identity_dir_12345"
                }
            }
        }));
        assert!(
            is_tool_error(&resp),
            "Non-existent path should return error"
        );
        let text = tool_text(&resp);
        assert!(text.contains("not found") || text.contains("Path not found"));
    }

    // ── Integration tests ────────────────────────────────────────────────

    #[test]
    fn test_v2_ground_after_grant() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Ground before any grant — should be ungrounded.
        let resp_before = server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"read calendar events"}
            }
        }));
        let j_before = tool_json(&resp_before);
        assert_eq!(j_before["status"], "ungrounded");

        // Now grant the capability.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:calendar"]
                }
            }
        }));

        // Ground after grant — should be verified.
        let resp_after = server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"identity_ground",
                "arguments":{"claim":"read calendar events"}
            }
        }));
        let j_after = tool_json(&resp_after);
        assert_eq!(
            j_after["status"], "verified",
            "After granting, claim should be verified"
        );
    }

    #[test]
    fn test_v2_workspace_permission_comparison() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Grant deploy to default identity.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["deploy:production", "deploy:staging"]
                }
            }
        }));

        // Create a second identity.
        let resp2 = server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{"name":"identity_create","arguments":{"name":"agent-b"}}
        }));
        let id2 = extract_identity_id(&tool_text(&resp2));

        // Grant only staging to agent-b.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": id2,
                    "capabilities": ["deploy:staging"],
                    "identity":"agent-b"
                }
            }
        }));

        // Create separate context dirs pointing to the server's trust stores.
        // Both share the server's trust dir, so both see all grants.
        // Use the server's temp path as one context (has all grants).
        let ctx_tmp = tempfile::tempdir().unwrap();
        let empty_dir = setup_context_dir(ctx_tmp.path(), "agent-limited");

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-perm-compare"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        server.handle_request(json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": _tmp.path().to_str().unwrap(), "label":"full-agent"}
            }
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":7,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": empty_dir.to_str().unwrap(), "label":"limited-agent"}
            }
        }));

        // Compare "deploy" across the two.
        let cmp_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":8,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_compare",
                "arguments":{"workspace_id": ws_id, "item":"deploy"}
            }
        }));
        assert!(is_ok(&cmp_resp));
        let j = tool_json(&cmp_resp);
        // full-agent should be found_in, limited-agent (empty dir) should be missing_from.
        assert!(!j["found_in"].as_array().unwrap().is_empty());
        assert!(!j["missing_from"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_v2_grounding_with_many_grants() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Create 12 grants with distinct capabilities.
        for i in 0..12 {
            server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i,
                "method":"tools/call",
                "params":{
                    "name":"trust_grant",
                    "arguments":{
                        "grantee": if i % 2 == 0 { identity_id.clone() } else { format!("aid_agent_{i}") },
                        "capabilities": [format!("action_{}:{}", ["read","write","deploy","admin","execute","manage"][i % 6], ["files","logs","services","config","keys","db"][i % 6])]
                    }
                }
            }));
        }

        // Ground various claims.
        let claim_results = [
            ("read files", "verified"),
            ("write logs", "verified"),
            ("deploy services", "verified"),
            ("hack the planet", "ungrounded"),
        ];

        for (i, (claim, expected)) in claim_results.iter().enumerate() {
            let resp = server.handle_request(json!({
                "jsonrpc":"2.0","id": 100 + i as i64,
                "method":"tools/call",
                "params":{
                    "name":"identity_ground",
                    "arguments":{"claim": claim}
                }
            }));
            assert!(is_ok(&resp));
            let j = tool_json(&resp);
            assert_eq!(
                j["status"].as_str().unwrap(),
                *expected,
                "Claim '{}' should be {}, got {}",
                claim,
                expected,
                j["status"]
            );
        }
    }

    #[test]
    fn test_v2_workspace_roles_and_labels() {
        init();
        let (mut server, _tmp) = test_server();
        let ctx_tmp = tempfile::tempdir().unwrap();

        let roles = ["primary", "secondary", "reference", "archive"];
        let labels = [
            "Main Agent",
            "Backup Agent",
            "Reference Docs",
            "Archived Agent",
        ];
        let mut dirs = Vec::new();

        for (i, _) in roles.iter().enumerate() {
            dirs.push(setup_context_dir(ctx_tmp.path(), &format!("agent-{i}")));
        }

        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":1,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"ws-roles"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        for (i, (dir, (role, label))) in
            dirs.iter().zip(roles.iter().zip(labels.iter())).enumerate()
        {
            let resp = server.handle_request(json!({
                "jsonrpc":"2.0","id": 10 + i as i64,
                "method":"tools/call",
                "params":{
                    "name":"identity_workspace_add",
                    "arguments":{
                        "workspace_id": ws_id,
                        "path": dir.to_str().unwrap(),
                        "role": role,
                        "label": label
                    }
                }
            }));
            assert!(
                !is_tool_error(&resp),
                "Adding context {i} with role {role} should succeed"
            );
        }

        // List and verify roles + labels.
        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":20,
            "method":"tools/call",
            "params":{"name":"identity_workspace_list","arguments":{"workspace_id": ws_id}}
        }));
        let j = tool_json(&list_resp);
        assert_eq!(j["count"].as_u64().unwrap(), 4);

        let contexts = j["contexts"].as_array().unwrap();
        for (i, ctx) in contexts.iter().enumerate() {
            assert_eq!(
                ctx["role"].as_str().unwrap(),
                roles[i],
                "Role mismatch at index {i}"
            );
            assert_eq!(
                ctx["label"].as_str().unwrap(),
                labels[i],
                "Label mismatch at index {i}"
            );
        }
    }

    #[test]
    fn test_v2_full_workflow() {
        init();
        let (mut server, _tmp, identity_id) = setup_identity();

        // Step 1: Grant capabilities.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":2,
            "method":"tools/call",
            "params":{
                "name":"trust_grant",
                "arguments":{
                    "grantee": identity_id,
                    "capabilities": ["read:files", "write:logs", "deploy:staging"]
                }
            }
        }));

        // Step 2: Sign an action.
        server.handle_request(json!({
            "jsonrpc":"2.0","id":3,
            "method":"tools/call",
            "params":{
                "name":"action_sign",
                "arguments":{"action":"Deployed to staging environment","action_type":"mutation"}
            }
        }));

        // Step 3: Verify grounding.
        let ground_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":4,
            "method":"tools/call",
            "params":{"name":"identity_ground","arguments":{"claim":"deploy staging"}}
        }));
        let gj = tool_json(&ground_resp);
        assert_eq!(gj["status"], "verified");

        // Step 4: Get evidence.
        let evidence_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":5,
            "method":"tools/call",
            "params":{"name":"identity_evidence","arguments":{"query":"deploy staging"}}
        }));
        let ej = tool_json(&evidence_resp);
        assert!(ej["count"].as_u64().unwrap() >= 1);

        // Step 5: Get suggestions.
        let suggest_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":6,
            "method":"tools/call",
            "params":{"name":"identity_suggest","arguments":{"query":"deploy"}}
        }));
        let sj = tool_json(&suggest_resp);
        assert!(sj["count"].as_u64().unwrap() >= 1);

        // Step 6: Create workspace.
        let ws_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":7,
            "method":"tools/call",
            "params":{"name":"identity_workspace_create","arguments":{"name":"full-workflow"}}
        }));
        let ws_id = tool_json(&ws_resp)["workspace_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Step 7: Add contexts (main + empty for comparison).
        let ctx_tmp = tempfile::tempdir().unwrap();
        let empty_dir = setup_context_dir(ctx_tmp.path(), "empty");

        server.handle_request(json!({
            "jsonrpc":"2.0","id":8,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": _tmp.path().to_str().unwrap(), "label":"main", "role":"primary"}
            }
        }));
        server.handle_request(json!({
            "jsonrpc":"2.0","id":9,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_add",
                "arguments":{"workspace_id": ws_id, "path": empty_dir.to_str().unwrap(), "label":"empty", "role":"secondary"}
            }
        }));

        // Step 8: List workspace.
        let list_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":10,
            "method":"tools/call",
            "params":{"name":"identity_workspace_list","arguments":{"workspace_id": ws_id}}
        }));
        let lj = tool_json(&list_resp);
        assert_eq!(lj["count"].as_u64().unwrap(), 2);

        // Step 9: Query workspace.
        let query_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":11,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_query",
                "arguments":{"workspace_id": ws_id, "query":"deploy"}
            }
        }));
        let qj = tool_json(&query_resp);
        assert!(qj["total_matches"].as_u64().unwrap() >= 1);

        // Step 10: Compare.
        let cmp_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":12,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_compare",
                "arguments":{"workspace_id": ws_id, "item":"deploy"}
            }
        }));
        let cj = tool_json(&cmp_resp);
        assert!(!cj["found_in"].as_array().unwrap().is_empty());
        assert!(!cj["missing_from"].as_array().unwrap().is_empty());

        // Step 11: Cross-reference.
        let xref_resp = server.handle_request(json!({
            "jsonrpc":"2.0","id":13,
            "method":"tools/call",
            "params":{
                "name":"identity_workspace_xref",
                "arguments":{"workspace_id": ws_id, "item":"deploy"}
            }
        }));
        let xj = tool_json(&xref_resp);
        assert!(!xj["present_in"].as_array().unwrap().is_empty());
        assert!(!xj["absent_from"].as_array().unwrap().is_empty());
        assert!(xj["coverage"].as_str().unwrap().contains("/"));
    }
}
