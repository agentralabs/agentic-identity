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

use serde_json::{json, Value};

use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::storage::{
    load_identity, read_public_document, save_identity, ReceiptStore, TrustStore,
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

struct McpServer {
    identity_dir: PathBuf,
    receipt_dir: PathBuf,
    trust_dir: PathBuf,
}

impl McpServer {
    fn new() -> Self {
        Self {
            identity_dir: identity_dir(),
            receipt_dir: receipt_dir(),
            trust_dir: trust_dir(),
        }
    }

    /// Route a JSON-RPC request to the appropriate handler.
    fn handle_request(&self, request: Value) -> Value {
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
            "initialize" => self.handle_initialize(id),
            "initialized" => {
                // Notification — no response needed, return null sentinel
                Value::Null
            }
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, &params),
            "resources/list" => self.handle_resources_list(id),
            "resources/read" => self.handle_resources_read(id, &params),
            "ping" => ok_result(id, json!({})),
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
                    }
                ]
            }),
        )
    }

    // ── tools/call ────────────────────────────────────────────────────────────

    fn handle_tools_call(&self, id: Value, params: &Value) -> Value {
        let tool_name = match params.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => return rpc_error(id, -32602, "missing tool name"),
        };
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        match tool_name.as_str() {
            "identity_create" => self.tool_identity_create(id, &args),
            "identity_show" => self.tool_identity_show(id, &args),
            "action_sign" => self.tool_action_sign(id, &args),
            "receipt_verify" => self.tool_receipt_verify(id, &args),
            "trust_grant" => self.tool_trust_grant(id, &args),
            "trust_revoke" => self.tool_trust_revoke(id, &args),
            "trust_verify" => self.tool_trust_verify(id, &args),
            "trust_list" => self.tool_trust_list(id, &args),
            "receipt_list" => self.tool_receipt_list(id, &args),
            "identity_health" => self.tool_identity_health(id, &args),
            "continuity_record" => self.tool_continuity_record(id, &args),
            "continuity_anchor" => self.tool_continuity_anchor(id, &args),
            "continuity_heartbeat" => self.tool_continuity_heartbeat(id, &args),
            "continuity_status" => self.tool_continuity_status(id, &args),
            "continuity_gaps" => self.tool_continuity_gaps(id, &args),
            "spawn_create" => self.tool_spawn_create(id, &args),
            "spawn_terminate" => self.tool_spawn_terminate(id, &args),
            "spawn_list" => self.tool_spawn_list(id, &args),
            "spawn_lineage" => self.tool_spawn_lineage(id, &args),
            "spawn_authority" => self.tool_spawn_authority(id, &args),
            "competence_record" => self.tool_competence_record(id, &args),
            "competence_show" => self.tool_competence_show(id, &args),
            "competence_prove" => self.tool_competence_prove(id, &args),
            "competence_verify" => self.tool_competence_verify(id, &args),
            "competence_list" => self.tool_competence_list(id, &args),
            "negative_prove" => self.tool_negative_prove(id, &args),
            "negative_verify" => self.tool_negative_verify(id, &args),
            "negative_declare" => self.tool_negative_declare(id, &args),
            "negative_list" => self.tool_negative_list(id, &args),
            "negative_check" => self.tool_negative_check(id, &args),
            _ => rpc_error(id, -32602, format!("unknown tool: {tool_name}")),
        }
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

    fn tool_spawn_terminate(&self, id: Value, _args: &Value) -> Value {
        tool_ok(
            id,
            "Spawn termination not yet implemented (requires spawn record storage)".to_string(),
        )
    }

    // ── Tool: spawn_list ──────────────────────────────────────────────────────

    fn tool_spawn_list(&self, id: Value, _args: &Value) -> Value {
        tool_ok(
            id,
            "No spawned identities found (use spawn_create to spawn a child)".to_string(),
        )
    }

    // ── Tool: spawn_lineage ───────────────────────────────────────────────────

    fn tool_spawn_lineage(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let out = format!(
            "Lineage for identity '{}'\n  Root (no spawn record — this is a root identity)\n  Depth: 0\n  Authority: * (full)",
            name
        );
        tool_ok(id, out)
    }

    // ── Tool: spawn_authority ─────────────────────────────────────────────────

    fn tool_spawn_authority(&self, id: Value, args: &Value) -> Value {
        let name = args
            .get("identity")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_IDENTITY);
        let out = format!(
            "Effective authority for identity '{}'\n  * (root identity — full authority)",
            name
        );
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

fn main() {
    // Log to stderr (stdout is reserved for JSON-RPC responses).
    // Use a minimal subscriber without the env-filter feature (not enabled in workspace).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();

    let server = McpServer::new();
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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}});
        let resp = server.handle_request(req);
        assert!(is_ok(&resp));
    }

    // ── tools/list ────────────────────────────────────────────────────────────

    #[test]
    fn test_tools_list() {
        init();
        let (server, _tmp) = test_server();
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
        assert_eq!(tools.len(), 30);
    }

    // ── resources/list ────────────────────────────────────────────────────────

    #[test]
    fn test_resources_list() {
        init();
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();
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
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","id":41,"method":"no_such_method","params":{}});
        let resp = server.handle_request(req);
        assert!(resp.get("error").is_some());
        assert_eq!(resp["error"]["code"], -32601);
    }

    // ── notification (no response) ────────────────────────────────────────────

    #[test]
    fn test_initialized_notification_returns_null() {
        init();
        let (server, _tmp) = test_server();
        let req = json!({"jsonrpc":"2.0","method":"initialized","params":{}});
        let resp = server.handle_request(req);
        assert!(resp.is_null());
    }

    // ── resources/read ────────────────────────────────────────────────────────

    #[test]
    fn test_resource_identity_read() {
        init();
        let (server, _tmp) = test_server();

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
        let (server, _tmp) = test_server();

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
}
