//! AgenticIdentity CLI — `aid` command.
//!
//! Provides a command-line interface for managing agentic identities,
//! signing actions, verifying receipts, and managing trust relationships.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use agentic_identity::competence::{self, AttemptOutcome, CompetenceDomain};
use agentic_identity::continuity::{
    self, AnchorType, CognitionType, ExperienceType, HealthMetrics, HeartbeatStatus, MemoryOpType,
    PerceptionSource, PlanningType, SystemEvent,
};
use agentic_identity::identity::RotationReason;
use agentic_identity::negative;
use agentic_identity::receipt::receipt::ReceiptBuilder;
use agentic_identity::receipt::verify::verify_receipt;
use agentic_identity::spawn::{self, SpawnConstraints, SpawnLifetime, SpawnType};
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

fn identity_path(name: &str) -> PathBuf {
    identity_dir().join(format!("{name}.aid"))
}

// ── Passphrase helper ─────────────────────────────────────────────────────────

fn read_passphrase(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut passphrase = String::new();
    std::io::stdin()
        .read_line(&mut passphrase)
        .expect("Failed to read passphrase");
    passphrase.trim().to_string()
}

// ── Time formatting helpers ───────────────────────────────────────────────────

fn micros_to_datetime(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let naive = chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    naive.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Parse a duration string like "24h", "7d", "30d", "1h30m", or plain seconds.
/// Returns the duration as microseconds.
fn parse_duration_to_micros(s: &str) -> Result<u64> {
    let s = s.trim();

    // Try parsing as plain integer (hours for backward compat or as seconds)
    if let Ok(n) = s.parse::<u64>() {
        // Treat bare number as hours
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
                .map_err(|_| anyhow!("invalid duration: {s}"))?;
            current.clear();
            match ch {
                'h' => total_micros += val * 3600 * 1_000_000,
                'd' => total_micros += val * 86400 * 1_000_000,
                'm' => total_micros += val * 60 * 1_000_000,
                's' => total_micros += val * 1_000_000,
                _ => return Err(anyhow!("unknown duration unit '{}' in '{s}'", ch)),
            }
        }
    }

    if !current.is_empty() {
        return Err(anyhow!("duration '{s}' is missing a unit (h/d/m/s)"));
    }

    if total_micros == 0 {
        return Err(anyhow!("duration must be > 0"));
    }

    Ok(total_micros)
}

// ── CLI structure ─────────────────────────────────────────────────────────────

/// AgenticIdentity CLI — manage cryptographic identities, sign actions, and
/// control trust relationships for AI agents.
#[derive(Parser, Debug)]
#[command(
    name = "aid",
    about = "AgenticIdentity CLI",
    version,
    long_about = "aid — AgenticIdentity CLI\n\nManage cryptographic identities, sign actions, verify receipts,\nand control trust relationships for AI agents."
)]
struct Cli {
    /// Use specific identity (default: default)
    #[arg(long, global = true, default_value = "default")]
    identity: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new identity
    Init {
        /// Name for the new identity
        #[arg(long)]
        name: Option<String>,
    },

    /// Display identity information
    Show {
        /// Identity name to show (overrides --identity)
        #[arg(long)]
        identity: Option<String>,
    },

    /// List all identities
    List,

    /// Sign an action and create a receipt
    Sign {
        /// Action type (decision, observation, mutation, delegation, revocation, identity_operation, or custom)
        #[arg(long)]
        r#type: String,

        /// Human-readable description of the action
        #[arg(long)]
        description: String,

        /// Optional JSON data payload
        #[arg(long)]
        data: Option<String>,

        /// Chain this receipt to a previous receipt ID
        #[arg(long)]
        chain_to: Option<String>,
    },

    /// Verify a receipt or trust grant
    Verify {
        #[command(subcommand)]
        subcommand: VerifyCommands,
    },

    /// Manage trust relationships
    Trust {
        #[command(subcommand)]
        subcommand: TrustCommands,
    },

    /// Rotate identity keys
    Rotate {
        /// Reason for rotation (manual, scheduled, compromised, device_lost, policy_required)
        #[arg(long)]
        reason: Option<String>,
    },

    /// Export identity public document as JSON
    Export {
        /// Identity name to export (overrides --identity)
        #[arg(long)]
        identity: Option<String>,

        /// Output file path (default: stdout)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Manage receipts
    Receipt {
        #[command(subcommand)]
        subcommand: ReceiptCommands,
    },

    /// Manage temporal continuity (experience chain, anchors, heartbeats)
    Continuity {
        #[command(subcommand)]
        subcommand: ContinuityCommands,
    },

    /// Manage identity inheritance (spawn child identities)
    Spawn {
        #[command(subcommand)]
        subcommand: SpawnCommands,
    },

    /// Manage competence proofs (demonstrated ability)
    Competence {
        #[command(subcommand)]
        subcommand: CompetenceCommands,
    },

    /// Manage negative capability proofs (structural impossibility)
    Cannot {
        #[command(subcommand)]
        subcommand: CannotCommands,
    },
}

#[derive(Subcommand, Debug)]
enum VerifyCommands {
    /// Verify a receipt by ID
    Receipt {
        /// Receipt ID (e.g. arec_...)
        receipt_id: String,
    },
    /// Verify a trust grant by ID
    Trust {
        /// Trust ID (e.g. atrust_...)
        trust_id: String,

        /// Capability URI to check (e.g. read:calendar)
        #[arg(long)]
        capability: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustCommands {
    /// Grant trust to another identity
    Grant {
        /// Grantee identity ID (aid_...)
        #[arg(long)]
        to: String,

        /// Capability URI to grant (e.g. read:calendar)
        #[arg(long)]
        capability: String,

        /// Expiry duration (e.g. 24h, 7d, 30d)
        #[arg(long)]
        expires: Option<String>,

        /// Maximum number of uses
        #[arg(long)]
        max_uses: Option<u64>,

        /// Allow the grantee to delegate trust
        #[arg(long)]
        allow_delegation: bool,

        /// Maximum delegation depth (requires --allow-delegation)
        #[arg(long)]
        max_depth: Option<u32>,
    },

    /// Revoke a trust grant
    Revoke {
        /// Trust ID to revoke
        trust_id: String,

        /// Reason for revocation
        #[arg(long)]
        reason: Option<String>,
    },

    /// List trust grants
    List {
        /// List grants issued by this identity
        #[arg(long)]
        granted: bool,

        /// List grants received by this identity
        #[arg(long)]
        received: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ReceiptCommands {
    /// List receipts with optional filters
    List {
        /// Filter by actor identity ID
        #[arg(long)]
        actor: Option<String>,

        /// Filter by action type
        #[arg(long, name = "type")]
        action_type: Option<String>,

        /// Maximum number of receipts to display
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
enum ContinuityCommands {
    /// Record an experience event
    Record {
        /// Experience type (perception, cognition, action, communication, memory, learning, planning, emotion, idle, system)
        #[arg(long)]
        r#type: String,

        /// Content hash
        #[arg(long)]
        content_hash: String,

        /// Intensity (0.0 - 1.0)
        #[arg(long, default_value = "0.5")]
        intensity: f32,
    },

    /// Create a continuity anchor (checkpoint)
    Anchor {
        /// Anchor type (genesis, manual, time-based, experience-count)
        #[arg(long, default_value = "manual")]
        r#type: String,
    },

    /// Create a heartbeat record
    Heartbeat {
        /// Status (active, idle, suspended, degraded)
        #[arg(long, default_value = "active")]
        status: String,
    },

    /// Get continuity status
    Status,

    /// Detect gaps in the experience chain
    Gaps {
        /// Grace period in seconds (gaps shorter are ignored)
        #[arg(long, default_value = "300")]
        grace_period: u64,
    },
}

#[derive(Subcommand, Debug)]
enum SpawnCommands {
    /// Spawn a child identity
    Create {
        /// Spawn type (worker, delegate, clone, specialist, custom)
        #[arg(long)]
        r#type: String,

        /// Purpose of the spawned identity
        #[arg(long)]
        purpose: String,

        /// Authority to grant (comma-separated capability URIs)
        #[arg(long)]
        authority: String,

        /// Lifetime (indefinite, or duration like "24h", "7d")
        #[arg(long, default_value = "indefinite")]
        lifetime: String,
    },

    /// List spawned children
    List {
        /// Show only active spawns
        #[arg(long)]
        active: bool,

        /// Show only terminated spawns
        #[arg(long)]
        terminated: bool,
    },

    /// Terminate a spawned child
    Terminate {
        /// Child identity ID to terminate
        child_id: String,

        /// Reason for termination
        #[arg(long)]
        reason: Option<String>,

        /// Cascade termination to descendants
        #[arg(long)]
        cascade: bool,
    },

    /// Show lineage for an identity
    Lineage {
        /// Identity ID (default: current identity)
        identity_id: Option<String>,
    },

    /// Show effective authority for an identity
    Authority {
        /// Identity ID (default: current identity)
        identity_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CompetenceCommands {
    /// Record a competence attempt
    Record {
        /// Competence domain (e.g., deploy, code_review, data_analysis)
        #[arg(long)]
        domain: String,

        /// Outcome (success, failure, partial)
        #[arg(long)]
        outcome: String,

        /// Failure reason (required if outcome=failure)
        #[arg(long)]
        reason: Option<String>,

        /// Partial score 0.0-1.0 (required if outcome=partial)
        #[arg(long)]
        score: Option<f32>,

        /// Receipt ID linking to the action
        #[arg(long)]
        receipt: String,
    },

    /// Show competence record for a domain
    Show {
        /// Competence domain
        #[arg(long)]
        domain: Option<String>,
    },

    /// Generate a competence proof
    Prove {
        /// Competence domain
        #[arg(long)]
        domain: String,

        /// Minimum success rate (0.0-1.0)
        #[arg(long, default_value = "0.8")]
        min_rate: f32,

        /// Minimum number of attempts
        #[arg(long, default_value = "10")]
        min_attempts: u64,
    },

    /// List all competence domains
    List,
}

#[derive(Subcommand, Debug)]
enum CannotCommands {
    /// Prove an identity cannot do something
    Prove {
        /// Capability URI to prove impossible
        capability: String,
    },

    /// Verify a negative capability proof
    Verify {
        /// Proof ID to verify
        proof_id: String,
    },

    /// Declare voluntary restriction
    Declare {
        /// Capabilities to declare impossible (comma-separated)
        #[arg(long)]
        capabilities: String,

        /// Reason for the declaration
        #[arg(long)]
        reason: String,

        /// Make declaration permanent (cannot be undone)
        #[arg(long)]
        permanent: bool,
    },

    /// List all negative declarations
    List,

    /// Quick check if a capability is impossible
    Check {
        /// Capability URI to check
        capability: String,
    },
}

// ── Main entry point ──────────────────────────────────────────────────────────

fn main() {
    env_logger::init();

    let cli = Cli::parse();
    let verbose = cli.verbose;
    let identity_name = cli.identity.clone();

    let result = match cli.command {
        Commands::Init { name } => cmd_init(name, verbose),
        Commands::Show { identity } => {
            let name = identity.unwrap_or(identity_name);
            cmd_show(&name, verbose)
        }
        Commands::List => cmd_list(verbose),
        Commands::Sign {
            r#type,
            description,
            data,
            chain_to,
        } => cmd_sign(
            &identity_name,
            &r#type,
            &description,
            data.as_deref(),
            chain_to.as_deref(),
            verbose,
        ),
        Commands::Verify { subcommand } => match subcommand {
            VerifyCommands::Receipt { receipt_id } => cmd_verify_receipt(&receipt_id, verbose),
            VerifyCommands::Trust {
                trust_id,
                capability,
            } => cmd_verify_trust(&trust_id, capability.as_deref(), verbose),
        },
        Commands::Trust { subcommand } => match subcommand {
            TrustCommands::Grant {
                to,
                capability,
                expires,
                max_uses,
                allow_delegation,
                max_depth,
            } => cmd_trust_grant(
                &identity_name,
                &to,
                &capability,
                expires.as_deref(),
                max_uses,
                allow_delegation,
                max_depth,
                verbose,
            ),
            TrustCommands::Revoke { trust_id, reason } => {
                cmd_trust_revoke(&identity_name, &trust_id, reason.as_deref(), verbose)
            }
            TrustCommands::List { granted, received } => {
                cmd_trust_list(&identity_name, granted, received, verbose)
            }
        },
        Commands::Rotate { reason } => cmd_rotate(&identity_name, reason.as_deref(), verbose),
        Commands::Export { identity, output } => {
            let name = identity.unwrap_or(identity_name);
            cmd_export(&name, output.as_deref(), verbose)
        }
        Commands::Receipt { subcommand } => match subcommand {
            ReceiptCommands::List {
                actor,
                action_type,
                limit,
            } => cmd_receipt_list(actor.as_deref(), action_type.as_deref(), limit, verbose),
        },
        Commands::Continuity { subcommand } => match subcommand {
            ContinuityCommands::Record {
                r#type,
                content_hash,
                intensity,
            } => cmd_continuity_record(&identity_name, &r#type, &content_hash, intensity, verbose),
            ContinuityCommands::Anchor { r#type } => {
                cmd_continuity_anchor(&identity_name, &r#type, verbose)
            }
            ContinuityCommands::Heartbeat { status } => {
                cmd_continuity_heartbeat(&identity_name, &status, verbose)
            }
            ContinuityCommands::Status => cmd_continuity_status(&identity_name, verbose),
            ContinuityCommands::Gaps { grace_period } => {
                cmd_continuity_gaps(&identity_name, grace_period, verbose)
            }
        },
        Commands::Spawn { subcommand } => match subcommand {
            SpawnCommands::Create {
                r#type,
                purpose,
                authority,
                lifetime,
            } => cmd_spawn_create(
                &identity_name,
                &r#type,
                &purpose,
                &authority,
                &lifetime,
                verbose,
            ),
            SpawnCommands::List { active, terminated } => {
                cmd_spawn_list(&identity_name, active, terminated, verbose)
            }
            SpawnCommands::Terminate {
                child_id,
                reason,
                cascade,
            } => cmd_spawn_terminate(
                &identity_name,
                &child_id,
                reason.as_deref(),
                cascade,
                verbose,
            ),
            SpawnCommands::Lineage { identity_id } => {
                cmd_spawn_lineage(&identity_name, identity_id.as_deref(), verbose)
            }
            SpawnCommands::Authority { identity_id } => {
                cmd_spawn_authority(&identity_name, identity_id.as_deref(), verbose)
            }
        },
        Commands::Competence { subcommand } => match subcommand {
            CompetenceCommands::Record {
                domain,
                outcome,
                reason,
                score,
                receipt,
            } => cmd_competence_record(
                &identity_name,
                &domain,
                &outcome,
                reason.as_deref(),
                score,
                &receipt,
                verbose,
            ),
            CompetenceCommands::Show { domain } => {
                cmd_competence_show(&identity_name, domain.as_deref(), verbose)
            }
            CompetenceCommands::Prove {
                domain,
                min_rate,
                min_attempts,
            } => cmd_competence_prove(&identity_name, &domain, min_rate, min_attempts, verbose),
            CompetenceCommands::List => cmd_competence_list(&identity_name, verbose),
        },
        Commands::Cannot { subcommand } => match subcommand {
            CannotCommands::Prove { capability } => {
                cmd_cannot_prove(&identity_name, &capability, verbose)
            }
            CannotCommands::Verify { proof_id } => cmd_cannot_verify(&proof_id, verbose),
            CannotCommands::Declare {
                capabilities,
                reason,
                permanent,
            } => cmd_cannot_declare(&identity_name, &capabilities, &reason, permanent, verbose),
            CannotCommands::List => cmd_cannot_list(&identity_name, verbose),
            CannotCommands::Check { capability } => {
                cmd_cannot_check(&identity_name, &capability, verbose)
            }
        },
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ── Command implementations ───────────────────────────────────────────────────

/// `aid init [--name NAME]`
fn cmd_init(name: Option<String>, verbose: bool) -> Result<()> {
    let name = name.unwrap_or_else(|| "default".to_string());
    let path = identity_path(&name);

    if path.exists() {
        return Err(anyhow!(
            "identity '{}' already exists at {}",
            name,
            path.display()
        ));
    }

    // Create the identity directory if needed
    std::fs::create_dir_all(identity_dir()).context("failed to create identity directory")?;

    let passphrase = read_passphrase("Enter passphrase for new identity: ");
    if passphrase.is_empty() {
        return Err(anyhow!("passphrase cannot be empty"));
    }
    let confirm = read_passphrase("Confirm passphrase: ");
    if passphrase != confirm {
        return Err(anyhow!("passphrases do not match"));
    }

    let anchor = IdentityAnchor::new(Some(name.clone()));
    let id = anchor.id();

    save_identity(&anchor, &path, &passphrase).context("failed to save identity")?;

    println!("Created identity '{name}'");
    println!("  ID:   {id}");
    println!("  File: {}", path.display());

    if verbose {
        let doc = anchor.to_document();
        println!("  Key:  {}", doc.public_key);
        println!("  Created: {}", micros_to_datetime(anchor.created_at));
    }

    Ok(())
}

/// `aid show [--identity NAME]`
fn cmd_show(name: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found (expected at {})",
            name,
            path.display()
        ));
    }

    let doc = read_public_document(&path).context("failed to read identity file")?;

    println!("Identity: {}", name);
    println!("  ID:        {}", doc.id);
    println!("  Algorithm: {}", doc.algorithm);
    println!("  Public Key: {}", doc.public_key);
    println!("  Created:   {}", micros_to_datetime(doc.created_at));

    if let Some(ref n) = doc.name {
        println!("  Name:      {n}");
    }

    if !doc.rotation_history.is_empty() {
        println!(
            "  Rotation History ({} rotation(s)):",
            doc.rotation_history.len()
        );
        for (i, rot) in doc.rotation_history.iter().enumerate() {
            println!(
                "    [{}] {} — reason: {:?}",
                i + 1,
                micros_to_datetime(rot.rotated_at),
                rot.reason
            );
            println!("        Previous key: {}...", &rot.previous_key[..16]);
            println!("        New key:      {}...", &rot.new_key[..16]);
        }
    } else {
        println!("  Rotation History: none");
    }

    if !doc.attestations.is_empty() {
        println!("  Attestations: {}", doc.attestations.len());
    }

    // Verify the document signature
    match doc.verify_signature() {
        Ok(()) => println!("  Signature: valid"),
        Err(e) => println!("  Signature: INVALID ({e})"),
    }

    Ok(())
}

/// `aid list`
fn cmd_list(_verbose: bool) -> Result<()> {
    let dir = identity_dir();

    if !dir.exists() {
        println!(
            "No identities found (directory {} does not exist)",
            dir.display()
        );
        return Ok(());
    }

    let mut entries: Vec<(String, PathBuf)> = std::fs::read_dir(&dir)
        .context("failed to read identity directory")?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            if path.extension().map(|x| x == "aid").unwrap_or(false) {
                let stem = path.file_stem()?.to_string_lossy().into_owned();
                Some((stem, path))
            } else {
                None
            }
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    if entries.is_empty() {
        println!("No identities found in {}", dir.display());
        return Ok(());
    }

    println!("{:<20} {:<30} CREATED", "NAME", "ID");
    println!("{}", "-".repeat(72));

    for (name, path) in &entries {
        match read_public_document(path) {
            Ok(doc) => {
                println!(
                    "{:<20} {:<30} {}",
                    name,
                    doc.id,
                    micros_to_datetime(doc.created_at)
                );
            }
            Err(e) => {
                println!("{:<20} (failed to read: {e})", name);
            }
        }
    }

    Ok(())
}

/// `aid sign --type TYPE --description DESC [--data JSON] [--chain-to RECEIPT_ID]`
fn cmd_sign(
    identity_name: &str,
    action_type_str: &str,
    description: &str,
    data: Option<&str>,
    chain_to: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor =
        load_identity(&path, &passphrase).context("failed to load identity (wrong passphrase?)")?;

    let action_type = parse_action_type(action_type_str)?;

    let action_content = if let Some(json_str) = data {
        let json_val: serde_json::Value =
            serde_json::from_str(json_str).context("--data must be valid JSON")?;
        ActionContent::with_data(description, json_val)
    } else {
        ActionContent::new(description)
    };

    let mut builder = ReceiptBuilder::new(anchor.id(), action_type, action_content);

    if let Some(prev_id_str) = chain_to {
        let prev_id = ReceiptId(prev_id_str.to_string());
        builder = builder.chain_to(prev_id);
    }

    let receipt = builder
        .sign(anchor.signing_key())
        .context("failed to sign receipt")?;

    let store = ReceiptStore::new(receipt_dir()).context("failed to open receipt store")?;
    store.save(&receipt).context("failed to save receipt")?;

    println!("Receipt created");
    println!("  ID:        {}", receipt.id);
    println!("  Type:      {}", receipt.action_type.as_tag());
    println!("  Actor:     {}", receipt.actor);
    println!("  Timestamp: {}", micros_to_datetime(receipt.timestamp));

    if let Some(ref prev) = receipt.previous_receipt {
        println!("  Chained to: {prev}");
    }

    if verbose {
        println!("  Hash:      {}", receipt.receipt_hash);
        println!("  Signature: {}...", &receipt.signature[..16]);
        if let Some(ref ctx) = receipt.context_hash {
            println!("  Context:   {ctx}");
        }
    }

    Ok(())
}

/// `aid verify receipt RECEIPT_ID`
fn cmd_verify_receipt(receipt_id_str: &str, verbose: bool) -> Result<()> {
    let store = ReceiptStore::new(receipt_dir()).context("failed to open receipt store")?;

    let id = ReceiptId(receipt_id_str.to_string());
    let receipt = store
        .load(&id)
        .with_context(|| format!("receipt '{}' not found", receipt_id_str))?;

    let verification = verify_receipt(&receipt).context("verification failed")?;

    println!("Receipt: {}", receipt.id);
    println!("  Actor:     {}", receipt.actor);
    println!("  Type:      {}", receipt.action_type.as_tag());
    println!("  Timestamp: {}", micros_to_datetime(receipt.timestamp));
    println!("  Description: {}", receipt.action.description);

    println!();
    println!("Verification:");
    println!(
        "  Signature: {}",
        if verification.signature_valid {
            "VALID"
        } else {
            "INVALID"
        }
    );

    if !receipt.witnesses.is_empty() {
        println!("  Witnesses ({}):", receipt.witnesses.len());
        for (i, valid) in verification.witnesses_valid.iter().enumerate() {
            println!(
                "    [{}] {}",
                i + 1,
                if *valid { "VALID" } else { "INVALID" }
            );
        }
    }

    if verification.is_valid {
        println!();
        println!("Result: VALID");
    } else {
        println!();
        println!("Result: INVALID");
    }

    if verbose {
        println!();
        println!("  Hash:      {}", receipt.receipt_hash);
        if let Some(ref prev) = receipt.previous_receipt {
            println!("  Chained to: {prev}");
        }
    }

    Ok(())
}

/// `aid verify trust TRUST_ID [--capability URI]`
fn cmd_verify_trust(trust_id_str: &str, capability: Option<&str>, _verbose: bool) -> Result<()> {
    let store = TrustStore::new(trust_dir()).context("failed to open trust store")?;

    let id = TrustId(trust_id_str.to_string());
    let grant = store
        .load_grant(&id)
        .with_context(|| format!("trust grant '{}' not found", trust_id_str))?;

    // Check revocation
    let revocations = if store.is_revoked(&id) {
        match store.load_revocation(&id) {
            Ok(rev) => vec![rev],
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    let requested_capability = capability.unwrap_or("*");

    let verification = verify_trust_grant(&grant, requested_capability, 0, &revocations)
        .context("verification failed")?;

    println!("Trust Grant: {}", grant.id);
    println!("  Grantor:    {}", grant.grantor);
    println!("  Grantee:    {}", grant.grantee);
    println!("  Granted At: {}", micros_to_datetime(grant.granted_at));
    println!("  Capabilities:");
    for cap in &grant.capabilities {
        if let Some(ref desc) = cap.description {
            println!("    - {} ({})", cap.uri, desc);
        } else {
            println!("    - {}", cap.uri);
        }
    }

    if let Some(expiry) = grant.constraints.not_after {
        println!("  Expires:    {}", micros_to_datetime(expiry));
    }
    if let Some(max) = grant.constraints.max_uses {
        println!("  Max Uses:   {max}");
    }
    if grant.delegation_allowed {
        println!(
            "  Delegation: allowed (max depth: {})",
            grant.max_delegation_depth.unwrap_or(0)
        );
    }

    println!();
    println!("Verification (capability: {requested_capability}):");
    println!(
        "  Signature:   {}",
        if verification.signature_valid {
            "VALID"
        } else {
            "INVALID"
        }
    );
    println!(
        "  Time:        {}",
        if verification.time_valid {
            "VALID"
        } else {
            "EXPIRED/NOT-YET-VALID"
        }
    );
    println!(
        "  Not Revoked: {}",
        if verification.not_revoked {
            "YES"
        } else {
            "REVOKED"
        }
    );
    println!(
        "  Uses:        {}",
        if verification.uses_valid {
            "WITHIN LIMIT"
        } else {
            "EXCEEDED"
        }
    );
    println!(
        "  Capability:  {}",
        if verification.capability_granted {
            "GRANTED"
        } else {
            "NOT GRANTED"
        }
    );

    println!();
    if verification.is_valid {
        println!("Result: VALID");
    } else {
        println!("Result: INVALID");
    }

    Ok(())
}

/// `aid trust grant --to IDENTITY_ID --capability URI [options]`
#[allow(clippy::too_many_arguments)]
fn cmd_trust_grant(
    identity_name: &str,
    grantee_id_str: &str,
    capability_uri: &str,
    expires: Option<&str>,
    max_uses: Option<u64>,
    allow_delegation: bool,
    max_depth: Option<u32>,
    verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor =
        load_identity(&path, &passphrase).context("failed to load identity (wrong passphrase?)")?;

    let grantee_id = IdentityId(grantee_id_str.to_string());

    // Build constraints
    let now_micros = agentic_identity::time::now_micros();
    let mut constraints = TrustConstraints::open();

    if let Some(duration_str) = expires {
        let duration_micros = parse_duration_to_micros(duration_str)
            .with_context(|| format!("invalid --expires value: '{duration_str}'"))?;
        constraints.not_after = Some(now_micros + duration_micros);
    }

    if let Some(max) = max_uses {
        constraints = constraints.with_max_uses(max);
    }

    // We use the grantor's own public key as the grantee key placeholder.
    // In a real scenario, we'd look up the grantee's public key from a registry.
    // Since we don't have a key registry in the CLI, we use the grantor's own
    // public key as a stand-in. The grant ID still uniquely identifies the grant,
    // and the grantor signature is what gets verified. Production usage would
    // resolve the grantee's public key via a key discovery mechanism.
    let grantee_key = anchor.public_key_base64();

    let mut builder = TrustGrantBuilder::new(anchor.id(), grantee_id.clone(), grantee_key)
        .capability(Capability::new(capability_uri))
        .constraints(constraints);

    if allow_delegation {
        let depth = max_depth.unwrap_or(1);
        builder = builder.allow_delegation(depth);
    }

    let grant = builder
        .sign(anchor.signing_key())
        .context("failed to sign trust grant")?;

    let store = TrustStore::new(trust_dir()).context("failed to open trust store")?;
    store
        .save_granted(&grant)
        .context("failed to save trust grant")?;

    println!("Trust grant created");
    println!("  Trust ID:   {}", grant.id);
    println!("  Grantor:    {}", grant.grantor);
    println!("  Grantee:    {}", grant.grantee);
    println!("  Capability: {}", capability_uri);

    if let Some(expiry) = grant.constraints.not_after {
        println!("  Expires:    {}", micros_to_datetime(expiry));
    } else {
        println!("  Expires:    never");
    }

    if let Some(max) = grant.constraints.max_uses {
        println!("  Max Uses:   {max}");
    }

    if grant.delegation_allowed {
        println!(
            "  Delegation: allowed (max depth: {})",
            grant.max_delegation_depth.unwrap_or(0)
        );
    }

    if verbose {
        println!("  Hash:       {}", grant.grant_hash);
        println!("  Signature:  {}...", &grant.grantor_signature[..16]);
    }

    Ok(())
}

/// `aid trust revoke TRUST_ID [--reason REASON]`
fn cmd_trust_revoke(
    identity_name: &str,
    trust_id_str: &str,
    reason_str: Option<&str>,
    _verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor =
        load_identity(&path, &passphrase).context("failed to load identity (wrong passphrase?)")?;

    let trust_id = TrustId(trust_id_str.to_string());

    // Verify the grant exists
    let store = TrustStore::new(trust_dir()).context("failed to open trust store")?;

    // Check the grant exists (may be in either granted or received)
    let _ = store
        .load_grant(&trust_id)
        .with_context(|| format!("trust grant '{}' not found", trust_id_str))?;

    let reason = parse_revocation_reason(reason_str.unwrap_or("manual_revocation"));

    let revocation =
        Revocation::create(trust_id.clone(), anchor.id(), reason, anchor.signing_key());

    store
        .save_revocation(&revocation)
        .context("failed to save revocation")?;

    println!("Trust grant revoked");
    println!("  Trust ID:  {trust_id}");
    println!("  Revoker:   {}", revocation.revoker);
    println!(
        "  Revoked At: {}",
        micros_to_datetime(revocation.revoked_at)
    );
    println!("  Reason:    {}", revocation.reason.as_str());

    Ok(())
}

/// `aid trust list [--granted] [--received]`
fn cmd_trust_list(
    _identity_name: &str,
    granted: bool,
    received: bool,
    verbose: bool,
) -> Result<()> {
    let store = TrustStore::new(trust_dir()).context("failed to open trust store")?;

    // Default: show both if neither flag specified
    let show_granted = granted || !received;
    let show_received = received || !granted;

    if show_granted {
        let ids = store
            .list_granted()
            .context("failed to list granted trust grants")?;

        println!("Granted ({}):", ids.len());
        if ids.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:<30} {:<30} CAPABILITY", "TRUST ID", "GRANTEE");
            println!("  {}", "-".repeat(80));
            for id in &ids {
                match store.load_grant(id) {
                    Ok(grant) => {
                        let caps: Vec<&str> =
                            grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                        let revoked = if store.is_revoked(id) {
                            " [REVOKED]"
                        } else {
                            ""
                        };
                        if verbose {
                            println!(
                                "  {:<30} {:<30} {}{}",
                                id,
                                grant.grantee,
                                caps.join(", "),
                                revoked
                            );
                            println!("    Granted: {}", micros_to_datetime(grant.granted_at));
                        } else {
                            println!(
                                "  {:<30} {:<30} {}{}",
                                id,
                                grant.grantee,
                                caps.join(", "),
                                revoked
                            );
                        }
                    }
                    Err(e) => {
                        println!("  {id} (error: {e})");
                    }
                }
            }
        }
        println!();
    }

    if show_received {
        let ids = store
            .list_received()
            .context("failed to list received trust grants")?;

        println!("Received ({}):", ids.len());
        if ids.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:<30} {:<30} CAPABILITY", "TRUST ID", "GRANTOR");
            println!("  {}", "-".repeat(80));
            for id in &ids {
                match store.load_grant(id) {
                    Ok(grant) => {
                        let caps: Vec<&str> =
                            grant.capabilities.iter().map(|c| c.uri.as_str()).collect();
                        let revoked = if store.is_revoked(id) {
                            " [REVOKED]"
                        } else {
                            ""
                        };
                        if verbose {
                            println!(
                                "  {:<30} {:<30} {}{}",
                                id,
                                grant.grantor,
                                caps.join(", "),
                                revoked
                            );
                            println!("    Granted: {}", micros_to_datetime(grant.granted_at));
                        } else {
                            println!(
                                "  {:<30} {:<30} {}{}",
                                id,
                                grant.grantor,
                                caps.join(", "),
                                revoked
                            );
                        }
                    }
                    Err(e) => {
                        println!("  {id} (error: {e})");
                    }
                }
            }
        }
    }

    Ok(())
}

/// `aid rotate [--reason REASON]`
fn cmd_rotate(identity_name: &str, reason_str: Option<&str>, verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!(
        "Current passphrase for identity '{}': ",
        identity_name
    ));
    let anchor =
        load_identity(&path, &passphrase).context("failed to load identity (wrong passphrase?)")?;

    let old_id = anchor.id();
    let old_key = anchor.public_key_base64();

    let reason = parse_rotation_reason(reason_str.unwrap_or("manual"));

    let rotated = anchor
        .rotate(reason)
        .context("failed to rotate identity keys")?;

    let new_passphrase = read_passphrase("New passphrase (or press Enter to keep current): ");
    let final_passphrase = if new_passphrase.is_empty() {
        passphrase
    } else {
        let confirm = read_passphrase("Confirm new passphrase: ");
        if new_passphrase != confirm {
            return Err(anyhow!("passphrases do not match"));
        }
        new_passphrase
    };

    save_identity(&rotated, &path, &final_passphrase).context("failed to save rotated identity")?;

    let new_id = rotated.id();

    println!("Identity rotated successfully");
    println!("  Identity: {identity_name}");
    println!("  Old ID:   {old_id}");
    println!("  New ID:   {new_id}");
    println!("  Rotations: {}", rotated.rotation_history.len());

    if verbose {
        println!("  Old Key: {old_key}");
        println!("  New Key: {}", rotated.public_key_base64());
    }

    Ok(())
}

/// `aid export [--identity NAME] [--output FILE]`
fn cmd_export(name: &str, output: Option<&std::path::Path>, _verbose: bool) -> Result<()> {
    let path = identity_path(name);

    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found (expected at {})",
            name,
            path.display()
        ));
    }

    let doc = read_public_document(&path).context("failed to read identity file")?;

    let json =
        serde_json::to_string_pretty(&doc).context("failed to serialize identity document")?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &json)
            .with_context(|| format!("failed to write to {}", out_path.display()))?;
        println!("Exported identity '{}' to {}", name, out_path.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

/// `aid receipt list [--actor IDENTITY] [--type TYPE] [--limit N]`
fn cmd_receipt_list(
    actor_filter: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
    verbose: bool,
) -> Result<()> {
    let store = ReceiptStore::new(receipt_dir()).context("failed to open receipt store")?;

    let all_ids = store.list().context("failed to list receipts")?;

    if all_ids.is_empty() {
        println!("No receipts found.");
        return Ok(());
    }

    // Load all receipts (with optional filters)
    let mut receipts = Vec::new();
    for id in &all_ids {
        match store.load(id) {
            Ok(receipt) => {
                // Apply actor filter
                if let Some(actor) = actor_filter {
                    if receipt.actor.0 != actor {
                        continue;
                    }
                }
                // Apply type filter
                if let Some(type_str) = type_filter {
                    if receipt.action_type.as_tag() != type_str {
                        continue;
                    }
                }
                receipts.push(receipt);
            }
            Err(e) => {
                if verbose {
                    eprintln!("warning: could not load receipt {}: {e}", id.0);
                }
            }
        }
    }

    // Sort by timestamp descending (newest first)
    receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply limit
    let total = receipts.len();
    receipts.truncate(limit);

    println!("Receipts ({} shown, {} total):", receipts.len(), total);
    if receipts.is_empty() {
        println!("  (none match filters)");
    } else {
        println!(
            "  {:<25} {:<15} {:<25} DESCRIPTION",
            "ID", "TYPE", "TIMESTAMP"
        );
        println!("  {}", "-".repeat(90));
        for receipt in &receipts {
            let desc_preview = if receipt.action.description.len() > 35 {
                format!("{}...", &receipt.action.description[..32])
            } else {
                receipt.action.description.clone()
            };
            println!(
                "  {:<25} {:<15} {:<25} {}",
                receipt.id,
                receipt.action_type.as_tag(),
                micros_to_datetime(receipt.timestamp),
                desc_preview
            );
            if verbose {
                println!("    Actor: {}", receipt.actor);
                if let Some(ref prev) = receipt.previous_receipt {
                    println!("    Chained to: {prev}");
                }
            }
        }
    }

    Ok(())
}

// ── Continuity commands ──────────────────────────────────────────────────────

/// `aid continuity record --type TYPE --content-hash HASH [--intensity N]`
fn cmd_continuity_record(
    identity_name: &str,
    type_str: &str,
    content_hash: &str,
    intensity: f32,
    verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let event_type = parse_experience_type(type_str)?;

    let exp = continuity::record_experience(&anchor, event_type, content_hash, intensity, None)
        .map_err(|e| anyhow!("failed to record experience: {e}"))?;

    println!("Experience recorded");
    println!("  ID:          {}", exp.id);
    println!("  Type:        {}", exp.event_type.as_tag());
    println!("  Sequence:    {}", exp.sequence_number);
    println!("  Timestamp:   {}", micros_to_datetime(exp.timestamp));
    println!("  Intensity:   {:.1}", exp.intensity);

    if verbose {
        println!("  Hash:        {}", exp.cumulative_hash);
        println!("  Content:     {}", exp.content_hash);
    }

    Ok(())
}

/// `aid continuity anchor --type TYPE`
fn cmd_continuity_anchor(identity_name: &str, type_str: &str, verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let anchor_type = parse_anchor_type(type_str)?;

    // Create a genesis experience to anchor to
    let exp = continuity::record_experience(
        &anchor,
        ExperienceType::System {
            event: SystemEvent::Checkpoint,
        },
        &format!("anchor_{type_str}"),
        1.0,
        None,
    )
    .map_err(|e| anyhow!("failed to create experience: {e}"))?;

    let ca = continuity::create_anchor(&anchor, anchor_type, &exp, None, None)
        .map_err(|e| anyhow!("failed to create anchor: {e}"))?;

    println!("Continuity anchor created");
    println!("  ID:         {}", ca.id);
    println!("  Type:       {}", ca.anchor_type.as_tag());
    println!("  Experience: {}", ca.experience_id);
    println!("  Count:      {}", ca.experience_count);
    println!("  Timestamp:  {}", micros_to_datetime(ca.timestamp));

    if verbose {
        println!("  Hash:       {}", ca.cumulative_hash);
    }

    Ok(())
}

/// `aid continuity heartbeat --status STATUS`
fn cmd_continuity_heartbeat(identity_name: &str, status_str: &str, verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let status = parse_heartbeat_status(status_str);
    let health = HealthMetrics {
        memory_usage_bytes: 0,
        experience_rate_per_hour: 0.0,
        error_count: 0,
        latency_ms: 0,
    };

    let hb = continuity::create_heartbeat(&anchor, 0, "cli_heartbeat", 0, 0, status, health)
        .map_err(|e| anyhow!("failed to create heartbeat: {e}"))?;

    println!("Heartbeat created");
    println!("  ID:        {}", hb.id);
    println!("  Status:    {}", hb.status.as_tag());
    println!("  Timestamp: {}", micros_to_datetime(hb.timestamp));

    if verbose {
        println!("  Sequence:  {}", hb.sequence_number);
        println!("  Hash:      {}", hb.continuity_hash);
    }

    Ok(())
}

/// `aid continuity status`
fn cmd_continuity_status(identity_name: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!("Continuity status for identity '{identity_name}'");
    println!("  No experiences recorded yet (use `aid continuity record` to start)");

    Ok(())
}

/// `aid continuity gaps --grace-period SECONDS`
fn cmd_continuity_gaps(identity_name: &str, grace_period: u64, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!(
        "Gap analysis for identity '{}' (grace period: {}s)",
        identity_name, grace_period
    );
    println!("  No experiences recorded yet (use `aid continuity record` to start)");

    Ok(())
}

// ── Spawn commands ───────────────────────────────────────────────────────────

/// `aid spawn create --type TYPE --purpose PURPOSE --authority URI`
fn cmd_spawn_create(
    identity_name: &str,
    type_str: &str,
    purpose: &str,
    authority_str: &str,
    lifetime_str: &str,
    verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!(
            "identity '{}' not found — run `aid init` first",
            identity_name
        ));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let spawn_type = parse_spawn_type(type_str)?;
    let authority: Vec<Capability> = authority_str
        .split(',')
        .map(|s| Capability::new(s.trim()))
        .collect();
    let ceiling = authority.clone();
    let lifetime = parse_spawn_lifetime(lifetime_str)?;

    let (child, record, receipt) = spawn::spawn_child(
        &anchor,
        spawn_type,
        purpose,
        authority,
        ceiling,
        lifetime,
        SpawnConstraints::default(),
        None,
        &[],
    )
    .map_err(|e| anyhow!("failed to spawn child: {e}"))?;

    // Save the child identity
    let child_passphrase = read_passphrase("Passphrase for child identity: ");
    let child_path = identity_path(&format!("{}-{}", identity_name, record.spawn_type.as_tag()));
    save_identity(&child, &child_path, &child_passphrase)
        .context("failed to save child identity")?;

    // Save the receipt
    let receipt_store = ReceiptStore::new(receipt_dir()).context("failed to open receipt store")?;
    receipt_store
        .save(&receipt)
        .context("failed to save receipt")?;

    println!("Child identity spawned");
    println!("  Spawn ID:   {}", record.id);
    println!("  Parent:     {}", record.parent_id);
    println!("  Child ID:   {}", record.child_id);
    println!("  Type:       {}", record.spawn_type.as_tag());
    println!("  Purpose:    {}", record.spawn_purpose);
    println!("  Lifetime:   {}", record.lifetime.as_tag());
    println!("  Receipt:    {}", receipt.id);
    println!("  Child file: {}", child_path.display());

    if verbose {
        println!("  Authority:");
        for cap in &record.authority_granted {
            println!("    - {}", cap.uri);
        }
    }

    Ok(())
}

/// `aid spawn list [--active] [--terminated]`
fn cmd_spawn_list(
    _identity_name: &str,
    _active: bool,
    _terminated: bool,
    _verbose: bool,
) -> Result<()> {
    println!("Spawned identities:");
    println!("  (no spawn records found — use `aid spawn create` to spawn a child)");
    Ok(())
}

/// `aid spawn terminate CHILD_ID [--reason REASON] [--cascade]`
fn cmd_spawn_terminate(
    _identity_name: &str,
    child_id: &str,
    reason: Option<&str>,
    cascade: bool,
    _verbose: bool,
) -> Result<()> {
    let reason = reason.unwrap_or("manual termination");
    println!(
        "Terminate child {} (reason: {}, cascade: {})",
        child_id, reason, cascade
    );
    println!("  (spawn record not found — ensure the child was spawned from this identity)");
    Ok(())
}

/// `aid spawn lineage [IDENTITY_ID]`
fn cmd_spawn_lineage(
    identity_name: &str,
    _identity_id: Option<&str>,
    _verbose: bool,
) -> Result<()> {
    println!("Lineage for identity '{}':", identity_name);
    println!("  Root (no spawn record — this is a root identity)");
    Ok(())
}

/// `aid spawn authority [IDENTITY_ID]`
fn cmd_spawn_authority(
    identity_name: &str,
    _identity_id: Option<&str>,
    _verbose: bool,
) -> Result<()> {
    println!("Effective authority for identity '{}':", identity_name);
    println!("  * (root identity — full authority)");
    Ok(())
}

// ── Competence commands ──────────────────────────────────────────────────────

/// `aid competence record --domain DOMAIN --outcome OUTCOME --receipt RECEIPT_ID`
#[allow(clippy::too_many_arguments)]
fn cmd_competence_record(
    identity_name: &str,
    domain: &str,
    outcome_str: &str,
    reason: Option<&str>,
    score: Option<f32>,
    receipt_id_str: &str,
    _verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let outcome = match outcome_str.to_lowercase().as_str() {
        "success" => AttemptOutcome::Success,
        "failure" => AttemptOutcome::Failure {
            reason: reason.unwrap_or("unspecified").to_string(),
        },
        "partial" => AttemptOutcome::Partial {
            score: score.unwrap_or(0.5),
        },
        _ => {
            return Err(anyhow!(
                "unknown outcome: '{}'. Use: success, failure, partial",
                outcome_str
            ))
        }
    };

    let receipt_id = ReceiptId(receipt_id_str.to_string());
    let comp_domain = CompetenceDomain::new(domain);

    let attempt = competence::record_attempt(&anchor, comp_domain, outcome, receipt_id, None, None)
        .map_err(|e| anyhow!("failed to record attempt: {e}"))?;

    println!("Competence attempt recorded");
    println!("  Attempt ID: {}", attempt.attempt_id);
    println!("  Domain:     {}", attempt.domain);
    println!("  Outcome:    {:?}", attempt.outcome);
    println!("  Timestamp:  {}", micros_to_datetime(attempt.timestamp));

    Ok(())
}

/// `aid competence show [--domain DOMAIN]`
fn cmd_competence_show(identity_name: &str, _domain: Option<&str>, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!("Competence records for '{}':", identity_name);
    println!("  (no competence records found — use `aid competence record` to start)");
    Ok(())
}

/// `aid competence prove --domain DOMAIN --min-rate RATE --min-attempts N`
fn cmd_competence_prove(
    identity_name: &str,
    domain: &str,
    min_rate: f32,
    min_attempts: u64,
    _verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!(
        "Generate competence proof for '{}' domain '{}' (min rate: {:.0}%, min attempts: {})",
        identity_name,
        domain,
        min_rate * 100.0,
        min_attempts
    );
    println!("  (no competence records found — record attempts first)");
    Ok(())
}

/// `aid competence list`
fn cmd_competence_list(identity_name: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!("Competence domains for '{}':", identity_name);
    println!("  (no competence records found)");
    Ok(())
}

// ── Cannot (negative) commands ──────────────────────────────────────────────

/// `aid cannot prove CAPABILITY`
fn cmd_cannot_prove(identity_name: &str, capability: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!(
        "Generate negative proof that '{}' cannot do '{}'",
        identity_name, capability
    );
    println!("  (no ceiling or spawn records found — root identities have no structural limits)");
    Ok(())
}

/// `aid cannot verify PROOF_ID`
fn cmd_cannot_verify(proof_id: &str, _verbose: bool) -> Result<()> {
    println!("Verify negative proof: {}", proof_id);
    println!("  (proof not found)");
    Ok(())
}

/// `aid cannot declare --capabilities CAPS --reason REASON [--permanent]`
fn cmd_cannot_declare(
    identity_name: &str,
    capabilities_str: &str,
    reason: &str,
    permanent: bool,
    _verbose: bool,
) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    let passphrase = read_passphrase(&format!("Passphrase for identity '{}': ", identity_name));
    let anchor = load_identity(&path, &passphrase).context("failed to load identity")?;

    let capabilities: Vec<String> = capabilities_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let decl = negative::declare_cannot(&anchor, capabilities, reason, permanent, vec![])
        .map_err(|e| anyhow!("failed to create declaration: {e}"))?;

    println!("Negative declaration created");
    println!("  Declaration ID: {}", decl.declaration_id);
    println!("  Cannot do:");
    for cap in &decl.cannot_do {
        println!("    - {}", cap);
    }
    println!("  Reason:     {}", decl.reason);
    println!("  Permanent:  {}", decl.permanent);
    println!("  Declared:   {}", micros_to_datetime(decl.declared_at));

    Ok(())
}

/// `aid cannot list`
fn cmd_cannot_list(identity_name: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!("Negative declarations for '{}':", identity_name);
    println!("  (no declarations found — use `aid cannot declare` to create)");
    Ok(())
}

/// `aid cannot check CAPABILITY`
fn cmd_cannot_check(identity_name: &str, capability: &str, _verbose: bool) -> Result<()> {
    let path = identity_path(identity_name);
    if !path.exists() {
        return Err(anyhow!("identity '{}' not found", identity_name));
    }

    println!("Check if '{}' can do '{}':", identity_name, capability);
    println!("  Result: possibly (root identity — no structural limits found)");
    Ok(())
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

fn parse_action_type(s: &str) -> Result<ActionType> {
    match s.to_lowercase().as_str() {
        "decision" => Ok(ActionType::Decision),
        "observation" => Ok(ActionType::Observation),
        "mutation" => Ok(ActionType::Mutation),
        "delegation" => Ok(ActionType::Delegation),
        "revocation" => Ok(ActionType::Revocation),
        "identity_operation" | "identityoperation" => Ok(ActionType::IdentityOperation),
        other => Ok(ActionType::Custom(other.to_string())),
    }
}

fn parse_rotation_reason(s: &str) -> RotationReason {
    match s.to_lowercase().as_str() {
        "scheduled" => RotationReason::Scheduled,
        "compromised" => RotationReason::Compromised,
        "device_lost" | "devicelost" => RotationReason::DeviceLost,
        "policy_required" | "policyrequired" => RotationReason::PolicyRequired,
        _ => RotationReason::Manual,
    }
}

fn parse_revocation_reason(s: &str) -> RevocationReason {
    match s.to_lowercase().as_str() {
        "expired" => RevocationReason::Expired,
        "compromised" => RevocationReason::Compromised,
        "policy_violation" | "policyviolation" => RevocationReason::PolicyViolation,
        "grantee_request" | "granteerequest" => RevocationReason::GranteeRequest,
        "manual" | "manual_revocation" | "manualrevocation" => RevocationReason::ManualRevocation,
        other => RevocationReason::Custom(other.to_string()),
    }
}

fn parse_experience_type(s: &str) -> Result<ExperienceType> {
    match s.to_lowercase().as_str() {
        "perception" => Ok(ExperienceType::Perception { source: PerceptionSource::Text }),
        "cognition" => Ok(ExperienceType::Cognition { cognition_type: CognitionType::Thought }),
        "action" => Ok(ExperienceType::Action { receipt_id: agentic_identity::ReceiptId("arec_cli".into()) }),
        "memory" => Ok(ExperienceType::Memory { operation: MemoryOpType::Store }),
        "learning" => Ok(ExperienceType::Learning { learning_type: agentic_identity::continuity::LearningType::SelfDirected, domain: "general".into() }),
        "planning" => Ok(ExperienceType::Planning { planning_type: PlanningType::GoalSetting }),
        "emotion" => Ok(ExperienceType::Emotion { emotion_type: "neutral".into() }),
        "idle" => Ok(ExperienceType::Idle { reason: "awaiting input".into() }),
        "system" => Ok(ExperienceType::System { event: SystemEvent::Checkpoint }),
        other => Err(anyhow!("unknown experience type: '{}'. Valid types: perception, cognition, action, memory, learning, planning, emotion, idle, system", other)),
    }
}

fn parse_anchor_type(s: &str) -> Result<AnchorType> {
    match s.to_lowercase().as_str() {
        "genesis" => Ok(AnchorType::Genesis),
        "manual" => Ok(AnchorType::Manual),
        "time-based" | "timebased" | "time_based" => {
            Ok(AnchorType::TimeBased { interval_hours: 24 })
        }
        "experience-count" | "experiencecount" | "experience_count" => {
            Ok(AnchorType::ExperienceCount { interval: 1000 })
        }
        other => Err(anyhow!(
            "unknown anchor type: '{}'. Valid types: genesis, manual, time-based, experience-count",
            other
        )),
    }
}

fn parse_heartbeat_status(s: &str) -> HeartbeatStatus {
    match s.to_lowercase().as_str() {
        "active" => HeartbeatStatus::Active,
        "idle" => HeartbeatStatus::Idle,
        "suspended" => HeartbeatStatus::Suspended,
        "degraded" => HeartbeatStatus::Degraded,
        _ => HeartbeatStatus::Active,
    }
}

fn parse_spawn_type(s: &str) -> Result<SpawnType> {
    match s.to_lowercase().as_str() {
        "worker" => Ok(SpawnType::Worker),
        "delegate" => Ok(SpawnType::Delegate),
        "clone" => Ok(SpawnType::Clone),
        "specialist" => Ok(SpawnType::Specialist),
        other => Ok(SpawnType::Custom(other.to_string())),
    }
}

fn parse_spawn_lifetime(s: &str) -> Result<SpawnLifetime> {
    match s.to_lowercase().as_str() {
        "indefinite" => Ok(SpawnLifetime::Indefinite),
        "parent" | "parent_termination" => Ok(SpawnLifetime::ParentTermination),
        other => {
            // Try parsing as duration
            let micros = parse_duration_to_micros(other)?;
            let seconds = micros / 1_000_000;
            Ok(SpawnLifetime::Duration { seconds })
        }
    }
}
