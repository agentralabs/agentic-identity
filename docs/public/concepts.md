---
title: Core Concepts
description: Identity anchors, action receipts, and trust web explained
order: 2
status: stable
---

# Core Concepts

AgenticIdentity provides cryptographic identity infrastructure for AI agents. It solves the fundamental problem that agent actions are anonymous, untraceable, and irrevocable by default.

## Identity Anchor

An **Identity Anchor** is a cryptographic key pair (Ed25519) that serves as an agent's permanent identity. The public key IS the identity — mathematical, unforgeable, and portable.

- **Identity ID**: `aid_` prefix + base58-encoded hash of the first 16 bytes of SHA-256(public_key)
- **Key derivation**: Scoped session, capability, device, and revocation keys via HKDF-SHA256
- **Key rotation**: Seamless key replacement with a signed authorization chain linking old and new keys
- **Self-signed document**: Each identity produces an `IdentityDocument` containing the public key, algorithm, creation timestamp, rotation history, and attestations — all self-signed for verification without a central authority

### Identity Creation

Creating an identity generates a fresh Ed25519 key pair from the OS CSPRNG, records a creation timestamp, and optionally attaches a human-readable name. The private key is zeroized on drop to prevent memory leakage. Identities are stored in `.aid` files with private keys encrypted using ChaCha20-Poly1305 (passphrase derived via Argon2id + HKDF-SHA256).

### Key Derivation Hierarchy

From the root signing key, scoped child keys are derived deterministically using HKDF-SHA256:

- **Session keys**: Scoped to a single session identifier, isolating signing authority per session
- **Capability keys**: Scoped to a capability URI, enabling fine-grained proof of authorization
- **Device keys**: Scoped to a device identifier, allowing multi-device operation from one root identity
- **Revocation keys**: Scoped to a trust grant ID, used to sign revocation notices

## Action Receipts

An **Action Receipt** is a signed proof that an agent took a specific action. Every receipt includes:

- Actor identity (public key)
- Action type (decision, observation, mutation, delegation, revocation, identity_operation, or custom)
- Action content (human-readable description plus optional structured data payload)
- Timestamp (microseconds since Unix epoch)
- Cryptographic signature (Ed25519 over the receipt hash)
- Optional witness signatures from third-party observers
- Optional chain to previous receipts via `previous_receipt` field

Receipts are **chained** — each receipt can reference the previous one, creating an immutable audit trail. The receipt ID uses the `arec_` prefix followed by base58-encoded truncated SHA-256 of the receipt hash.

### Receipt Verification

Any party with the actor's public key can verify a receipt by checking the Ed25519 signature over the receipt hash. Witness signatures are independently verifiable. Chain integrity is confirmed by walking the `previous_receipt` links and checking each signature in sequence.

## Trust Web

The **Trust Web** is a network of signed trust relationships between identities:

- **Grants**: "I trust identity B to do X until time T" — each grant is signed by the grantor and optionally acknowledged by the grantee
- **Capabilities**: Scoped permissions using URI patterns (e.g., `read:calendar`, `execute:deploy:*`) supporting wildcard matching
- **Constraints**: Time bounds (`not_before`, `not_after`), use limits (`max_uses`), and custom conditions
- **Revocation**: Built-in revocation with configurable channels (local file, HTTP endpoint, or custom) and optional witness requirements
- **Delegation**: Trust chains with configurable depth limits — a grantee can delegate to a third party if `delegation_allowed` is true, up to `max_delegation_depth` hops

Trust grant IDs use the `atrust_` prefix. Chain verification scales linearly with depth.

## Competence Tracking

The **Competence Engine** records and aggregates task outcomes per domain, building a verifiable track record:

- **Domains**: Named skill areas (e.g., `deploy`, `code_review`, `data_analysis`, `planning`)
- **Attempts**: Each attempt records an outcome (Success, Failure with reason, or Partial with a 0.0-1.0 score), linked to an action receipt
- **Aggregation**: The competence record tracks total attempts, successes, failures, partial scores, success rate, current streak, and best streak
- **Proofs**: A `CompetenceProof` is a signed cryptographic claim that an agent meets minimum competence thresholds (min attempts, min success rate, optional min streak) in a given domain
- **Requirements**: Trust grants can embed `CompetenceRequirement` constraints, requiring the grantee to prove competence before exercising a capability

## Child Spawning

The **Spawn Engine** manages parent-child identity relationships with verifiable lineage:

- **Spawn types**: Worker (temporary, task-specific), Delegate (acts on behalf of parent), Clone (full copy within ceiling), Specialist (subset for a specific domain), or Custom
- **Authority ceiling**: The child's capabilities are bounded by the parent's grant — a child can never exceed its parent's authority
- **Lifetime policies**: Indefinite, fixed duration, until a timestamp, on task completion, or on parent termination
- **Constraints**: Configurable max spawn depth, max children, max descendants, whether the child can itself spawn, and authority decay factor per generation
- **Lineage**: Each spawned identity carries a `SpawnInfo` record linking back to the parent, and the system can reconstruct the full parent chain to the root ancestor
- **Termination**: Parents can terminate children, optionally cascading to all descendants

## Negative Capability Proofs

The **Negative Engine** produces cryptographic evidence that an agent **cannot** perform a specific action:

- **Impossibility reasons**: Not in the identity's capability ceiling, not in lineage, explicitly excluded at spawn time, capability structurally nonexistent, or voluntarily declared
- **Evidence types**: Ceiling exclusion (hash of the ceiling that omits the capability), lineage exclusion (ancestor ceiling hashes), spawn exclusion (spawn record hash), or reference to a voluntary declaration
- **Voluntary declarations**: An agent can self-impose permanent or temporary restrictions, signed and optionally witnessed, that serve as negative capability evidence

Negative proofs let agents prove what they cannot do, which is essential for safety-critical delegation decisions.

## Continuity Engine

The **Continuity Engine** maintains a tamper-evident chain of experience events across sessions:

- **Experience types**: Perception, Cognition, Action, Communication, Memory, Learning, Planning, Emotion, Idle, and System events — each with typed metadata
- **Chain structure**: Each experience event links to the previous via `previous_experience_id` and `previous_experience_hash`, with a running `cumulative_hash` and monotonic `sequence_number`
- **Anchors**: Checkpoints (genesis, time-based, experience-count, manual, or external-witness) that snapshot the chain state for efficient verification
- **Heartbeats**: Periodic signed records confirming the agent is alive, including health metrics (memory usage, experience rate, error count, latency)
- **Gap detection**: The system detects temporal, sequence, hash, and heartbeat gaps with severity levels (Minor, Moderate, Major, Critical)
- **Claims**: A `ContinuityClaim` asserts unbroken continuity over a range, verifiable by walking the chain and checking signatures

## Teams

Team identities allow multiple agents to act collectively with **quorum-based authorization**. A team is created with a set of member identities and a minimum signer threshold. Actions taken as a team require signatures from at least the quorum number of members, and the resulting action receipts record which members signed.

## File Format

Identities are stored in `.aid` files — JSON with encrypted private keys and plaintext public documents. Private keys are encrypted with ChaCha20-Poly1305 using a passphrase-derived key (Argon2id + HKDF-SHA256). Receipts, trust grants, and spawn records are stored in separate JSON files under `~/.agentic/receipts/`, `~/.agentic/trust/`, and `~/.agentic/spawn/` respectively.
