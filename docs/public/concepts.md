---
title: Core Concepts
description: Identity anchors, action receipts, and trust web explained
order: 2
status: stable
---

# Core Concepts

AgenticIdentity solves three fundamental problems in AI agent systems.

## Identity Anchor

An **Identity Anchor** is a cryptographic key pair (Ed25519) that serves as an agent's permanent identity. The public key IS the identity — mathematical, unforgeable, and portable.

- **Identity ID**: `aid_` prefix + base58-encoded hash of the public key
- **Key derivation**: Scoped session, capability, and device keys via HKDF-SHA256
- **Key rotation**: Seamless key replacement with signed authorization chain

## Action Receipts

An **Action Receipt** is a signed proof that an agent took a specific action. Every receipt includes:

- Actor identity (public key)
- Action type and content
- Timestamp
- Cryptographic signature
- Optional witness signatures
- Optional chain to previous receipts

Receipts are **chained** — each receipt can reference the previous one, creating an immutable audit trail.

## Trust Web

The **Trust Web** is a network of signed trust relationships between identities:

- **Grants**: "I trust identity B to do X until time T"
- **Capabilities**: Scoped permissions using URI patterns (e.g., `read:calendar`, `execute:deploy:*`)
- **Constraints**: Time bounds, use limits, geographic restrictions
- **Revocation**: Built-in revocation with configurable channels
- **Delegation**: Trust chains with depth limits

## File Format

Identities are stored in `.aid` files — JSON with encrypted private keys and plaintext public documents. Private keys are encrypted with ChaCha20-Poly1305 using a passphrase-derived key (Argon2id + HKDF-SHA256).
