---
status: stable
---

# Guide

## Creating Your First Identity

```bash
aid create --name "my-agent"
```

This generates an Ed25519 keypair and creates an identity anchor stored locally.

## Signing Actions

```bash
aid sign --action "Deployed v2.1.0 to production" --type decision
```

Produces a signed receipt with timestamp, action content, and cryptographic signature.

## Verifying Receipts

```bash
aid verify --receipt receipt.json
```

Checks signature validity, timestamp integrity, and chain consistency.

## Trust Delegation

```bash
aid trust grant --to <agent-id> --scope read --expires 24h
```

Grants scoped, time-limited trust to another identity.

## Continuity Sessions

```bash
aid continuity start --identity <id>
```

Starts a tamper-evident experience chain that tracks agent activity across sessions.
