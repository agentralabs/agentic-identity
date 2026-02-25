---
title: File Format
description: Specification of the .aid identity file format
order: 7
status: stable
---

# .aid File Format Specification

Version: 1 (`aid-v1`)

## Overview

An `.aid` file stores an identity anchor's private key material encrypted at rest alongside the public identity document in plaintext. The file is JSON for human readability and tool compatibility. The encryption ensures that the private key cannot be recovered without the correct passphrase.

## Structure

```json
{
    "version": 1,
    "format": "aid-v1",
    "encryption": {
        "algorithm": "chacha20-poly1305",
        "kdf": "argon2id",
        "salt": "<base64-16-bytes>",
        "nonce": "<base64-12-bytes>"
    },
    "encrypted_anchor": "<base64-ciphertext>",
    "public_document": {
        "id": "aid_...",
        "public_key": "<base64-32-bytes>",
        "algorithm": "ed25519",
        "created_at": 1719840000000000,
        "name": "my-agent",
        "rotation_history": [],
        "attestations": [],
        "signature": "<base64-signature>"
    }
}
```

## Fields

### Top Level

| Field | Type | Description |
|:---|:---|:---|
| `version` | `u32` | Format version number. Currently `1`. |
| `format` | `string` | Format identifier. Must be `"aid-v1"`. |
| `encryption` | `object` | Encryption parameters needed for decryption. |
| `encrypted_anchor` | `string` | Base64-encoded ciphertext of the encrypted private data. |
| `public_document` | `object` | Public identity document (no private key material). |

### encryption

| Field | Type | Description |
|:---|:---|:---|
| `algorithm` | `string` | Symmetric cipher. Must be `"chacha20-poly1305"`. |
| `kdf` | `string` | Key derivation function. Must be `"argon2id"`. |
| `salt` | `string` | Base64-encoded Argon2id salt (16 bytes). |
| `nonce` | `string` | Base64-encoded ChaCha20-Poly1305 nonce (12 bytes). |

### public_document

| Field | Type | Description |
|:---|:---|:---|
| `id` | `string` | Identity ID (`aid_` + base58 hash). |
| `public_key` | `string` | Base64-encoded Ed25519 public key (32 bytes). |
| `algorithm` | `string` | Key algorithm. Must be `"ed25519"`. |
| `created_at` | `u64` | Creation timestamp in microseconds since Unix epoch. |
| `name` | `string?` | Optional human-readable name. |
| `rotation_history` | `array` | Array of `PublicKeyRotation` records. |
| `attestations` | `array` | Array of `Attestation` records. |
| `signature` | `string` | Base64-encoded self-signature over the document payload. |

### PublicKeyRotation

| Field | Type | Description |
|:---|:---|:---|
| `previous_key` | `string` | Base64-encoded previous public key. |
| `new_key` | `string` | Base64-encoded new public key. |
| `rotated_at` | `u64` | Rotation timestamp in microseconds. |
| `reason` | `string` | One of: `Scheduled`, `Compromised`, `DeviceLost`, `PolicyRequired`, `Manual`. |
| `authorization_signature` | `string` | Base64-encoded signature of the old key authorizing the rotation. |

### Attestation

| Field | Type | Description |
|:---|:---|:---|
| `attester` | `string` | Attester's identity ID. |
| `attester_key` | `string` | Attester's public key (base64). |
| `claim` | `object` | Attestation claim (see below). |
| `attested_at` | `u64` | Attestation timestamp in microseconds. |
| `signature` | `string` | Attester's signature over the claim (base64). |

Claim types: `KeyOwnership`, `NameVerification { name }`, `OrganizationMembership { org }`, `Custom { claim_type, claim_value }`.

## Encryption Pipeline

The encryption pipeline transforms a passphrase into the symmetric key used to encrypt the private anchor data.

### Save (Encryption)

```
passphrase (user input)
    |
    v
Argon2id(passphrase, salt)          salt = 16 random bytes
    |                               m_cost = 64 MiB
    |                               t_cost = 3 iterations
    v                               p_cost = 4 lanes
master_key (32 bytes)
    |
    v
HKDF-SHA256(master_key, "identity-encryption")
    |
    v
encryption_key (32 bytes)
    |
    v
ChaCha20-Poly1305(encryption_key, nonce, plaintext)
    |                               nonce = 12 random bytes
    v
ciphertext (variable length)
    |
    v
base64(ciphertext) -> encrypted_anchor field
```

### Load (Decryption)

```
passphrase (user input) + salt (from file) + nonce (from file)
    |
    v
Argon2id(passphrase, salt)          same parameters as save
    |
    v
master_key (32 bytes)
    |
    v
HKDF-SHA256(master_key, "identity-encryption")
    |
    v
encryption_key (32 bytes)
    |
    v
ChaCha20-Poly1305_decrypt(encryption_key, nonce, ciphertext)
    |
    v
plaintext JSON -> AnchorPrivateData
```

If the passphrase is wrong, ChaCha20-Poly1305 authentication will fail and the error `InvalidPassphrase` is returned. The wrong key never produces valid plaintext.

## Encrypted Private Data

The `encrypted_anchor` field, when decrypted, contains a JSON object with the following structure:

```json
{
    "signing_key_b64": "<base64-32-bytes>",
    "created_at": 1719840000000000,
    "name": "my-agent",
    "rotation_history": [
        {
            "previous_key": "<base64>",
            "new_key": "<base64>",
            "rotated_at": 1719840100000000,
            "reason": "Scheduled",
            "authorization_signature": "<base64>"
        }
    ]
}
```

| Field | Type | Description |
|:---|:---|:---|
| `signing_key_b64` | `string` | Base64-encoded Ed25519 signing key (32 bytes). |
| `created_at` | `u64` | Creation timestamp (microseconds). |
| `name` | `string?` | Optional identity name. |
| `rotation_history` | `array` | Full rotation history including authorization signatures. |

## Security Properties

### Key Zeroization

All intermediate key material is zeroized immediately after use:

- The Argon2id master key is zeroized after HKDF expansion.
- The HKDF-derived encryption key is zeroized after encrypt/decrypt.
- The plaintext private data buffer is zeroized after deserialization.
- The signing key bytes are zeroized after `IdentityAnchor` reconstruction.

### Atomic Writes

File writes use a temporary sibling file (`.aid.tmp`) and `rename()` to prevent partial writes. A crash during write never leaves a corrupt `.aid` file visible to readers.

### Tamper Detection

ChaCha20-Poly1305 is an AEAD cipher. If any byte of the ciphertext, nonce, or authentication tag is modified, decryption will fail with an authentication error. This prevents undetected tampering with the encrypted private key.

### Passphrase Strength

Argon2id with 64 MiB memory cost, 3 iterations, and 4 parallel lanes provides strong resistance against:

- **GPU attacks** -- high memory requirement makes GPU parallelism expensive.
- **ASIC attacks** -- memory-hard design resists custom hardware.
- **Dictionary attacks** -- each guess requires ~200-500 ms of computation.

### Public Document Availability

The public identity document is intentionally stored in plaintext. This enables:

- Identity inspection without the passphrase (`read_public_document`).
- Signature verification by third parties.
- Rotation history auditing.

No private key material is present in the public document.

## Self-Signature

The public document includes a self-signature over the following payload (JSON-serialized):

```json
{
    "id": "aid_...",
    "public_key": "<base64>",
    "algorithm": "ed25519",
    "created_at": 1719840000000000,
    "name": "my-agent"
}
```

The signature is an Ed25519 signature of this JSON string, encoded as base64. It proves that the document was created by the holder of the corresponding private key.

## Version History

| Version | Format | Description |
|:---|:---|:---|
| 1 | `aid-v1` | Initial release. ChaCha20-Poly1305 + Argon2id. |
