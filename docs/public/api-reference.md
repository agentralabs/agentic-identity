---
title: API Reference
description: Complete API documentation for the agentic-identity Rust library
order: 4
---

# API Reference

This document covers the public API of the `agentic-identity` crate. The crate is organized into four top-level modules: `identity`, `receipt`, `trust`, and `crypto`.

---

## identity

### IdentityId

Unique identifier for an identity. Format: `aid_` + base58 of first 16 bytes of SHA-256(public_key).

```rust
pub struct IdentityId(pub String);
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `from_verifying_key` | `fn from_verifying_key(key: &VerifyingKey) -> Self` | Compute an identity ID from a public key |
| `Display` | impl Display | Formats as the inner string |

### IdentityAnchor

The root cryptographic identity. Contains an Ed25519 key pair, creation timestamp, optional name, and rotation history. The signing key is zeroized on drop.

```rust
pub struct IdentityAnchor {
    pub created_at: u64,
    pub name: Option<String>,
    pub rotation_history: Vec<KeyRotation>,
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `new` | `fn new(name: Option<String>) -> Self` | Create a new anchor with a fresh key pair |
| `from_parts` | `fn from_parts(signing_key_bytes: &[u8; 32], created_at: u64, name: Option<String>, rotation_history: Vec<KeyRotation>) -> Result<Self>` | Reconstruct from existing key bytes and metadata |
| `id` | `fn id(&self) -> IdentityId` | Return the identity ID (derived from public key) |
| `signing_key` | `fn signing_key(&self) -> &SigningKey` | Return a reference to the Ed25519 signing key |
| `verifying_key` | `fn verifying_key(&self) -> &VerifyingKey` | Return the verifying (public) key |
| `signing_key_bytes` | `fn signing_key_bytes(&self) -> [u8; 32]` | Return signing key bytes (caller must zeroize) |
| `verifying_key_bytes` | `fn verifying_key_bytes(&self) -> [u8; 32]` | Return verifying key bytes |
| `public_key_base64` | `fn public_key_base64(&self) -> String` | Return the public key as base64 |
| `derive_session_key` | `fn derive_session_key(&self, session_id: &str) -> Result<SigningKey>` | Derive a scoped signing key for a session |
| `derive_capability_key` | `fn derive_capability_key(&self, capability_uri: &str) -> Result<SigningKey>` | Derive a scoped signing key for a capability |
| `derive_device_key` | `fn derive_device_key(&self, device_id: &str) -> Result<SigningKey>` | Derive a scoped signing key for a device |
| `derive_revocation_key` | `fn derive_revocation_key(&self, trust_id: &str) -> Result<SigningKey>` | Derive a revocation signing key for a trust grant |
| `rotate` | `fn rotate(&self, reason: RotationReason) -> Result<Self>` | Rotate the root key, returning a new anchor |
| `to_document` | `fn to_document(&self) -> IdentityDocument` | Generate the public identity document |

### IdentityDocument

Public identity document (shareable, does not contain private keys). Self-signed by the identity's key.

```rust
pub struct IdentityDocument {
    pub id: IdentityId,
    pub public_key: String,        // base64
    pub algorithm: String,         // "ed25519"
    pub created_at: u64,
    pub name: Option<String>,
    pub rotation_history: Vec<PublicKeyRotation>,
    pub attestations: Vec<Attestation>,
    pub signature: String,         // base64
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `verify_signature` | `fn verify_signature(&self) -> Result<()>` | Verify the self-signature on this document |

### RotationReason

Reason for key rotation.

```rust
pub enum RotationReason {
    Scheduled,
    Compromised,
    DeviceLost,
    PolicyRequired,
    Manual,
}
```

### KeyRotation

Record of a key rotation. Stored in the anchor's rotation history.

```rust
pub struct KeyRotation {
    pub previous_key: String,              // base64
    pub new_key: String,                   // base64
    pub rotated_at: u64,                   // microseconds
    pub reason: RotationReason,
    pub authorization_signature: String,   // base64
}
```

---

## receipt

### ActionType

Type of action being recorded.

```rust
pub enum ActionType {
    Decision,
    Observation,
    Mutation,
    Delegation,
    Revocation,
    IdentityOperation,
    Custom(String),
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `as_tag` | `fn as_tag(&self) -> &str` | Return a stable string tag for hashing |

### ActionContent

Content of an action.

```rust
pub struct ActionContent {
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub references: Vec<String>,
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `new` | `fn new(description: impl Into<String>) -> Self` | Create with just a description |
| `with_data` | `fn with_data(description: impl Into<String>, data: serde_json::Value) -> Self` | Create with description and structured data |

### ReceiptId

Unique identifier for a receipt. Format: `arec_` + base58 of first 16 bytes of SHA-256(receipt_hash).

```rust
pub struct ReceiptId(pub String);
```

### ActionReceipt

A signed proof that an agent took an action.

```rust
pub struct ActionReceipt {
    pub id: ReceiptId,
    pub actor: IdentityId,
    pub actor_key: String,               // base64
    pub action_type: ActionType,
    pub action: ActionContent,
    pub timestamp: u64,                  // microseconds
    pub context_hash: Option<String>,
    pub previous_receipt: Option<ReceiptId>,
    pub receipt_hash: String,            // hex SHA-256
    pub signature: String,               // base64
    pub witnesses: Vec<WitnessSignature>,
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `add_witness` | `fn add_witness(&mut self, witness: WitnessSignature)` | Add a witness signature |

### ReceiptBuilder

Builder for creating action receipts.

```rust
pub struct ReceiptBuilder { /* private */ }
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `new` | `fn new(actor: IdentityId, action_type: ActionType, action: ActionContent) -> Self` | Start building a receipt |
| `context_hash` | `fn context_hash(self, hash: String) -> Self` | Set the context hash |
| `chain_to` | `fn chain_to(self, previous: ReceiptId) -> Self` | Chain this receipt to a previous one |
| `sign` | `fn sign(self, signing_key: &SigningKey) -> Result<ActionReceipt>` | Sign and finalize the receipt |

### ReceiptVerification

Result of verifying a receipt.

```rust
pub struct ReceiptVerification {
    pub signature_valid: bool,
    pub chain_valid: Option<bool>,
    pub witnesses_valid: Vec<bool>,
    pub is_valid: bool,
    pub verified_at: u64,
}
```

### verify_receipt

```rust
pub fn verify_receipt(receipt: &ActionReceipt) -> Result<ReceiptVerification>
```

Verify that a receipt's signature (and any witness signatures) are valid.

### verify_chain

```rust
pub fn verify_chain(chain: &[ActionReceipt]) -> Result<bool>
```

Verify a chain of receipts ordered from oldest to newest. Checks every signature and the chain linkage between consecutive receipts.

### WitnessSignature

A witness co-signature on a receipt.

```rust
pub struct WitnessSignature {
    pub witness: IdentityId,
    pub witness_key: String,     // base64
    pub witnessed_at: u64,
    pub signature: String,       // base64
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `create` | `fn create(witness_id: IdentityId, signing_key: &SigningKey, receipt_hash: &str) -> Self` | Create a witness signature |

---

## trust

### Capability

A capability being granted.

```rust
pub struct Capability {
    pub uri: String,
    pub description: Option<String>,
    pub constraints: Option<serde_json::Value>,
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `new` | `fn new(uri: impl Into<String>) -> Self` | Create from a URI string |
| `with_description` | `fn with_description(uri: impl Into<String>, description: impl Into<String>) -> Self` | Create with a description |
| `covers` | `fn covers(&self, requested: &str) -> bool` | Check if this capability covers a requested URI |

**Standalone functions:**

| Function | Signature | Description |
|:---|:---|:---|
| `capabilities_cover` | `fn capabilities_cover(granted: &[Capability], requested: &str) -> bool` | Check if any granted capability covers a request |
| `capabilities_cover_all` | `fn capabilities_cover_all(granted: &[Capability], requested: &[&str]) -> bool` | Check if grants cover ALL requests |

### TrustConstraints

Constraints on a trust grant.

```rust
pub struct TrustConstraints {
    pub not_before: u64,
    pub not_after: Option<u64>,
    pub max_uses: Option<u64>,
    pub geographic: Option<Vec<String>>,
    pub ip_allowlist: Option<Vec<String>>,
    pub custom: Option<serde_json::Value>,
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `open` | `fn open() -> Self` | Valid immediately with no expiry |
| `time_bounded` | `fn time_bounded(not_before: u64, not_after: u64) -> Self` | Valid within a specific time window |
| `with_max_uses` | `fn with_max_uses(self, max: u64) -> Self` | Add a maximum use count |
| `validate` | `fn validate(&self, now: u64, current_uses: u64) -> Result<()>` | Check all constraints |
| `is_time_valid` | `fn is_time_valid(&self, now: u64) -> bool` | Check time window only |
| `is_within_uses` | `fn is_within_uses(&self, current_uses: u64) -> bool` | Check use count only |

### TrustId

Unique identifier for a trust grant. Format: `atrust_` + base58 of first 16 bytes of SHA-256(grant_hash).

```rust
pub struct TrustId(pub String);
```

### TrustGrant

A signed trust relationship between two identities.

```rust
pub struct TrustGrant {
    pub id: TrustId,
    pub grantor: IdentityId,
    pub grantor_key: String,                  // base64
    pub grantee: IdentityId,
    pub grantee_key: String,                  // base64
    pub capabilities: Vec<Capability>,
    pub constraints: TrustConstraints,
    pub delegation_allowed: bool,
    pub max_delegation_depth: Option<u32>,
    pub parent_grant: Option<TrustId>,
    pub delegation_depth: u32,
    pub revocation: RevocationConfig,
    pub granted_at: u64,
    pub grant_hash: String,                   // hex SHA-256
    pub grantor_signature: String,            // base64
    pub grantee_acknowledgment: Option<String>, // base64
}
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `verify_signature` | `fn verify_signature(&self) -> Result<()>` | Verify the grantor's signature |
| `acknowledge` | `fn acknowledge(&mut self, grantee_signing_key: &SigningKey) -> Result<()>` | Add the grantee's acknowledgment signature |

### TrustGrantBuilder

Builder for creating trust grants.

```rust
pub struct TrustGrantBuilder { /* private */ }
```

**Methods:**

| Method | Signature | Description |
|:---|:---|:---|
| `new` | `fn new(grantor: IdentityId, grantee: IdentityId, grantee_key: String) -> Self` | Start building a trust grant |
| `capability` | `fn capability(self, cap: Capability) -> Self` | Add a capability |
| `capabilities` | `fn capabilities(self, caps: Vec<Capability>) -> Self` | Add multiple capabilities |
| `constraints` | `fn constraints(self, constraints: TrustConstraints) -> Self` | Set the constraints |
| `allow_delegation` | `fn allow_delegation(self, max_depth: u32) -> Self` | Allow the grantee to delegate |
| `delegated_from` | `fn delegated_from(self, parent: TrustId, depth: u32) -> Self` | Mark as delegated from a parent |
| `revocation_channel` | `fn revocation_channel(self, channel: RevocationChannel) -> Self` | Set the revocation channel |
| `revocation_witnesses` | `fn revocation_witnesses(self, witnesses: Vec<IdentityId>) -> Self` | Set required revocation witnesses |
| `sign` | `fn sign(self, grantor_signing_key: &SigningKey) -> Result<TrustGrant>` | Sign and finalize the grant |

### TrustVerification

Result of verifying a trust grant.

```rust
pub struct TrustVerification {
    pub signature_valid: bool,
    pub time_valid: bool,
    pub not_revoked: bool,
    pub uses_valid: bool,
    pub capability_granted: bool,
    pub trust_chain: Vec<TrustId>,
    pub is_valid: bool,
    pub verified_at: u64,
}
```

### verify_trust_grant

```rust
pub fn verify_trust_grant(
    grant: &TrustGrant,
    requested_capability: &str,
    current_uses: u64,
    revocations: &[Revocation],
) -> Result<TrustVerification>
```

Verify a trust grant for a specific capability at the current time.

### is_grant_valid

```rust
pub fn is_grant_valid(
    grant: &TrustGrant,
    requested_capability: &str,
    current_uses: u64,
    revocations: &[Revocation],
) -> bool
```

Convenience function: returns `true` if the grant is valid for the requested capability.

### verify_trust_chain

```rust
pub fn verify_trust_chain(
    chain: &[TrustGrant],
    requested_capability: &str,
    revocations: &[Revocation],
) -> Result<TrustVerification>
```

Verify a delegation chain from root to leaf. Each link must be signed, time-valid, not revoked, capability-covering, and properly delegated.

### validate_delegation

```rust
pub fn validate_delegation(
    parent_grant: &TrustGrant,
    requested_capabilities: &[Capability],
) -> Result<()>
```

Check whether a delegation from a parent grant would be valid: delegation must be allowed, depth must not be exceeded, and capabilities must be covered.

### Revocation

```rust
pub struct Revocation {
    pub trust_id: TrustId,
    pub revoked_by: IdentityId,
    pub reason: RevocationReason,
    pub revoked_at: u64,
    pub signature: String,
}
```

### RevocationReason

```rust
pub enum RevocationReason {
    ManualRevocation,
    PolicyViolation,
    KeyCompromise,
    Expired,
    Superseded,
}
```

### RevocationChannel

Where revocation is published.

```rust
pub enum RevocationChannel {
    Local,
    Http { url: String },
    Ledger { ledger_id: String },
    Multi(Vec<RevocationChannel>),
}
```

---

## crypto

Low-level cryptographic operations. Most users should use the higher-level `identity`, `receipt`, and `trust` APIs.

### keys

| Function | Description |
|:---|:---|
| `Ed25519KeyPair::generate()` | Generate a fresh Ed25519 key pair |
| `Ed25519KeyPair::from_signing_key_bytes(&[u8; 32])` | Reconstruct from existing key bytes |
| `Ed25519KeyPair::verifying_key_from_bytes(&[u8; 32])` | Reconstruct a verifying key from bytes |

### signing

| Function | Description |
|:---|:---|
| `sign(key: &SigningKey, message: &[u8]) -> Signature` | Sign a message |
| `verify(key: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<()>` | Verify a signature |
| `sign_to_base64(key: &SigningKey, message: &[u8]) -> String` | Sign and return base64-encoded signature |
| `verify_from_base64(key: &VerifyingKey, message: &[u8], sig_b64: &str) -> Result<()>` | Verify a base64-encoded signature |

### derivation

| Function | Description |
|:---|:---|
| `derive_key(root: &[u8; 32], context: &str) -> Result<[u8; 32]>` | Derive a 32-byte child key via HKDF-SHA256 |
| `derive_signing_key(root: &[u8; 32], context: &str) -> Result<SigningKey>` | Derive an Ed25519 signing key |
| `session_context(session_id: &str) -> String` | Build derivation path for a session key |
| `capability_context(uri: &str) -> String` | Build derivation path for a capability key |
| `device_context(device_id: &str) -> String` | Build derivation path for a device key |

### encryption

| Function | Description |
|:---|:---|
| `derive_passphrase_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]>` | Argon2id passphrase-based key derivation |
| `encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>` | ChaCha20-Poly1305 encrypt; returns (nonce, ciphertext) |
| `decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>` | ChaCha20-Poly1305 decrypt |
| `encrypt_with_passphrase(passphrase: &[u8], plaintext: &[u8]) -> Result<([u8; 16], Vec<u8>, Vec<u8>)>` | Encrypt with passphrase; returns (salt, nonce, ciphertext) |
| `decrypt_with_passphrase(passphrase: &[u8], salt: &[u8; 16], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>` | Decrypt with passphrase |

---

## storage

### File Operations

| Function | Signature | Description |
|:---|:---|:---|
| `save_identity` | `fn save_identity(anchor: &IdentityAnchor, path: &Path, passphrase: &str) -> Result<()>` | Save identity to `.aid` file with passphrase encryption |
| `load_identity` | `fn load_identity(path: &Path, passphrase: &str) -> Result<IdentityAnchor>` | Load identity from `.aid` file with passphrase decryption |
| `read_public_document` | `fn read_public_document(path: &Path) -> Result<IdentityDocument>` | Read only the public document (no passphrase needed) |

---

## error

### IdentityError

All errors are strongly typed. Private key material is never included in error messages.

```rust
pub enum IdentityError {
    InvalidKey(String),
    SignatureInvalid,
    NotFound(String),
    DerivationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidPassphrase,
    TrustNotGranted(String),
    TrustRevoked(String),
    TrustExpired,
    TrustNotYetValid,
    MaxUsesExceeded,
    DelegationNotAllowed,
    DelegationDepthExceeded,
    InvalidChain,
    StorageError(String),
    SerializationError(String),
    InvalidFileFormat(String),
    Io(std::io::Error),
}
```

```rust
pub type Result<T> = std::result::Result<T, IdentityError>;
```
