
# API Reference

This document covers the public API of the `agentic-identity` crate. The crate is organized into four top-level modules: `identity`, `receipt`, `trust`, and `crypto`.
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
