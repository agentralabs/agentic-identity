
# Frequently Asked Questions

## Identity

### What is an identity anchor?

An identity anchor is an Ed25519 key pair that serves as the permanent cryptographic root of an agent's identity. The public key IS the identity -- it is mathematically unique, unforgeable, and portable across systems. The identity ID is derived from the public key: `aid_` + base58(SHA-256(public_key)[0..16]).

### Can two agents have the same identity?

No. Each identity anchor generates a fresh Ed25519 key pair from a cryptographically secure random number generator. The probability of collision is approximately 2^-128, which is negligible in practice.

### What happens if the private key is compromised?

Use key rotation immediately with `RotationReason::Compromised`. The old key signs an authorization transferring trust to the new key, and the rotation is recorded in the identity's rotation history. Any trust grants signed with the old key remain verifiable through the rotation chain, but new operations use the new key.

### How does key rotation work?

Key rotation generates a new Ed25519 key pair and has the old key sign an authorization message proving the rotation was intentional. The rotation record includes: the old public key, the new public key, the timestamp, the reason, and the authorization signature. Multiple rotations accumulate in the rotation history, creating a verifiable chain of key custody.

### What are derived keys?

Derived keys are child signing keys generated from the root key using HKDF-SHA256 with context-specific derivation paths. There are three types:

- **Session keys** -- scoped to a single session (path: `agentic-identity/session/{session_id}`)
- **Capability keys** -- scoped to a specific capability (path: `agentic-identity/capability/{uri}`)
- **Device keys** -- scoped to a specific device (path: `agentic-identity/device/{device_id}`)

Derived keys are deterministic: the same root key and context always produce the same child key. Compromising a derived key does not expose the root key.

## Action Receipts

### What is an action receipt?

An action receipt is a signed, timestamped proof that a specific agent took a specific action. It includes the actor's identity and public key, the action type and content, a SHA-256 content hash, and an Ed25519 signature over that hash. Receipts are non-repudiable: the agent cannot deny having taken the action.

### What action types are supported?

Built-in types: `Decision`, `Observation`, `Mutation`, `Delegation`, `Revocation`, `IdentityOperation`. You can also use `Custom("your-type")` for domain-specific actions.

### How does receipt chaining work?

Each receipt can reference a previous receipt by ID using `chain_to()`. This creates a linked sequence where each link is individually signed. Chain verification (`verify_chain`) checks every signature AND the linkage -- if any receipt is tampered with or a link is broken, the entire chain fails verification.

### Can different agents contribute to the same chain?

Yes. Receipt chaining only requires that each receipt references the correct previous receipt ID. Different agents can sign different links in the chain, enabling multi-agent audit trails.

### What is a witness signature?

A witness is a second identity that co-signs a receipt. Witness signatures provide additional assurance that the action was observed by a third party. Witnesses are verified alongside the primary signature during receipt verification.

## Trust

### How do trust grants work?

A trust grant is a cryptographic statement: "Identity A trusts Identity B to do {capabilities} under {constraints}." It is signed by A's private key and includes B's public key for binding. Verification checks the signature, time validity, revocation status, use count, and capability match.

### What are capability URIs?

Capabilities are expressed as colon-delimited URI strings with wildcard support:

| Pattern | Matches |
|:---|:---|
| `read:calendar` | Exactly `read:calendar` |
| `read:*` | Any `read:...` capability |
| `execute:deploy:*` | Any `execute:deploy:...` capability |
| `*` | Everything (root trust) |

### How does delegation work?

When a trust grant has `delegation_allowed: true`, the grantee can create a new trust grant passing their trust to a third party. The delegation chain is verified end-to-end: every link must have a valid signature, the delegator must have delegation rights, and the delegation depth must not exceed the limit set by the root grant.

### What is the maximum delegation depth?

The root grantor sets the maximum depth when creating the grant via `allow_delegation(max_depth)`. A depth of 1 means the grantee can delegate once (A -> B -> C). A depth of 0 means no delegation. There is no hard upper limit, but deeper chains take linearly more time to verify.

### How does revocation work?

A revocation record is created by signing the trust grant ID with the grantor's key. When verifying a trust grant, you pass the list of known revocations. If the grant's ID appears in the revocation list, verification returns `not_revoked: false` and `is_valid: false`. Revoking any link in a delegation chain invalidates the entire chain downstream.

### Can a revoked grant be un-revoked?

No. Revocation is permanent. To restore access, create a new trust grant. This is a deliberate design choice -- revocation must be reliable and irreversible for security guarantees to hold.

## Security

### What cryptographic algorithms are used?

| Purpose | Algorithm |
|:---|:---|
| Identity keys | Ed25519 (RFC 8032) |
| Signing | Ed25519 |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Hashing | SHA-256 |
| Private key encryption at rest | ChaCha20-Poly1305 (RFC 8439) |
| Passphrase-based key derivation | Argon2id (RFC 9106) |
| Content addressing | SHA-256 |
| ID encoding | Base58, Base64 |

### Is private key material ever exposed?

No. Signing keys are zeroized on drop. The `.aid` file format encrypts private keys at rest with ChaCha20-Poly1305. Intermediate key material (Argon2id output, HKDF output) is zeroized immediately after use. Error messages never include private key data.

### What Argon2id parameters are used?

The passphrase-based key derivation uses Argon2id with: memory cost = 64 MiB, time cost = 3 iterations, parallelism = 4 lanes. These parameters provide strong resistance against GPU and ASIC brute-force attacks while remaining practical on consumer hardware.

### Is there a formal security model?

The security model is based on standard cryptographic primitives with well-understood properties. Ed25519 provides 128-bit security against key recovery. HKDF-SHA256 provides secure key derivation. ChaCha20-Poly1305 provides authenticated encryption. Argon2id provides memory-hard passphrase stretching. No custom cryptography is used.

## Storage

### What is the `.aid` file format?

The `.aid` file is a JSON document containing: a version number, encryption metadata (algorithm, KDF, salt, nonce), the encrypted private key blob (base64-encoded ChaCha20-Poly1305 ciphertext), and the plaintext public identity document. The public document can be read without the passphrase.

### Can I inspect an identity file without the passphrase?

Yes. The public identity document (ID, public key, name, rotation history) is stored in plaintext within the `.aid` file. Use `read_public_document(path)` or `aid inspect <file>` to view it. Only decrypting the private key requires the passphrase.

### Are writes atomic?

Yes. File writes use a temporary sibling file and `rename()` to ensure that a crash during write never leaves a partially-written file visible to readers.

## Performance

### How fast is signing?

Ed25519 signing takes approximately 9.17 microseconds. Receipt signing (which includes hashing, ID generation, and Ed25519 signing) takes approximately 11.55 microseconds. These numbers are from Criterion statistical benchmarks on standard hardware.

### How fast is verification?

Ed25519 verification takes approximately 19.34 microseconds. Receipt verification takes approximately 21.77 microseconds. Trust chain verification scales linearly with chain depth -- a depth-2 chain takes approximately 43.51 microseconds.

### What is the bottleneck?

Ed25519 verification is the dominant cost in all verification paths. Key derivation via HKDF is sub-microsecond (972 ns). File I/O (passphrase-based decryption) is dominated by the intentionally slow Argon2id computation, which takes approximately 200-500 ms depending on hardware -- this is by design to resist brute-force attacks.

## Compatibility

### What Rust edition and MSRV does this require?

Rust 2021 edition. The minimum supported Rust version tracks the latest stable release minus two.

### Does this work on embedded systems?

The core library uses `std` and is designed for server and desktop environments. A `no_std` port is not currently available but the cryptographic primitives (Ed25519, HKDF, ChaCha20) are available in `no_std` form from the underlying crate ecosystem.

### Can I use this with non-Rust agents?

Yes. The C FFI layer exposes all core operations and can be called from any language with C interop: Python, Swift, Go, Ruby, Java/JNI, C#, etc. The Python package provides a ready-made wrapper.
