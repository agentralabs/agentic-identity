//! Error types for AgenticIdentity.
//!
//! All errors are strongly typed and propagated without panicking.
//! Private key material is never included in error messages.

/// Identity error types covering all operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("Identity not found: {0}")]
    NotFound(String),

    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid passphrase")]
    InvalidPassphrase,

    #[error("Trust not granted for capability: {0}")]
    TrustNotGranted(String),

    #[error("Trust has been revoked: {0}")]
    TrustRevoked(String),

    #[error("Trust expired")]
    TrustExpired,

    #[error("Trust not yet valid")]
    TrustNotYetValid,

    #[error("Max uses exceeded")]
    MaxUsesExceeded,

    #[error("Delegation not allowed")]
    DelegationNotAllowed,

    #[error("Delegation depth exceeded")]
    DelegationDepthExceeded,

    #[error("Invalid receipt chain")]
    InvalidChain,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid file format: {0}")]
    InvalidFileFormat(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Competence not met for {domain}: required {required_rate}%, actual {actual_rate}%")]
    CompetenceNotMet {
        domain: String,
        required_rate: f32,
        actual_rate: f32,
    },

    #[error("Insufficient attempts: required {required}, actual {actual}")]
    InsufficientAttempts { required: u64, actual: u64 },

    #[error("Competence proof expired")]
    CompetenceProofExpired,

    #[error("Cannot prove impossibility: identity CAN do {capability}")]
    NotImpossible { capability: String },

    #[error("Invalid negative proof: {reason}")]
    InvalidNegativeProof { reason: String },

    #[error("Permanent declaration cannot be revoked")]
    PermanentDeclaration,
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, IdentityError>;
