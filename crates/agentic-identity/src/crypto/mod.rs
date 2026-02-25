//! Cryptographic primitives for AgenticIdentity.
//!
//! This module provides:
//! - Ed25519 key generation, signing, and verification
//! - X25519 Diffie-Hellman key exchange
//! - HKDF-SHA256 key derivation
//! - Argon2id passphrase-based key derivation
//! - ChaCha20-Poly1305 authenticated encryption
//! - Cryptographically secure random number generation

pub mod derivation;
pub mod encryption;
pub mod keys;
pub mod random;
pub mod signing;
