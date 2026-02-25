//! Secure random number generation.
//!
//! Uses the operating system's cryptographic random source via `rand`.

use rand::RngCore;

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

/// Generate a fixed-size array of cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill_random(&mut buf);
    buf
}

/// Generate a random 32-byte nonce.
pub fn random_nonce_32() -> [u8; 32] {
    random_bytes()
}

/// Generate a random 12-byte nonce (for ChaCha20-Poly1305).
pub fn random_nonce_12() -> [u8; 12] {
    random_bytes()
}

/// Generate a random 16-byte salt.
pub fn random_salt_16() -> [u8; 16] {
    random_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_not_zero() {
        let bytes: [u8; 32] = random_bytes();
        // Probability of all zeros is 2^-256; if this fails, something is very wrong
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_unique() {
        let a: [u8; 32] = random_bytes();
        let b: [u8; 32] = random_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
