//! Trust constraints — time, scope, and count limits.
//!
//! Constraints define the boundaries of a trust grant: when it becomes
//! valid, when it expires, how many times it can be used, and any
//! additional custom restrictions.

use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};

/// Constraints on a trust grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConstraints {
    /// Not valid before this time (microseconds since epoch).
    pub not_before: u64,
    /// Not valid after this time (None = until revoked).
    pub not_after: Option<u64>,
    /// Maximum number of uses (None = unlimited).
    pub max_uses: Option<u64>,
    /// Geographic constraints (optional).
    pub geographic: Option<Vec<String>>,
    /// IP allowlist constraints (optional).
    pub ip_allowlist: Option<Vec<String>>,
    /// Custom constraints (arbitrary JSON).
    pub custom: Option<serde_json::Value>,
}

impl TrustConstraints {
    /// Create constraints that are valid immediately with no expiry.
    pub fn open() -> Self {
        Self {
            not_before: crate::time::now_micros(),
            not_after: None,
            max_uses: None,
            geographic: None,
            ip_allowlist: None,
            custom: None,
        }
    }

    /// Create constraints with a specific time window.
    pub fn time_bounded(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after: Some(not_after),
            max_uses: None,
            geographic: None,
            ip_allowlist: None,
            custom: None,
        }
    }

    /// Add a maximum use count.
    pub fn with_max_uses(mut self, max: u64) -> Self {
        self.max_uses = Some(max);
        self
    }

    /// Check if the constraints are satisfied at the given time with the given use count.
    pub fn validate(&self, now: u64, current_uses: u64) -> Result<()> {
        // Time: not before
        if now < self.not_before {
            return Err(IdentityError::TrustNotYetValid);
        }

        // Time: not after
        if let Some(expiry) = self.not_after {
            if now > expiry {
                return Err(IdentityError::TrustExpired);
            }
        }

        // Use count
        if let Some(max) = self.max_uses {
            if current_uses >= max {
                return Err(IdentityError::MaxUsesExceeded);
            }
        }

        Ok(())
    }

    /// Check if the grant is within its time window at the given time.
    pub fn is_time_valid(&self, now: u64) -> bool {
        if now < self.not_before {
            return false;
        }
        if let Some(expiry) = self.not_after {
            if now > expiry {
                return false;
            }
        }
        true
    }

    /// Check if the use count is within limits.
    pub fn is_within_uses(&self, current_uses: u64) -> bool {
        match self.max_uses {
            Some(max) => current_uses < max,
            None => true,
        }
    }
}

impl Default for TrustConstraints {
    fn default() -> Self {
        Self::open()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_constraints() {
        let c = TrustConstraints::open();
        let now = crate::time::now_micros();
        assert!(c.validate(now, 0).is_ok());
        assert!(c.is_time_valid(now));
        assert!(c.is_within_uses(999));
    }

    #[test]
    fn test_time_bounded_valid() {
        let now = crate::time::now_micros();
        let c = TrustConstraints::time_bounded(now - 1_000_000, now + 1_000_000);
        assert!(c.validate(now, 0).is_ok());
    }

    #[test]
    fn test_time_bounded_expired() {
        let now = crate::time::now_micros();
        let c = TrustConstraints::time_bounded(now - 2_000_000, now - 1_000_000);
        let result = c.validate(now, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdentityError::TrustExpired));
    }

    #[test]
    fn test_time_bounded_not_yet_valid() {
        let now = crate::time::now_micros();
        let c = TrustConstraints::time_bounded(now + 1_000_000, now + 2_000_000);
        let result = c.validate(now, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::TrustNotYetValid
        ));
    }

    #[test]
    fn test_max_uses() {
        let c = TrustConstraints::open().with_max_uses(3);
        let now = crate::time::now_micros();
        assert!(c.validate(now, 0).is_ok());
        assert!(c.validate(now, 1).is_ok());
        assert!(c.validate(now, 2).is_ok());
        let result = c.validate(now, 3);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::MaxUsesExceeded
        ));
    }

    #[test]
    fn test_is_within_uses() {
        let c = TrustConstraints::open().with_max_uses(5);
        assert!(c.is_within_uses(0));
        assert!(c.is_within_uses(4));
        assert!(!c.is_within_uses(5));
        assert!(!c.is_within_uses(10));
    }

    #[test]
    fn test_unlimited_uses() {
        let c = TrustConstraints::open();
        assert!(c.is_within_uses(u64::MAX));
    }
}
