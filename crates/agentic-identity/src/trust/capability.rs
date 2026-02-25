//! Capability URI parsing and wildcard matching.
//!
//! Capabilities use a URI scheme: `action:resource` with wildcards.
//! Examples:
//!   - `read:calendar` — read calendar specifically
//!   - `read:*` — read anything
//!   - `execute:deploy:production` — execute deploy to production
//!   - `execute:deploy:*` — execute deploy to any environment
//!   - `*` — all capabilities (root trust)

use serde::{Deserialize, Serialize};

/// A capability being granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Capability URI (e.g., "read:calendar", "execute:deploy:production").
    pub uri: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Capability-specific constraints (arbitrary JSON).
    pub constraints: Option<serde_json::Value>,
}

impl Capability {
    /// Create a new capability from a URI string.
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            description: None,
            constraints: None,
        }
    }

    /// Create a capability with a description.
    pub fn with_description(uri: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            description: Some(description.into()),
            constraints: None,
        }
    }

    /// Check whether this capability's URI covers (grants) a requested URI.
    ///
    /// Matching rules:
    /// - `*` matches everything
    /// - `action:*` matches any resource under `action:`
    /// - `action:resource` matches exactly
    /// - `action:resource:*` matches anything under `action:resource:`
    pub fn covers(&self, requested: &str) -> bool {
        capability_uri_covers(&self.uri, requested)
    }
}

impl PartialEq for Capability {
    fn eq(&self, other: &Self) -> bool {
        self.uri == other.uri
    }
}

impl Eq for Capability {}

/// Check whether a granted URI covers a requested URI.
///
/// This is the core wildcard matching logic for capability URIs.
pub fn capability_uri_covers(granted: &str, requested: &str) -> bool {
    // Universal wildcard
    if granted == "*" {
        return true;
    }

    // Exact match
    if granted == requested {
        return true;
    }

    // Wildcard suffix matching: "read:*" covers "read:calendar"
    if let Some(prefix) = granted.strip_suffix(":*") {
        // requested must start with the prefix followed by ':'
        if requested == prefix {
            return true;
        }
        if requested.starts_with(prefix) && requested.as_bytes().get(prefix.len()) == Some(&b':') {
            return true;
        }
    }

    // Wildcard suffix with path-like matching: "storage/*" covers "storage/files/readme.md"
    if let Some(prefix) = granted.strip_suffix("/*") {
        if requested == prefix {
            return true;
        }
        if requested.starts_with(prefix) && requested.as_bytes().get(prefix.len()) == Some(&b'/') {
            return true;
        }
    }

    false
}

/// Check if a set of granted capabilities covers a single requested capability URI.
pub fn capabilities_cover(granted: &[Capability], requested: &str) -> bool {
    granted.iter().any(|cap| cap.covers(requested))
}

/// Check if a set of granted capabilities covers ALL requested capability URIs.
pub fn capabilities_cover_all(granted: &[Capability], requested: &[&str]) -> bool {
    requested.iter().all(|req| capabilities_cover(granted, req))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(capability_uri_covers("read:calendar", "read:calendar"));
        assert!(!capability_uri_covers("read:calendar", "write:calendar"));
    }

    #[test]
    fn test_universal_wildcard() {
        assert!(capability_uri_covers("*", "read:calendar"));
        assert!(capability_uri_covers("*", "write:anything:at:all"));
        assert!(capability_uri_covers("*", "*"));
    }

    #[test]
    fn test_action_wildcard() {
        assert!(capability_uri_covers("read:*", "read:calendar"));
        assert!(capability_uri_covers("read:*", "read:email"));
        assert!(capability_uri_covers("read:*", "read:anything:nested"));
        assert!(!capability_uri_covers("read:*", "write:calendar"));
        assert!(!capability_uri_covers("read:*", "reading:calendar"));
    }

    #[test]
    fn test_nested_wildcard() {
        assert!(capability_uri_covers(
            "execute:deploy:*",
            "execute:deploy:production"
        ));
        assert!(capability_uri_covers(
            "execute:deploy:*",
            "execute:deploy:staging"
        ));
        assert!(!capability_uri_covers(
            "execute:deploy:*",
            "execute:build:production"
        ));
    }

    #[test]
    fn test_path_wildcard() {
        assert!(capability_uri_covers("storage/*", "storage/files"));
        assert!(capability_uri_covers(
            "storage/*",
            "storage/files/readme.md"
        ));
        assert!(!capability_uri_covers("storage/*", "other/files"));
    }

    #[test]
    fn test_no_partial_prefix_match() {
        // "read:*" should NOT match "reading:calendar"
        assert!(!capability_uri_covers("read:*", "reading:calendar"));
        // "read:cal" should NOT match "read:calendar" (no wildcard)
        assert!(!capability_uri_covers("read:cal", "read:calendar"));
    }

    #[test]
    fn test_capabilities_cover_set() {
        let caps = vec![Capability::new("read:*"), Capability::new("write:calendar")];
        assert!(capabilities_cover(&caps, "read:email"));
        assert!(capabilities_cover(&caps, "write:calendar"));
        assert!(!capabilities_cover(&caps, "write:email"));
    }

    #[test]
    fn test_capabilities_cover_all_set() {
        let caps = vec![Capability::new("read:*"), Capability::new("write:calendar")];
        assert!(capabilities_cover_all(
            &caps,
            &["read:email", "write:calendar"]
        ));
        assert!(!capabilities_cover_all(
            &caps,
            &["read:email", "write:email"]
        ));
    }

    #[test]
    fn test_capability_equality() {
        let a = Capability::new("read:calendar");
        let b = Capability::new("read:calendar");
        let c = Capability::with_description("read:calendar", "Can read calendar events");
        assert_eq!(a, b);
        // Equality is based on URI only
        assert_eq!(a, c);
    }
}
