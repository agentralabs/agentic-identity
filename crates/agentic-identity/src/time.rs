//! Time utilities for AgenticIdentity.
//!
//! All timestamps are Unix epoch microseconds (u64).

/// Return the current time as microseconds since Unix epoch.
pub fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_micros() as u64
}

/// Convert microseconds to an RFC 3339 string.
pub fn micros_to_rfc3339(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let nsecs = ((micros % 1_000_000) * 1000) as u32;
    let dt = chrono::DateTime::from_timestamp(secs, nsecs).unwrap_or(chrono::DateTime::UNIX_EPOCH);
    dt.to_rfc3339()
}
