//! Conservation tests for AgenticIdentity.
//!
//! Exercises cache and metrics modules to verify token conservation
//! properties hold across the foundation layer.
//!
//! Note: Identity uses domain-specific query types (ReceiptQuery, TrustQuery)
//! rather than the standard ExtractionIntent/TokenBudget pattern.

use std::time::Duration;

use agentic_identity::cache::LruCache;
use agentic_identity::metrics::tokens::{Layer, TokenMetrics};

// ---------------------------------------------------------------------------
// Test 1: Cache hit is cheaper than miss
// ---------------------------------------------------------------------------

#[test]
fn test_cache_hit_cheaper() {
    let mut cache: LruCache<String, String> = LruCache::new(100, Duration::from_secs(300));

    // First access: miss
    assert!(cache.get(&"key1".to_string()).is_none());

    // Insert
    cache.insert("key1".to_string(), "value1".to_string());

    // Second access: hit (0 token cost)
    assert!(cache.get(&"key1".to_string()).is_some());

    // Verify metrics
    assert!(cache.metrics().hits() >= 1);
    assert!(cache.metrics().misses() >= 1);
    assert!(cache.metrics().hit_rate() > 0.0);
}

// ---------------------------------------------------------------------------
// Test 2: Layer cost ordering
// ---------------------------------------------------------------------------

#[test]
fn test_layer_cost_ordering() {
    // Verify that the Layer enum has the expected variants and that
    // Full is the most expensive. We test via TokenMetrics recording.
    let metrics = TokenMetrics::new();

    // Record at Cache layer (cheapest)
    metrics.record(Layer::Cache, 0, 100);
    assert_eq!(metrics.total_tokens(), 0);
    assert_eq!(metrics.total_savings(), 100);

    // Record at Full layer (most expensive)
    metrics.record(Layer::Full, 100, 100);
    assert_eq!(metrics.total_tokens(), 100);
    // Full layer savings go to no bucket, so total_savings stays at 100
    assert_eq!(metrics.total_savings(), 100);
}

// ---------------------------------------------------------------------------
// Test 3: Query module — ReceiptQuery default is conservative
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_query_default() {
    use agentic_identity::query::ReceiptQuery;

    let q = ReceiptQuery::default();
    // Default query has no filters, which is the broadest but structurally
    // cheapest form (no chain traversal, no timestamp filtering)
    assert!(q.actor.is_none());
    assert!(q.action_type.is_none());
    assert!(q.time_range.is_none());
    assert!(q.chain_root.is_none());
    // Default limit is None (unbounded)
    assert!(q.limit.is_none());
}

// ---------------------------------------------------------------------------
// Test 4: Conservation score
// ---------------------------------------------------------------------------

#[test]
fn test_conservation_score() {
    let metrics = TokenMetrics::new();

    // Full retrieval: 100 tokens used, potential was 100
    metrics.record(Layer::Full, 100, 100);

    // Cache hit: 0 tokens used, potential was 400
    metrics.record(Layer::Cache, 0, 400);

    // total_tokens = 100, cache_savings = 400, total_savings = 400
    // conservation = 400 / (100 + 400) = 0.8
    let score = metrics.conservation_score();
    assert!(
        score > 0.7 && score < 0.9,
        "Conservation score should be ~0.8, got {}",
        score
    );
}

// ---------------------------------------------------------------------------
// Test 5: Cache invalidation
// ---------------------------------------------------------------------------

#[test]
fn test_cache_invalidation() {
    let mut cache: LruCache<String, i32> = LruCache::new(100, Duration::from_secs(300));

    cache.insert("key".to_string(), 42);
    assert!(cache.contains(&"key".to_string()));

    // Invalidate the entry
    assert!(cache.invalidate(&"key".to_string()));
    assert!(!cache.contains(&"key".to_string()));

    // Double invalidation returns false
    assert!(!cache.invalidate(&"key".to_string()));
}
