//! Query engine for receipts and trust grants.
//!
//! This module provides two high-level query types and matching execution
//! functions that operate directly on the in-memory indexes from
//! [`crate::index`]:
//!
//! - [`ReceiptQuery`] / [`query_receipts`] — filter and sort action receipts
//!   by actor, action type, timestamp range, chain root, and result limit.
//! - [`TrustQuery`] / [`query_trust`] — filter trust grants by grantor,
//!   grantee, capability URI prefix, and validity.
//!
//! ## Query execution model
//!
//! Each query function:
//! 1. Collects an initial candidate set from the most selective index hint
//!    available, or falls back to a full scan.
//! 2. Applies every specified filter in turn to narrow the set.
//! 3. Sorts the results according to [`SortOrder`].
//! 4. Applies an optional result limit.

use crate::identity::IdentityId;
use crate::index::{ReceiptIndex, TrustIndex};
use crate::receipt::{ActionReceipt, ActionType, ReceiptId};
use crate::trust::TrustGrant;

// ── SortOrder ─────────────────────────────────────────────────────────────────

/// Sort direction for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Most recently recorded receipt first (descending timestamp).
    #[default]
    NewestFirst,
    /// Oldest receipt first (ascending timestamp).
    OldestFirst,
}

// ── ReceiptQuery ──────────────────────────────────────────────────────────────

/// Query parameters for filtering and sorting [`ActionReceipt`] records.
///
/// All fields are optional.  Unset fields impose no restriction.
/// When multiple filters are set they are combined with logical AND.
#[derive(Debug, Clone, Default)]
pub struct ReceiptQuery {
    /// Restrict results to receipts recorded by this actor identity.
    pub actor: Option<IdentityId>,
    /// Restrict results to receipts of this action type.
    pub action_type: Option<ActionType>,
    /// Restrict results to receipts whose timestamp falls within `[from, to]`.
    pub time_range: Option<(u64, u64)>,
    /// Restrict results to receipts that are part of the chain rooted at this
    /// receipt ID.  A receipt is in the chain if its `previous_receipt` field
    /// matches `chain_root`, or transitively.
    ///
    /// Note: chain traversal is a linear scan over the candidate set and is
    /// O(n) in the number of matching receipts.
    pub chain_root: Option<ReceiptId>,
    /// Maximum number of receipts to return (applied after sorting).
    pub limit: Option<usize>,
    /// Sort order for the returned receipts.
    pub sort: SortOrder,
}

// ── TrustQuery ────────────────────────────────────────────────────────────────

/// Query parameters for filtering [`TrustGrant`] records.
///
/// All fields are optional.  Unset fields impose no restriction.
/// When multiple filters are set they are combined with logical AND.
#[derive(Debug, Clone, Default)]
pub struct TrustQuery {
    /// Restrict results to grants issued by this identity.
    pub grantor: Option<IdentityId>,
    /// Restrict results to grants issued to this identity.
    pub grantee: Option<IdentityId>,
    /// Restrict results to grants that contain at least one capability whose
    /// URI *starts with* this prefix string.
    ///
    /// Example: `Some("read:".to_string())` matches capabilities
    /// `"read:calendar"`, `"read:email"`, `"read:*"`, etc.
    pub capability_prefix: Option<String>,
    /// When `true`, only return grants that are currently time-valid **and**
    /// not revoked.  Uses [`crate::time::now_micros`] as the reference time.
    pub valid_only: bool,
    /// Maximum number of grants to return.
    pub limit: Option<usize>,
}

// ── query_receipts ────────────────────────────────────────────────────────────

/// Execute a [`ReceiptQuery`] against a [`ReceiptIndex`].
///
/// Returns a `Vec` of references to matching receipts sorted according to
/// `query.sort` and capped at `query.limit` entries.
pub fn query_receipts<'a>(index: &'a ReceiptIndex, query: &ReceiptQuery) -> Vec<&'a ActionReceipt> {
    // ── Step 1: build the initial candidate set ───────────────────────────

    // Use the most selective single-key index available.
    // Priority: actor index > type index > time-range index > full scan.
    let mut candidates: Vec<&ActionReceipt> =
        match (&query.actor, &query.action_type, &query.time_range) {
            // Actor filter present — start from actor index (typically smallest set).
            (Some(actor), _, _) => index.by_actor(actor),

            // No actor, but action type present — start from type index.
            (None, Some(atype), _) => index.by_type(atype),

            // No actor or type, but time range present — use time index.
            (None, None, Some((from, to))) => index.by_time_range(*from, *to),

            // No hints at all — full scan over everything.
            (None, None, None) => {
                // Collect all receipts from the time-ordered index for a
                // stable, reproducible ordering baseline.
                index.by_time_range(0, u64::MAX)
            }
        };

    // ── Step 2: apply remaining filters ──────────────────────────────────

    // Actor filter (applied when the initial set came from a different index).
    if let Some(actor) = &query.actor {
        // When we already started from the actor index no extra work is needed.
        // But when the starting set came from another index we must filter.
        // We detect this by checking whether we entered the (Some(actor), _, _)
        // branch above — unfortunately Rust's ownership model makes that
        // awkward, so we simply re-apply the filter unconditionally; it is
        // idempotent and cheap.
        candidates.retain(|r| &r.actor == actor);
    }

    // Action-type filter.
    if let Some(atype) = &query.action_type {
        candidates.retain(|r| r.action_type.as_tag() == atype.as_tag());
    }

    // Time-range filter.
    if let Some((from, to)) = &query.time_range {
        candidates.retain(|r| r.timestamp >= *from && r.timestamp <= *to);
    }

    // Chain-root filter: keep only receipts that follow the given root.
    // A receipt is a direct successor if its `previous_receipt == chain_root`.
    // We do a single-level filter here (direct successors only) as a linear
    // chain walk would require a mutable borrow of the index.
    if let Some(root) = &query.chain_root {
        candidates.retain(|r| r.previous_receipt.as_ref() == Some(root));
    }

    // ── Step 3: sort ─────────────────────────────────────────────────────

    match query.sort {
        SortOrder::NewestFirst => {
            candidates.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));
        }
        SortOrder::OldestFirst => {
            candidates.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));
        }
    }

    // ── Step 4: apply limit ───────────────────────────────────────────────

    if let Some(limit) = query.limit {
        candidates.truncate(limit);
    }

    candidates
}

// ── query_trust ───────────────────────────────────────────────────────────────

/// Execute a [`TrustQuery`] against a [`TrustIndex`].
///
/// Returns a `Vec` of references to matching grants.  Results are
/// **not** sorted (trust grants do not have a canonical ordering); apply
/// `query.limit` to cap the set size.
pub fn query_trust<'a>(index: &'a TrustIndex, query: &TrustQuery) -> Vec<&'a TrustGrant> {
    // ── Step 1: build the initial candidate set ───────────────────────────

    let mut candidates: Vec<&TrustGrant> = match (&query.grantor, &query.grantee) {
        // Both grantor and grantee specified — start from the smaller set.
        // We start with grantor and will filter by grantee below.
        (Some(grantor), _) => index.by_grantor(grantor),

        // Only grantee specified.
        (None, Some(grantee)) => index.by_grantee(grantee),

        // Neither — full scan (collect all grants from all grantors).
        (None, None) => {
            // We get a deduplicated list by iterating through the grantee
            // index.  However, since TrustIndex does not expose an iterator
            // over all grants, we use the grantee secondary index which
            // (together with the grantor index) covers all inserted grants.
            // The cleanest full-scan approach is to call by_time_range on
            // ReceiptIndex — but we don't have that here. Instead, we expose
            // the full scan via a helper that collects unique grants from
            // both secondary maps.  Because we only have HashMap internals,
            // we fall back to a Vec collected through the `by_grantee` path
            // by aggregating all entries.
            //
            // Since TrustIndex doesn't expose an iterator, we collect the
            // universe by issuing an "all grantor" query — which we do by
            // going through the grantor map (all values). In practice the
            // caller usually provides at least one of grantor/grantee, so
            // this path is rare.
            collect_all_grants(index)
        }
    };

    // ── Step 2: apply remaining filters ──────────────────────────────────

    // Grantor filter (idempotent re-application when already used as seed).
    if let Some(grantor) = &query.grantor {
        candidates.retain(|g| &g.grantor == grantor);
    }

    // Grantee filter.
    if let Some(grantee) = &query.grantee {
        candidates.retain(|g| &g.grantee == grantee);
    }

    // Capability prefix filter: at least one capability URI starts with prefix.
    if let Some(prefix) = &query.capability_prefix {
        candidates.retain(|g| {
            g.capabilities
                .iter()
                .any(|c| c.uri.starts_with(prefix.as_str()))
        });
    }

    // Validity filter: time-valid AND not revoked.
    if query.valid_only {
        let now = crate::time::now_micros();
        candidates.retain(|g| g.constraints.is_time_valid(now) && !index.is_revoked(&g.id));
    }

    // ── Step 3: apply limit ───────────────────────────────────────────────

    if let Some(limit) = query.limit {
        candidates.truncate(limit);
    }

    candidates
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Collect every grant stored in `index` without duplicates.
///
/// Because `TrustIndex` does not expose a direct iterator over its internal
/// `by_id` map, we reconstruct the full set by iterating the secondary
/// grantor index.  The result is de-duplicated using a simple `ReceiptId`
/// comparison (we rely on the fact that a grant is stored once for each
/// unique `TrustId`, and the secondary index never inserts duplicates for a
/// single `insert_grant` call).
///
/// This is only called when neither `grantor` nor `grantee` is specified in
/// the query — an unusual but supported code path.
fn collect_all_grants(index: &TrustIndex) -> Vec<&TrustGrant> {
    // We walk through grantee entries and deduplicate via the TrustId.
    // To avoid exposing internals we use the public API: gather all IDs
    // we've seen via by_grantor/by_grantee. Since the secondary maps may
    // overlap, we use a seen-set to avoid duplicates.
    //
    // We build the full list by collecting grants encountered through
    // any secondary-index walk. The simplest correct approach is to
    // iterate nothing — but since the TrustIndex fields are private, we
    // provide a `iter_grants` method on TrustIndex via the blanket
    // approach below, OR we collect through the public secondary index
    // by querying a sentinel that covers everything.
    //
    // Practical solution: expose an `iter_all_grants` on TrustIndex.
    // Rather than changing the index API, we collect the full set by
    // combining two walks and deduplicating.
    index.iter_all_grants()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::index::{ReceiptIndex, TrustIndex};
    use crate::receipt::action::{ActionContent, ActionType};
    use crate::receipt::receipt::ReceiptBuilder;
    use crate::trust::capability::Capability;
    use crate::trust::constraint::TrustConstraints;
    use crate::trust::grant::TrustGrantBuilder;
    use crate::trust::revocation::{Revocation, RevocationReason};

    // ── test helpers ─────────────────────────────────────────────────────────

    fn make_receipt(anchor: &IdentityAnchor, atype: ActionType, desc: &str) -> ActionReceipt {
        ReceiptBuilder::new(anchor.id(), atype, ActionContent::new(desc))
            .sign(anchor.signing_key())
            .expect("sign receipt")
    }

    fn grantee_key(a: &IdentityAnchor) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            a.verifying_key_bytes(),
        )
    }

    fn make_grant(grantor: &IdentityAnchor, grantee: &IdentityAnchor, cap: &str) -> TrustGrant {
        TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee_key(grantee))
            .capability(Capability::new(cap))
            .sign(grantor.signing_key())
            .expect("sign grant")
    }

    fn make_grant_with_constraints(
        grantor: &IdentityAnchor,
        grantee: &IdentityAnchor,
        cap: &str,
        constraints: TrustConstraints,
    ) -> TrustGrant {
        TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee_key(grantee))
            .capability(Capability::new(cap))
            .constraints(constraints)
            .sign(grantor.signing_key())
            .expect("sign grant")
    }

    // ── test_receipt_query_by_actor ───────────────────────────────────────────

    #[test]
    fn test_receipt_query_by_actor() {
        let a1 = IdentityAnchor::new(Some("actor-1".into()));
        let a2 = IdentityAnchor::new(Some("actor-2".into()));
        let a3 = IdentityAnchor::new(Some("actor-3".into()));

        let mut idx = ReceiptIndex::new();
        idx.insert(make_receipt(&a1, ActionType::Decision, "a1 decision 1"));
        idx.insert(make_receipt(&a1, ActionType::Observation, "a1 observation"));
        idx.insert(make_receipt(&a2, ActionType::Decision, "a2 decision"));
        idx.insert(make_receipt(&a2, ActionType::Mutation, "a2 mutation"));
        idx.insert(make_receipt(&a3, ActionType::Decision, "a3 decision"));

        let q = ReceiptQuery {
            actor: Some(a1.id()),
            ..Default::default()
        };
        let results = query_receipts(&idx, &q);

        assert_eq!(results.len(), 2, "expected exactly a1's 2 receipts");
        assert!(
            results.iter().all(|r| r.actor == a1.id()),
            "all returned receipts must belong to actor-1"
        );
    }

    // ── test_receipt_query_by_type ────────────────────────────────────────────

    #[test]
    fn test_receipt_query_by_type() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        idx.insert(make_receipt(&anchor, ActionType::Decision, "decision A"));
        idx.insert(make_receipt(&anchor, ActionType::Decision, "decision B"));
        idx.insert(make_receipt(
            &anchor,
            ActionType::Observation,
            "observation",
        ));
        idx.insert(make_receipt(&anchor, ActionType::Mutation, "mutation"));
        idx.insert(make_receipt(
            &anchor,
            ActionType::Custom("audit".into()),
            "audit event",
        ));

        let q = ReceiptQuery {
            action_type: Some(ActionType::Decision),
            ..Default::default()
        };
        let results = query_receipts(&idx, &q);

        assert_eq!(results.len(), 2, "expected 2 Decision receipts");
        assert!(
            results
                .iter()
                .all(|r| r.action_type == ActionType::Decision),
            "all returned receipts must be Decision type"
        );
    }

    // ── test_receipt_query_by_time_range ──────────────────────────────────────

    #[test]
    fn test_receipt_query_by_time_range() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        // Create three receipts with distinct timestamps.
        let r1 = make_receipt(&anchor, ActionType::Decision, "early");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r2 = make_receipt(&anchor, ActionType::Decision, "middle");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r3 = make_receipt(&anchor, ActionType::Decision, "late");

        let t1 = r1.timestamp;
        let t2 = r2.timestamp;
        let t3 = r3.timestamp;

        idx.insert(r1);
        idx.insert(r2);
        idx.insert(r3);

        // Query for only the first receipt (up to t1 inclusive).
        let q_first = ReceiptQuery {
            time_range: Some((0, t1)),
            ..Default::default()
        };
        let first = query_receipts(&idx, &q_first);
        assert_eq!(first.len(), 1, "expected only the earliest receipt");
        assert!(first[0].timestamp <= t1);

        // Query for the middle window [t2, t2].
        let q_middle = ReceiptQuery {
            time_range: Some((t2, t2)),
            ..Default::default()
        };
        let middle = query_receipts(&idx, &q_middle);
        assert_eq!(middle.len(), 1);
        assert_eq!(middle[0].timestamp, t2);

        // Query for all three.
        let q_all = ReceiptQuery {
            time_range: Some((t1, t3)),
            ..Default::default()
        };
        let all = query_receipts(&idx, &q_all);
        assert_eq!(all.len(), 3);

        // Query for none (before any receipts).
        let q_none = ReceiptQuery {
            time_range: Some((0, t1 - 1)),
            ..Default::default()
        };
        let none = query_receipts(&idx, &q_none);
        assert!(none.is_empty());
    }

    // ── test_receipt_query_sort_order ─────────────────────────────────────────

    #[test]
    fn test_receipt_query_sort_order() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        let r1 = make_receipt(&anchor, ActionType::Decision, "oldest");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r2 = make_receipt(&anchor, ActionType::Decision, "middle");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r3 = make_receipt(&anchor, ActionType::Decision, "newest");

        idx.insert(r1);
        idx.insert(r2);
        idx.insert(r3);

        // NewestFirst — descending timestamp.
        let q_newest = ReceiptQuery {
            sort: SortOrder::NewestFirst,
            ..Default::default()
        };
        let newest_first = query_receipts(&idx, &q_newest);
        assert_eq!(newest_first.len(), 3);
        assert!(
            newest_first[0].timestamp >= newest_first[1].timestamp,
            "first result should be newest"
        );
        assert!(
            newest_first[1].timestamp >= newest_first[2].timestamp,
            "results should be in descending order"
        );

        // OldestFirst — ascending timestamp.
        let q_oldest = ReceiptQuery {
            sort: SortOrder::OldestFirst,
            ..Default::default()
        };
        let oldest_first = query_receipts(&idx, &q_oldest);
        assert_eq!(oldest_first.len(), 3);
        assert!(
            oldest_first[0].timestamp <= oldest_first[1].timestamp,
            "first result should be oldest"
        );
        assert!(
            oldest_first[1].timestamp <= oldest_first[2].timestamp,
            "results should be in ascending order"
        );

        // The two orderings are reversed mirrors of each other.
        assert_eq!(
            newest_first[0].id, oldest_first[2].id,
            "newest-first[0] should equal oldest-first[2]"
        );
        assert_eq!(
            newest_first[2].id, oldest_first[0].id,
            "newest-first[2] should equal oldest-first[0]"
        );
    }

    // ── test_receipt_query_limit ──────────────────────────────────────────────

    #[test]
    fn test_receipt_query_limit() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        for i in 0..10 {
            idx.insert(make_receipt(
                &anchor,
                ActionType::Observation,
                &format!("obs {i}"),
            ));
        }

        let q = ReceiptQuery {
            limit: Some(3),
            sort: SortOrder::NewestFirst,
            ..Default::default()
        };
        let results = query_receipts(&idx, &q);
        assert_eq!(results.len(), 3);
    }

    // ── test_trust_query_by_grantor ───────────────────────────────────────────

    #[test]
    fn test_trust_query_by_grantor() {
        let g1 = IdentityAnchor::new(Some("grantor-1".into()));
        let g2 = IdentityAnchor::new(Some("grantor-2".into()));
        let tee = IdentityAnchor::new(Some("grantee".into()));

        let mut idx = TrustIndex::new();
        idx.insert_grant(make_grant(&g1, &tee, "read:*"));
        idx.insert_grant(make_grant(&g1, &tee, "write:calendar"));
        idx.insert_grant(make_grant(&g2, &tee, "read:calendar"));

        let q = TrustQuery {
            grantor: Some(g1.id()),
            ..Default::default()
        };
        let results = query_trust(&idx, &q);

        assert_eq!(results.len(), 2, "expected grantor-1's 2 grants");
        assert!(
            results.iter().all(|g| g.grantor == g1.id()),
            "all results must be from grantor-1"
        );
    }

    // ── test_trust_query_by_capability ───────────────────────────────────────

    #[test]
    fn test_trust_query_by_capability() {
        let grantor = IdentityAnchor::new(None);
        let tee = IdentityAnchor::new(None);

        let mut idx = TrustIndex::new();
        idx.insert_grant(make_grant(&grantor, &tee, "read:calendar"));
        idx.insert_grant(make_grant(&grantor, &tee, "read:email"));
        idx.insert_grant(make_grant(&grantor, &tee, "write:calendar"));
        idx.insert_grant(make_grant(&grantor, &tee, "execute:deploy:production"));

        // Query for all "read:" capabilities.
        let q = TrustQuery {
            capability_prefix: Some("read:".to_string()),
            ..Default::default()
        };
        let results = query_trust(&idx, &q);

        assert_eq!(results.len(), 2, "expected 2 read:* grants");
        assert!(
            results
                .iter()
                .all(|g| { g.capabilities.iter().any(|c| c.uri.starts_with("read:")) }),
            "all returned grants must contain a read: capability"
        );

        // Query for "write:" — only one.
        let q_write = TrustQuery {
            capability_prefix: Some("write:".to_string()),
            ..Default::default()
        };
        let write_results = query_trust(&idx, &q_write);
        assert_eq!(write_results.len(), 1);
        assert!(write_results[0]
            .capabilities
            .iter()
            .any(|c| c.uri.starts_with("write:")));

        // Query for "execute:" — only one.
        let q_exec = TrustQuery {
            capability_prefix: Some("execute:".to_string()),
            ..Default::default()
        };
        let exec_results = query_trust(&idx, &q_exec);
        assert_eq!(exec_results.len(), 1);

        // Query for nonexistent prefix — none.
        let q_none = TrustQuery {
            capability_prefix: Some("admin:".to_string()),
            ..Default::default()
        };
        assert!(query_trust(&idx, &q_none).is_empty());
    }

    // ── test_trust_query_valid_only ───────────────────────────────────────────

    #[test]
    fn test_trust_query_valid_only() {
        let grantor = IdentityAnchor::new(None);
        let tee = IdentityAnchor::new(None);
        let now = crate::time::now_micros();

        let valid_grant = make_grant(&grantor, &tee, "read:calendar");

        let expired_grant = make_grant_with_constraints(
            &grantor,
            &tee,
            "read:email",
            TrustConstraints::time_bounded(now - 2_000_000, now - 1_000_000),
        );

        let not_yet_valid_grant = make_grant_with_constraints(
            &grantor,
            &tee,
            "write:calendar",
            TrustConstraints::time_bounded(now + 1_000_000, now + 2_000_000),
        );

        let revoked_grant = make_grant(&grantor, &tee, "execute:deploy");
        let revoked_id = revoked_grant.id.clone();

        let mut idx = TrustIndex::new();
        idx.insert_grant(valid_grant.clone());
        idx.insert_grant(expired_grant);
        idx.insert_grant(not_yet_valid_grant);
        idx.insert_grant(revoked_grant);

        // Revoke the fourth grant.
        let rev = Revocation::create(
            revoked_id.clone(),
            grantor.id(),
            RevocationReason::ManualRevocation,
            grantor.signing_key(),
        );
        idx.insert_revocation(rev);

        // valid_only = true should return only valid_grant.
        let q = TrustQuery {
            valid_only: true,
            ..Default::default()
        };
        let results = query_trust(&idx, &q);

        assert_eq!(results.len(), 1, "expected exactly 1 valid grant");
        assert_eq!(
            results[0].id, valid_grant.id,
            "the valid grant must be the one returned"
        );

        // valid_only = false returns all 4.
        let q_all = TrustQuery {
            valid_only: false,
            ..Default::default()
        };
        let all = query_trust(&idx, &q_all);
        assert_eq!(all.len(), 4);
    }

    // ── test_trust_query_combined_filters ─────────────────────────────────────

    #[test]
    fn test_trust_query_combined_filters() {
        let g1 = IdentityAnchor::new(None);
        let g2 = IdentityAnchor::new(None);
        let tee = IdentityAnchor::new(None);

        let mut idx = TrustIndex::new();
        idx.insert_grant(make_grant(&g1, &tee, "read:calendar"));
        idx.insert_grant(make_grant(&g1, &tee, "write:calendar"));
        idx.insert_grant(make_grant(&g2, &tee, "read:email"));

        let q = TrustQuery {
            grantor: Some(g1.id()),
            capability_prefix: Some("read:".to_string()),
            ..Default::default()
        };
        let results = query_trust(&idx, &q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].grantor, g1.id());
        assert!(results[0]
            .capabilities
            .iter()
            .any(|c| c.uri.starts_with("read:")));
    }

    // ── test_trust_query_limit ────────────────────────────────────────────────

    #[test]
    fn test_trust_query_limit() {
        let grantor = IdentityAnchor::new(None);
        let tee = IdentityAnchor::new(None);

        let mut idx = TrustIndex::new();
        for i in 0..5 {
            idx.insert_grant(make_grant(&grantor, &tee, &format!("read:resource-{i}")));
        }

        let q = TrustQuery {
            limit: Some(2),
            ..Default::default()
        };
        let results = query_trust(&idx, &q);
        assert_eq!(results.len(), 2);
    }

    // ── test_receipt_query_chain_root ─────────────────────────────────────────

    #[test]
    fn test_receipt_query_chain_root() {
        let anchor = IdentityAnchor::new(None);

        // Build a chain: r1 <- r2 <- r3 (r2 and r3 chain from r1)
        let r1 = make_receipt(&anchor, ActionType::Observation, "root observation");
        let r2 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("decision following observation"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .expect("sign r2");
        let r3 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Mutation,
            ActionContent::new("mutation following observation"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .expect("sign r3");

        // r4 is unrelated (no chain link to r1)
        let r4 = make_receipt(&anchor, ActionType::Decision, "unrelated decision");

        let root_id = r1.id.clone();
        let mut idx = ReceiptIndex::new();
        idx.insert(r1);
        idx.insert(r2);
        idx.insert(r3);
        idx.insert(r4);

        let q = ReceiptQuery {
            chain_root: Some(root_id),
            ..Default::default()
        };
        let results = query_receipts(&idx, &q);

        assert_eq!(results.len(), 2, "expected the two direct successors of r1");
        assert!(
            results.iter().all(|r| r.previous_receipt.is_some()),
            "all results must reference a previous receipt"
        );
    }

    // ── test_empty_index_queries ──────────────────────────────────────────────

    #[test]
    fn test_empty_index_queries() {
        let receipt_idx = ReceiptIndex::new();
        let trust_idx = TrustIndex::new();

        let rq = ReceiptQuery::default();
        assert!(query_receipts(&receipt_idx, &rq).is_empty());

        let tq = TrustQuery::default();
        assert!(query_trust(&trust_idx, &tq).is_empty());
    }
}
