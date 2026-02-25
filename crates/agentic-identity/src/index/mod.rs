//! Indexes for efficient lookups on receipts and trust grants.
//!
//! This module provides two in-memory index structures:
//!
//! - [`ReceiptIndex`] — indexes [`ActionReceipt`] records by ID, actor,
//!   action type, and timestamp.
//! - [`TrustIndex`] — indexes [`TrustGrant`] and [`Revocation`] records by
//!   ID, grantor, and grantee.
//!
//! Both indexes hold owned copies of the records and support O(1) lookups
//! by primary key as well as set lookups by the secondary keys.

use std::collections::{BTreeMap, HashMap};

use crate::identity::IdentityId;
use crate::receipt::{ActionReceipt, ActionType, ReceiptId};
use crate::trust::{Revocation, TrustGrant, TrustId};

// ── ReceiptIndex ─────────────────────────────────────────────────────────────

/// In-memory index over [`ActionReceipt`] records.
///
/// Maintains four secondary indexes so that receipts can be found
/// efficiently by primary ID, by actor identity, by action-type tag,
/// or by a timestamp range.
pub struct ReceiptIndex {
    /// Primary store: receipt ID → receipt.
    by_id: HashMap<ReceiptId, ActionReceipt>,
    /// Secondary index: actor identity → list of receipt IDs.
    by_actor: HashMap<IdentityId, Vec<ReceiptId>>,
    /// Secondary index: action-type tag → list of receipt IDs.
    by_type: HashMap<String, Vec<ReceiptId>>,
    /// Ordered secondary index: timestamp → list of receipt IDs.
    ///
    /// Using a `BTreeMap` gives us cheap range queries without sorting.
    by_time: BTreeMap<u64, Vec<ReceiptId>>,
}

impl ReceiptIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_actor: HashMap::new(),
            by_type: HashMap::new(),
            by_time: BTreeMap::new(),
        }
    }

    /// Insert a receipt into all four indexes.
    ///
    /// If a receipt with the same ID already exists it is replaced in
    /// `by_id`, but **not** removed from the secondary indexes (the old
    /// ID entry is simply overwritten on the next lookup).  For the
    /// typical append-only usage pattern this is never a problem.
    pub fn insert(&mut self, receipt: ActionReceipt) {
        let id = receipt.id.clone();
        let actor = receipt.actor.clone();
        let type_tag = receipt.action_type.as_tag().to_string();
        let ts = receipt.timestamp;

        self.by_id.insert(id.clone(), receipt);
        self.by_actor.entry(actor).or_default().push(id.clone());
        self.by_type.entry(type_tag).or_default().push(id.clone());
        self.by_time.entry(ts).or_default().push(id);
    }

    /// Look up a single receipt by its ID.
    pub fn get(&self, id: &ReceiptId) -> Option<&ActionReceipt> {
        self.by_id.get(id)
    }

    /// Return all receipts recorded for `actor`.
    ///
    /// The order of the returned slice is insertion order within each
    /// timestamp bucket and is otherwise unspecified.
    pub fn by_actor(&self, actor: &IdentityId) -> Vec<&ActionReceipt> {
        self.by_actor
            .get(actor)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Return all receipts whose action type matches `action_type`.
    pub fn by_type(&self, action_type: &ActionType) -> Vec<&ActionReceipt> {
        let tag = action_type.as_tag();
        self.by_type
            .get(tag)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Return all receipts whose timestamp falls within `[from, to]` (inclusive).
    pub fn by_time_range(&self, from: u64, to: u64) -> Vec<&ActionReceipt> {
        self.by_time
            .range(from..=to)
            .flat_map(|(_ts, ids)| ids.iter().filter_map(|id| self.by_id.get(id)))
            .collect()
    }

    /// Return the total number of receipts stored.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Return `true` when the index contains no receipts.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl Default for ReceiptIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ── TrustIndex ───────────────────────────────────────────────────────────────

/// In-memory index over [`TrustGrant`] and [`Revocation`] records.
///
/// Provides fast lookups by grant ID, grantor identity, or grantee
/// identity, and a revocation map for O(1) revocation status checks.
pub struct TrustIndex {
    /// Primary store: trust ID → grant.
    by_id: HashMap<TrustId, TrustGrant>,
    /// Secondary index: grantor identity → list of trust IDs.
    by_grantor: HashMap<IdentityId, Vec<TrustId>>,
    /// Secondary index: grantee identity → list of trust IDs.
    by_grantee: HashMap<IdentityId, Vec<TrustId>>,
    /// Revocation map: trust ID → revocation record.
    revocations: HashMap<TrustId, Revocation>,
}

impl TrustIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_grantor: HashMap::new(),
            by_grantee: HashMap::new(),
            revocations: HashMap::new(),
        }
    }

    /// Insert a trust grant into all three grant indexes.
    ///
    /// An existing grant with the same ID is replaced.
    pub fn insert_grant(&mut self, grant: TrustGrant) {
        let id = grant.id.clone();
        let grantor = grant.grantor.clone();
        let grantee = grant.grantee.clone();

        self.by_id.insert(id.clone(), grant);
        self.by_grantor.entry(grantor).or_default().push(id.clone());
        self.by_grantee.entry(grantee).or_default().push(id);
    }

    /// Insert a revocation record, keyed by the trust ID being revoked.
    pub fn insert_revocation(&mut self, revocation: Revocation) {
        self.revocations
            .insert(revocation.trust_id.clone(), revocation);
    }

    /// Look up a trust grant by its ID.
    pub fn get_grant(&self, id: &TrustId) -> Option<&TrustGrant> {
        self.by_id.get(id)
    }

    /// Return all grants issued *by* `grantor`.
    pub fn by_grantor(&self, grantor: &IdentityId) -> Vec<&TrustGrant> {
        self.by_grantor
            .get(grantor)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Return all grants issued *to* `grantee`.
    pub fn by_grantee(&self, grantee: &IdentityId) -> Vec<&TrustGrant> {
        self.by_grantee
            .get(grantee)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Return `true` if the grant with `id` has been revoked.
    pub fn is_revoked(&self, id: &TrustId) -> bool {
        self.revocations.contains_key(id)
    }

    /// Return the [`Revocation`] record for grant `id`, if any.
    pub fn get_revocation(&self, id: &TrustId) -> Option<&Revocation> {
        self.revocations.get(id)
    }

    /// Return the total number of grants stored.
    pub fn len_grants(&self) -> usize {
        self.by_id.len()
    }

    /// Return the total number of revocations stored.
    pub fn len_revocations(&self) -> usize {
        self.revocations.len()
    }

    /// Return an iterator over every grant in the index, in unspecified order.
    ///
    /// Used internally by the query engine for full-scan queries where neither
    /// grantor nor grantee has been specified.
    pub fn iter_all_grants(&self) -> Vec<&TrustGrant> {
        self.by_id.values().collect()
    }
}

impl Default for TrustIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::action::{ActionContent, ActionType};
    use crate::receipt::receipt::ReceiptBuilder;
    use crate::trust::capability::Capability;
    use crate::trust::constraint::TrustConstraints;
    use crate::trust::grant::TrustGrantBuilder;
    use crate::trust::revocation::{Revocation, RevocationReason};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_receipt(anchor: &IdentityAnchor, action_type: ActionType, desc: &str) -> ActionReceipt {
        ReceiptBuilder::new(anchor.id(), action_type, ActionContent::new(desc))
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

    // ── ReceiptIndex tests ───────────────────────────────────────────────────

    #[test]
    fn test_receipt_index_insert_and_get() {
        let anchor = IdentityAnchor::new(None);
        let receipt = make_receipt(&anchor, ActionType::Decision, "deployed");

        let mut idx = ReceiptIndex::new();
        let id = receipt.id.clone();
        idx.insert(receipt);

        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());
        assert!(idx.get(&id).is_some());
        assert!(idx.get(&ReceiptId("nonexistent".to_string())).is_none());
    }

    #[test]
    fn test_receipt_index_by_actor() {
        let a1 = IdentityAnchor::new(None);
        let a2 = IdentityAnchor::new(None);

        let mut idx = ReceiptIndex::new();
        idx.insert(make_receipt(&a1, ActionType::Decision, "a1 action 1"));
        idx.insert(make_receipt(&a1, ActionType::Observation, "a1 action 2"));
        idx.insert(make_receipt(&a2, ActionType::Decision, "a2 action"));

        let a1_receipts = idx.by_actor(&a1.id());
        assert_eq!(a1_receipts.len(), 2);
        assert!(a1_receipts.iter().all(|r| r.actor == a1.id()));

        let a2_receipts = idx.by_actor(&a2.id());
        assert_eq!(a2_receipts.len(), 1);
        assert_eq!(a2_receipts[0].actor, a2.id());
    }

    #[test]
    fn test_receipt_index_by_type() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        idx.insert(make_receipt(&anchor, ActionType::Decision, "decision 1"));
        idx.insert(make_receipt(&anchor, ActionType::Decision, "decision 2"));
        idx.insert(make_receipt(
            &anchor,
            ActionType::Observation,
            "observation",
        ));
        idx.insert(make_receipt(&anchor, ActionType::Mutation, "mutation"));

        let decisions = idx.by_type(&ActionType::Decision);
        assert_eq!(decisions.len(), 2);
        assert!(decisions
            .iter()
            .all(|r| r.action_type == ActionType::Decision));

        let observations = idx.by_type(&ActionType::Observation);
        assert_eq!(observations.len(), 1);

        let delegations = idx.by_type(&ActionType::Delegation);
        assert!(delegations.is_empty());
    }

    #[test]
    fn test_receipt_index_by_time_range() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        // Insert three receipts with small sleeps to get distinct timestamps.
        let r1 = make_receipt(&anchor, ActionType::Decision, "first");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r2 = make_receipt(&anchor, ActionType::Decision, "second");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let r3 = make_receipt(&anchor, ActionType::Decision, "third");

        let t1 = r1.timestamp;
        let t3 = r3.timestamp;

        idx.insert(r1);
        idx.insert(r2);
        idx.insert(r3);

        // Full range — all three.
        let all = idx.by_time_range(t1, t3);
        assert_eq!(all.len(), 3);

        // Only the first (up to but not including the second's timestamp).
        let just_first = idx.by_time_range(0, t1);
        assert_eq!(just_first.len(), 1);

        // Empty range before any receipts.
        let none = idx.by_time_range(0, t1 - 1);
        assert!(none.is_empty());
    }

    #[test]
    fn test_receipt_index_empty() {
        let idx = ReceiptIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    // ── TrustIndex tests ─────────────────────────────────────────────────────

    #[test]
    fn test_trust_index_insert_and_get() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee, "read:calendar");

        let mut idx = TrustIndex::new();
        let id = grant.id.clone();
        idx.insert_grant(grant);

        assert_eq!(idx.len_grants(), 1);
        assert_eq!(idx.len_revocations(), 0);
        assert!(idx.get_grant(&id).is_some());
        assert!(!idx.is_revoked(&id));
    }

    #[test]
    fn test_trust_index_by_grantor() {
        let g1 = IdentityAnchor::new(None);
        let g2 = IdentityAnchor::new(None);
        let tee = IdentityAnchor::new(None);

        let mut idx = TrustIndex::new();
        idx.insert_grant(make_grant(&g1, &tee, "read:*"));
        idx.insert_grant(make_grant(&g1, &tee, "write:calendar"));
        idx.insert_grant(make_grant(&g2, &tee, "read:calendar"));

        let from_g1 = idx.by_grantor(&g1.id());
        assert_eq!(from_g1.len(), 2);
        assert!(from_g1.iter().all(|g| g.grantor == g1.id()));

        let from_g2 = idx.by_grantor(&g2.id());
        assert_eq!(from_g2.len(), 1);
    }

    #[test]
    fn test_trust_index_by_grantee() {
        let tor = IdentityAnchor::new(None);
        let tee1 = IdentityAnchor::new(None);
        let tee2 = IdentityAnchor::new(None);

        let mut idx = TrustIndex::new();
        idx.insert_grant(make_grant(&tor, &tee1, "read:*"));
        idx.insert_grant(make_grant(&tor, &tee1, "write:calendar"));
        idx.insert_grant(make_grant(&tor, &tee2, "read:calendar"));

        let for_tee1 = idx.by_grantee(&tee1.id());
        assert_eq!(for_tee1.len(), 2);
        assert!(for_tee1.iter().all(|g| g.grantee == tee1.id()));

        let for_tee2 = idx.by_grantee(&tee2.id());
        assert_eq!(for_tee2.len(), 1);
    }

    #[test]
    fn test_trust_index_revocation() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let grant = make_grant(&grantor, &grantee, "read:calendar");
        let trust_id = grant.id.clone();

        let mut idx = TrustIndex::new();
        idx.insert_grant(grant);
        assert!(!idx.is_revoked(&trust_id));
        assert!(idx.get_revocation(&trust_id).is_none());

        let rev = Revocation::create(
            trust_id.clone(),
            grantor.id(),
            RevocationReason::ManualRevocation,
            grantor.signing_key(),
        );
        idx.insert_revocation(rev);

        assert!(idx.is_revoked(&trust_id));
        assert!(idx.get_revocation(&trust_id).is_some());
        assert_eq!(idx.len_revocations(), 1);
    }

    #[test]
    fn test_trust_index_unknown_actor_returns_empty() {
        let idx = TrustIndex::new();
        let unknown = IdentityAnchor::new(None);
        assert!(idx.by_grantor(&unknown.id()).is_empty());
        assert!(idx.by_grantee(&unknown.id()).is_empty());
    }

    #[test]
    fn test_receipt_index_custom_type() {
        let anchor = IdentityAnchor::new(None);
        let mut idx = ReceiptIndex::new();

        idx.insert(make_receipt(
            &anchor,
            ActionType::Custom("audit".into()),
            "audited file",
        ));
        idx.insert(make_receipt(&anchor, ActionType::Decision, "decided"));

        let audits = idx.by_type(&ActionType::Custom("audit".into()));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].action_type, ActionType::Custom("audit".into()));
    }

    #[test]
    fn test_receipt_index_unknown_actor_returns_empty() {
        let idx = ReceiptIndex::new();
        let unknown = IdentityAnchor::new(None);
        assert!(idx.by_actor(&unknown.id()).is_empty());
        assert!(idx.by_type(&ActionType::Decision).is_empty());
        assert!(idx.by_time_range(0, u64::MAX).is_empty());
    }

    #[test]
    fn test_trust_index_with_expired_constraints() {
        let grantor = IdentityAnchor::new(None);
        let grantee = IdentityAnchor::new(None);
        let now = crate::time::now_micros();

        let expired_grant =
            TrustGrantBuilder::new(grantor.id(), grantee.id(), grantee_key(&grantee))
                .capability(Capability::new("read:calendar"))
                .constraints(TrustConstraints::time_bounded(
                    now - 2_000_000,
                    now - 1_000_000,
                ))
                .sign(grantor.signing_key())
                .expect("sign grant");

        let mut idx = TrustIndex::new();
        idx.insert_grant(expired_grant.clone());

        // The index stores the grant regardless of expiry; time validity is a
        // query-layer concern.
        assert!(idx.get_grant(&expired_grant.id).is_some());
        assert!(!idx.is_revoked(&expired_grant.id));
    }
}
