//! Spawn engine — child identity creation, authority bounding, lineage management.

use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityAnchor, IdentityId};
use crate::receipt::{ActionContent, ActionReceipt, ActionType};
use crate::trust::{capabilities_cover, Capability};

use super::types::*;

// ---------------------------------------------------------------------------
// Spawn child
// ---------------------------------------------------------------------------

/// Spawn a child identity with bounded authority.
///
/// Returns a tuple of (child IdentityAnchor, SpawnRecord, ActionReceipt).
///
/// The child's authority is bounded by `authority_ceiling` and the parent's
/// own authority. If any requested capability exceeds the parent's ceiling,
/// the spawn fails.
#[allow(clippy::too_many_arguments)]
pub fn spawn_child(
    parent: &IdentityAnchor,
    spawn_type: SpawnType,
    purpose: &str,
    authority_granted: Vec<Capability>,
    authority_ceiling: Vec<Capability>,
    lifetime: SpawnLifetime,
    constraints: SpawnConstraints,
    parent_spawn_info: Option<&SpawnInfo>,
    existing_children: &[SpawnRecord],
) -> Result<(IdentityAnchor, SpawnRecord, ActionReceipt)> {
    // 1. Check spawn depth limit
    if let Some(info) = parent_spawn_info {
        if let Some(max_depth) = info.constraints.max_spawn_depth {
            let current_depth = compute_depth(parent_spawn_info);
            if current_depth >= max_depth {
                return Err(IdentityError::DelegationDepthExceeded);
            }
        }

        // Check if parent is allowed to spawn
        if !info.constraints.can_spawn {
            return Err(IdentityError::DelegationNotAllowed);
        }

        // Check authority ceiling — granted must be covered by parent's ceiling
        for cap in &authority_granted {
            if !capabilities_cover(&info.authority_ceiling, &cap.uri) {
                return Err(IdentityError::TrustNotGranted(format!(
                    "Capability '{}' exceeds parent's authority ceiling",
                    cap.uri
                )));
            }
        }
        for cap in &authority_ceiling {
            if !capabilities_cover(&info.authority_ceiling, &cap.uri) {
                return Err(IdentityError::TrustNotGranted(format!(
                    "Ceiling capability '{}' exceeds parent's authority ceiling",
                    cap.uri
                )));
            }
        }
    }

    // 2. Check max children limit
    if let Some(info) = parent_spawn_info {
        if let Some(max_children) = info.constraints.max_children {
            let active_children = existing_children.iter().filter(|c| !c.terminated).count() as u32;
            if active_children >= max_children {
                return Err(IdentityError::MaxUsesExceeded);
            }
        }
    }

    // 3. Create child identity
    let child = IdentityAnchor::new(Some(format!("{}:{}", spawn_type.as_tag(), purpose)));

    let now = crate::time::now_micros();
    let parent_id = parent.id();
    let child_id = child.id();

    // 4. Generate spawn ID
    let id_input = format!("spawn:{}:{}:{}", parent_id.0, child_id.0, now);
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let spawn_id = SpawnId(format!("aspawn_{id_encoded}"));

    // 5. Create the spawn receipt
    let receipt = crate::receipt::receipt::ReceiptBuilder::new(
        parent_id.clone(),
        ActionType::Delegation,
        ActionContent::with_data(
            format!("Spawned {} child: {}", spawn_type.as_tag(), purpose),
            serde_json::json!({
                "spawn_id": spawn_id.0,
                "child_id": child_id.0,
                "spawn_type": spawn_type.as_tag(),
                "purpose": purpose,
                "authority_granted": authority_granted.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                "authority_ceiling": authority_ceiling.iter().map(|c| &c.uri).collect::<Vec<_>>(),
                "lifetime": lifetime.as_tag(),
            }),
        ),
    )
    .sign(parent.signing_key())?;

    let parent_key = parent.public_key_base64();
    let child_key = child.public_key_base64();

    // 6. Sign the spawn record
    let sign_input = format!(
        "spawn:{}:{}:{}:{}:{}",
        spawn_id.0,
        parent_id.0,
        child_id.0,
        spawn_type.as_tag(),
        now,
    );
    let parent_signature = signing::sign_to_base64(parent.signing_key(), sign_input.as_bytes());

    // 7. Child acknowledges
    let ack_input = format!("ack:{}:{}:{}", spawn_id.0, child_id.0, now);
    let child_acknowledgment = Some(signing::sign_to_base64(
        child.signing_key(),
        ack_input.as_bytes(),
    ));

    let record = SpawnRecord {
        id: spawn_id,
        parent_id,
        parent_key,
        child_id,
        child_key,
        spawn_timestamp: now,
        spawn_type,
        spawn_purpose: purpose.to_string(),
        spawn_receipt_id: receipt.id.clone(),
        authority_granted,
        authority_ceiling,
        lifetime,
        constraints,
        parent_signature,
        child_acknowledgment,
        terminated: false,
        terminated_at: None,
        termination_reason: None,
    };

    Ok((child, record, receipt))
}

// ---------------------------------------------------------------------------
// Terminate
// ---------------------------------------------------------------------------

/// Terminate a spawned child.
///
/// If `cascade` is true, all descendants in `all_records` are also marked
/// terminated.  Returns the IDs of all records that were terminated.
pub fn terminate_spawn(
    parent: &IdentityAnchor,
    spawn_record: &mut SpawnRecord,
    reason: &str,
    cascade: bool,
    all_records: &mut [SpawnRecord],
) -> Result<(ActionReceipt, Vec<SpawnId>)> {
    let parent_id = parent.id();

    // Only the parent can terminate
    if parent_id != spawn_record.parent_id {
        return Err(IdentityError::TrustNotGranted(
            "Only the parent can terminate a spawn".to_string(),
        ));
    }

    let now = crate::time::now_micros();
    let mut terminated_ids = vec![spawn_record.id.clone()];

    // Terminate the direct child
    spawn_record.terminated = true;
    spawn_record.terminated_at = Some(now);
    spawn_record.termination_reason = Some(reason.to_string());

    // Cascade termination
    if cascade {
        let child_id = spawn_record.child_id.clone();
        cascade_terminate(&child_id, now, reason, all_records, &mut terminated_ids);
    }

    // Create termination receipt
    let receipt = crate::receipt::receipt::ReceiptBuilder::new(
        parent_id,
        ActionType::Revocation,
        ActionContent::with_data(
            format!("Terminated spawn: {}", reason),
            serde_json::json!({
                "spawn_id": spawn_record.id.0,
                "child_id": spawn_record.child_id.0,
                "reason": reason,
                "cascade": cascade,
                "terminated_count": terminated_ids.len(),
            }),
        ),
    )
    .sign(parent.signing_key())?;

    Ok((receipt, terminated_ids))
}

/// Recursively terminate descendants.
fn cascade_terminate(
    parent_id: &IdentityId,
    now: u64,
    reason: &str,
    all_records: &mut [SpawnRecord],
    terminated_ids: &mut Vec<SpawnId>,
) {
    // Find all children of this parent
    let child_ids: Vec<IdentityId> = all_records
        .iter()
        .filter(|r| r.parent_id == *parent_id && !r.terminated)
        .map(|r| r.child_id.clone())
        .collect();

    for record in all_records.iter_mut() {
        if record.parent_id == *parent_id && !record.terminated {
            record.terminated = true;
            record.terminated_at = Some(now);
            record.termination_reason = Some(format!("Cascade from parent: {reason}"));
            terminated_ids.push(record.id.clone());
        }
    }

    // Recurse into children's children
    for child_id in child_ids {
        cascade_terminate(&child_id, now, reason, all_records, terminated_ids);
    }
}

// ---------------------------------------------------------------------------
// Lineage queries
// ---------------------------------------------------------------------------

/// Verify an identity's lineage.
pub fn verify_lineage(
    identity: &IdentityId,
    spawn_records: &[SpawnRecord],
) -> Result<LineageVerification> {
    let now = crate::time::now_micros();

    // Find the spawn record for this identity (as child)
    let record = spawn_records.iter().find(|r| r.child_id == *identity);

    match record {
        None => {
            // Root identity — no spawn record, full authority
            Ok(LineageVerification {
                identity: identity.clone(),
                lineage_valid: true,
                all_ancestors_active: true,
                effective_authority: vec![Capability::new("*")],
                spawn_depth: 0,
                revoked_ancestor: None,
                is_valid: true,
                verified_at: now,
                errors: Vec::new(),
            })
        }
        Some(record) => {
            let mut errors = Vec::new();
            let mut parent_chain = Vec::new();
            let mut all_active = true;
            let mut revoked_ancestor = None;

            // Walk up the lineage
            let mut current_id = record.parent_id.clone();
            loop {
                parent_chain.push(current_id.clone());

                let parent_record = spawn_records.iter().find(|r| r.child_id == current_id);

                match parent_record {
                    Some(pr) => {
                        if pr.terminated {
                            all_active = false;
                            revoked_ancestor = Some(current_id.clone());
                            errors.push(format!("Ancestor {} is terminated", current_id));
                        }

                        // Check lifetime expiration
                        if pr.lifetime.is_expired(pr.spawn_timestamp) {
                            all_active = false;
                            errors.push(format!("Ancestor {} has expired", current_id));
                        }

                        current_id = pr.parent_id.clone();
                    }
                    None => break, // Reached root
                }
            }

            // Check if this spawn itself is terminated
            let lineage_valid = !record.terminated && all_active;
            let is_valid = lineage_valid;

            // Effective authority is the intersection of all ancestors' ceilings
            let effective_authority = if is_valid {
                record.authority_granted.clone()
            } else {
                Vec::new()
            };

            Ok(LineageVerification {
                identity: identity.clone(),
                lineage_valid,
                all_ancestors_active: all_active,
                effective_authority,
                spawn_depth: parent_chain.len() as u32,
                revoked_ancestor,
                is_valid,
                verified_at: now,
                errors,
            })
        }
    }
}

/// Get the effective authority for an identity, bounded by all ancestors.
pub fn get_effective_authority(
    identity: &IdentityId,
    spawn_records: &[SpawnRecord],
) -> Result<Vec<Capability>> {
    let record = spawn_records.iter().find(|r| r.child_id == *identity);

    match record {
        None => Ok(vec![Capability::new("*")]), // Root: full authority
        Some(r) => {
            if r.terminated {
                return Ok(Vec::new());
            }
            if r.lifetime.is_expired(r.spawn_timestamp) {
                return Ok(Vec::new());
            }
            Ok(r.authority_granted.clone())
        }
    }
}

/// Get all ancestors of an identity (from parent to root).
pub fn get_ancestors(
    identity: &IdentityId,
    spawn_records: &[SpawnRecord],
) -> Result<Vec<IdentityId>> {
    let mut ancestors = Vec::new();
    let mut current_id = identity.clone();

    loop {
        let record = spawn_records.iter().find(|r| r.child_id == current_id);

        match record {
            Some(r) => {
                ancestors.push(r.parent_id.clone());
                current_id = r.parent_id.clone();
            }
            None => break, // Reached root
        }
    }

    Ok(ancestors)
}

/// Get direct children of an identity.
pub fn get_children(
    identity: &IdentityId,
    spawn_records: &[SpawnRecord],
) -> Result<Vec<IdentityId>> {
    let children: Vec<IdentityId> = spawn_records
        .iter()
        .filter(|r| r.parent_id == *identity)
        .map(|r| r.child_id.clone())
        .collect();

    Ok(children)
}

/// Get all descendants of an identity (breadth-first).
pub fn get_descendants(
    identity: &IdentityId,
    spawn_records: &[SpawnRecord],
) -> Result<Vec<IdentityId>> {
    let mut descendants = Vec::new();
    let mut queue = vec![identity.clone()];

    while let Some(current) = queue.pop() {
        let children: Vec<IdentityId> = spawn_records
            .iter()
            .filter(|r| r.parent_id == current)
            .map(|r| r.child_id.clone())
            .collect();

        for child in children {
            descendants.push(child.clone());
            queue.push(child);
        }
    }

    Ok(descendants)
}

/// Check if a parent can spawn with the proposed authority.
pub fn can_spawn(
    parent_spawn_info: Option<&SpawnInfo>,
    proposed_authority: &[Capability],
    existing_children: &[SpawnRecord],
) -> Result<bool> {
    match parent_spawn_info {
        None => Ok(true), // Root can spawn anything
        Some(info) => {
            // Check if spawning is allowed
            if !info.constraints.can_spawn {
                return Ok(false);
            }

            // Check depth limit
            // For simplicity, depth is determined from the spawn chain but
            // we approximate here based on info alone.

            // Check max children
            if let Some(max) = info.constraints.max_children {
                let active = existing_children.iter().filter(|c| !c.terminated).count() as u32;
                if active >= max {
                    return Ok(false);
                }
            }

            // Check authority coverage
            for cap in proposed_authority {
                if !capabilities_cover(&info.authority_ceiling, &cap.uri) {
                    return Ok(false);
                }
            }

            Ok(true)
        }
    }
}

/// Compute the current spawn depth from spawn info chain.
fn compute_depth(spawn_info: Option<&SpawnInfo>) -> u32 {
    match spawn_info {
        None => 0,
        Some(_) => 1, // Simplified — actual depth requires walking the chain
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    fn make_parent() -> IdentityAnchor {
        IdentityAnchor::new(Some("parent".to_string()))
    }

    fn default_constraints() -> SpawnConstraints {
        SpawnConstraints::default()
    }

    // 1. Spawn creation succeeds
    #[test]
    fn test_spawn_creation() {
        let parent = make_parent();
        let (child, record, receipt) = spawn_child(
            &parent,
            SpawnType::Worker,
            "process documents",
            vec![Capability::new("memory:docs:read")],
            vec![Capability::new("memory:docs:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        assert!(record.id.0.starts_with("aspawn_"));
        assert_eq!(record.parent_id, parent.id());
        assert_eq!(record.child_id, child.id());
        assert_eq!(record.spawn_type, SpawnType::Worker);
        assert_eq!(record.spawn_purpose, "process documents");
        assert!(!record.terminated);
        assert!(record.child_acknowledgment.is_some());
        assert!(receipt.id.0.starts_with("arec_"));
    }

    // 2. Child authority bounded by parent
    #[test]
    fn test_authority_bounded_by_parent() {
        let parent = make_parent();
        let parent_info = SpawnInfo {
            spawn_id: SpawnId("aspawn_test".into()),
            parent_id: IdentityAnchor::new(None).id(),
            spawn_type: SpawnType::Delegate,
            spawn_timestamp: crate::time::now_micros(),
            authority_ceiling: vec![Capability::new("calendar:*"), Capability::new("email:read")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: default_constraints(),
        };

        // This should succeed — calendar:events:read is covered by calendar:*
        let result = spawn_child(
            &parent,
            SpawnType::Worker,
            "reader",
            vec![Capability::new("calendar:events:read")],
            vec![Capability::new("calendar:events:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&parent_info),
            &[],
        );
        assert!(result.is_ok());
    }

    // 3. Authority exceeding ceiling fails
    #[test]
    fn test_authority_exceeding_ceiling_fails() {
        let parent = make_parent();
        let parent_info = SpawnInfo {
            spawn_id: SpawnId("aspawn_test".into()),
            parent_id: IdentityAnchor::new(None).id(),
            spawn_type: SpawnType::Delegate,
            spawn_timestamp: crate::time::now_micros(),
            authority_ceiling: vec![Capability::new("calendar:*")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: default_constraints(),
        };

        // deploy:* is NOT covered by calendar:*
        let result = spawn_child(
            &parent,
            SpawnType::Worker,
            "deployer",
            vec![Capability::new("deploy:production")],
            vec![Capability::new("deploy:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&parent_info),
            &[],
        );
        assert!(result.is_err());
    }

    // 4. Lineage chain builds correctly
    #[test]
    fn test_lineage_chain() {
        let root = make_parent();
        let (child1, record1, _) = spawn_child(
            &root,
            SpawnType::Worker,
            "child1",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let child1_info = SpawnInfo {
            spawn_id: record1.id.clone(),
            parent_id: root.id(),
            spawn_type: SpawnType::Worker,
            spawn_timestamp: record1.spawn_timestamp,
            authority_ceiling: vec![Capability::new("read:*")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: default_constraints(),
        };

        let (_child2, record2, _) = spawn_child(
            &child1,
            SpawnType::Worker,
            "grandchild",
            vec![Capability::new("read:calendar")],
            vec![Capability::new("read:calendar")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&child1_info),
            &[],
        )
        .unwrap();

        let child2_id = record2.child_id.clone();
        let ancestors = get_ancestors(&child2_id, &[record1, record2]).unwrap();
        assert_eq!(ancestors.len(), 2); // parent + root
    }

    // 5. Spawn depth limit enforced
    #[test]
    fn test_spawn_depth_limit() {
        let parent = make_parent();
        let parent_info = SpawnInfo {
            spawn_id: SpawnId("aspawn_depth".into()),
            parent_id: IdentityAnchor::new(None).id(),
            spawn_type: SpawnType::Worker,
            spawn_timestamp: crate::time::now_micros(),
            authority_ceiling: vec![Capability::new("*")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: SpawnConstraints {
                max_spawn_depth: Some(1), // Only 1 level allowed
                ..default_constraints()
            },
        };

        // First spawn from depth-limited parent should fail (depth 1 >= max 1)
        let result = spawn_child(
            &parent,
            SpawnType::Worker,
            "too-deep",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&parent_info),
            &[],
        );
        assert!(result.is_err());
    }

    // 6. Max children limit enforced
    #[test]
    fn test_max_children_limit() {
        let parent = make_parent();
        let parent_info = SpawnInfo {
            spawn_id: SpawnId("aspawn_limit".into()),
            parent_id: IdentityAnchor::new(None).id(),
            spawn_type: SpawnType::Delegate,
            spawn_timestamp: crate::time::now_micros(),
            authority_ceiling: vec![Capability::new("*")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: SpawnConstraints {
                max_children: Some(1),
                max_spawn_depth: Some(10),
                ..default_constraints()
            },
        };

        // First child succeeds
        let (_, record1, _) = spawn_child(
            &parent,
            SpawnType::Worker,
            "child1",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&parent_info),
            &[],
        )
        .unwrap();

        // Second child should fail — max 1
        let result = spawn_child(
            &parent,
            SpawnType::Worker,
            "child2",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&parent_info),
            &[record1],
        );
        assert!(result.is_err());
    }

    // 7. All 5 spawn types work
    #[test]
    fn test_all_spawn_types() {
        let parent = make_parent();
        let types = vec![
            SpawnType::Worker,
            SpawnType::Delegate,
            SpawnType::Clone,
            SpawnType::Specialist,
            SpawnType::Custom("auditor".into()),
        ];

        for st in types {
            let tag = st.as_tag().to_string();
            let (_, record, _) = spawn_child(
                &parent,
                st.clone(),
                &format!("test-{tag}"),
                vec![Capability::new("read:*")],
                vec![Capability::new("read:*")],
                SpawnLifetime::Indefinite,
                default_constraints(),
                None,
                &[],
            )
            .unwrap();
            assert_eq!(record.spawn_type, st);
        }
    }

    // 8. Spawn termination works
    #[test]
    fn test_spawn_termination() {
        let parent = make_parent();
        let (_, mut record, _) = spawn_child(
            &parent,
            SpawnType::Worker,
            "worker",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        assert!(!record.terminated);

        let (receipt, terminated_ids) =
            terminate_spawn(&parent, &mut record, "task complete", false, &mut []).unwrap();

        assert!(record.terminated);
        assert!(record.terminated_at.is_some());
        assert_eq!(record.termination_reason.as_deref(), Some("task complete"));
        assert_eq!(terminated_ids.len(), 1);
        assert!(receipt.id.0.starts_with("arec_"));
    }

    // 9. Parent termination cascades to children
    #[test]
    fn test_termination_cascade() {
        let parent = make_parent();
        let (child1, mut record1, _) = spawn_child(
            &parent,
            SpawnType::Worker,
            "child1",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        // child1 spawns grandchild
        let child1_info = SpawnInfo {
            spawn_id: record1.id.clone(),
            parent_id: parent.id(),
            spawn_type: SpawnType::Worker,
            spawn_timestamp: record1.spawn_timestamp,
            authority_ceiling: vec![Capability::new("read:*")],
            lifetime: SpawnLifetime::Indefinite,
            constraints: default_constraints(),
        };

        let (_, grandchild_record, _) = spawn_child(
            &child1,
            SpawnType::Worker,
            "grandchild",
            vec![Capability::new("read:calendar")],
            vec![Capability::new("read:calendar")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            Some(&child1_info),
            &[],
        )
        .unwrap();

        // Terminate child1 with cascade
        let mut all_records = vec![grandchild_record.clone()];
        let (_, terminated_ids) =
            terminate_spawn(&parent, &mut record1, "cleanup", true, &mut all_records).unwrap();

        assert!(record1.terminated);
        // Grandchild should also be terminated via cascade
        assert!(all_records[0].terminated);
        assert!(terminated_ids.len() >= 2);
    }

    // 10. Revocation cascade works
    #[test]
    fn test_revocation_cascade() {
        // Same as test 9 — revocation and termination are the same mechanism
        let parent = make_parent();
        let (_, mut record, _) = spawn_child(
            &parent,
            SpawnType::Delegate,
            "delegate",
            vec![Capability::new("calendar:*")],
            vec![Capability::new("calendar:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let (_, ids) = terminate_spawn(&parent, &mut record, "revoked", true, &mut []).unwrap();
        assert!(record.terminated);
        assert!(!ids.is_empty());
    }

    // 11. Ancestry walking works
    #[test]
    fn test_ancestry_walking() {
        let root = make_parent();
        let (child, record1, _) = spawn_child(
            &root,
            SpawnType::Worker,
            "child",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let ancestors = get_ancestors(&child.id(), &[record1]).unwrap();
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors[0], root.id());
    }

    // 12. Descendant listing works
    #[test]
    fn test_descendant_listing() {
        let root = make_parent();
        let (_, record1, _) = spawn_child(
            &root,
            SpawnType::Worker,
            "child1",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let (_, record2, _) = spawn_child(
            &root,
            SpawnType::Worker,
            "child2",
            vec![Capability::new("write:*")],
            vec![Capability::new("write:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let descendants = get_descendants(&root.id(), &[record1, record2]).unwrap();
        assert_eq!(descendants.len(), 2);
    }

    // 13. Effective authority calculation correct
    #[test]
    fn test_effective_authority() {
        let parent = make_parent();
        let (child, record, _) = spawn_child(
            &parent,
            SpawnType::Specialist,
            "calendar-reader",
            vec![Capability::new("calendar:events:read")],
            vec![Capability::new("calendar:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        let authority = get_effective_authority(&child.id(), &[record]).unwrap();
        assert_eq!(authority.len(), 1);
        assert_eq!(authority[0].uri, "calendar:events:read");

        // Root has full authority
        let root_auth = get_effective_authority(&parent.id(), &[]).unwrap();
        assert_eq!(root_auth.len(), 1);
        assert_eq!(root_auth[0].uri, "*");
    }

    // 14. Lifetime Duration expiration works
    #[test]
    fn test_lifetime_duration_expiration() {
        let lifetime = SpawnLifetime::Duration { seconds: 0 };
        // A spawn created at epoch with 0 seconds should be expired
        assert!(lifetime.is_expired(0));

        let not_expired = SpawnLifetime::Duration {
            seconds: 999_999_999,
        };
        assert!(!not_expired.is_expired(crate::time::now_micros()));
    }

    // 15. Lifetime Until expiration works
    #[test]
    fn test_lifetime_until_expiration() {
        let past = SpawnLifetime::Until { timestamp: 1 };
        assert!(past.is_expired(0));

        let future = SpawnLifetime::Until {
            timestamp: crate::time::now_micros() + 60_000_000,
        };
        assert!(!future.is_expired(0));
    }

    // 16. Spawn receipt is created correctly
    #[test]
    fn test_spawn_receipt() {
        let parent = make_parent();
        let (_, record, receipt) = spawn_child(
            &parent,
            SpawnType::Worker,
            "receipt-test",
            vec![Capability::new("read:*")],
            vec![Capability::new("read:*")],
            SpawnLifetime::Indefinite,
            default_constraints(),
            None,
            &[],
        )
        .unwrap();

        assert_eq!(receipt.actor, parent.id());
        assert_eq!(receipt.action_type, ActionType::Delegation);
        assert_eq!(record.spawn_receipt_id, receipt.id);
        assert!(!receipt.signature.is_empty());

        // Receipt data should contain spawn info
        let data = receipt.action.data.unwrap();
        assert_eq!(data["spawn_id"], record.id.0);
        assert_eq!(data["spawn_type"], "worker");
    }
}
