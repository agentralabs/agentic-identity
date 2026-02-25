//! Negative capability engine — impossibility proofs, declarations, verification.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityAnchor, IdentityId};
use crate::spawn::SpawnRecord;
use crate::trust::capability::capability_uri_covers;

use super::types::*;

// ---------------------------------------------------------------------------
// prove_cannot
// ---------------------------------------------------------------------------

/// Generate a negative capability proof — prove an identity CANNOT do something.
///
/// This checks the ceiling (authority_ceiling) to determine if the capability
/// is structurally excluded. For spawned identities, it also checks the lineage.
pub fn prove_cannot(
    identity: &IdentityAnchor,
    capability: &str,
    ceiling: &[String],
    spawn_records: &[SpawnRecord],
) -> Result<NegativeCapabilityProof> {
    let now = crate::time::now_micros();
    let identity_id = identity.id();

    // Try to find an impossibility reason

    // 1. Check if NOT in ceiling
    let in_ceiling = ceiling.iter().any(|c| capability_uri_covers(c, capability));

    if !in_ceiling && !ceiling.is_empty() {
        // Prove via ceiling exclusion
        let ceiling_hash = hex::encode(Sha256::digest(
            ceiling
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        ));

        let evidence = NegativeEvidence::CeilingExclusion {
            ceiling: ceiling.to_vec(),
            ceiling_hash,
        };

        return build_proof(
            identity,
            capability,
            ImpossibilityReason::NotInCeiling,
            evidence,
            now,
        );
    }

    // 2. Check lineage for spawn exclusion
    let my_spawn = spawn_records
        .iter()
        .find(|r| r.child_id == identity_id && !r.terminated);

    if let Some(spawn_record) = my_spawn {
        // Check if this capability is in parent ceiling but NOT in granted authority
        let in_parent_ceiling = spawn_record
            .authority_ceiling
            .iter()
            .any(|c| capability_uri_covers(&c.uri, capability));
        let in_granted = spawn_record
            .authority_granted
            .iter()
            .any(|c| capability_uri_covers(&c.uri, capability));

        if in_parent_ceiling && !in_granted {
            let spawn_hash = hex::encode(Sha256::digest(
                format!("{}:{}", spawn_record.id.0, spawn_record.parent_id.0).as_bytes(),
            ));

            let exclusions: Vec<String> = spawn_record
                .authority_ceiling
                .iter()
                .filter(|c| {
                    !spawn_record
                        .authority_granted
                        .iter()
                        .any(|g| g.uri == c.uri)
                })
                .map(|c| c.uri.clone())
                .collect();

            let evidence = NegativeEvidence::SpawnExclusion {
                spawn_id: spawn_record.id.clone(),
                spawn_record_hash: spawn_hash,
                exclusions,
            };

            return build_proof(
                identity,
                capability,
                ImpossibilityReason::SpawnExclusion {
                    spawn_id: spawn_record.id.clone(),
                },
                evidence,
                now,
            );
        }
    }

    // 3. Check lineage — walk up ancestors
    if !spawn_records.is_empty() {
        let mut current_id = identity_id.clone();
        let mut lineage = vec![current_id.clone()];
        let mut ancestor_ceilings: Vec<(IdentityId, Vec<String>)> = Vec::new();
        let mut found_in_lineage = false;

        loop {
            let parent_spawn = spawn_records
                .iter()
                .find(|r| r.child_id == current_id && !r.terminated);

            match parent_spawn {
                Some(record) => {
                    let parent_ceiling: Vec<String> = record
                        .authority_ceiling
                        .iter()
                        .map(|c| c.uri.clone())
                        .collect();
                    let cap_in_ceiling = parent_ceiling
                        .iter()
                        .any(|c| capability_uri_covers(c, capability));

                    ancestor_ceilings.push((record.parent_id.clone(), parent_ceiling));
                    lineage.push(record.parent_id.clone());

                    if cap_in_ceiling {
                        found_in_lineage = true;
                        break;
                    }

                    current_id = record.parent_id.clone();
                }
                None => break,
            }
        }

        if !found_in_lineage && !ancestor_ceilings.is_empty() {
            let lineage_hash = hex::encode(Sha256::digest(
                lineage
                    .iter()
                    .map(|id| id.0.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
                    .as_bytes(),
            ));

            let evidence = NegativeEvidence::LineageExclusion {
                lineage,
                ancestor_ceilings,
                lineage_hash,
            };

            return build_proof(
                identity,
                capability,
                ImpossibilityReason::NotInLineage,
                evidence,
                now,
            );
        }
    }

    // If we got here, we couldn't prove impossibility
    Err(IdentityError::TrustNotGranted(format!(
        "Cannot prove impossibility: identity may be able to do '{}'",
        capability
    )))
}

/// Helper: build a signed negative proof.
fn build_proof(
    identity: &IdentityAnchor,
    capability: &str,
    reason: ImpossibilityReason,
    evidence: NegativeEvidence,
    now: u64,
) -> Result<NegativeCapabilityProof> {
    let hash_input = format!(
        "negproof:{}:{}:{:?}:{}",
        identity.id().0,
        capability,
        reason,
        now
    );
    let proof_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    let id_hash = Sha256::digest(proof_hash.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let proof_id = NegativeProofId(format!("aneg_{id_encoded}"));

    let signature = signing::sign_to_base64(identity.signing_key(), proof_hash.as_bytes());

    Ok(NegativeCapabilityProof {
        proof_id,
        identity: identity.id(),
        cannot_do: capability.to_string(),
        reason,
        evidence,
        generated_at: now,
        valid_until: None,
        proof_hash,
        signature,
    })
}

// ---------------------------------------------------------------------------
// verify_negative_proof
// ---------------------------------------------------------------------------

/// Verify a negative capability proof.
pub fn verify_negative_proof(
    proof: &NegativeCapabilityProof,
    verifying_key: &VerifyingKey,
) -> Result<NegativeVerification> {
    let now = crate::time::now_micros();
    let mut errors = Vec::new();

    // Verify signature
    let sig_valid =
        signing::verify_from_base64(verifying_key, proof.proof_hash.as_bytes(), &proof.signature)
            .is_ok();

    if !sig_valid {
        errors.push("Signature verification failed".to_string());
    }

    // Verify evidence matches reason
    let evidence_valid = match (&proof.reason, &proof.evidence) {
        (ImpossibilityReason::NotInCeiling, NegativeEvidence::CeilingExclusion { ceiling, .. }) => {
            // Verify the capability is NOT covered by the ceiling
            let covered = ceiling
                .iter()
                .any(|c| capability_uri_covers(c, &proof.cannot_do));
            if covered {
                errors.push("Capability IS in ceiling — proof invalid".to_string());
                false
            } else {
                true
            }
        }
        (ImpossibilityReason::NotInLineage, NegativeEvidence::LineageExclusion { .. }) => true,
        (ImpossibilityReason::SpawnExclusion { .. }, NegativeEvidence::SpawnExclusion { .. }) => {
            true
        }
        (
            ImpossibilityReason::VoluntaryDeclaration { .. },
            NegativeEvidence::Declaration { .. },
        ) => true,
        _ => {
            errors.push("Evidence type does not match reason".to_string());
            false
        }
    };

    // Check reason validity
    let reason_valid = !matches!(proof.reason, ImpossibilityReason::CapabilityNonexistent);

    let is_valid = sig_valid && evidence_valid && reason_valid;

    Ok(NegativeVerification {
        proof_id: proof.proof_id.clone(),
        identity: proof.identity.clone(),
        capability: proof.cannot_do.clone(),
        reason_valid,
        evidence_valid,
        signature_valid: sig_valid,
        is_valid,
        verified_at: now,
        errors,
    })
}

// ---------------------------------------------------------------------------
// is_impossible
// ---------------------------------------------------------------------------

/// Check if a capability is impossible for an identity.
///
/// Returns the reason if impossible, None if possibly possible.
pub fn is_impossible(
    identity_id: &IdentityId,
    capability: &str,
    ceiling: &[String],
    spawn_records: &[SpawnRecord],
    declarations: &[NegativeDeclaration],
) -> Option<ImpossibilityReason> {
    // 1. Check ceiling
    if !ceiling.is_empty() {
        let in_ceiling = ceiling.iter().any(|c| capability_uri_covers(c, capability));
        if !in_ceiling {
            return Some(ImpossibilityReason::NotInCeiling);
        }
    }

    // 2. Check spawn exclusion
    let my_spawn = spawn_records
        .iter()
        .find(|r| &r.child_id == identity_id && !r.terminated);

    if let Some(record) = my_spawn {
        let in_granted = record
            .authority_granted
            .iter()
            .any(|c| capability_uri_covers(&c.uri, capability));
        if !in_granted {
            let in_ceiling = record
                .authority_ceiling
                .iter()
                .any(|c| capability_uri_covers(&c.uri, capability));
            if in_ceiling {
                return Some(ImpossibilityReason::SpawnExclusion {
                    spawn_id: record.id.clone(),
                });
            }
        }
    }

    // 3. Check voluntary declarations
    for decl in declarations {
        if &decl.identity == identity_id
            && decl
                .cannot_do
                .iter()
                .any(|c| capability_uri_covers(c, capability))
        {
            return Some(ImpossibilityReason::VoluntaryDeclaration {
                declaration_id: decl.declaration_id.clone(),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// declare_cannot
// ---------------------------------------------------------------------------

/// Create a voluntary negative declaration — self-imposed restriction.
pub fn declare_cannot(
    identity: &IdentityAnchor,
    capabilities: Vec<String>,
    reason: &str,
    permanent: bool,
    witnesses: Vec<&IdentityAnchor>,
) -> Result<NegativeDeclaration> {
    let now = crate::time::now_micros();

    if capabilities.is_empty() {
        return Err(IdentityError::InvalidKey(
            "Must specify at least one capability to declare impossible".to_string(),
        ));
    }

    // Generate declaration ID
    let id_input = format!(
        "decl:{}:{}:{}",
        identity.id().0,
        capabilities.join(","),
        now
    );
    let id_hash = Sha256::digest(id_input.as_bytes());
    let id_encoded = bs58::encode(&id_hash[..16]).into_string();
    let declaration_id = DeclarationId(format!("adecl_{id_encoded}"));

    // Sign the declaration
    let sign_input = format!(
        "negdecl:{}:{}:{}:{}:{}",
        declaration_id.0,
        identity.id().0,
        capabilities.join(","),
        reason,
        permanent
    );
    let signature = signing::sign_to_base64(identity.signing_key(), sign_input.as_bytes());

    // Collect witness signatures
    let witness_sigs: Vec<crate::receipt::witness::WitnessSignature> = witnesses
        .iter()
        .map(|w| {
            crate::receipt::witness::WitnessSignature::create(
                w.id(),
                w.signing_key(),
                &declaration_id.0,
            )
        })
        .collect();

    Ok(NegativeDeclaration {
        declaration_id,
        identity: identity.id(),
        cannot_do: capabilities,
        reason: reason.to_string(),
        declared_at: now,
        permanent,
        witnesses: witness_sigs,
        signature,
    })
}

// ---------------------------------------------------------------------------
// list_declarations
// ---------------------------------------------------------------------------

/// List all negative declarations for an identity.
pub fn list_declarations(
    identity: &IdentityId,
    declarations: &[NegativeDeclaration],
) -> Vec<NegativeDeclaration> {
    declarations
        .iter()
        .filter(|d| &d.identity == identity)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// get_impossibilities
// ---------------------------------------------------------------------------

/// Get all capabilities an identity structurally cannot do.
pub fn get_impossibilities(
    identity_id: &IdentityId,
    _ceiling: &[String],
    spawn_records: &[SpawnRecord],
    declarations: &[NegativeDeclaration],
) -> Vec<(String, ImpossibilityReason)> {
    let mut impossibilities = Vec::new();

    // Collect from declarations
    for decl in declarations {
        if &decl.identity == identity_id {
            for cap in &decl.cannot_do {
                impossibilities.push((
                    cap.clone(),
                    ImpossibilityReason::VoluntaryDeclaration {
                        declaration_id: decl.declaration_id.clone(),
                    },
                ));
            }
        }
    }

    // Collect from spawn exclusions
    let my_spawn = spawn_records
        .iter()
        .find(|r| &r.child_id == identity_id && !r.terminated);

    if let Some(record) = my_spawn {
        for cap in &record.authority_ceiling {
            let in_granted = record.authority_granted.iter().any(|g| g.uri == cap.uri);
            if !in_granted {
                impossibilities.push((
                    cap.uri.clone(),
                    ImpossibilityReason::SpawnExclusion {
                        spawn_id: record.id.clone(),
                    },
                ));
            }
        }
    }

    impossibilities
}

// ---------------------------------------------------------------------------
// Tests (12 scenarios)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::spawn::{SpawnConstraints, SpawnId, SpawnLifetime, SpawnType};
    use crate::trust::Capability;

    fn test_identity() -> IdentityAnchor {
        IdentityAnchor::new(Some("negative-tester".to_string()))
    }

    fn make_spawn_record(
        parent: &IdentityAnchor,
        child: &IdentityAnchor,
        granted: Vec<&str>,
        ceiling: Vec<&str>,
    ) -> SpawnRecord {
        let now = crate::time::now_micros();
        let id_hash =
            sha2::Sha256::digest(format!("{}:{}:{}", parent.id().0, child.id().0, now).as_bytes());
        let id_encoded = bs58::encode(&id_hash[..16]).into_string();

        SpawnRecord {
            id: SpawnId(format!("aspawn_{id_encoded}")),
            parent_id: parent.id(),
            parent_key: parent.public_key_base64(),
            child_id: child.id(),
            child_key: child.public_key_base64(),
            spawn_timestamp: now,
            spawn_type: SpawnType::Worker,
            spawn_purpose: "test".to_string(),
            spawn_receipt_id: crate::receipt::ReceiptId("arec_test".to_string()),
            authority_granted: granted.iter().map(|u| Capability::new(*u)).collect(),
            authority_ceiling: ceiling.iter().map(|u| Capability::new(*u)).collect(),
            lifetime: SpawnLifetime::Indefinite,
            constraints: SpawnConstraints {
                max_spawn_depth: Some(5),
                max_children: Some(10),
                max_descendants: None,
                can_spawn: true,
                authority_decay: None,
            },
            parent_signature: "test_sig".to_string(),
            child_acknowledgment: None,
            terminated: false,
            terminated_at: None,
            termination_reason: None,
        }
    }

    // 1. Prove cannot — not in ceiling
    #[test]
    fn test_prove_cannot_not_in_ceiling() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string(), "email:read".to_string()];

        let proof = prove_cannot(&identity, "deploy:production", &ceiling, &[]).unwrap();

        assert!(proof.proof_id.0.starts_with("aneg_"));
        assert_eq!(proof.cannot_do, "deploy:production");
        assert_eq!(proof.reason, ImpossibilityReason::NotInCeiling);
        assert!(!proof.signature.is_empty());

        if let NegativeEvidence::CeilingExclusion { ceiling: c, .. } = &proof.evidence {
            assert_eq!(c.len(), 2);
        } else {
            panic!("Expected CeilingExclusion evidence");
        }
    }

    // 2. Prove cannot — not in lineage
    #[test]
    fn test_prove_cannot_not_in_lineage() {
        let parent = test_identity();
        let child = test_identity();

        // Parent has calendar and email; child gets only calendar
        // "deploy:*" is not in any ancestor's ceiling
        let spawn_record = make_spawn_record(
            &parent,
            &child,
            vec!["calendar:*"],
            vec!["calendar:*", "email:*"],
        );

        // Empty ceiling means we don't use ceiling check, fall through to lineage
        let proof = prove_cannot(&child, "deploy:production", &[], &[spawn_record]).unwrap();

        assert_eq!(proof.reason, ImpossibilityReason::NotInLineage);
    }

    // 3. Prove cannot — spawn exclusion
    #[test]
    fn test_prove_cannot_spawn_exclusion() {
        let parent = test_identity();
        let child = test_identity();

        // Parent ceiling has both, but child only gets calendar
        let spawn_record = make_spawn_record(
            &parent,
            &child,
            vec!["calendar:*"],
            vec!["calendar:*", "email:*"],
        );

        let proof = prove_cannot(&child, "email:inbox:read", &[], &[spawn_record]).unwrap();

        assert!(matches!(
            proof.reason,
            ImpossibilityReason::SpawnExclusion { .. }
        ));
    }

    // 4. Verify valid negative proof
    #[test]
    fn test_verify_valid_negative_proof() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string()];

        let proof = prove_cannot(&identity, "deploy:production", &ceiling, &[]).unwrap();

        let verification = verify_negative_proof(&proof, identity.verifying_key()).unwrap();

        assert!(verification.is_valid);
        assert!(verification.signature_valid);
        assert!(verification.evidence_valid);
        assert!(verification.reason_valid);
        assert!(verification.errors.is_empty());
    }

    // 5. Verify invalid negative proof (actually CAN do it)
    #[test]
    fn test_prove_cannot_fails_when_possible() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string(), "deploy:*".to_string()];

        // deploy:production IS covered by "deploy:*", so we can't prove impossibility
        let result = prove_cannot(&identity, "deploy:production", &ceiling, &[]);
        assert!(result.is_err());
    }

    // 6. is_impossible returns correct reason
    #[test]
    fn test_is_impossible_ceiling() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string()];

        let reason = is_impossible(&identity.id(), "deploy:production", &ceiling, &[], &[]);
        assert_eq!(reason, Some(ImpossibilityReason::NotInCeiling));
    }

    // 7. is_impossible returns None when possible
    #[test]
    fn test_is_impossible_returns_none_when_possible() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string()];

        let reason = is_impossible(&identity.id(), "calendar:events:read", &ceiling, &[], &[]);
        assert!(reason.is_none());
    }

    // 8. Voluntary declaration creates proof
    #[test]
    fn test_voluntary_declaration() {
        let identity = test_identity();

        let decl = declare_cannot(
            &identity,
            vec!["deploy:*".to_string(), "admin:*".to_string()],
            "security policy",
            false,
            vec![],
        )
        .unwrap();

        assert!(decl.declaration_id.0.starts_with("adecl_"));
        assert_eq!(decl.identity, identity.id());
        assert_eq!(decl.cannot_do.len(), 2);
        assert_eq!(decl.reason, "security policy");
        assert!(!decl.permanent);
        assert!(!decl.signature.is_empty());
    }

    // 9. Permanent declaration is marked
    #[test]
    fn test_permanent_declaration() {
        let identity = test_identity();

        let decl = declare_cannot(
            &identity,
            vec!["admin:*".to_string()],
            "never needs admin",
            true,
            vec![],
        )
        .unwrap();

        assert!(decl.permanent);
    }

    // 10. Lineage proof walks entire ancestry
    #[test]
    fn test_lineage_proof_walks_ancestry() {
        let grandparent = test_identity();
        let parent = test_identity();
        let child = test_identity();

        // grandparent -> parent -> child
        // Neither grandparent nor parent has "deploy" in ceiling
        let spawn1 = make_spawn_record(
            &grandparent,
            &parent,
            vec!["calendar:*"],
            vec!["calendar:*", "email:*"],
        );
        let spawn2 = make_spawn_record(&parent, &child, vec!["calendar:*"], vec!["calendar:*"]);

        let proof = prove_cannot(&child, "deploy:production", &[], &[spawn1, spawn2]).unwrap();
        assert_eq!(proof.reason, ImpossibilityReason::NotInLineage);

        if let NegativeEvidence::LineageExclusion { lineage, .. } = &proof.evidence {
            assert!(lineage.len() >= 2); // child + at least one ancestor
        } else {
            panic!("Expected LineageExclusion evidence");
        }
    }

    // 11. Ceiling hash prevents tampering
    #[test]
    fn test_ceiling_hash_deterministic() {
        let identity = test_identity();
        let ceiling = vec!["calendar:*".to_string(), "email:read".to_string()];

        let proof1 = prove_cannot(&identity, "deploy:production", &ceiling, &[]).unwrap();
        let proof2 = prove_cannot(&identity, "deploy:production", &ceiling, &[]).unwrap();

        // The ceiling hash should be the same for the same ceiling
        if let (
            NegativeEvidence::CeilingExclusion {
                ceiling_hash: h1, ..
            },
            NegativeEvidence::CeilingExclusion {
                ceiling_hash: h2, ..
            },
        ) = (&proof1.evidence, &proof2.evidence)
        {
            assert_eq!(h1, h2);
        } else {
            panic!("Expected CeilingExclusion evidence");
        }
    }

    // 12. Spawned child inherits impossibilities from parent
    #[test]
    fn test_spawned_child_inherits_impossibilities() {
        let parent = test_identity();
        let child = test_identity();

        let spawn_record = make_spawn_record(
            &parent,
            &child,
            vec!["calendar:events:read"],
            vec!["calendar:*", "email:*"],
        );

        // Child can only do calendar:events:read
        // email:* is in ceiling but NOT in granted — spawn exclusion
        let impossibilities = get_impossibilities(&child.id(), &[], &[spawn_record], &[]);

        // email:* should be listed as impossible via spawn exclusion
        assert!(!impossibilities.is_empty());
        let has_email = impossibilities.iter().any(|(cap, _)| cap == "email:*");
        assert!(has_email, "Expected email:* in impossibilities");
    }
}
