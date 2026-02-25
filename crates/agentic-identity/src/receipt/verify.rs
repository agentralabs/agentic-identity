//! Receipt verification.

use crate::crypto::keys::Ed25519KeyPair;
use crate::crypto::signing;
use crate::error::{IdentityError, Result};

use super::receipt::ActionReceipt;

/// Result of verifying a receipt.
#[derive(Debug, Clone)]
pub struct ReceiptVerification {
    pub signature_valid: bool,
    pub chain_valid: Option<bool>,
    pub witnesses_valid: Vec<bool>,
    pub is_valid: bool,
    pub verified_at: u64,
}

/// Verify that a receipt's signature is valid.
pub fn verify_receipt(receipt: &ActionReceipt) -> Result<ReceiptVerification> {
    let now = crate::time::now_micros();

    // Decode the actor's public key
    let pub_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &receipt.actor_key,
    )
    .map_err(|e| IdentityError::InvalidKey(format!("invalid actor key: {e}")))?;

    let key_bytes: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| IdentityError::InvalidKey("actor key must be 32 bytes".into()))?;

    let verifying_key = Ed25519KeyPair::verifying_key_from_bytes(&key_bytes)?;

    // Verify the main signature
    let sig_valid = signing::verify_from_base64(
        &verifying_key,
        receipt.receipt_hash.as_bytes(),
        &receipt.signature,
    )
    .is_ok();

    // Verify witness signatures
    let witnesses_valid: Vec<bool> = receipt
        .witnesses
        .iter()
        .map(|w| {
            let Ok(wb) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &w.witness_key)
            else {
                return false;
            };
            let Ok(wk): std::result::Result<[u8; 32], _> = wb.try_into() else {
                return false;
            };
            let Ok(wvk) = Ed25519KeyPair::verifying_key_from_bytes(&wk) else {
                return false;
            };
            let to_verify = format!(
                "witness:{}:{}:{}",
                w.witness.0, receipt.receipt_hash, w.witnessed_at
            );
            signing::verify_from_base64(&wvk, to_verify.as_bytes(), &w.signature).is_ok()
        })
        .collect();

    let all_witnesses_ok = witnesses_valid.iter().all(|&v| v);
    let is_valid = sig_valid && all_witnesses_ok;

    Ok(ReceiptVerification {
        signature_valid: sig_valid,
        chain_valid: None, // Chain verification requires access to the receipt store
        witnesses_valid,
        is_valid,
        verified_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::action::{ActionContent, ActionType};
    use crate::receipt::receipt::ReceiptBuilder;
    use crate::receipt::witness::WitnessSignature;

    #[test]
    fn test_receipt_verify() {
        let anchor = IdentityAnchor::new(None);
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("Approved"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        let result = verify_receipt(&receipt).unwrap();
        assert!(result.signature_valid);
        assert!(result.is_valid);
    }

    #[test]
    fn test_receipt_verify_wrong_actor() {
        let anchor_a = IdentityAnchor::new(None);
        let anchor_b = IdentityAnchor::new(None);

        // Sign with A's key but claim to be B
        let mut receipt = ReceiptBuilder::new(
            anchor_b.id(), // Claim to be B
            ActionType::Decision,
            ActionContent::new("fake"),
        )
        .sign(anchor_a.signing_key()) // But sign with A
        .unwrap();

        // Manually set the actor_key to B's key to simulate forgery attempt
        receipt.actor_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            anchor_b.verifying_key_bytes(),
        );

        let result = verify_receipt(&receipt).unwrap();
        assert!(!result.signature_valid);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_receipt_verify_with_witness() {
        let actor = IdentityAnchor::new(None);
        let witness_anchor = IdentityAnchor::new(None);

        let mut receipt = ReceiptBuilder::new(
            actor.id(),
            ActionType::Mutation,
            ActionContent::new("deployed"),
        )
        .sign(actor.signing_key())
        .unwrap();

        let ws = WitnessSignature::create(
            witness_anchor.id(),
            witness_anchor.signing_key(),
            &receipt.receipt_hash,
        );
        receipt.add_witness(ws);

        let result = verify_receipt(&receipt).unwrap();
        assert!(result.signature_valid);
        assert_eq!(result.witnesses_valid.len(), 1);
        assert!(result.witnesses_valid[0]);
        assert!(result.is_valid);
    }
}
