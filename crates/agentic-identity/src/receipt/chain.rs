//! Receipt chain verification.
//!
//! Verifies the integrity of a sequence of chained receipts
//! by walking the `previous_receipt` links.

use super::receipt::ActionReceipt;
use super::verify::verify_receipt;
use crate::error::{IdentityError, Result};

/// Verify a chain of receipts (ordered from oldest to newest).
///
/// Checks that each receipt's `previous_receipt` correctly references
/// the preceding receipt, and that every signature is valid.
pub fn verify_chain(chain: &[ActionReceipt]) -> Result<bool> {
    if chain.is_empty() {
        return Ok(true);
    }

    // First receipt should have no previous
    if chain[0].previous_receipt.is_some() {
        // It's valid to verify a partial chain, so we don't fail here
    }

    for i in 0..chain.len() {
        // Verify each receipt's signature
        let verification = verify_receipt(&chain[i])?;
        if !verification.signature_valid {
            return Err(IdentityError::InvalidChain);
        }

        // For receipts after the first, verify chain links
        if i > 0 {
            let expected_prev = &chain[i - 1].id;
            match &chain[i].previous_receipt {
                Some(prev) if prev == expected_prev => {}
                _ => return Err(IdentityError::InvalidChain),
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;
    use crate::receipt::action::{ActionContent, ActionType};
    use crate::receipt::receipt::ReceiptBuilder;

    #[test]
    fn test_verify_chain_valid() {
        let anchor = IdentityAnchor::new(None);

        let r1 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Observation,
            ActionContent::new("step 1"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        let r2 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("step 2"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .unwrap();

        let r3 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Mutation,
            ActionContent::new("step 3"),
        )
        .chain_to(r2.id.clone())
        .sign(anchor.signing_key())
        .unwrap();

        assert!(verify_chain(&[r1, r2, r3]).is_ok());
    }

    #[test]
    fn test_verify_chain_broken_link() {
        let anchor = IdentityAnchor::new(None);

        let r1 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Observation,
            ActionContent::new("step 1"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        let r2 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("step 2"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .unwrap();

        // r3 chains to r1 instead of r2 — broken chain
        let r3 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Mutation,
            ActionContent::new("step 3"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .unwrap();

        assert!(verify_chain(&[r1, r2, r3]).is_err());
    }

    #[test]
    fn test_verify_chain_5_receipts() {
        let anchor = IdentityAnchor::new(None);
        let mut chain = Vec::new();

        let r = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("receipt 0"),
        )
        .sign(anchor.signing_key())
        .unwrap();
        chain.push(r);

        for i in 1..5 {
            let prev_id = chain.last().unwrap().id.clone();
            let r = ReceiptBuilder::new(
                anchor.id(),
                ActionType::Decision,
                ActionContent::new(format!("receipt {i}")),
            )
            .chain_to(prev_id)
            .sign(anchor.signing_key())
            .unwrap();
            chain.push(r);
        }

        assert!(verify_chain(&chain).is_ok());
    }
}
