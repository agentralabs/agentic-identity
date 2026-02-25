//! Action receipt — signed proof of an action.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::signing;
use crate::error::Result;
use crate::identity::IdentityId;

use super::action::{ActionContent, ActionType};
use super::witness::WitnessSignature;

/// Unique identifier for a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An action receipt proving an agent took an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub id: ReceiptId,
    pub actor: IdentityId,
    pub actor_key: String,
    pub action_type: ActionType,
    pub action: ActionContent,
    pub timestamp: u64,
    pub context_hash: Option<String>,
    pub previous_receipt: Option<ReceiptId>,
    pub receipt_hash: String,
    pub signature: String,
    pub witnesses: Vec<WitnessSignature>,
}

/// Builder for creating action receipts.
pub struct ReceiptBuilder {
    actor: IdentityId,
    action_type: ActionType,
    action: ActionContent,
    context_hash: Option<String>,
    previous_receipt: Option<ReceiptId>,
}

impl ReceiptBuilder {
    /// Start building a receipt for an action.
    pub fn new(actor: IdentityId, action_type: ActionType, action: ActionContent) -> Self {
        Self {
            actor,
            action_type,
            action,
            context_hash: None,
            previous_receipt: None,
        }
    }

    /// Set the context hash (hash of relevant state at action time).
    pub fn context_hash(mut self, hash: String) -> Self {
        self.context_hash = Some(hash);
        self
    }

    /// Chain this receipt to a previous one.
    pub fn chain_to(mut self, previous: ReceiptId) -> Self {
        self.previous_receipt = Some(previous);
        self
    }

    /// Sign and finalize the receipt.
    pub fn sign(self, signing_key: &SigningKey) -> Result<ActionReceipt> {
        let now = crate::time::now_micros();
        let actor_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing_key.verifying_key().to_bytes(),
        );

        // Compute the receipt hash over all content fields
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.actor.0,
            actor_key,
            self.action_type.as_tag(),
            serde_json::to_string(&self.action).unwrap_or_default(),
            now,
            self.context_hash.as_deref().unwrap_or(""),
            self.previous_receipt
                .as_ref()
                .map(|r| r.0.as_str())
                .unwrap_or(""),
        );
        let receipt_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        // Generate receipt ID from the hash
        let id_hash = Sha256::digest(receipt_hash.as_bytes());
        let id_encoded = bs58::encode(&id_hash[..16]).into_string();
        let id = ReceiptId(format!("arec_{id_encoded}"));

        // Sign the receipt hash
        let signature = signing::sign_to_base64(signing_key, receipt_hash.as_bytes());

        Ok(ActionReceipt {
            id,
            actor: self.actor,
            actor_key,
            action_type: self.action_type,
            action: self.action,
            timestamp: now,
            context_hash: self.context_hash,
            previous_receipt: self.previous_receipt,
            receipt_hash,
            signature,
            witnesses: Vec::new(),
        })
    }
}

impl ActionReceipt {
    /// Add a witness signature to this receipt.
    pub fn add_witness(&mut self, witness: WitnessSignature) {
        self.witnesses.push(witness);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAnchor;

    #[test]
    fn test_receipt_create() {
        let anchor = IdentityAnchor::new(Some("test".into()));
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("Approved deployment to production"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        assert!(receipt.id.0.starts_with("arec_"));
        assert!(!receipt.receipt_hash.is_empty());
        assert!(!receipt.signature.is_empty());
        assert_eq!(receipt.actor, anchor.id());
    }

    #[test]
    fn test_receipt_with_chain() {
        let anchor = IdentityAnchor::new(None);
        let r1 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Observation,
            ActionContent::new("Observed error rate spike"),
        )
        .sign(anchor.signing_key())
        .unwrap();

        let r2 = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Decision,
            ActionContent::new("Decided to rollback"),
        )
        .chain_to(r1.id.clone())
        .sign(anchor.signing_key())
        .unwrap();

        assert_eq!(r2.previous_receipt.as_ref().unwrap(), &r1.id);
    }

    #[test]
    fn test_receipt_with_context() {
        let anchor = IdentityAnchor::new(None);
        let receipt = ReceiptBuilder::new(
            anchor.id(),
            ActionType::Mutation,
            ActionContent::with_data(
                "Updated config",
                serde_json::json!({"key": "max_retries", "value": 5}),
            ),
        )
        .context_hash("abc123def456".to_string())
        .sign(anchor.signing_key())
        .unwrap();

        assert_eq!(receipt.context_hash.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn test_receipt_types() {
        let anchor = IdentityAnchor::new(None);
        let types = vec![
            ActionType::Decision,
            ActionType::Observation,
            ActionType::Mutation,
            ActionType::Delegation,
            ActionType::Revocation,
            ActionType::IdentityOperation,
            ActionType::Custom("audit".into()),
        ];
        for action_type in types {
            let receipt = ReceiptBuilder::new(
                anchor.id(),
                action_type.clone(),
                ActionContent::new("test action"),
            )
            .sign(anchor.signing_key())
            .unwrap();
            assert_eq!(receipt.action_type, action_type);
        }
    }
}
