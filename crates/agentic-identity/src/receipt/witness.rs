//! Witness signatures on action receipts.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::signing;
use crate::identity::IdentityId;

/// A witness signature on a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness: IdentityId,
    pub witness_key: String,
    pub witnessed_at: u64,
    pub signature: String,
}

impl WitnessSignature {
    /// Create a witness signature over a receipt hash.
    pub fn create(witness_id: IdentityId, signing_key: &SigningKey, receipt_hash: &str) -> Self {
        let now = crate::time::now_micros();
        let witness_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing_key.verifying_key().to_bytes(),
        );
        let to_sign = format!("witness:{}:{receipt_hash}:{now}", witness_id.0);
        let signature = signing::sign_to_base64(signing_key, to_sign.as_bytes());

        Self {
            witness: witness_id,
            witness_key,
            witnessed_at: now,
            signature,
        }
    }
}
