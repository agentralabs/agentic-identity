use wasm_bindgen::prelude::*;
use agentic_identity::{
    IdentityAnchor,
    ActionContent, ActionType, ReceiptId,
    receipt::receipt::ReceiptBuilder,
    receipt::verify::verify_receipt,
};

#[wasm_bindgen]
pub struct WasmIdentity {
    inner: IdentityAnchor,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Create a new identity anchor with an optional display name.
    #[wasm_bindgen(constructor)]
    pub fn new(display_name: Option<String>) -> WasmIdentity {
        WasmIdentity {
            inner: IdentityAnchor::new(display_name),
        }
    }

    /// Get the identity ID string.
    #[wasm_bindgen]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Get the display name.
    #[wasm_bindgen]
    pub fn display_name(&self) -> Option<String> {
        self.inner.name.clone()
    }

    /// Get the public key as hex.
    #[wasm_bindgen]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.inner.verifying_key_bytes())
    }

    /// Get the public key as base64.
    #[wasm_bindgen]
    pub fn public_key_base64(&self) -> String {
        self.inner.public_key_base64()
    }

    /// Sign an action and return the receipt as JSON.
    #[wasm_bindgen]
    pub fn sign_action(
        &self,
        action_type: &str,
        description: &str,
    ) -> Result<String, JsValue> {
        let atype = parse_action_type(action_type);
        let content = ActionContent::new(description);
        let receipt = ReceiptBuilder::new(self.inner.id(), atype, content)
            .sign(self.inner.signing_key())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Sign an action with a reference to a previous receipt (chain).
    #[wasm_bindgen]
    pub fn sign_action_chained(
        &self,
        action_type: &str,
        description: &str,
        previous_receipt_id: &str,
    ) -> Result<String, JsValue> {
        let atype = parse_action_type(action_type);
        let content = ActionContent::new(description);
        let receipt = ReceiptBuilder::new(self.inner.id(), atype, content)
            .chain_to(ReceiptId(previous_receipt_id.to_string()))
            .sign(self.inner.signing_key())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Export the identity document as JSON.
    #[wasm_bindgen]
    pub fn to_document_json(&self) -> Result<String, JsValue> {
        let doc = self.inner.to_document();
        serde_json::to_string(&doc)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Verify a receipt JSON string. Returns true if signature is valid.
#[wasm_bindgen]
pub fn verify_receipt_json(receipt_json: &str) -> Result<bool, JsValue> {
    let receipt: agentic_identity::ActionReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verification = verify_receipt(&receipt)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(verification.is_valid)
}

fn parse_action_type(s: &str) -> ActionType {
    match s {
        "Decision" | "decision" => ActionType::Decision,
        "Observation" | "observation" => ActionType::Observation,
        "Mutation" | "mutation" => ActionType::Mutation,
        "Delegation" | "delegation" => ActionType::Delegation,
        "Revocation" | "revocation" => ActionType::Revocation,
        "IdentityOperation" | "identity_operation" => ActionType::IdentityOperation,
        other => ActionType::Custom(other.to_string()),
    }
}
