//! Action receipts — signed proofs that an agent took an action.

pub mod action;
pub mod chain;
#[allow(clippy::module_inception)]
pub mod receipt;
pub mod verify;
pub mod witness;

pub use action::{ActionContent, ActionType};
pub use receipt::{ActionReceipt, ReceiptId};
pub use verify::ReceiptVerification;
pub use witness::WitnessSignature;
