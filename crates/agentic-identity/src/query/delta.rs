use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType { Created, Updated, Deleted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaQuery { pub since: i64, pub until: Option<i64>, pub change_types: Vec<ChangeType> }

impl DeltaQuery {
    pub fn since(timestamp: i64) -> Self { Self { since: timestamp, until: None, change_types: vec![ChangeType::Created, ChangeType::Updated, ChangeType::Deleted] } }
    pub fn until(mut self, timestamp: i64) -> Self { self.until = Some(timestamp); self }
    pub fn filter_type(mut self, ct: ChangeType) -> Self { self.change_types = vec![ct]; self }
}
