use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorError {
    field: &'static str,
    reason: &'static str,
}

impl CoordinatorError {
    #[must_use]
    pub const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.reason)
    }
}

impl Error for CoordinatorError {}

impl From<crowsi_control_contracts::ValidationError> for CoordinatorError {
    fn from(_: crowsi_control_contracts::ValidationError) -> Self {
        Self::new("control_contract", "nested control contract is invalid")
    }
}
