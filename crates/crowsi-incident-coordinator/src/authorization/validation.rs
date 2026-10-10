//! Implement the closed command-authorization validation contract.
use super::{CommandAuthorizationV1, CoordinatorError, Validate};

impl Validate for CommandAuthorizationV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        self.validate_at(&self.grant.issued_at)
    }
}
