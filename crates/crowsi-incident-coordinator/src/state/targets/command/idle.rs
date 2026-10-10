//! Reject idle targets that already contain an active command.
use super::{
    CoordinatorError, DesiredTargetState, ObservedTargetState, TargetStateV1, TransactionState,
};

pub(in crate::state::targets::command) fn validate_idle(
    target: &TargetStateV1,
) -> Result<(), CoordinatorError> {
    let valid = target.desired == DesiredTargetState::Unchanged
        && target.observed == ObservedTargetState::Unknown
        && target.transaction == TransactionState::Idle
        && target.transaction_id.is_none()
        && target.active_commands.is_empty()
        && target.receipts.is_empty()
        && target.verified_evidence.is_empty();
    if valid {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "target",
            "epoch zero target must be idle",
        ))
    }
}
