//! Aggregate enforcement states without promoting incomplete containment.
use super::{
    Aggregate, CoordinatorError, CoordinatorStateV1, DesiredTargetState, ObservedTargetState,
    TransactionState,
};

pub(in crate::state::phase) fn aggregate(
    state: &CoordinatorStateV1,
    desired: DesiredTargetState,
) -> Aggregate {
    let expected = match desired {
        DesiredTargetState::Isolated => ObservedTargetState::Isolated,
        DesiredTargetState::Restored => ObservedTargetState::Restored,
        DesiredTargetState::Unchanged => return Aggregate::Partial,
    };
    if state.snapshot.targets.values().all(|target| {
        target.observed == expected && target.transaction == TransactionState::Verified
    }) {
        Aggregate::Success
    } else if state.snapshot.targets.values().all(|target| {
        target.observed == ObservedTargetState::Failed
            && target.transaction == TransactionState::Failed
    }) {
        Aggregate::Failed
    } else {
        Aggregate::Partial
    }
}

pub(in crate::state::phase) fn require(
    condition: bool,
    reason: &'static str,
) -> Result<(), CoordinatorError> {
    if condition {
        Ok(())
    } else {
        Err(CoordinatorError::new("phase", reason))
    }
}
