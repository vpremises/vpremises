//! Reduce per-enforcement receipts to one target state.
use super::{
    EnforcementOutcome, IndependentObservedOutcome, ObservedTargetState, OperationMode,
    TargetStateV1, TransactionState,
};

pub(crate) fn aggregate_target(target: &mut TargetStateV1, mode: OperationMode) {
    let total = target.active_commands.len();
    let mut success = 0;
    let mut definitive_failure = 0;
    let mut unknown = 0;
    for command in target.active_commands.values() {
        let receipt = target.receipts.get(&command.requirement_id);
        let evidence = target.verified_evidence.get(&command.requirement_id);
        match (receipt, evidence) {
            (Some(receipt), _)
                if matches!(
                    receipt.enforcement.outcome,
                    EnforcementOutcome::Failed | EnforcementOutcome::Rejected
                ) =>
            {
                definitive_failure += 1;
            }
            (Some(receipt), Some(evidence))
                if receipt.enforcement.outcome == EnforcementOutcome::Applied
                    && evidence.artifact.observed_outcome
                        == IndependentObservedOutcome::Applied =>
            {
                success += 1;
            }
            (_, Some(evidence))
                if evidence.artifact.observed_outcome == IndependentObservedOutcome::NotApplied =>
            {
                definitive_failure += 1;
            }
            (_, Some(evidence))
                if evidence.artifact.observed_outcome == IndependentObservedOutcome::Unknown =>
            {
                unknown += 1;
            }
            (None, _) | (Some(_), None) => unknown += 1,
            _ => {}
        }
    }
    if success == total && total > 0 {
        target.observed = match mode {
            OperationMode::Containment => ObservedTargetState::Isolated,
            OperationMode::Restore => ObservedTargetState::Restored,
        };
        target.transaction = TransactionState::Verified;
    } else if definitive_failure == total && total > 0 {
        target.observed = ObservedTargetState::Failed;
        target.transaction = TransactionState::Failed;
    } else if target.receipts.is_empty() || (unknown == total && success == 0) {
        target.observed = ObservedTargetState::Unknown;
        target.transaction = if target.receipts.is_empty() {
            TransactionState::Pending
        } else {
            TransactionState::Partial
        };
    } else {
        target.observed = ObservedTargetState::Partial;
        target.transaction = TransactionState::Partial;
    }
}
