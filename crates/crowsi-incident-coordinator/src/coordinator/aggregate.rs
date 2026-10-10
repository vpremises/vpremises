use crowsi_control_contracts::EnforcementOutcome;

use crate::{
    CoordinatorCommandV1, CoordinatorError, IncidentCoordinator, IncidentPhase,
    IndependentObservedOutcome, ObservedTargetState, OperationMode, TargetStateV1,
    TransactionState,
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

impl IncidentCoordinator {
    pub(super) fn finalize_containment(
        &mut self,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        if self.snapshot.phase != IncidentPhase::ContainmentRequested {
            return Err(CoordinatorError::new(
                "phase",
                "containment finalization requires an active transaction",
            ));
        }
        self.snapshot.phase = self.aggregate_phase(OperationMode::Containment);
        Ok(Vec::new())
    }

    pub(super) fn finalize_restore(
        &mut self,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        if self.snapshot.phase != IncidentPhase::Restoring {
            return Err(CoordinatorError::new(
                "phase",
                "restore finalization requires an active transaction",
            ));
        }
        self.snapshot.phase = self.aggregate_phase(OperationMode::Restore);
        Ok(Vec::new())
    }

    fn aggregate_phase(&mut self, mode: OperationMode) -> IncidentPhase {
        for target in self.snapshot.targets.values_mut() {
            aggregate_target(target, mode);
        }
        let expected = match mode {
            OperationMode::Containment => ObservedTargetState::Isolated,
            OperationMode::Restore => ObservedTargetState::Restored,
        };
        if self
            .snapshot
            .targets
            .values()
            .all(|target| target.observed == expected)
        {
            match mode {
                OperationMode::Containment => IncidentPhase::Contained,
                OperationMode::Restore => IncidentPhase::Restored,
            }
        } else if self
            .snapshot
            .targets
            .values()
            .all(|target| target.observed == ObservedTargetState::Failed)
        {
            match mode {
                OperationMode::Containment => IncidentPhase::ContainmentFailed,
                OperationMode::Restore => IncidentPhase::RestoreFailed,
            }
        } else {
            match mode {
                OperationMode::Containment => IncidentPhase::ContainmentPartial,
                OperationMode::Restore => IncidentPhase::RestorePartial,
            }
        }
    }
}
