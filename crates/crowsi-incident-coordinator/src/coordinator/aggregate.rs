use crowsi_control_contracts::EnforcementOutcome;

use crate::{
    CoordinatorCommandV1, CoordinatorError, IncidentCoordinator, IncidentPhase,
    IndependentObservedOutcome, ObservedTargetState, OperationMode, TargetStateV1,
    TransactionState,
};

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

mod target;
pub(crate) use target::aggregate_target;
