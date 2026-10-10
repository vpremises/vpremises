use crate::{CoordinatorCommandV1, CoordinatorError, IncidentCoordinator, IncidentPhase};

impl IncidentCoordinator {
    pub(super) fn begin_triage(&mut self) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        self.transition(IncidentPhase::Detected, IncidentPhase::Triage)?;
        Ok(Vec::new())
    }

    pub(super) fn begin_eradication(
        &mut self,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        self.transition(IncidentPhase::Contained, IncidentPhase::Eradication)?;
        Ok(Vec::new())
    }

    pub(super) fn request_recovery(
        &mut self,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        self.transition(IncidentPhase::Eradication, IncidentPhase::RecoveryPending)?;
        self.pending_recovery = None;
        self.snapshot.recovery_approval_id = None;
        Ok(Vec::new())
    }

    pub(super) fn retry_recovery(&mut self) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        if !matches!(
            self.snapshot.phase,
            IncidentPhase::RestorePartial | IncidentPhase::RestoreFailed
        ) {
            return Err(CoordinatorError::new(
                "phase",
                "recovery retry requires partial or failed restore",
            ));
        }
        self.snapshot.phase = IncidentPhase::RecoveryPending;
        self.pending_recovery = None;
        self.snapshot.recovery_approval_id = None;
        Ok(Vec::new())
    }

    pub(super) fn transition(
        &mut self,
        expected: IncidentPhase,
        next: IncidentPhase,
    ) -> Result<(), CoordinatorError> {
        if self.snapshot.phase == expected {
            self.snapshot.phase = next;
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "phase",
                "event is not valid in the current phase",
            ))
        }
    }
}
