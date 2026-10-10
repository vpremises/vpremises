//! Require independent recovery approval before starting restoration.
use super::{
    CoordinatorCommandV1, CoordinatorError, IncidentCoordinator, IncidentEventV1, IncidentPhase,
    OperationMode, RecoveryApprovalV1, ReplayExpectation, verify_recovery_authority,
};

impl IncidentCoordinator {
    pub(in crate::coordinator) fn authorize_recovery(
        &mut self,
        approval: &RecoveryApprovalV1,
        event: &IncidentEventV1,
        trusted_now: &str,
    ) -> Result<(), CoordinatorError> {
        if self.snapshot.phase != IncidentPhase::RecoveryPending {
            return Err(CoordinatorError::new(
                "phase",
                "recovery approval requires recovery-pending",
            ));
        }
        approval.validate_at(trusted_now)?;
        self.validate_authorizations(
            OperationMode::Restore,
            &approval.authorizations,
            trusted_now,
            &event.owner_authority,
        )?;
        let recovery_jtis = verify_recovery_authority(
            approval,
            &self.snapshot.incident_id,
            &self.trust,
            trusted_now,
            &self.reserved_authorization_jtis,
            &self.seen_evidence_jtis,
            ReplayExpectation::Fresh,
        )?;
        if !self.used_approval_ids.insert(approval.approval_id.clone()) {
            return Err(CoordinatorError::new(
                "approval_id",
                "recovery approval replay detected",
            ));
        }
        self.snapshot
            .recovery_approval_id
            .clone_from(&Some(approval.approval_id.clone()));
        self.pending_recovery = Some(approval.clone());
        self.seen_evidence_jtis.extend(recovery_jtis);
        self.snapshot.phase = IncidentPhase::RecoveryAuthorized;
        Ok(())
    }

    pub(in crate::coordinator) fn start_restore(
        &mut self,
        event: &IncidentEventV1,
        automatic: bool,
        trusted_now: &str,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        if automatic {
            return Err(CoordinatorError::new(
                "automatic",
                "automatic restore is forbidden",
            ));
        }
        if self.snapshot.phase != IncidentPhase::RecoveryAuthorized {
            return Err(CoordinatorError::new(
                "phase",
                "restore requires a separate recovery approval",
            ));
        }
        let approval = self
            .pending_recovery
            .clone()
            .ok_or_else(|| CoordinatorError::new("approval", "recovery approval is missing"))?;
        let mapped = self.validate_authorizations(
            OperationMode::Restore,
            &approval.authorizations,
            trusted_now,
            &event.owner_authority,
        )?;
        verify_recovery_authority(
            &approval,
            &self.snapshot.incident_id,
            &self.trust,
            trusted_now,
            &self.reserved_authorization_jtis,
            &self.seen_evidence_jtis,
            ReplayExpectation::Recorded,
        )?;
        self.snapshot.restore_attempt = self
            .snapshot
            .restore_attempt
            .checked_add(1)
            .ok_or_else(|| CoordinatorError::new("restore_attempt", "attempt overflow"))?;
        let commands = self.begin_targets(
            OperationMode::Restore,
            self.snapshot.isolation_epoch,
            trusted_now,
            &mapped,
        )?;
        self.reserve(&mapped);
        self.pending_recovery = None;
        self.snapshot.phase = IncidentPhase::Restoring;
        Ok(commands)
    }
}
