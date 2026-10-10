//! Start explicitly authorized containment in an allowed incident phase.
use super::{
    CommandAuthorizationV1, CoordinatorCommandV1, CoordinatorError, IncidentCoordinator,
    IncidentEventV1, IncidentPhase, OperationMode,
};

impl IncidentCoordinator {
    pub(in crate::coordinator) fn request_containment(
        &mut self,
        authorizations: &[CommandAuthorizationV1],
        event: &IncidentEventV1,
        retry: bool,
        trusted_now: &str,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        let allowed = if retry {
            matches!(
                self.snapshot.phase,
                IncidentPhase::ContainmentPartial | IncidentPhase::ContainmentFailed
            )
        } else {
            self.snapshot.phase == IncidentPhase::Triage
        };
        if !allowed {
            return Err(CoordinatorError::new(
                "phase",
                "containment request is not allowed",
            ));
        }
        let mapped = self.validate_authorizations(
            OperationMode::Containment,
            authorizations,
            trusted_now,
            &event.owner_authority,
        )?;
        let epoch = self
            .snapshot
            .isolation_epoch
            .checked_add(1)
            .ok_or_else(|| CoordinatorError::new("isolation_epoch", "epoch overflow"))?;
        self.snapshot.isolation_epoch = epoch;
        let commands =
            self.begin_targets(OperationMode::Containment, epoch, trusted_now, &mapped)?;
        self.reserve(&mapped);
        self.snapshot.phase = IncidentPhase::ContainmentRequested;
        self.pending_recovery = None;
        self.snapshot.recovery_approval_id = None;
        Ok(commands)
    }
}
