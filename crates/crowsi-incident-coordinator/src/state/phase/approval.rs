use crate::{CoordinatorError, CoordinatorStateV1, DesiredTargetState, IncidentPhase};

pub(super) fn validate(
    state: &CoordinatorStateV1,
    desired: DesiredTargetState,
) -> Result<(), CoordinatorError> {
    let requires_none = matches!(
        state.snapshot.phase,
        IncidentPhase::Detected
            | IncidentPhase::Triage
            | IncidentPhase::ContainmentRequested
            | IncidentPhase::Contained
            | IncidentPhase::ContainmentPartial
            | IncidentPhase::ContainmentFailed
            | IncidentPhase::Eradication
            | IncidentPhase::RecoveryPending
    );
    if requires_none != state.snapshot.recovery_approval_id.is_none() {
        return Err(CoordinatorError::new(
            "recovery_approval_id",
            "marker is inconsistent with phase",
        ));
    }
    let before_recovery = matches!(
        state.snapshot.phase,
        IncidentPhase::ContainmentRequested
            | IncidentPhase::Contained
            | IncidentPhase::ContainmentPartial
            | IncidentPhase::ContainmentFailed
            | IncidentPhase::Eradication
    );
    let initial_recovery = state.snapshot.phase == IncidentPhase::RecoveryPending
        && desired == DesiredTargetState::Isolated;
    if (before_recovery || initial_recovery) && !state.used_approval_ids.is_empty() {
        return Err(CoordinatorError::new(
            "used_approval_ids",
            "approval history exists before recovery authorization",
        ));
    }
    if state.snapshot.phase == IncidentPhase::RecoveryPending
        && desired == DesiredTargetState::Restored
        && state.used_approval_ids.is_empty()
    {
        return Err(CoordinatorError::new(
            "used_approval_ids",
            "recovery retry must retain prior approval history",
        ));
    }
    Ok(())
}
