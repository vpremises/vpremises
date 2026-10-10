mod approval;

use crate::{
    CoordinatorError, CoordinatorStateV1, DesiredTargetState, IncidentPhase, ObservedTargetState,
    TransactionState,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Aggregate {
    Success,
    Partial,
    Failed,
}

pub(super) fn validate(state: &CoordinatorStateV1) -> Result<(), CoordinatorError> {
    let snapshot = &state.snapshot;
    let phase = snapshot.phase;
    if phase == IncidentPhase::Detected {
        if snapshot.isolation_epoch == 0
            && snapshot.restore_attempt == 0
            && snapshot.last_event_at == snapshot.detected_at
            && snapshot.trusted_time_watermark == snapshot.detected_at
            && state.seen_event_jtis.is_empty()
            && state.seen_receipt_jtis.is_empty()
            && state.seen_evidence_jtis.is_empty()
            && state.reserved_authorization_jtis.is_empty()
            && state.used_approval_ids.is_empty()
            && snapshot.recovery_approval_id.is_none()
            && snapshot.monitoring_started_at.is_none()
            && snapshot.monitoring_evidence_jti.is_none()
            && state.monitoring_evidence.is_none()
        {
            return Ok(());
        }
        return Err(CoordinatorError::new(
            "phase",
            "detected state must be the untouched initial state",
        ));
    }
    if state.seen_event_jtis.is_empty() {
        return Err(CoordinatorError::new(
            "seen_event_jtis",
            "non-initial state requires event replay history",
        ));
    }
    if phase == IncidentPhase::Triage {
        let clean = snapshot.isolation_epoch == 0
            && snapshot.restore_attempt == 0
            && state.seen_receipt_jtis.is_empty()
            && state.seen_evidence_jtis.is_empty()
            && state.reserved_authorization_jtis.is_empty()
            && state.used_approval_ids.is_empty()
            && snapshot.recovery_approval_id.is_none()
            && snapshot.monitoring_started_at.is_none()
            && snapshot.monitoring_evidence_jti.is_none()
            && state.monitoring_evidence.is_none();
        return require(clean, "triage must precede isolation");
    }
    let desired = state
        .snapshot
        .targets
        .values()
        .next()
        .map(|target| target.desired)
        .ok_or_else(|| CoordinatorError::new("targets", "must not be empty"))?;
    let attempt_valid = match desired {
        DesiredTargetState::Isolated => snapshot.restore_attempt == 0,
        DesiredTargetState::Restored => snapshot.restore_attempt > 0,
        DesiredTargetState::Unchanged => false,
    };
    require(
        attempt_valid,
        "restore attempt does not match target lifecycle",
    )?;
    let aggregate = aggregate(state, desired);
    let valid = match phase {
        IncidentPhase::ContainmentRequested => desired == DesiredTargetState::Isolated,
        IncidentPhase::Contained | IncidentPhase::Eradication => {
            desired == DesiredTargetState::Isolated && aggregate == Aggregate::Success
        }
        IncidentPhase::ContainmentPartial => {
            desired == DesiredTargetState::Isolated && aggregate == Aggregate::Partial
        }
        IncidentPhase::ContainmentFailed => {
            desired == DesiredTargetState::Isolated && aggregate == Aggregate::Failed
        }
        IncidentPhase::RecoveryPending | IncidentPhase::RecoveryAuthorized => {
            (desired == DesiredTargetState::Isolated && aggregate == Aggregate::Success)
                || (desired == DesiredTargetState::Restored && aggregate != Aggregate::Success)
        }
        IncidentPhase::Restoring => desired == DesiredTargetState::Restored,
        IncidentPhase::Restored | IncidentPhase::Monitoring | IncidentPhase::Closed => {
            desired == DesiredTargetState::Restored && aggregate == Aggregate::Success
        }
        IncidentPhase::RestorePartial => {
            desired == DesiredTargetState::Restored && aggregate == Aggregate::Partial
        }
        IncidentPhase::RestoreFailed => {
            desired == DesiredTargetState::Restored && aggregate == Aggregate::Failed
        }
        IncidentPhase::Detected | IncidentPhase::Triage => false,
    };
    require(valid, "phase does not match target transaction state")?;
    approval::validate(state, desired)
}

mod aggregation;
use aggregation::aggregate;
use aggregation::require;
