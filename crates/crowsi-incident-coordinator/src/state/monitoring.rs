use crate::{
    CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1, IncidentPhase,
    monitoring::verify,
    validation::{identifier, timestamp},
};

pub(super) fn validate(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
) -> Result<(), CoordinatorError> {
    if let Some(started_at) = &state.snapshot.monitoring_started_at {
        timestamp("monitoring_started_at", started_at)?;
        if started_at > &state.snapshot.trusted_time_watermark {
            return Err(CoordinatorError::new(
                "monitoring_started_at",
                "must not be later than the last event",
            ));
        }
    }
    if let Some(jti) = &state.snapshot.monitoring_evidence_jti {
        identifier("monitoring_evidence_jti", jti)?;
    }
    match state.snapshot.phase {
        IncidentPhase::Monitoring => {
            let clean = state.snapshot.monitoring_started_at.is_some()
                && state.snapshot.monitoring_evidence_jti.is_none()
                && state.monitoring_evidence.is_none();
            require(clean, "monitoring state must await explicit evidence")
        }
        IncidentPhase::Closed => validate_closed(state, trust),
        _ => {
            let clean = state.snapshot.monitoring_started_at.is_none()
                && state.snapshot.monitoring_evidence_jti.is_none()
                && state.monitoring_evidence.is_none();
            require(
                clean,
                "monitoring fields exist outside monitoring lifecycle",
            )
        }
    }
}

fn validate_closed(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
) -> Result<(), CoordinatorError> {
    let evidence = state
        .monitoring_evidence
        .as_ref()
        .ok_or_else(|| CoordinatorError::new("monitoring_evidence", "closed state requires it"))?;
    let marker_matches = state.snapshot.monitoring_evidence_jti.as_ref() == Some(&evidence.jti)
        && state.seen_evidence_jtis.contains(&evidence.jti);
    if !marker_matches {
        return Err(CoordinatorError::new(
            "monitoring_evidence",
            "marker or durable replay state is inconsistent",
        ));
    }
    verify::evidence(
        evidence,
        &state.snapshot,
        trust,
        &state.snapshot.last_event_at,
    )
}

fn require(condition: bool, reason: &'static str) -> Result<(), CoordinatorError> {
    if condition {
        Ok(())
    } else {
        Err(CoordinatorError::new("monitoring", reason))
    }
}
