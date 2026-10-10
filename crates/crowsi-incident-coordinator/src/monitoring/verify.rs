use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    CoordinatorError, CoordinatorTrustV1, IncidentCanonicalPayloadV1, IncidentSnapshotV1,
    MIN_MONITORING_WINDOW_MILLIS, MonitoringEvidenceV1, MonitoringOutcome,
    monitoring::subject,
    time::elapsed_at_least,
    trust::{TrustRole, TrustScope, ensure_independent},
};

pub(crate) fn evidence(
    value: &MonitoringEvidenceV1,
    snapshot: &IncidentSnapshotV1,
    trust: &CoordinatorTrustV1,
    now: &str,
) -> Result<(), CoordinatorError> {
    value.validate_at(now)?;
    let started_at = snapshot
        .monitoring_started_at
        .as_deref()
        .ok_or_else(|| CoordinatorError::new("monitoring_started_at", "is missing"))?;
    let exact = value.deployment_id == snapshot.deployment_id
        && value.incident_id == snapshot.incident_id
        && value.isolation_epoch == snapshot.isolation_epoch
        && value.monitoring_started_at == started_at
        && value.subject_digest == subject::digest(snapshot)?
        && value.outcome == MonitoringOutcome::Stable
        && elapsed_at_least(started_at, &value.observed_at, MIN_MONITORING_WINDOW_MILLIS);
    if !exact {
        return Err(CoordinatorError::new(
            "monitoring_evidence",
            "binding, outcome, or minimum observation window is invalid",
        ));
    }
    let verifier = trust.verify(
        Some(&value.verifier_authority),
        TrustRole::IndependentVerifier,
        TrustScope::Monitoring,
        &value.signed,
        &value.signing_payload(),
    )?;
    for target in snapshot.targets.values() {
        for receipt in target.receipts.values() {
            let pep = trust.verify(
                Some(&receipt.enforcement.provider),
                TrustRole::Pep,
                TrustScope::Restore,
                &receipt.enforcement.signed,
                &receipt.enforcement.signing_payload(),
            )?;
            ensure_independent(pep, verifier)?;
        }
    }
    Ok(())
}
