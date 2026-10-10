use crate::{
    CoordinatorError, IncidentPhase, IncidentSnapshotV1, ObservedTargetState, TransactionState,
    canonical::{Encoder, digest_payload},
};

pub(crate) fn digest(snapshot: &IncidentSnapshotV1) -> Result<String, CoordinatorError> {
    if !matches!(
        snapshot.phase,
        IncidentPhase::Restored | IncidentPhase::Monitoring | IncidentPhase::Closed
    ) || snapshot.targets.values().any(|target| {
        target.observed != ObservedTargetState::Restored
            || target.transaction != TransactionState::Verified
    }) {
        return Err(CoordinatorError::new(
            "monitoring_subject",
            "requires a fully verified restored state",
        ));
    }
    let mut value = Encoder::new("monitoring-subject-v1");
    value.text("deployment_id", &snapshot.deployment_id);
    value.text("incident_id", &snapshot.incident_id);
    value.number("isolation_epoch", snapshot.isolation_epoch);
    value.number("restore_attempt", snapshot.restore_attempt);
    value.number("target_count", snapshot.targets.len() as u64);
    for (target_index, target) in snapshot.targets.values().enumerate() {
        value.text(&format!("target.{target_index}.id"), &target.target_id);
        value.number(
            &format!("target.{target_index}.requirement_count"),
            target.requirements.len() as u64,
        );
        for (index, requirement) in target.requirements.iter().enumerate() {
            let receipt = target
                .receipts
                .get(&requirement.requirement_id)
                .ok_or_else(|| CoordinatorError::new("receipt", "restored receipt is missing"))?;
            let evidence = target
                .verified_evidence
                .get(&requirement.requirement_id)
                .ok_or_else(|| {
                    CoordinatorError::new("verified_evidence", "restored evidence is missing")
                })?;
            let prefix = format!("target.{target_index}.requirement.{index}");
            value.text(&format!("{prefix}.id"), &requirement.requirement_id);
            value.text(
                &format!("{prefix}.receipt_digest"),
                &receipt.enforcement.signed.digest,
            );
            value.text(
                &format!("{prefix}.evidence_digest"),
                &evidence.artifact.signed.digest,
            );
        }
    }
    Ok(digest_payload(&value.finish()))
}
