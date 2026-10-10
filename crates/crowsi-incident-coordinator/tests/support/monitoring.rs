use crowsi_incident_coordinator::{
    IncidentCanonicalPayloadV1, IncidentCoordinator, MONITORING_EVIDENCE_SCHEMA_V1,
    MonitoringEvidenceV1, MonitoringOutcome,
};

use super::{INDEPENDENT_AUTHORITY, common::signed, crypto::sign_independent};

pub fn monitoring_evidence(coordinator: &IncidentCoordinator, id: &str) -> MonitoringEvidenceV1 {
    let mut evidence = MonitoringEvidenceV1 {
        schema: MONITORING_EVIDENCE_SCHEMA_V1.to_owned(),
        evidence_id: format!("monitoring.{id}"),
        jti: format!("jti.monitoring.{id}"),
        nonce: format!("nonce-{id}"),
        deployment_id: coordinator.snapshot().deployment_id.clone(),
        incident_id: coordinator.snapshot().incident_id.clone(),
        isolation_epoch: coordinator.snapshot().isolation_epoch,
        monitoring_started_at: coordinator
            .snapshot()
            .monitoring_started_at
            .clone()
            .expect("monitoring started"),
        observed_at: "2026-07-01T00:07:31.000Z".to_owned(),
        subject_digest: coordinator
            .monitoring_subject_digest()
            .expect("monitoring subject"),
        outcome: MonitoringOutcome::Stable,
        verifier_authority: INDEPENDENT_AUTHORITY.to_owned(),
        issued_at: "2026-07-01T00:07:32.000Z".to_owned(),
        expires_at: "2026-07-01T00:12:32.000Z".to_owned(),
        signed: signed(),
    };
    evidence.signed = sign_independent(&evidence.signing_payload());
    evidence
}
