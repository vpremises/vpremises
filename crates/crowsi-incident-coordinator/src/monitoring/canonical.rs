use crate::{
    IncidentCanonicalPayloadV1, MonitoringEvidenceV1, MonitoringOutcome, canonical::Encoder,
};

impl IncidentCanonicalPayloadV1 for MonitoringEvidenceV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("monitoring-evidence-v1");
        value.text("schema", &self.schema);
        value.text("evidence_id", &self.evidence_id);
        value.text("jti", &self.jti);
        value.text("nonce", &self.nonce);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.number("isolation_epoch", self.isolation_epoch);
        value.text("monitoring_started_at", &self.monitoring_started_at);
        value.text("observed_at", &self.observed_at);
        value.text("subject_digest", &self.subject_digest);
        value.text(
            "outcome",
            match self.outcome {
                MonitoringOutcome::Stable => "stable",
                MonitoringOutcome::Regression => "regression",
                MonitoringOutcome::Unknown => "unknown",
            },
        );
        value.text("verifier_authority", &self.verifier_authority);
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.finish()
    }

    fn signed_digest(&self) -> &crowsi_control_contracts::SignedDigestV1 {
        &self.signed
    }
}
