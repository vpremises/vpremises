use crate::{
    IncidentCanonicalPayloadV1,
    canonical::Encoder,
    verification::{IndependentObservedOutcome, IndependentVerificationArtifactV1},
};

impl IncidentCanonicalPayloadV1 for IndependentVerificationArtifactV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("independent-verification-artifact-v1");
        value.text("schema", &self.schema);
        value.text("artifact_id", &self.artifact_id);
        value.text("jti", &self.jti);
        value.text("nonce", &self.nonce);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.number("isolation_epoch", self.isolation_epoch);
        value.text("transaction_id", &self.transaction_id);
        value.text("target_id", &self.target_id);
        value.text("requirement_id", &self.requirement_id);
        value.text("enforcement_receipt_id", &self.enforcement_receipt_id);
        value.text(
            "enforcement_receipt_digest",
            &self.enforcement_receipt_digest,
        );
        value.text(
            "observed_outcome",
            match self.observed_outcome {
                IndependentObservedOutcome::Applied => "applied",
                IndependentObservedOutcome::NotApplied => "not-applied",
                IndependentObservedOutcome::Partial => "partial",
                IndependentObservedOutcome::Unknown => "unknown",
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
