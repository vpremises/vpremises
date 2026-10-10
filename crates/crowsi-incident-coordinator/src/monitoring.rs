mod canonical;
pub(crate) mod subject;
pub(crate) mod verify;

use crowsi_control_contracts::SignedDigestV1;
use serde::{Deserialize, Serialize};

use crate::{
    CoordinatorError, IncidentCanonicalPayloadV1, MONITORING_EVIDENCE_SCHEMA_V1, Validate,
    time::{current, window_within},
    validation::{digest, identifier, schema, timestamp},
};

const MAX_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MonitoringOutcome {
    Stable,
    Regression,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitoringEvidenceV1 {
    pub schema: String,
    pub evidence_id: String,
    pub jti: String,
    pub nonce: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub isolation_epoch: u64,
    pub monitoring_started_at: String,
    pub observed_at: String,
    pub subject_digest: String,
    pub outcome: MonitoringOutcome,
    pub verifier_authority: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}

impl Validate for MonitoringEvidenceV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, MONITORING_EVIDENCE_SCHEMA_V1)?;
        identifier("evidence_id", &self.evidence_id)?;
        identifier("jti", &self.jti)?;
        crate::validation::opaque("nonce", &self.nonce, 128)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        if self.isolation_epoch == 0 {
            return Err(CoordinatorError::new("isolation_epoch", "must be positive"));
        }
        timestamp("monitoring_started_at", &self.monitoring_started_at)?;
        timestamp("observed_at", &self.observed_at)?;
        digest("subject_digest", &self.subject_digest)?;
        identifier("verifier_authority", &self.verifier_authority)?;
        timestamp("issued_at", &self.issued_at)?;
        timestamp("expires_at", &self.expires_at)?;
        crowsi_control_contracts::Validate::validate(&self.signed)?;
        let timeline = self.monitoring_started_at <= self.observed_at
            && self.observed_at <= self.issued_at
            && window_within(&self.issued_at, &self.expires_at, MAX_TTL_MILLIS);
        if timeline && self.payload_digest_matches() {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "monitoring_evidence",
                "timeline or canonical digest is invalid",
            ))
        }
    }
}

impl MonitoringEvidenceV1 {
    pub(crate) fn validate_at(&self, now: &str) -> Result<(), CoordinatorError> {
        self.validate()?;
        timestamp("trusted_now", now)?;
        if current(&self.issued_at, &self.expires_at, now) && self.observed_at.as_str() <= now {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "trusted_now",
                "monitoring evidence is not current",
            ))
        }
    }
}
