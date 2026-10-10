mod canonical;

use crowsi_control_contracts::SignedDigestV1;
use serde::{Deserialize, Serialize};

use crate::{
    CoordinatorError, INDEPENDENT_VERIFICATION_SCHEMA_V1, IncidentCanonicalPayloadV1, Validate,
    time::{current, window_within},
    validation::{digest, identifier, opaque, schema, timestamp},
};

const MAX_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndependentObservedOutcome {
    Applied,
    NotApplied,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentVerificationArtifactV1 {
    pub schema: String,
    pub artifact_id: String,
    pub jti: String,
    pub nonce: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub isolation_epoch: u64,
    pub transaction_id: String,
    pub target_id: String,
    pub requirement_id: String,
    pub enforcement_receipt_id: String,
    pub enforcement_receipt_digest: String,
    pub observed_outcome: IndependentObservedOutcome,
    pub verifier_authority: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}

impl Validate for IndependentVerificationArtifactV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, INDEPENDENT_VERIFICATION_SCHEMA_V1)?;
        identifier("artifact_id", &self.artifact_id)?;
        identifier("jti", &self.jti)?;
        opaque("nonce", &self.nonce, 128)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        if self.isolation_epoch == 0 {
            return Err(CoordinatorError::new("isolation_epoch", "must be positive"));
        }
        identifier("transaction_id", &self.transaction_id)?;
        opaque("target_id", &self.target_id, 256)?;
        identifier("requirement_id", &self.requirement_id)?;
        identifier("enforcement_receipt_id", &self.enforcement_receipt_id)?;
        digest(
            "enforcement_receipt_digest",
            &self.enforcement_receipt_digest,
        )?;
        identifier("verifier_authority", &self.verifier_authority)?;
        timestamp("issued_at", &self.issued_at)?;
        timestamp("expires_at", &self.expires_at)?;
        crowsi_control_contracts::Validate::validate(&self.signed)?;
        if !window_within(&self.issued_at, &self.expires_at, MAX_TTL_MILLIS)
            || !self.payload_digest_matches()
        {
            return Err(CoordinatorError::new(
                "signed",
                "artifact lifetime or canonical digest is invalid",
            ));
        }
        Ok(())
    }
}

impl IndependentVerificationArtifactV1 {
    pub(crate) fn validate_at(&self, now: &str) -> Result<(), CoordinatorError> {
        self.validate()?;
        timestamp("trusted_now", now)?;
        if current(&self.issued_at, &self.expires_at, now) {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "trusted_now",
                "verification artifact is not current",
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedEvidenceV1 {
    pub(crate) artifact: IndependentVerificationArtifactV1,
    pub(crate) verified_at: String,
}

impl VerifiedEvidenceV1 {
    pub(crate) fn mint(artifact: IndependentVerificationArtifactV1, verified_at: &str) -> Self {
        Self {
            artifact,
            verified_at: verified_at.to_owned(),
        }
    }
}
