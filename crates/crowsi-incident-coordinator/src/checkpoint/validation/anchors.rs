//! Validate freshness and correlation of external monotonic anchors.
use super::{
    CoordinatorError, ExternalMonotonicAnchorV1, IncidentCanonicalPayloadV1, MAX_ANCHOR_TTL_MILLIS,
    MONOTONIC_ANCHOR_SCHEMA_V1, Validate, current, digest, identifier, schema, timestamp,
    window_within,
};

impl Validate for ExternalMonotonicAnchorV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, MONOTONIC_ANCHOR_SCHEMA_V1)?;
        identifier("anchor_id", &self.anchor_id)?;
        identifier("anchor.jti", &self.jti)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        crate::validation::opaque("challenge_nonce", &self.challenge_nonce, 128)?;
        digest("checkpoint_digest", &self.checkpoint_digest)?;
        identifier("anchor.authority", &self.authority)?;
        timestamp("anchor.issued_at", &self.issued_at)?;
        timestamp("anchor.expires_at", &self.expires_at)?;
        crowsi_control_contracts::Validate::validate(&self.signed)?;
        if self.sequence > 0
            && window_within(&self.issued_at, &self.expires_at, MAX_ANCHOR_TTL_MILLIS)
            && self.payload_digest_matches()
        {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "sequence",
                "external anchor sequence must be positive",
            ))
        }
    }
}

impl ExternalMonotonicAnchorV1 {
    pub(crate) fn validate_at(&self, trusted_now: &str) -> Result<(), CoordinatorError> {
        self.validate()?;
        timestamp("trusted_now", trusted_now)?;
        if current(&self.issued_at, &self.expires_at, trusted_now) {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "anchor",
                "monotonic authority attestation is not current",
            ))
        }
    }
}
