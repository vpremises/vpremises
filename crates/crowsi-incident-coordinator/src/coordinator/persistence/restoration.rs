use crate::{
    CoordinatorCheckpointV1, CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1,
    ExternalMonotonicAnchorV1, IncidentCanonicalPayloadV1, IncidentCoordinator,
    MonotonicChallengeV1, MonotonicHeadReaderV1, Validate, coordinator::ClockMode,
    time::system_utc_now,
};

use super::verification::{verify_checkpoint, verify_current_head};

impl IncidentCoordinator {
    /// Restores state only when its signed checkpoint equals an external anchor.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated, rolled-back, or inconsistent state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn restore_authenticated(
        state: CoordinatorStateV1,
        checkpoint: &CoordinatorCheckpointV1,
        anchor: &ExternalMonotonicAnchorV1,
        challenge: MonotonicChallengeV1,
        expected_trust_bundle_digest: &str,
        trust: CoordinatorTrustV1,
        head_reader: &impl MonotonicHeadReaderV1,
    ) -> Result<Self, CoordinatorError> {
        trust.validate()?;
        let trusted_now = system_utc_now()?;
        challenge.validate_at(&trusted_now)?;
        crate::validation::digest("expected_trust_bundle_digest", expected_trust_bundle_digest)?;
        if state.snapshot.deployment_id != challenge.deployment_id()
            || state.snapshot.incident_id != challenge.incident_id()
            || trust.deployment_id != challenge.deployment_id()
            || state.snapshot.trust_bundle_digest != expected_trust_bundle_digest
            || trust.canonical_digest()? != expected_trust_bundle_digest
        {
            return Err(CoordinatorError::new(
                "restore_scope",
                "state does not match configured deployment and incident",
            ));
        }
        verify_checkpoint(&state, checkpoint, anchor, &challenge, &trust, &trusted_now)?;
        verify_current_head(checkpoint, head_reader)?;
        let mut value = Self::restore_validated(state, trust, ClockMode::System)?;
        value.snapshot.trusted_time_watermark = trusted_now;
        value.checkpoint_required = true;
        value.last_checkpoint_sequence = Some(checkpoint.sequence);
        value.last_checkpoint_digest = Some(checkpoint.payload_digest());
        Ok(value)
    }
}
