use crate::{
    CoordinatorCheckpointV1, CoordinatorError, ExternalMonotonicAnchorV1,
    IncidentCanonicalPayloadV1, IncidentCoordinator, MonotonicChallengeV1, MonotonicHeadReaderV1,
    coordinator::ClockMode, time::system_utc_now,
};

use super::verification::{verify_checkpoint, verify_current_head};

impl IncidentCoordinator {
    /// Releases staged commands after an exact checkpoint was durably committed.
    ///
    /// # Errors
    ///
    /// Rejects simulation mode, a branch, or a checkpoint not binding state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn confirm_checkpoint_commit(
        &mut self,
        checkpoint: &CoordinatorCheckpointV1,
        anchor: &ExternalMonotonicAnchorV1,
        challenge: MonotonicChallengeV1,
        head_reader: &impl MonotonicHeadReaderV1,
    ) -> Result<Vec<crate::CommandReleaseV1>, CoordinatorError> {
        if self.clock_mode != ClockMode::System || !self.checkpoint_required {
            return Err(CoordinatorError::new(
                "checkpoint",
                "no production checkpoint commit is pending",
            ));
        }
        let expected_sequence = self
            .last_checkpoint_sequence
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or_else(|| CoordinatorError::new("sequence", "checkpoint sequence overflow"))?;
        if checkpoint.sequence != expected_sequence
            || checkpoint.previous_checkpoint_digest != self.last_checkpoint_digest
        {
            return Err(CoordinatorError::new(
                "checkpoint",
                "sequence or previous digest does not extend the committed chain",
            ));
        }
        let trusted_now = system_utc_now()?;
        challenge.validate_at(&trusted_now)?;
        verify_checkpoint(
            &self.export_state(),
            checkpoint,
            anchor,
            &challenge,
            &self.trust,
            &trusted_now,
        )?;
        verify_current_head(checkpoint, head_reader)?;
        let released = self
            .pending_outbox
            .drain(..)
            .map(|command| {
                crate::CommandReleaseV1::new(command, checkpoint.clone(), anchor.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.checkpoint_required = false;
        self.last_checkpoint_sequence = Some(checkpoint.sequence);
        self.last_checkpoint_digest = Some(checkpoint.payload_digest());
        Ok(released)
    }
}
