mod commit;
mod restoration;
mod verification;

use crate::{
    COORDINATOR_STATE_SCHEMA_V1, CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1,
    IncidentCoordinator, MonotonicChallengeV1, Validate, coordinator::ClockMode,
};

impl IncidentCoordinator {
    #[must_use]
    pub fn export_state(&self) -> CoordinatorStateV1 {
        CoordinatorStateV1 {
            schema: COORDINATOR_STATE_SCHEMA_V1.to_owned(),
            snapshot: self.snapshot.clone(),
            seen_event_jtis: self.seen_event_jtis.clone(),
            seen_receipt_jtis: self.seen_receipt_jtis.clone(),
            reserved_authorization_jtis: self.reserved_authorization_jtis.clone(),
            used_approval_ids: self.used_approval_ids.clone(),
            seen_evidence_jtis: self.seen_evidence_jtis.clone(),
            pending_outbox: self.pending_outbox.clone(),
            pending_recovery: self.pending_recovery.clone(),
            monitoring_evidence: self.monitoring_evidence.clone(),
        }
    }

    /// Issues a fresh, one-use challenge for an authenticated restore.
    ///
    /// # Errors
    ///
    /// Fails if identifiers are invalid or OS randomness is unavailable.
    pub fn begin_authenticated_restore(
        deployment_id: &str,
        incident_id: &str,
    ) -> Result<MonotonicChallengeV1, CoordinatorError> {
        MonotonicChallengeV1::issue(deployment_id, incident_id)
    }

    /// Issues a fresh challenge for the pending production checkpoint commit.
    ///
    /// # Errors
    ///
    /// Rejects simulation mode or a coordinator without a pending commit.
    pub fn checkpoint_commit_challenge(&self) -> Result<MonotonicChallengeV1, CoordinatorError> {
        if self.clock_mode != ClockMode::System || !self.checkpoint_required {
            return Err(CoordinatorError::new(
                "checkpoint",
                "no production checkpoint commit is pending",
            ));
        }
        MonotonicChallengeV1::issue(&self.snapshot.deployment_id, &self.snapshot.incident_id)
    }

    /// Restores structural state for deterministic tests only.
    ///
    /// This API provides no checkpoint provenance or rollback protection.
    ///
    /// # Errors
    ///
    /// Rejects unsupported or internally inconsistent state.
    pub fn restore_simulation(
        state: CoordinatorStateV1,
        trust: CoordinatorTrustV1,
    ) -> Result<Self, CoordinatorError> {
        trust.validate()?;
        Self::restore_validated(state, trust, ClockMode::Simulation)
    }

    pub(super) fn restore_validated(
        state: CoordinatorStateV1,
        trust: CoordinatorTrustV1,
        clock_mode: ClockMode,
    ) -> Result<Self, CoordinatorError> {
        state.validate_with_trust(&trust)?;
        Ok(Self {
            snapshot: state.snapshot,
            seen_event_jtis: state.seen_event_jtis,
            seen_receipt_jtis: state.seen_receipt_jtis,
            reserved_authorization_jtis: state.reserved_authorization_jtis,
            used_approval_ids: state.used_approval_ids,
            seen_evidence_jtis: state.seen_evidence_jtis,
            pending_outbox: state.pending_outbox,
            pending_recovery: state.pending_recovery,
            monitoring_evidence: state.monitoring_evidence,
            trust,
            clock_mode,
            checkpoint_required: false,
            last_checkpoint_sequence: None,
            last_checkpoint_digest: None,
        })
    }
}
