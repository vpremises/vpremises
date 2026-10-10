use crate::{
    COORDINATOR_CHECKPOINT_SCHEMA_V1, CoordinatorError, IncidentCanonicalPayloadV1,
    MONOTONIC_ANCHOR_SCHEMA_V1, Validate,
    time::{current, window_within},
    validation::{digest, identifier, schema, timestamp},
};

use super::{CoordinatorCheckpointV1, ExternalMonotonicAnchorV1};

const MAX_ANCHOR_TTL_MILLIS: i64 = 60_000;
const MAX_CHECKPOINT_COMMANDS: usize = 4_096;

impl CoordinatorCheckpointV1 {
    /// Validates checkpoint structure and its relationship to trusted time.
    ///
    /// # Errors
    ///
    /// Rejects malformed, future-issued, or non-chainable checkpoints.
    pub fn validate_at(&self, trusted_now: &str) -> Result<(), CoordinatorError> {
        self.validate()?;
        timestamp("trusted_now", trusted_now)?;
        if self.issued_at.as_str() <= trusted_now {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "issued_at",
                "checkpoint must not be issued in the future",
            ))
        }
    }
}

impl Validate for CoordinatorCheckpointV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, COORDINATOR_CHECKPOINT_SCHEMA_V1)?;
        identifier("checkpoint_id", &self.checkpoint_id)?;
        identifier("jti", &self.jti)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        digest("trust_bundle_digest", &self.trust_bundle_digest)?;
        if self.trust_revision == 0 {
            return Err(CoordinatorError::new("trust_revision", "must be positive"));
        }
        identifier("checkpoint.authority", &self.authority)?;
        timestamp("issued_at", &self.issued_at)?;
        digest("state_digest", &self.state_digest)?;
        if self.command_digests.len() > MAX_CHECKPOINT_COMMANDS {
            return Err(CoordinatorError::new(
                "command_digests",
                "exceeds the bounded checkpoint outbox",
            ));
        }
        for command_digest in &self.command_digests {
            digest("command_digests", command_digest)?;
        }
        if !self
            .command_digests
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(CoordinatorError::new(
                "command_digests",
                "must be sorted and unique",
            ));
        }
        crowsi_control_contracts::Validate::validate(&self.signed)?;
        if let Some(previous) = &self.previous_checkpoint_digest {
            digest("previous_checkpoint_digest", previous)?;
        }
        let chain_shape = self.sequence > 0
            && ((self.sequence == 1 && self.previous_checkpoint_digest.is_none())
                || (self.sequence > 1 && self.previous_checkpoint_digest.is_some()));
        if !chain_shape || !self.payload_digest_matches() {
            return Err(CoordinatorError::new(
                "checkpoint",
                "chain shape or canonical signed digest is invalid",
            ));
        }
        Ok(())
    }
}

mod anchors;
