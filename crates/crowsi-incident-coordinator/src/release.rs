use serde::{Deserialize, Serialize};

use crate::{
    AtomicReleaseConsumerV1, AtomicReleaseRequestV1, COMMAND_RELEASE_SCHEMA_V1,
    CoordinatorCheckpointV1, CoordinatorCommandV1, CoordinatorError, CoordinatorTrustV1,
    ExternalMonotonicAnchorV1, IncidentCanonicalPayloadV1, Validate,
    time::system_utc_now,
    trust::{TrustRole, TrustScope, ensure_separate_control_planes},
    validation::{digest, schema},
};

/// A command with cryptographic proof that it belongs to the current durable
/// checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReleaseV1 {
    schema: String,
    command: CoordinatorCommandV1,
    command_digest: String,
    checkpoint: CoordinatorCheckpointV1,
    anchor: ExternalMonotonicAnchorV1,
}

impl CommandReleaseV1 {
    pub(crate) fn new(
        command: CoordinatorCommandV1,
        checkpoint: CoordinatorCheckpointV1,
        anchor: ExternalMonotonicAnchorV1,
    ) -> Result<Self, CoordinatorError> {
        let command_digest = command.canonical_digest()?;
        Ok(Self {
            schema: COMMAND_RELEASE_SCHEMA_V1.to_owned(),
            command,
            command_digest,
            checkpoint,
            anchor,
        })
    }

    #[must_use]
    pub const fn command(&self) -> &CoordinatorCommandV1 {
        &self.command
    }

    #[must_use]
    pub fn command_digest(&self) -> &str {
        &self.command_digest
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &CoordinatorCheckpointV1 {
        &self.checkpoint
    }

    #[must_use]
    pub const fn anchor(&self) -> &ExternalMonotonicAnchorV1 {
        &self.anchor
    }

    /// Verifies membership, both signatures, trust pin, and freshness, then
    /// delegates current-head checking and one-use reservation to one atomic
    /// boundary before Policy Administrator issuance.
    ///
    /// # Errors
    ///
    /// Rejects stale, forged, cross-deployment, or non-member commands.
    pub fn consume_if_current<E: AtomicReleaseConsumerV1>(
        self,
        expected_trust_bundle_digest: &str,
        trust: &CoordinatorTrustV1,
        consumer: &mut E,
    ) -> Result<E::Output, CoordinatorError> {
        self.validate()?;
        trust.validate()?;
        digest("expected_trust_bundle_digest", expected_trust_bundle_digest)?;
        let trusted_now = system_utc_now()?;
        self.checkpoint.validate_at(&trusted_now)?;
        self.anchor.validate_at(&trusted_now)?;
        if trust.deployment_id != self.command.deployment_id
            || trust.revision != self.checkpoint.trust_revision
            || self.checkpoint.trust_bundle_digest != expected_trust_bundle_digest
            || trust.canonical_digest()? != expected_trust_bundle_digest
        {
            return Err(CoordinatorError::new(
                "release_trust",
                "release does not match root-pinned deployment trust",
            ));
        }
        let checkpoint_signer = trust.verify(
            Some(&self.checkpoint.authority),
            TrustRole::CheckpointAuthority,
            TrustScope::Checkpoint,
            &self.checkpoint.signed,
            &self.checkpoint.signing_payload(),
        )?;
        let anchor_signer = trust.verify(
            Some(&self.anchor.authority),
            TrustRole::AnchorAuthority,
            TrustScope::Anchor,
            &self.anchor.signed,
            &self.anchor.signing_payload(),
        )?;
        ensure_separate_control_planes(checkpoint_signer, anchor_signer)?;
        consumer.consume_if_current(AtomicReleaseRequestV1 { release: &self })
    }
}

impl Validate for CommandReleaseV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, COMMAND_RELEASE_SCHEMA_V1)?;
        self.command.validate()?;
        self.checkpoint.validate()?;
        self.anchor.validate()?;
        digest("command_digest", &self.command_digest)?;
        let exact = self.command.canonical_digest()? == self.command_digest
            && self
                .checkpoint
                .command_digests
                .binary_search(&self.command_digest)
                .is_ok()
            && self.command.deployment_id == self.checkpoint.deployment_id
            && self.command.incident_id == self.checkpoint.incident_id
            && self.anchor.deployment_id == self.checkpoint.deployment_id
            && self.anchor.incident_id == self.checkpoint.incident_id
            && self.anchor.sequence == self.checkpoint.sequence
            && self.anchor.checkpoint_digest == self.checkpoint.payload_digest()
            && self.command.issued_at <= self.checkpoint.issued_at;
        if exact {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "command_release",
                "command is not a member of the anchored checkpoint",
            ))
        }
    }
}
