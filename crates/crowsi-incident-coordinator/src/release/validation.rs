//! Validate signed command membership against a durable checkpoint.
use super::{
    COMMAND_RELEASE_SCHEMA_V1, CommandReleaseV1, CoordinatorError, IncidentCanonicalPayloadV1,
    Validate, digest, schema,
};

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
