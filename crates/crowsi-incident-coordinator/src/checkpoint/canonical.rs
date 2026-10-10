use crate::{IncidentCanonicalPayloadV1, canonical::Encoder};

use super::{CoordinatorCheckpointV1, ExternalMonotonicAnchorV1};

impl IncidentCanonicalPayloadV1 for CoordinatorCheckpointV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("coordinator-checkpoint-v1");
        value.text("schema", &self.schema);
        value.text("checkpoint_id", &self.checkpoint_id);
        value.text("jti", &self.jti);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.text("trust_bundle_digest", &self.trust_bundle_digest);
        value.number("trust_revision", self.trust_revision);
        value.number("sequence", self.sequence);
        value.optional_text(
            "previous_checkpoint_digest",
            self.previous_checkpoint_digest.as_deref(),
        );
        value.text("state_digest", &self.state_digest);
        value.number("command_digest_count", self.command_digests.len() as u64);
        for (index, digest) in self.command_digests.iter().enumerate() {
            value.text(&format!("command_digest.{index}"), digest);
        }
        value.text("issued_at", &self.issued_at);
        value.text("authority", &self.authority);
        value.finish()
    }

    fn signed_digest(&self) -> &crowsi_control_contracts::SignedDigestV1 {
        &self.signed
    }
}

impl IncidentCanonicalPayloadV1 for ExternalMonotonicAnchorV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("external-monotonic-anchor-v1");
        value.text("schema", &self.schema);
        value.text("anchor_id", &self.anchor_id);
        value.text("jti", &self.jti);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.text("challenge_nonce", &self.challenge_nonce);
        value.number("sequence", self.sequence);
        value.text("checkpoint_digest", &self.checkpoint_digest);
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.text("authority", &self.authority);
        value.finish()
    }

    fn signed_digest(&self) -> &crowsi_control_contracts::SignedDigestV1 {
        &self.signed
    }
}
