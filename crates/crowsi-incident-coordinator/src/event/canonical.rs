use crate::{
    IncidentCanonicalPayloadV1,
    canonical::{Encoder, digest_payload},
};

use super::IncidentEventV1;

impl IncidentCanonicalPayloadV1 for IncidentEventV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let kind = serde_json::to_vec(&self.kind).expect("closed event kind is serializable");
        let mut value = Encoder::new("incident-event-v1");
        value.text("schema", &self.schema);
        value.text("event_id", &self.event_id);
        value.text("jti", &self.jti);
        value.text("deployment_id", &self.deployment_id);
        value.text("incident_id", &self.incident_id);
        value.number("isolation_epoch", self.isolation_epoch);
        value.text("occurred_at", &self.occurred_at);
        value.text("valid_until", &self.valid_until);
        value.text("owner_authority", &self.owner_authority);
        value.text("kind_digest", &digest_payload(&kind));
        value.finish()
    }

    fn signed_digest(&self) -> &crowsi_control_contracts::SignedDigestV1 {
        &self.signed
    }
}
