use crowsi_incident_coordinator::{
    CoordinatorCheckpointV1, IncidentCanonicalPayloadV1, MonotonicHeadReaderV1,
};

pub struct CurrentHead {
    deployment_id: String,
    incident_id: String,
    sequence: u64,
    digest: String,
}

impl MonotonicHeadReaderV1 for CurrentHead {
    fn is_current_head(
        &self,
        deployment_id: &str,
        incident_id: &str,
        sequence: u64,
        checkpoint_digest: &str,
    ) -> bool {
        self.deployment_id == deployment_id
            && self.incident_id == incident_id
            && self.sequence == sequence
            && self.digest == checkpoint_digest
    }
}

pub fn current_head(checkpoint: &CoordinatorCheckpointV1) -> CurrentHead {
    CurrentHead {
        deployment_id: checkpoint.deployment_id.clone(),
        incident_id: checkpoint.incident_id.clone(),
        sequence: checkpoint.sequence,
        digest: checkpoint.payload_digest(),
    }
}
