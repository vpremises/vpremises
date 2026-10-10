use std::collections::BTreeSet;

use crowsi_incident_coordinator::{
    AtomicReleaseConsumerV1, AtomicReleaseRequestV1, CoordinatorCheckpointV1, CoordinatorError,
    IncidentCanonicalPayloadV1,
};

pub struct AtomicGate {
    deployment_id: String,
    incident_id: String,
    sequence: u64,
    checkpoint_digest: String,
    consumed: BTreeSet<String>,
    advance_before_execution: bool,
}

impl AtomicGate {
    pub fn current(checkpoint: &CoordinatorCheckpointV1) -> Self {
        Self {
            deployment_id: checkpoint.deployment_id.clone(),
            incident_id: checkpoint.incident_id.clone(),
            sequence: checkpoint.sequence,
            checkpoint_digest: checkpoint.payload_digest(),
            consumed: BTreeSet::new(),
            advance_before_execution: false,
        }
    }

    pub fn advancing(checkpoint: &CoordinatorCheckpointV1) -> Self {
        let mut value = Self::current(checkpoint);
        value.advance_before_execution = true;
        value
    }
}

impl AtomicReleaseConsumerV1 for AtomicGate {
    type Output = String;

    fn consume_if_current(
        &mut self,
        request: AtomicReleaseRequestV1<'_>,
    ) -> Result<Self::Output, CoordinatorError> {
        if self.advance_before_execution {
            self.sequence = self.sequence.saturating_add(1);
            self.advance_before_execution = false;
        }
        let command = request.command();
        let exact = self.deployment_id == command.deployment_id
            && self.incident_id == command.incident_id
            && self.sequence == request.checkpoint_sequence()
            && self.checkpoint_digest == request.checkpoint_digest();
        if !exact || !self.consumed.insert(request.command_digest().to_owned()) {
            return Err(CoordinatorError::new(
                "atomic_execution",
                "stale head or replay",
            ));
        }
        Ok(command.jti.clone())
    }
}
