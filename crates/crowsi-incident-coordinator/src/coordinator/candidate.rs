use crate::IncidentCoordinator;

impl IncidentCoordinator {
    pub(super) fn fork_candidate(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            seen_event_jtis: self.seen_event_jtis.clone(),
            seen_receipt_jtis: self.seen_receipt_jtis.clone(),
            reserved_authorization_jtis: self.reserved_authorization_jtis.clone(),
            used_approval_ids: self.used_approval_ids.clone(),
            seen_evidence_jtis: self.seen_evidence_jtis.clone(),
            pending_recovery: self.pending_recovery.clone(),
            monitoring_evidence: self.monitoring_evidence.clone(),
            trust: self.trust.clone(),
            clock_mode: self.clock_mode,
            checkpoint_required: self.checkpoint_required,
            last_checkpoint_sequence: self.last_checkpoint_sequence,
            last_checkpoint_digest: self.last_checkpoint_digest.clone(),
            pending_outbox: self.pending_outbox.clone(),
        }
    }
}
