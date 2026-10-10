pub(crate) mod aggregate;
mod apply;
mod candidate;
mod construction;
mod events;
mod monitoring;
mod operations;
mod persistence;
mod planning;
mod receipts;
mod transitions;
pub(crate) mod verifications;

use std::collections::BTreeSet;

use crate::{
    CoordinatorCommandV1, CoordinatorTrustV1, IncidentSnapshotV1, MonitoringEvidenceV1,
    RecoveryApprovalV1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClockMode {
    System,
    Simulation,
}

#[derive(Debug)]
pub struct IncidentCoordinator {
    snapshot: IncidentSnapshotV1,
    seen_event_jtis: BTreeSet<String>,
    seen_receipt_jtis: BTreeSet<String>,
    reserved_authorization_jtis: BTreeSet<String>,
    used_approval_ids: BTreeSet<String>,
    seen_evidence_jtis: BTreeSet<String>,
    pending_recovery: Option<RecoveryApprovalV1>,
    monitoring_evidence: Option<MonitoringEvidenceV1>,
    trust: CoordinatorTrustV1,
    clock_mode: ClockMode,
    checkpoint_required: bool,
    last_checkpoint_sequence: Option<u64>,
    last_checkpoint_digest: Option<String>,
    pending_outbox: Vec<CoordinatorCommandV1>,
}

impl IncidentCoordinator {
    #[must_use]
    pub const fn snapshot(&self) -> &IncidentSnapshotV1 {
        &self.snapshot
    }

    /// Reports whether production apply is gated on a durable checkpoint.
    #[must_use]
    pub const fn checkpoint_required(&self) -> bool {
        self.checkpoint_required
    }
}
