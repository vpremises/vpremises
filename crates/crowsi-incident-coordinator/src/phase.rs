use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncidentPhase {
    Detected,
    Triage,
    ContainmentRequested,
    Contained,
    ContainmentPartial,
    ContainmentFailed,
    Eradication,
    RecoveryPending,
    RecoveryAuthorized,
    Restoring,
    Restored,
    RestorePartial,
    RestoreFailed,
    Monitoring,
    Closed,
}
