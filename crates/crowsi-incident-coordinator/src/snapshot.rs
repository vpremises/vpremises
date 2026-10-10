use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{IncidentPhase, TargetStateV1};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentSnapshotV1 {
    pub deployment_id: String,
    pub incident_owner_authority: String,
    pub trust_bundle_digest: String,
    pub trust_revision: u64,
    pub incident_id: String,
    pub phase: IncidentPhase,
    pub isolation_epoch: u64,
    pub restore_attempt: u64,
    pub detected_at: String,
    pub last_event_at: String,
    pub trusted_time_watermark: String,
    pub recovery_approval_id: Option<String>,
    pub monitoring_started_at: Option<String>,
    pub monitoring_evidence_jti: Option<String>,
    pub targets: BTreeMap<String, TargetStateV1>,
}
