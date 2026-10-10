use serde::{Deserialize, Serialize};

use crate::validation::{
    MAX_FINDINGS, MAX_LISTENERS, known_routes, sort_unique, timestamp, unknown_routes,
};
use crate::{
    FindingCodeV1, FindingV1, ListenerV1, RoutesV1, SIGNAL_TRUST_UNSIGNED_LOCAL,
    SNAPSHOT_SCHEMA_V1, SensorError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotStatusV1 {
    Observed,
    Drifted,
    Unknown,
}

/// Metadata-only observation or baseline evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotV1 {
    pub(super) schema: String,
    pub(super) generated_at: String,
    pub(super) external_actions: bool,
    pub(super) signal_trust: String,
    pub(super) status: SnapshotStatusV1,
    pub(super) listeners: Vec<ListenerV1>,
    pub(super) default_routes: RoutesV1,
    pub(super) findings: Vec<FindingV1>,
}

mod wire;

mod construction;
mod view;
