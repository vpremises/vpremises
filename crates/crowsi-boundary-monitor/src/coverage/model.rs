use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlAuthority {
    Manage,
    ObserveOnly,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensorStatus {
    Connected,
    Degraded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcerStatus {
    Ready,
    Degraded,
    Absent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifelineStatus {
    Verified,
    Unknown,
    Absent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlAction {
    RevokeCredentials,
    Quarantine,
    VerifyIsolation,
    Restore,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageState {
    Controlled,
    Partial,
    Unknown,
    Unmanaged,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageInputV2 {
    pub schema: String,
    pub generated_at_epoch_s: u64,
    pub external_actions: bool,
    pub assets: Vec<CoverageAssetInputV2>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageAssetInputV2 {
    pub id: String,
    pub authority: ControlAuthority,
    pub sensor_status: SensorStatus,
    pub observed_at_epoch_s: u64,
    pub observation_ttl_s: u64,
    pub enforcer_status: EnforcerStatus,
    pub supported_actions: Vec<ControlAction>,
    pub lifeline_status: LifelineStatus,
    pub last_drill_at_epoch_s: Option<u64>,
    pub drill_ttl_s: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageSnapshotV2 {
    pub schema: String,
    pub generated_at_epoch_s: u64,
    pub external_actions: bool,
    pub overall_state: CoverageState,
    pub summary: CoverageSummaryV2,
    pub assets: Vec<CoverageAssetResultV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct CoverageSummaryV2 {
    pub asset_count: usize,
    pub controlled_count: usize,
    pub gap_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageAssetResultV2 {
    pub id: String,
    pub state: CoverageState,
    pub isolation_ready: bool,
    pub finding_codes: Vec<String>,
}
