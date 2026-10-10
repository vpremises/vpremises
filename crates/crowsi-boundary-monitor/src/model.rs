use serde::{Deserialize, Serialize};

pub const INPUT_SCHEMA: &str = "crowsi://network/boundary-input/v1";
pub const SNAPSHOT_SCHEMA: &str = "crowsi://network/boundary-snapshot/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryInputV1 {
    pub schema: String,
    pub generated_at: String,
    pub external_actions: bool,
    pub environments: Vec<BoundaryObservationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryObservationV1 {
    pub id: String,
    pub label: String,
    pub provider: String,
    pub source: String,
    pub status: String,
    pub isolation_mode: String,
    pub expected_isolation_mode: String,
    pub project_count: u32,
    pub network_count: u32,
    pub instance_count: u32,
    pub public_ingress: bool,
    pub management_endpoint_exposed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundarySnapshotV1 {
    pub schema: String,
    pub generated_at: String,
    pub external_actions: bool,
    pub overall_status: String,
    pub summary: BoundarySummaryV1,
    pub environments: Vec<EvaluatedEnvironmentV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct BoundarySummaryV1 {
    pub environment_count: usize,
    pub healthy_count: usize,
    pub attention_count: usize,
    pub unknown_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatedEnvironmentV1 {
    pub id: String,
    pub label: String,
    pub provider: String,
    pub source: String,
    pub status: String,
    pub isolation_mode: String,
    pub isolation_verified: bool,
    pub project_count: u32,
    pub network_count: u32,
    pub instance_count: u32,
    pub public_ingress: bool,
    pub finding_codes: Vec<String>,
}
