//! Mounted-report contracts bind one expected artifact to one allowlisted local root.

use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

/// Closed request binding one report to an expected organizational context.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MountedSharePointReportRequest {
    pub schema: String,
    pub request_id: String,
    pub correlation_id: String,
    pub artifact_id: String,
    pub expected_report: ExpectedDepartmentDailyReport,
    pub allowlisted_root: ReportAllowedRoot,
    pub relative_file: String,
    pub max_bytes: u64,
}

/// Portable root reference resolved outside the acquisition library.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportAllowedRoot {
    pub id: String,
    pub base: ReportRootBase,
    pub relative_path: PathBuf,
}

/// Base from which the portable root path is resolved by the caller.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReportRootBase {
    WorkspaceRoot,
    RequestDirectory,
}

/// Identity and information policy expected in the report body.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDepartmentDailyReport {
    pub record_mode: ReportRecordMode,
    pub reporting_date: String,
    pub headquarters_id: String,
    pub department_id: String,
    pub reporting_team_id: String,
    pub owner_account_id: String,
    pub classification: ReportClassification,
    pub customer_data: bool,
}

/// Supported operational record modes.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReportRecordMode {
    SimulationSeed,
    Runtime,
    Imported,
}

/// Supported information classifications.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReportClassification {
    Internal,
    InternalConfidential,
    PersonalConfidential,
    RestrictedSensitive,
    CustomerConfidential,
}

/// Content-free receipt for exact validated report bytes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MountedSharePointReportReceipt {
    pub schema: &'static str,
    pub request_id: String,
    pub receipt_id: String,
    pub correlation_id: String,
    pub root_id: String,
    pub artifact_id: String,
    pub operational_report_id: String,
    pub headquarters_id: String,
    pub department_id: String,
    pub reporting_team_id: String,
    pub schema_id: &'static str,
    pub media_type: &'static str,
    pub size_bytes: u64,
    pub digest_sha256: String,
    pub classification: String,
    pub customer_data: bool,
    pub external_actions: bool,
}

/// Stable fail-closed acquisition error.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportAcquisitionError {
    pub code: &'static str,
    pub field: &'static str,
    pub message: &'static str,
}

impl fmt::Display for ReportAcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ReportAcquisitionError {}
