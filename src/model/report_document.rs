//! The acquired body is private and closed; only validated metadata reaches the receipt.

use super::{ReportClassification, ReportRecordMode};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DepartmentDailyReport {
    pub schema: String,
    pub operational_report_id: String,
    pub record_mode: ReportRecordMode,
    pub reporting_date: String,
    pub headquarters_id: String,
    pub department_id: String,
    pub reporting_team_id: String,
    pub owner_account_id: String,
    pub window_started_at: String,
    pub window_ended_at: String,
    pub generated_at: String,
    pub source_case_ids: Vec<String>,
    pub source_event_ids: Vec<String>,
    pub source_task_ids: Vec<String>,
    pub source_report_ids: Vec<String>,
    pub source_artifact_ids: Vec<String>,
    pub escalated_decision_ids: Vec<String>,
    pub metrics: DepartmentDailyMetrics,
    pub exceptions: Vec<DepartmentDailyException>,
    pub classification: ReportClassification,
    pub customer_data: bool,
    pub summary: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DepartmentDailyMetrics {
    pub completed_tasks: u64,
    pub open_tasks: u64,
    pub blocked_tasks: u64,
    pub reported_deliverables: u64,
    pub open_escalations: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DepartmentDailyException {
    pub case_id: String,
    pub severity: String,
    pub status: String,
    pub decision_id: Option<String>,
}
