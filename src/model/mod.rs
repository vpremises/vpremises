//! Public contracts keep general observation separate from mounted-report acquisition.

mod observation;
mod report;
pub(crate) mod report_document;

pub use observation::{
    AllowedRoot, Diagnostic, ObservationLimits, ObservationPolicy, ObservationReport,
    ObservationTotals, ObserverConfig, ReportedPolicy, RootObservation,
};
pub use report::{
    ExpectedDepartmentDailyReport, MountedSharePointReportReceipt, MountedSharePointReportRequest,
    ReportAcquisitionError, ReportAllowedRoot, ReportClassification, ReportRecordMode,
    ReportRootBase,
};
pub(crate) use report_document::DepartmentDailyReport;
