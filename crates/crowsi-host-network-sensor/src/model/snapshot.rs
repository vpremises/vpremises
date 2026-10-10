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

impl SnapshotV1 {
    /// Creates a complete observation with no baseline interpretation.
    ///
    /// # Errors
    ///
    /// Rejects malformed time, unknown routes, duplicates, or excess listeners.
    pub fn observed(
        generated_at: impl Into<String>,
        mut listeners: Vec<ListenerV1>,
        default_routes: RoutesV1,
    ) -> Result<Self, SensorError> {
        sort_unique(&mut listeners, MAX_LISTENERS)?;
        Self::build(
            generated_at.into(),
            SnapshotStatusV1::Observed,
            listeners,
            default_routes,
            Vec::new(),
        )
    }

    pub(crate) fn unknown(
        generated_at: impl Into<String>,
        code: FindingCodeV1,
    ) -> Result<Self, SensorError> {
        Self::build(
            generated_at.into(),
            SnapshotStatusV1::Unknown,
            Vec::new(),
            RoutesV1::new(crate::RouteStateV1::Unknown, crate::RouteStateV1::Unknown),
            vec![FindingV1::source(code)],
        )
    }

    pub(crate) fn evaluated(&self, mut findings: Vec<FindingV1>) -> Result<Self, SensorError> {
        sort_unique(&mut findings, MAX_FINDINGS)?;
        let status = if findings.is_empty() {
            SnapshotStatusV1::Observed
        } else {
            SnapshotStatusV1::Drifted
        };
        Self::build(
            self.generated_at.clone(),
            status,
            self.listeners.clone(),
            self.default_routes.clone(),
            findings,
        )
    }

    fn build(
        generated_at: String,
        status: SnapshotStatusV1,
        listeners: Vec<ListenerV1>,
        default_routes: RoutesV1,
        findings: Vec<FindingV1>,
    ) -> Result<Self, SensorError> {
        let value = Self {
            schema: SNAPSHOT_SCHEMA_V1.to_owned(),
            generated_at,
            external_actions: false,
            signal_trust: SIGNAL_TRUST_UNSIGNED_LOCAL.to_owned(),
            status,
            listeners,
            default_routes,
            findings,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), SensorError> {
        if self.schema != SNAPSHOT_SCHEMA_V1
            || !timestamp(&self.generated_at)
            || self.external_actions
            || self.signal_trust != SIGNAL_TRUST_UNSIGNED_LOCAL
        {
            return Err(SensorError::InvalidContract);
        }
        crate::validation::validate_sorted(&self.listeners, MAX_LISTENERS)?;
        crate::validation::validate_sorted(&self.findings, MAX_FINDINGS)?;
        let shape = match self.status {
            SnapshotStatusV1::Observed => {
                self.findings.is_empty() && known_routes(&self.default_routes)
            }
            SnapshotStatusV1::Drifted => {
                !self.findings.is_empty()
                    && self.findings.iter().all(FindingV1::is_drift)
                    && known_routes(&self.default_routes)
            }
            SnapshotStatusV1::Unknown => {
                self.listeners.is_empty()
                    && !self.findings.is_empty()
                    && self.findings.iter().all(FindingV1::is_source)
                    && unknown_routes(&self.default_routes)
            }
        };
        self.findings.iter().try_for_each(FindingV1::validate)?;
        shape.then_some(()).ok_or(SensorError::InvalidContract)
    }

    #[must_use]
    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }
    #[must_use]
    pub const fn external_actions(&self) -> bool {
        self.external_actions
    }
    #[must_use]
    pub fn signal_trust(&self) -> &str {
        &self.signal_trust
    }
    #[must_use]
    pub const fn status(&self) -> SnapshotStatusV1 {
        self.status
    }
    #[must_use]
    pub fn listeners(&self) -> &[ListenerV1] {
        &self.listeners
    }
    #[must_use]
    pub const fn default_routes(&self) -> &RoutesV1 {
        &self.default_routes
    }
    #[must_use]
    pub fn findings(&self) -> &[FindingV1] {
        &self.findings
    }
}

mod wire;
