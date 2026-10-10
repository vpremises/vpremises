use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::validation::{MAX_LISTENERS, known_routes, sort_unique, valid_identifier};
use crate::{BASELINE_SCHEMA_V1, ListenerV1, RoutesV1, SIGNAL_TRUST_UNSIGNED_LOCAL, SensorError};

/// Unsigned operator-reviewed expectations for metadata-only drift comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineV1 {
    schema: String,
    baseline_id: String,
    external_actions: bool,
    signal_trust: String,
    expected_listeners: Vec<ListenerV1>,
    expected_default_routes: RoutesV1,
}

impl BaselineV1 {
    /// Creates a canonical baseline without granting any enforcement authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, duplicates, unknown routes, or excess entries.
    pub fn try_new(
        baseline_id: impl Into<String>,
        mut expected_listeners: Vec<ListenerV1>,
        expected_default_routes: RoutesV1,
    ) -> Result<Self, SensorError> {
        sort_unique(&mut expected_listeners, MAX_LISTENERS)?;
        let value = Self {
            schema: BASELINE_SCHEMA_V1.to_owned(),
            baseline_id: baseline_id.into(),
            external_actions: false,
            signal_trust: SIGNAL_TRUST_UNSIGNED_LOCAL.to_owned(),
            expected_listeners,
            expected_default_routes,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), SensorError> {
        if self.schema != BASELINE_SCHEMA_V1
            || !valid_identifier(&self.baseline_id)
            || self.external_actions
            || self.signal_trust != SIGNAL_TRUST_UNSIGNED_LOCAL
            || !known_routes(&self.expected_default_routes)
        {
            return Err(SensorError::InvalidContract);
        }
        crate::validation::validate_sorted(&self.expected_listeners, MAX_LISTENERS)
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }
    #[must_use]
    pub fn baseline_id(&self) -> &str {
        &self.baseline_id
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
    pub fn expected_listeners(&self) -> &[ListenerV1] {
        &self.expected_listeners
    }
    #[must_use]
    pub const fn expected_default_routes(&self) -> &RoutesV1 {
        &self.expected_default_routes
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineWire {
    schema: String,
    baseline_id: String,
    external_actions: bool,
    signal_trust: String,
    expected_listeners: Vec<ListenerV1>,
    expected_default_routes: RoutesV1,
}

impl<'de> Deserialize<'de> for BaselineV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BaselineWire::deserialize(deserializer)?;
        let mut listeners = wire.expected_listeners;
        sort_unique(&mut listeners, MAX_LISTENERS).map_err(D::Error::custom)?;
        let value = Self {
            schema: wire.schema,
            baseline_id: wire.baseline_id,
            external_actions: wire.external_actions,
            signal_trust: wire.signal_trust,
            expected_listeners: listeners,
            expected_default_routes: wire.expected_default_routes,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}
