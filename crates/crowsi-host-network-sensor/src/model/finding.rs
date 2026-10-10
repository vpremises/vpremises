use serde::{Deserialize, Serialize};

use crate::{AddressFamilyV1, FINDING_SCHEMA_V1, ListenerV1, RouteStateV1, SensorError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCodeV1 {
    UnexpectedListener,
    ExpectedListenerMissing,
    DefaultRouteChanged,
    SourceUnavailable,
    SourceParseFailure,
}

/// A closed finding with no free-form operating-system or endpoint text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FindingV1 {
    pub(super) schema: String,
    pub(super) code: FindingCodeV1,
    pub(super) listener: Option<ListenerV1>,
    pub(super) route_family: Option<AddressFamilyV1>,
    pub(super) expected_route: Option<RouteStateV1>,
    pub(super) observed_route: Option<RouteStateV1>,
}

impl FindingV1 {
    pub(crate) fn listener(code: FindingCodeV1, listener: ListenerV1) -> Self {
        Self {
            schema: FINDING_SCHEMA_V1.to_owned(),
            code,
            listener: Some(listener),
            route_family: None,
            expected_route: None,
            observed_route: None,
        }
    }

    pub(crate) fn route(
        family: AddressFamilyV1,
        expected: RouteStateV1,
        observed: RouteStateV1,
    ) -> Self {
        Self {
            schema: FINDING_SCHEMA_V1.to_owned(),
            code: FindingCodeV1::DefaultRouteChanged,
            listener: None,
            route_family: Some(family),
            expected_route: Some(expected),
            observed_route: Some(observed),
        }
    }

    pub(crate) fn source(code: FindingCodeV1) -> Self {
        Self {
            schema: FINDING_SCHEMA_V1.to_owned(),
            code,
            listener: None,
            route_family: None,
            expected_route: None,
            observed_route: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SensorError> {
        if self.schema != FINDING_SCHEMA_V1 {
            return Err(SensorError::InvalidContract);
        }
        let valid = match self.code {
            FindingCodeV1::UnexpectedListener | FindingCodeV1::ExpectedListenerMissing => {
                self.listener.is_some()
                    && self.route_family.is_none()
                    && self.expected_route.is_none()
                    && self.observed_route.is_none()
            }
            FindingCodeV1::DefaultRouteChanged => {
                self.listener.is_none()
                    && self.route_family.is_some()
                    && route_pair(self.expected_route, self.observed_route)
            }
            FindingCodeV1::SourceUnavailable | FindingCodeV1::SourceParseFailure => {
                self.listener.is_none()
                    && self.route_family.is_none()
                    && self.expected_route.is_none()
                    && self.observed_route.is_none()
            }
        };
        valid.then_some(()).ok_or(SensorError::InvalidContract)
    }

    pub(crate) const fn is_source(&self) -> bool {
        matches!(
            self.code,
            FindingCodeV1::SourceUnavailable | FindingCodeV1::SourceParseFailure
        )
    }
    pub(crate) const fn is_drift(&self) -> bool {
        !self.is_source()
    }
    #[must_use]
    pub const fn code(&self) -> FindingCodeV1 {
        self.code
    }
    #[must_use]
    pub const fn listener_metadata(&self) -> Option<&ListenerV1> {
        self.listener.as_ref()
    }
    #[must_use]
    pub const fn route_family(&self) -> Option<AddressFamilyV1> {
        self.route_family
    }
    #[must_use]
    pub const fn expected_route(&self) -> Option<RouteStateV1> {
        self.expected_route
    }
    #[must_use]
    pub const fn observed_route(&self) -> Option<RouteStateV1> {
        self.observed_route
    }
}

fn route_pair(expected: Option<RouteStateV1>, observed: Option<RouteStateV1>) -> bool {
    matches!(expected, Some(RouteStateV1::Present | RouteStateV1::Absent))
        && matches!(observed, Some(RouteStateV1::Present | RouteStateV1::Absent))
        && expected != observed
}

mod wire;
