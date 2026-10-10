//! Validate closed drift findings and expose immutable metadata.
use super::{
    AddressFamilyV1, FINDING_SCHEMA_V1, FindingCodeV1, FindingV1, ListenerV1, RouteStateV1,
    SensorError, route_pair,
};

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
