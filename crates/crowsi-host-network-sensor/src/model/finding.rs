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

fn route_pair(expected: Option<RouteStateV1>, observed: Option<RouteStateV1>) -> bool {
    matches!(expected, Some(RouteStateV1::Present | RouteStateV1::Absent))
        && matches!(observed, Some(RouteStateV1::Present | RouteStateV1::Absent))
        && expected != observed
}

mod wire;

mod validation;
