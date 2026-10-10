use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{FindingCodeV1, FindingV1};
use crate::{AddressFamilyV1, ListenerV1, RouteStateV1};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingWire {
    schema: String,
    code: FindingCodeV1,
    #[serde(deserialize_with = "required_nullable")]
    listener: Option<ListenerV1>,
    #[serde(deserialize_with = "required_nullable")]
    route_family: Option<AddressFamilyV1>,
    #[serde(deserialize_with = "required_nullable")]
    expected_route: Option<RouteStateV1>,
    #[serde(deserialize_with = "required_nullable")]
    observed_route: Option<RouteStateV1>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl<'de> Deserialize<'de> for FindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FindingWire::deserialize(deserializer)?;
        let value = Self {
            schema: wire.schema,
            code: wire.code,
            listener: wire.listener,
            route_family: wire.route_family,
            expected_route: wire.expected_route,
            observed_route: wire.observed_route,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}
