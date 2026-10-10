//! Represent default-route availability without retaining destination addresses.
use super::{AddressFamilyV1, Deserialize, RouteStateV1, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesV1 {
    ipv4: RouteStateV1,
    ipv6: RouteStateV1,
}

impl RoutesV1 {
    #[must_use]
    pub const fn new(ipv4: RouteStateV1, ipv6: RouteStateV1) -> Self {
        Self { ipv4, ipv6 }
    }
    #[must_use]
    pub const fn ipv4(&self) -> RouteStateV1 {
        self.ipv4
    }
    #[must_use]
    pub const fn ipv6(&self) -> RouteStateV1 {
        self.ipv6
    }
    #[must_use]
    pub const fn get(&self, family: AddressFamilyV1) -> RouteStateV1 {
        match family {
            AddressFamilyV1::Ipv4 => self.ipv4,
            AddressFamilyV1::Ipv6 => self.ipv6,
        }
    }
}
