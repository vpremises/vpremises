use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::SensorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolV1 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamilyV1 {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindScopeV1 {
    Loopback,
    Specific,
    Wildcard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteStateV1 {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ListenerV1 {
    protocol: ProtocolV1,
    family: AddressFamilyV1,
    port: u16,
    bind_scope: BindScopeV1,
}

impl ListenerV1 {
    /// Creates metadata for one locally bound port.
    ///
    /// # Errors
    ///
    /// Rejects port zero, which is not an observable bound service port.
    pub const fn new(
        protocol: ProtocolV1,
        family: AddressFamilyV1,
        port: u16,
        bind_scope: BindScopeV1,
    ) -> Result<Self, SensorError> {
        if port == 0 {
            Err(SensorError::InvalidContract)
        } else {
            Ok(Self {
                protocol,
                family,
                port,
                bind_scope,
            })
        }
    }

    #[must_use]
    pub const fn protocol(&self) -> ProtocolV1 {
        self.protocol
    }
    #[must_use]
    pub const fn family(&self) -> AddressFamilyV1 {
        self.family
    }
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
    #[must_use]
    pub const fn bind_scope(&self) -> BindScopeV1 {
        self.bind_scope
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerWire {
    protocol: ProtocolV1,
    family: AddressFamilyV1,
    port: u16,
    bind_scope: BindScopeV1,
}

impl<'de> Deserialize<'de> for ListenerV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ListenerWire::deserialize(deserializer)?;
        Self::new(wire.protocol, wire.family, wire.port, wire.bind_scope).map_err(D::Error::custom)
    }
}

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
