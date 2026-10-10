use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{SnapshotStatusV1, SnapshotV1};
use crate::validation::{MAX_FINDINGS, MAX_LISTENERS, sort_unique};
use crate::{FindingV1, ListenerV1, RoutesV1};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    schema: String,
    generated_at: String,
    external_actions: bool,
    signal_trust: String,
    status: SnapshotStatusV1,
    listeners: Vec<ListenerV1>,
    default_routes: RoutesV1,
    findings: Vec<FindingV1>,
}

impl<'de> Deserialize<'de> for SnapshotV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SnapshotWire::deserialize(deserializer)?;
        let mut listeners = wire.listeners;
        let mut findings = wire.findings;
        sort_unique(&mut listeners, MAX_LISTENERS).map_err(D::Error::custom)?;
        sort_unique(&mut findings, MAX_FINDINGS).map_err(D::Error::custom)?;
        let value = Self {
            schema: wire.schema,
            generated_at: wire.generated_at,
            external_actions: wire.external_actions,
            signal_trust: wire.signal_trust,
            status: wire.status,
            listeners,
            default_routes: wire.default_routes,
            findings,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}
