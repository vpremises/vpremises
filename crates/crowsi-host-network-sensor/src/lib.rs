//! Unsigned, read-only host network metadata for the current Linux namespace.

mod error;
mod evaluate;
mod input;
mod model;
mod sample;
mod sensor;
mod time;
mod validation;

pub use error::SensorError;
pub use evaluate::evaluate_drift;
pub use input::read_baseline;
pub use model::{
    AddressFamilyV1, BASELINE_SCHEMA_V1, BaselineV1, BindScopeV1, FINDING_SCHEMA_V1, FindingCodeV1,
    FindingV1, ListenerV1, ProtocolV1, RouteStateV1, RoutesV1, SIGNAL_TRUST_UNSIGNED_LOCAL,
    SNAPSHOT_SCHEMA_V1, SnapshotStatusV1, SnapshotV1,
};
pub use sample::{SAMPLE_TIME, sample_baseline, sample_snapshot};
pub use sensor::observe_host;
pub use time::{now_rfc3339, unix_millis_to_rfc3339};
