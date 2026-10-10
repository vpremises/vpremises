mod baseline;
mod common;
mod finding;
mod snapshot;

pub use baseline::BaselineV1;
pub use common::{AddressFamilyV1, BindScopeV1, ListenerV1, ProtocolV1, RouteStateV1, RoutesV1};
pub use finding::{FindingCodeV1, FindingV1};
pub use snapshot::{SnapshotStatusV1, SnapshotV1};

pub const BASELINE_SCHEMA_V1: &str = "crowsi://network/host-network-baseline/v1";
pub const SNAPSHOT_SCHEMA_V1: &str = "crowsi://network/host-network-snapshot/v1";
pub const FINDING_SCHEMA_V1: &str = "crowsi://network/host-network-finding/v1";
pub const SIGNAL_TRUST_UNSIGNED_LOCAL: &str = "unsigned-local";
