mod evaluate;
mod model;
mod validation;

pub use evaluate::evaluate_coverage;
pub use model::{
    ControlAction, ControlAuthority, ControlCoverageInputV2, ControlCoverageSnapshotV2,
    CoverageAssetInputV2, CoverageAssetResultV2, CoverageState, EnforcerStatus, LifelineStatus,
    SensorStatus,
};
pub use validation::{
    ValidatedControlCoverageInputV2, parse_coverage_input, validate_coverage_input,
};

pub const COVERAGE_INPUT_SCHEMA: &str = "crowsi://network/control-coverage/v2";
pub const COVERAGE_SNAPSHOT_SCHEMA: &str = "crowsi://network/control-coverage-snapshot/v2";
