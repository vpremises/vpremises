//! Evaluates provider-neutral isolation metadata without contacting environments.

mod coverage;
mod evaluate;
mod model;
mod validation;

pub use coverage::{
    COVERAGE_INPUT_SCHEMA, COVERAGE_SNAPSHOT_SCHEMA, ControlAction, ControlAuthority,
    ControlCoverageInputV2, ControlCoverageSnapshotV2, CoverageAssetInputV2, CoverageAssetResultV2,
    CoverageState, EnforcerStatus, LifelineStatus, SensorStatus, ValidatedControlCoverageInputV2,
    evaluate_coverage, parse_coverage_input, validate_coverage_input,
};
pub use evaluate::evaluate;
pub use model::{BoundaryInputV1, BoundarySnapshotV1};
pub use validation::{MAX_DOCUMENT_BYTES, parse_input};
