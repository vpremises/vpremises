#![doc = "Pure deterministic incident coordination for Crowsi."]

mod authorization;
mod canonical;
mod challenge;
mod checkpoint;
mod command;
mod coordinator;
mod crypto;
mod definition;
mod error;
mod event;
mod monitoring;
mod monotonic;
mod phase;
mod receipt;
mod recovery;
mod release;
mod snapshot;
mod state;
mod target;
mod time;
mod trust;
mod validation;
mod verification;

pub use authorization::CommandAuthorizationV1;
pub use canonical::IncidentCanonicalPayloadV1;
pub use challenge::MonotonicChallengeV1;
pub use checkpoint::{CoordinatorCheckpointV1, ExternalMonotonicAnchorV1};
pub use command::CoordinatorCommandV1;
pub use coordinator::IncidentCoordinator;
pub use definition::{EnforcementRequirementV1, IncidentDefinitionV1, TargetDefinitionV1};
pub use error::CoordinatorError;
pub use event::{IncidentEventKindV1, IncidentEventV1};
pub use monitoring::{MonitoringEvidenceV1, MonitoringOutcome};
pub use monotonic::{AtomicReleaseConsumerV1, AtomicReleaseRequestV1, MonotonicHeadReaderV1};
pub use phase::IncidentPhase;
pub use receipt::CoordinatorReceiptV1;
pub use recovery::RecoveryApprovalV1;
pub use release::CommandReleaseV1;
pub use snapshot::IncidentSnapshotV1;
pub use state::CoordinatorStateV1;
pub use target::{
    DesiredTargetState, ObservedTargetState, OperationMode, TargetStateV1, TransactionState,
};
pub use trust::{CoordinatorTrustV1, TrustAnchorV1, TrustRole, TrustScope};
pub use validation::Validate;
pub use verification::{IndependentObservedOutcome, IndependentVerificationArtifactV1};

pub const INCIDENT_EVENT_SCHEMA_V1: &str = "crowsi://incident/event/v1";
pub const COORDINATOR_COMMAND_SCHEMA_V1: &str = "crowsi://incident/command/v1";
pub const COORDINATOR_RECEIPT_SCHEMA_V1: &str = "crowsi://incident/receipt/v1";
pub const COORDINATOR_STATE_SCHEMA_V1: &str = "crowsi://incident/coordinator-state/v1";
pub const COORDINATOR_TRUST_SCHEMA_V1: &str = "crowsi://incident/coordinator-trust/v1";
pub const COORDINATOR_CHECKPOINT_SCHEMA_V1: &str = "crowsi://incident/coordinator-checkpoint/v1";
pub const MONOTONIC_ANCHOR_SCHEMA_V1: &str = "crowsi://incident/monotonic-anchor/v1";
pub const COMMAND_RELEASE_SCHEMA_V1: &str = "crowsi://incident/command-release/v1";
pub const INDEPENDENT_VERIFICATION_SCHEMA_V1: &str =
    "crowsi://incident/independent-verification/v1";
pub const MONITORING_EVIDENCE_SCHEMA_V1: &str = "crowsi://incident/monitoring-evidence/v1";
pub const COORDINATOR_AUDIENCE: &str = "crowsi-incident-coordinator";
pub const MIN_MONITORING_WINDOW_MILLIS: i64 = 300_000;
