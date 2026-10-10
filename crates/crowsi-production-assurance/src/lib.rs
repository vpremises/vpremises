//! Production evidence is kept separate from control execution.

mod canonical;
mod clock;
mod context;
mod context_model;
mod controls;
mod error;
mod evaluate;
mod model;
mod runtime;
mod secure_path;
mod signed;
mod time_anchor;
mod trust;

pub use context_model::AssuranceContext;
pub use error::AssuranceError;
pub use model::{
    AssuranceControl, AssuranceControls, EvidenceKind, EvidenceOrigin, EvidencePayload,
    ReadinessBundle, ReadinessDecision, ReadinessState, SignatureAlgorithm,
};
pub use runtime::ProductionAssurance;
pub use signed::SignedEvidence;
use time_anchor::DurableTimeAnchor;
pub use trust::{TrustError, TrustStore};
