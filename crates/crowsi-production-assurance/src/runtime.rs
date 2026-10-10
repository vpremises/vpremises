use std::path::Path;

use crate::{
    AssuranceError, DurableTimeAnchor, ReadinessBundle, ReadinessDecision, ReadinessState,
    TrustStore,
};

pub struct ProductionAssurance {
    time_anchor: DurableTimeAnchor,
}

impl ProductionAssurance {
    /// Opens the owner-only rollback-resistant assurance state.
    ///
    /// # Errors
    ///
    /// Rejects relative, shared-writable, symlinked, malformed, or unavailable state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AssuranceError> {
        Ok(Self {
            time_anchor: DurableTimeAnchor::open(path.as_ref())?,
        })
    }

    #[must_use]
    pub fn evaluate(&mut self, bundle: &ReadinessBundle, trust: &TrustStore) -> ReadinessDecision {
        let Some(now) = crate::clock::trusted_now_epoch_s() else {
            return blocked("trusted-time-unavailable");
        };
        if self.time_anchor.observe(now).is_err() {
            return blocked("trusted-time-rollback-or-state-unavailable");
        }
        crate::evaluate::evaluate_at(bundle, now, trust)
    }
}

fn blocked(finding: &str) -> ReadinessDecision {
    ReadinessDecision {
        schema: "crowsi://production/readiness/v1",
        state: ReadinessState::Blocked,
        finding_codes: vec![finding.into()],
        external_actions: false,
    }
}
