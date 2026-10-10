use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CoordinatorError, CoordinatorTrustV1, IncidentDefinitionV1, IncidentPhase, IncidentSnapshotV1,
    TargetStateV1, Validate,
    trust::{TrustRole, TrustScope},
};

use super::{ClockMode, IncidentCoordinator};

impl IncidentCoordinator {
    /// Creates a detected incident without performing external work.
    ///
    /// # Errors
    ///
    /// Rejects invalid definitions or a trust bundle that differs from the
    /// root-pinned deployment configuration.
    pub fn new(
        definition: IncidentDefinitionV1,
        trust: CoordinatorTrustV1,
        expected_trust_bundle_digest: &str,
    ) -> Result<Self, CoordinatorError> {
        Self::build(
            definition,
            trust,
            ClockMode::System,
            Some(expected_trust_bundle_digest),
        )
    }

    /// Creates a deterministic coordinator that cannot use production apply.
    ///
    /// # Errors
    ///
    /// Rejects an invalid definition or trust configuration.
    pub fn new_simulation(
        definition: IncidentDefinitionV1,
        trust: CoordinatorTrustV1,
    ) -> Result<Self, CoordinatorError> {
        Self::build(definition, trust, ClockMode::Simulation, None)
    }

    fn build(
        definition: IncidentDefinitionV1,
        trust: CoordinatorTrustV1,
        clock_mode: ClockMode,
        expected_trust_bundle_digest: Option<&str>,
    ) -> Result<Self, CoordinatorError> {
        definition.validate()?;
        trust.validate()?;
        let trust_bundle_digest = trust.canonical_digest()?;
        if expected_trust_bundle_digest.is_some_and(|expected| expected != trust_bundle_digest) {
            return Err(CoordinatorError::new(
                "trust_bundle_digest",
                "does not match the root-pinned deployment configuration",
            ));
        }
        if trust.deployment_id != definition.deployment_id
            || !trust.supports(
                &definition.incident_owner_authority,
                TrustRole::IncidentOwner,
                TrustScope::IncidentLifecycle,
            )
        {
            return Err(CoordinatorError::new(
                "trust",
                "deployment or fixed incident owner is not trusted",
            ));
        }
        let detected_at = definition.detected_at;
        let targets = definition
            .targets
            .into_iter()
            .map(|target| (target.target_id.clone(), TargetStateV1::new(target)))
            .collect::<BTreeMap<_, _>>();
        Ok(Self {
            snapshot: IncidentSnapshotV1 {
                deployment_id: definition.deployment_id,
                incident_owner_authority: definition.incident_owner_authority,
                trust_bundle_digest,
                trust_revision: trust.revision,
                incident_id: definition.incident_id,
                phase: IncidentPhase::Detected,
                isolation_epoch: 0,
                restore_attempt: 0,
                detected_at: detected_at.clone(),
                last_event_at: detected_at.clone(),
                trusted_time_watermark: detected_at,
                recovery_approval_id: None,
                monitoring_started_at: None,
                monitoring_evidence_jti: None,
                targets,
            },
            seen_event_jtis: BTreeSet::new(),
            seen_receipt_jtis: BTreeSet::new(),
            reserved_authorization_jtis: BTreeSet::new(),
            used_approval_ids: BTreeSet::new(),
            seen_evidence_jtis: BTreeSet::new(),
            pending_recovery: None,
            monitoring_evidence: None,
            trust,
            clock_mode,
            checkpoint_required: clock_mode == ClockMode::System,
            last_checkpoint_sequence: None,
            last_checkpoint_digest: None,
            pending_outbox: Vec::new(),
        })
    }
}
