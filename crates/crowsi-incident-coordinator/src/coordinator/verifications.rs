use crowsi_control_contracts::{CanonicalPayloadV1, EnforcementOutcome};

use crate::{
    CoordinatorError, IncidentCanonicalPayloadV1, IncidentCoordinator, IncidentPhase,
    IndependentObservedOutcome, IndependentVerificationArtifactV1, OperationMode,
    coordinator::aggregate::aggregate_target,
    trust::{TrustRole, TrustScope, ensure_independent},
    verification::VerifiedEvidenceV1,
};

impl IncidentCoordinator {
    pub(super) fn record_verification(
        &mut self,
        artifact: &IndependentVerificationArtifactV1,
        now: &str,
    ) -> Result<(), CoordinatorError> {
        let (mode, scope) = match self.snapshot.phase {
            IncidentPhase::ContainmentRequested => {
                (OperationMode::Containment, TrustScope::Containment)
            }
            IncidentPhase::Restoring => (OperationMode::Restore, TrustScope::Restore),
            _ => {
                return Err(CoordinatorError::new(
                    "phase",
                    "independent verification requires an active transaction",
                ));
            }
        };
        let target = self
            .snapshot
            .targets
            .get(&artifact.target_id)
            .ok_or_else(|| CoordinatorError::new("target_id", "target is not active"))?;
        let receipt = target
            .receipts
            .get(&artifact.requirement_id)
            .ok_or_else(|| CoordinatorError::new("receipt", "PEP receipt is not recorded"))?;
        if let Some(existing) = target.verified_evidence.get(&artifact.requirement_id) {
            if existing.artifact == *artifact {
                return Ok(());
            }
            return Err(CoordinatorError::new(
                "verification",
                "immutable independent evidence already exists",
            ));
        }
        if self.seen_evidence_jtis.contains(&artifact.jti) {
            return Err(CoordinatorError::new(
                "verification",
                "artifact replay detected",
            ));
        }
        verify_artifact(artifact, receipt, &self.trust, scope, now)?;
        let evidence = VerifiedEvidenceV1::mint(artifact.clone(), now);
        let target = self
            .snapshot
            .targets
            .get_mut(&artifact.target_id)
            .expect("validated target remains present");
        target
            .verified_evidence
            .insert(artifact.requirement_id.clone(), evidence);
        aggregate_target(target, mode);
        self.seen_evidence_jtis.insert(artifact.jti.clone());
        Ok(())
    }
}

pub(crate) fn verify_artifact(
    artifact: &IndependentVerificationArtifactV1,
    receipt: &crate::CoordinatorReceiptV1,
    trust: &crate::CoordinatorTrustV1,
    scope: TrustScope,
    now: &str,
) -> Result<(), CoordinatorError> {
    artifact.validate_at(now)?;
    if !exact_match(artifact, receipt) {
        return Err(CoordinatorError::new(
            "verification",
            "artifact binding does not match the exact PEP receipt",
        ));
    }
    if artifact.observed_outcome == IndependentObservedOutcome::Applied
        && receipt.enforcement.outcome != EnforcementOutcome::Applied
    {
        return Err(CoordinatorError::new(
            "observed_outcome",
            "applied observation conflicts with the PEP outcome",
        ));
    }
    let pep = trust.verify(
        Some(&receipt.enforcement.provider),
        TrustRole::Pep,
        scope,
        &receipt.enforcement.signed,
        &receipt.enforcement.signing_payload(),
    )?;
    let verifier = trust.verify(
        Some(&artifact.verifier_authority),
        TrustRole::IndependentVerifier,
        scope,
        &artifact.signed,
        &artifact.signing_payload(),
    )?;
    ensure_independent(pep, verifier)
}

pub(crate) fn exact_match(
    artifact: &IndependentVerificationArtifactV1,
    receipt: &crate::CoordinatorReceiptV1,
) -> bool {
    artifact.deployment_id == receipt.deployment_id
        && artifact.incident_id == receipt.incident_id
        && artifact.isolation_epoch == receipt.isolation_epoch
        && artifact.transaction_id == receipt.transaction_id
        && artifact.target_id == receipt.target_id
        && artifact.requirement_id == receipt.requirement_id
        && artifact.enforcement_receipt_id == receipt.receipt_jti
        && artifact.enforcement_receipt_digest == receipt.enforcement.signed.digest
}
