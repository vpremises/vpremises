use crowsi_control_contracts::{
    CanonicalPayloadV1, ENFORCEMENT_RECEIPT_SCHEMA_V1, EnforcementOutcome, EnforcementReceiptV1,
};
use crowsi_incident_coordinator::{
    COORDINATOR_RECEIPT_SCHEMA_V1, CoordinatorCommandV1, CoordinatorReceiptV1,
    INDEPENDENT_VERIFICATION_SCHEMA_V1, IncidentCanonicalPayloadV1, IndependentObservedOutcome,
    IndependentVerificationArtifactV1,
};

use super::{
    INDEPENDENT_AUTHORITY,
    common::{digest, signed},
    crypto::{sign_independent, sign_pep},
};

pub fn receipt(
    command: &CoordinatorCommandV1,
    id: &str,
    outcome: EnforcementOutcome,
) -> CoordinatorReceiptV1 {
    let receipt_id = format!("receipt.{id}");
    let resulting_resource_version = if outcome == EnforcementOutcome::Applied {
        Some("provider-version-2".to_owned())
    } else {
        None
    };
    let residual_exposures = if outcome == EnforcementOutcome::Partial {
        vec!["provider update remains pending".to_owned()]
    } else {
        Vec::new()
    };
    let mut enforcement = EnforcementReceiptV1 {
        schema: ENFORCEMENT_RECEIPT_SCHEMA_V1.to_owned(),
        receipt_id: receipt_id.clone(),
        command_jti: command.jti.clone(),
        enforcement_grant_jti: command.enforcement_grant_jti.clone(),
        binding: command.binding.clone(),
        provider: command.pep.clone(),
        outcome,
        grant_consumed: true,
        applied_at: command.issued_at.clone(),
        resulting_resource_version,
        residual_exposures,
        evidence_digest: digest(),
        signed: signed(),
    };
    enforcement.signed = sign_pep(&enforcement.provider, &enforcement.signing_payload());
    CoordinatorReceiptV1 {
        schema: COORDINATOR_RECEIPT_SCHEMA_V1.to_owned(),
        receipt_jti: receipt_id,
        deployment_id: command.deployment_id.clone(),
        incident_id: command.incident_id.clone(),
        isolation_epoch: command.isolation_epoch,
        transaction_id: command.transaction_id.clone(),
        target_id: command.target_id.clone(),
        requirement_id: command.requirement_id.clone(),
        enforcement,
    }
}

pub fn verification(
    receipt: &CoordinatorReceiptV1,
    id: &str,
    outcome: IndependentObservedOutcome,
) -> IndependentVerificationArtifactV1 {
    let restore =
        receipt.enforcement.binding.action == crowsi_control_contracts::ControlAction::Restore;
    let (issued_at, expires_at) = if restore {
        ("2026-07-01T00:02:11.000Z", "2026-07-01T00:07:11.000Z")
    } else {
        ("2026-07-01T00:01:06.000Z", "2026-07-01T00:06:06.000Z")
    };
    let mut artifact = IndependentVerificationArtifactV1 {
        schema: INDEPENDENT_VERIFICATION_SCHEMA_V1.to_owned(),
        artifact_id: format!("verification.{id}"),
        jti: format!("jti.verification.{id}"),
        nonce: format!("nonce-{id}"),
        deployment_id: receipt.deployment_id.clone(),
        incident_id: receipt.incident_id.clone(),
        isolation_epoch: receipt.isolation_epoch,
        transaction_id: receipt.transaction_id.clone(),
        target_id: receipt.target_id.clone(),
        requirement_id: receipt.requirement_id.clone(),
        enforcement_receipt_id: receipt.receipt_jti.clone(),
        enforcement_receipt_digest: receipt.enforcement.signed.digest.clone(),
        observed_outcome: outcome,
        verifier_authority: INDEPENDENT_AUTHORITY.to_owned(),
        issued_at: issued_at.to_owned(),
        expires_at: expires_at.to_owned(),
        signed: signed(),
    };
    artifact.signed = sign_independent(&artifact.signing_payload());
    artifact
}
