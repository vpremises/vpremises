use std::collections::BTreeSet;

use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    CoordinatorCommandV1, CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1, OperationMode,
    TargetStateV1, Validate,
    coordinator::aggregate::aggregate_target,
    coordinator::verifications::verify_artifact,
    receipt::matches_command,
    trust::{TrustRole, TrustScope},
};

pub(super) fn validate_receipt(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
    target: &TargetStateV1,
    command: &CoordinatorCommandV1,
    receipt_jtis: &mut BTreeSet<String>,
) -> Result<(), CoordinatorError> {
    let Some(receipt) = target.receipts.get(&command.requirement_id) else {
        return Ok(());
    };
    receipt.validate()?;
    let scope = if command.binding.action == crowsi_control_contracts::ControlAction::Restore {
        TrustScope::Restore
    } else {
        TrustScope::Containment
    };
    if !matches_command(receipt, command)
        || receipt.enforcement.applied_at > state.snapshot.trusted_time_watermark
        || !receipt_jtis.insert(receipt.receipt_jti.clone())
        || !state.seen_receipt_jtis.contains(&receipt.receipt_jti)
    {
        return Err(CoordinatorError::new(
            "receipts",
            "receipt state is inconsistent with its command or replay set",
        ));
    }
    trust.verify(
        Some(&receipt.enforcement.provider),
        TrustRole::Pep,
        scope,
        &receipt.enforcement.signed,
        &receipt.enforcement.signing_payload(),
    )?;
    if let Some(evidence) = target.verified_evidence.get(&command.requirement_id) {
        crate::validation::timestamp("verified_at", &evidence.verified_at)?;
        if evidence.verified_at > state.snapshot.trusted_time_watermark
            || !state.seen_evidence_jtis.contains(&evidence.artifact.jti)
        {
            return Err(CoordinatorError::new(
                "verified_evidence",
                "trusted time or durable replay state is inconsistent",
            ));
        }
        verify_artifact(
            &evidence.artifact,
            receipt,
            trust,
            scope,
            &evidence.verified_at,
        )?;
    }
    Ok(())
}

pub(super) fn validate_aggregate(
    target: &TargetStateV1,
    mode: OperationMode,
) -> Result<(), CoordinatorError> {
    let mut expected = target.clone();
    aggregate_target(&mut expected, mode);
    if target.observed == expected.observed && target.transaction == expected.transaction {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "target.transaction",
            "does not match the immutable receipt aggregate",
        ))
    }
}
