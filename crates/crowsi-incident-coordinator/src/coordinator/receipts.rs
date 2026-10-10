use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    CoordinatorError, CoordinatorReceiptV1, IncidentCoordinator, IncidentPhase, OperationMode,
    receipt::matches_command,
    trust::{TrustRole, TrustScope},
};

use super::aggregate::aggregate_target;

impl IncidentCoordinator {
    pub(super) fn record_receipt(
        &mut self,
        receipt: &CoordinatorReceiptV1,
        now: &str,
    ) -> Result<(), CoordinatorError> {
        let mode = match self.snapshot.phase {
            IncidentPhase::ContainmentRequested => OperationMode::Containment,
            IncidentPhase::Restoring => OperationMode::Restore,
            _ => {
                return Err(CoordinatorError::new(
                    "phase",
                    "receipts require an active enforcement transaction",
                ));
            }
        };
        let target = self
            .snapshot
            .targets
            .get_mut(&receipt.target_id)
            .ok_or_else(|| CoordinatorError::new("target_id", "target is not in the incident"))?;
        let command = target
            .active_commands
            .get(&receipt.requirement_id)
            .ok_or_else(|| CoordinatorError::new("requirement_id", "command is not active"))?;
        if !matches_command(receipt, command) {
            return Err(CoordinatorError::new(
                "receipt",
                "does not match the active command",
            ));
        }
        if let Some(existing) = target.receipts.get(&receipt.requirement_id) {
            if existing == receipt
                && existing.enforcement.signed.digest == receipt.enforcement.signed.digest
            {
                return Ok(());
            }
            return Err(CoordinatorError::new(
                "receipt",
                "an immutable receipt already exists for this command",
            ));
        }
        if self.seen_receipt_jtis.contains(&receipt.receipt_jti) {
            return Err(CoordinatorError::new(
                "receipt_jti",
                "receipt identifier is already bound to another command",
            ));
        }
        let scope = match mode {
            OperationMode::Containment => TrustScope::Containment,
            OperationMode::Restore => TrustScope::Restore,
        };
        self.trust.verify(
            Some(&receipt.enforcement.provider),
            TrustRole::Pep,
            scope,
            &receipt.enforcement.signed,
            &receipt.enforcement.signing_payload(),
        )?;
        if receipt.enforcement.applied_at.as_str() > now {
            return Err(CoordinatorError::new(
                "enforcement.applied_at",
                "must not be later than trusted caller time",
            ));
        }
        target
            .receipts
            .insert(receipt.requirement_id.clone(), receipt.clone());
        aggregate_target(target, mode);
        self.seen_receipt_jtis.insert(receipt.receipt_jti.clone());
        Ok(())
    }
}
