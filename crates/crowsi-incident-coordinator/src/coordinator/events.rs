use crate::{
    CoordinatorCommandV1, CoordinatorError, IncidentCoordinator, IncidentEventKindV1,
    IncidentEventV1,
};

impl IncidentCoordinator {
    pub(super) fn dispatch(
        &mut self,
        event: &IncidentEventV1,
        trusted_now: &str,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        match &event.kind {
            IncidentEventKindV1::BeginTriage => self.begin_triage(),
            IncidentEventKindV1::RequestContainment { authorizations } => {
                self.request_containment(authorizations, event, false, trusted_now)
            }
            IncidentEventKindV1::RetryContainment { authorizations } => {
                self.request_containment(authorizations, event, true, trusted_now)
            }
            IncidentEventKindV1::SubmitReceipt { receipt } => {
                self.record_receipt(receipt, trusted_now)?;
                Ok(Vec::new())
            }
            IncidentEventKindV1::SubmitVerification { verification } => {
                self.record_verification(verification, trusted_now)?;
                Ok(Vec::new())
            }
            IncidentEventKindV1::FinalizeContainment => self.finalize_containment(),
            IncidentEventKindV1::BeginEradication => self.begin_eradication(),
            IncidentEventKindV1::RequestRecovery => self.request_recovery(),
            IncidentEventKindV1::AuthorizeRecovery { approval } => {
                self.authorize_recovery(approval, event, trusted_now)?;
                Ok(Vec::new())
            }
            IncidentEventKindV1::StartRestore { automatic } => {
                self.start_restore(event, *automatic, trusted_now)
            }
            IncidentEventKindV1::FinalizeRestore => self.finalize_restore(),
            IncidentEventKindV1::RetryRecovery => self.retry_recovery(),
            IncidentEventKindV1::BeginMonitoring => self.begin_monitoring(trusted_now),
            IncidentEventKindV1::Close { evidence } => self.close(evidence, trusted_now),
        }
    }
}
