use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    CommandAuthorizationV1, CoordinatorError, CoordinatorTrustV1, OperationMode,
    trust::{TrustRole, TrustScope},
};

pub(crate) fn verify_signatures(
    authorization: &CommandAuthorizationV1,
    trust: &CoordinatorTrustV1,
    mode: OperationMode,
    owner_authority: Option<&str>,
) -> Result<(), CoordinatorError> {
    let scope = match mode {
        OperationMode::Containment => TrustScope::Containment,
        OperationMode::Restore => TrustScope::Restore,
    };
    trust.verify(
        Some(&authorization.identity.issuer),
        TrustRole::IdentityProvider,
        scope,
        &authorization.identity.signed,
        &authorization.identity.signing_payload(),
    )?;
    trust.verify(
        owner_authority,
        TrustRole::IncidentOwner,
        scope,
        &authorization.intent.signed,
        &authorization.intent.signing_payload(),
    )?;
    let decision = trust.verify(
        None,
        TrustRole::PolicyAdministrator,
        scope,
        &authorization.decision.signed,
        &authorization.decision.signing_payload(),
    )?;
    let grant = trust.verify(
        None,
        TrustRole::PolicyAdministrator,
        scope,
        &authorization.grant.signed,
        &authorization.grant.signing_payload(),
    )?;
    if decision.authority == grant.authority {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "authorization",
            "decision and grant must share one policy authority",
        ))
    }
}
