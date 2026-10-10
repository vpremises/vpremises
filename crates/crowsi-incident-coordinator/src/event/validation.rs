use crate::{
    CoordinatorError, INCIDENT_EVENT_SCHEMA_V1, IncidentCanonicalPayloadV1, Validate,
    time::window_within,
    validation::{identifier, schema, timestamp},
};

use super::{IncidentEventKindV1, IncidentEventV1};

const MAX_AUTHORIZATIONS: usize = 256;
const MAX_EVENT_VALIDITY_MILLIS: i64 = 60_000;

impl Validate for IncidentEventV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, INCIDENT_EVENT_SCHEMA_V1)?;
        identifier("event_id", &self.event_id)?;
        identifier("jti", &self.jti)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        identifier("owner_authority", &self.owner_authority)?;
        timestamp("occurred_at", &self.occurred_at)?;
        timestamp("valid_until", &self.valid_until)?;
        if !window_within(
            &self.occurred_at,
            &self.valid_until,
            MAX_EVENT_VALIDITY_MILLIS,
        ) {
            return Err(CoordinatorError::new(
                "valid_until",
                "event validity must be positive and at most 60 seconds",
            ));
        }
        crowsi_control_contracts::Validate::validate(&self.signed)?;
        if !self.payload_digest_matches() {
            return Err(CoordinatorError::new(
                "signed.digest",
                "does not cover the complete event envelope",
            ));
        }
        self.validate_kind()
    }
}

impl IncidentEventV1 {
    fn validate_kind(&self) -> Result<(), CoordinatorError> {
        match &self.kind {
            IncidentEventKindV1::RequestContainment { authorizations }
            | IncidentEventKindV1::RetryContainment { authorizations } => {
                self.validate_authorizations(authorizations)
            }
            IncidentEventKindV1::SubmitReceipt { receipt } => {
                receipt.validate()?;
                require(
                    receipt.deployment_id == self.deployment_id
                        && receipt.incident_id == self.incident_id
                        && receipt.isolation_epoch == self.isolation_epoch
                        && receipt.enforcement.applied_at <= self.occurred_at,
                    "receipt",
                    "must match event incident, epoch, and trusted time",
                )
            }
            IncidentEventKindV1::SubmitVerification { verification } => {
                verification.validate()?;
                require(
                    verification.deployment_id == self.deployment_id
                        && verification.incident_id == self.incident_id
                        && verification.isolation_epoch == self.isolation_epoch
                        && verification.issued_at <= self.occurred_at,
                    "verification",
                    "must match event incident, epoch, and trusted time",
                )
            }
            IncidentEventKindV1::AuthorizeRecovery { approval } => {
                approval.validate_at(&self.occurred_at)
            }
            IncidentEventKindV1::Close { evidence } => {
                evidence.validate()?;
                require(
                    evidence.deployment_id == self.deployment_id
                        && evidence.incident_id == self.incident_id
                        && evidence.isolation_epoch == self.isolation_epoch
                        && evidence.issued_at <= self.occurred_at,
                    "monitoring_evidence",
                    "must match event incident, epoch, and trusted time",
                )
            }
            _ => Ok(()),
        }
    }

    fn validate_authorizations(
        &self,
        authorizations: &[crate::CommandAuthorizationV1],
    ) -> Result<(), CoordinatorError> {
        if authorizations.is_empty() || authorizations.len() > MAX_AUTHORIZATIONS {
            return Err(CoordinatorError::new(
                "authorizations",
                "must contain between 1 and 256 entries",
            ));
        }
        for authorization in authorizations {
            authorization.validate_at(&self.occurred_at)?;
        }
        Ok(())
    }
}

fn require(
    condition: bool,
    field: &'static str,
    reason: &'static str,
) -> Result<(), CoordinatorError> {
    if condition {
        Ok(())
    } else {
        Err(CoordinatorError::new(field, reason))
    }
}
