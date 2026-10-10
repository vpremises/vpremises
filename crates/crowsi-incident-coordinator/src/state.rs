mod monitoring;
mod outbox;
mod phase;
mod recovery;
mod targets;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    COORDINATOR_STATE_SCHEMA_V1, CoordinatorError, CoordinatorTrustV1, IncidentSnapshotV1,
    MonitoringEvidenceV1, RecoveryApprovalV1,
    validation::{identifier, schema, timestamp},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStateV1 {
    pub schema: String,
    pub snapshot: IncidentSnapshotV1,
    pub seen_event_jtis: BTreeSet<String>,
    pub seen_receipt_jtis: BTreeSet<String>,
    pub reserved_authorization_jtis: BTreeSet<String>,
    pub used_approval_ids: BTreeSet<String>,
    pub seen_evidence_jtis: BTreeSet<String>,
    pub pending_outbox: Vec<crate::CoordinatorCommandV1>,
    pub pending_recovery: Option<RecoveryApprovalV1>,
    pub monitoring_evidence: Option<MonitoringEvidenceV1>,
}

impl CoordinatorStateV1 {
    /// Returns the domain-separated digest used by coordinator checkpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if this closed state cannot be serialized.
    pub fn canonical_digest(&self) -> Result<String, CoordinatorError> {
        let json = serde_json::to_vec(self).map_err(|_| {
            CoordinatorError::new("coordinator_state", "canonical serialization failed")
        })?;
        let mut value = crate::canonical::Encoder::new("coordinator-state-v1");
        value.text("schema", &self.schema);
        value.text("json_digest", &crate::canonical::digest_payload(&json));
        Ok(crate::canonical::digest_payload(&value.finish()))
    }

    pub(crate) fn validate_with_trust(
        &self,
        trust: &CoordinatorTrustV1,
    ) -> Result<(), CoordinatorError> {
        schema(&self.schema, COORDINATOR_STATE_SCHEMA_V1)?;
        identifier("deployment_id", &self.snapshot.deployment_id)?;
        identifier(
            "incident_owner_authority",
            &self.snapshot.incident_owner_authority,
        )?;
        crate::validation::digest("trust_bundle_digest", &self.snapshot.trust_bundle_digest)?;
        identifier("incident_id", &self.snapshot.incident_id)?;
        if trust.deployment_id != self.snapshot.deployment_id
            || trust.revision != self.snapshot.trust_revision
            || trust.canonical_digest()? != self.snapshot.trust_bundle_digest
            || !trust.supports(
                &self.snapshot.incident_owner_authority,
                crate::TrustRole::IncidentOwner,
                crate::TrustScope::IncidentLifecycle,
            )
        {
            return Err(CoordinatorError::new(
                "trust",
                "state deployment or incident owner is not trusted",
            ));
        }
        timestamp("detected_at", &self.snapshot.detected_at)?;
        timestamp("last_event_at", &self.snapshot.last_event_at)?;
        timestamp(
            "trusted_time_watermark",
            &self.snapshot.trusted_time_watermark,
        )?;
        let event_time_bounded = crate::time::unix_millis(&self.snapshot.last_event_at)
            .zip(crate::time::unix_millis(
                &self.snapshot.trusted_time_watermark,
            ))
            .is_some_and(|(event, trusted)| event <= trusted.saturating_add(5_000));
        if self.snapshot.detected_at > self.snapshot.last_event_at
            || self.snapshot.detected_at > self.snapshot.trusted_time_watermark
            || !event_time_bounded
        {
            return Err(CoordinatorError::new(
                "trusted_time_watermark",
                "must bound detection and signed event time",
            ));
        }
        validate_identifiers("seen_event_jtis", &self.seen_event_jtis)?;
        validate_identifiers("seen_receipt_jtis", &self.seen_receipt_jtis)?;
        validate_identifiers(
            "reserved_authorization_jtis",
            &self.reserved_authorization_jtis,
        )?;
        validate_identifiers("used_approval_ids", &self.used_approval_ids)?;
        validate_identifiers("seen_evidence_jtis", &self.seen_evidence_jtis)?;
        outbox::validate(self)?;
        targets::validate(self, trust)?;
        recovery::validate(self, trust)?;
        monitoring::validate(self, trust)?;
        phase::validate(self)
    }
}

fn validate_identifiers(
    field: &'static str,
    values: &BTreeSet<String>,
) -> Result<(), CoordinatorError> {
    for value in values {
        identifier(field, value)?;
    }
    Ok(())
}
