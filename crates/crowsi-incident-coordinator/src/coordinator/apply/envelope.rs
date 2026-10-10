use crate::{
    CoordinatorError, IncidentCanonicalPayloadV1, IncidentEventV1,
    time::unix_millis,
    trust::{TrustRole, TrustScope},
};

use super::IncidentCoordinator;

const MAX_EVENT_FUTURE_SKEW_MILLIS: i64 = 5_000;

impl IncidentCoordinator {
    pub(super) fn validate_event_envelope(
        &self,
        event: &IncidentEventV1,
        trusted_now: &str,
    ) -> Result<(), CoordinatorError> {
        self.validate_event_scope(event)?;
        if event.occurred_at < self.snapshot.last_event_at {
            return Err(CoordinatorError::new(
                "occurred_at",
                "events must be monotonic",
            ));
        }
        if self.seen_event_jtis.contains(&event.jti) {
            return Err(CoordinatorError::new("jti", "event replay detected"));
        }
        let issued = unix_millis(&event.occurred_at).expect("validated event time");
        let expires = unix_millis(&event.valid_until).expect("validated event expiry");
        let now = unix_millis(trusted_now)
            .ok_or_else(|| CoordinatorError::new("system_clock", "returned invalid UTC time"))?;
        let current = trusted_now >= self.snapshot.trusted_time_watermark.as_str()
            && issued <= now.saturating_add(MAX_EVENT_FUTURE_SKEW_MILLIS)
            && now < expires;
        if !current {
            return Err(CoordinatorError::new(
                "event_time",
                "event expired, exceeds future skew, or clock rolled back",
            ));
        }
        self.trust.verify(
            Some(&event.owner_authority),
            TrustRole::IncidentOwner,
            TrustScope::IncidentLifecycle,
            &event.signed,
            &event.signing_payload(),
        )?;
        Ok(())
    }

    fn validate_event_scope(&self, event: &IncidentEventV1) -> Result<(), CoordinatorError> {
        if event.deployment_id != self.snapshot.deployment_id
            || event.incident_id != self.snapshot.incident_id
        {
            return Err(CoordinatorError::new(
                "event_scope",
                "deployment or incident does not match this coordinator",
            ));
        }
        if event.owner_authority != self.snapshot.incident_owner_authority {
            return Err(CoordinatorError::new(
                "owner_authority",
                "does not match the fixed incident owner",
            ));
        }
        if event.isolation_epoch != self.snapshot.isolation_epoch {
            return Err(CoordinatorError::new(
                "isolation_epoch",
                "stale or future epoch",
            ));
        }
        Ok(())
    }
}
