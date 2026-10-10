mod envelope;

use crate::{
    CoordinatorCommandV1, CoordinatorError, IncidentEventV1, Validate, time::system_utc_now,
};

use super::{ClockMode, IncidentCoordinator};

impl IncidentCoordinator {
    /// Applies one owner-signed event using the internally owned system clock.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated, mistimed, replayed, stale, or invalid events.
    pub fn apply(&mut self, event: &IncidentEventV1) -> Result<(), CoordinatorError> {
        if self.clock_mode != ClockMode::System {
            return Err(CoordinatorError::new(
                "clock_mode",
                "simulation coordinator cannot use production apply",
            ));
        }
        if self.checkpoint_required {
            return Err(CoordinatorError::new(
                "checkpoint",
                "durable checkpoint commit is required before apply",
            ));
        }
        if !self.pending_outbox.is_empty() {
            return Err(CoordinatorError::new(
                "pending_outbox",
                "previous commands must be durably released first",
            ));
        }
        let commands = self.apply_at(event, &system_utc_now()?)?;
        self.pending_outbox = commands;
        Ok(())
    }

    /// Deterministic event application for isolated simulation only.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed, unauthenticated, or invalid events.
    pub fn apply_simulation(
        &mut self,
        event: &IncidentEventV1,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        self.apply_simulation_at(event, &event.occurred_at)
    }

    /// Deterministic clock-skew helper for isolated simulation only.
    ///
    /// # Errors
    ///
    /// Rejects production mode and invalid input.
    pub fn apply_simulation_at(
        &mut self,
        event: &IncidentEventV1,
        simulated_now: &str,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        if self.clock_mode != ClockMode::Simulation {
            return Err(CoordinatorError::new(
                "clock_mode",
                "production coordinator cannot use simulation apply",
            ));
        }
        self.apply_at(event, simulated_now)
    }

    fn apply_at(
        &mut self,
        event: &IncidentEventV1,
        trusted_now: &str,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        event.validate()?;
        self.validate_event_envelope(event, trusted_now)?;
        let mut candidate = self.fork_candidate();
        let commands = candidate.dispatch(event, trusted_now)?;
        candidate.seen_event_jtis.insert(event.jti.clone());
        candidate
            .snapshot
            .last_event_at
            .clone_from(&event.occurred_at);
        trusted_now.clone_into(&mut candidate.snapshot.trusted_time_watermark);
        if candidate.clock_mode == ClockMode::System {
            candidate.checkpoint_required = true;
        }
        *self = candidate;
        Ok(commands)
    }
}
