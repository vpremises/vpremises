use std::collections::{BTreeMap, BTreeSet};

use crate::{CoordinatorError, CoordinatorStateV1, Validate};

pub(super) fn validate(state: &CoordinatorStateV1) -> Result<(), CoordinatorError> {
    let active = state
        .snapshot
        .targets
        .values()
        .flat_map(|target| target.active_commands.values())
        .map(|command| (command.jti.as_str(), command))
        .collect::<BTreeMap<_, _>>();
    let valid_phase = matches!(
        state.snapshot.phase,
        crate::IncidentPhase::ContainmentRequested | crate::IncidentPhase::Restoring
    );
    if state.pending_outbox.is_empty() {
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for command in &state.pending_outbox {
        command.validate()?;
        if !seen.insert(command.jti.as_str()) || active.get(command.jti.as_str()) != Some(&command)
        {
            return Err(CoordinatorError::new(
                "pending_outbox",
                "must contain each active command exactly once",
            ));
        }
    }
    if valid_phase && state.pending_outbox.len() == active.len() {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "pending_outbox",
            "must exactly equal active commands in an executing phase",
        ))
    }
}
