use crate::support;

use crowsi_incident_coordinator::{IncidentEventKindV1, IncidentPhase};

use support::{coordinator, definition, event};

#[test]
fn invalid_transition_is_atomic() {
    let mut coordinator = coordinator(definition());
    let before = coordinator.snapshot().clone();
    assert!(
        coordinator
            .apply_simulation(&event(
                "invalid.eradicate",
                0,
                "2026-07-01T00:01:00.000Z",
                IncidentEventKindV1::BeginEradication,
            ))
            .is_err()
    );
    assert_eq!(coordinator.snapshot(), &before);
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::Detected);
}
