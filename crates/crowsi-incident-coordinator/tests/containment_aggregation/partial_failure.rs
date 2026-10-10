//! Regression coverage and synthetic evidence for partial failure boundaries.
use super::*;

#[test]
fn verified_partial_failure_remains_partial() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "partial");
    submit(
        &mut coordinator,
        &commands[0],
        "partial.applied",
        Some(IndependentObservedOutcome::Applied),
        EnforcementOutcome::Applied,
        "2026-07-01T00:01:10.000Z",
    );
    submit(
        &mut coordinator,
        &commands[1],
        "partial.failed",
        None,
        EnforcementOutcome::Failed,
        "2026-07-01T00:01:11.000Z",
    );
    coordinator
        .apply_simulation(&event(
            "partial.finalize",
            1,
            "2026-07-01T00:01:12.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("finalize partial");
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::ContainmentPartial
    );
    assert_eq!(
        coordinator.snapshot().targets[TARGET].observed,
        ObservedTargetState::Partial
    );
}
