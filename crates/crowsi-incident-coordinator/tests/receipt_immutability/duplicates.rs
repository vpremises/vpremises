//! Regression coverage and synthetic evidence for duplicates boundaries.
use super::*;

#[test]
fn a_second_receipt_for_one_command_is_rejected() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "conflict");
    let original = receipt(
        &commands[0],
        "conflict.original",
        EnforcementOutcome::Failed,
    );
    submit_receipt(
        &mut coordinator,
        "conflict.submit",
        "2026-07-01T00:01:10.000Z",
        original,
    )
    .expect("first receipt");
    let snapshot = coordinator.snapshot().clone();
    let conflicting = receipt(&commands[0], "conflict.second", EnforcementOutcome::Applied);
    assert!(
        submit_receipt(
            &mut coordinator,
            "conflict.replace",
            "2026-07-01T00:01:11.000Z",
            conflicting,
        )
        .is_err()
    );
    assert_eq!(coordinator.snapshot(), &snapshot);
}
