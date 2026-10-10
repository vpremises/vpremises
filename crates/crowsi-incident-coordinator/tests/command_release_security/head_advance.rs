//! Regression coverage and synthetic evidence for head advance boundaries.
use super::*;

#[test]
fn head_advance_inside_execution_barrier_rejects_old_release() {
    let definition = definition();
    let mut simulation = coordinator(definition.clone());
    let commands = begin_containment(&mut simulation, &definition, "race");
    let mut staged = simulation.export_state();
    staged.pending_outbox = commands;
    let first = checkpoint(&staged, 1, None);
    let challenge = restore_challenge();
    let signed_anchor = anchor(&first, &challenge);
    let release_json = serde_json::json!({
        "schema": crowsi_incident_coordinator::COMMAND_RELEASE_SCHEMA_V1,
        "command": staged.pending_outbox[0],
        "command_digest": first.command_digests[0],
        "checkpoint": first,
        "anchor": signed_anchor
    });
    let release: CommandReleaseV1 =
        serde_json::from_value(release_json).expect("closed release shape");
    let mut gate = AtomicGate::advancing(release.checkpoint());
    assert!(
        release
            .consume_if_current(&trust_digest(), &trust(), &mut gate)
            .is_err()
    );
}
