use crate::support;

use crowsi_incident_coordinator::{
    CommandReleaseV1, IncidentCanonicalPayloadV1, IncidentCoordinator,
};

use support::{
    AtomicGate, anchor, begin_containment, checkpoint, coordinator, current_head, definition,
    restore_challenge, trust, trust_digest,
};

#[test]
fn commands_are_released_only_with_signed_current_head_membership() {
    let definition = definition();
    let mut simulation = coordinator(definition.clone());
    let commands = begin_containment(&mut simulation, &definition, "release");
    let mut staged = simulation.export_state();
    staged.pending_outbox.clone_from(&commands);

    let first = checkpoint(&staged, 1, None);
    let restore_challenge = restore_challenge();
    let restore_anchor = anchor(&first, &restore_challenge);
    let mut production = IncidentCoordinator::restore_authenticated(
        staged,
        &first,
        &restore_anchor,
        restore_challenge,
        &trust_digest(),
        trust(),
        &current_head(&first),
    )
    .expect("authenticated staged state");

    let second = checkpoint(&production.export_state(), 2, Some(first.payload_digest()));
    let commit_challenge = production
        .checkpoint_commit_challenge()
        .expect("commit challenge");
    let commit_anchor = anchor(&second, &commit_challenge);
    let releases = production
        .confirm_checkpoint_commit(
            &second,
            &commit_anchor,
            commit_challenge,
            &current_head(&second),
        )
        .expect("committed command releases");

    assert_eq!(releases.len(), commands.len());
    let mut gate = AtomicGate::current(&second);
    for release in releases {
        release
            .consume_if_current(&trust_digest(), &trust(), &mut gate)
            .expect("signed current-head membership");
    }
}

#[test]
fn stale_command_cannot_be_rewrapped_with_a_current_fence() {
    let definition = definition();
    let mut simulation = coordinator(definition.clone());
    let commands = begin_containment(&mut simulation, &definition, "stale");
    let mut staged = simulation.export_state();
    staged.pending_outbox.clone_from(&commands);
    let member_checkpoint = checkpoint(&staged, 1, None);
    let member_challenge = restore_challenge();
    let member_anchor = anchor(&member_checkpoint, &member_challenge);

    let mut empty = staged;
    empty.pending_outbox.clear();
    let current = checkpoint(&empty, 2, Some(member_checkpoint.payload_digest()));
    let current_challenge = restore_challenge();
    let current_anchor = anchor(&current, &current_challenge);

    let forged_json = serde_json::json!({
        "schema": crowsi_incident_coordinator::COMMAND_RELEASE_SCHEMA_V1,
        "command": commands[0],
        "command_digest": commands[0].canonical_digest().expect("digest"),
        "checkpoint": current,
        "anchor": current_anchor
    });
    let forged: CommandReleaseV1 =
        serde_json::from_value(forged_json).expect("closed release shape");
    assert!(
        forged
            .consume_if_current(
                &trust_digest(),
                &trust(),
                &mut AtomicGate::current(&current),
            )
            .is_err()
    );

    assert_eq!(
        member_anchor.checkpoint_digest,
        member_checkpoint.payload_digest()
    );
}

#[path = "command_release_security/head_advance.rs"]
mod head_advance;
