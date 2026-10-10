use crowsi_incident_coordinator::{
    COORDINATOR_CHECKPOINT_SCHEMA_V1, CoordinatorCheckpointV1, CoordinatorStateV1,
    ExternalMonotonicAnchorV1, IncidentCanonicalPayloadV1, IncidentCoordinator,
    MONOTONIC_ANCHOR_SCHEMA_V1, MonotonicChallengeV1,
};

use super::{
    ANCHOR_AUTHORITY, CHECKPOINT_AUTHORITY,
    clock::system_now,
    common::signed,
    crypto::{sign_anchor, sign_checkpoint},
    definition::{DEPLOYMENT, INCIDENT},
};

pub fn checkpoint(
    state: &CoordinatorStateV1,
    sequence: u64,
    previous_checkpoint_digest: Option<String>,
) -> CoordinatorCheckpointV1 {
    let mut value = CoordinatorCheckpointV1 {
        schema: COORDINATOR_CHECKPOINT_SCHEMA_V1.to_owned(),
        checkpoint_id: format!("checkpoint.{sequence}"),
        jti: format!("jti.checkpoint.{sequence}"),
        deployment_id: state.snapshot.deployment_id.clone(),
        incident_id: state.snapshot.incident_id.clone(),
        trust_bundle_digest: state.snapshot.trust_bundle_digest.clone(),
        trust_revision: state.snapshot.trust_revision,
        sequence,
        previous_checkpoint_digest,
        state_digest: state.canonical_digest().expect("state digest"),
        command_digests: command_digests(state),
        issued_at: state.snapshot.trusted_time_watermark.clone(),
        authority: CHECKPOINT_AUTHORITY.to_owned(),
        signed: signed(),
    };
    value.signed = sign_checkpoint(&value.signing_payload());
    value
}

fn command_digests(state: &CoordinatorStateV1) -> Vec<String> {
    let mut values = state
        .pending_outbox
        .iter()
        .map(|command| command.canonical_digest().expect("command digest"))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

pub fn anchor(
    checkpoint: &CoordinatorCheckpointV1,
    challenge: &MonotonicChallengeV1,
) -> ExternalMonotonicAnchorV1 {
    let mut value = ExternalMonotonicAnchorV1 {
        schema: MONOTONIC_ANCHOR_SCHEMA_V1.to_owned(),
        anchor_id: format!("anchor.{}", checkpoint.sequence),
        jti: format!("jti.anchor.{}", checkpoint.sequence),
        deployment_id: checkpoint.deployment_id.clone(),
        incident_id: checkpoint.incident_id.clone(),
        challenge_nonce: challenge.nonce().to_owned(),
        sequence: checkpoint.sequence,
        checkpoint_digest: checkpoint.payload_digest(),
        issued_at: system_now(),
        expires_at: challenge.expires_at().to_owned(),
        authority: ANCHOR_AUTHORITY.to_owned(),
        signed: signed(),
    };
    value.signed = sign_anchor(&value.signing_payload());
    value
}

pub fn restore_challenge() -> MonotonicChallengeV1 {
    IncidentCoordinator::begin_authenticated_restore(DEPLOYMENT, INCIDENT)
        .expect("restore challenge")
}
