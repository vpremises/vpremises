use crate::{
    CoordinatorCheckpointV1, CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1,
    ExternalMonotonicAnchorV1, IncidentCanonicalPayloadV1, MonotonicChallengeV1,
    MonotonicHeadReaderV1,
    trust::{TrustRole, TrustScope, ensure_separate_control_planes},
};

pub(super) fn verify_current_head(
    checkpoint: &CoordinatorCheckpointV1,
    reader: &impl MonotonicHeadReaderV1,
) -> Result<(), CoordinatorError> {
    if reader.is_current_head(
        &checkpoint.deployment_id,
        &checkpoint.incident_id,
        checkpoint.sequence,
        &checkpoint.payload_digest(),
    ) {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "monotonic_head",
            "checkpoint is not the durable store current head",
        ))
    }
}

pub(super) fn verify_checkpoint(
    state: &CoordinatorStateV1,
    checkpoint: &CoordinatorCheckpointV1,
    anchor: &ExternalMonotonicAnchorV1,
    challenge: &MonotonicChallengeV1,
    trust: &CoordinatorTrustV1,
    trusted_now: &str,
) -> Result<(), CoordinatorError> {
    checkpoint.validate_at(trusted_now)?;
    anchor.validate_at(trusted_now)?;
    let exact = checkpoint.deployment_id == anchor.deployment_id
        && checkpoint.deployment_id == state.snapshot.deployment_id
        && checkpoint.incident_id == anchor.incident_id
        && anchor.incident_id == state.snapshot.incident_id
        && anchor.challenge_nonce == challenge.nonce()
        && anchor.deployment_id == challenge.deployment_id()
        && anchor.incident_id == challenge.incident_id()
        && anchor.issued_at.as_str() >= challenge.issued_at()
        && anchor.expires_at.as_str() <= challenge.expires_at()
        && checkpoint.sequence == anchor.sequence
        && checkpoint.payload_digest() == anchor.checkpoint_digest
        && checkpoint.incident_id == state.snapshot.incident_id
        && checkpoint.trust_bundle_digest == state.snapshot.trust_bundle_digest
        && checkpoint.trust_revision == state.snapshot.trust_revision
        && checkpoint.issued_at == state.snapshot.trusted_time_watermark
        && checkpoint.state_digest == state.canonical_digest()?
        && checkpoint.command_digests == command_digests(state)?;
    if !exact {
        return Err(CoordinatorError::new(
            "checkpoint",
            "does not match state, watermark, or external anchor",
        ));
    }
    let monotonic = trust.verify(
        Some(&anchor.authority),
        TrustRole::AnchorAuthority,
        TrustScope::Anchor,
        &anchor.signed,
        &anchor.signing_payload(),
    )?;
    let signer = trust.verify(
        Some(&checkpoint.authority),
        TrustRole::CheckpointAuthority,
        TrustScope::Checkpoint,
        &checkpoint.signed,
        &checkpoint.signing_payload(),
    )?;
    ensure_separate_control_planes(signer, monotonic)
}

fn command_digests(state: &CoordinatorStateV1) -> Result<Vec<String>, CoordinatorError> {
    let mut values = state
        .pending_outbox
        .iter()
        .map(crate::CoordinatorCommandV1::canonical_digest)
        .collect::<Result<Vec<_>, _>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}
