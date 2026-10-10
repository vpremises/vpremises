//! Require independent signing identities and separated control planes.
use super::{CoordinatorError, TrustAnchorV1};

pub(crate) fn ensure_independent(
    pep: &TrustAnchorV1,
    verifier: &TrustAnchorV1,
) -> Result<(), CoordinatorError> {
    if pep.authority != verifier.authority
        && pep.key_id != verifier.key_id
        && pep.public_key != verifier.public_key
    {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "verifier",
            "must be cryptographically and administratively independent from the PEP",
        ))
    }
}

pub(crate) fn ensure_separate_control_planes(
    checkpoint: &TrustAnchorV1,
    anchor: &TrustAnchorV1,
) -> Result<(), CoordinatorError> {
    if checkpoint.authority != anchor.authority
        && checkpoint.key_id != anchor.key_id
        && checkpoint.public_key != anchor.public_key
    {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "checkpoint_trust",
            "checkpoint and monotonic authorities must be independent",
        ))
    }
}
