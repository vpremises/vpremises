mod validation;

use std::collections::BTreeSet;

use crowsi_control_contracts::SignedDigestV1;
use serde::{Deserialize, Serialize};

use crate::{CoordinatorError, crypto::verify_ed25519};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustRole {
    Pep,
    IndependentVerifier,
    RecoveryAuthority,
    IncidentOwner,
    IdentityProvider,
    PolicyAdministrator,
    CheckpointAuthority,
    AnchorAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustScope {
    Containment,
    Restore,
    Recovery,
    Monitoring,
    IncidentLifecycle,
    Checkpoint,
    Anchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorV1 {
    pub authority: String,
    pub key_id: String,
    pub role: TrustRole,
    pub scopes: BTreeSet<TrustScope>,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorTrustV1 {
    pub schema: String,
    pub deployment_id: String,
    pub revision: u64,
    pub keys: Vec<TrustAnchorV1>,
}

impl CoordinatorTrustV1 {
    /// Returns the immutable, domain-separated deployment trust bundle digest.
    ///
    /// # Errors
    ///
    /// Returns an error if this closed bundle cannot be serialized.
    pub fn canonical_digest(&self) -> Result<String, CoordinatorError> {
        let json = serde_json::to_vec(self)
            .map_err(|_| CoordinatorError::new("trust", "canonical serialization failed"))?;
        let mut value = crate::canonical::Encoder::new("coordinator-trust-v1");
        value.text("schema", &self.schema);
        value.text("json_digest", &crate::canonical::digest_payload(&json));
        Ok(crate::canonical::digest_payload(&value.finish()))
    }

    pub(crate) fn supports(&self, authority: &str, role: TrustRole, scope: TrustScope) -> bool {
        self.keys.iter().any(|key| {
            key.authority == authority && key.role == role && key.scopes.contains(&scope)
        })
    }

    pub(crate) fn verify<'a>(
        &'a self,
        authority: Option<&str>,
        role: TrustRole,
        scope: TrustScope,
        signed: &SignedDigestV1,
        payload: &[u8],
    ) -> Result<&'a TrustAnchorV1, CoordinatorError> {
        let anchor = self
            .keys
            .iter()
            .find(|key| key.key_id == signed.key_id)
            .ok_or_else(|| CoordinatorError::new("signed.key_id", "key is not trusted"))?;
        if anchor.role != role
            || !anchor.scopes.contains(&scope)
            || authority.is_some_and(|expected| anchor.authority != expected)
        {
            return Err(CoordinatorError::new(
                "trust",
                "authority, role, or scope is not trusted",
            ));
        }
        verify_ed25519(&anchor.public_key, signed, payload)?;
        Ok(anchor)
    }
}

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
