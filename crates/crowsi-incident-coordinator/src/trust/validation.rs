use std::collections::BTreeSet;

use crate::{
    COORDINATOR_TRUST_SCHEMA_V1, CoordinatorError, Validate,
    crypto::decode_public_key,
    validation::{https_uri, identifier, schema},
};

use super::{CoordinatorTrustV1, TrustAnchorV1, TrustRole, TrustScope};

const MAX_KEYS: usize = 64;

impl Validate for CoordinatorTrustV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, COORDINATOR_TRUST_SCHEMA_V1)?;
        identifier("trust.deployment_id", &self.deployment_id)?;
        if self.revision == 0 {
            return Err(CoordinatorError::new(
                "trust.revision",
                "must be positive and immutable for an incident",
            ));
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(CoordinatorError::new(
                "trust.keys",
                "must contain 1 to 64 keys",
            ));
        }
        let mut key_ids = BTreeSet::new();
        let mut materials = BTreeSet::new();
        let mut capabilities = BTreeSet::new();
        for key in &self.keys {
            authority(key)?;
            identifier("trust.key_id", &key.key_id)?;
            let material = decode_public_key(&key.public_key)?;
            if key.scopes.is_empty()
                || !key_ids.insert(&key.key_id)
                || !materials.insert(material)
                || !valid_scopes(key)
            {
                return Err(CoordinatorError::new(
                    "trust.keys",
                    "key identity, material, role, or scope is invalid",
                ));
            }
            capabilities.extend(key.scopes.iter().map(|scope| (key.role, *scope)));
        }
        if required()
            .into_iter()
            .all(|value| capabilities.contains(&value))
        {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "trust.keys",
                "required role and scope coverage is missing",
            ))
        }
    }
}

fn authority(anchor: &TrustAnchorV1) -> Result<(), CoordinatorError> {
    if anchor.role == TrustRole::IdentityProvider {
        https_uri("trust.authority", &anchor.authority)
    } else {
        identifier("trust.authority", &anchor.authority)
    }
}

fn valid_scopes(anchor: &TrustAnchorV1) -> bool {
    anchor.scopes.iter().all(|scope| match anchor.role {
        TrustRole::Pep | TrustRole::IdentityProvider | TrustRole::PolicyAdministrator => {
            operation(*scope)
        }
        TrustRole::IndependentVerifier => operation(*scope) || *scope == TrustScope::Monitoring,
        TrustRole::RecoveryAuthority => *scope == TrustScope::Recovery,
        TrustRole::IncidentOwner => operation(*scope) || *scope == TrustScope::IncidentLifecycle,
        TrustRole::CheckpointAuthority => *scope == TrustScope::Checkpoint,
        TrustRole::AnchorAuthority => *scope == TrustScope::Anchor,
    })
}

const fn operation(scope: TrustScope) -> bool {
    matches!(scope, TrustScope::Containment | TrustScope::Restore)
}

const fn required() -> [(TrustRole, TrustScope); 15] {
    [
        (TrustRole::Pep, TrustScope::Containment),
        (TrustRole::Pep, TrustScope::Restore),
        (TrustRole::IndependentVerifier, TrustScope::Containment),
        (TrustRole::IndependentVerifier, TrustScope::Restore),
        (TrustRole::IndependentVerifier, TrustScope::Monitoring),
        (TrustRole::RecoveryAuthority, TrustScope::Recovery),
        (TrustRole::IncidentOwner, TrustScope::IncidentLifecycle),
        (TrustRole::IncidentOwner, TrustScope::Containment),
        (TrustRole::IncidentOwner, TrustScope::Restore),
        (TrustRole::IdentityProvider, TrustScope::Containment),
        (TrustRole::IdentityProvider, TrustScope::Restore),
        (TrustRole::PolicyAdministrator, TrustScope::Containment),
        (TrustRole::PolicyAdministrator, TrustScope::Restore),
        (TrustRole::CheckpointAuthority, TrustScope::Checkpoint),
        (TrustRole::AnchorAuthority, TrustScope::Anchor),
    ]
}
