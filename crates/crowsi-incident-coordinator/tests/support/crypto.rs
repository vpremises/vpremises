mod signatures;

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_incident_coordinator::{
    COORDINATOR_TRUST_SCHEMA_V1, CoordinatorTrustV1, IncidentCoordinator, IncidentDefinitionV1,
    TrustAnchorV1, TrustRole, TrustScope,
};
use ed25519_dalek::SigningKey;

pub use signatures::{
    sign_anchor, sign_checkpoint, sign_foreign_owner, sign_identity, sign_independent, sign_owner,
    sign_pep, sign_policy, sign_recovery,
};

pub const INDEPENDENT_AUTHORITY: &str = "crowsi-independent-observer";
pub const INDEPENDENT_KEY_ID: &str = "key.independent.1";
pub const RECOVERY_KEY_ID: &str = "key.recovery.1";
pub const OWNER_AUTHORITY: &str = "crowsi-incident-owner";
pub const IDENTITY_AUTHORITY: &str = "https://identity.example.test";
pub const POLICY_AUTHORITY: &str = "crowsi-policy-administrator";
pub const CHECKPOINT_AUTHORITY: &str = "crowsi-checkpoint-authority";
pub const ANCHOR_AUTHORITY: &str = "crowsi-monotonic-anchor";
pub const FOREIGN_OWNER_AUTHORITY: &str = "crowsi-foreign-owner";

const INDEPENDENT_KEY: [u8; 32] = [2; 32];
const RECOVERY_KEY: [u8; 32] = [3; 32];
const INCUS_KEY: [u8; 32] = [1; 32];
const PEP_IDENTITY_KEY: [u8; 32] = [4; 32];
const OWNER_KEY: [u8; 32] = [5; 32];
const IDENTITY_KEY: [u8; 32] = [6; 32];
const POLICY_KEY: [u8; 32] = [7; 32];
const CHECKPOINT_KEY: [u8; 32] = [8; 32];
const ANCHOR_KEY: [u8; 32] = [9; 32];
const FOREIGN_OWNER_KEY: [u8; 32] = [10; 32];

pub fn coordinator(definition: IncidentDefinitionV1) -> IncidentCoordinator {
    IncidentCoordinator::new_simulation(definition, trust()).expect("coordinator")
}

pub fn trust() -> CoordinatorTrustV1 {
    CoordinatorTrustV1 {
        schema: COORDINATOR_TRUST_SCHEMA_V1.to_owned(),
        deployment_id: super::definition::DEPLOYMENT.to_owned(),
        revision: 1,
        keys: vec![
            anchor(
                "crowsi-enforcer-incus",
                "key.pep.incus",
                TrustRole::Pep,
                &[TrustScope::Containment, TrustScope::Restore],
                INCUS_KEY,
            ),
            anchor(
                "crowsi-enforcer-identity",
                "key.pep.identity",
                TrustRole::Pep,
                &[TrustScope::Containment, TrustScope::Restore],
                PEP_IDENTITY_KEY,
            ),
            anchor(
                INDEPENDENT_AUTHORITY,
                INDEPENDENT_KEY_ID,
                TrustRole::IndependentVerifier,
                &[
                    TrustScope::Containment,
                    TrustScope::Restore,
                    TrustScope::Monitoring,
                ],
                INDEPENDENT_KEY,
            ),
            anchor(
                "crowsi-recovery-authority",
                RECOVERY_KEY_ID,
                TrustRole::RecoveryAuthority,
                &[TrustScope::Recovery],
                RECOVERY_KEY,
            ),
            anchor(
                OWNER_AUTHORITY,
                "key.owner.1",
                TrustRole::IncidentOwner,
                &[
                    TrustScope::IncidentLifecycle,
                    TrustScope::Containment,
                    TrustScope::Restore,
                ],
                OWNER_KEY,
            ),
            anchor(
                IDENTITY_AUTHORITY,
                "key.identity-provider.1",
                TrustRole::IdentityProvider,
                &[TrustScope::Containment, TrustScope::Restore],
                IDENTITY_KEY,
            ),
            anchor(
                POLICY_AUTHORITY,
                "key.policy-administrator.1",
                TrustRole::PolicyAdministrator,
                &[TrustScope::Containment, TrustScope::Restore],
                POLICY_KEY,
            ),
            anchor(
                CHECKPOINT_AUTHORITY,
                "key.checkpoint.1",
                TrustRole::CheckpointAuthority,
                &[TrustScope::Checkpoint],
                CHECKPOINT_KEY,
            ),
            anchor(
                ANCHOR_AUTHORITY,
                "key.anchor.1",
                TrustRole::AnchorAuthority,
                &[TrustScope::Anchor],
                ANCHOR_KEY,
            ),
        ],
    }
}

pub fn trust_with_foreign_owner() -> CoordinatorTrustV1 {
    let mut value = trust();
    value.keys.push(anchor(
        FOREIGN_OWNER_AUTHORITY,
        "key.owner.foreign",
        TrustRole::IncidentOwner,
        &[
            TrustScope::IncidentLifecycle,
            TrustScope::Containment,
            TrustScope::Restore,
        ],
        FOREIGN_OWNER_KEY,
    ));
    value
}

pub fn trust_digest() -> String {
    trust().canonical_digest().expect("trust digest")
}

fn anchor(
    authority: &str,
    key_id: &str,
    role: TrustRole,
    scopes: &[TrustScope],
    secret: [u8; 32],
) -> TrustAnchorV1 {
    TrustAnchorV1 {
        authority: authority.to_owned(),
        key_id: key_id.to_owned(),
        role,
        scopes: scopes.iter().copied().collect::<BTreeSet<_>>(),
        public_key: URL_SAFE_NO_PAD
            .encode(SigningKey::from_bytes(&secret).verifying_key().as_bytes()),
    }
}
