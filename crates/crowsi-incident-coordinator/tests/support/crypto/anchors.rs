//! Regression coverage and synthetic evidence for anchors boundaries.
use super::*;

pub fn trust() -> CoordinatorTrustV1 {
    CoordinatorTrustV1 {
        schema: COORDINATOR_TRUST_SCHEMA_V1.to_owned(),
        deployment_id: super::super::definition::DEPLOYMENT.to_owned(),
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
