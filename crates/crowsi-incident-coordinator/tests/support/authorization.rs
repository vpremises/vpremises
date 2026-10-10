#[path = "authorization/builders.rs"]
mod builders;

use std::collections::BTreeMap;

use crowsi_control_contracts::{
    ActionBindingV1, AssuranceLevel, CanonicalPayloadV1, ControlAction,
    RECOVERY_AUTHORIZATION_SCHEMA_V1, RecoveryAuthorizationV1,
};
use crowsi_incident_coordinator::{
    CommandAuthorizationV1, IncidentDefinitionV1, RecoveryApprovalV1,
};

use builders::{decision, grant, identity, intent};

use super::{
    common::signed,
    crypto::{sign_identity, sign_owner, sign_policy, sign_recovery},
};

pub fn containment_authorizations(
    definition: &IncidentDefinitionV1,
    tag: &str,
) -> Vec<CommandAuthorizationV1> {
    authorizations(definition, tag, AssuranceLevel::PhishingResistant, false)
}

pub fn recovery_approval(definition: &IncidentDefinitionV1, tag: &str) -> RecoveryApprovalV1 {
    let authorizations = authorizations(definition, tag, AssuranceLevel::HardwareBoundStepUp, true);
    let recovery_authorizations = authorizations
        .iter()
        .map(|authorization| {
            (
                authorization.requirement_id.clone(),
                recovery_authority(definition, authorization, tag),
            )
        })
        .collect::<BTreeMap<_, _>>();
    RecoveryApprovalV1 {
        approval_id: format!("approval.{tag}"),
        approved_at: "2026-07-01T00:02:00.000Z".to_owned(),
        authorizations,
        recovery_authorizations,
    }
}

fn recovery_authority(
    definition: &IncidentDefinitionV1,
    authorization: &CommandAuthorizationV1,
    tag: &str,
) -> RecoveryAuthorizationV1 {
    let mut value = RecoveryAuthorizationV1 {
        schema: RECOVERY_AUTHORIZATION_SCHEMA_V1.to_owned(),
        authorization_id: format!("recovery.{tag}.{}", authorization.requirement_id),
        jti: format!("jti.recovery.{tag}.{}", authorization.requirement_id),
        identity_context_id: authorization.identity.context_id.clone(),
        pairwise_subject: authorization.identity.pairwise_subject.clone(),
        binding: authorization.intent.binding.clone(),
        incident_id: definition.incident_id.clone(),
        policy_snapshot_id: format!("snapshot.{tag}.{}", authorization.requirement_id),
        policy_snapshot_digest: authorization.decision.policy_digest.clone(),
        authoritative_revocation_epoch: authorization.current_revocation_epoch,
        issued_at: "2026-07-01T00:02:00.000Z".to_owned(),
        expires_at: "2026-07-01T00:03:00.000Z".to_owned(),
        use_limit: 1,
        signed: signed(),
    };
    value.signed = sign_recovery(&value.signing_payload());
    value
}

fn authorizations(
    definition: &IncidentDefinitionV1,
    tag: &str,
    assurance: AssuranceLevel,
    restore: bool,
) -> Vec<CommandAuthorizationV1> {
    definition
        .targets
        .iter()
        .flat_map(|target| {
            target.requirements.iter().map(|requirement| {
                let mut binding = requirement.binding.clone();
                if restore {
                    binding.action = ControlAction::Restore;
                    "incident-recovery".clone_into(&mut binding.purpose);
                }
                authorization(
                    &target.target_id,
                    &requirement.requirement_id,
                    binding,
                    tag,
                    assurance,
                )
            })
        })
        .collect()
}

#[path = "authorization/document.rs"]
mod document;
use document::authorization;
