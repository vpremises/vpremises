use crowsi_control_contracts::{ActionBindingV1, ControlAction, ControlChannel};
use crowsi_incident_coordinator::{
    EnforcementRequirementV1, IncidentDefinitionV1, TargetDefinitionV1,
};

pub const INCIDENT: &str = "incident.1";
pub const DEPLOYMENT: &str = "deployment.test";
pub const TARGET: &str = "incus://project/default/instance/worker-a";

pub fn definition() -> IncidentDefinitionV1 {
    IncidentDefinitionV1 {
        deployment_id: DEPLOYMENT.to_owned(),
        incident_owner_authority: super::crypto::OWNER_AUTHORITY.to_owned(),
        incident_id: INCIDENT.to_owned(),
        detected_at: "2026-07-01T00:00:00.000Z".to_owned(),
        targets: vec![TargetDefinitionV1 {
            target_id: TARGET.to_owned(),
            requirements: vec![
                requirement(
                    "quarantine",
                    "crowsi-enforcer-incus",
                    ControlAction::Quarantine,
                ),
                requirement(
                    "revoke",
                    "crowsi-enforcer-identity",
                    ControlAction::RevokeAccess,
                ),
            ],
        }],
    }
}

fn requirement(
    requirement_id: &str,
    audience: &str,
    action: ControlAction,
) -> EnforcementRequirementV1 {
    EnforcementRequirementV1 {
        requirement_id: requirement_id.to_owned(),
        binding: ActionBindingV1 {
            audience: audience.to_owned(),
            resource: TARGET.to_owned(),
            action,
            purpose: "incident-containment".to_owned(),
            channel: ControlChannel::EmergencyConsole,
        },
    }
}
