use crate::support;

use crowsi_incident_coordinator::{
    IncidentCanonicalPayloadV1, IncidentCoordinator, IncidentEventKindV1,
};

use support::{
    FOREIGN_OWNER_AUTHORITY, containment_authorizations, coordinator, definition, event,
    sign_foreign_owner, sign_owner, trust, trust_with_foreign_owner,
};

#[test]
fn event_and_nested_authorization_signatures_are_both_required() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let mut unsigned = event(
        "auth.unsigned",
        0,
        "2026-07-01T00:01:00.000Z",
        IncidentEventKindV1::BeginTriage,
    );
    corrupt_signature(&mut unsigned.signed.signature);
    let initial = coordinator.export_state();
    assert!(coordinator.apply_simulation(&unsigned).is_err());
    assert_eq!(coordinator.export_state(), initial);

    coordinator
        .apply_simulation(&event(
            "auth.triage",
            0,
            "2026-07-01T00:01:00.000Z",
            IncidentEventKindV1::BeginTriage,
        ))
        .expect("owner-signed triage");
    let mut authorizations = containment_authorizations(&definition, "auth.chain");
    corrupt_signature(&mut authorizations[0].decision.signed.signature);
    let request = event(
        "auth.request",
        0,
        "2026-07-01T00:01:05.000Z",
        IncidentEventKindV1::RequestContainment { authorizations },
    );
    let before = coordinator.export_state();
    assert!(coordinator.apply_simulation(&request).is_err());
    assert_eq!(coordinator.export_state(), before);
}

#[test]
fn owner_signature_cannot_move_an_event_between_deployments() {
    let mut coordinator = coordinator(definition());
    let mut cross_deployment = event(
        "deployment.cross",
        0,
        "2026-07-01T00:01:00.000Z",
        IncidentEventKindV1::BeginTriage,
    );
    cross_deployment.deployment_id = "deployment.other".to_owned();
    cross_deployment.signed = sign_owner(&cross_deployment.signing_payload());
    let before = coordinator.export_state();
    assert!(coordinator.apply_simulation(&cross_deployment).is_err());
    assert_eq!(coordinator.export_state(), before);
}

#[test]
fn another_trusted_owner_cannot_take_over_the_fixed_incident_owner() {
    let mut coordinator =
        IncidentCoordinator::new_simulation(definition(), trust_with_foreign_owner())
            .expect("multi-owner trust");
    let mut foreign = event(
        "owner.foreign",
        0,
        "2026-07-01T00:01:00.000Z",
        IncidentEventKindV1::BeginTriage,
    );
    foreign.owner_authority = FOREIGN_OWNER_AUTHORITY.to_owned();
    foreign.signed = sign_foreign_owner(&foreign.signing_payload());
    assert!(coordinator.apply_simulation(&foreign).is_err());
}

#[test]
fn trusted_clock_lag_is_persisted_separately_from_signed_event_order() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    coordinator
        .apply_simulation(&event(
            "lag.triage",
            0,
            "2026-07-01T00:01:00.000Z",
            IncidentEventKindV1::BeginTriage,
        ))
        .expect("triage");
    let request = event(
        "lag.request",
        0,
        "2026-07-01T00:01:05.000Z",
        IncidentEventKindV1::RequestContainment {
            authorizations: containment_authorizations(&definition, "lag"),
        },
    );
    let commands = coordinator
        .apply_simulation_at(&request, "2026-07-01T00:01:05.100Z")
        .expect("lagged trusted clock");
    assert!(
        commands
            .iter()
            .all(|command| command.issued_at > request.occurred_at)
    );
    IncidentCoordinator::restore_simulation(coordinator.export_state(), trust())
        .expect("watermark validates internally observed command time");
}

fn corrupt_signature(value: &mut String) {
    let replacement = if value.starts_with('A') { "B" } else { "A" };
    value.replace_range(0..1, replacement);
}
