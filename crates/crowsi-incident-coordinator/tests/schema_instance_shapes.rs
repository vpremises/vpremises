use crate::support;

use std::collections::BTreeSet;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{
    COMMAND_RELEASE_SCHEMA_V1, CommandReleaseV1, IncidentEventKindV1,
    MONITORING_EVIDENCE_SCHEMA_V1, MonitoringEvidenceV1, MonitoringOutcome,
};
use serde::Serialize;
use serde_json::Value;

use support::{
    INDEPENDENT_AUTHORITY, anchor, begin_containment, checkpoint, coordinator, definition, digest,
    event, receipt, restore_challenge, signed, trust, verification,
};

#[test]
fn representative_serialized_roots_match_schema_properties() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let state = coordinator.export_state();
    let checkpoint = checkpoint(&state, 1, None);
    let challenge = restore_challenge();
    let anchor = anchor(&checkpoint, &challenge);
    let event = event(
        "schema.triage",
        0,
        "2026-07-01T00:01:00.000Z",
        IncidentEventKindV1::BeginTriage,
    );
    let commands = begin_containment(&mut coordinator, &definition, "schema");
    let receipt = receipt(&commands[0], "schema", EnforcementOutcome::Applied);
    let verification = verification(
        &receipt,
        "schema",
        crowsi_incident_coordinator::IndependentObservedOutcome::Applied,
    );
    let monitoring = MonitoringEvidenceV1 {
        schema: MONITORING_EVIDENCE_SCHEMA_V1.to_owned(),
        evidence_id: "monitoring.schema".to_owned(),
        jti: "jti.monitoring.schema".to_owned(),
        nonce: "nonce-schema".to_owned(),
        deployment_id: state.snapshot.deployment_id.clone(),
        incident_id: state.snapshot.incident_id.clone(),
        isolation_epoch: 1,
        monitoring_started_at: "2026-07-01T00:02:31.000Z".to_owned(),
        observed_at: "2026-07-01T00:07:31.000Z".to_owned(),
        subject_digest: digest(),
        outcome: MonitoringOutcome::Stable,
        verifier_authority: INDEPENDENT_AUTHORITY.to_owned(),
        issued_at: "2026-07-01T00:07:32.000Z".to_owned(),
        expires_at: "2026-07-01T00:12:32.000Z".to_owned(),
        signed: signed(),
    };
    let release: CommandReleaseV1 = serde_json::from_value(serde_json::json!({
        "schema": COMMAND_RELEASE_SCHEMA_V1,
        "command": commands[0],
        "command_digest": commands[0].canonical_digest().expect("digest"),
        "checkpoint": checkpoint,
        "anchor": anchor
    }))
    .expect("release shape");

    assert_root(
        include_str!("../schemas/incident-event-v1.schema.json"),
        &event,
    );
    assert_root(
        include_str!("../schemas/coordinator-state-v1.schema.json"),
        &state,
    );
    assert_root(
        include_str!("../schemas/coordinator-trust-v1.schema.json"),
        &trust(),
    );
    assert_root(
        include_str!("../schemas/coordinator-checkpoint-v1.schema.json"),
        &checkpoint,
    );
    assert_root(
        include_str!("../schemas/monotonic-anchor-v1.schema.json"),
        &anchor,
    );
    assert_root(
        include_str!("../schemas/coordinator-command-v1.schema.json"),
        &commands[0],
    );
    assert_root(
        include_str!("../schemas/coordinator-receipt-v1.schema.json"),
        &receipt,
    );
    assert_root(
        include_str!("../schemas/independent-verification-v1.schema.json"),
        &verification,
    );
    assert_root(
        include_str!("../schemas/monitoring-evidence-v1.schema.json"),
        &monitoring,
    );
    assert_root(
        include_str!("../schemas/command-release-v1.schema.json"),
        &release,
    );
}

#[path = "schema_instance_shapes/properties.rs"]
mod properties;
use properties::assert_root;
