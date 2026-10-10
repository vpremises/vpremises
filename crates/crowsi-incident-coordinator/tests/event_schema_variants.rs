use std::collections::BTreeSet;

use crowsi_incident_coordinator::IncidentEventKindV1;
use serde_json::Value;

#[test]
fn event_schema_enumerates_every_rust_variant() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/incident-event-v1.schema.json"))
            .expect("event schema");
    let schema_tags = collect_schema_tags(&schema);
    let rust_tags = [
        IncidentEventKindV1::BeginTriage,
        IncidentEventKindV1::FinalizeContainment,
        IncidentEventKindV1::BeginEradication,
        IncidentEventKindV1::RequestRecovery,
        IncidentEventKindV1::StartRestore { automatic: false },
        IncidentEventKindV1::FinalizeRestore,
        IncidentEventKindV1::RetryRecovery,
        IncidentEventKindV1::BeginMonitoring,
    ]
    .iter()
    .map(known_tag)
    .chain([
        "request-containment",
        "submit-receipt",
        "submit-verification",
        "retry-containment",
        "authorize-recovery",
        "close",
    ])
    .collect::<BTreeSet<_>>();
    assert_eq!(schema_tags, rust_tags);
}

fn known_tag(kind: &IncidentEventKindV1) -> &'static str {
    match kind {
        IncidentEventKindV1::BeginTriage => "begin-triage",
        IncidentEventKindV1::RequestContainment { .. } => "request-containment",
        IncidentEventKindV1::SubmitReceipt { .. } => "submit-receipt",
        IncidentEventKindV1::SubmitVerification { .. } => "submit-verification",
        IncidentEventKindV1::FinalizeContainment => "finalize-containment",
        IncidentEventKindV1::RetryContainment { .. } => "retry-containment",
        IncidentEventKindV1::BeginEradication => "begin-eradication",
        IncidentEventKindV1::RequestRecovery => "request-recovery",
        IncidentEventKindV1::AuthorizeRecovery { .. } => "authorize-recovery",
        IncidentEventKindV1::StartRestore { .. } => "start-restore",
        IncidentEventKindV1::FinalizeRestore => "finalize-restore",
        IncidentEventKindV1::RetryRecovery => "retry-recovery",
        IncidentEventKindV1::BeginMonitoring => "begin-monitoring",
        IncidentEventKindV1::Close { .. } => "close",
    }
}

fn collect_schema_tags(schema: &Value) -> BTreeSet<&str> {
    let mut tags = BTreeSet::new();
    for definition in schema["$defs"].as_object().expect("definitions").values() {
        let type_schema = &definition["properties"]["type"];
        if let Some(value) = type_schema["const"].as_str() {
            tags.insert(value);
        }
        if let Some(values) = type_schema["enum"].as_array() {
            for value in values {
                tags.insert(value.as_str().expect("event type"));
            }
        }
    }
    tags
}
