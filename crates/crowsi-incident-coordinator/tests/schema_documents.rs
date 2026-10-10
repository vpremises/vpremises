use crowsi_incident_coordinator::{
    COMMAND_RELEASE_SCHEMA_V1, COORDINATOR_CHECKPOINT_SCHEMA_V1, COORDINATOR_COMMAND_SCHEMA_V1,
    COORDINATOR_RECEIPT_SCHEMA_V1, COORDINATOR_STATE_SCHEMA_V1, COORDINATOR_TRUST_SCHEMA_V1,
    INCIDENT_EVENT_SCHEMA_V1, INDEPENDENT_VERIFICATION_SCHEMA_V1, MONITORING_EVIDENCE_SCHEMA_V1,
    MONOTONIC_ANCHOR_SCHEMA_V1,
};
use serde_json::Value;

const SCHEMAS: [(&str, &str); 10] = [
    (
        INCIDENT_EVENT_SCHEMA_V1,
        include_str!("../schemas/incident-event-v1.schema.json"),
    ),
    (
        COORDINATOR_COMMAND_SCHEMA_V1,
        include_str!("../schemas/coordinator-command-v1.schema.json"),
    ),
    (
        COORDINATOR_RECEIPT_SCHEMA_V1,
        include_str!("../schemas/coordinator-receipt-v1.schema.json"),
    ),
    (
        COORDINATOR_STATE_SCHEMA_V1,
        include_str!("../schemas/coordinator-state-v1.schema.json"),
    ),
    (
        COORDINATOR_TRUST_SCHEMA_V1,
        include_str!("../schemas/coordinator-trust-v1.schema.json"),
    ),
    (
        INDEPENDENT_VERIFICATION_SCHEMA_V1,
        include_str!("../schemas/independent-verification-v1.schema.json"),
    ),
    (
        MONITORING_EVIDENCE_SCHEMA_V1,
        include_str!("../schemas/monitoring-evidence-v1.schema.json"),
    ),
    (
        COORDINATOR_CHECKPOINT_SCHEMA_V1,
        include_str!("../schemas/coordinator-checkpoint-v1.schema.json"),
    ),
    (
        MONOTONIC_ANCHOR_SCHEMA_V1,
        include_str!("../schemas/monotonic-anchor-v1.schema.json"),
    ),
    (
        COMMAND_RELEASE_SCHEMA_V1,
        include_str!("../schemas/command-release-v1.schema.json"),
    ),
];

#[test]
fn versioned_schema_documents_are_closed_valid_json() {
    for (expected, source) in SCHEMAS {
        let schema: Value = serde_json::from_str(source).expect("valid schema JSON");
        assert_eq!(schema["$id"], expected);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}

#[test]
fn closed_objects_declare_every_property_as_required() {
    for (_, source) in SCHEMAS {
        let schema: Value = serde_json::from_str(source).expect("valid schema JSON");
        check_closed_object_shape(&schema);
    }
}

fn check_closed_object_shape(value: &Value) {
    if value["type"] == "object"
        && value["additionalProperties"] == false
        && value.get("properties").is_some()
    {
        let required = value["required"]
            .as_array()
            .expect("closed object has required")
            .iter()
            .map(|item| item.as_str().expect("required string"))
            .collect::<std::collections::BTreeSet<_>>();
        let properties = value["properties"]
            .as_object()
            .expect("properties object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(required, properties);
    }
    if let Some(object) = value.as_object() {
        for nested in object.values() {
            check_closed_object_shape(nested);
        }
    } else if let Some(array) = value.as_array() {
        for nested in array {
            check_closed_object_shape(nested);
        }
    }
}
