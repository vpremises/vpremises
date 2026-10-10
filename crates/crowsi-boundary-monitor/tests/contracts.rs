use crowsi_boundary_monitor::{evaluate, parse_input};

const SAMPLE: &[u8] = include_bytes!("../examples/boundary-input.sample.json");

#[test]
fn sample_exposes_multiple_environments_without_external_actions() {
    let snapshot = evaluate(parse_input(SAMPLE).expect("valid input"));
    assert_eq!(snapshot.summary.environment_count, 3);
    assert_eq!(snapshot.summary.healthy_count, 2);
    assert_eq!(snapshot.summary.unknown_count, 1);
    assert!(
        snapshot.environments[2]
            .finding_codes
            .contains(&"provider-not-connected".to_owned())
    );
    assert!(!snapshot.external_actions);
}

#[test]
fn management_exposure_requires_attention() {
    let mut input = parse_input(SAMPLE).expect("valid input");
    input.environments[0].management_endpoint_exposed = true;
    let snapshot = evaluate(input);
    assert_eq!(snapshot.environments[0].status, "attention");
    assert!(
        snapshot.environments[0]
            .finding_codes
            .contains(&"management-endpoint-exposed".to_owned())
    );
}

#[test]
fn parser_enforces_the_schema_label_bound() {
    let mut value: serde_json::Value = serde_json::from_slice(SAMPLE).expect("valid JSON");
    value["environments"][0]["label"] = serde_json::Value::String("\u{9577}".repeat(129));
    let source = serde_json::to_vec(&value).expect("serializable JSON");
    assert!(parse_input(&source).is_err());
}
