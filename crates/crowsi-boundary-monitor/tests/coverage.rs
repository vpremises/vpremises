use crowsi_boundary_monitor::{
    ControlAction, CoverageState, evaluate_coverage, parse_coverage_input,
};

const SAMPLE: &[u8] = include_bytes!("../examples/control-coverage.sample.json");

#[test]
fn complete_coverage_requires_fresh_observation_enforcement_and_drill() {
    let snapshot = evaluate_coverage(parse_coverage_input(SAMPLE).expect("valid coverage"));
    assert_eq!(snapshot.overall_state, CoverageState::Controlled);
    assert_eq!(snapshot.summary.controlled_count, 1);
    assert!(snapshot.assets[0].isolation_ready);
}

#[test]
fn unknown_stale_and_unmanaged_assets_never_become_controlled() {
    let mut value: serde_json::Value = serde_json::from_slice(SAMPLE).expect("valid JSON");
    value["assets"][0]["sensor_status"] = serde_json::json!("unknown");
    value["assets"][0]["observed_at_epoch_s"] = serde_json::json!(1);
    value["assets"][0]["authority"] = serde_json::json!("observe-only");
    let snapshot = evaluate_coverage(
        parse_coverage_input(&serde_json::to_vec(&value).unwrap()).expect("valid coverage"),
    );
    assert_eq!(snapshot.overall_state, CoverageState::Unmanaged);
    assert!(!snapshot.assets[0].isolation_ready);
    assert!(snapshot.assets[0].finding_codes.len() >= 3);
}

#[test]
fn every_emergency_action_is_required() {
    let mut value: serde_json::Value = serde_json::from_slice(SAMPLE).expect("valid JSON");
    value["assets"][0]["supported_actions"] = serde_json::json!([
        ControlAction::Quarantine,
        ControlAction::VerifyIsolation,
        ControlAction::Restore
    ]);
    let snapshot = evaluate_coverage(
        parse_coverage_input(&serde_json::to_vec(&value).unwrap()).expect("valid coverage"),
    );
    assert_eq!(snapshot.overall_state, CoverageState::Partial);
    assert!(
        snapshot.assets[0]
            .finding_codes
            .contains(&"required-control-action-missing".to_owned())
    );
}

#[test]
fn duplicate_actions_are_rejected() {
    let mut value: serde_json::Value = serde_json::from_slice(SAMPLE).expect("valid JSON");
    value["assets"][0]["supported_actions"] = serde_json::json!(["quarantine", "quarantine"]);
    let source = serde_json::to_vec(&value).expect("serializable JSON");
    assert!(parse_coverage_input(&source).is_err());
}

#[test]
fn empty_assets_fail_closed_before_evaluation() {
    let mut value: serde_json::Value = serde_json::from_slice(SAMPLE).expect("valid JSON");
    value["assets"] = serde_json::json!([]);
    let source = serde_json::to_vec(&value).expect("serializable JSON");
    assert!(parse_coverage_input(&source).is_err());
}
