use std::fs;
use std::process::Command;

use crowsi_host_network_sensor::{
    BASELINE_SCHEMA_V1, BaselineV1, FINDING_SCHEMA_V1, FindingV1, SNAPSHOT_SCHEMA_V1, SnapshotV1,
    sample_baseline, sample_snapshot,
};

#[test]
fn deterministic_samples_match_checked_in_contracts() {
    let baseline = serde_json::to_value(sample_baseline().unwrap()).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/baseline.sample.json").unwrap())
            .unwrap();
    assert_eq!(baseline, expected);

    let snapshot = serde_json::to_value(sample_snapshot().unwrap()).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/snapshot.sample.json").unwrap())
            .unwrap();
    assert_eq!(snapshot, expected);
}

#[test]
fn closed_contracts_reject_unknown_fields() {
    let baseline = serde_json::to_string(&sample_baseline().unwrap()).unwrap();
    let changed = baseline.replacen('{', "{\"unknown\":true,", 1);
    assert!(serde_json::from_str::<BaselineV1>(&changed).is_err());

    let snapshot = serde_json::to_string(&sample_snapshot().unwrap()).unwrap();
    let changed = snapshot.replacen('{', "{\"unknown\":true,", 1);
    assert!(serde_json::from_str::<SnapshotV1>(&changed).is_err());

    let finding = r#"{
      "schema":"crowsi://network/host-network-finding/v1",
      "code":"source-parse-failure",
      "listener":null,
      "route_family":null,
      "expected_route":null,
      "observed_route":null,
      "message":"raw error"
    }"#;
    assert!(serde_json::from_str::<FindingV1>(finding).is_err());
    let valid = finding.replace(",\n      \"message\":\"raw error\"", "");
    assert!(serde_json::from_str::<FindingV1>(&valid).is_ok());
    let mut missing_nullable: serde_json::Value = serde_json::from_str(&valid).unwrap();
    missing_nullable.as_object_mut().unwrap().remove("listener");
    assert!(serde_json::from_value::<FindingV1>(missing_nullable).is_err());
}

#[test]
fn output_has_only_metadata_and_no_identity_or_endpoint_fields() {
    let json = serde_json::to_string(&sample_snapshot().unwrap()).unwrap();
    for forbidden_key in [
        "address",
        "remote_endpoint",
        "remote_port",
        "packet",
        "payload",
        "pid",
        "uid",
        "inode",
        "process",
        "credential",
        "hostname",
        "interface",
    ] {
        assert!(!json.contains(&format!("\"{forbidden_key}\"")));
    }
    assert!(json.contains("\"external_actions\":false"));
    assert!(json.contains("\"signal_trust\":\"unsigned-local\""));
}

#[test]
fn schemas_are_closed_and_use_the_executable_ids() {
    for (path, expected_id) in [
        (
            "schemas/host-network-baseline-v1.schema.json",
            BASELINE_SCHEMA_V1,
        ),
        (
            "schemas/host-network-snapshot-v1.schema.json",
            SNAPSHOT_SCHEMA_V1,
        ),
        (
            "schemas/host-network-finding-v1.schema.json",
            FINDING_SCHEMA_V1,
        ),
    ] {
        let schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(schema["$id"], expected_id);
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[test]
fn cli_sample_emits_the_snapshot_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-host-network-sensor"))
        .arg("sample")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: SnapshotV1 = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value, sample_snapshot().unwrap());
    assert!(output.stderr.is_empty());
}
