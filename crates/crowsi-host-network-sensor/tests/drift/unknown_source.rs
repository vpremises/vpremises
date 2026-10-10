//! Regression coverage and synthetic evidence for unknown source boundaries.
use super::*;

#[test]
fn unknown_source_state_is_preserved_without_false_drift() {
    let baseline = BaselineV1::try_new(
        "host-one",
        vec![listener(443)],
        routes(RouteStateV1::Absent),
    )
    .unwrap();
    let source = format!(
        r#"{{
          "schema":"crowsi://network/host-network-snapshot/v1",
          "generated_at":"{TIME}",
          "external_actions":false,
          "signal_trust":"unsigned-local",
          "status":"unknown",
          "listeners":[],
          "default_routes":{{"ipv4":"unknown","ipv6":"unknown"}},
          "findings":[{{
            "schema":"crowsi://network/host-network-finding/v1",
            "code":"source-parse-failure",
            "listener":null,
            "route_family":null,
            "expected_route":null,
            "observed_route":null
          }}]
        }}"#
    );
    let snapshot: SnapshotV1 = serde_json::from_str(&source).unwrap();
    let result = evaluate_drift(&baseline, &snapshot).unwrap();
    assert_eq!(result, snapshot);
    assert_eq!(result.status(), SnapshotStatusV1::Unknown);
}
