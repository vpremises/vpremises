use crowsi_host_network_sensor::{
    AddressFamilyV1, BaselineV1, BindScopeV1, FindingCodeV1, ListenerV1, ProtocolV1, RouteStateV1,
    RoutesV1, SnapshotStatusV1, SnapshotV1, evaluate_drift,
};

const TIME: &str = "2026-08-01T00:00:00.000Z";

fn listener(port: u16) -> ListenerV1 {
    ListenerV1::new(
        ProtocolV1::Tcp,
        AddressFamilyV1::Ipv4,
        port,
        BindScopeV1::Wildcard,
    )
    .unwrap()
}

fn routes(ipv4: RouteStateV1) -> RoutesV1 {
    RoutesV1::new(ipv4, RouteStateV1::Absent)
}

#[test]
fn unexpected_listener_is_a_closed_drift_finding() {
    let baseline = BaselineV1::try_new(
        "host-one",
        vec![listener(443)],
        routes(RouteStateV1::Present),
    )
    .unwrap();
    let snapshot = SnapshotV1::observed(
        TIME,
        vec![listener(443), listener(8_080)],
        routes(RouteStateV1::Present),
    )
    .unwrap();

    let result = evaluate_drift(&baseline, &snapshot).unwrap();
    assert_eq!(result.status(), SnapshotStatusV1::Drifted);
    assert_eq!(result.findings().len(), 1);
    assert_eq!(
        result.findings()[0].code(),
        FindingCodeV1::UnexpectedListener
    );
    assert_eq!(
        result.findings()[0]
            .listener_metadata()
            .expect("listener metadata")
            .port(),
        8_080
    );
}

#[test]
fn default_route_change_is_reported_without_route_details() {
    let baseline = BaselineV1::try_new("host-one", vec![], routes(RouteStateV1::Present)).unwrap();
    let snapshot = SnapshotV1::observed(TIME, vec![], routes(RouteStateV1::Absent)).unwrap();

    let first = evaluate_drift(&baseline, &snapshot).unwrap();
    let second = evaluate_drift(&baseline, &snapshot).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.status(), SnapshotStatusV1::Drifted);
    let finding = &first.findings()[0];
    assert_eq!(finding.code(), FindingCodeV1::DefaultRouteChanged);
    assert_eq!(finding.route_family(), Some(AddressFamilyV1::Ipv4));
    assert_eq!(finding.expected_route(), Some(RouteStateV1::Present));
    assert_eq!(finding.observed_route(), Some(RouteStateV1::Absent));
}

#[test]
fn missing_listener_and_clean_snapshot_are_distinct() {
    let baseline = BaselineV1::try_new(
        "host-one",
        vec![listener(443)],
        routes(RouteStateV1::Absent),
    )
    .unwrap();
    let missing = SnapshotV1::observed(TIME, Vec::new(), routes(RouteStateV1::Absent)).unwrap();
    let result = evaluate_drift(&baseline, &missing).unwrap();
    assert_eq!(
        result.findings()[0].code(),
        FindingCodeV1::ExpectedListenerMissing
    );

    let clean =
        SnapshotV1::observed(TIME, vec![listener(443)], routes(RouteStateV1::Absent)).unwrap();
    let result = evaluate_drift(&baseline, &clean).unwrap();
    assert_eq!(result.status(), SnapshotStatusV1::Observed);
    assert!(result.findings().is_empty());
    assert!(!result.external_actions());
}

#[path = "drift/unknown_source.rs"]
mod unknown_source;
