use std::collections::BTreeSet;

use crate::{
    AddressFamilyV1, BaselineV1, FindingCodeV1, FindingV1, SensorError, SnapshotStatusV1,
    SnapshotV1,
};

/// Purely compares a complete snapshot with an unsigned local baseline.
///
/// Unknown source state is preserved without inferring drift from partial data.
///
/// # Errors
///
/// Returns an error only if the bounded result contract cannot be constructed.
pub fn evaluate_drift(
    baseline: &BaselineV1,
    snapshot: &SnapshotV1,
) -> Result<SnapshotV1, SensorError> {
    if snapshot.status() == SnapshotStatusV1::Unknown {
        return Ok(snapshot.clone());
    }
    let expected = baseline
        .expected_listeners()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed = snapshot
        .listeners()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    findings.extend(
        observed
            .difference(&expected)
            .cloned()
            .map(|listener| FindingV1::listener(FindingCodeV1::UnexpectedListener, listener)),
    );
    findings.extend(
        expected
            .difference(&observed)
            .cloned()
            .map(|listener| FindingV1::listener(FindingCodeV1::ExpectedListenerMissing, listener)),
    );
    for family in [AddressFamilyV1::Ipv4, AddressFamilyV1::Ipv6] {
        let expected_route = baseline.expected_default_routes().get(family);
        let observed_route = snapshot.default_routes().get(family);
        if expected_route != observed_route {
            findings.push(FindingV1::route(family, expected_route, observed_route));
        }
    }
    snapshot.evaluated(findings)
}
