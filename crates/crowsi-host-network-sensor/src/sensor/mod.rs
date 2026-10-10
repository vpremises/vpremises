mod read;
mod route;
mod socket;

use std::collections::BTreeSet;

use crate::validation::MAX_LISTENERS;
use crate::{
    AddressFamilyV1, FindingCodeV1, ProtocolV1, RouteStateV1, RoutesV1, SensorError, SnapshotV1,
};
use read::{SourceFailure, Sources};

/// Observes only six fixed Linux procfs files in the current network namespace.
///
/// Source failures become an unsigned `unknown` snapshot, never a partial success.
///
/// # Errors
///
/// Rejects an invalid caller-supplied timestamp or an impossible result contract.
pub fn observe_host(generated_at: &str) -> Result<SnapshotV1, SensorError> {
    match read::fixed_sources() {
        Ok(sources) => observe_sources(&sources, generated_at),
        Err(failure) => unknown(generated_at, failure),
    }
}

fn observe_sources(sources: &Sources, generated_at: &str) -> Result<SnapshotV1, SensorError> {
    let result = parse_sources(sources);
    match result {
        Ok((listeners, routes)) => {
            SnapshotV1::observed(generated_at, listeners.into_iter().collect(), routes)
        }
        Err(failure) => unknown(generated_at, failure),
    }
}

fn parse_sources(
    sources: &Sources,
) -> Result<(BTreeSet<crate::ListenerV1>, RoutesV1), SourceFailure> {
    let mut listeners = BTreeSet::new();
    for (source, protocol, family) in [
        (&sources.tcp, ProtocolV1::Tcp, AddressFamilyV1::Ipv4),
        (&sources.tcp6, ProtocolV1::Tcp, AddressFamilyV1::Ipv6),
        (&sources.udp, ProtocolV1::Udp, AddressFamilyV1::Ipv4),
        (&sources.udp6, ProtocolV1::Udp, AddressFamilyV1::Ipv6),
    ] {
        listeners.extend(socket::parse(source, protocol, family)?);
        if listeners.len() > MAX_LISTENERS {
            return Err(SourceFailure::Invalid);
        }
    }
    let ipv4 = route::parse_ipv4(&sources.route)?;
    let ipv6 = route::parse_ipv6(&sources.ipv6_route)?;
    Ok((
        listeners,
        RoutesV1::new(
            if ipv4 {
                RouteStateV1::Present
            } else {
                RouteStateV1::Absent
            },
            if ipv6 {
                RouteStateV1::Present
            } else {
                RouteStateV1::Absent
            },
        ),
    ))
}

fn unknown(generated_at: &str, failure: SourceFailure) -> Result<SnapshotV1, SensorError> {
    let code = match failure {
        SourceFailure::Unavailable => FindingCodeV1::SourceUnavailable,
        SourceFailure::Invalid => FindingCodeV1::SourceParseFailure,
    };
    SnapshotV1::unknown(generated_at, code)
}

#[cfg(test)]
mod tests {
    use super::{SourceFailure, observe_sources, read::Sources, unknown};
    use crate::{FindingCodeV1, SnapshotStatusV1};

    #[test]
    fn parse_failure_discards_partial_data_and_becomes_unknown() {
        let mut sources = Sources::minimal();
        sources.tcp = "malformed".to_owned();
        let snapshot = observe_sources(&sources, "2026-08-01T00:00:00.000Z").unwrap();
        assert_eq!(snapshot.status(), SnapshotStatusV1::Unknown);
        assert!(snapshot.listeners().is_empty());
        assert_eq!(
            snapshot.findings()[0].code(),
            FindingCodeV1::SourceParseFailure
        );
    }

    #[test]
    fn unavailable_source_is_a_safe_unknown_code() {
        let snapshot = unknown("2026-08-01T00:00:00.000Z", SourceFailure::Unavailable).unwrap();
        assert_eq!(snapshot.status(), SnapshotStatusV1::Unknown);
        assert_eq!(
            snapshot.findings()[0].code(),
            FindingCodeV1::SourceUnavailable
        );
    }
}
