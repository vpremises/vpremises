use crate::{
    AddressFamilyV1, BaselineV1, BindScopeV1, ListenerV1, ProtocolV1, RouteStateV1, RoutesV1,
    SensorError, SnapshotV1,
};

pub const SAMPLE_TIME: &str = "2026-08-01T00:00:00.000Z";

/// Returns the deterministic checked-in baseline example.
///
/// # Errors
///
/// Fails only if static example constants violate the executable contract.
pub fn sample_baseline() -> Result<BaselineV1, SensorError> {
    BaselineV1::try_new(
        "sample-local-host",
        sample_listeners()?,
        RoutesV1::new(RouteStateV1::Present, RouteStateV1::Absent),
    )
}

/// Returns the deterministic checked-in snapshot example.
///
/// # Errors
///
/// Fails only if static example constants violate the executable contract.
pub fn sample_snapshot() -> Result<SnapshotV1, SensorError> {
    SnapshotV1::observed(
        SAMPLE_TIME,
        sample_listeners()?,
        RoutesV1::new(RouteStateV1::Present, RouteStateV1::Absent),
    )
}

fn sample_listeners() -> Result<Vec<ListenerV1>, SensorError> {
    Ok(vec![
        ListenerV1::new(
            ProtocolV1::Tcp,
            AddressFamilyV1::Ipv4,
            8_443,
            BindScopeV1::Wildcard,
        )?,
        ListenerV1::new(
            ProtocolV1::Udp,
            AddressFamilyV1::Ipv6,
            5_353,
            BindScopeV1::Loopback,
        )?,
    ])
}
