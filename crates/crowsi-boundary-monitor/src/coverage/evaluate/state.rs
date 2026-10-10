//! Classify bounded isolation observations without changing host policy.
use super::{
    ControlAuthority, CoverageAssetInputV2, CoverageAssetResultV2, CoverageState, SensorStatus,
};

pub(in crate::coverage::evaluate) fn classify(
    asset: &CoverageAssetInputV2,
    ready: bool,
) -> CoverageState {
    if ready {
        CoverageState::Controlled
    } else if asset.authority != ControlAuthority::Manage {
        CoverageState::Unmanaged
    } else if asset.sensor_status == SensorStatus::Unknown {
        CoverageState::Unknown
    } else {
        CoverageState::Partial
    }
}

pub(in crate::coverage::evaluate) fn reduce_state(
    assets: &[CoverageAssetResultV2],
) -> CoverageState {
    if assets.is_empty() {
        CoverageState::Unknown
    } else if assets
        .iter()
        .all(|asset| asset.state == CoverageState::Controlled)
    {
        CoverageState::Controlled
    } else if assets
        .iter()
        .any(|asset| asset.state == CoverageState::Unmanaged)
    {
        CoverageState::Unmanaged
    } else if assets
        .iter()
        .any(|asset| asset.state == CoverageState::Unknown)
    {
        CoverageState::Unknown
    } else {
        CoverageState::Partial
    }
}

pub(in crate::coverage::evaluate) fn fresh(observed_at: u64, ttl: u64, now: u64) -> bool {
    observed_at <= now && now - observed_at <= ttl
}
