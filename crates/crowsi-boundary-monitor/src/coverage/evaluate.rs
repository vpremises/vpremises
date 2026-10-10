use std::collections::BTreeSet;

use super::{
    COVERAGE_SNAPSHOT_SCHEMA, ControlAction, ControlAuthority, ControlCoverageInputV2,
    ControlCoverageSnapshotV2, CoverageAssetInputV2, CoverageAssetResultV2, CoverageState,
    EnforcerStatus, LifelineStatus, SensorStatus, ValidatedControlCoverageInputV2,
};
use crate::coverage::model::CoverageSummaryV2;

const REQUIRED_ACTIONS: [ControlAction; 4] = [
    ControlAction::RevokeCredentials,
    ControlAction::Quarantine,
    ControlAction::VerifyIsolation,
    ControlAction::Restore,
];

#[must_use]
pub fn evaluate_coverage(input: ValidatedControlCoverageInputV2) -> ControlCoverageSnapshotV2 {
    let input: ControlCoverageInputV2 = input.into_inner();
    let generated_at = input.generated_at_epoch_s;
    let assets = input
        .assets
        .into_iter()
        .map(|asset| evaluate_asset(asset, generated_at))
        .collect::<Vec<_>>();
    let controlled_count = assets
        .iter()
        .filter(|asset| asset.state == CoverageState::Controlled)
        .count();
    let overall_state = reduce_state(&assets);
    ControlCoverageSnapshotV2 {
        schema: COVERAGE_SNAPSHOT_SCHEMA.to_owned(),
        generated_at_epoch_s: generated_at,
        external_actions: false,
        overall_state,
        summary: CoverageSummaryV2 {
            asset_count: assets.len(),
            controlled_count,
            gap_count: assets.len() - controlled_count,
        },
        assets,
    }
}

fn evaluate_asset(asset: CoverageAssetInputV2, now: u64) -> CoverageAssetResultV2 {
    let mut findings = Vec::new();
    if asset.authority != ControlAuthority::Manage {
        findings.push("management-authority-missing".to_owned());
    }
    if asset.sensor_status != SensorStatus::Connected {
        findings.push("sensor-not-connected".to_owned());
    }
    if !fresh(asset.observed_at_epoch_s, asset.observation_ttl_s, now) {
        findings.push("observation-stale".to_owned());
    }
    if asset.enforcer_status != EnforcerStatus::Ready {
        findings.push("enforcer-not-ready".to_owned());
    }
    let actions = asset
        .supported_actions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if REQUIRED_ACTIONS
        .iter()
        .any(|action| !actions.contains(action))
    {
        findings.push("required-control-action-missing".to_owned());
    }
    if asset.lifeline_status != LifelineStatus::Verified {
        findings.push("management-lifeline-unverified".to_owned());
    }
    if !asset
        .last_drill_at_epoch_s
        .is_some_and(|at| fresh(at, asset.drill_ttl_s, now))
    {
        findings.push("isolation-drill-stale".to_owned());
    }
    let isolation_ready = findings.is_empty();
    let state = classify(&asset, isolation_ready);
    CoverageAssetResultV2 {
        id: asset.id,
        state,
        isolation_ready,
        finding_codes: findings,
    }
}

fn classify(asset: &CoverageAssetInputV2, ready: bool) -> CoverageState {
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

fn reduce_state(assets: &[CoverageAssetResultV2]) -> CoverageState {
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

fn fresh(observed_at: u64, ttl: u64, now: u64) -> bool {
    observed_at <= now && now - observed_at <= ttl
}
