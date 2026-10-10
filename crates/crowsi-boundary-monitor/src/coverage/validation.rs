use std::collections::{BTreeSet, HashSet};

use crate::MAX_DOCUMENT_BYTES;

use super::{COVERAGE_INPUT_SCHEMA, ControlCoverageInputV2};

const MAX_ASSETS: usize = 1_024;
const MAX_TTL_SECONDS: u64 = 2_592_000;

/// Structurally validated, but still unsigned, coverage input.
pub struct ValidatedControlCoverageInputV2(ControlCoverageInputV2);

impl ValidatedControlCoverageInputV2 {
    pub(crate) fn into_inner(self) -> ControlCoverageInputV2 {
        self.0
    }
}

/// Parses closed, metadata-only control coverage evidence.
///
/// # Errors
///
/// Returns a bounded validation error when the document is malformed or does
/// not satisfy the closed coverage contract.
pub fn parse_coverage_input(source: &[u8]) -> Result<ValidatedControlCoverageInputV2, String> {
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err("coverage input exceeds 131072 bytes".into());
    }
    let input: ControlCoverageInputV2 =
        serde_json::from_slice(source).map_err(|error| format!("invalid JSON: {error}"))?;
    validate_coverage_input(input)
}

/// Applies all structural checks before pure declared-state evaluation.
///
/// This does not authenticate the input. Consumers must verify provenance
/// independently and must not treat the resulting snapshot as signed evidence.
///
/// # Errors
///
/// Returns a bounded validation error for malformed contracts, duplicate
/// assets or actions, invalid identifiers, times, or TTLs.
pub fn validate_coverage_input(
    input: ControlCoverageInputV2,
) -> Result<ValidatedControlCoverageInputV2, String> {
    if input.schema != COVERAGE_INPUT_SCHEMA || input.external_actions {
        return Err("coverage contract or external action flag is invalid".into());
    }
    if input.generated_at_epoch_s == 0 || input.assets.is_empty() || input.assets.len() > MAX_ASSETS
    {
        return Err("coverage input needs a bounded asset set".into());
    }
    let mut ids = HashSet::new();
    for asset in &input.assets {
        let actions = asset
            .supported_actions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if !ids.insert(asset.id.as_str())
            || !safe_id(&asset.id)
            || actions.len() != asset.supported_actions.len()
            || asset.observed_at_epoch_s > input.generated_at_epoch_s
            || asset.last_drill_at_epoch_s > Some(input.generated_at_epoch_s)
            || !valid_ttl(asset.observation_ttl_s)
            || !valid_ttl(asset.drill_ttl_s)
        {
            return Err(format!("asset {} violates coverage bounds", asset.id));
        }
    }
    Ok(ValidatedControlCoverageInputV2(input))
}

fn valid_ttl(value: u64) -> bool {
    value > 0 && value <= MAX_TTL_SECONDS
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}
