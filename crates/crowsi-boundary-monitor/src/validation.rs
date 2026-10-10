use crate::model::{BoundaryInputV1, INPUT_SCHEMA};
use std::collections::HashSet;

pub const MAX_DOCUMENT_BYTES: usize = 131_072;
const MAX_ENVIRONMENTS: usize = 64;

/// Parses one closed boundary observation document.
///
/// # Errors
///
/// Returns an error for oversized, malformed, externally acting, duplicated,
/// or vocabulary-widening input.
pub fn parse_input(source: &[u8]) -> Result<BoundaryInputV1, String> {
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err("boundary input exceeds 131072 bytes".into());
    }
    let input: BoundaryInputV1 =
        serde_json::from_slice(source).map_err(|error| format!("invalid JSON: {error}"))?;
    validate(&input)?;
    Ok(input)
}

fn validate(input: &BoundaryInputV1) -> Result<(), String> {
    if input.schema != INPUT_SCHEMA || input.external_actions {
        return Err("boundary input contract or external action flag is invalid".into());
    }
    if input.generated_at.is_empty()
        || input.environments.is_empty()
        || input.environments.len() > MAX_ENVIRONMENTS
    {
        return Err("boundary input needs a bounded observation set".into());
    }
    let mut ids = HashSet::new();
    for environment in &input.environments {
        if !ids.insert(environment.id.as_str())
            || !safe_id(&environment.id)
            || !safe_id(&environment.provider)
            || !safe_id(&environment.source)
            || !safe_id(&environment.status)
            || !safe_id(&environment.isolation_mode)
            || !safe_id(&environment.expected_isolation_mode)
            || environment.label.is_empty()
            || environment.label.chars().count() > 128
            || environment.label.chars().any(char::is_control)
        {
            return Err(format!(
                "environment {} violates the boundary vocabulary",
                environment.id
            ));
        }
    }
    Ok(())
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}
