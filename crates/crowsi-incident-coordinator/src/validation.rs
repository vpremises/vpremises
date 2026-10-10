use crowsi_control_contracts::ActionBindingV1;

use crate::{CoordinatorError, time::normalized_utc};

pub trait Validate {
    /// Validates a closed incident coordination contract.
    ///
    /// # Errors
    ///
    /// Returns the first stable field-level error.
    fn validate(&self) -> Result<(), CoordinatorError>;
}

pub(crate) fn schema(actual: &str, expected: &'static str) -> Result<(), CoordinatorError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CoordinatorError::new("schema", "unsupported schema"))
    }
}

pub(crate) fn identifier(field: &'static str, value: &str) -> Result<(), CoordinatorError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        });
    if valid {
        Ok(())
    } else {
        Err(CoordinatorError::new(field, "must be a closed identifier"))
    }
}

pub(crate) fn opaque(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), CoordinatorError> {
    if !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(CoordinatorError::new(field, "must be bounded opaque text"))
    }
}

pub(crate) fn https_uri(field: &'static str, value: &str) -> Result<(), CoordinatorError> {
    opaque(field, value, 512)?;
    if value.starts_with("https://") {
        Ok(())
    } else {
        Err(CoordinatorError::new(field, "must be an HTTPS URI"))
    }
}

pub(crate) fn timestamp(field: &'static str, value: &str) -> Result<(), CoordinatorError> {
    if normalized_utc(value) {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            field,
            "must use normalized UTC milliseconds",
        ))
    }
}

pub(crate) fn digest(field: &'static str, value: &str) -> Result<(), CoordinatorError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            field,
            "must be a lowercase SHA-256 digest",
        ))
    }
}

pub(crate) fn binding(target_id: &str, value: &ActionBindingV1) -> Result<(), CoordinatorError> {
    crowsi_control_contracts::Validate::validate(value)?;
    if value.resource == target_id {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "binding.resource",
            "must equal the target",
        ))
    }
}
