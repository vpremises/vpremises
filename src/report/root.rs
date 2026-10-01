//! The allowlisted root must stay beneath its explicit base with no symlinked prefix.

use crate::{
    model::{ReportAcquisitionError, ReportAllowedRoot},
    report::error,
    MAX_RELATIVE_COMPONENTS, MAX_RELATIVE_FILE_BYTES,
};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub(super) fn validate(
    root: &ReportAllowedRoot,
    resolved_base: &Path,
) -> Result<PathBuf, ReportAcquisitionError> {
    validate_base(resolved_base)?;
    let relative_root = validate_relative(&root.relative_path)?;
    reject_symlinked_prefix(resolved_base)?;
    let canonical_base = resolved_base.canonicalize().map_err(|_| {
        error::create(
            "vpremises.report.root-base-unavailable",
            "$.allowlisted_root.base",
            "the resolved root base is unavailable",
        )
    })?;
    let root_path = canonical_base.join(relative_root);
    reject_symlinked_prefix(&root_path)?;
    let metadata = fs::symlink_metadata(&root_path).map_err(|_| {
        error::create(
            "vpremises.report.root-unavailable",
            "$.allowlisted_root.relative_path",
            "the allowlisted root is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(error::create(
            "vpremises.report.root-invalid",
            "$.allowlisted_root.relative_path",
            "the allowlisted root must be a regular directory and not a symbolic link",
        ));
    }
    let canonical = root_path.canonicalize().map_err(|_| {
        error::create(
            "vpremises.report.root-unavailable",
            "$.allowlisted_root.relative_path",
            "the allowlisted root could not be resolved",
        )
    })?;
    if canonical == Path::new("/") || !canonical.starts_with(&canonical_base) {
        return Err(error::create(
            "vpremises.report.root-invalid",
            "$.allowlisted_root.relative_path",
            "the allowlisted root must remain below its resolved base",
        ));
    }
    Ok(canonical)
}

fn validate_base(path: &Path) -> Result<(), ReportAcquisitionError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(error::create(
            "vpremises.report.root-base-invalid",
            "$.allowlisted_root.base",
            "the resolved root base must be an absolute non-system path",
        ));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<&Path, ReportAcquisitionError> {
    let count = path.components().count();
    let portable = path.to_str().is_some_and(|value| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    });
    if path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_RELATIVE_FILE_BYTES
        || !portable
        || path.is_absolute()
        || count == 0
        || count > MAX_RELATIVE_COMPONENTS
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(error::create(
            "vpremises.report.root-relative-path-invalid",
            "$.allowlisted_root.relative_path",
            "relative_path must be a bounded relative path without traversal",
        ));
    }
    Ok(path)
}

fn reject_symlinked_prefix(path: &Path) -> Result<(), ReportAcquisitionError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if let Component::Normal(name) = component {
            current.push(name);
            let metadata = fs::symlink_metadata(&current).map_err(|_| {
                error::create(
                    "vpremises.report.root-unavailable",
                    "$.allowlisted_root.relative_path",
                    "an allowlisted root path component is unavailable",
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(error::create(
                    "vpremises.report.root-invalid",
                    "$.allowlisted_root.relative_path",
                    "symbolic links are forbidden in the allowlisted root path",
                ));
            }
        }
    }
    Ok(())
}
