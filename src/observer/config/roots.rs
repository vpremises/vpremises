//! Allowed roots must resolve to unique, non-overlapping directories below the system root.

use crate::{
    model::{AllowedRoot, Diagnostic},
    observer::{diagnostic, ValidatedRoot},
    validation::valid_identifier,
};
use std::{collections::BTreeSet, fs, path::Path};

pub(super) fn validate(
    roots: &[AllowedRoot],
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<ValidatedRoot> {
    let mut ids = BTreeSet::new();
    let mut validated = Vec::new();
    for root in roots {
        validate_identity(root, &mut ids, diagnostics);
        let Some(canonical_path) = resolve(root, diagnostics) else {
            continue;
        };
        validated.push(ValidatedRoot {
            id: root.id.clone(),
            canonical_path,
        });
    }
    validated
}

pub(super) fn reject_overlaps(roots: &mut [ValidatedRoot], diagnostics: &mut Vec<Diagnostic>) {
    for left_index in 0..roots.len() {
        for right_index in (left_index + 1)..roots.len() {
            let left = &roots[left_index];
            let right = &roots[right_index];
            if left.canonical_path.starts_with(&right.canonical_path)
                || right.canonical_path.starts_with(&left.canonical_path)
            {
                diagnostics.push(diagnostic::create(
                    "vpremises.root.overlap",
                    Some(&left.id),
                    "$.roots",
                    format!("allowed roots '{}' and '{}' overlap", left.id, right.id),
                ));
            }
        }
    }
}

fn validate_identity(
    root: &AllowedRoot,
    ids: &mut BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !valid_identifier(&root.id) {
        diagnostics.push(diagnostic::create(
            "vpremises.root.invalid-id",
            Some(&root.id),
            "$.roots[].id",
            "root id must contain only lowercase ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    if !ids.insert(root.id.clone()) {
        diagnostics.push(diagnostic::create(
            "vpremises.root.duplicate-id",
            Some(&root.id),
            "$.roots[].id",
            "root ids must be unique",
        ));
    }
}

fn resolve(root: &AllowedRoot, diagnostics: &mut Vec<Diagnostic>) -> Option<std::path::PathBuf> {
    if !root.path.is_absolute() {
        diagnostics.push(diagnostic::create(
            "vpremises.root.not-absolute",
            Some(&root.id),
            "$.roots[].path",
            "allowed root must be an absolute path",
        ));
        return None;
    }
    let metadata = fs::symlink_metadata(&root.path)
        .map_err(|error| {
            diagnostics.push(diagnostic::io(
                "vpremises.root.unavailable",
                &root.id,
                "$.roots[].path",
                &error,
            ));
        })
        .ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        let (code, message) = if metadata.file_type().is_symlink() {
            (
                "vpremises.root.symlink-forbidden",
                "an allowed root cannot itself be a symlink",
            )
        } else {
            (
                "vpremises.root.not-directory",
                "an allowed root must be a directory",
            )
        };
        diagnostics.push(diagnostic::create(
            code,
            Some(&root.id),
            "$.roots[].path",
            message,
        ));
        return None;
    }
    let canonical = root
        .path
        .canonicalize()
        .map_err(|error| {
            diagnostics.push(diagnostic::io(
                "vpremises.root.canonicalize-failed",
                &root.id,
                "$.roots[].path",
                &error,
            ));
        })
        .ok()?;
    if canonical == Path::new("/") {
        diagnostics.push(diagnostic::create(
            "vpremises.root.system-root-forbidden",
            Some(&root.id),
            "$.roots[].path",
            "observing the filesystem root is forbidden",
        ));
        None
    } else {
        Some(canonical)
    }
}
