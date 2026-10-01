//! Traversal rechecks canonical ancestry and accounts entries without exposing their names.

mod totals;

use crate::{
    model::{Diagnostic, ObservationLimits, ObservationTotals},
    observer::{diagnostic, ValidatedRoot},
};
use std::fs;
use totals::EntryKind;

pub(super) fn root(
    root: &ValidatedRoot,
    limits: &ObservationLimits,
    global: &mut ObservationTotals,
    local: &mut ObservationTotals,
) -> Result<(), Diagnostic> {
    totals::account(root, limits, global, local, EntryKind::Directory, 0, 0)?;
    let mut pending = vec![(root.canonical_path.clone(), 0_u32)];
    while let Some((directory, depth)) = pending.pop() {
        let canonical = directory.canonicalize().map_err(|error| {
            diagnostic::io(
                "vpremises.scan.canonicalize-failed",
                &root.id,
                "observation",
                &error,
            )
        })?;
        require_beneath(root, &canonical)?;
        let entries = fs::read_dir(&canonical).map_err(|error| {
            diagnostic::io(
                "vpremises.scan.read-directory-failed",
                &root.id,
                "observation",
                &error,
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                diagnostic::io(
                    "vpremises.scan.read-entry-failed",
                    &root.id,
                    "observation",
                    &error,
                )
            })?;
            inspect_entry(
                root,
                limits,
                global,
                local,
                &mut pending,
                &entry.path(),
                depth + 1,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inspect_entry(
    root: &ValidatedRoot,
    limits: &ObservationLimits,
    global: &mut ObservationTotals,
    local: &mut ObservationTotals,
    pending: &mut Vec<(std::path::PathBuf, u32)>,
    path: &std::path::Path,
    depth: u32,
) -> Result<(), Diagnostic> {
    if depth > limits.max_depth {
        return Err(diagnostic::create(
            "vpremises.limit.depth-exceeded",
            Some(&root.id),
            "observation",
            "max_depth was exceeded",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        diagnostic::io(
            "vpremises.scan.metadata-failed",
            &root.id,
            "observation",
            &error,
        )
    })?;
    let file_type = metadata.file_type();
    let (kind, bytes) = if file_type.is_symlink() {
        (EntryKind::Symlink, 0)
    } else if file_type.is_dir() {
        let canonical = path.canonicalize().map_err(|error| {
            diagnostic::io(
                "vpremises.scan.canonicalize-failed",
                &root.id,
                "observation",
                &error,
            )
        })?;
        require_beneath(root, &canonical)?;
        pending.push((canonical, depth));
        (EntryKind::Directory, 0)
    } else if file_type.is_file() {
        (EntryKind::File, metadata.len())
    } else {
        (EntryKind::Other, 0)
    };
    totals::account(root, limits, global, local, kind, depth, bytes)
}

fn require_beneath(root: &ValidatedRoot, canonical: &std::path::Path) -> Result<(), Diagnostic> {
    if canonical.starts_with(&root.canonical_path) {
        Ok(())
    } else {
        Err(diagnostic::create(
            "vpremises.scan.boundary-escape",
            Some(&root.id),
            "observation",
            "a traversed directory escaped its allowed root",
        ))
    }
}
