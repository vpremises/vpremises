use std::{
    fs::{self, OpenOptions},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use nix::unistd::Uid;

use crate::AssuranceError;

pub(crate) fn prepare_file(path: &Path) -> Result<bool, AssuranceError> {
    let owner = Uid::effective().as_raw();
    validate_parent(path, owner)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => secure_file(&metadata, owner)
            .then_some(true)
            .ok_or(AssuranceError::StateUnavailable),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| AssuranceError::StateUnavailable)?;
            let metadata =
                fs::symlink_metadata(path).map_err(|_| AssuranceError::StateUnavailable)?;
            secure_file(&metadata, owner)
                .then_some(false)
                .ok_or(AssuranceError::StateUnavailable)
        }
        Err(_) => Err(AssuranceError::StateUnavailable),
    }
}

fn validate_parent(path: &Path, owner: u32) -> Result<(), AssuranceError> {
    if !path.is_absolute() {
        return Err(AssuranceError::StateUnavailable);
    }
    let parent = path.parent().ok_or(AssuranceError::StateUnavailable)?;
    let canonical = fs::canonicalize(parent).map_err(|_| AssuranceError::StateUnavailable)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| AssuranceError::StateUnavailable)?;
    if canonical != parent
        || !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(AssuranceError::StateUnavailable);
    }
    Ok(())
}

fn secure_file(metadata: &fs::Metadata, owner: u32) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == owner
        && metadata.permissions().mode() & 0o777 == 0o600
}
