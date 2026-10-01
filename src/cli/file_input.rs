//! CLI documents are bounded and opened without following a final symlink.

use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn read_utf8(path: &Path, maximum: u64) -> Result<String, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "file is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err("file must be a bounded regular non-symlink file");
    }
    let file = open_no_follow(path)?;
    let metadata = file.metadata().map_err(|_| "opened file is unavailable")?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err("opened file exceeds its regular-file boundary");
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "file could not be read")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err("file exceeds its byte boundary");
    }
    String::from_utf8(bytes).map_err(|_| "file must contain UTF-8")
}

#[cfg(target_os = "linux")]
fn open_no_follow(path: &Path) -> Result<File, &'static str> {
    const O_NOFOLLOW: i32 = 0o400_000;
    const O_NONBLOCK: i32 = 0o4_000;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .map_err(|_| "file could not be opened without following links")
}

#[cfg(not(target_os = "linux"))]
fn open_no_follow(path: &Path) -> Result<File, &'static str> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| "file could not be opened")
}
