use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use crowsi_production_assurance::ProductionAssurance;

#[test]
fn relative_state_path_is_rejected() {
    assert!(ProductionAssurance::open("relative.sqlite3").is_err());
}

#[test]
fn shared_writable_parent_is_rejected() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).expect("permissions");

    assert!(ProductionAssurance::open(root.path().join("clock.sqlite3")).is_err());
}

#[test]
fn insecure_existing_file_is_not_silently_repaired() {
    let root = tempfile::tempdir().expect("temporary root");
    let path = root.path().join("clock.sqlite3");
    fs::write(&path, []).expect("state file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");

    assert!(ProductionAssurance::open(&path).is_err());
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn symlinked_state_and_parent_are_rejected() {
    let root = tempfile::tempdir().expect("temporary root");
    let target = root.path().join("target.sqlite3");
    fs::write(&target, []).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("permissions");
    let link = root.path().join("state.sqlite3");
    symlink(&target, &link).expect("file symlink");
    assert!(ProductionAssurance::open(link).is_err());

    let parent = root.path().join("parent");
    let linked_parent = root.path().join("linked-parent");
    fs::create_dir(&parent).expect("parent");
    symlink(&parent, &linked_parent).expect("parent symlink");
    assert!(ProductionAssurance::open(linked_parent.join("clock.sqlite3")).is_err());
}

#[test]
fn malformed_existing_database_is_rejected() {
    let root = tempfile::tempdir().expect("temporary root");
    let path = root.path().join("clock.sqlite3");
    fs::write(&path, b"not sqlite").expect("malformed state");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");

    assert!(ProductionAssurance::open(path).is_err());
}
