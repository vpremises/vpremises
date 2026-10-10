//! Repository policy checks inspect names and line counts, never source secrets.

use std::{fs, path::Path};

/// Check every maintained Rust file, including untracked local additions.
pub fn check_tree(root: &Path) {
    for entry in fs::read_dir(root).expect("maintained source directory") {
        let entry = entry.expect("source entry");
        let kind = entry.file_type().expect("source type");
        assert!(!kind.is_symlink(), "maintained sources cannot be symlinks");
        if kind.is_dir() {
            if ["target", "dist", "node_modules", ".git"]
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                continue;
            }
            check_tree(&entry.path());
        } else if entry.path().extension().is_some_and(|value| value == "rs") {
            let source = fs::read_to_string(entry.path()).expect("UTF-8 Rust source");
            assert!(
                source.lines().count() <= 120,
                "Rust source exceeds 120 lines: {}",
                entry.path().display()
            );
            assert!(
                source.is_ascii(),
                "Rust source comments and fixtures must be English ASCII"
            );
        }
    }
}

/// Reject local state, Python helpers and generated files in the Git inventory.
pub fn check_tracked(name: &str) {
    let first = name.split('/').next().expect("file component");
    let forbidden_root = [
        "target",
        "state",
        "registration",
        "secrets",
        "credentials",
        "dist",
        "build",
    ];
    let forbidden_suffix = [".py", ".pyc", ".zip", ".crate", ".tgz", ".sqlite", ".log"];
    assert!(!forbidden_root.contains(&first), "local state is tracked");
    assert!(
        !forbidden_suffix.iter().any(|suffix| name.ends_with(suffix)),
        "generated or unsupported file is tracked"
    );
}
