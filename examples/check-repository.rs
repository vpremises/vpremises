//! Enforce source hygiene without a Python runtime or third-party policy service.

#[path = "policy/files.rs"]
mod files;

use std::{fs, process::Command};

fn main() {
    for path in [
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
    ] {
        assert!(
            fs::metadata(path).is_ok(),
            "required OSS document is missing"
        );
    }
    files::check_tree(std::path::Path::new("src"));
    files::check_tree(std::path::Path::new("tests"));
    files::check_tree(std::path::Path::new("examples"));
    files::check_tree(std::path::Path::new("crates"));
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .output()
        .expect("Git file inventory");
    assert!(output.status.success(), "Git file inventory failed");
    let names = String::from_utf8(output.stdout).expect("UTF-8 tracked file names");
    for name in names.split('\0').filter(|name| !name.is_empty()) {
        if std::path::Path::new(name).exists() {
            files::check_tracked(name);
        }
    }
    println!("OSS files, tracked-file hygiene and Rust source limits passed.");
}
