//! npm publication requires explicit registry routes and packaged entry points.
use super::OssReport;
use serde_json::Value;

pub(super) fn npm(value: &Value, report: &mut OssReport) {
    if value["private"].as_bool() == Some(true) {
        report.finding("npm-private-package", "private");
    }
    if value["publishConfig"]["registry"] != "https://registry.npmjs.org" {
        report.finding("npm-official-registry-required", "publishConfig/registry");
    }
    if value["files"].as_array().is_none_or(Vec::is_empty) {
        report.finding("npm-files-allowlist-required", "files");
    }
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(object) = value.get(section) else {
            continue;
        };
        let Some(object) = object.as_object() else {
            report.gap("dependency-section-invalid", section);
            continue;
        };
        for (name, v) in object {
            if v.as_str().is_none_or(|s| {
                [
                    "file:",
                    "link:",
                    "workspace:",
                    "git",
                    "http:",
                    "https:",
                    "/",
                    ".",
                ]
                .iter()
                .any(|p| s.starts_with(p))
            }) {
                report.finding("npm-nonregistry-dependency", &format!("{section}/{name}"));
            }
        }
    }
}
