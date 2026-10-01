//! CLI routing preserves JSON-only output and delegates all observation policy to the library.

mod file_input;
mod output;
mod report_request;
mod workspace;

#[cfg(test)]
mod tests;

use serde_json::{json, Value};
use std::{env, path::Path, process::ExitCode};
use vpremises::{acquire_mounted_sharepoint_report, observe};

pub(super) fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(value) => {
            output::emit(&value);
            ExitCode::SUCCESS
        }
        Err((code, value)) => {
            output::emit(&value);
            ExitCode::from(code)
        }
    }
}

fn run(arguments: &[String]) -> Result<Value, (u8, Value)> {
    match arguments {
        [command] if command == "doctor" => Ok(doctor()),
        [command, path] if command == "observe" => {
            let report = observe(&workspace::load_observer_config(Path::new(path))?);
            let ok = report.ok;
            let value = serde_json::to_value(report).expect("observation report serializes");
            if ok {
                Ok(value)
            } else {
                Err((2, value))
            }
        }
        [command, path] if command == "acquire-mounted-sharepoint-report" => {
            acquire_report(Path::new(path))
        }
        _ => Err((1, output::usage_error())),
    }
}

fn acquire_report(path: &Path) -> Result<Value, (u8, Value)> {
    let request = report_request::load(path)?;
    let root_base = report_request::resolve_root_base(path, request.allowlisted_root.base)?;
    acquire_mounted_sharepoint_report(&request, &root_base)
        .map(|receipt| serde_json::to_value(receipt).expect("receipt serializes"))
        .map_err(|error| {
            (
                2,
                json!({
                    "schema": "vpremises://errors/mounted-sharepoint-report/v1",
                    "ok": false,
                    "code": error.code,
                    "field": error.field,
                    "message": error.message,
                    "external_actions": false
                }),
            )
        })
}

fn doctor() -> Value {
    json!({
        "schema_version": "vpremises.doctor/v1",
        "healthy": true,
        "capabilities": {
            "metadata_only": true,
            "bounded_traversal": true,
            "symlink_following": false,
            "path_disclosure": false,
            "content_reading": false,
            "network_access": false
        }
    })
}
