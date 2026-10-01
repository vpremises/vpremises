//! CLI failures remain structured and avoid leaking provider paths through stderr.

use serde::Serialize;
use serde_json::{json, Value};

pub(super) fn emit<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("command output serializes")
    );
}

pub(super) fn report_request_error(code: &str, message: &str) -> Value {
    json!({
        "schema": "vpremises://errors/mounted-sharepoint-report/v1",
        "ok": false,
        "code": code,
        "message": message,
        "external_actions": false
    })
}

pub(super) fn usage_error() -> Value {
    json!({
        "schema_version": "vpremises.error/v1",
        "ok": false,
        "code": "vpremises.cli.usage",
        "message": "usage: vpremises doctor | observe <config.json> | acquire-mounted-sharepoint-report <request.json>"
    })
}
