//! Observation contracts disclose aggregate metadata and never filesystem names or paths.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Closed policy, root allowlist, and global traversal limits.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObserverConfig {
    pub schema_version: String,
    pub roots: Vec<AllowedRoot>,
    pub limits: ObservationLimits,
    pub policy: ObservationPolicy,
}

/// One explicitly allowed observation root.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowedRoot {
    pub id: String,
    pub path: PathBuf,
}

/// Global traversal ceilings shared by every configured root.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationLimits {
    pub max_depth: u32,
    pub max_entries: u64,
    pub max_total_bytes: u64,
}

/// Mandatory metadata-only and no-follow policy.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationPolicy {
    pub metadata_only: bool,
    pub follow_symlinks: bool,
}

/// Machine-readable observer validation or traversal finding.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: String,
    pub root_id: Option<String>,
    pub field: String,
    pub message: String,
}

/// Aggregate-only result for one observation attempt.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ObservationReport {
    pub schema_version: &'static str,
    pub ok: bool,
    pub policy: ReportedPolicy,
    pub totals: ObservationTotals,
    pub roots: Vec<RootObservation>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Effective disclosure policy recorded in every result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportedPolicy {
    pub access_mode: &'static str,
    pub disclosure: &'static str,
    pub symlink_policy: &'static str,
}

/// Aggregate metadata counters that disclose no entry names.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ObservationTotals {
    pub entries_examined: u64,
    pub directories: u64,
    pub files: u64,
    pub symlinks_skipped: u64,
    pub other_entries: u64,
    pub total_file_bytes: u64,
    pub max_depth_reached: u32,
}

/// Completion state and counters for one opaque root ID.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RootObservation {
    pub root_id: String,
    pub complete: bool,
    pub totals: ObservationTotals,
}
