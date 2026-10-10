use serde::{Deserialize, Serialize};

/// Immutable identifiers and digests shared by all evidence authorities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceContext {
    pub schema: String,
    pub hardware_key_attestation_id: String,
    pub hardware_key_attestation_digest_sha256: String,
    pub management_lifeline_id: String,
    pub management_lifeline_digest_sha256: String,
    pub release_id: String,
    pub release_digest_sha256: String,
    pub sbom_id: String,
    pub sbom_digest_sha256: String,
    pub command_id: String,
    pub command_digest_sha256: String,
    pub fence_epoch: u64,
    pub isolation_drill_id: String,
    pub isolation_drill_digest_sha256: String,
    pub recovery_drill_id: String,
    pub recovery_drill_digest_sha256: String,
    pub readback_id: String,
    pub readback_digest_sha256: String,
}
