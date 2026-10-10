mod canonical;
mod validation;

use crowsi_control_contracts::SignedDigestV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCheckpointV1 {
    pub schema: String,
    pub checkpoint_id: String,
    pub jti: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub trust_bundle_digest: String,
    pub trust_revision: u64,
    pub sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub state_digest: String,
    pub command_digests: Vec<String>,
    pub issued_at: String,
    pub authority: String,
    pub signed: SignedDigestV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMonotonicAnchorV1 {
    pub schema: String,
    pub anchor_id: String,
    pub jti: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub challenge_nonce: String,
    pub sequence: u64,
    pub checkpoint_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub authority: String,
    pub signed: SignedDigestV1,
}
