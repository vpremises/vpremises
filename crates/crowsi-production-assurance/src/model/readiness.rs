//! Readiness bundle and decision contracts for externally supplied evidence.
use super::{AssuranceContext, Deserialize, Serialize, SignedEvidence};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessBundle {
    pub schema: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub asset_id: String,
    pub assurance_context_digest_sha256: String,
    pub assurance_context: AssuranceContext,
    #[serde(rename = "hardware-key-attestation")]
    pub hardware_key_attestation: SignedEvidence,
    #[serde(rename = "management-lifeline")]
    pub management_lifeline: SignedEvidence,
    #[serde(rename = "release-provenance")]
    pub release_provenance: SignedEvidence,
    pub sbom: SignedEvidence,
    #[serde(rename = "isolation-drill")]
    pub isolation_drill: SignedEvidence,
    #[serde(rename = "recovery-drill")]
    pub recovery_drill: SignedEvidence,
    #[serde(rename = "independent-readback")]
    pub independent_readback: SignedEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessState {
    Ready,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessDecision {
    pub schema: &'static str,
    pub state: ReadinessState,
    pub finding_codes: Vec<String>,
    pub external_actions: bool,
}
