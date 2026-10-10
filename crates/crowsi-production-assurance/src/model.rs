use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{AssuranceContext, SignedEvidence};

/// Evidence categories are separate so one successful check cannot satisfy another.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    HardwareKeyAttestation,
    ManagementLifeline,
    ReleaseProvenance,
    Sbom,
    IsolationDrill,
    RecoveryDrill,
    IndependentReadback,
}

impl EvidenceKind {
    pub(crate) const fn expected_role(self) -> &'static str {
        match self {
            Self::HardwareKeyAttestation => "key-attestor",
            Self::ManagementLifeline => "network-owner",
            Self::ReleaseProvenance => "release-builder",
            Self::Sbom => "sbom-attestor",
            Self::IsolationDrill => "drill-observer",
            Self::RecoveryDrill => "recovery-observer",
            Self::IndependentReadback => "sensor-observer",
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::HardwareKeyAttestation => "hardware-key-attestation",
            Self::ManagementLifeline => "management-lifeline",
            Self::ReleaseProvenance => "release-provenance",
            Self::Sbom => "sbom",
            Self::IsolationDrill => "isolation-drill",
            Self::RecoveryDrill => "recovery-drill",
            Self::IndependentReadback => "independent-readback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOrigin {
    Hardware,
    AttestedService,
    Simulation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256Sha256Asn1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceControl {
    HardwareBacked,
    NonExportable,
    RoleScoped,
    AttestationChainVerified,
    OutsideBlastRadius,
    IndependentChannel,
    ArtifactDigestVerified,
    SourceRevisionBound,
    ReleaseSignatureVerified,
    SbomComplete,
    SbomDigestBound,
    DependencyReviewPassed,
    SecretScanPassed,
    DrillPassed,
    DrillEvidenceImmutable,
    TargetStateVerified,
    IndependentRecoveryAuthority,
    IndependentVantage,
    ReadbackSignatureVerified,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceControls {
    pub assertions: BTreeSet<AssuranceControl>,
    pub freshness_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePayload {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub origin: EvidenceOrigin,
    pub security_domain: String,
    pub deployment_id: String,
    pub asset_id: String,
    pub assurance_context_digest_sha256: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub subject_digest_sha256: String,
    pub controls: AssuranceControls,
}

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
