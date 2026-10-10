use crate::{AssuranceControl, AssuranceControls, EvidenceKind, EvidenceOrigin};

pub(crate) fn satisfy(
    kind: EvidenceKind,
    origin: EvidenceOrigin,
    value: &AssuranceControls,
) -> bool {
    let has = |control| value.assertions.contains(&control);
    match kind {
        EvidenceKind::HardwareKeyAttestation => {
            origin == EvidenceOrigin::Hardware
                && has(AssuranceControl::HardwareBacked)
                && has(AssuranceControl::NonExportable)
                && has(AssuranceControl::RoleScoped)
                && has(AssuranceControl::AttestationChainVerified)
        }
        EvidenceKind::ManagementLifeline => {
            has(AssuranceControl::OutsideBlastRadius)
                && has(AssuranceControl::IndependentChannel)
                && has(AssuranceControl::TargetStateVerified)
        }
        EvidenceKind::ReleaseProvenance => {
            has(AssuranceControl::ArtifactDigestVerified)
                && has(AssuranceControl::SourceRevisionBound)
                && has(AssuranceControl::SecretScanPassed)
                && has(AssuranceControl::ReleaseSignatureVerified)
        }
        EvidenceKind::Sbom => {
            has(AssuranceControl::SbomComplete)
                && has(AssuranceControl::SbomDigestBound)
                && has(AssuranceControl::DependencyReviewPassed)
        }
        EvidenceKind::IsolationDrill => {
            has(AssuranceControl::DrillPassed)
                && has(AssuranceControl::DrillEvidenceImmutable)
                && has(AssuranceControl::TargetStateVerified)
                && has(AssuranceControl::IndependentVantage)
        }
        EvidenceKind::RecoveryDrill => {
            has(AssuranceControl::DrillPassed)
                && has(AssuranceControl::DrillEvidenceImmutable)
                && has(AssuranceControl::TargetStateVerified)
                && has(AssuranceControl::IndependentRecoveryAuthority)
        }
        EvidenceKind::IndependentReadback => {
            has(AssuranceControl::TargetStateVerified)
                && has(AssuranceControl::IndependentVantage)
                && has(AssuranceControl::ReadbackSignatureVerified)
                && (1..=30).contains(&value.freshness_seconds)
        }
    }
}
