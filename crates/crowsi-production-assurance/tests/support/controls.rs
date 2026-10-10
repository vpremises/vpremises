use crowsi_production_assurance::{AssuranceControl, AssuranceControls, EvidenceKind};

pub(super) fn controls(kind: EvidenceKind) -> AssuranceControls {
    let mut value = AssuranceControls::default();
    let mut add = |control| {
        value.assertions.insert(control);
    };
    match kind {
        EvidenceKind::HardwareKeyAttestation => {
            add(AssuranceControl::HardwareBacked);
            add(AssuranceControl::NonExportable);
            add(AssuranceControl::RoleScoped);
            add(AssuranceControl::AttestationChainVerified);
        }
        EvidenceKind::ManagementLifeline => {
            add(AssuranceControl::OutsideBlastRadius);
            add(AssuranceControl::IndependentChannel);
            add(AssuranceControl::TargetStateVerified);
        }
        EvidenceKind::ReleaseProvenance => {
            add(AssuranceControl::ArtifactDigestVerified);
            add(AssuranceControl::SourceRevisionBound);
            add(AssuranceControl::SecretScanPassed);
            add(AssuranceControl::ReleaseSignatureVerified);
        }
        EvidenceKind::Sbom => {
            add(AssuranceControl::SbomComplete);
            add(AssuranceControl::SbomDigestBound);
            add(AssuranceControl::DependencyReviewPassed);
        }
        EvidenceKind::IsolationDrill => {
            add(AssuranceControl::DrillPassed);
            add(AssuranceControl::DrillEvidenceImmutable);
            add(AssuranceControl::TargetStateVerified);
            add(AssuranceControl::IndependentVantage);
        }
        EvidenceKind::RecoveryDrill => {
            add(AssuranceControl::DrillPassed);
            add(AssuranceControl::DrillEvidenceImmutable);
            add(AssuranceControl::TargetStateVerified);
            add(AssuranceControl::IndependentRecoveryAuthority);
        }
        EvidenceKind::IndependentReadback => {
            add(AssuranceControl::TargetStateVerified);
            add(AssuranceControl::IndependentVantage);
            add(AssuranceControl::ReadbackSignatureVerified);
            value.freshness_seconds = 15;
        }
    }
    value
}
