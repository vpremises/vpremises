use sha2::{Digest, Sha256};

use crate::{AssuranceControl, EvidenceKind, EvidenceOrigin, EvidencePayload};

impl EvidencePayload {
    /// Returns the versioned binary digest signed by an evidence authority.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"CROWSI-PRODUCTION-EVIDENCE-V1\0".to_vec();
        push_text(&mut bytes, &self.evidence_id);
        bytes.push(kind_tag(self.kind));
        bytes.push(origin_tag(self.origin));
        push_text(&mut bytes, &self.security_domain);
        push_text(&mut bytes, &self.deployment_id);
        push_text(&mut bytes, &self.asset_id);
        push_text(&mut bytes, &self.assurance_context_digest_sha256);
        bytes.extend_from_slice(&self.issued_at_epoch_s.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_epoch_s.to_be_bytes());
        push_text(&mut bytes, &self.subject_digest_sha256);
        bytes.extend_from_slice(&(self.controls.assertions.len() as u64).to_be_bytes());
        for assertion in &self.controls.assertions {
            bytes.push(control_tag(*assertion));
        }
        bytes.extend_from_slice(&self.controls.freshness_seconds.to_be_bytes());
        Sha256::digest(bytes).to_vec()
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

const fn kind_tag(value: EvidenceKind) -> u8 {
    match value {
        EvidenceKind::HardwareKeyAttestation => 1,
        EvidenceKind::ManagementLifeline => 2,
        EvidenceKind::ReleaseProvenance => 3,
        EvidenceKind::Sbom => 4,
        EvidenceKind::IsolationDrill => 5,
        EvidenceKind::RecoveryDrill => 6,
        EvidenceKind::IndependentReadback => 7,
    }
}

const fn origin_tag(value: EvidenceOrigin) -> u8 {
    match value {
        EvidenceOrigin::Hardware => 1,
        EvidenceOrigin::AttestedService => 2,
        EvidenceOrigin::Simulation => 3,
    }
}

const fn control_tag(value: AssuranceControl) -> u8 {
    match value {
        AssuranceControl::HardwareBacked => 1,
        AssuranceControl::NonExportable => 2,
        AssuranceControl::RoleScoped => 3,
        AssuranceControl::AttestationChainVerified => 4,
        AssuranceControl::OutsideBlastRadius => 5,
        AssuranceControl::IndependentChannel => 6,
        AssuranceControl::ArtifactDigestVerified => 7,
        AssuranceControl::SourceRevisionBound => 8,
        AssuranceControl::ReleaseSignatureVerified => 9,
        AssuranceControl::SbomComplete => 10,
        AssuranceControl::SbomDigestBound => 11,
        AssuranceControl::DependencyReviewPassed => 12,
        AssuranceControl::SecretScanPassed => 13,
        AssuranceControl::DrillPassed => 14,
        AssuranceControl::DrillEvidenceImmutable => 15,
        AssuranceControl::TargetStateVerified => 16,
        AssuranceControl::IndependentRecoveryAuthority => 17,
        AssuranceControl::IndependentVantage => 18,
        AssuranceControl::ReadbackSignatureVerified => 19,
    }
}
