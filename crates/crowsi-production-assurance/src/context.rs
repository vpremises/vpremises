use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{AssuranceContext, EvidenceKind, EvidencePayload, ReadinessBundle};

impl AssuranceContext {
    /// Computes the fixed binary digest signed by every evidence authority.
    #[must_use]
    pub fn digest_sha256(&self) -> String {
        let mut bytes = b"CROWSI-ASSURANCE-CONTEXT-V1\0".to_vec();
        for value in [
            &self.schema,
            &self.hardware_key_attestation_id,
            &self.hardware_key_attestation_digest_sha256,
            &self.management_lifeline_id,
            &self.management_lifeline_digest_sha256,
            &self.release_id,
            &self.release_digest_sha256,
            &self.sbom_id,
            &self.sbom_digest_sha256,
            &self.command_id,
            &self.command_digest_sha256,
            &self.isolation_drill_id,
            &self.isolation_drill_digest_sha256,
            &self.recovery_drill_id,
            &self.recovery_drill_digest_sha256,
            &self.readback_id,
            &self.readback_digest_sha256,
        ] {
            push_text(&mut bytes, value);
        }
        bytes.extend_from_slice(&self.fence_epoch.to_be_bytes());
        format!("{:x}", Sha256::digest(bytes))
    }

    pub(crate) fn expected(&self, kind: EvidenceKind) -> (&str, &str) {
        match kind {
            EvidenceKind::HardwareKeyAttestation => (
                &self.hardware_key_attestation_id,
                &self.hardware_key_attestation_digest_sha256,
            ),
            EvidenceKind::ManagementLifeline => (
                &self.management_lifeline_id,
                &self.management_lifeline_digest_sha256,
            ),
            EvidenceKind::ReleaseProvenance => (&self.release_id, &self.release_digest_sha256),
            EvidenceKind::Sbom => (&self.sbom_id, &self.sbom_digest_sha256),
            EvidenceKind::IsolationDrill => (
                &self.isolation_drill_id,
                &self.isolation_drill_digest_sha256,
            ),
            EvidenceKind::RecoveryDrill => {
                (&self.recovery_drill_id, &self.recovery_drill_digest_sha256)
            }
            EvidenceKind::IndependentReadback => (&self.readback_id, &self.readback_digest_sha256),
        }
    }
}

pub(crate) fn inspect_context(bundle: &ReadinessBundle, findings: &mut BTreeSet<String>) {
    let context = &bundle.assurance_context;
    let identifiers = [
        &context.hardware_key_attestation_id,
        &context.management_lifeline_id,
        &context.release_id,
        &context.sbom_id,
        &context.command_id,
        &context.isolation_drill_id,
        &context.recovery_drill_id,
        &context.readback_id,
    ];
    let digests = [
        &context.hardware_key_attestation_digest_sha256,
        &context.management_lifeline_digest_sha256,
        &context.release_digest_sha256,
        &context.sbom_digest_sha256,
        &context.command_digest_sha256,
        &context.isolation_drill_digest_sha256,
        &context.recovery_drill_digest_sha256,
        &context.readback_digest_sha256,
    ];
    if context.schema != "crowsi://production/assurance-context/v1"
        || context.fence_epoch == 0
        || identifiers
            .iter()
            .any(|value| !crate::evaluate::valid_id(value))
        || digests
            .iter()
            .any(|value| !crate::evaluate::is_sha256(value))
    {
        findings.insert("assurance-context-invalid".into());
    }
    if context.digest_sha256() != bundle.assurance_context_digest_sha256 {
        findings.insert("assurance-context-digest-mismatch".into());
    }
}

pub(crate) fn evidence_binding(
    bundle: &ReadinessBundle,
    kind: EvidenceKind,
    payload: &EvidencePayload,
) -> bool {
    let (evidence_id, subject_digest) = bundle.assurance_context.expected(kind);
    payload.kind == kind
        && payload.security_domain == bundle.security_domain
        && payload.deployment_id == bundle.deployment_id
        && payload.asset_id == bundle.asset_id
        && payload.assurance_context_digest_sha256 == bundle.assurance_context_digest_sha256
        && payload.evidence_id == evidence_id
        && payload.subject_digest_sha256 == subject_digest
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
