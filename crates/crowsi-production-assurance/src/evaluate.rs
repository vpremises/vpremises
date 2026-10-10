use std::collections::BTreeSet;

use crate::{
    EvidenceKind, EvidenceOrigin, ReadinessBundle, ReadinessDecision, ReadinessState,
    SignedEvidence, TrustStore,
};

const SCHEMA: &str = "crowsi://production/readiness/v1";
const MAX_EVIDENCE_LIFETIME_S: u64 = 90 * 24 * 60 * 60;

pub(crate) fn evaluate_at(
    bundle: &ReadinessBundle,
    now: u64,
    trust: &TrustStore,
) -> ReadinessDecision {
    let mut findings = BTreeSet::new();
    if bundle.schema != SCHEMA {
        findings.insert("schema-mismatch".to_owned());
    }
    if !valid_id(&bundle.security_domain)
        || !valid_id(&bundle.deployment_id)
        || !valid_id(&bundle.asset_id)
    {
        findings.insert("bundle-identity-missing".to_owned());
    }
    if !is_sha256(&bundle.assurance_context_digest_sha256) {
        findings.insert("assurance-context-digest-invalid".to_owned());
    }
    crate::context::inspect_context(bundle, &mut findings);
    let expected = [
        (
            EvidenceKind::HardwareKeyAttestation,
            &bundle.hardware_key_attestation,
        ),
        (
            EvidenceKind::ManagementLifeline,
            &bundle.management_lifeline,
        ),
        (EvidenceKind::ReleaseProvenance, &bundle.release_provenance),
        (EvidenceKind::Sbom, &bundle.sbom),
        (EvidenceKind::IsolationDrill, &bundle.isolation_drill),
        (EvidenceKind::RecoveryDrill, &bundle.recovery_drill),
        (
            EvidenceKind::IndependentReadback,
            &bundle.independent_readback,
        ),
    ];
    let mut signer_keys = BTreeSet::new();
    for (kind, evidence) in expected {
        inspect(bundle, kind, evidence, now, trust, &mut findings);
        if !signer_keys.insert(&evidence.signer_key_id) {
            findings.insert("independent-role-key-reused".to_owned());
        }
    }
    ReadinessDecision {
        schema: SCHEMA,
        state: if findings.is_empty() {
            ReadinessState::Ready
        } else {
            ReadinessState::Blocked
        },
        finding_codes: findings.into_iter().collect(),
        external_actions: false,
    }
}

mod inspection;
use inspection::inspect;
pub(crate) use inspection::is_sha256;
pub(crate) use inspection::valid_id;
