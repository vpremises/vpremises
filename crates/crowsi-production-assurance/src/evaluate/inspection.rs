//! Inspect freshness, signatures, policy and control evidence before classification.
use super::{
    BTreeSet, EvidenceKind, EvidenceOrigin, MAX_EVIDENCE_LIFETIME_S, ReadinessBundle,
    SignedEvidence, TrustStore,
};

pub(in crate::evaluate) fn inspect(
    bundle: &ReadinessBundle,
    kind: EvidenceKind,
    evidence: &SignedEvidence,
    now: u64,
    trust: &TrustStore,
    findings: &mut BTreeSet<String>,
) {
    let payload = &evidence.payload;
    let prefix = kind.code();
    let invalid_binding = !crate::context::evidence_binding(bundle, kind, payload);
    record(findings, invalid_binding, prefix, "binding-invalid");
    let invalid_identity = !valid_id(&payload.evidence_id)
        || !valid_id(&payload.security_domain)
        || !valid_id(&payload.deployment_id)
        || !valid_id(&payload.asset_id)
        || !valid_id(&evidence.signer_role)
        || !valid_id(&evidence.signer_key_id);
    record(findings, invalid_identity, prefix, "identity-invalid");
    record(
        findings,
        !is_sha256(&payload.subject_digest_sha256),
        prefix,
        "subject-digest-invalid",
    );
    record(
        findings,
        !is_sha256(&payload.assurance_context_digest_sha256),
        prefix,
        "context-digest-invalid",
    );
    let invalid_time = payload.issued_at_epoch_s > now
        || payload.expires_at_epoch_s <= now
        || payload
            .expires_at_epoch_s
            .saturating_sub(payload.issued_at_epoch_s)
            > MAX_EVIDENCE_LIFETIME_S;
    record(findings, invalid_time, prefix, "time-invalid");
    record(
        findings,
        payload.origin == EvidenceOrigin::Simulation,
        prefix,
        "simulation-rejected",
    );
    let readback_stale = kind == EvidenceKind::IndependentReadback
        && (payload.controls.freshness_seconds == 0
            || now.saturating_sub(payload.issued_at_epoch_s) > payload.controls.freshness_seconds);
    record(findings, readback_stale, prefix, "freshness-invalid");
    record(
        findings,
        evidence.signer_role != kind.expected_role() || !trust.verifies(evidence),
        prefix,
        "signature-invalid",
    );
    record(
        findings,
        !crate::controls::satisfy(kind, payload.origin, &payload.controls),
        prefix,
        "controls-incomplete",
    );
}

pub(in crate::evaluate) fn record(
    findings: &mut BTreeSet<String>,
    failed: bool,
    prefix: &str,
    suffix: &str,
) {
    if failed {
        findings.insert(format!("{prefix}-{suffix}"));
    }
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_id(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
}
