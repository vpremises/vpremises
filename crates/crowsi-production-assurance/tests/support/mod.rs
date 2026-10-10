mod context;
mod controls;
mod trust;

use context::context;
use controls::controls;
use crowsi_production_assurance::{
    EvidenceKind, EvidenceOrigin, EvidencePayload, ProductionAssurance, ReadinessBundle,
    ReadinessDecision, SignedEvidence, TrustStore,
};
use ed25519_dalek::Signer;

pub use trust::{key, valid_trust};

const DOMAIN: &str = "crowsi.production.example";
const DEPLOYMENT: &str = "deployment-a";
const ASSET: &str = "asset-a";

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock")
        .as_secs()
}

pub fn evaluate(bundle: &ReadinessBundle, trust: &TrustStore) -> ReadinessDecision {
    let root = tempfile::tempdir().expect("private assurance state");
    let mut assurance =
        ProductionAssurance::open(root.path().join("clock.sqlite3")).expect("assurance evaluator");
    assurance.evaluate(bundle, trust)
}

fn signed(kind: EvidenceKind, role: &str, seed: u8, context: &str, now: u64) -> SignedEvidence {
    let payload = EvidencePayload {
        evidence_id: format!("evidence-{seed}"),
        kind,
        origin: if kind == EvidenceKind::HardwareKeyAttestation {
            EvidenceOrigin::Hardware
        } else {
            EvidenceOrigin::AttestedService
        },
        security_domain: DOMAIN.into(),
        deployment_id: DEPLOYMENT.into(),
        asset_id: ASSET.into(),
        assurance_context_digest_sha256: context.into(),
        issued_at_epoch_s: now - 10,
        expires_at_epoch_s: now + 30,
        subject_digest_sha256: format!("{seed:064x}"),
        controls: controls(kind),
    };
    let signing = key(seed);
    let signature = signing.sign(&payload.signing_bytes());
    SignedEvidence::new(
        payload,
        role.into(),
        format!("key-{seed}"),
        signature.to_bytes(),
    )
}

pub fn valid_bundle() -> ReadinessBundle {
    valid_bundle_with_context(250)
}

pub fn valid_bundle_with_context(context_seed: u8) -> ReadinessBundle {
    let now = now();
    let assurance_context = context(context_seed);
    let context = assurance_context.digest_sha256();
    ReadinessBundle {
        schema: "crowsi://production/readiness/v1".into(),
        security_domain: DOMAIN.into(),
        deployment_id: DEPLOYMENT.into(),
        asset_id: ASSET.into(),
        assurance_context_digest_sha256: context.clone(),
        assurance_context,
        hardware_key_attestation: signed(
            EvidenceKind::HardwareKeyAttestation,
            "key-attestor",
            1,
            &context,
            now,
        ),
        management_lifeline: signed(
            EvidenceKind::ManagementLifeline,
            "network-owner",
            2,
            &context,
            now,
        ),
        release_provenance: signed(
            EvidenceKind::ReleaseProvenance,
            "release-builder",
            3,
            &context,
            now,
        ),
        sbom: signed(EvidenceKind::Sbom, "sbom-attestor", 4, &context, now),
        isolation_drill: signed(
            EvidenceKind::IsolationDrill,
            "drill-observer",
            5,
            &context,
            now,
        ),
        recovery_drill: signed(
            EvidenceKind::RecoveryDrill,
            "recovery-observer",
            6,
            &context,
            now,
        ),
        independent_readback: signed(
            EvidenceKind::IndependentReadback,
            "sensor-observer",
            7,
            &context,
            now,
        ),
    }
}
