mod support;

use crowsi_production_assurance::ReadinessState;
use support::{evaluate, now, valid_bundle, valid_bundle_with_context, valid_trust};

#[test]
fn complete_independent_evidence_is_ready() {
    let trust = valid_trust();
    let decision = evaluate(&valid_bundle(), &trust);
    assert_eq!(decision.state, ReadinessState::Ready);
    assert!(decision.finding_codes.is_empty());
    assert!(!decision.external_actions);
}

#[test]
fn target_or_deployment_substitution_fails_closed() {
    let trust = valid_trust();
    let mut target = valid_bundle();
    target.independent_readback.payload.asset_id = "other-asset".into();
    assert_eq!(evaluate(&target, &trust).state, ReadinessState::Blocked);

    let mut deployment = valid_bundle();
    deployment.sbom.payload.deployment_id = "other-deployment".into();
    assert_eq!(evaluate(&deployment, &trust).state, ReadinessState::Blocked);
}

#[test]
fn simulation_stale_and_missing_controls_are_blocked() {
    let trust = valid_trust();
    let mut simulated = valid_bundle();
    simulated.isolation_drill.payload.origin =
        crowsi_production_assurance::EvidenceOrigin::Simulation;
    assert_eq!(evaluate(&simulated, &trust).state, ReadinessState::Blocked);

    let mut stale = valid_bundle();
    stale.management_lifeline.payload.expires_at_epoch_s = now();
    assert_eq!(evaluate(&stale, &trust).state, ReadinessState::Blocked);

    let mut unsafe_key = valid_bundle();
    unsafe_key
        .hardware_key_attestation
        .payload
        .controls
        .assertions
        .remove(&crowsi_production_assurance::AssuranceControl::NonExportable);
    assert_eq!(evaluate(&unsafe_key, &trust).state, ReadinessState::Blocked);
}

#[test]
fn signature_or_role_substitution_is_blocked() {
    let trust = valid_trust();
    let mut tampered = valid_bundle();
    tampered
        .release_provenance
        .payload
        .controls
        .assertions
        .remove(&crowsi_production_assurance::AssuranceControl::SecretScanPassed);
    assert_eq!(evaluate(&tampered, &trust).state, ReadinessState::Blocked);

    let mut wrong_role = valid_bundle();
    wrong_role.sbom.signer_role = "release-builder".into();
    assert_eq!(evaluate(&wrong_role, &trust).state, ReadinessState::Blocked);
}

#[test]
fn stale_readback_and_cross_context_evidence_are_blocked() {
    let trust = valid_trust();
    let mut stale = valid_bundle();
    stale.independent_readback.payload.issued_at_epoch_s = now() - 16;
    let stale_decision = evaluate(&stale, &trust);
    assert_eq!(stale_decision.state, ReadinessState::Blocked);
    assert!(
        stale_decision
            .finding_codes
            .contains(&"independent-readback-freshness-invalid".into())
    );

    let mut mixed = valid_bundle();
    let other = valid_bundle_with_context(251);
    mixed.sbom = other.sbom;
    let mixed_decision = evaluate(&mixed, &trust);
    assert_eq!(mixed_decision.state, ReadinessState::Blocked);
    assert!(
        mixed_decision
            .finding_codes
            .contains(&"sbom-binding-invalid".into())
    );
}
