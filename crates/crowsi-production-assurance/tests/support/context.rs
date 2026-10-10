use crowsi_production_assurance::AssuranceContext;

pub fn context(context_seed: u8) -> AssuranceContext {
    AssuranceContext {
        schema: "crowsi://production/assurance-context/v1".into(),
        hardware_key_attestation_id: "evidence-1".into(),
        hardware_key_attestation_digest_sha256: format!("{:064x}", 1),
        management_lifeline_id: "evidence-2".into(),
        management_lifeline_digest_sha256: format!("{:064x}", 2),
        release_id: "evidence-3".into(),
        release_digest_sha256: format!("{:064x}", 3),
        sbom_id: "evidence-4".into(),
        sbom_digest_sha256: format!("{:064x}", 4),
        command_id: "command-a".into(),
        command_digest_sha256: format!("{context_seed:064x}"),
        fence_epoch: 9,
        isolation_drill_id: "evidence-5".into(),
        isolation_drill_digest_sha256: format!("{:064x}", 5),
        recovery_drill_id: "evidence-6".into(),
        recovery_drill_digest_sha256: format!("{:064x}", 6),
        readback_id: "evidence-7".into(),
        readback_digest_sha256: format!("{:064x}", 7),
    }
}
