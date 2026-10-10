use crowsi_production_assurance::TrustStore;
use ed25519_dalek::SigningKey;

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn valid_trust() -> TrustStore {
    let mut trust = TrustStore::default();
    for (role, seed) in [
        ("key-attestor", 1),
        ("network-owner", 2),
        ("release-builder", 3),
        ("sbom-attestor", 4),
        ("drill-observer", 5),
        ("recovery-observer", 6),
        ("sensor-observer", 7),
    ] {
        trust
            .insert(role, &format!("key-{seed}"), key(seed).verifying_key())
            .unwrap();
    }
    trust
}
