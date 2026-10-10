mod support;

use crowsi_production_assurance::{ReadinessState, SignatureAlgorithm, SignedEvidence, TrustStore};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};

#[test]
fn hardware_compatible_p256_evidence_is_verified() {
    let _baseline = support::valid_trust();
    let mut bundle = support::valid_bundle();
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng).unwrap();
    let signature = pair
        .sign(&rng, &bundle.release_provenance.payload.signing_bytes())
        .unwrap();
    bundle.release_provenance = SignedEvidence::new_with_algorithm(
        bundle.release_provenance.payload,
        "release-builder".into(),
        "p256-release-key".into(),
        SignatureAlgorithm::EcdsaP256Sha256Asn1,
        signature.as_ref().to_vec(),
    );

    let mut trust = TrustStore::default();
    for (role, seed) in [
        ("key-attestor", 1),
        ("network-owner", 2),
        ("sbom-attestor", 4),
        ("drill-observer", 5),
        ("recovery-observer", 6),
        ("sensor-observer", 7),
    ] {
        trust
            .insert(
                role,
                &format!("key-{seed}"),
                support::key(seed).verifying_key(),
            )
            .unwrap();
    }
    trust
        .insert_p256(
            "release-builder",
            "p256-release-key",
            pair.public_key().as_ref().to_vec(),
        )
        .unwrap();
    assert_eq!(
        support::evaluate(&bundle, &trust).state,
        ReadinessState::Ready
    );
}
