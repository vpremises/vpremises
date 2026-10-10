use crowsi_control_contracts::{SignatureAlgorithm, SignedDigestV1};

pub fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

pub fn signed() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "key.incident.1".to_owned(),
        digest: digest(),
        signature: "a".repeat(86),
    }
}
