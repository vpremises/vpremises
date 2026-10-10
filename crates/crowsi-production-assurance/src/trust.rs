use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{SignatureAlgorithm, SignedEvidence};

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("a signer role or key id is already registered")]
    DuplicateIdentity,
    #[error("one public key cannot satisfy two independent roles")]
    RoleConfusion,
}

struct TrustedSigner {
    key_id: String,
    key: TrustedKey,
}

enum TrustedKey {
    Ed25519(VerifyingKey),
    EcdsaP256(Vec<u8>),
}

impl TrustedKey {
    fn fingerprint(&self) -> Vec<u8> {
        let material: &[u8] = match self {
            Self::Ed25519(key) => key.as_bytes(),
            Self::EcdsaP256(key) => key,
        };
        Sha256::digest(material).to_vec()
    }
}

fn verify(trusted: &TrustedSigner, evidence: &SignedEvidence, signature: &[u8]) -> bool {
    let message = evidence.payload.signing_bytes();
    match (&trusted.key, evidence.algorithm) {
        (TrustedKey::Ed25519(key), SignatureAlgorithm::Ed25519) => {
            let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
                return false;
            };
            key.verify_strict(&message, &Signature::from_bytes(&bytes))
                .is_ok()
        }
        (TrustedKey::EcdsaP256(key), SignatureAlgorithm::EcdsaP256Sha256Asn1) => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
                .verify(&message, signature)
                .is_ok()
        }
        _ => false,
    }
}

mod store;
pub use store::TrustStore;
