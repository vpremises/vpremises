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

/// Trust roots are supplied by the local deployment, never by evidence itself.
#[derive(Default)]
pub struct TrustStore {
    signers: BTreeMap<String, TrustedSigner>,
}

impl TrustStore {
    /// Registers one out-of-band verifier for exactly one evidence role.
    ///
    /// # Errors
    ///
    /// Returns an error when a role, key identifier, or public key is reused.
    pub fn insert(
        &mut self,
        role: &str,
        key_id: &str,
        verifying_key: VerifyingKey,
    ) -> Result<(), TrustError> {
        if role.is_empty() || key_id.is_empty() || self.signers.contains_key(role) {
            return Err(TrustError::DuplicateIdentity);
        }
        let key = TrustedKey::Ed25519(verifying_key);
        if self.duplicates(key_id, &key) {
            return Err(TrustError::RoleConfusion);
        }
        self.signers.insert(
            role.to_owned(),
            TrustedSigner {
                key_id: key_id.to_owned(),
                key,
            },
        );
        Ok(())
    }

    /// Registers a SEC1-encoded P-256 public key for one evidence role.
    ///
    /// # Errors
    ///
    /// Returns an error when a role, key identifier, or public key is reused.
    pub fn insert_p256(
        &mut self,
        role: &str,
        key_id: &str,
        public_key: Vec<u8>,
    ) -> Result<(), TrustError> {
        if role.is_empty() || key_id.is_empty() || !(33..=65).contains(&public_key.len()) {
            return Err(TrustError::DuplicateIdentity);
        }
        let key = TrustedKey::EcdsaP256(public_key);
        if self.signers.contains_key(role) || self.duplicates(key_id, &key) {
            return Err(TrustError::RoleConfusion);
        }
        self.signers.insert(
            role.to_owned(),
            TrustedSigner {
                key_id: key_id.to_owned(),
                key,
            },
        );
        Ok(())
    }

    pub(crate) fn verifies(&self, evidence: &SignedEvidence) -> bool {
        let Some(trusted) = self.signers.get(&evidence.signer_role) else {
            return false;
        };
        let Some(signature) = evidence.signature_bytes() else {
            return false;
        };
        trusted.key_id == evidence.signer_key_id && verify(trusted, evidence, &signature)
    }

    fn duplicates(&self, key_id: &str, key: &TrustedKey) -> bool {
        let fingerprint = key.fingerprint();
        self.signers
            .values()
            .any(|entry| entry.key_id == key_id || entry.key.fingerprint() == fingerprint)
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
