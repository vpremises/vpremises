//! Pin trusted signers and verify their bounded evidence documents.
use super::{
    BTreeMap, SignedEvidence, TrustError, TrustedKey, TrustedSigner, VerifyingKey, verify,
};

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
