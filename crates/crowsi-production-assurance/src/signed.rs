use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{EvidencePayload, SignatureAlgorithm};

/// Signed evidence contains no private key or credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidence {
    pub payload: EvidencePayload,
    pub signer_role: String,
    pub signer_key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub signature_base64: String,
}

impl SignedEvidence {
    #[must_use]
    pub fn new(
        payload: EvidencePayload,
        signer_role: String,
        signer_key_id: String,
        signature: [u8; 64],
    ) -> Self {
        Self {
            payload,
            signer_role,
            signer_key_id,
            algorithm: SignatureAlgorithm::Ed25519,
            signature_base64: STANDARD_NO_PAD.encode(signature),
        }
    }

    #[must_use]
    pub fn new_with_algorithm(
        payload: EvidencePayload,
        signer_role: String,
        signer_key_id: String,
        algorithm: SignatureAlgorithm,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            payload,
            signer_role,
            signer_key_id,
            algorithm,
            signature_base64: STANDARD_NO_PAD.encode(signature),
        }
    }

    pub(crate) fn signature_bytes(&self) -> Option<Vec<u8>> {
        if !(40..=684).contains(&self.signature_base64.len()) {
            return None;
        }
        let decoded = STANDARD_NO_PAD.decode(&self.signature_base64).ok()?;
        (32..=512).contains(&decoded.len()).then_some(decoded)
    }
}
