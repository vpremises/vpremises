use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{SignatureAlgorithm, SignedDigestV1};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{CoordinatorError, canonical::digest_payload};

pub(crate) fn decode_public_key(value: &str) -> Result<[u8; 32], CoordinatorError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CoordinatorError::new("public_key", "must be unpadded base64url"))?;
    decoded
        .try_into()
        .map_err(|_| CoordinatorError::new("public_key", "must encode 32 Ed25519 bytes"))
}

pub(crate) fn verify_ed25519(
    public_key: &str,
    signed: &SignedDigestV1,
    payload: &[u8],
) -> Result<(), CoordinatorError> {
    if signed.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(CoordinatorError::new(
            "signed.algorithm",
            "only Ed25519 is trusted",
        ));
    }
    if signed.digest != digest_payload(payload) {
        return Err(CoordinatorError::new(
            "signed.digest",
            "does not cover the strict canonical payload",
        ));
    }
    let key = VerifyingKey::from_bytes(&decode_public_key(public_key)?)
        .map_err(|_| CoordinatorError::new("public_key", "is not a valid Ed25519 key"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| CoordinatorError::new("signed.signature", "must be unpadded base64url"))?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|_| CoordinatorError::new("signed.signature", "must encode 64 Ed25519 bytes"))?;
    key.verify_strict(payload, &signature)
        .map_err(|_| CoordinatorError::new("signed.signature", "Ed25519 verification failed"))
}
