use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{SignatureAlgorithm, SignedDigestV1};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::{
    ANCHOR_KEY, CHECKPOINT_KEY, FOREIGN_OWNER_KEY, IDENTITY_KEY, INCUS_KEY, INDEPENDENT_KEY,
    INDEPENDENT_KEY_ID, OWNER_KEY, PEP_IDENTITY_KEY, POLICY_KEY, RECOVERY_KEY, RECOVERY_KEY_ID,
};

pub fn sign_independent(payload: &[u8]) -> SignedDigestV1 {
    signed(INDEPENDENT_KEY_ID, INDEPENDENT_KEY, payload)
}

pub fn sign_recovery(payload: &[u8]) -> SignedDigestV1 {
    signed(RECOVERY_KEY_ID, RECOVERY_KEY, payload)
}

pub fn sign_owner(payload: &[u8]) -> SignedDigestV1 {
    signed("key.owner.1", OWNER_KEY, payload)
}

pub fn sign_foreign_owner(payload: &[u8]) -> SignedDigestV1 {
    signed("key.owner.foreign", FOREIGN_OWNER_KEY, payload)
}

pub fn sign_identity(payload: &[u8]) -> SignedDigestV1 {
    signed("key.identity-provider.1", IDENTITY_KEY, payload)
}

pub fn sign_policy(payload: &[u8]) -> SignedDigestV1 {
    signed("key.policy-administrator.1", POLICY_KEY, payload)
}

pub fn sign_checkpoint(payload: &[u8]) -> SignedDigestV1 {
    signed("key.checkpoint.1", CHECKPOINT_KEY, payload)
}

pub fn sign_anchor(payload: &[u8]) -> SignedDigestV1 {
    signed("key.anchor.1", ANCHOR_KEY, payload)
}

pub fn sign_pep(authority: &str, payload: &[u8]) -> SignedDigestV1 {
    match authority {
        "crowsi-enforcer-incus" => signed("key.pep.incus", INCUS_KEY, payload),
        "crowsi-enforcer-identity" => signed("key.pep.identity", PEP_IDENTITY_KEY, payload),
        _ => panic!("unknown test PEP"),
    }
}

fn signed(key_id: &str, secret: [u8; 32], payload: &[u8]) -> SignedDigestV1 {
    let digest = Sha256::digest(payload);
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: key_id.to_owned(),
        digest: format!("sha256:{digest:x}"),
        signature: URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&secret).sign(payload).to_bytes()),
    }
}
