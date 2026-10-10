use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    CoordinatorError,
    time::{current, system_utc_window},
    validation::identifier,
};

const CHALLENGE_TTL_SECONDS: u64 = 60;

#[derive(Debug)]
pub struct MonotonicChallengeV1 {
    deployment_id: String,
    incident_id: String,
    nonce: String,
    issued_at: String,
    expires_at: String,
}

impl MonotonicChallengeV1 {
    pub(crate) fn issue(deployment_id: &str, incident_id: &str) -> Result<Self, CoordinatorError> {
        identifier("deployment_id", deployment_id)?;
        identifier("incident_id", incident_id)?;
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| CoordinatorError::new("challenge", "OS randomness unavailable"))?;
        let (issued_at, expires_at) = system_utc_window(CHALLENGE_TTL_SECONDS)?;
        Ok(Self {
            deployment_id: deployment_id.to_owned(),
            incident_id: incident_id.to_owned(),
            nonce: URL_SAFE_NO_PAD.encode(bytes),
            issued_at,
            expires_at,
        })
    }

    pub(crate) fn validate_at(&self, trusted_now: &str) -> Result<(), CoordinatorError> {
        if current(&self.issued_at, &self.expires_at, trusted_now) {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "challenge",
                "monotonic challenge is not current",
            ))
        }
    }

    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    #[must_use]
    pub fn incident_id(&self) -> &str {
        &self.incident_id
    }

    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    #[must_use]
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
}
