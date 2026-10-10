/// Authenticated, rollback-resistant current-head lookup supplied by the
/// deployment adapter.
///
/// Implementations must read a durable CAS/monotonic store keyed by
/// `(deployment_id, incident_id)`. A cache or caller assertion is not valid.
pub trait MonotonicHeadReaderV1: Send + Sync {
    /// Returns true only when the tuple is the store's current committed head.
    fn is_current_head(
        &self,
        deployment_id: &str,
        incident_id: &str,
        sequence: u64,
        checkpoint_digest: &str,
    ) -> bool;
}

/// Cryptographically verified release presented only to an atomic reservation
/// gate before Policy Administrator issuance.
pub struct AtomicReleaseRequestV1<'a> {
    pub(crate) release: &'a crate::CommandReleaseV1,
}

impl AtomicReleaseRequestV1<'_> {
    #[must_use]
    pub fn command(&self) -> &crate::CoordinatorCommandV1 {
        self.release.command()
    }

    #[must_use]
    pub fn command_digest(&self) -> &str {
        self.release.command_digest()
    }

    #[must_use]
    pub fn checkpoint_sequence(&self) -> u64 {
        self.release.checkpoint().sequence
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> String {
        use crate::IncidentCanonicalPayloadV1 as _;
        self.release.checkpoint().payload_digest()
    }

    #[must_use]
    pub fn anchor_digest(&self) -> String {
        use crate::IncidentCanonicalPayloadV1 as _;
        self.release.anchor().payload_digest()
    }
}

/// Linearizable release-reservation boundary supplied by the deployment.
///
/// Implementations must atomically verify the exact durable current head,
/// consume `(head, command_digest)` once, and issue an unforgeable, short-lived
/// reservation bound to that tuple. A read followed by reservation is not an
/// implementation of this contract.
///
/// This is not a PEP executor. The Policy Administrator must bind the
/// reservation and fence into a signed downstream command; the PEP/provider
/// must recheck the latest fence, revocation, expiry, and resource-version CAS.
pub trait AtomicReleaseConsumerV1 {
    type Output;

    /// Reserves the release only within that linearizable transaction.
    ///
    /// # Errors
    ///
    /// Must fail closed on a stale head, replay, lost lease, CAS conflict, or
    /// indeterminate durable-store result.
    fn consume_if_current(
        &mut self,
        request: AtomicReleaseRequestV1<'_>,
    ) -> Result<Self::Output, crate::CoordinatorError>;
}
