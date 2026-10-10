//! Expose immutable snapshot metadata without widening the wire model.
use super::{FindingV1, ListenerV1, RoutesV1, SnapshotStatusV1, SnapshotV1};

impl SnapshotV1 {
    #[must_use]
    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }

    #[must_use]
    pub const fn external_actions(&self) -> bool {
        self.external_actions
    }

    #[must_use]
    pub fn signal_trust(&self) -> &str {
        &self.signal_trust
    }

    #[must_use]
    pub const fn status(&self) -> SnapshotStatusV1 {
        self.status
    }

    #[must_use]
    pub fn listeners(&self) -> &[ListenerV1] {
        &self.listeners
    }

    #[must_use]
    pub const fn default_routes(&self) -> &RoutesV1 {
        &self.default_routes
    }

    #[must_use]
    pub fn findings(&self) -> &[FindingV1] {
        &self.findings
    }
}
