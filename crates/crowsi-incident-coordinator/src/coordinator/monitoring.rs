use crate::{
    CoordinatorError, IncidentCoordinator, IncidentPhase, MonitoringEvidenceV1,
    monitoring::{subject, verify},
};

impl IncidentCoordinator {
    pub(super) fn begin_monitoring(
        &mut self,
        trusted_now: &str,
    ) -> Result<Vec<crate::CoordinatorCommandV1>, CoordinatorError> {
        self.transition(IncidentPhase::Restored, IncidentPhase::Monitoring)?;
        self.snapshot.monitoring_started_at = Some(trusted_now.to_owned());
        self.snapshot.monitoring_evidence_jti = None;
        self.monitoring_evidence = None;
        Ok(Vec::new())
    }

    pub(super) fn close(
        &mut self,
        evidence: &MonitoringEvidenceV1,
        trusted_now: &str,
    ) -> Result<Vec<crate::CoordinatorCommandV1>, CoordinatorError> {
        if self.snapshot.phase != IncidentPhase::Monitoring {
            return Err(CoordinatorError::new(
                "phase",
                "close requires active monitoring",
            ));
        }
        if self.seen_evidence_jtis.contains(&evidence.jti) {
            return Err(CoordinatorError::new(
                "monitoring_evidence.jti",
                "evidence replay detected",
            ));
        }
        verify::evidence(evidence, &self.snapshot, &self.trust, trusted_now)?;
        self.snapshot.phase = IncidentPhase::Closed;
        self.snapshot.monitoring_evidence_jti = Some(evidence.jti.clone());
        self.monitoring_evidence = Some(evidence.clone());
        self.seen_evidence_jtis.insert(evidence.jti.clone());
        Ok(Vec::new())
    }

    /// Computes the exact restored state a monitoring verifier must bind.
    ///
    /// # Errors
    ///
    /// Requires every restore target to have verified applied evidence.
    pub fn monitoring_subject_digest(&self) -> Result<String, CoordinatorError> {
        subject::digest(&self.snapshot)
    }
}
