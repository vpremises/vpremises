//! Validate exact authorization bindings and reserve fresh JTIs.
use super::{
    ActionBindingV1, BTreeMap, BTreeSet, CommandAuthorizationV1, ControlAction, CoordinatorError,
    IncidentCoordinator, OperationMode, verify_signatures,
};

impl IncidentCoordinator {
    pub(in crate::coordinator) fn validate_authorizations(
        &self,
        mode: OperationMode,
        authorizations: &[CommandAuthorizationV1],
        at: &str,
        owner_authority: &str,
    ) -> Result<BTreeMap<String, CommandAuthorizationV1>, CoordinatorError> {
        let mut expected = self.expected_bindings(mode);
        if authorizations.len() != expected.len() {
            return Err(CoordinatorError::new(
                "authorizations",
                "one authorization is required per enforcement",
            ));
        }
        let mut mapped = BTreeMap::new();
        let mut fresh_jtis = BTreeSet::new();
        for authorization in authorizations {
            authorization.validate_at(at)?;
            verify_signatures(authorization, &self.trust, mode, Some(owner_authority))?;
            let Some((target, binding)) = expected.remove(&authorization.requirement_id) else {
                return Err(CoordinatorError::new(
                    "requirement_id",
                    "authorization is not required",
                ));
            };
            let jtis = [&authorization.intent.jti, &authorization.grant.jti];
            let fresh = jtis.into_iter().all(|jti| {
                !self.reserved_authorization_jtis.contains(jti) && fresh_jtis.insert(jti)
            });
            if authorization.target_id != target
                || authorization.intent.binding != binding
                || !fresh
                || mapped
                    .insert(authorization.requirement_id.clone(), authorization.clone())
                    .is_some()
            {
                return Err(CoordinatorError::new(
                    "authorization",
                    "authorization binding or JTI is invalid",
                ));
            }
        }
        Ok(mapped)
    }

    pub(in crate::coordinator::planning) fn expected_bindings(
        &self,
        mode: OperationMode,
    ) -> BTreeMap<String, (String, ActionBindingV1)> {
        let mut expected = BTreeMap::new();
        for target in self.snapshot.targets.values() {
            for requirement in &target.requirements {
                let mut binding = requirement.binding.clone();
                if mode == OperationMode::Restore {
                    binding.action = ControlAction::Restore;
                    "incident-recovery".clone_into(&mut binding.purpose);
                }
                expected.insert(
                    requirement.requirement_id.clone(),
                    (target.target_id.clone(), binding),
                );
            }
        }
        expected
    }

    pub(in crate::coordinator) fn reserve(
        &mut self,
        authorizations: &BTreeMap<String, CommandAuthorizationV1>,
    ) {
        for authorization in authorizations.values() {
            self.reserved_authorization_jtis
                .insert(authorization.intent.jti.clone());
            self.reserved_authorization_jtis
                .insert(authorization.grant.jti.clone());
        }
    }
}
