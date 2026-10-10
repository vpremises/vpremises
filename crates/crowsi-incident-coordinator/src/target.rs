use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    CoordinatorCommandV1, CoordinatorReceiptV1, EnforcementRequirementV1, TargetDefinitionV1,
    verification::VerifiedEvidenceV1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesiredTargetState {
    Unchanged,
    Isolated,
    Restored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedTargetState {
    Unknown,
    Isolated,
    Restored,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionState {
    Idle,
    Pending,
    Verified,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationMode {
    Containment,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetStateV1 {
    pub target_id: String,
    pub isolation_epoch: u64,
    pub desired: DesiredTargetState,
    pub observed: ObservedTargetState,
    pub transaction: TransactionState,
    pub transaction_id: Option<String>,
    pub requirements: Vec<EnforcementRequirementV1>,
    pub active_commands: BTreeMap<String, CoordinatorCommandV1>,
    pub receipts: BTreeMap<String, CoordinatorReceiptV1>,
    pub(crate) verified_evidence: BTreeMap<String, VerifiedEvidenceV1>,
}

impl TargetStateV1 {
    pub(crate) fn new(definition: TargetDefinitionV1) -> Self {
        Self {
            target_id: definition.target_id,
            isolation_epoch: 0,
            desired: DesiredTargetState::Unchanged,
            observed: ObservedTargetState::Unknown,
            transaction: TransactionState::Idle,
            transaction_id: None,
            requirements: definition.requirements,
            active_commands: BTreeMap::new(),
            receipts: BTreeMap::new(),
            verified_evidence: BTreeMap::new(),
        }
    }

    pub(crate) fn begin(
        &mut self,
        mode: OperationMode,
        isolation_epoch: u64,
        transaction_id: String,
        commands: BTreeMap<String, CoordinatorCommandV1>,
    ) {
        self.isolation_epoch = isolation_epoch;
        self.desired = match mode {
            OperationMode::Containment => DesiredTargetState::Isolated,
            OperationMode::Restore => DesiredTargetState::Restored,
        };
        self.observed = ObservedTargetState::Unknown;
        self.transaction = TransactionState::Pending;
        self.transaction_id = Some(transaction_id);
        self.active_commands = commands;
        self.receipts.clear();
        self.verified_evidence.clear();
    }
}
