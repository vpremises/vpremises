mod canonical;
mod validation;

use crowsi_control_contracts::SignedDigestV1;
use serde::{Deserialize, Serialize};

use crate::{
    CommandAuthorizationV1, CoordinatorReceiptV1, IndependentVerificationArtifactV1,
    MonitoringEvidenceV1, RecoveryApprovalV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum IncidentEventKindV1 {
    BeginTriage,
    RequestContainment {
        authorizations: Vec<CommandAuthorizationV1>,
    },
    SubmitReceipt {
        receipt: Box<CoordinatorReceiptV1>,
    },
    SubmitVerification {
        verification: Box<IndependentVerificationArtifactV1>,
    },
    FinalizeContainment,
    RetryContainment {
        authorizations: Vec<CommandAuthorizationV1>,
    },
    BeginEradication,
    RequestRecovery,
    AuthorizeRecovery {
        approval: Box<RecoveryApprovalV1>,
    },
    StartRestore {
        automatic: bool,
    },
    FinalizeRestore,
    RetryRecovery,
    BeginMonitoring,
    Close {
        evidence: Box<MonitoringEvidenceV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentEventV1 {
    pub schema: String,
    pub event_id: String,
    pub jti: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub isolation_epoch: u64,
    pub occurred_at: String,
    pub valid_until: String,
    pub owner_authority: String,
    pub kind: IncidentEventKindV1,
    pub signed: SignedDigestV1,
}
