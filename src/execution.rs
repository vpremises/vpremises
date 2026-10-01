//! Transport-neutral execution placement contracts; this module never runs a process.
use serde::{Deserialize, Serialize};

use crate::{
    EXECUTION_CONTROL_SCHEMA_V1, EXECUTION_LEASE_REQUEST_SCHEMA_V1, EXECUTION_LEASE_SCHEMA_V1,
    EXECUTION_RESULT_SCHEMA_V1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlacementV1 {
    pub provider_ref: String,
    pub environment_ref: String,
    pub resource_profile_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLeaseRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub invocation_id: String,
    pub workspace_ref: String,
    pub action_id: String,
    pub action_digest_sha256: String,
    pub effective_grant_digest_sha256: String,
    pub placement: ExecutionPlacementV1,
    pub expected_state_revision: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStateV1 {
    Prepared,
    Running,
    Unknown,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLeaseV1 {
    pub schema: String,
    pub lease_id: String,
    pub request_id: String,
    pub request_digest_sha256: String,
    pub invocation_id: String,
    pub action_digest_sha256: String,
    pub state_revision: u64,
    pub state: ExecutionStateV1,
    pub placement: ExecutionPlacementV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionOutcomeV1 {
    Completed,
    Failed,
    Denied,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReferenceV1 {
    pub owner_id: String,
    pub projection_ref: String,
    pub schema_id: String,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultV1 {
    pub schema: String,
    pub lease_id: String,
    pub invocation_id: String,
    pub action_digest_sha256: String,
    pub state_revision: u64,
    pub outcome: ExecutionOutcomeV1,
    pub output: Option<ProjectionReferenceV1>,
    pub reason_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionControlKindV1 {
    ReadStatus,
    Cancel,
    Recover,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionControlRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub lease_id: String,
    pub invocation_id: String,
    pub expected_state_revision: u64,
    pub idempotency_key: String,
    pub kind: ExecutionControlKindV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContractError(pub &'static str);

pub trait ValidateExecution {
    fn validate_execution(&self) -> Result<(), ExecutionContractError>;
}

impl ValidateExecution for ExecutionLeaseRequestV1 {
    fn validate_execution(&self) -> Result<(), ExecutionContractError> {
        require(self.schema == EXECUTION_LEASE_REQUEST_SCHEMA_V1, "schema")?;
        for value in [
            &self.request_id,
            &self.invocation_id,
            &self.workspace_ref,
            &self.idempotency_key,
            &self.placement.provider_ref,
            &self.placement.environment_ref,
            &self.placement.resource_profile_ref,
        ] {
            require(identifier(value), "identifier")?;
        }
        require(schema_id(&self.action_id), "action_id")?;
        require(digest(&self.action_digest_sha256), "action_digest")?;
        require(digest(&self.effective_grant_digest_sha256), "grant_digest")
    }
}

impl ValidateExecution for ExecutionLeaseV1 {
    fn validate_execution(&self) -> Result<(), ExecutionContractError> {
        require(self.schema == EXECUTION_LEASE_SCHEMA_V1, "schema")?;
        for value in [&self.lease_id, &self.request_id, &self.invocation_id] {
            require(identifier(value), "lease identity")?;
        }
        require(
            digest(&self.request_digest_sha256) && digest(&self.action_digest_sha256),
            "lease digest",
        )?;
        require(
            matches!(self.state, ExecutionStateV1::Prepared),
            "lease state",
        )?;
        for value in [
            &self.placement.provider_ref,
            &self.placement.environment_ref,
            &self.placement.resource_profile_ref,
        ] {
            require(identifier(value), "placement")?;
        }
        Ok(())
    }
}

impl ValidateExecution for ExecutionResultV1 {
    fn validate_execution(&self) -> Result<(), ExecutionContractError> {
        require(self.schema == EXECUTION_RESULT_SCHEMA_V1, "schema")?;
        require(
            identifier(&self.lease_id) && identifier(&self.invocation_id),
            "identity",
        )?;
        require(digest(&self.action_digest_sha256), "action_digest")?;
        match self.outcome {
            ExecutionOutcomeV1::Completed => {
                require(
                    self.output.is_some() && self.reason_id.is_none(),
                    "completed",
                )?;
            }
            _ => require(
                self.output.is_none() && self.reason_id.as_ref().is_some_and(|id| schema_id(id)),
                "terminal",
            )?,
        }
        if let Some(output) = &self.output {
            require(identifier(&output.owner_id), "output owner")?;
            require(identifier(&output.projection_ref), "projection_ref")?;
            require(
                schema_id(&output.schema_id) && digest(&output.digest_sha256),
                "output",
            )?;
        }
        Ok(())
    }
}

impl ValidateExecution for ExecutionControlRequestV1 {
    fn validate_execution(&self) -> Result<(), ExecutionContractError> {
        require(self.schema == EXECUTION_CONTROL_SCHEMA_V1, "schema")?;
        for value in [
            &self.request_id,
            &self.lease_id,
            &self.invocation_id,
            &self.idempotency_key,
        ] {
            require(identifier(value), "control identity")?;
        }
        Ok(())
    }
}

fn require(value: bool, field: &'static str) -> Result<(), ExecutionContractError> {
    value.then_some(()).ok_or(ExecutionContractError(field))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn schema_id(value: &str) -> bool {
    value.len() <= 256
        && value.starts_with("hathq://")
        && value.rsplit_once("/v").is_some_and(|(_, version)| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        })
}
