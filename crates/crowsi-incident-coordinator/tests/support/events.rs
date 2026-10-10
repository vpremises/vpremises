use crowsi_incident_coordinator::{
    INCIDENT_EVENT_SCHEMA_V1, IncidentCanonicalPayloadV1, IncidentEventKindV1, IncidentEventV1,
};

use super::{
    common::signed,
    crypto::{OWNER_AUTHORITY, sign_owner},
    definition::{DEPLOYMENT, INCIDENT},
};

pub fn event(
    id: &str,
    isolation_epoch: u64,
    occurred_at: &str,
    kind: IncidentEventKindV1,
) -> IncidentEventV1 {
    let mut value = IncidentEventV1 {
        schema: INCIDENT_EVENT_SCHEMA_V1.to_owned(),
        event_id: format!("event.{id}"),
        jti: format!("jti.event.{id}"),
        deployment_id: DEPLOYMENT.to_owned(),
        incident_id: INCIDENT.to_owned(),
        isolation_epoch,
        occurred_at: occurred_at.to_owned(),
        valid_until: valid_until(occurred_at),
        owner_authority: OWNER_AUTHORITY.to_owned(),
        kind,
        signed: signed(),
    };
    value.signed = sign_owner(&value.signing_payload());
    value
}

fn valid_until(issued_at: &str) -> String {
    let hour = issued_at[11..13].parse::<u32>().expect("test hour");
    let minute = issued_at[14..16].parse::<u32>().expect("test minute");
    let second = issued_at[17..19].parse::<u32>().expect("test second");
    let total = hour * 3_600 + minute * 60 + second + 30;
    let mut value = issued_at.to_owned();
    value.replace_range(
        11..19,
        &format!(
            "{:02}:{:02}:{:02}",
            total / 3_600,
            total % 3_600 / 60,
            total % 60
        ),
    );
    value
}
