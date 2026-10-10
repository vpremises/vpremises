mod support;

use crowsi_production_assurance::{ReadinessState, TrustError, TrustStore};
use ed25519_dalek::SigningKey;

#[test]
fn one_key_cannot_satisfy_independent_roles() {
    let signing = SigningKey::from_bytes(&[42; 32]);
    let mut trust = TrustStore::default();
    trust
        .insert("key-attestor", "key-a", signing.verifying_key())
        .unwrap();
    let result = trust.insert("sensor-observer", "key-b", signing.verifying_key());
    assert!(matches!(result, Err(TrustError::RoleConfusion)));
}

#[test]
fn readiness_bundle_rejects_unknown_json_fields() {
    let trust = support::valid_trust();
    let bundle = support::valid_bundle();
    assert_eq!(
        support::evaluate(&bundle, &trust).state,
        ReadinessState::Ready
    );
    let mut value = serde_json::to_value(bundle).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("private_key".into(), serde_json::Value::String("no".into()));
    assert!(serde_json::from_value::<crowsi_production_assurance::ReadinessBundle>(value).is_err());
}

#[test]
fn checked_in_schema_is_closed_and_versioned() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/production-readiness-v1.schema.json"
    ))
    .unwrap();
    assert_eq!(document["$id"], "crowsi://production/readiness/v1");
    assert_eq!(document["additionalProperties"], false);
    assert_eq!(document["$defs"]["evidence"]["additionalProperties"], false);
    assert_eq!(document["$defs"]["context"]["additionalProperties"], false);
    assert_eq!(document["$defs"]["payload"]["additionalProperties"], false);
    assert_eq!(document["$defs"]["controls"]["additionalProperties"], false);
}
