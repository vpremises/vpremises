//! Regression coverage and synthetic evidence for properties boundaries.
use super::*;

pub(super) fn assert_root(schema_source: &str, instance: &impl Serialize) {
    let schema: Value = serde_json::from_str(schema_source).expect("schema");
    let instance = serde_json::to_value(instance).expect("serialize");
    let actual = instance
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let properties = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, properties);
    assert_eq!(actual, required);
}
