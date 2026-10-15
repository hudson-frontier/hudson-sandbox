#![allow(clippy::unwrap_used)]
use super::CommandInput;
use crate::RequestDigest;
use serde_json::json;

#[test]
fn omitted_generation_preserves_legacy_normalization_and_digest() {
    let minimal = json!({"argv":["true"],"deadline_unix_ms":1});
    let command: CommandInput = serde_json::from_value(minimal).unwrap();
    let legacy =
        json!({"argv":["true"],"env":{},"cwd":"/","deadline_unix_ms":1,"output_limit":1048576});
    assert_eq!(serde_json::to_value(&command).unwrap(), legacy);
    assert_eq!(
        RequestDigest::compute("POST", "/execute", &command).unwrap(),
        RequestDigest::compute("POST", "/execute", &legacy).unwrap()
    );
    let mut guarded = command.clone();
    guarded.expected_generation = Some(1);
    assert!(guarded.validate().is_ok());
    assert_ne!(
        RequestDigest::compute("POST", "/execute", &command).unwrap(),
        RequestDigest::compute("POST", "/execute", &guarded).unwrap()
    );
    let first = RequestDigest::compute("POST", "/execute", &guarded).unwrap();
    guarded.expected_generation = Some(2);
    assert_ne!(
        first,
        RequestDigest::compute("POST", "/execute", &guarded).unwrap()
    );
}

#[test]
fn generation_preconditions_reject_null_wrong_types_and_nonpositive_values() {
    for value in [
        json!(null),
        json!(true),
        json!("1"),
        json!(9223372036854775808u64),
    ] {
        assert!(
            serde_json::from_value::<CommandInput>(json!({
                "argv":["true"],"deadline_unix_ms":1,"expected_generation":value
            }))
            .is_err()
        );
    }
    for generation in [0, -1] {
        let command: CommandInput = serde_json::from_value(json!({
            "argv":["true"],"deadline_unix_ms":1,"expected_generation":generation
        }))
        .unwrap();
        assert!(command.validate().is_err());
    }
    let command: CommandInput = serde_json::from_value(json!({
        "argv":["true"],"deadline_unix_ms":1,"expected_generation":i64::MAX
    }))
    .unwrap();
    assert_eq!(command.expected_generation, Some(i64::MAX));
    assert!(command.validate().is_ok());
}
