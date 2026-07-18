mod conformance;
use conformance::*;
use ocsf_core::objects::{Metadata, Product};

#[test]
fn product_matches_oracle() {
    assert_object_matches::<Product>("product");
}

#[test]
fn metadata_matches_oracle() {
    assert_object_matches::<Metadata>("metadata");
}

/// `FIELD_NAMES` (read by the extension-key collision check) must stay in
/// lockstep with the schemars property set for the types that declare it.
#[test]
fn field_names_match_schema() {
    assert_field_names_match::<Product>("object", "product", Product::FIELD_NAMES);
    assert_field_names_match::<Metadata>("object", "metadata", Metadata::FIELD_NAMES);
}

/// `SeverityId::KNOWN` must line up with the oracle's `severity_id` enum
/// vocabulary on a real class, not just be internally self-consistent.
#[test]
fn severity_enum_matches_oracle() {
    assert_enum_matches(
        ocsf_core::enums::SeverityId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "severity_id",
    );
}

/// `assert_valid_against_oracle_schema` must actually load the vendored
/// jsonschema oracle and enforce it — an empty event is missing every
/// required top-level attribute (`class_uid`, `severity_id`, `time`, ...)
/// and must be rejected, not silently accepted.
#[test]
fn oracle_jsonschema_rejects_garbage() {
    let result = std::panic::catch_unwind(|| {
        assert_valid_against_oracle_schema(&serde_json::json!({}), "vulnerability_finding", "base")
    });
    let payload = result.expect_err(
        "an empty event should fail validation against the vulnerability_finding base oracle schema",
    );
    let message = panic_message(payload);
    assert!(
        message.contains("event failed validation against vulnerability_finding.base"),
        "panic must come from the oracle-schema validation path, got: {message:?}"
    );
}

/// Converts a supported panic payload into its string message.
///
/// # Panics
///
/// Panics if `payload` contains neither a string slice nor a `String`.
///
/// # Examples
///
/// ```
/// let payload: Box<dyn std::any::Any + Send> = Box::new("panic message");
/// assert_eq!(panic_message(payload), "panic message");
/// ```
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        panic!("panic payload was neither &str nor String");
    }
}

/// The coarse type-compatibility check (`assert_matches` step 4) must
/// actually fire: a throwaway type that mirrors the oracle's tiny `epss`
/// object in every property name and required-ness, but deliberately
/// mistypes `percentile` (oracle `float_t` -> `Kind::Number`) as `String`,
/// must be rejected.
#[test]
fn type_mismatch_is_detected() {
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct BadEpss {
        score: String,
        percentile: Option<String>, // wrong: oracle epss.percentile is float_t
        version: Option<String>,
        created_time: Option<i64>,
        created_time_dt: Option<String>,
    }

    let result = std::panic::catch_unwind(|| {
        assert_object_matches::<BadEpss>("epss");
    });
    let payload = result.expect_err(
        "a String field standing in for oracle epss.percentile (float_t) should be caught",
    );
    let message = panic_message(payload);
    assert!(
        message.contains("attribute types do not match oracle FULL attributes"),
        "panic must come from the coarse type-compatibility check, got: {message:?}"
    );
    assert!(
        message.contains("percentile"),
        "the type-mismatch panic must name the offending attribute, got: {message:?}"
    );
}

/// A whole-number `Integer` on our side is a *narrowing* of the oracle's
/// `float_t` (`Kind::Number`): it cannot deserialize a fractional value, so it
/// is a real mismatch. This pins the removal of the old `(Number, Integer)`
/// escape hatch — `percentile: Option<i64>` must still be rejected.
#[test]
fn integer_narrowing_of_oracle_float_is_rejected() {
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct BadEpss {
        score: String,
        percentile: Option<i64>, // wrong: oracle epss.percentile is float_t
        version: Option<String>,
        created_time: Option<i64>,
        created_time_dt: Option<String>,
    }

    let result = std::panic::catch_unwind(|| {
        assert_object_matches::<BadEpss>("epss");
    });
    let payload = result.expect_err(
        "an Integer field standing in for oracle epss.percentile (float_t) should be caught",
    );
    let message = panic_message(payload);
    assert!(
        message.contains("attribute types do not match oracle FULL attributes"),
        "panic must come from the coarse type-compatibility check, got: {message:?}"
    );
    assert!(
        message.contains("percentile"),
        "the type-mismatch panic must name the offending attribute, got: {message:?}"
    );
}
