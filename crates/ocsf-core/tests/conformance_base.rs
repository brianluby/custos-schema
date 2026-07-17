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
    assert!(
        result.is_err(),
        "an empty event should fail validation against the vulnerability_finding base oracle schema"
    );
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
    assert!(
        result.is_err(),
        "a String field standing in for oracle epss.percentile (float_t) should be caught"
    );
}
