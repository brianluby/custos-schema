//! Serde edge cases that cut across the whole-document shape rather than a
//! single class or enum: unknown top-level attributes and out-of-vocabulary
//! enum values arriving together in one fixture document must both survive a
//! full round-trip losslessly.
//!
//! This is complementary to
//! `conformance_findings::vulnerability_finding_roundtrips_unknown_fields`,
//! which proves the `#[serde(flatten)] other` catch-all in isolation by
//! mutating an in-memory sample; this test instead drives a file-based
//! fixture that combines an unknown field *and* an out-of-vocab `status_id`
//! in a single document.

use ocsf_core::findings::VulnerabilityFinding;

#[test]
fn event_with_unknown_top_level_fields_roundtrips() {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/vf_future.json")).unwrap();
    let vf: VulnerabilityFinding = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(&vf).unwrap(), raw);
}
