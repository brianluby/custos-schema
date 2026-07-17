use serde_json::Value;
use std::collections::BTreeSet;

/// Every object in the closure must be assigned a tier in docs/typed-objects.md,
/// and every object referenced by a *required* attribute of a supported class
/// or typed object must itself be typed.
#[test]
fn every_closure_object_has_a_tier_decision() {
    let report: Value =
        serde_json::from_str(include_str!("../../../conformance/closure-report.json")).unwrap();
    let table = include_str!("../../../docs/typed-objects.md");
    let missing: BTreeSet<&str> = report
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|name| !table.contains(&format!("| {name} |")))
        .collect();
    assert!(
        missing.is_empty(),
        "objects missing a tier decision: {missing:?}"
    );
}
