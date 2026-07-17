//! Tier-policy conformance: `docs/typed-objects.md` assigns every object in
//! the closure a tier (`typed` | `json`), and the documented required-⇒-typed
//! rule is enforced mechanically against the oracle compiles rather than by
//! substring inspection.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// The 8 supported event classes (mirrors `xtask/src/oracle.rs` `CLASSES`).
const CLASSES: &[&str] = &[
    "vulnerability_finding",
    "compliance_finding",
    "detection_finding",
    "application_security_posture_finding",
    "inventory_info",
    "user_inventory",
    "software_info",
    "cloud_resources_inventory_info",
];

/// Workspace root, resolved from the crate manifest dir at compile time.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parse the `docs/typed-objects.md` tier table into `object -> tier`.
///
/// Only genuine data rows are accepted: exactly three `|`-delimited cells,
/// a non-blank object name, and a tier that is exactly `typed` or `json`.
/// The header (`| object | tier | ... |`) and separator (`| --- | ... |`)
/// rows are rejected by the tier whitelist, and any malformed/blank cell
/// fails the test loudly rather than being silently skipped.
fn parse_tier_table() -> BTreeMap<String, String> {
    let doc = include_str!("../../../docs/typed-objects.md");
    let mut map = BTreeMap::new();
    let mut in_table = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        // Split the pipe-delimited row, dropping the empty leading/trailing
        // cells produced by the outer pipes.
        let cells: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() != 3 {
            continue;
        }
        let (name, tier) = (cells[0], cells[1]);
        // Skip the header (`| object | tier | rationale |`, keyed on the tier
        // cell so the legitimate data row named "object" is not swallowed) and
        // the `--- | --- | ---` separator.
        if tier == "tier" || name.chars().all(|c| c == '-') {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        assert!(!name.is_empty(), "tier table row has a blank object name");
        assert!(
            tier == "typed" || tier == "json",
            "object {name:?} has invalid tier {tier:?}; must be \"typed\" or \"json\""
        );
        let previous = map.insert(name.to_string(), tier.to_string());
        assert!(
            previous.is_none(),
            "object {name:?} listed twice in the tier table"
        );
    }
    assert!(!map.is_empty(), "parsed no tier rows from typed-objects.md");
    map
}

fn load_oracle(relative: &str) -> Value {
    let path = workspace_root().join(relative);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read oracle {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse oracle {}: {e}", path.display()))
}

/// The `(attribute, object_type)` pairs whose `requirement` is `"required"`
/// and which carry an `object_type` (i.e. reference another OCSF object).
fn required_object_refs(oracle: &Value) -> Vec<(String, String)> {
    let Some(attrs) = oracle.get("attributes").and_then(Value::as_object) else {
        return Vec::new();
    };
    attrs
        .iter()
        .filter(|(_, def)| def.get("requirement").and_then(Value::as_str) == Some("required"))
        .filter_map(|(name, def)| {
            def.get("object_type")
                .and_then(Value::as_str)
                .map(|ot| (name.clone(), ot.to_string()))
        })
        .collect()
}

/// Every object reachable in the closure must have a tier decision.
#[test]
fn every_closure_object_has_a_tier_decision() {
    let report: Value =
        serde_json::from_str(include_str!("../../../conformance/closure-report.json")).unwrap();
    let tiers = parse_tier_table();
    let missing: Vec<&str> = report
        .as_object()
        .expect("closure report is an object map")
        .keys()
        .map(String::as_str)
        .filter(|name| !tiers.contains_key(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "closure objects missing a tier decision: {missing:?}"
    );
}

/// The documented required-⇒-typed rule, enforced mechanically: for each of
/// the 8 supported classes AND each `typed`-tier object, every attribute
/// marked `"requirement": "required"` that carries an `object_type` must
/// resolve to a `typed` row.
#[test]
fn required_object_references_are_typed() {
    let tiers = parse_tier_table();
    let mut violations: Vec<String> = Vec::new();

    let mut check = |source: &str, oracle: &Value| {
        for (attr, object_type) in required_object_refs(oracle) {
            match tiers.get(&object_type) {
                Some(tier) if tier == "typed" => {}
                Some(tier) => violations.push(format!(
                    "{source}: required attribute {attr:?} references object {object_type:?} \
                     which is tier {tier:?}, not \"typed\""
                )),
                None => violations.push(format!(
                    "{source}: required attribute {attr:?} references object {object_type:?} \
                     which has no tier decision"
                )),
            }
        }
    };

    for class in CLASSES {
        let oracle = load_oracle(&format!("conformance/api/classes/{class}.base.json"));
        check(&format!("class {class}"), &oracle);
    }
    for (object, tier) in &tiers {
        if tier != "typed" {
            continue;
        }
        let oracle = load_oracle(&format!("conformance/api/objects/{object}.base.json"));
        check(&format!("object {object}"), &oracle);
    }

    assert!(
        violations.is_empty(),
        "required-⇒-typed rule violated:\n  {}",
        violations.join("\n  ")
    );
}
