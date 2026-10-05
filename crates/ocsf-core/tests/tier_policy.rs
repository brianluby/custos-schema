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

/// Resolves the workspace root from the crate's manifest directory at compile time.
///
/// # Examples
///
/// ```
/// let root = workspace_root();
/// assert!(root.is_absolute());
/// ```
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses the documented object tier table into an object-to-tier map.

///

/// Panics if the table contains an invalid tier, a blank object name, a duplicate

/// object, or no data rows.

///

/// # Examples

///

/// ```

/// let tiers = parse_tier_table();

/// assert!(tiers.values().all(|tier| tier == "typed" || tier == "json"));

/// ```
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

/// Loads and parses an oracle JSON file relative to the workspace root.
///
/// # Panics
///
/// Panics if the file cannot be read or does not contain valid JSON.
///
/// # Examples
///
/// ```
/// let oracle = load_oracle("conformance/closure-report.json");
/// assert!(oracle.is_object());
/// ```
fn load_oracle(relative: &str) -> Value {
    let path = workspace_root().join(relative);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read oracle {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse oracle {}: {e}", path.display()))
}

/// Extracts required attribute references from an oracle.
///
/// # Arguments
///
/// * `oracle` - Oracle JSON containing an `attributes` object.
///
/// # Returns
///
/// A vector of `(attribute_name, object_type)` pairs for required attributes
/// that reference another object.
///
/// # Examples
///
/// ```
/// let oracle = serde_json::json!({
///     "attributes": {
///         "parent": {
///             "requirement": "required",
///             "object_type": "example_object"
///         }
///     }
/// });
///
/// assert_eq!(
///     required_object_refs(&oracle),
///     vec![("parent".to_owned(), "example_object".to_owned())]
/// );
/// ```
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
