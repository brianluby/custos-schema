use anyhow::{Context, Result};
use ocsf_core::base::OcsfClass;
use ocsf_core::validation::ranges;
use ocsf_core::{discovery::*, findings::*};
use schemars::schema_for;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fs;

/// Collects generated schemas and OCSF UID constants for each supported event class.
///
/// # Examples
///
/// ```
/// let classes = all();
/// assert!(!classes.is_empty());
/// assert_eq!(classes[0].0, "vulnerability_finding");
/// ```
fn all() -> Vec<(&'static str, Value, u32, u32)>
fn all() -> Vec<(&'static str, Value, u32, u32)> {
    vec![
        (
            "vulnerability_finding",
            serde_json::to_value(schema_for!(VulnerabilityFinding))
                .expect("schemars output is always valid JSON"),
            VulnerabilityFinding::CLASS_UID,
            VulnerabilityFinding::CATEGORY_UID,
        ),
        (
            "compliance_finding",
            serde_json::to_value(schema_for!(ComplianceFinding))
                .expect("schemars output is always valid JSON"),
            ComplianceFinding::CLASS_UID,
            ComplianceFinding::CATEGORY_UID,
        ),
        (
            "detection_finding",
            serde_json::to_value(schema_for!(DetectionFinding))
                .expect("schemars output is always valid JSON"),
            DetectionFinding::CLASS_UID,
            DetectionFinding::CATEGORY_UID,
        ),
        (
            "application_security_posture_finding",
            serde_json::to_value(schema_for!(ApplicationSecurityPostureFinding))
                .expect("schemars output is always valid JSON"),
            ApplicationSecurityPostureFinding::CLASS_UID,
            ApplicationSecurityPostureFinding::CATEGORY_UID,
        ),
        (
            "inventory_info",
            serde_json::to_value(schema_for!(InventoryInfo))
                .expect("schemars output is always valid JSON"),
            InventoryInfo::CLASS_UID,
            InventoryInfo::CATEGORY_UID,
        ),
        (
            "user_inventory",
            serde_json::to_value(schema_for!(UserInventory))
                .expect("schemars output is always valid JSON"),
            UserInventory::CLASS_UID,
            UserInventory::CATEGORY_UID,
        ),
        (
            "software_info",
            serde_json::to_value(schema_for!(SoftwareInfo))
                .expect("schemars output is always valid JSON"),
            SoftwareInfo::CLASS_UID,
            SoftwareInfo::CATEGORY_UID,
        ),
        (
            "cloud_resources_inventory_info",
            serde_json::to_value(schema_for!(CloudResourcesInventoryInfo))
                .expect("schemars output is always valid JSON"),
            CloudResourcesInventoryInfo::CLASS_UID,
            CloudResourcesInventoryInfo::CATEGORY_UID,
        ),
    ]
}

/// Reads and parses a JSON file relative to the workspace root.
///
/// # Arguments
///
/// * `rel_path` - Path to the JSON file relative to the workspace root.
///
/// # Examples
///
/// ```
/// let oracle = read_oracle_json("conformance/api/classes/detection_finding.base.json")?;
/// assert!(oracle.is_object());
/// # Ok::<(), anyhow::Error>(())
/// ```
///
/// # Returns
///
/// The parsed JSON value.
fn read_oracle_json(rel_path: &str) -> Result<Value> {
    let path = crate::workspace_root().join(rel_path);
    serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))
}

/// Converts oracle field constraints into JSON Schema `allOf` clauses.
///
/// `at_least_one` constraints become `anyOf` clauses, while `just_one`
/// constraints become `oneOf` clauses. Returns an empty vector when the oracle
/// has no object-valued `constraints` field.
///
/// # Examples
///
/// ```
/// let oracle = serde_json::json!({
///     "constraints": {
///         "at_least_one": ["title", "description"],
///         "just_one": ["id", "uid"]
///     }
/// });
///
/// let all_of = constraint_all_of(&oracle);
/// assert_eq!(all_of.len(), 2);
/// ```
fn constraint_all_of(oracle: &Value) -> Vec<Value> {
    let Some(cons) = oracle.get("constraints").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut all_of = Vec::new();
    if let Some(list) = cons.get("at_least_one").and_then(Value::as_array) {
        all_of.push(json!({
            "anyOf": list.iter().map(present_non_null).collect::<Vec<_>>()
        }));
    }
    if let Some(list) = cons.get("just_one").and_then(Value::as_array) {
        all_of.push(json!({
            "oneOf": list.iter().map(present_non_null).collect::<Vec<_>>()
        }));
    }
    all_of
}

/// Builds a schema clause requiring an attribute to be present and contain a non-null value.
///
/// # Examples
///
/// ```
/// let clause = present_non_null(&serde_json::json!("name"));
/// assert_eq!(
///     clause,
///     serde_json::json!({
///         "required": ["name"],
///         "properties": {
///             "name": { "not": { "type": "null" } }
///         }
///     })
/// );
/// ```
///
/// # Arguments
///
/// * `attr` - The attribute name to require.
///
/// # Returns
///
/// A JSON Schema presence clause, or a basic required-property clause when `attr` is not a string.
fn present_non_null(attr: &Value) -> Value {
    let Some(name) = attr.as_str() else {
        // Non-string constraint member (not present in the vendored oracle);
        // degrade to a bare presence check rather than emitting a malformed
        // `properties` key.
        return json!({ "required": [attr] });
    };
    let mut properties = serde_json::Map::new();
    properties.insert(name.to_string(), json!({ "not": { "type": "null" } }));
    json!({
        "required": [name],
        "properties": properties,
    })
}

/// Injects oracle-defined root-class constraints into a generated JSON Schema.
///
/// Applies `at_least_one` and `just_one` constraints as `allOf` fragments. If the
/// oracle contains no supported constraints, the schema remains unchanged.
///
/// # Examples
///
/// ```
/// let oracle = serde_json::json!({
///     "constraints": { "at_least_one": ["a", "b"] }
/// });
/// let mut schema = serde_json::json!({});
///
/// inject_constraints(&oracle, &mut schema)?;
///
/// assert!(schema["allOf"].is_array());
/// # Ok::<(), anyhow::Error>(())
/// ```
fn inject_constraints(oracle: &Value, schema: &mut Value) -> Result<()> {
    let all_of = constraint_all_of(oracle);
    if !all_of.is_empty() {
        schema["allOf"] = Value::Array(all_of);
    }
    Ok(())
}

/// Maps a schemars definition name (as emitted for a nested OCSF object) to
/// its oracle object file stem, for the objects whose oracle definition
/// carries a `constraints` entry (`at_least_one` or `just_one`) that
/// schemars cannot derive from the struct alone. Not every class schema
/// embeds every one of these definitions — e.g. `compliance_finding` has no
/// `Vulnerability` definition, and only Findings classes have `KbArticle` —
/// so each entry below is applied only when the definition is present.
const CONSTRAINED_NESTED_OBJECTS: &[(&str, &str)] = &[
    ("Product", "product"),
    ("User", "user"),
    ("Group", "group"),
    ("Account", "account"),
    ("Organization", "organization"),
    ("Container", "container"),
    ("KbArticle", "kb_article"),
    ("Device", "device"),
    ("ResourceDetails", "resource_details"),
    ("Vulnerability", "vulnerability"),
];

/// Applies oracle-defined constraints to matching nested object definitions in a schema.
///
/// Schemas without a `definitions` object or without matching nested definitions are left unchanged.
///
/// # Examples
///
/// ```
/// let mut schema = serde_json::json!({});
/// inject_nested_object_constraints(&mut schema)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
fn inject_nested_object_constraints(schema: &mut Value) -> Result<()> {
    let Some(defs) = schema.get_mut("definitions").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    for (def_name, object_file) in CONSTRAINED_NESTED_OBJECTS {
        let Some(def) = defs.get_mut(*def_name) else {
            continue; // this class doesn't embed this object; nothing to do
        };
        let oracle = read_oracle_json(&format!("conformance/api/objects/{object_file}.base.json"))?;
        let all_of = constraint_all_of(&oracle);
        if !all_of.is_empty() {
            def["allOf"] = Value::Array(all_of);
        }
    }
    Ok(())
}

/// Adds class identity constraints and the normative `type_uid` expression to a schema.
///
/// Validates that the oracle's class and category identifiers match the supplied
/// [`OcsfClass`] constants. Returns an error when either identifier is missing,
/// non-integer, or mismatched.
///
/// # Examples
///
/// ```
/// use serde_json::json;
///
/// let oracle = json!({ "uid": 1, "category_uid": 2 });
/// let mut schema = json!({
///     "properties": {
///         "class_uid": {},
///         "category_uid": {},
///         "type_uid": {}
///     }
/// });
///
/// inject_class_uid_consts("example", &oracle, &mut schema, 1, 2)?;
///
/// assert_eq!(schema["properties"]["class_uid"]["const"], 1);
/// assert_eq!(schema["properties"]["category_uid"]["const"], 2);
/// # Ok::<(), anyhow::Error>(())
/// ```
fn inject_class_uid_consts(
    class: &str,
    oracle: &Value,
    schema: &mut Value,
    class_uid: u32,
    category_uid: u32,
) -> Result<()> {
    let oracle_uid = oracle
        .get("uid")
        .and_then(Value::as_u64)
        .with_context(|| format!("{class}: oracle class file has no integer top-level `uid`"))?;
    let oracle_category_uid = oracle
        .get("category_uid")
        .and_then(Value::as_u64)
        .with_context(|| {
            format!("{class}: oracle class file has no integer top-level `category_uid`")
        })?;
    anyhow::ensure!(
        oracle_uid == u64::from(class_uid),
        "{class}: oracle class uid {oracle_uid} disagrees with \
         ocsf_core's OcsfClass::CLASS_UID {class_uid} — the generated schema and the \
         Rust source of truth have drifted; fix one of them before regenerating"
    );
    anyhow::ensure!(
        oracle_category_uid == u64::from(category_uid),
        "{class}: oracle category_uid {oracle_category_uid} disagrees with \
         ocsf_core's OcsfClass::CATEGORY_UID {category_uid} — the generated schema and \
         the Rust source of truth have drifted; fix one of them before regenerating"
    );

    let props = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{class}: schema has no top-level `properties`"))?;
    if let Some(p) = props.get_mut("class_uid") {
        p["const"] = json!(class_uid);
    }
    if let Some(p) = props.get_mut("category_uid") {
        p["const"] = json!(category_uid);
    }
    if let Some(p) = props.get_mut("type_uid") {
        p["x-ocsf-type-uid"] = json!("class_uid * 100 + activity_id");
    }
    Ok(())
}

/// Adds documented scalar range constraints to the schema properties.
///
/// Applies the timezone offset range to every class and the impact score range
/// to detection-finding schemas.
///
/// # Examples
///
/// ```
/// let mut schema = serde_json::json!({
///     "properties": {
///         "timezone_offset": {}
///     }
/// });
///
/// inject_scalar_ranges("example", &mut schema);
///
/// assert!(schema["properties"]["timezone_offset"]["minimum"].is_number());
/// assert!(schema["properties"]["timezone_offset"]["maximum"].is_number());
/// ```
fn inject_scalar_ranges(class: &str, schema: &mut Value) {
    let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    apply_range(props, ranges::TIMEZONE_OFFSET);
    if class == DetectionFinding::CLASS_NAME {
        apply_range(props, ranges::IMPACT_SCORE);
    }
}

/// Applies an inclusive range to a matching schema property.
///
/// # Examples
///
/// ```
/// use serde_json::{json, Map};
///
/// let mut props = Map::new();
/// props.insert("score".to_owned(), json!({}));
///
/// apply_range(&mut props, ("score", 0, 100));
///
/// assert_eq!(props["score"]["minimum"], json!(0));
/// assert_eq!(props["score"]["maximum"], json!(100));
/// ```
fn apply_range(props: &mut Map<String, Value>, (attr, min, max): (&str, i32, i32)) {
    if let Some(p) = props.get_mut(attr) {
        p["minimum"] = json!(min);
        p["maximum"] = json!(max);
    }
}

/// Generates JSON Schema artifacts for all supported OCSF classes and optionally checks for drift.
///
/// In check mode, reports an error when generated schemas are missing, outdated, or stale.
/// Otherwise, writes the generated schemas and removes stale schema artifacts.
///
/// # Arguments
///
/// * `check` - When `true`, checks for drift without modifying the schemas directory.
///
/// # Examples
///
/// ```no_run
/// generate(true)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn generate(check: bool) -> Result<()> {
pub fn generate(check: bool) -> Result<()> {
    let schemas_dir = crate::workspace_root().join("schemas");
    if !check {
        // Only create the directory when we intend to write into it: `--check`
        // must not have the side effect of creating `schemas/` on a checkout
        // that doesn't have it yet (e.g. a clean clone before first build).
        fs::create_dir_all(&schemas_dir)?;
    }
    let mut drift = Vec::new();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for (class, mut schema, class_uid, category_uid) in all() {
        let oracle = read_oracle_json(&format!("conformance/api/classes/{class}.base.json"))?;
        inject_constraints(&oracle, &mut schema)?;
        inject_class_uid_consts(class, &oracle, &mut schema, class_uid, category_uid)?;
        inject_nested_object_constraints(&mut schema)?;
        inject_scalar_ranges(class, &mut schema);
        let file_name = format!("{class}.schema.json");
        expected.insert(file_name.clone());
        let path = schemas_dir.join(&file_name);
        let new = serde_json::to_string_pretty(&schema)? + "\n";
        let old = fs::read_to_string(&path).unwrap_or_default();
        if check {
            if old != new {
                drift.push(path.display().to_string());
            }
        } else {
            fs::write(&path, new)?;
            println!("wrote {}", path.display());
        }
    }

    // Reconcile stale artifacts: any `*.schema.json` in `schemas/` that no
    // longer corresponds to a current class (e.g. a class removed from the
    // list, or renamed) must not linger. In write mode it is deleted; in
    // `--check` mode an unknown file is drift, so CI fails until it is
    // regenerated away. Git provides rollback if a deletion was unintended.
    if schemas_dir.exists() {
        for entry in fs::read_dir(&schemas_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".schema.json") || expected.contains(&name) {
                continue;
            }
            let path = entry.path();
            if check {
                drift.push(path.display().to_string());
            } else {
                fs::remove_file(&path)?;
                println!("removed stale {}", path.display());
            }
        }
    }

    if check && !drift.is_empty() {
        anyhow::bail!("schema drift, run `cargo xtask schemas`: {drift:?}");
    }
    Ok(())
}
