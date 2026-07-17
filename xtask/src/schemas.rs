use anyhow::{Context, Result};
use ocsf_core::base::OcsfClass;
use ocsf_core::validation::ranges;
use ocsf_core::{discovery::*, findings::*};
use schemars::schema_for;
use serde_json::{Map, Value, json};
use std::fs;

/// (class_name, generated schema, class_uid, category_uid) for every
/// supported event class. The UIDs come from each type's [`OcsfClass`]
/// trait consts — the Rust source of truth — so [`inject_class_uid_consts`]
/// can cross-check them against the oracle's class-level `uid`/
/// `category_uid` instead of hard-coding a second table that could drift
/// from the one already encoded in the generated types.
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

/// Read and parse a JSON file relative to the workspace root.
fn read_oracle_json(rel_path: &str) -> Result<Value> {
    let path = crate::workspace_root().join(rel_path);
    serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))
}

/// Build the `allOf` array encoding an oracle `constraints` object
/// (`at_least_one` -> `anyOf`, `just_one` -> `oneOf`), or an empty `Vec` if
/// `oracle` carries no `constraints`. Shared between class-level constraint
/// injection ([`inject_constraints`]) and nested-object-level constraint
/// injection ([`inject_nested_object_constraints`]) — the oracle shape is
/// identical for both classes and objects.
fn constraint_all_of(oracle: &Value) -> Vec<Value> {
    let Some(cons) = oracle.get("constraints").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut all_of = Vec::new();
    if let Some(list) = cons.get("at_least_one").and_then(Value::as_array) {
        all_of.push(json!({
            "anyOf": list.iter().map(|a| json!({"required": [a]})).collect::<Vec<_>>()
        }));
    }
    if let Some(list) = cons.get("just_one").and_then(Value::as_array) {
        all_of.push(json!({
            "oneOf": list.iter().map(|a| json!({"required": [a]})).collect::<Vec<_>>()
        }));
    }
    all_of
}

/// Inject OCSF root-class constraints schemars cannot express, read from the
/// oracle.
///
/// Oracle shape (verified against `conformance/api/classes/*.base.json`):
/// `constraints` is either `null` (most classes) or an object with an
/// `at_least_one` array of attribute names (currently the only constraint
/// kind present: `application_security_posture_finding` and
/// `cloud_resources_inventory_info`). `just_one` is not present in any
/// vendored class today but is handled the same way for forward
/// compatibility with future oracle syncs.
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

/// Inject the same class of oracle constraint as [`inject_constraints`], but
/// onto the nested object definitions schemars collects under the schema's
/// `definitions` map, per [`CONSTRAINED_NESTED_OBJECTS`].
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

/// Inject class-identity constraints schemars cannot derive from the struct
/// alone:
///
/// - `const` on `class_uid`/`category_uid`, from each class's [`OcsfClass`]
///   trait consts — cross-checked here against the oracle's top-level
///   `uid`/`category_uid` so the generated artifact and the Rust source of
///   truth cannot silently drift apart; a mismatch fails the generator with
///   a clear error rather than emitting an incorrect `const`.
/// - An `x-ocsf-type-uid` annotation on `type_uid` documenting its
///   normative arithmetic (`class_uid * 100 + activity_id`), which is not a
///   JSON Schema keyword and so cannot be expressed as a structural
///   constraint.
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

/// Inject `minimum`/`maximum` onto properties that carry a documented
/// scalar range in `ocsf_core::validation::ranges` — stricter than the
/// upstream OCSF JSON Schema (see that module's doc comment), but a
/// deliberate divergence `validate()` already enforces at the Rust level;
/// this brings the generated schema artifact in line with it.
/// `timezone_offset` is present on all 8 classes; `impact_score` only on
/// `detection_finding`.
fn inject_scalar_ranges(class: &str, schema: &mut Value) {
    let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    apply_range(props, ranges::TIMEZONE_OFFSET);
    if class == DetectionFinding::CLASS_NAME {
        apply_range(props, ranges::IMPACT_SCORE);
    }
}

/// Set `minimum`/`maximum` on `props[attr]` from an inclusive `(attr, min,
/// max)` range constant, if `attr` is one of `props`.
fn apply_range(props: &mut Map<String, Value>, (attr, min, max): (&str, i32, i32)) {
    if let Some(p) = props.get_mut(attr) {
        p["minimum"] = json!(min);
        p["maximum"] = json!(max);
    }
}

pub fn generate(check: bool) -> Result<()> {
    let schemas_dir = crate::workspace_root().join("schemas");
    if !check {
        // Only create the directory when we intend to write into it: `--check`
        // must not have the side effect of creating `schemas/` on a checkout
        // that doesn't have it yet (e.g. a clean clone before first build).
        fs::create_dir_all(&schemas_dir)?;
    }
    let mut drift = Vec::new();
    for (class, mut schema, class_uid, category_uid) in all() {
        let oracle = read_oracle_json(&format!("conformance/api/classes/{class}.base.json"))?;
        inject_constraints(&oracle, &mut schema)?;
        inject_class_uid_consts(class, &oracle, &mut schema, class_uid, category_uid)?;
        inject_nested_object_constraints(&mut schema)?;
        inject_scalar_ranges(class, &mut schema);
        let path = schemas_dir.join(format!("{class}.schema.json"));
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
    if check && !drift.is_empty() {
        anyhow::bail!("schema drift, run `cargo xtask schemas`: {drift:?}");
    }
    Ok(())
}
