use anyhow::{Context, Result};
use schemars::schema_for;
use serde_json::{Value, json};
use std::fs;

/// (class_name, generated schema) for every supported event class.
fn all() -> Vec<(&'static str, Value)> {
    use ocsf_core::{discovery::*, findings::*};
    vec![
        (
            "vulnerability_finding",
            serde_json::to_value(schema_for!(VulnerabilityFinding))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "compliance_finding",
            serde_json::to_value(schema_for!(ComplianceFinding))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "detection_finding",
            serde_json::to_value(schema_for!(DetectionFinding))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "application_security_posture_finding",
            serde_json::to_value(schema_for!(ApplicationSecurityPostureFinding))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "inventory_info",
            serde_json::to_value(schema_for!(InventoryInfo))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "user_inventory",
            serde_json::to_value(schema_for!(UserInventory))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "software_info",
            serde_json::to_value(schema_for!(SoftwareInfo))
                .expect("schemars output is always valid JSON"),
        ),
        (
            "cloud_resources_inventory_info",
            serde_json::to_value(schema_for!(CloudResourcesInventoryInfo))
                .expect("schemars output is always valid JSON"),
        ),
    ]
}

/// Inject OCSF constraints schemars cannot express, read from the oracle.
///
/// Oracle shape (verified against `conformance/api/classes/*.base.json`):
/// `constraints` is either `null` (most classes) or an object with an
/// `at_least_one` array of attribute names (currently the only constraint
/// kind present: `application_security_posture_finding` and
/// `cloud_resources_inventory_info`). `just_one` is not present in any
/// vendored class today but is handled the same way for forward
/// compatibility with future oracle syncs.
fn inject_constraints(class: &str, schema: &mut Value) -> Result<()> {
    let oracle_path =
        crate::workspace_root().join(format!("conformance/api/classes/{class}.base.json"));
    let oracle: Value = serde_json::from_str(
        &fs::read_to_string(&oracle_path)
            .with_context(|| format!("reading {}", oracle_path.display()))?,
    )
    .with_context(|| format!("parsing {}", oracle_path.display()))?;
    let Some(cons) = oracle.get("constraints").and_then(Value::as_object) else {
        return Ok(());
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
    if !all_of.is_empty() {
        schema["allOf"] = Value::Array(all_of);
    }
    Ok(())
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
    for (class, mut schema) in all() {
        inject_constraints(class, &mut schema)?;
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
