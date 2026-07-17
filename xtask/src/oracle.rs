use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;

const VERSION: &str = "1.8.0";
const FULL_PROFILES: &str = "cloud,container,host,datetime,security_control";
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

fn fetch(url: &str) -> Result<Value> {
    let body: Value = ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?
        .into_json()?;
    Ok(body)
}

fn write(path: &str, value: &Value) -> Result<()> {
    let p = crate::workspace_root().join(path);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&p, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

/// Collect `object_type` references from a compiled class/object definition.
fn object_refs(def: &Value) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    if let Some(attrs) = def.get("attributes").and_then(Value::as_object) {
        for attr in attrs.values() {
            if let Some(t) = attr.get("object_type").and_then(Value::as_str) {
                refs.insert(t.to_string());
            }
        }
    }
    refs
}

pub fn sync() -> Result<()> {
    let api = format!("https://schema.ocsf.io/api/{VERSION}");
    let js = format!("https://schema.ocsf.io/schema/{VERSION}");
    // referrers: object name -> set of class/object names that reference it
    let mut referrers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    // Clear the managed conformance API and JSON Schema trees before
    // re-vendoring so classes/objects removed upstream (or dropped from
    // `CLASSES`) do not linger as stale files. This is an in-place refresh,
    // not a transactional staging swap: a failed fetch partway through can
    // leave the trees partially rewritten. That is an accepted trade-off —
    // git provides rollback (`git checkout conformance/`) if a sync aborts or
    // misbehaves; full transactional staging is deliberately not implemented.
    for managed in ["conformance/api", "conformance/jsonschema"] {
        let dir = crate::workspace_root().join(managed);
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("clearing {}", dir.display()))?;
        }
    }

    for class in CLASSES {
        let base = fetch(&format!("{api}/classes/{class}?profiles="))?;
        let full = fetch(&format!("{api}/classes/{class}?profiles={FULL_PROFILES}"))?;
        write(&format!("conformance/api/classes/{class}.base.json"), &base)?;
        write(&format!("conformance/api/classes/{class}.full.json"), &full)?;
        let sbase = fetch(&format!("{js}/classes/{class}?profiles="))?;
        let sfull = fetch(&format!("{js}/classes/{class}?profiles={FULL_PROFILES}"))?;
        write(
            &format!("conformance/jsonschema/classes/{class}.base.json"),
            &sbase,
        )?;
        write(
            &format!("conformance/jsonschema/classes/{class}.full.json"),
            &sfull,
        )?;
        for r in object_refs(&full) {
            referrers
                .entry(r.clone())
                .or_default()
                .insert(class.to_string());
            if seen.insert(r.clone()) {
                queue.push_back(r);
            }
        }
    }

    while let Some(name) = queue.pop_front() {
        let base = fetch(&format!("{api}/objects/{name}?profiles="))?;
        write(&format!("conformance/api/objects/{name}.base.json"), &base)?;
        let def = fetch(&format!("{api}/objects/{name}?profiles={FULL_PROFILES}"))?;
        write(&format!("conformance/api/objects/{name}.full.json"), &def)?;
        for r in object_refs(&def) {
            referrers.entry(r.clone()).or_default().insert(name.clone());
            if seen.insert(r.clone()) {
                queue.push_back(r);
            }
        }
        println!("vendored object: {name}");
    }

    let report: Value = serde_json::to_value(
        referrers
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().cloned().collect::<Vec<_>>()))
            .collect::<BTreeMap<_, _>>(),
    )?;
    write("conformance/closure-report.json", &report)?;
    println!("closure size: {} objects", seen.len());
    Ok(())
}
