//! Shared helpers for the oracle conformance harness.
//!
//! Loads the vendored OCSF 1.8.0 API/JSON-Schema oracle (`conformance/` at
//! the workspace root) and asserts that our schemars-derived types match it
//! exactly. This module is test-support code, not part of the library:
//! `unwrap`/`expect`/`panic!` are fine here. Some helpers below are unused
//! by `conformance_base.rs` (this task only proves `Product`/`Metadata`);
//! they exist for every later struct task's own `conformance_*.rs` binary,
//! which is expected and not dead code in practice.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use schemars::JsonSchema;
use serde_json::Value;

/// Root of the vendored oracle checkout. Tests run with CWD =
/// `crates/ocsf-core`, so this is resolved from the crate's manifest dir at
/// compile time rather than assumed from the process's working directory.
const CONFORMANCE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance");

/// A single loaded oracle document: one OCSF API-compile JSON file (an
/// `attributes` map plus surrounding metadata) for one object or class.
pub struct Oracle {
    value: Value,
}

impl Oracle {
    fn load(relative_path: &str) -> Oracle {
        let path = format!("{CONFORMANCE_DIR}/{relative_path}");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read oracle file {path}: {e}"));
        let value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("failed to parse oracle file {path}: {e}"));
        Oracle { value }
    }

    /// `conformance/api/objects/<name>.base.json`
    pub fn object_base(name: &str) -> Oracle {
        Self::load(&format!("api/objects/{name}.base.json"))
    }

    /// `conformance/api/objects/<name>.full.json`
    pub fn object_full(name: &str) -> Oracle {
        Self::load(&format!("api/objects/{name}.full.json"))
    }

    /// `conformance/api/classes/<name>.base.json`
    pub fn class_base(name: &str) -> Oracle {
        Self::load(&format!("api/classes/{name}.base.json"))
    }

    /// `conformance/api/classes/<name>.full.json`
    pub fn class_full(name: &str) -> Oracle {
        Self::load(&format!("api/classes/{name}.full.json"))
    }

    /// The `attributes` map: attribute name -> its raw oracle definition.
    pub fn attributes(&self) -> BTreeMap<String, Value> {
        self.value
            .get("attributes")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("oracle document has no \"attributes\" object"))
            .iter()
            .map(|(name, def)| (name.clone(), def.clone()))
            .collect()
    }

    /// Attribute names whose `requirement` is `"required"`.
    pub fn required(&self) -> BTreeSet<String> {
        self.attributes()
            .into_iter()
            .filter(|(_, def)| def.get("requirement").and_then(Value::as_str) == Some("required"))
            .map(|(name, _)| name)
            .collect()
    }

    /// The integer keys of `attr`'s `enum` map, e.g. `severity_id` ->
    /// `{0, 1, 2, 3, 4, 5, 6, 99}`.
    pub fn enum_values(&self, attr: &str) -> BTreeSet<i32> {
        self.value
            .get("attributes")
            .and_then(|attrs| attrs.get(attr))
            .and_then(|def| def.get("enum"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("oracle has no \"enum\" map for attribute {attr:?}"))
            .keys()
            .map(|k| {
                k.parse::<i32>()
                    .unwrap_or_else(|e| panic!("enum key {k:?} on {attr:?} is not an integer: {e}"))
            })
            .collect()
    }

    /// The raw `constraints` member (e.g. `at_least_one`), or `Value::Null`
    /// if the oracle document has none.
    pub fn constraints(&self) -> Value {
        self.value
            .get("constraints")
            .cloned()
            .unwrap_or(Value::Null)
    }
}

/// The property names and required-field names of `T`'s schemars-derived
/// root object schema.
pub fn schema_props<T: JsonSchema>() -> (BTreeSet<String>, BTreeSet<String>) {
    let root = schemars::schema_for!(T);
    let object = root.schema.object.unwrap_or_else(|| {
        panic!(
            "schema for {} has no object validation (not a struct?)",
            T::schema_name()
        )
    });
    let properties = object.properties.keys().cloned().collect();
    (properties, object.required)
}

/// The mechanical gate for every struct task:
/// 1. Every FULL-compile oracle attribute name is one of our schema's
///    properties (missing field -> panic with the list).
/// 2. Every property of ours is a FULL-compile oracle attribute name,
///    strictly both ways (the flattened `other` map adds no named property).
/// 3. The BASE-compile oracle's required set equals our schema's required
///    set exactly (profile requirements are conditional and belong to
///    `validate()`, not the type system).
fn assert_matches<T: JsonSchema>(kind: &str, name: &str, full: &Oracle, base: &Oracle) {
    let (schema_properties, schema_required) = schema_props::<T>();
    let oracle_full_attrs: BTreeSet<String> = full.attributes().into_keys().collect();
    let oracle_base_required = base.required();

    let missing: Vec<&String> = oracle_full_attrs.difference(&schema_properties).collect();
    let extra: Vec<&String> = schema_properties.difference(&oracle_full_attrs).collect();
    if !missing.is_empty() || !extra.is_empty() {
        panic!(
            "{kind} {name:?}: schema properties do not match oracle FULL attributes.\n  \
             missing from schema (present in oracle, absent from our type): {missing:?}\n  \
             extra in schema (present in our type, absent from oracle):     {extra:?}"
        );
    }

    if schema_required != oracle_base_required {
        panic!(
            "{kind} {name:?}: required set does not match oracle BASE compile.\n  \
             oracle (base) required: {oracle_base_required:?}\n  \
             schema required:        {schema_required:?}"
        );
    }
}

/// `objects/<name>.{base,full}.json`
pub fn assert_object_matches<T: JsonSchema>(name: &str) {
    assert_matches::<T>(
        "object",
        name,
        &Oracle::object_full(name),
        &Oracle::object_base(name),
    );
}

/// `classes/<name>.{base,full}.json`
pub fn assert_class_matches<T: JsonSchema>(name: &str) {
    assert_matches::<T>(
        "class",
        name,
        &Oracle::class_full(name),
        &Oracle::class_base(name),
    );
}

/// `known` must equal the oracle's enum values for `attr`, minus `{0, 99}`
/// (Unknown/Other are macro-provided; some OCSF enums omit them upstream,
/// tolerated because `Unrecognized` still accepts the value on the wire).
pub fn assert_enum_matches(known: &[i32], oracle: &Oracle, attr: &str) {
    let known: BTreeSet<i32> = known.iter().copied().collect();
    let mut expected = oracle.enum_values(attr);
    expected.remove(&0);
    expected.remove(&99);
    if known != expected {
        panic!(
            "enum attribute {attr:?}: KNOWN {known:?} does not match oracle enum values \
             (minus {{0, 99}}) {expected:?}"
        );
    }
}

/// Validate `event` against `conformance/jsonschema/classes/<class>.<variant>.json`
/// (`variant` = `"base"` | `"full"`), panicking with the joined error
/// messages on failure.
pub fn assert_valid_against_oracle_schema(event: &Value, class: &str, variant: &str) {
    let path = format!("{CONFORMANCE_DIR}/jsonschema/classes/{class}.{variant}.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read jsonschema oracle {path}: {e}"));
    let schema: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse jsonschema oracle {path}: {e}"));
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|e| panic!("invalid oracle jsonschema {path}: {e}"));
    let errors: Vec<String> = validator
        .iter_errors(event)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        panic!(
            "event failed validation against {class}.{variant} jsonschema oracle:\n{}",
            errors.join("\n")
        );
    }
}
