//! Shared helpers for the oracle conformance harness.
//!
//! Loads the vendored OCSF 1.8.0 API/JSON-Schema oracle (`conformance/` at
//! the workspace root) and asserts that our schemars-derived types match it.
//! This module is test-support code, not part of the library:
//! `unwrap`/`expect`/`panic!` are fine here. Some helpers below are unused
//! by `conformance_base.rs` (this task only proves `Product`/`Metadata`);
//! they exist for every later struct task's own `conformance_*.rs` binary,
//! which is expected and not dead code in practice.
//!
//! ## What `assert_object_matches`/`assert_class_matches` guarantee
//!
//! For a type `T` checked against oracle object/class `name`, a passing
//! test proves:
//!
//! - **Names**: `T`'s schemars property names are exactly the FULL-compile
//!   oracle's attribute names (nothing missing, nothing extra — the
//!   `#[serde(flatten)] other: Map<...>` catch-all doesn't count as a named
//!   property, so it can't paper over a name mismatch).
//! - **Required set**: `T`'s schema-required properties are exactly the
//!   BASE-compile oracle's `requirement: "required"` attributes (profile-
//!   conditional requirements are `validate()`'s job, not the type
//!   system's).
//! - **Coarse type compatibility**: for every property in both the FULL
//!   oracle and `T`'s schema, the oracle's coarse kind (string / integer /
//!   number / boolean / object / array-of-those, derived from the
//!   attribute's `type` field — see `kind::Kind::from_oracle_attr`) is
//!   compatible with `T`'s schemars-derived coarse kind (see
//!   `kind::Kind::from_schema` and `kind::Kind::compatible`). This catches
//!   e.g. a field typed `Option<String>` where the oracle says
//!   `integer_t`, or a scalar field where the oracle says the attribute is
//!   an array. `serde_json::Value` placeholder fields are always
//!   compatible (by design — they're the escape hatch for objects this
//!   codebase hasn't modeled as a real struct yet).
//! - **Enum vocabulary** (only where a test explicitly calls
//!   `assert_enum_matches`): an `ocsf_enum!` type's `KNOWN` values match
//!   the oracle's `enum` map for that attribute (minus `{0, 99}`).
//!
//! ## What it does NOT guarantee
//!
//! - **Exact integer width**: `i32` vs `i64` vs `u32` are all `Kind::Integer`
//!   to this harness; the oracle's `integer_t`/`long_t`/`timestamp_t`/
//!   `port_t` distinction is not checked.
//! - **String-format semantics**: `uuid_t`, `email_t`, `ip_t`, `datetime_t`,
//!   etc. are all `Kind::String`. Whether a `String` field actually holds a
//!   UUID/email/IP/RFC-3339 timestamp is unchecked by this harness.
//! - **Constraint enforcement**: `at_least_one`/`just_one` groups, enum
//!   value restriction beyond vocabulary comparison, and other normative
//!   rules are `Validate::validate()`'s responsibility, not this harness's.
//! - **Full JSON Schema equivalence**: this is a coarse smoke check, not a
//!   structural schema diff. `assert_valid_against_oracle_schema` (backed
//!   by the vendored `conformance/jsonschema/classes/*.json`) is the
//!   stronger check, but it only exists for classes, not objects.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use schemars::JsonSchema;
use schemars::schema::SchemaObject;
use serde_json::Value;

mod kind;
use kind::Kind;

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

/// Describe a non-object root schema shape for diagnostics: which JSON
/// Schema wrapper (`$ref`, `allOf`, `anyOf`, `oneOf`, a bare scalar/array
/// instance type, or an enum-valued schema) was found instead of the
/// expected `object` validation, so a future newtype or enum root — where
/// `T` isn't a plain struct — is diagnosable from the panic message alone.
fn describe_non_object_schema(schema: &SchemaObject) -> String {
    if let Some(reference) = &schema.reference {
        return format!("a bare $ref ({reference:?}, not wrapped in an object)");
    }
    if let Some(sub) = &schema.subschemas {
        if sub.all_of.is_some() {
            return "an allOf wrapper (likely a newtype/tuple struct around a $ref)".to_string();
        }
        if sub.any_of.is_some() {
            return "an anyOf wrapper (likely Option<$ref-typed> or an untagged enum)".to_string();
        }
        if sub.one_of.is_some() {
            return "a oneOf wrapper (likely a tagged/adjacently-tagged enum)".to_string();
        }
    }
    if let Some(instance_type) = &schema.instance_type {
        return format!(
            "a bare instance type {instance_type:?} with no object validation \
             (likely a newtype wrapping a scalar, or an enum root)"
        );
    }
    if schema.enum_values.is_some() {
        return "an enum-valued schema (\"enum\": [...]) with no object validation".to_string();
    }
    "an empty/unconstrained schema (serde_json::Value-like root)".to_string()
}

/// Everything `assert_matches` needs from `T`'s schemars-derived root
/// object schema: property names, the required set, and — resolved
/// against the root schema's `definitions` — each property's coarse
/// [`Kind`].
struct SchemaShape {
    properties: BTreeSet<String>,
    required: BTreeSet<String>,
    kinds: BTreeMap<String, Kind>,
}

fn schema_shape<T: JsonSchema>() -> SchemaShape {
    let root = schemars::schema_for!(T);
    let object = root.schema.object.as_ref().unwrap_or_else(|| {
        panic!(
            "schema for {} has no object validation (not a struct?); root schema shape: {}",
            T::schema_name(),
            describe_non_object_schema(&root.schema)
        )
    });
    let properties = object.properties.keys().cloned().collect();
    let required = object.required.clone();
    let kinds = object
        .properties
        .iter()
        .map(|(name, schema)| (name.clone(), Kind::from_schema(schema, &root.definitions)))
        .collect();
    SchemaShape {
        properties,
        required,
        kinds,
    }
}

/// The property names and required-field names of `T`'s schemars-derived
/// root object schema.
pub fn schema_props<T: JsonSchema>() -> (BTreeSet<String>, BTreeSet<String>) {
    let shape = schema_shape::<T>();
    (shape.properties, shape.required)
}

/// The mechanical gate for every struct task:
/// 1. Every FULL-compile oracle attribute name is one of our schema's
///    properties (missing field -> panic with the list).
/// 2. Every property of ours is a FULL-compile oracle attribute name,
///    strictly both ways (the flattened `other` map adds no named property).
/// 3. The BASE-compile oracle's required set equals our schema's required
///    set exactly (profile requirements are conditional and belong to
///    `validate()`, not the type system).
/// 4. For every property present in BOTH the FULL oracle and our schema,
///    the oracle's coarse type (`Kind::from_oracle_attr`) is compatible
///    with ours (`Kind::from_schema` + `Kind::compatible`) — see the
///    module doc for exactly what "compatible" does and does not mean.
fn assert_matches<T: JsonSchema>(kind: &str, name: &str, full: &Oracle, base: &Oracle) {
    let shape = schema_shape::<T>();
    let schema_properties = &shape.properties;
    let schema_required = &shape.required;
    let oracle_full_attributes = full.attributes();
    let oracle_full_attrs: BTreeSet<String> = oracle_full_attributes.keys().cloned().collect();
    let oracle_base_required = base.required();

    let missing: Vec<&String> = oracle_full_attrs.difference(schema_properties).collect();
    let extra: Vec<&String> = schema_properties.difference(&oracle_full_attrs).collect();
    if !missing.is_empty() || !extra.is_empty() {
        panic!(
            "{kind} {name:?}: schema properties do not match oracle FULL attributes.\n  \
             missing from schema (present in oracle, absent from our type): {missing:?}\n  \
             extra in schema (present in our type, absent from oracle):     {extra:?}"
        );
    }

    if schema_required != &oracle_base_required {
        panic!(
            "{kind} {name:?}: required set does not match oracle BASE compile.\n  \
             oracle (base) required: {oracle_base_required:?}\n  \
             schema required:        {schema_required:?}"
        );
    }

    // Coarse type-compatibility: for every property present in both the
    // FULL oracle and our schema (which, given the name check above, is
    // every property), the oracle's coarse kind must be compatible with
    // ours. Collected rather than fail-fast so one run surfaces every
    // mismatch, not just the first.
    let mismatches: Vec<String> = oracle_full_attributes
        .iter()
        .filter_map(|(attr, def)| {
            let ours = shape.kinds.get(attr)?;
            let oracle_kind = Kind::from_oracle_attr(def);
            if Kind::compatible(&oracle_kind, ours) {
                None
            } else {
                Some(format!(
                    "{attr}: oracle expects {oracle_kind}, schema has {ours}"
                ))
            }
        })
        .collect();
    if !mismatches.is_empty() {
        panic!(
            "{kind} {name:?}: attribute types do not match oracle FULL attributes.\n  {}",
            mismatches.join("\n  ")
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
