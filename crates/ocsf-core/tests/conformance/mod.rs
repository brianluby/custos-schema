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
    /// Loads and parses an oracle JSON document from the conformance directory.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be read or contains invalid JSON.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let oracle = Oracle::load("api/objects/example.full.json");
    /// assert!(oracle.attributes().len() >= 0);
    /// ```
    fn load(relative_path: &str) -> Oracle {
        let path = format!("{CONFORMANCE_DIR}/{relative_path}");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read oracle file {path}: {e}"));
        let value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("failed to parse oracle file {path}: {e}"));
        Oracle { value }
    }

    /// Loads the base oracle document for an OCSF object.
    ///
    /// # Arguments
    ///
    /// * `name` - The object name used to locate `api/objects/<name>.base.json`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let oracle = Oracle::object_base("account");
    /// let attributes = oracle.attributes();
    /// ```
    ///
    /// Returns the parsed base oracle document.
    pub fn object_base(name: &str) -> Oracle {
        Self::load(&format!("api/objects/{name}.base.json"))
    }

    /// Loads the full oracle document for an OCSF object.
    ///
    /// # Parameters
    ///
    /// * `name` - Object name used to locate the oracle document.
    ///
    /// # Examples
    ///
    /// ```
    /// let oracle = Oracle::object_full("account");
    /// ```
    pub fn object_full(name: &str) -> Oracle {
        Self::load(&format!("api/objects/{name}.full.json"))
    }

    /// Loads the base oracle document for an OCSF class.
    ///
    /// # Arguments
    ///
    /// * `name` - The class name used to locate the oracle document.
    ///
    /// # Returns
    ///
    /// The parsed base oracle document.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let oracle = Oracle::class_base("file_activity");
    /// ```
    ///
    pub fn class_base(name: &str) -> Oracle {
        Self::load(&format!("api/classes/{name}.base.json"))
    }

    /// Loads the full oracle document for an OCSF class.
    ///
    /// # Examples
    ///
    /// ```
    /// let oracle = Oracle::class_full("activity");
    /// let attributes = oracle.attributes();
    /// assert!(!attributes.is_empty());
    /// ```
    ///
    /// `name` is the OCSF class name.
    ///
    /// # Returns
    ///
    /// The parsed full class oracle document.
    pub fn class_full(name: &str) -> Oracle {
        Self::load(&format!("api/classes/{name}.full.json"))
    }

    /// Copies the raw definitions of all attributes in the oracle document.
    ///
    /// Panics if the document does not contain an `attributes` object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let oracle = Oracle::object_base("example");
    /// let attributes = oracle.attributes();
    /// assert!(attributes.contains_key("name"));
    /// ```
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

    /// Collects the integer keys from an attribute's oracle `enum` map.
    ///
    /// # Examples
    ///
    /// ```
    /// let oracle = Oracle::class_full("base_event");
    /// let values = oracle.enum_values("severity_id");
    ///
    /// assert!(values.contains(&0));
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the attribute has no enum map or an enum key cannot be parsed as an integer.
    pub fn enum_values(&self, attr: &str) -> BTreeSet<i32>
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

    /// Retrieves the oracle document's raw `constraints` member.
    ///
    /// Returns `Value::Null` when the document does not define constraints.
    ///
    /// # Examples
    ///
    /// ```
    /// let constraints = Oracle::object_base("file").constraints();
    /// ```
    pub fn constraints(&self) -> Value {
        self.value
            .get("constraints")
            .cloned()
            .unwrap_or(Value::Null)
    }
}

/// Describes why a root schema does not contain object validation.
///
/// # Examples
///
/// ```
/// let description = describe_non_object_schema(&schemars::schema::SchemaObject::default());
/// assert!(description.contains("empty/unconstrained"));
/// ```
fn describe_non_object_schema(schema: &SchemaObject) -> String
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

/// Extracts the property names, required fields, and coarse property kinds from a type's JSON schema.
///
/// # Panics
///
/// Panics if the generated schema does not define object validation.
///
/// # Examples
///
/// ```
/// #[derive(schemars::JsonSchema)]
/// struct Event {
///     id: String,
/// }
///
/// let shape = schema_shape::<Event>();
/// assert!(shape.properties.contains("id"));
/// ```
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

/// Retrieves the property and required-field names from `T`'s root object schema.
///
/// # Examples
///
/// ```
/// #[derive(schemars::JsonSchema)]
/// struct Event {
///     id: String,
/// }
///
/// let (properties, required) = schema_props::<Event>();
/// assert!(properties.contains("id"));
/// assert!(required.contains("id"));
/// ```
pub fn schema_props<T: JsonSchema>() -> (BTreeSet<String>, BTreeSet<String>) {
    let shape = schema_shape::<T>();
    (shape.properties, shape.required)
}

/// Compares a modeled schema shape with the corresponding OCSF oracle definitions.
///
/// The comparison verifies exact property names, required attributes, and compatible
/// coarse attribute kinds between the schema and the FULL and BASE oracle documents.
///
/// # Panics
///
/// Panics when property names, required attributes, or attribute kinds differ from
/// the oracle definitions.
///
/// # Examples
///
/// ```ignore
/// assert_matches::<MyEvent>("class", "my_event", &full_oracle, &base_oracle);
/// ```
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

/// Verifies that a modeled object schema matches its vendored OCSF oracle definition.
///
/// # Examples
///
/// ```ignore
/// assert_object_matches::<MyObject>("my_object");
/// ```
pub fn assert_object_matches<T: JsonSchema>(name: &str) {
pub fn assert_object_matches<T: JsonSchema>(name: &str) {
    assert_matches::<T>(
        "object",
        name,
        &Oracle::object_full(name),
        &Oracle::object_base(name),
    );
}

/// Verifies that a modeled class matches the corresponding OCSF oracle schema.
///
/// # Examples
///
/// ```no_run
/// # use schemars::JsonSchema;
/// # #[derive(JsonSchema)]
/// # struct ExampleClass;
/// assert_class_matches::<ExampleClass>("example");
/// ```
pub fn assert_class_matches<T: JsonSchema>(name: &str) {
    assert_matches::<T>(
        "class",
        name,
        &Oracle::class_full(name),
        &Oracle::class_base(name),
    );
}

/// Verifies that a type's declared field names match its schemars-derived properties.
///
/// # Examples
///
/// ```
/// #[derive(schemars::JsonSchema)]
/// struct Event {
///     id: String,
/// }
///
/// assert_field_names_match::<Event>("object", "Event", &["id"]);
/// ```
///
/// # Panics
///
/// Panics when `field_names` differs from the type's schema properties.
pub fn assert_field_names_match<T: JsonSchema>(kind: &str, name: &str, field_names: &[&str]) {
pub fn assert_field_names_match<T: JsonSchema>(kind: &str, name: &str, field_names: &[&str]) {
    let (properties, _required) = schema_props::<T>();
    let declared: BTreeSet<String> = field_names.iter().map(|s| (*s).to_string()).collect();
    if declared != properties {
        let missing: Vec<&String> = properties.difference(&declared).collect();
        let extra: Vec<&String> = declared.difference(&properties).collect();
        panic!(
            "{kind} {name:?}: FIELD_NAMES does not match the schemars property set.\n  \
             missing from FIELD_NAMES (schema has, const lacks): {missing:?}\n  \
             extra in FIELD_NAMES (const has, schema lacks):     {extra:?}"
        );
    }
}

/// Verifies that an enum's known values match the oracle vocabulary, excluding the

/// reserved `0` and `99` values.

///

/// # Examples

///

/// ```rust,no_run

/// let oracle = Oracle::object_full("file");

/// assert_enum_matches(&[0, 1, 2], &oracle, "type_id");

/// ```
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

/// Validates an event against a vendored class and variant JSON Schema oracle.
///
/// # Panics
///
/// Panics if the oracle cannot be read, parsed, or compiled, or if the event
/// fails validation.
///
/// # Examples
///
/// ```
/// let event = serde_json::json!({});
/// assert_valid_against_oracle_schema(&event, "network_activity", "base");
/// ```
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
