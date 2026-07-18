//! Coarse type-kind derivation and compatibility for the conformance
//! harness's per-attribute type check. See the module doc in `mod.rs` for
//! what this does and does not guarantee.

use schemars::Map;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec};
use serde_json::Value;

/// A coarse JSON-value shape. Deliberately coarse: this exists to catch
/// "wrong category of value" (a string where the oracle wants an integer,
/// a scalar where it wants an array) — not to prove full JSON Schema
/// equivalence. See the module doc in `mod.rs` for the exact guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// No constraint either way: `serde_json::Value` on our side, `json_t`
    /// on the oracle side, or a schema shape with no discoverable type.
    /// Always compatible with anything.
    Any,
    String,
    Integer,
    Number,
    Boolean,
    Object,
    /// A `$ref`/`allOf`/`anyOf` wrapper whose target couldn't be resolved
    /// in the root schema's `definitions`. Shouldn't happen for our own
    /// schemars-derived types (every `$ref` we emit points at a sibling
    /// definition in the same root schema) but degrades safely rather than
    /// panicking. Compatible with both `Object` (a nested OCSF object) and
    /// `Integer` (an `ocsf_enum!` id, whose wire form is a plain integer).
    ObjectOrEnumRef,
    Array(Box<Kind>),
}

impl std::fmt::Display for Kind {
    /// Formats the kind as a stable, human-readable label.
    ///
    /// # Examples
    ///
    /// ```
    /// let kind = Kind::String;
    /// assert_eq!(kind.to_string(), "string");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Any => write!(f, "any"),
            Kind::String => write!(f, "string"),
            Kind::Integer => write!(f, "integer"),
            Kind::Number => write!(f, "number"),
            Kind::Boolean => write!(f, "boolean"),
            Kind::Object => write!(f, "object"),
            Kind::ObjectOrEnumRef => write!(f, "object-or-enum-ref"),
            Kind::Array(inner) => write!(f, "array<{inner}>"),
        }
    }
}

impl Kind {
    /// Determines whether an oracle-derived kind is compatible with a locally derived kind.
    ///
    /// Compatibility is asymmetric: `Any` on the local side accepts every oracle kind,
    /// while wrapper references can match object or integer kinds. Array element kinds
    /// are compared recursively.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(Kind::compatible(&Kind::String, &Kind::Any));
    /// assert!(Kind::compatible(&Kind::ObjectOrEnumRef, &Kind::Object));
    /// assert!(!Kind::compatible(&Kind::Number, &Kind::Integer));
    /// ```
    pub fn compatible(oracle: &Kind, ours: &Kind) -> bool {
        use Kind::{Any, Array, Integer, Object, ObjectOrEnumRef};
        match (oracle, ours) {
            (_, Any) => true,
            (ObjectOrEnumRef, Object | Integer | ObjectOrEnumRef) => true,
            (Object | Integer, ObjectOrEnumRef) => true,
            (Array(a), Array(b)) => Kind::compatible(a, b),
            (a, b) => a == b,
        }
    }

    /// Derives a coarse value kind from an oracle attribute definition.
    ///
    /// The `type` field determines the scalar kind, and `is_array` wraps it as an
    /// array kind when set to `true`.
    ///
    /// # Panics
    ///
    /// Panics when the `type` field is missing or unrecognized.
    ///
    /// # Examples
    ///
    /// ```
    /// let definition = serde_json::json!({
    ///     "type": "string_t",
    ///     "is_array": true
    /// });
    ///
    /// assert_eq!(
    ///     Kind::from_oracle_attr(&definition),
    ///     Kind::Array(Box::new(Kind::String))
    /// );
    /// ```
    pub fn from_oracle_attr(def: &Value) -> Kind {
    pub fn from_oracle_attr(def: &Value) -> Kind {
        let raw = def.get("type").and_then(Value::as_str).unwrap_or("");
        let scalar = match raw {
            "boolean_t" => Kind::Boolean,
            // long_t/port_t/timestamp_t are all whole-number wire types.
            "integer_t" | "long_t" | "port_t" | "timestamp_t" => Kind::Integer,
            "float_t" => Kind::Number,
            "json_t" => Kind::Any,
            "object_t" => Kind::Object,
            // Every OCSF 1.8.0 string-derived scalar type observed in the
            // vendored oracle. datetime_t is a formatted string (RFC 3339),
            // not a numeric timestamp - timestamp_t is the epoch-millis one.
            "string_t" | "datetime_t" | "email_t" | "file_hash_t" | "file_name_t"
            | "file_path_t" | "hostname_t" | "ip_t" | "mac_t" | "process_name_t"
            | "resource_uid_t" | "subnet_t" | "url_t" | "username_t" | "uuid_t" => Kind::String,
            other => panic!(
                "oracle attribute has unrecognized \"type\" {other:?}; extend the mapping in \
                 Kind::from_oracle_attr (tests/conformance/kind.rs) — this list was derived by \
                 scanning every vendored api/objects and api/classes file, so a new value here \
                 means the vendored oracle picked up a type this harness hasn't seen before"
            ),
        };
        if def
            .get("is_array")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            Kind::Array(Box::new(scalar))
        } else {
            scalar
        }
    }

    /// Derives a coarse value kind from a schemars schema, resolving references against the root definitions.
    ///
    /// Boolean schemas, schemas without type information, and schemas containing only `null` are treated as unconstrained.
    /// References embedded directly or within `allOf` or `anyOf` are resolved when their definitions are available. Array
    /// schemas include the derived kind of their elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use schemars::{schema::Schema, Map};
    ///
    /// let definitions = Map::new();
    /// assert_eq!(Kind::from_schema(&Schema::Bool(true), &definitions), Kind::Any);
    /// ```
    ///
    /// # Parameters
    ///
    /// * `schema` - The schemars schema to classify.
    /// * `defs` - The root schema definitions used to resolve references.
    ///
    /// # Returns
    ///
    /// The coarse kind represented by the schema.
    pub fn from_schema(schema: &Schema, defs: &Map<String, Schema>) -> Kind {
        let obj = match schema {
            Schema::Bool(_) => return Kind::Any, // `true`/`{}`: fully permissive
            Schema::Object(obj) => obj,
        };

        if let Some(reference) = &obj.reference {
            return Kind::resolve_ref(reference, defs);
        }
        if let Some(sub) = &obj.subschemas {
            let wrapped_ref = sub
                .all_of
                .iter()
                .chain(sub.any_of.iter())
                .flatten()
                .find_map(schema_reference);
            if let Some(target) = wrapped_ref {
                return Kind::resolve_ref(target, defs);
            }
        }

        let Some(instance_type) = &obj.instance_type else {
            return Kind::Any; // no $ref, no type keyword: Value-like schema
        };
        let types: Vec<InstanceType> = match instance_type {
            SingleOrVec::Single(t) => vec![**t],
            SingleOrVec::Vec(v) => v.clone(),
        };
        if types.contains(&InstanceType::Array) {
            return Kind::Array(Box::new(Kind::array_item_kind(obj, defs)));
        }
        match types.into_iter().find(|t| *t != InstanceType::Null) {
            Some(InstanceType::String) => Kind::String,
            Some(InstanceType::Integer) => Kind::Integer,
            Some(InstanceType::Number) => Kind::Number,
            Some(InstanceType::Boolean) => Kind::Boolean,
            Some(InstanceType::Object) => Kind::Object,
            // Only Null was present (or nothing recognizable): unconstrained.
            _ => Kind::Any,
        }
    }

    /// Determines the element kind for an array schema.
    ///
    /// Untyped or empty item definitions are treated as [`Kind::Any`].
    ///
    /// # Examples
    ///
    /// ```
    /// let obj = SchemaObject::default();
    /// let defs = schemars::Map::new();
    ///
    /// assert_eq!(array_item_kind(&obj, &defs), Kind::Any);
    /// ```
    fn array_item_kind(obj: &SchemaObject, defs: &Map<String, Schema>) -> Kind {
        let Some(items) = obj.array.as_ref().and_then(|a| a.items.as_ref()) else {
            return Kind::Any; // "items" omitted: heterogeneous/untyped array
        };
        match items {
            SingleOrVec::Single(item) => Kind::from_schema(item, defs),
            SingleOrVec::Vec(items) => items
                .first()
                .map_or(Kind::Any, |item| Kind::from_schema(item, defs)),
        }
    }

    /// Resolves a schema reference against the provided definitions.
    ///
    /// Unresolved references are represented as [`Kind::ObjectOrEnumRef`].
    ///
    /// # Examples
    ///
    /// ```
    /// let defs = Map::new();
    /// assert_eq!(
    ///     resolve_ref("#/definitions/Missing", &defs),
    ///     Kind::ObjectOrEnumRef
    /// );
    /// ```
    fn resolve_ref(reference: &str, defs: &Map<String, Schema>) -> Kind {
        reference
            .rsplit('/')
            .next()
            .and_then(|name| defs.get(name))
            .map(|target| Kind::from_schema(target, defs))
            .unwrap_or(Kind::ObjectOrEnumRef)
    }
}

/// Extracts a `$ref` value from a schema member.
///
/// Non-object schemas and object schemas without a reference return `None`.
///
/// # Examples
///
/// ```
/// use schemars::schema::{Schema, SchemaObject};
///
/// let schema = Schema::Object(SchemaObject {
///     reference: Some("#/definitions/Example".to_owned()),
///     ..Default::default()
/// });
///
/// assert_eq!(schema_reference(&schema), Some("#/definitions/Example"));
/// ```
///
/// # Returns
///
/// The referenced schema path, or `None` when the schema has no `$ref`.
fn schema_reference(schema: &Schema) -> Option<&str> {
    match schema {
        Schema::Object(obj) => obj.reference.as_deref(),
        Schema::Bool(_) => None,
    }
}
