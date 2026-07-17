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
    /// Whether `ours` is an acceptable schemars rendering of something the
    /// oracle typed as `oracle`. Not symmetric: `Number`/`Integer` only
    /// matches oracle-number-vs-our-integer (a whole-number `float_t`
    /// modeled as an integer on our side is a narrowing, not a lossy one;
    /// the reverse — oracle wants a whole integer but we render a float —
    /// is a real mismatch and is caught).
    pub fn compatible(oracle: &Kind, ours: &Kind) -> bool {
        use Kind::{Any, Array, Integer, Number, Object, ObjectOrEnumRef};
        match (oracle, ours) {
            (Any, _) | (_, Any) => true,
            (ObjectOrEnumRef, Object | Integer | ObjectOrEnumRef) => true,
            (Object | Integer, ObjectOrEnumRef) => true,
            (Number, Integer) => true,
            (Array(a), Array(b)) => Kind::compatible(a, b),
            (a, b) => a == b,
        }
    }

    /// Derive the oracle's coarse kind from one attribute's raw definition
    /// (a value out of an api-compile document's `attributes` map).
    ///
    /// Dispatches on the `type` field (e.g. `"string_t"`, `"integer_t"`,
    /// `"object_t"`), not `type_name`. A scan of every vendored 1.8.0
    /// `conformance/api/{objects,classes}/*.json` file found `type_name` is
    /// a human caption that does not reliably say "String" for
    /// string-derived types — `email_t` -> "Email Address", `uuid_t` ->
    /// "UUID", `ip_t` -> "IP Address", `mac_t` -> "MAC Address", `file_hash_t`
    /// -> "Hash" — and is simply absent (`null`) for `object_t`. `type` is
    /// the stable, always-present machine discriminator; `is_array` (a
    /// sibling boolean) marks the attribute as a JSON array of that type.
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

    /// Derive our coarse kind from a schemars property schema, resolving
    /// `$ref`/`allOf`/`anyOf` wrappers against `defs` (the root schema's
    /// `definitions`) where possible.
    ///
    /// Handles every shape schemars 0.8 emits for our derive-macro types:
    /// a bare instance type (`{"type": "string"}`), an `Option<T>` (`{"type":
    /// ["string", "null"]}`), an array (`{"type": "array", "items": ...}`),
    /// a nested struct (`{"allOf": [{"$ref": "..."}]}`), an `Option` of a
    /// nested struct or `ocsf_enum!` id (`{"anyOf": [{"$ref": "..."}, {"type":
    /// "null"}]}`), a bare `$ref` (no doc comment on the field), and the
    /// permissive/no-type schema `serde_json::Value` fields render as.
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

    fn resolve_ref(reference: &str, defs: &Map<String, Schema>) -> Kind {
        reference
            .rsplit('/')
            .next()
            .and_then(|name| defs.get(name))
            .map(|target| Kind::from_schema(target, defs))
            .unwrap_or(Kind::ObjectOrEnumRef)
    }
}

/// Pull the `$ref` out of one `allOf`/`anyOf` member, ignoring non-`$ref`
/// siblings (namely the `{"type": "null"}` schemars adds for `Option<T>`
/// where `T` is itself `$ref`-shaped).
fn schema_reference(schema: &Schema) -> Option<&str> {
    match schema {
        Schema::Object(obj) => obj.reference.as_deref(),
        Schema::Bool(_) => None,
    }
}
