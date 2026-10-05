use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validation::{Validate, ValidationReport, check_other_collisions};

/// OCSF `product` object: describes characteristics of a software product.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Product {
    /// The name of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The name of the vendor of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    /// The version of the product, as defined by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The Common Platform Enumeration (CPE) name of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe_name: Option<String>,
    /// The feature that reported the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<serde_json::Value>,
    /// The two letter lower case language code (ISO 639-1) of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// The installation path of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The unique identifier of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The URL pointing towards the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_string: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`]: inserting a key that names a modeled field
    /// (e.g. `other["name"]`) is invalid — see [`check_other_collisions`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Product {
    /// Modeled wire-name set (every field except the flattened `other`),
    /// pinned to the schemars property set by the conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "name",
        "vendor_name",
        "version",
        "cpe_name",
        "feature",
        "lang",
        "path",
        "uid",
        "url_string",
    ];

    /// Constructs a `Product` with the specified name and default values for all other fields.
    ///
    /// # Examples
    ///
    /// ```
    /// let product = Product::named("trivy");
    /// assert_eq!(product.name.as_deref(), Some("trivy"));
    /// assert!(product.vendor_name.is_none());
    /// ```
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }
}

impl Validate for Product {
    /// Validates the product's required identity fields and extension keys.
    ///
    /// # Returns
    ///
    /// A validation report that is invalid when both `name` and `uid` are absent
    /// or when an extension key collides with a modeled field name.
    ///
    /// # Examples
    ///
    /// ```
    /// let product = Product::default();
    /// let report = product.validate();
    ///
    /// assert!(!report.is_valid());
    /// ```
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("name", self.name.is_some()), ("uid", self.uid.is_some())]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_sets_name_and_defaults_rest() {
        let p = Product::named("trivy");
        assert_eq!(p.name.as_deref(), Some("trivy"));
        assert_eq!(p.vendor_name, None);
    }

    #[test]
    fn roundtrips_unknown_fields() {
        let json = r#"{"name":"x","future_field":{"a":1}}"#;
        let p: Product = serde_json::from_str(json).unwrap();
        assert_eq!(p.other["future_field"]["a"], 1);
        let out = serde_json::to_value(&p).unwrap();
        assert_eq!(out["future_field"]["a"], 1);
        assert!(out.get("uid").is_none());
    }

    #[test]
    fn at_least_one_name_or_uid_enforced() {
        use crate::validation::Validate;
        assert!(!Product::default().validate().is_valid());
        assert!(Product::named("trivy").validate().is_valid());
        let by_uid = Product {
            uid: Some("p-1".into()),
            ..Default::default()
        };
        assert!(by_uid.validate().is_valid());
    }

    #[test]
    fn extension_key_collision_is_invalid() {
        use crate::validation::Validate;
        // A modeled key can only reach `other` via a programmatic insert
        // (serde routes a real `uid` field to the modeled slot, not `other`).
        let mut p = Product::named("x");
        p.other.insert("uid".to_string(), serde_json::Value::Null);
        let report = p.validate();
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| e.attribute == "other"));
    }
}
