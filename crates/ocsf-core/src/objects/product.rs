use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Product {
    /// Construct a `Product` with only `name` set; all other fields default.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
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
}
