use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::ocsf_enum;
use crate::objects::{Cve, Cwe, Os, Product};
use crate::validation::{Validate, ValidationReport, check_nested, check_other_collisions};

ocsf_enum! {
    /// Normalized install state (OCSF `install_state_id`), shared by the
    /// `advisory` and `kb_article` objects.
    pub enum InstallStateId {
        Installed = 1,
        NotInstalled = 2,
        InstalledPendingReboot = 3,
    }
}

/// OCSF `advisory` object: a publicly disclosed security advisory used to
/// notify of cybersecurity vulnerabilities, e.g. a vendor bulletin or a
/// GitHub Security Advisory (GHSA).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Advisory {
    /// The average time to patch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_timespan: Option<serde_json::Value>,
    /// The Advisory bulletin identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulletin: Option<String>,
    /// The vendor's classification of the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// The time when the Advisory record was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// A brief description of the Advisory Record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The install state of the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_state: Option<String>,
    /// The normalized install state ID of the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_state_id: Option<InstallStateId>,
    /// Whether the Advisory has been replaced by another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_superseded: Option<bool>,
    /// The time when the Advisory record was last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The operating system the Advisory applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<Os>,
    /// The product where the vulnerability was discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// A list of reference URLs with additional information about the
    /// vulnerabilities disclosed in the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// CVEs related to the vulnerabilities disclosed in the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_cves: Option<Vec<Cve>>,
    /// CWEs related to the vulnerabilities disclosed in the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_cwes: Option<Vec<Cwe>>,
    /// The size in bytes for the Advisory. Usually populated for a KB
    /// Article patch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// The Advisory link from the source vendor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// A title or a brief phrase summarizing the Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The unique identifier assigned to the advisory or disclosed
    /// vulnerability, e.g. `GHSA-5mrr-rgp6-x4gr`.
    pub uid: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Advisory {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "avg_timespan",
        "bulletin",
        "classification",
        "created_time",
        "created_time_dt",
        "desc",
        "install_state",
        "install_state_id",
        "is_superseded",
        "modified_time",
        "modified_time_dt",
        "os",
        "product",
        "references",
        "related_cves",
        "related_cwes",
        "size",
        "src_url",
        "title",
        "uid",
    ];
}

impl Validate for Advisory {
    /// Validates the advisory and its nested product.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```
    
    /// let advisory = Advisory {
    
    ///     uid: "ADV-1".into(),
    
    ///     ..Default::default()
    
    /// };
    
    ///
    
    /// assert!(advisory.validate().is_valid());
    
    /// ```
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        if let Some(product) = &self.product {
            check_nested(product, "product", &mut r);
        }
        r
    }
}

/// OCSF `kb_article` object: metadata describing a patch or an update
/// applicable to an endpoint.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct KbArticle {
    /// The average time to patch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_timespan: Option<serde_json::Value>,
    /// The KB article bulletin identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulletin: Option<String>,
    /// The vendor's classification of the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// The date the KB article was released by the vendor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The install state of the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_state: Option<String>,
    /// The normalized install state ID of the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_state_id: Option<InstallStateId>,
    /// Whether the KB article has been replaced by another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_superseded: Option<bool>,
    /// The operating system the KB article applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<Os>,
    /// The product details the KB article applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// The severity of the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The size in bytes for the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// The KB article link from the source vendor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// The title of the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The unique identifier for the KB article.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl KbArticle {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "avg_timespan",
        "bulletin",
        "classification",
        "created_time",
        "created_time_dt",
        "install_state",
        "install_state_id",
        "is_superseded",
        "os",
        "product",
        "severity",
        "size",
        "src_url",
        "title",
        "uid",
    ];
}

impl Validate for KbArticle {
    /// Validates the knowledge-base article and its nested product.
    ///
    /// Validation requires either `uid` or `src_url`, checks extension fields for
    /// collisions with modeled fields, and validates `product` when present.
    ///
    /// # Examples
    ///
    /// ```
    /// let article = KbArticle::default();
    /// assert!(!article.validate().is_valid());
    /// ```
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[
            ("uid", self.uid.is_some()),
            ("src_url", self.src_url.is_some()),
        ]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        if let Some(product) = &self.product {
            check_nested(product, "product", &mut r);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::Validate;

    #[test]
    fn install_state_id_roundtrips_known_and_unrecognized() {
        assert_eq!(InstallStateId::from(2), InstallStateId::NotInstalled);
        assert_eq!(InstallStateId::from(0), InstallStateId::Unknown);
        assert_eq!(
            InstallStateId::from(1234),
            InstallStateId::Unrecognized(1234)
        );
    }

    #[test]
    fn advisory_roundtrips_unknown_fields() {
        let json = r#"{"uid":"GHSA-5mrr-rgp6-x4gr","future_field":1}"#;
        let advisory: Advisory = serde_json::from_str(json).unwrap();
        assert_eq!(advisory.other["future_field"], 1);
        let out = serde_json::to_value(&advisory).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("title").is_none());
    }

    #[test]
    fn advisory_recurses_into_invalid_product() {
        let advisory = Advisory {
            uid: "GHSA-xxxx".into(),
            product: Some(Product::default()), // invalid: no name/uid
            ..Default::default()
        };
        let report = advisory.validate();
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.attribute.starts_with("product."))
        );
    }

    #[test]
    fn kb_article_recurses_into_invalid_product() {
        let kb = KbArticle {
            uid: Some("KB123".into()),         // satisfies parent at_least_one
            product: Some(Product::default()), // invalid: no name/uid
            ..Default::default()
        };
        let report = kb.validate();
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.attribute.starts_with("product."))
        );
    }

    #[test]
    fn kb_article_at_least_one_and_collision_enforced() {
        assert!(!KbArticle::default().validate().is_valid());
        let mut ok = KbArticle {
            src_url: Some("https://example.com/kb".into()),
            ..Default::default()
        };
        assert!(ok.validate().is_valid());
        ok.other.insert("uid".to_string(), serde_json::Value::Null);
        assert!(ok.validate().errors.iter().any(|e| e.attribute == "other"));
    }
}
