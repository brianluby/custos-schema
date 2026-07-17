use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::ocsf_enum;
use crate::objects::{Cve, Cwe, Os, Product};

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
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
