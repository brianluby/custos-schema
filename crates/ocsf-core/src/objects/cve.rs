use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::objects::Product;

/// OCSF `cve` object: the Common Vulnerabilities and Exposures (CVE) record
/// related to a vulnerability.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Cve {
    /// The Record Creation Date: when the CVE ID was issued or the CVE
    /// Record was published on the CVE List.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// CVSS scores from the advisory that are related to the vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<Vec<Cvss>>,
    /// The weakness related to the CVE. Deprecated in favor of `related_cwes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<Cwe>,
    /// The CWE unique identifier. Deprecated in favor of `related_cwes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_uid: Option<String>,
    /// The CWE definition URL. Deprecated in favor of `related_cwes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_url: Option<String>,
    /// A brief description of the CVE Record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The estimated probability the vulnerability will be exploited (EPSS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<Epss>,
    /// The Record Modified Date: when the CVE record was last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The product where the vulnerability was discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// A list of reference URLs with additional information about the CVE Record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// The CWE weaknesses related to the CVE Record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_cwes: Option<Vec<Cwe>>,
    /// A title or a brief phrase summarizing the CVE record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The vulnerability type, e.g. `DoS`, `Code Execution`, `Overflow`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The CVE ID, e.g. `CVE-2021-44228`.
    pub uid: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `cvss` object: a Common Vulnerability Scoring System score.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Cvss {
    /// The CVSS base score, e.g. `9.1`.
    pub base_score: f64,
    /// The CVSS depth: `Base`, `Environmental`, or `Temporal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<String>,
    /// The individual CVSS metrics contributing to the score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Vec<serde_json::Value>>,
    /// The CVSS overall score, impacted by base, temporal, and environmental metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_score: Option<f64>,
    /// The CVSS qualitative severity rating, a textual representation of the numeric score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The source URL for the CVSS score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// The CVSS vector string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_string: Option<String>,
    /// The vendor that provided the CVSS score, e.g. `NVD`, `REDHAT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    /// The CVSS version, e.g. `3.1`.
    pub version: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `cwe` object: a Common Weakness Enumeration entry.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Cwe {
    /// The caption assigned to the CWE unique identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// URL pointing to the CWE Specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// The CWE ID, e.g. `CWE-123`.
    pub uid: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `epss` object: the Exploit Prediction Scoring System estimate for a
/// vulnerability.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Epss {
    /// The timestamp indicating when the EPSS score was calculated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The EPSS score's percentile, relative to the larger EPSS dataset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentile: Option<f64>,
    /// The EPSS score: probability [0-1] of exploitation in the next 30
    /// days. Modeled as `String` per the oracle's `string_t` wire type
    /// (`conformance/api/objects/epss.full.json`), not `float_t`.
    pub score: String,
    /// The version of the EPSS model used to calculate the score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_roundtrips_unknown_fields_and_renames_type() {
        let json = r#"{"uid":"CVE-2021-44228","type":"Code Execution","future_field":1}"#;
        let cve: Cve = serde_json::from_str(json).unwrap();
        assert_eq!(cve.r#type.as_deref(), Some("Code Execution"));
        assert_eq!(cve.other["future_field"], 1);
        let out = serde_json::to_value(&cve).unwrap();
        assert_eq!(out["type"], "Code Execution");
        assert!(out.get("r#type").is_none());
    }
}
