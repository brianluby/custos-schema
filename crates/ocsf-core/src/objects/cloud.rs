use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::objects::{Account, Organization};

/// OCSF `cloud` object: describes details about the cloud service or
/// infrastructure that is the subject of an event, such as the account,
/// region, and availability zone.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Cloud {
    /// The cloud account, subscription, or billing unit where the event or
    /// finding was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    /// The logical grouping or isolated segment within a cloud provider's
    /// infrastructure, e.g. an AWS partition (`aws`, `aws-cn`, `aws-us-gov`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_partition: Option<String>,
    /// The organizational unit or management structure that governs the
    /// account, subscription, or project where the event or finding was
    /// created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<Organization>,
    /// The unique identifier of a Cloud project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_uid: Option<String>,
    /// The unique name of the Cloud services provider, e.g. `AWS`, `Azure`,
    /// `GCP`, or `Oracle Cloud`.
    pub provider: String,
    /// The cloud region where the event or finding was created, as defined
    /// by the cloud provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The availability zone in the cloud region where the event or finding
    /// was created, as defined by the cloud provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_roundtrips_unknown_fields() {
        let json = r#"{"provider":"AWS","future_field":1}"#;
        let cloud: Cloud = serde_json::from_str(json).unwrap();
        assert_eq!(cloud.provider, "AWS");
        assert_eq!(cloud.other["future_field"], 1);
        let out = serde_json::to_value(&cloud).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("region").is_none());
    }
}
