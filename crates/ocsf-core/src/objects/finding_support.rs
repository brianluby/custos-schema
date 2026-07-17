use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::{SeverityId, ocsf_enum};
use crate::objects::{Group, KbArticle, Product, User};

ocsf_enum! {
    /// Normalized resource role (OCSF `resource_details.role_id`).
    pub enum RoleId {
        Target = 1,
        Actor = 2,
        Affected = 3,
        Related = 4,
    }
}

ocsf_enum! {
    /// Normalized compliance/check status (OCSF `status_id`), shared by the
    /// `compliance` and `check` objects.
    pub enum ComplianceStatusId {
        Pass = 1,
        Warning = 2,
        Fail = 3,
    }
}

/// OCSF `finding_info` object: describes metadata pertaining to a finding,
/// including timestamps, related analytics, and MITRE ATT&CK context.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct FindingInfo {
    /// The analytic technique used to derive insights that led to the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytic: Option<serde_json::Value>,
    /// The Attack Graph describing possible routes an attacker could take
    /// through the environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_graph: Option<serde_json::Value>,
    /// The MITRE ATT&CK® and ATLAS™ techniques and tactics related to the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attacks: Option<Vec<serde_json::Value>>,
    /// The time when the finding was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// A list of data sources utilized in generation of the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sources: Option<Vec<String>>,
    /// The description of the reported finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The time when the finding was first observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_time: Option<Timestamp>,
    /// `first_seen_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_time_dt: Option<String>,
    /// The Cyber Kill Chain® phases and their associated activities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_chain: Option<Vec<serde_json::Value>>,
    /// The time when the finding was most recently observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_time: Option<Timestamp>,
    /// `last_seen_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_time_dt: Option<String>,
    /// The time when the finding was last modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// Details about the product that reported the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// The unique identifier of the product that reported the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_uid: Option<String>,
    /// Other analytics related to this finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_analytics: Option<Vec<serde_json::Value>>,
    /// Events and/or other findings related to this finding, as identified
    /// by the security product; these may or may not be in OCSF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_events: Option<Vec<serde_json::Value>>,
    /// The number of related events or findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_events_count: Option<i32>,
    /// The URL pointing to the source of the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// The list of key:value tags associated with the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// A title or a brief phrase summarizing the reported finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The list of key traits or characteristics extracted from the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits: Option<Vec<serde_json::Value>>,
    /// One or more types of the reported finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    /// The unique identifier of the reported finding.
    pub uid: String,
    /// The alternative unique identifier of the reported finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_alt: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `resource_details` object: describes details about the resource
/// that is the subject of an event or finding, e.g. a cloud resource,
/// device, or file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ResourceDetails {
    /// A list of `agent` objects associated with the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_list: Option<Vec<serde_json::Value>>,
    /// The logical grouping or isolated segment within a cloud provider's
    /// infrastructure where the resource is located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_partition: Option<String>,
    /// The time when the resource was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The criticality of the resource as defined by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criticality: Option<String>,
    /// Additional data describing the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// The name of the related resource group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Group>,
    /// The fully qualified name of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The IP address of the resource, in either IPv4 or IPv6 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Indicates whether the resource has a backup enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_backed_up: Option<bool>,
    /// The list of labels associated with the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The time when the resource was last modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The name of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The namespace, useful when similar entities exist that need to be
    /// kept separate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The details of the entity that owns the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User>,
    /// The cloud service provider that hosts or manages the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The cloud region where the resource is hosted, as defined by the
    /// cloud provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// A graph representation showing how this resource relates to other
    /// entities in the environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_relationship: Option<serde_json::Value>,
    /// The role of the resource in the context of the event or finding,
    /// normalized to the caption of `role_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The normalized identifier of the resource's role in the context of
    /// the event or finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<RoleId>,
    /// The list of key:value tags associated with the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The resource type as defined by the event source.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The unique identifier of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The alternative unique identifier of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_alt: Option<String>,
    /// The version of the resource, e.g. `1.2.3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The availability zone within a cloud region where the resource is located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `compliance` object: describes the result of a compliance
/// requirements evaluation, e.g. against CIS, PCI DSS, or HIPAA controls.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Compliance {
    /// A list of assessments associated with the compliance requirements
    /// evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessments: Option<Vec<serde_json::Value>>,
    /// The category a control framework pertains to, e.g. `Asset Management`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// A list of compliance checks associated with specific industry
    /// standards or frameworks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<Check>>,
    /// A list of reference KB articles that help interpret and implement
    /// compliance standards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_references: Option<Vec<KbArticle>>,
    /// A list of established guidelines or criteria that define specific
    /// requirements an organization must follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_standards: Option<Vec<KbArticle>>,
    /// A prescriptive, actionable set of specifications that strengthens
    /// device posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    /// The list of control parameters evaluated in a compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_parameters: Option<Vec<serde_json::Value>>,
    /// The description or criteria of a control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The specific compliance requirements being evaluated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Vec<String>>,
    /// The regulatory or industry standards being evaluated for compliance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standards: Option<Vec<String>>,
    /// The resultant status of the compliance check, normalized to the
    /// caption of `status_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The resultant status code of the compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    /// The contextual description of the `status`/`status_code` values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
    /// A list of contextual descriptions of the `status`/`status_code` values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_details: Option<Vec<String>>,
    /// The normalized status identifier of the compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<ComplianceStatusId>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `check` object: describes an individual compliance check, its
/// evaluated resource, and its result.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Check {
    /// The detailed description of the compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The name or title of the compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Details about the resource that this check evaluated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceDetails>,
    /// The severity level as defined in the source document, e.g. CIS
    /// `Level 1`/`Level 2` or DISA STIG `CAT I`/`CAT II`/`CAT III`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The normalized severity identifier that maps severity levels to
    /// standard severity levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_id: Option<SeverityId>,
    /// The regulatory or industry standard this check is associated with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standards: Option<Vec<String>>,
    /// The resultant status of the compliance check, normalized to the
    /// caption of `status_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The normalized status identifier of the compliance check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<ComplianceStatusId>,
    /// The unique identifier of the compliance check within its standard
    /// or framework.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The check version, e.g. `1.1.0`.
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
    fn role_id_roundtrips_known_and_unrecognized() {
        assert_eq!(RoleId::from(2), RoleId::Actor);
        assert_eq!(RoleId::from(0), RoleId::Unknown);
        assert_eq!(RoleId::from(1234), RoleId::Unrecognized(1234));
    }

    #[test]
    fn status_id_roundtrips_known_and_unrecognized() {
        assert_eq!(ComplianceStatusId::from(3), ComplianceStatusId::Fail);
        assert_eq!(ComplianceStatusId::from(0), ComplianceStatusId::Unknown);
        assert_eq!(
            ComplianceStatusId::from(1234),
            ComplianceStatusId::Unrecognized(1234)
        );
    }

    #[test]
    fn finding_info_roundtrips_unknown_fields() {
        let json = r#"{"uid":"finding-1","future_field":1}"#;
        let fi: FindingInfo = serde_json::from_str(json).unwrap();
        assert_eq!(fi.uid, "finding-1");
        assert_eq!(fi.other["future_field"], 1);
        let out = serde_json::to_value(&fi).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("title").is_none());
    }

    #[test]
    fn resource_details_roundtrips_unknown_fields() {
        let json = r#"{"name":"my-bucket","future_field":1}"#;
        let r: ResourceDetails = serde_json::from_str(json).unwrap();
        assert_eq!(r.other["future_field"], 1);
        let out = serde_json::to_value(&r).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }

    #[test]
    fn compliance_roundtrips_unknown_fields() {
        let json = r#"{"status_id":1,"future_field":1}"#;
        let c: Compliance = serde_json::from_str(json).unwrap();
        assert_eq!(c.status_id, Some(ComplianceStatusId::Pass));
        assert_eq!(c.other["future_field"], 1);
        let out = serde_json::to_value(&c).unwrap();
        assert_eq!(out["future_field"], 1);
    }

    #[test]
    fn check_roundtrips_unknown_fields() {
        let json = r#"{"severity_id":4,"future_field":1}"#;
        let c: Check = serde_json::from_str(json).unwrap();
        assert_eq!(c.severity_id, Some(SeverityId::High));
        assert_eq!(c.other["future_field"], 1);
        let out = serde_json::to_value(&c).unwrap();
        assert_eq!(out["future_field"], 1);
    }

    #[test]
    fn compliance_status_id_default_is_unknown() {
        assert_eq!(ComplianceStatusId::default(), ComplianceStatusId::Unknown);
    }

    #[test]
    fn compliance_default_constructible() {
        let _c = Compliance::default();
    }
}
