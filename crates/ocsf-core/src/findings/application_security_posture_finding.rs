use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::{OcsfClass, Timestamp};
use crate::enums::{SeverityId, ocsf_enum};
use crate::findings::{
    FindingActionId, FindingConfidenceId, FindingDispositionId, FindingStatusId,
    check_vulnerabilities,
};
use crate::objects::{
    Cloud, Compliance, Device, FindingInfo, Metadata, Remediation, ResourceDetails, RiskLevelId,
    Vulnerability,
};
use crate::validation::{
    Validate, ValidationReport, check_cloud_profile, check_nested, check_other_collisions,
    check_scalar_range, check_uids, ranges, warn_recommended,
};

ocsf_enum! {
    /// Normalized activity for `application_security_posture_finding` (`activity_id`).
    pub enum ApplicationSecurityPostureFindingActivityId {
        Create = 1,
        Update = 2,
        Close = 3,
    }
}

/// OCSF `application_security_posture_finding` (class 2007): findings from application-security tooling — SAST, DAST, SCA, container/IaC scanning, and posture management.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApplicationSecurityPostureFinding {
    /// The normalized caption of action_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The action taken by a control or other policy-based system leading to an outcome or disposition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<FindingActionId>,
    /// The normalized identifier of the finding activity.
    pub activity_id: ApplicationSecurityPostureFindingActivityId,
    /// The finding activity name, as defined by the activity_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_name: Option<String>,
    /// The actor object describes details about the user/role/process that was the source of the activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<serde_json::Value>,
    /// Describes details about a typical API (Application Programming Interface) call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<serde_json::Value>,
    /// An Application describes the details for an inventoried application as reported by an Application Security tool or other Developer-centric tooling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<serde_json::Value>,
    /// An array of MITRE ATT&CK® objects describing identified tactics, techniques & sub-techniques.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attacks: Option<Vec<serde_json::Value>>,
    /// Provides details about an authorization, such as authorization outcome, and any associated policies related to the activity/event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<serde_json::Value>>,
    /// The event category name, as defined by category_uid value: Findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_name: Option<String>,
    /// The category unique identifier of the event.
    pub category_uid: i32,
    /// The event class name, as defined by class_uid value: Application Security Posture Finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// The unique identifier of a class.
    pub class_uid: i32,
    /// Describes details about the Cloud environment where the event or finding was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<Cloud>,
    /// A user provided comment about the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Provides compliance context to vulnerabilities and other weaknesses that are reported as part of an Application Security or Vulnerability Management tool's b...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Compliance>,
    /// The confidence, normalized to the caption of the confidence_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// The normalized confidence refers to the accuracy of the rule that created the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_id: Option<FindingConfidenceId>,
    /// The confidence score as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<i32>,
    /// The number of times that events in the same logical group occurred during the event Start Time to End Time period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,
    /// Describes the affected device/host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Device>,
    /// The disposition name, normalized to the caption of the disposition_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    /// Describes the outcome or action taken by a security control, such as access control checks, malware detections or various types of policy violations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_id: Option<FindingDispositionId>,
    /// The event duration or aggregate time, the amount of time the event covers from start_time to end_time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<i64>,
    /// The time of the most recent event included in the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<Timestamp>,
    /// The time of the most recent event included in the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_dt: Option<String>,
    /// The additional information from an external data source, which is associated with the event or a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<Vec<serde_json::Value>>,
    /// Describes the supporting information about a generated finding.
    pub finding_info: FindingInfo,
    /// The firewall rule that pertains to the control that triggered the event, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule: Option<serde_json::Value>,
    /// Indicates that the event is considered to be an alertable signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_alert: Option<bool>,
    /// A list of Malware objects, describing details about the identified malware.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malware: Option<Vec<serde_json::Value>>,
    /// Describes details about the scan job that identified malware on the target system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malware_scan_info: Option<serde_json::Value>,
    /// The description of the event/finding, as defined by the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The metadata associated with the event or a finding.
    pub metadata: Metadata,
    /// The observables associated with the event or a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observables: Option<Vec<serde_json::Value>>,
    /// The policy that pertains to the control that triggered the event, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<serde_json::Value>,
    /// The raw event/finding data as received from the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,
    /// The hash, which describes the content of the raw_data field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data_hash: Option<serde_json::Value>,
    /// The size of the raw data which was transformed into an OCSF event, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data_size: Option<i64>,
    /// Describes the recommended remediation steps to address identified vulnerabilities or weaknesses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
    /// Describes details about the resource/resources that are affected by the vulnerability/vulnerabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<ResourceDetails>>,
    /// Describes the risk associated with the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_details: Option<String>,
    /// The risk level, normalized to the caption of the risk_level_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// The normalized risk level id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level_id: Option<RiskLevelId>,
    /// The risk score as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    /// The event/finding severity, normalized to the caption of the severity_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The normalized identifier of the event/finding severity.The normalized severity is a measurement the effort and expense required to manage and resolve an eve...
    pub severity_id: SeverityId,
    /// The time of the least recent event included in the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<Timestamp>,
    /// The time of the least recent event included in the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_dt: Option<String>,
    /// The normalized status of the Finding set by the consumer normalized to the caption of the status_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The event status code, as reported by the event source.For example, in a Windows Failed Authentication event, this would be the value of 'Failure Code', e.g.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    /// The status detail contains additional information about the event/finding outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
    /// The normalized status identifier of the Finding, set by the consumer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<FindingStatusId>,
    /// The normalized event occurrence time or the finding creation time.
    pub time: Timestamp,
    /// The normalized event occurrence time or the finding creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_dt: Option<String>,
    /// The number of minutes that the reported event time is ahead or behind UTC, in the range -1,080 to +1,080.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone_offset: Option<i32>,
    /// The event/finding type name, as defined by the type_uid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    /// The event/finding type ID.
    pub type_uid: i32,
    /// The attributes that are not mapped to the event schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<serde_json::Value>,
    /// The Vendor Attributes object can be used to represent values of attributes populated by the Vendor/Finding Provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_attributes: Option<serde_json::Value>,
    /// This object describes vulnerabilities reported in a security finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl OcsfClass for ApplicationSecurityPostureFinding {
    const CLASS_UID: u32 = 2007;
    const CATEGORY_UID: u32 = 2;
    const CLASS_NAME: &'static str = "application_security_posture_finding";

    fn activity_id_value(&self) -> i32 {
        i32::from(self.activity_id)
    }
}

impl ApplicationSecurityPostureFinding {
    /// Modeled wire-name set (every field except the flattened `other`),
    /// pinned to the schemars property set by the conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "action",
        "action_id",
        "activity_id",
        "activity_name",
        "actor",
        "api",
        "application",
        "attacks",
        "authorizations",
        "category_name",
        "category_uid",
        "class_name",
        "class_uid",
        "cloud",
        "comment",
        "compliance",
        "confidence",
        "confidence_id",
        "confidence_score",
        "count",
        "device",
        "disposition",
        "disposition_id",
        "duration",
        "end_time",
        "end_time_dt",
        "enrichments",
        "finding_info",
        "firewall_rule",
        "is_alert",
        "malware",
        "malware_scan_info",
        "message",
        "metadata",
        "observables",
        "policy",
        "raw_data",
        "raw_data_hash",
        "raw_data_size",
        "remediation",
        "resources",
        "risk_details",
        "risk_level",
        "risk_level_id",
        "risk_score",
        "severity",
        "severity_id",
        "start_time",
        "start_time_dt",
        "status",
        "status_code",
        "status_detail",
        "status_id",
        "time",
        "time_dt",
        "timezone_offset",
        "type_name",
        "type_uid",
        "unmapped",
        "vendor_attributes",
        "vulnerabilities",
    ];

    /// Construct a `ApplicationSecurityPostureFinding` from its required attributes, deriving
    /// `class_uid`/`category_uid`/`type_uid` from the [`OcsfClass`] constants
    /// and `activity_id`. Every optional attribute starts unset.
    pub fn new(
        time: Timestamp,
        activity_id: ApplicationSecurityPostureFindingActivityId,
        severity_id: SeverityId,
        metadata: Metadata,
        finding_info: FindingInfo,
    ) -> Self {
        let mut s = Self {
            action: None,
            action_id: None,
            activity_id,
            activity_name: None,
            actor: None,
            api: None,
            application: None,
            attacks: None,
            authorizations: None,
            category_name: None,
            category_uid: Self::CATEGORY_UID as i32,
            class_name: None,
            class_uid: Self::CLASS_UID as i32,
            cloud: None,
            comment: None,
            compliance: None,
            confidence: None,
            confidence_id: None,
            confidence_score: None,
            count: None,
            device: None,
            disposition: None,
            disposition_id: None,
            duration: None,
            end_time: None,
            end_time_dt: None,
            enrichments: None,
            finding_info,
            firewall_rule: None,
            is_alert: None,
            malware: None,
            malware_scan_info: None,
            message: None,
            metadata,
            observables: None,
            policy: None,
            raw_data: None,
            raw_data_hash: None,
            raw_data_size: None,
            remediation: None,
            resources: None,
            risk_details: None,
            risk_level: None,
            risk_level_id: None,
            risk_score: None,
            severity: None,
            severity_id,
            start_time: None,
            start_time_dt: None,
            status: None,
            status_code: None,
            status_detail: None,
            status_id: None,
            time,
            time_dt: None,
            timezone_offset: None,
            type_name: None,
            type_uid: 0,
            unmapped: None,
            vendor_attributes: None,
            vulnerabilities: None,
            other: serde_json::Map::new(),
        };
        s.type_uid = OcsfClass::type_uid(&s) as i32;
        s
    }
}

impl Validate for ApplicationSecurityPostureFinding {
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        check_uids(
            self,
            self.class_uid,
            self.category_uid,
            self.type_uid,
            &mut r,
        );
        r.at_least_one(&[
            ("application", self.application.is_some()),
            ("compliance", self.compliance.is_some()),
            ("remediation", self.remediation.is_some()),
            (
                "vulnerabilities",
                self.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty()),
            ),
        ]);
        if let Some(vulnerabilities) = &self.vulnerabilities {
            check_vulnerabilities(vulnerabilities, &mut r);
        }
        check_cloud_profile(&self.metadata, self.cloud.is_some(), &mut r);
        check_nested(&self.metadata, "metadata", &mut r);
        if let Some(device) = &self.device {
            check_nested(device, "device", &mut r);
        }
        if let Some(resources) = &self.resources {
            for (i, resource) in resources.iter().enumerate() {
                check_nested(resource, &format!("resources[{i}]"), &mut r);
            }
        }
        let (attr, min, max) = ranges::TIMEZONE_OFFSET;
        check_scalar_range(attr, self.timezone_offset, min, max, &mut r);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        warn_recommended(
            &mut r,
            &[
                ("status_id", self.status_id.is_some()),
                ("disposition_id", self.disposition_id.is_some()),
                ("confidence_id", self.confidence_id.is_some()),
                ("observables", self.observables.is_some()),
                ("remediation", self.remediation.is_some()),
                ("application", self.application.is_some()),
                ("compliance", self.compliance.is_some()),
                (
                    "resources",
                    self.resources.as_ref().is_some_and(|v| !v.is_empty()),
                ),
                (
                    "vulnerabilities",
                    self.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty()),
                ),
            ],
        );
        r
    }
}
