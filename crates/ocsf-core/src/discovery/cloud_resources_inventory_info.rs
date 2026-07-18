use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::{OcsfClass, Timestamp};
use crate::discovery::DiscoveryStatusId;
use crate::enums::{SeverityId, ocsf_enum};
use crate::findings::{FindingActionId, FindingConfidenceId, FindingDispositionId};
use crate::objects::{Cloud, Container, Device, Metadata, ResourceDetails, RiskLevelId};
use crate::validation::{
    Validate, ValidationReport, check_nested, check_other_collisions, check_scalar_range,
    check_uids, ranges, warn_recommended,
};

ocsf_enum! {
    /// Normalized activity for `cloud_resources_inventory_info` (`activity_id`).
    pub enum CloudResourcesInventoryInfoActivityId {
        Log = 1,
        Collect = 2,
    }
}

/// OCSF `cloud_resources_inventory_info` (class 5023): the discovery result of a cloud resource (e.g. container, database, data bucket, identity provider) discovered by an inventory process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CloudResourcesInventoryInfo {
    /// The normalized caption of action_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The action taken by a control or other policy-based system leading to an outcome or disposition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<FindingActionId>,
    /// The normalized identifier of the activity that triggered the event.
    pub activity_id: CloudResourcesInventoryInfoActivityId,
    /// The event activity name, as defined by the activity_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_name: Option<String>,
    /// The actor object describes details about the user/role/process that was the source of the activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<serde_json::Value>,
    /// Describes details about a typical API (Application Programming Interface) call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<serde_json::Value>,
    /// An array of MITRE ATT&CK® objects describing identified tactics, techniques & sub-techniques.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attacks: Option<Vec<serde_json::Value>>,
    /// Provides details about an authorization, such as authorization outcome, and any associated policies related to the activity/event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<serde_json::Value>>,
    /// The event category name, as defined by category_uid value: Discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_name: Option<String>,
    /// The category unique identifier of the event.
    pub category_uid: i32,
    /// The event class name, as defined by class_uid value: Cloud Resources Inventory Info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// The unique identifier of a class.
    pub class_uid: i32,
    /// Cloud service provider or SaaS platform metadata about the cloud resource(s) that are being discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<Cloud>,
    /// The confidence, normalized to the caption of the confidence_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// The normalized confidence refers to the accuracy of the rule that created the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_id: Option<FindingConfidenceId>,
    /// The confidence score as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<i32>,
    /// A cloud-based container image or running container discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
    /// The number of times that events in the same logical group occurred during the event Start Time to End Time period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,
    /// A cloud-based database discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<serde_json::Value>,
    /// A cloud-based data bucket or other object storage discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub databucket: Option<serde_json::Value>,
    /// An addressable device, computer system or host.
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
    /// The end time of a time period, or the time of the most recent event included in the aggregate event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    /// The end time of a time period, or the time of the most recent event included in the aggregate event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_dt: Option<String>,
    /// The additional information from an external data source, which is associated with the event or a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<Vec<serde_json::Value>>,
    /// The firewall rule that pertains to the control that triggered the event, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_rule: Option<serde_json::Value>,
    /// The Identity Provider that is being discovered by an inventory process, or that is related to the cloud resource(s) being discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp: Option<serde_json::Value>,
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
    /// The cloud region where the resource is located, e.g. us-isof-south-1, eastus2, us-central1, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The cloud resource(s) that are being discovered by an inventory process. Use this object if there is not a direct object match in the class.
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
    /// The normalized identifier of the event/finding severity. Smaller numerical values represent lower impact events, larger represent higher impact events.
    pub severity_id: SeverityId,
    /// The start time of a time period, or the time of the least recent event included in the aggregate event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    /// The start time of a time period, or the time of the least recent event included in the aggregate event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_dt: Option<String>,
    /// The event status, normalized to the caption of the status_id value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The event status code, as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    /// The status detail contains additional information about the event/finding outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
    /// The normalized identifier of the event status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<DiscoveryStatusId>,
    /// A cloud-based database table discovered by an inventory process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<serde_json::Value>,
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
    /// The event/finding type ID. It identifies the event's semantics and structure: class_uid * 100 + activity_id.
    pub type_uid: i32,
    /// The attributes that are not mapped to the event schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<serde_json::Value>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl OcsfClass for CloudResourcesInventoryInfo {
    const CLASS_UID: u32 = 5023;
    const CATEGORY_UID: u32 = 5;
    const CLASS_NAME: &'static str = "cloud_resources_inventory_info";

    fn activity_id_value(&self) -> i32 {
        i32::from(self.activity_id)
    }
}

impl CloudResourcesInventoryInfo {
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
        "attacks",
        "authorizations",
        "category_name",
        "category_uid",
        "class_name",
        "class_uid",
        "cloud",
        "confidence",
        "confidence_id",
        "confidence_score",
        "container",
        "count",
        "database",
        "databucket",
        "device",
        "disposition",
        "disposition_id",
        "duration",
        "end_time",
        "end_time_dt",
        "enrichments",
        "firewall_rule",
        "idp",
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
        "region",
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
        "table",
        "time",
        "time_dt",
        "timezone_offset",
        "type_name",
        "type_uid",
        "unmapped",
    ];

    /// Construct a `CloudResourcesInventoryInfo` from its required
    /// attributes, deriving `class_uid`/`category_uid`/`type_uid` from the
    /// [`OcsfClass`] constants and `activity_id`. Every optional attribute
    /// starts unset — this class has no class-specific required object;
    /// callers must set at least one of `cloud`/`container`/`database`/
    /// `databucket`/`idp`/`resources`/`table` for the instance to validate
    /// (the oracle's `at_least_one` constraint).
    pub fn new(
        time: Timestamp,
        activity_id: CloudResourcesInventoryInfoActivityId,
        severity_id: SeverityId,
        metadata: Metadata,
    ) -> Self {
        let mut s = Self {
            action: None,
            action_id: None,
            activity_id,
            activity_name: None,
            actor: None,
            api: None,
            attacks: None,
            authorizations: None,
            category_name: None,
            category_uid: Self::CATEGORY_UID as i32,
            class_name: None,
            class_uid: Self::CLASS_UID as i32,
            cloud: None,
            confidence: None,
            confidence_id: None,
            confidence_score: None,
            container: None,
            count: None,
            database: None,
            databucket: None,
            device: None,
            disposition: None,
            disposition_id: None,
            duration: None,
            end_time: None,
            end_time_dt: None,
            enrichments: None,
            firewall_rule: None,
            idp: None,
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
            region: None,
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
            table: None,
            time,
            time_dt: None,
            timezone_offset: None,
            type_name: None,
            type_uid: 0,
            unmapped: None,
            other: serde_json::Map::new(),
        };
        s.type_uid = OcsfClass::type_uid(&s) as i32;
        s
    }
}

impl Validate for CloudResourcesInventoryInfo {
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
            ("cloud", self.cloud.is_some()),
            ("container", self.container.is_some()),
            ("database", self.database.is_some()),
            ("databucket", self.databucket.is_some()),
            ("idp", self.idp.is_some()),
            ("resources", self.resources.is_some()),
            ("table", self.table.is_some()),
        ]);
        // Unlike the other three Discovery classes, `cloud` here carries no
        // `profiles` tag in the oracle (verified: `profiles: null` on
        // cloud_resources_inventory_info's `cloud` attribute) — its presence
        // is governed solely by the `at_least_one` constraint above, not by
        // `metadata.profiles` containing `"cloud"`. So `check_cloud_profile`
        // does not apply to this class.
        check_nested(&self.metadata, "metadata", &mut r);
        if let Some(device) = &self.device {
            check_nested(device, "device", &mut r);
        }
        if let Some(container) = &self.container {
            check_nested(container, "container", &mut r);
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
                ("resources", self.resources.is_some()),
                ("cloud", self.cloud.is_some()),
                ("container", self.container.is_some()),
                ("database", self.database.is_some()),
                ("databucket", self.databucket.is_some()),
                ("idp", self.idp.is_some()),
                ("table", self.table.is_some()),
            ],
        );
        r
    }
}
