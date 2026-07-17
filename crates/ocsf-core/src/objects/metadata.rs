use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::objects::Product;

/// OCSF `metadata` object: describes the metadata associated with the event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Metadata {
    /// The product that reported the event.
    pub product: Product,
    /// The version of the OCSF schema (SemVer) used to produce the event.
    pub version: String,
    /// The list of profiles used to create the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<String>>,
    /// A unique identifier used to correlate this event with other related events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_uid: Option<String>,
    /// Debug information about non-fatal issues with this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<Vec<String>>,
    /// The identifier of the original event (e.g. Windows Event Code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    /// The schema extension used to create the event. Deprecated in favor of `extensions`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<serde_json::Value>,
    /// The schema extensions used to create the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<serde_json::Value>>,
    /// Indicates whether the OCSF event data has been truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_truncated: Option<bool>,
    /// The list of labels attached to the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The format of data in the log where the data originated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
    /// The level at which an event was logged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// The event log name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_name: Option<String>,
    /// The logging provider or logging service that logged the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_provider: Option<String>,
    /// The log system or component where the data originated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_source: Option<String>,
    /// The event log schema version of the original event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_version: Option<String>,
    /// The time when the logging system collected and logged the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_time: Option<Timestamp>,
    /// `logged_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_time_dt: Option<String>,
    /// The pipeline of devices and logging products between the source and destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loggers: Option<Vec<serde_json::Value>>,
    /// The time when the event was last modified or enriched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The unique identifier assigned to the event in its original logging system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_event_uid: Option<String>,
    /// The original event time as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<String>,
    /// The event processed time, such as an ETL operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_time: Option<Timestamp>,
    /// `processed_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_time_dt: Option<String>,
    /// The entity from which the event or finding was first reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reporter: Option<serde_json::Value>,
    /// Sequence number of the event, for unambiguous ordering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<i32>,
    /// The source of the event or finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The list of key:value tags associated with the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The unique tenant identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_uid: Option<String>,
    /// The amount of time an event spent in a queue awaiting processing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_queued_duration: Option<serde_json::Value>,
    /// An array of transformation info describing mappings/transforms applied to the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transformation_info_list: Option<Vec<serde_json::Value>>,
    /// The time when the event was transmitted from the logging device to its next destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmit_time: Option<Timestamp>,
    /// `transmit_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmit_time_dt: Option<String>,
    /// The type of the event or finding, as a subset of `source`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// A unique identifier assigned to the OCSF event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The original size of the OCSF event data in kilobytes before truncation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untruncated_size: Option<i32>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Metadata {
    /// Construct a `Metadata` pinned to [`crate::OCSF_VERSION`], with every
    /// other field defaulted (`None` / empty).
    pub fn new(product: Product) -> Self {
        Self {
            product,
            version: crate::OCSF_VERSION.to_string(),
            profiles: None,
            correlation_uid: None,
            debug: None,
            event_code: None,
            extension: None,
            extensions: None,
            is_truncated: None,
            labels: None,
            log_format: None,
            log_level: None,
            log_name: None,
            log_provider: None,
            log_source: None,
            log_version: None,
            logged_time: None,
            logged_time_dt: None,
            loggers: None,
            modified_time: None,
            modified_time_dt: None,
            original_event_uid: None,
            original_time: None,
            processed_time: None,
            processed_time_dt: None,
            reporter: None,
            sequence: None,
            source: None,
            tags: None,
            tenant_uid: None,
            total_queued_duration: None,
            transformation_info_list: None,
            transmit_time: None,
            transmit_time_dt: None,
            r#type: None,
            uid: None,
            untruncated_size: None,
            other: serde_json::Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::Product;

    #[test]
    fn metadata_new_pins_version_and_roundtrips_unknown_fields() {
        let m = Metadata::new(Product::named("trivy"));
        assert_eq!(m.version, crate::OCSF_VERSION);

        let json = r#"{"product":{"name":"x"},"version":"1.8.0","future_field":{"a":1}}"#;
        let m: Metadata = serde_json::from_str(json).unwrap();
        assert_eq!(m.other["future_field"]["a"], 1);
        let out = serde_json::to_value(&m).unwrap();
        assert_eq!(out["future_field"]["a"], 1); // lossless round-trip
        assert!(out.get("uid").is_none()); // None fields don't serialize
    }
}
