use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::enums::ocsf_enum;

ocsf_enum! {
    /// Normalized relationship between two software components (OCSF
    /// `software_component.relationship_id`).
    pub enum RelationshipId {
        DependsOn = 1,
    }
}

ocsf_enum! {
    /// Normalized software component type (OCSF
    /// `software_component.type_id`).
    pub enum SoftwareComponentTypeId {
        Framework = 1,
        Library = 2,
        OperatingSystem = 3,
    }
}

/// OCSF `software_component` object: describes characteristics of a
/// software component within a software package.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct SoftwareComponent {
    /// The author(s) who published the software component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Cryptographic hash to identify the binary instance of a software
    /// component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<serde_json::Value>,
    /// The software license applied to this component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// The software component name.
    pub name: String,
    /// The Package URL (PURL) to identify the software component. This is
    /// a URL that uniquely identifies the component, including the
    /// component's name, version, and type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// The package URL (PURL) of the component that this software
    /// component has a relationship with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_component: Option<String>,
    /// The relationship between two software components, normalized to the
    /// caption of the `relationship_id` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    /// The normalized identifier of the relationship between two software
    /// components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship_id: Option<RelationshipId>,
    /// The type of software component, normalized to the caption of the
    /// `type_id` value.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The type of software component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<SoftwareComponentTypeId>,
    /// The software component version.
    pub version: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_id_roundtrips_known_and_unrecognized() {
        assert_eq!(RelationshipId::from(1), RelationshipId::DependsOn);
        assert_eq!(RelationshipId::from(0), RelationshipId::Unknown);
        assert_eq!(
            RelationshipId::from(1234),
            RelationshipId::Unrecognized(1234)
        );
    }

    #[test]
    fn software_component_type_id_roundtrips_known_and_unrecognized() {
        assert_eq!(
            SoftwareComponentTypeId::from(3),
            SoftwareComponentTypeId::OperatingSystem
        );
        assert_eq!(
            SoftwareComponentTypeId::from(0),
            SoftwareComponentTypeId::Unknown
        );
        assert_eq!(
            SoftwareComponentTypeId::from(1234),
            SoftwareComponentTypeId::Unrecognized(1234)
        );
    }

    #[test]
    fn software_component_roundtrips_unknown_fields() {
        let json = r#"{"name":"left-pad","version":"1.3.0","future_field":1}"#;
        let sc: SoftwareComponent = serde_json::from_str(json).unwrap();
        assert_eq!(sc.name, "left-pad");
        assert_eq!(sc.version, "1.3.0");
        assert_eq!(sc.other["future_field"], 1);
        let out = serde_json::to_value(&sc).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("purl").is_none());
    }
}
