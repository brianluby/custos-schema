use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::ocsf_enum;
use crate::objects::Product;

ocsf_enum! {
    /// Normalized software package type (OCSF `type_id`), shared by the
    /// `package` and `affected_package` objects.
    pub enum PackageTypeId {
        Application = 1,
        OperatingSystem = 2,
    }
}

ocsf_enum! {
    /// Normalized SBOM specification type (OCSF `sbom.type_id`).
    pub enum SbomTypeId {
        Spdx = 1,
        CycloneDx = 2,
        Swid = 3,
    }
}

/// OCSF `package` object: describes details about a software package.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Package {
    /// A shorthand name describing the hardware architecture the packaged
    /// software is meant to run on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// The Common Platform Enumeration (CPE) name of the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe_name: Option<String>,
    /// The software package epoch: a way to define weighted dependencies
    /// based on version numbers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i32>,
    /// Cryptographic hash identifying the binary instance of the package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<serde_json::Value>,
    /// The software license applied to this package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// The URL pointing to the license applied on the package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_url: Option<String>,
    /// The software package name.
    pub name: String,
    /// The software package manager utilized to manage this package, e.g.
    /// `npm`, `yum`, `dpkg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<String>,
    /// The URL of the package or library at the package manager.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_manager_url: Option<String>,
    /// A purl: a URL string identifying and locating the package across
    /// package managers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// The number of times a version of the software has been packaged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The link to the specific library or package, e.g. within GitHub.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
    /// The type of software package, normalized to the caption of `type_id`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The normalized type of software package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<PackageTypeId>,
    /// A unique identifier for the package or library reported by the
    /// source tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The name of the vendor who published the software package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    /// The software package version.
    pub version: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `sbom` object: describes characteristics of a generated Software
/// Bill of Materials.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Sbom {
    /// The time when the SBOM was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The software package or library discovered/inventoried by the SBOM.
    pub package: Package,
    /// Details about the upstream product that generated the SBOM, e.g.
    /// `cdxgen` or `Syft`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// The list of software components used in the software package.
    pub software_components: Vec<serde_json::Value>,
    /// The type of SBOM, normalized to the caption of `type_id`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The normalized type of SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<SbomTypeId>,
    /// A unique identifier for the SBOM or the SBOM generation by a source tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The specification version of the particular SBOM, e.g. `1.6`.
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
    fn package_type_id_roundtrips() {
        assert_eq!(PackageTypeId::from(1), PackageTypeId::Application);
        assert_eq!(PackageTypeId::from(2), PackageTypeId::OperatingSystem);
    }

    #[test]
    fn sbom_roundtrips_unknown_fields() {
        let json = r#"{"package":{"name":"left-pad","version":"1.3.0"},"software_components":[],"future_field":1}"#;
        let sbom: Sbom = serde_json::from_str(json).unwrap();
        assert_eq!(sbom.package.name, "left-pad");
        assert_eq!(sbom.other["future_field"], 1);
        let out = serde_json::to_value(&sbom).unwrap();
        assert_eq!(out["future_field"], 1);
    }
}
