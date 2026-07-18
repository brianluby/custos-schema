use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::ocsf_enum;
use crate::objects::{Container, Group, Image, Organization, User};
use crate::validation::{Validate, ValidationReport, check_nested, check_other_collisions};

ocsf_enum! {
    /// Normalized risk level (OCSF `risk_level_id`), shared by the `device`
    /// and `user` objects.
    pub enum RiskLevelId {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
    }
}

ocsf_enum! {
    /// Normalized device type (OCSF `device.type_id`).
    pub enum DeviceTypeId {
        Server = 1,
        Desktop = 2,
        Laptop = 3,
        Tablet = 4,
        Mobile = 5,
        Virtual = 6,
        Iot = 7,
        Browser = 8,
        Firewall = 9,
        Switch = 10,
        Hub = 11,
        Router = 12,
        Ids = 13,
        Ips = 14,
        LoadBalancer = 15,
    }
}

ocsf_enum! {
    /// Normalized operating system type (OCSF `os.type_id`).
    pub enum OsTypeId {
        Windows = 100,
        WindowsMobile = 101,
        Linux = 200,
        Android = 201,
        MacOs = 300,
        Ios = 301,
        IPadOs = 302,
        Solaris = 400,
        Aix = 401,
        HpUx = 402,
    }
}

/// OCSF `os` object: describes characteristics of an operating system.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Os {
    /// The operating system build number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// The operating system country code (ISO 3166-1 Alpha-2), e.g. `US`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// The Common Platform Enumeration (CPE) name, e.g.
    /// `cpe:/a:apple:safari:16.2`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe_name: Option<String>,
    /// The CPU architecture: the number of bits used for addressing in
    /// memory, e.g. `32` or `64`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_bits: Option<i32>,
    /// The operating system edition, e.g. `Professional`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// The kernel release of the operating system, e.g. `5.15.0-122-generic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    /// The two-letter lower case language code (ISO 639-1), e.g. `en`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// The operating system name.
    pub name: String,
    /// The name of the latest Service Pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_name: Option<String>,
    /// The version number of the latest Service Pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_ver: Option<i32>,
    /// The type of the operating system.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The type identifier of the operating system.
    pub type_id: OsTypeId,
    /// The version of the OS running on the device that originated the
    /// event, e.g. `Windows 10`, `OS X 10.7`, or `iOS 9`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `device` object: describes characteristics of a device, endpoint,
/// virtual machine, or other resource that is the subject of an event.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Device {
    /// A list of `agent` objects associated with the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_list: Option<Vec<serde_json::Value>>,
    /// The unique identifier of the cloud autoscale configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autoscale_uid: Option<String>,
    /// The time the system was booted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_time: Option<Timestamp>,
    /// `boot_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_time_dt: Option<String>,
    /// A unique identifier of the device that changes after every reboot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_uid: Option<String>,
    /// The information describing an instance of a container running on the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
    /// The time when the device was known to have been created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The description of the device, ordinarily as reported by the
    /// operating system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The network domain where the device resides, e.g. `work.example.com`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The Embedded Identity Document: a unique serial number that
    /// identifies an eSIM-enabled device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eid: Option<String>,
    /// The initial discovery time of the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_time: Option<Timestamp>,
    /// `first_seen_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_time_dt: Option<String>,
    /// The group names to which the device belongs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Group>>,
    /// The device hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The endpoint hardware information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hw_info: Option<serde_json::Value>,
    /// The name of the hypervisor running on the device, e.g. `Xen`, `VMware`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<String>,
    /// The Integrated Circuit Card Identification of a mobile device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iccid: Option<String>,
    /// The image used as a template to run the virtual machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Image>,
    /// The International Mobile Equipment Identity associated with the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imei: Option<String>,
    /// The International Mobile Equipment Identity values associated with the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imei_list: Option<Vec<String>>,
    /// The unique identifier of a VM instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_uid: Option<String>,
    /// The name of the network interface, e.g. `eth2`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    /// The unique identifier of the network interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_uid: Option<String>,
    /// The device IP address, in either IPv4 or IPv6 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Indicates whether the device has a backup enabled, e.g. an
    /// automated snapshot or a cloud backup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_backed_up: Option<bool>,
    /// The event occurred on a compliant device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_compliant: Option<bool>,
    /// The event occurred on a managed device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_managed: Option<bool>,
    /// Indicates whether the device has an active mobile account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_mobile_account_active: Option<bool>,
    /// The event occurred on a personal device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_personal: Option<bool>,
    /// The event occurred on a shared device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_shared: Option<bool>,
    /// The event occurred on a supervised device (e.g. MDM-managed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_supervised: Option<bool>,
    /// The event occurred on a trusted device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_trusted: Option<bool>,
    /// The most recent discovery time of the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_time: Option<Timestamp>,
    /// `last_seen_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_time_dt: Option<String>,
    /// The geographical location of the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<serde_json::Value>,
    /// The Media Access Control (MAC) address of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The vendor or manufacturer of the endpoint's network interface
    /// controller (NIC), as identified from the MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_vendor: Option<String>,
    /// The Mobile Equipment Identifier, a unique number identifying a CDMA
    /// mobile device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meid: Option<String>,
    /// The model of the device, e.g. `ThinkPad X1 Carbon`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The time when the device was last known to have been modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The alternate device name, ordinarily as assigned by an administrator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// If running under a process namespace (such as in a container), the
    /// process identifier within that namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_pid: Option<i32>,
    /// The physical or virtual network interfaces associated with the
    /// device, one for each unique MAC/IP/hostname/name combination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<Vec<serde_json::Value>>,
    /// Organization and org unit related to the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<Organization>,
    /// The endpoint operating system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<Os>,
    /// The operating system assigned Machine ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_machine_uuid: Option<String>,
    /// The identity of the service or user account that owns the endpoint
    /// or was last logged into it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User>,
    /// The pool of desktops or virtual machines to which the endpoint belongs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<Group>,
    /// The region where the virtual machine is located, e.g. an AWS Region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The risk level, normalized to the caption of `risk_level_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// The normalized risk level id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level_id: Option<RiskLevelId>,
    /// The risk score as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    /// The subnet mask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    /// The unique identifier of a virtual subnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_uid: Option<String>,
    /// The device type, e.g. `server`, `desktop`, `laptop`, `mobile`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The device type ID.
    pub type_id: DeviceTypeId,
    /// The Apple assigned Unique Device Identifier (UDID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udid: Option<String>,
    /// The unique identifier of the device, e.g. the Windows TargetSID or
    /// AWS EC2 ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// An alternate unique identifier of the device, if any, e.g. the
    /// ActiveDirectory DN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_alt: Option<String>,
    /// The vendor for the device, e.g. `Dell` or `Lenovo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    /// The Virtual LAN identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_uid: Option<String>,
    /// The unique identifier of the Virtual Private Cloud (VPC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpc_uid: Option<String>,
    /// The network zone or LAN segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    ///
    /// Collision-checking of this catch-all happens at [`Validate::validate`]:
    /// inserting a key that names a modeled field is invalid.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Device {
    /// Modeled wire-name set (every field except the flattened `other`),
    /// pinned to the schemars property set by the conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "agent_list",
        "autoscale_uid",
        "boot_time",
        "boot_time_dt",
        "boot_uid",
        "container",
        "created_time",
        "created_time_dt",
        "desc",
        "domain",
        "eid",
        "first_seen_time",
        "first_seen_time_dt",
        "groups",
        "hostname",
        "hw_info",
        "hypervisor",
        "iccid",
        "image",
        "imei",
        "imei_list",
        "instance_uid",
        "interface_name",
        "interface_uid",
        "ip",
        "is_backed_up",
        "is_compliant",
        "is_managed",
        "is_mobile_account_active",
        "is_personal",
        "is_shared",
        "is_supervised",
        "is_trusted",
        "last_seen_time",
        "last_seen_time_dt",
        "location",
        "mac",
        "mac_vendor",
        "meid",
        "model",
        "modified_time",
        "modified_time_dt",
        "name",
        "namespace_pid",
        "network_interfaces",
        "org",
        "os",
        "os_machine_uuid",
        "owner",
        "pool",
        "region",
        "risk_level",
        "risk_level_id",
        "risk_score",
        "subnet",
        "subnet_uid",
        "type",
        "type_id",
        "udid",
        "uid",
        "uid_alt",
        "vendor_name",
        "vlan_uid",
        "vpc_uid",
        "zone",
    ];
}

impl Validate for Device {
    /// Validates the device identity constraint, extension fields, and nested objects.
    ///
    /// A device is valid when at least one identifying field is present, extension keys
    /// do not collide with modeled fields, and all present nested objects are valid.
    ///
    /// # Returns
    ///
    /// A report containing all validation findings.
    ///
    /// # Examples
    ///
    /// ```
    /// use ocsf_core::{Device, Validate};
    ///
    /// let report = Device::default().validate();
    /// assert!(!report.is_valid());
    /// ```
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[
            ("ip", self.ip.is_some()),
            ("uid", self.uid.is_some()),
            ("name", self.name.is_some()),
            ("hostname", self.hostname.is_some()),
            ("instance_uid", self.instance_uid.is_some()),
            ("interface_uid", self.interface_uid.is_some()),
            ("interface_name", self.interface_name.is_some()),
        ]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        if let Some(container) = &self.container {
            check_nested(container, "container", &mut r);
        }
        if let Some(groups) = &self.groups {
            for (i, group) in groups.iter().enumerate() {
                check_nested(group, &format!("groups[{i}]"), &mut r);
            }
        }
        if let Some(org) = &self.org {
            check_nested(org, "org", &mut r);
        }
        if let Some(owner) = &self.owner {
            check_nested(owner, "owner", &mut r);
        }
        if let Some(pool) = &self.pool {
            check_nested(pool, "pool", &mut r);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::Validate;

    #[test]
    fn device_at_least_one_constraint_enforced() {
        assert!(!Device::default().validate().is_valid());
        let ok = Device {
            hostname: Some("host-1".into()),
            ..Default::default()
        };
        assert!(ok.validate().is_valid());
    }

    #[test]
    fn device_extension_key_collision_is_invalid() {
        let mut d = Device {
            hostname: Some("h".into()),
            ..Default::default()
        };
        d.other.insert("uid".to_string(), serde_json::Value::Null);
        assert!(d.validate().errors.iter().any(|e| e.attribute == "other"));
    }

    #[test]
    fn device_recurses_into_invalid_typed_children() {
        // Parent's own `at_least_one` is satisfied (hostname set); each nested
        // child below is invalid on its own contract and must fail the parent
        // under its pinned nested path.
        let base = Device {
            hostname: Some("h".into()),
            ..Default::default()
        };
        let cases: &[(&str, Device)] = &[
            (
                "container.",
                Device {
                    container: Some(Container::default()),
                    ..base.clone()
                },
            ),
            (
                "groups[0].",
                Device {
                    groups: Some(vec![Group::default()]),
                    ..base.clone()
                },
            ),
            (
                "org.",
                Device {
                    org: Some(Organization::default()),
                    ..base.clone()
                },
            ),
            (
                "owner.",
                Device {
                    owner: Some(User::default()),
                    ..base.clone()
                },
            ),
            (
                "pool.",
                Device {
                    pool: Some(Group::default()),
                    ..base.clone()
                },
            ),
        ];
        for (path, device) in cases {
            let report = device.validate();
            assert!(!report.is_valid(), "expected {path} child to fail parent");
            assert!(
                report.errors.iter().any(|e| e.attribute.starts_with(path)),
                "missing nested error under {path}"
            );
        }
    }

    #[test]
    fn device_type_id_roundtrips_known_and_unrecognized() {
        assert_eq!(DeviceTypeId::from(15), DeviceTypeId::LoadBalancer);
        assert_eq!(DeviceTypeId::from(0), DeviceTypeId::Unknown);
        assert_eq!(DeviceTypeId::from(1234), DeviceTypeId::Unrecognized(1234));
    }

    #[test]
    fn os_type_id_roundtrips_non_contiguous_values() {
        assert_eq!(OsTypeId::from(302), OsTypeId::IPadOs);
        assert_eq!(OsTypeId::from(100), OsTypeId::Windows);
        assert_eq!(OsTypeId::from(0), OsTypeId::Unknown);
    }

    #[test]
    fn os_roundtrips_unknown_fields() {
        let json = r#"{"name":"Ubuntu","type_id":200,"future_field":1}"#;
        let os: Os = serde_json::from_str(json).unwrap();
        assert_eq!(os.name, "Ubuntu");
        assert_eq!(os.type_id, OsTypeId::Linux);
        assert_eq!(os.other["future_field"], 1);
        let out = serde_json::to_value(&os).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("version").is_none());
    }

    #[test]
    fn device_roundtrips_unknown_fields() {
        let json = r#"{"type_id":2,"name":"WORKSTATION-01","future_field":1}"#;
        let device: Device = serde_json::from_str(json).unwrap();
        assert_eq!(device.type_id, DeviceTypeId::Desktop);
        assert_eq!(device.other["future_field"], 1);
        let out = serde_json::to_value(&device).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }
}
