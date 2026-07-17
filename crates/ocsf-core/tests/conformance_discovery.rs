//! Oracle conformance for the four OCSF Discovery (category 5) event classes.
//!
//! Each class is gated three ways: `assert_class_matches` (property names both
//! directions vs the FULL compile, required set vs the BASE compile, coarse
//! types), `assert_enum_matches` for every `ocsf_enum!` we generated or
//! reused against its oracle vocabulary, and a fully constructed sample
//! validated against the vendored JSON-Schema oracle.

mod conformance;
use conformance::*;
use ocsf_core::base::OcsfClass;
use ocsf_core::discovery::*;
use ocsf_core::enums::SeverityId;
use ocsf_core::findings::{FindingActionId, FindingConfidenceId, FindingDispositionId};
use ocsf_core::objects::{
    Cloud, Container, Device, Metadata, Package, Product, ResourceDetails, RiskLevelId, Sbom, User,
};
use ocsf_core::validation::Validate;

// ---------------------------------------------------------------------------
// Structural conformance: schema shape vs the API-compile oracle.
// ---------------------------------------------------------------------------

#[test]
fn inventory_info_matches_oracle() {
    assert_class_matches::<InventoryInfo>("inventory_info");
    assert_enum_matches(
        InventoryInfoActivityId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "activity_id",
    );
}

#[test]
fn user_inventory_matches_oracle() {
    assert_class_matches::<UserInventory>("user_inventory");
    assert_enum_matches(
        UserInventoryActivityId::KNOWN,
        &Oracle::class_full("user_inventory"),
        "activity_id",
    );
}

#[test]
fn software_info_matches_oracle() {
    assert_class_matches::<SoftwareInfo>("software_info");
    assert_enum_matches(
        SoftwareInfoActivityId::KNOWN,
        &Oracle::class_full("software_info"),
        "activity_id",
    );
}

#[test]
fn cloud_resources_inventory_info_matches_oracle() {
    assert_class_matches::<CloudResourcesInventoryInfo>("cloud_resources_inventory_info");
    assert_enum_matches(
        CloudResourcesInventoryInfoActivityId::KNOWN,
        &Oracle::class_full("cloud_resources_inventory_info"),
        "activity_id",
    );
}

/// `FIELD_NAMES` (read by the extension-key collision check) must stay in
/// lockstep with the schemars property set for all four Discovery classes.
#[test]
fn field_names_match_schema() {
    assert_field_names_match::<InventoryInfo>(
        "class",
        "inventory_info",
        InventoryInfo::FIELD_NAMES,
    );
    assert_field_names_match::<UserInventory>(
        "class",
        "user_inventory",
        UserInventory::FIELD_NAMES,
    );
    assert_field_names_match::<SoftwareInfo>("class", "software_info", SoftwareInfo::FIELD_NAMES);
    assert_field_names_match::<CloudResourcesInventoryInfo>(
        "class",
        "cloud_resources_inventory_info",
        CloudResourcesInventoryInfo::FIELD_NAMES,
    );
}

// ---------------------------------------------------------------------------
// Shared/reused enum vocabularies. status_id is new here (Success/Failure,
// distinct from findings' FindingStatusId); action_id/confidence_id/
// disposition_id/risk_level_id are byte-for-byte identical to the vocab the
// Findings classes already defined (verified), so this module reuses those
// types rather than redefining them (per Task 9's own forward note).
// ---------------------------------------------------------------------------

#[test]
fn discovery_status_id_matches_oracle() {
    assert_enum_matches(
        DiscoveryStatusId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "status_id",
    );
}

#[test]
fn discovery_action_id_reuses_finding_action_id() {
    assert_enum_matches(
        FindingActionId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "action_id",
    );
}

#[test]
fn discovery_confidence_id_reuses_finding_confidence_id() {
    assert_enum_matches(
        FindingConfidenceId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "confidence_id",
    );
}

#[test]
fn discovery_disposition_id_reuses_finding_disposition_id() {
    assert_enum_matches(
        FindingDispositionId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "disposition_id",
    );
}

#[test]
fn discovery_risk_level_id_reuses_objects_enum() {
    assert_enum_matches(
        RiskLevelId::KNOWN,
        &Oracle::class_full("inventory_info"),
        "risk_level_id",
    );
}

// ---------------------------------------------------------------------------
// InventoryInfo (class 5001): full sample lifecycle.
// ---------------------------------------------------------------------------

fn sample_inventory_info() -> InventoryInfo {
    InventoryInfo::new(
        1_752_000_000_000,
        InventoryInfoActivityId::Collect,
        SeverityId::Informational,
        Metadata::new(Product::named("test")),
        Device {
            hostname: Some("host-1".into()),
            ..Default::default()
        },
    )
}

#[test]
fn inventory_info_validates_and_matches_oracle_jsonschema() {
    let ev = sample_inventory_info();
    assert_eq!(ev.type_uid(), 500102);
    let report = ev.validate();
    assert!(report.is_valid(), "errors: {:?}", report.errors);
    let value = serde_json::to_value(&ev).unwrap();
    assert_valid_against_oracle_schema(&value, "inventory_info", "base");
}

#[test]
fn inventory_info_uid_fields_set_from_constants() {
    let ev = sample_inventory_info();
    assert_eq!(ev.class_uid, 5001);
    assert_eq!(ev.category_uid, 5);
    assert_eq!(ev.type_uid, 500102);
}

#[test]
fn inventory_info_uid_mismatch_is_invalid() {
    let mut ev = sample_inventory_info();
    ev.type_uid = 999_999;
    let report = ev.validate();
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|e| e.attribute == "type_uid"));
}

#[test]
fn inventory_info_profile_requirement_is_conditional() {
    // Without the cloud profile, omitting `cloud` is valid.
    let ev = sample_inventory_info();
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );

    // Declaring the cloud profile makes `cloud` required.
    let mut ev = sample_inventory_info();
    ev.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!ev.validate().is_valid());

    // Supplying `cloud` satisfies the conditional requirement.
    ev.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn inventory_info_roundtrips_through_json() {
    let ev = sample_inventory_info();
    let value = serde_json::to_value(&ev).unwrap();
    let back: InventoryInfo = serde_json::from_value(value).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn inventory_info_roundtrips_unknown_fields() {
    let ev = sample_inventory_info();
    let mut value = serde_json::to_value(&ev).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("x_future".to_string(), serde_json::json!({"a": 1}));

    let back: InventoryInfo = serde_json::from_value(value).unwrap();
    assert_eq!(
        back.other.get("x_future"),
        Some(&serde_json::json!({"a": 1}))
    );

    let out = serde_json::to_value(&back).unwrap();
    assert_eq!(out["x_future"], serde_json::json!({"a": 1}));
}

// ---------------------------------------------------------------------------
// UserInventory (class 5003): full sample lifecycle.
// ---------------------------------------------------------------------------

fn sample_user_inventory() -> UserInventory {
    UserInventory::new(
        1_752_000_000_000,
        UserInventoryActivityId::Log,
        SeverityId::Informational,
        Metadata::new(Product::named("test")),
        User {
            name: Some("jdoe".into()),
            ..Default::default()
        },
    )
}

#[test]
fn user_inventory_type_uid_is_correct() {
    let ev = sample_user_inventory();
    assert_eq!(ev.type_uid(), 500301);
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn user_inventory_validates_against_oracle_jsonschema() {
    let ev = sample_user_inventory();
    let value = serde_json::to_value(&ev).unwrap();
    assert_valid_against_oracle_schema(&value, "user_inventory", "base");
}

#[test]
fn user_inventory_profile_requirement_is_conditional() {
    let ev = sample_user_inventory();
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );

    let mut ev = sample_user_inventory();
    ev.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!ev.validate().is_valid());

    ev.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn user_inventory_roundtrips_through_json() {
    let ev = sample_user_inventory();
    let value = serde_json::to_value(&ev).unwrap();
    let back: UserInventory = serde_json::from_value(value).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// SoftwareInfo (class 5020): full sample lifecycle. `SoftwareInfo::new`
// requires a `device`; its `sbom` field carries `Sbom` (Task 7).
// ---------------------------------------------------------------------------

fn sample_software_info() -> SoftwareInfo {
    let mut ev = SoftwareInfo::new(
        1_752_000_000_000,
        SoftwareInfoActivityId::Collect,
        SeverityId::Informational,
        Metadata::new(Product::named("test")),
        Device {
            hostname: Some("host-1".into()),
            ..Default::default()
        },
    );
    ev.package = Some(Package {
        name: "left-pad".into(),
        version: "1.3.0".into(),
        ..Default::default()
    });
    ev.sbom = Some(Sbom {
        package: Package {
            name: "left-pad".into(),
            version: "1.3.0".into(),
            ..Default::default()
        },
        software_components: Vec::new(),
        ..Default::default()
    });
    ev
}

#[test]
fn software_info_type_uid_is_correct() {
    let ev = sample_software_info();
    assert_eq!(ev.type_uid(), 502002);
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn software_info_validates_against_oracle_jsonschema() {
    let ev = sample_software_info();
    let value = serde_json::to_value(&ev).unwrap();
    assert_valid_against_oracle_schema(&value, "software_info", "base");
}

#[test]
fn software_info_profile_requirement_is_conditional() {
    let ev = sample_software_info();
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );

    let mut ev = sample_software_info();
    ev.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!ev.validate().is_valid());

    ev.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn software_info_roundtrips_through_json() {
    let ev = sample_software_info();
    let value = serde_json::to_value(&ev).unwrap();
    let back: SoftwareInfo = serde_json::from_value(value).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// CloudResourcesInventoryInfo (class 5023): class-level at_least_one
// constraint over [cloud, container, database, databucket, idp, resources,
// table]. `CloudResourcesInventoryInfo::new` takes no required class object.
// ---------------------------------------------------------------------------

fn sample_cloud_resources_inventory_info() -> CloudResourcesInventoryInfo {
    let mut ev = CloudResourcesInventoryInfo::new(
        1_752_000_000_000,
        CloudResourcesInventoryInfoActivityId::Collect,
        SeverityId::Informational,
        Metadata::new(Product::named("test")),
    );
    ev.resources = Some(vec![ResourceDetails {
        name: Some("my-bucket".into()),
        ..Default::default()
    }]);
    ev
}

#[test]
fn cloud_resources_inventory_info_type_uid_is_correct() {
    let ev = sample_cloud_resources_inventory_info();
    assert_eq!(ev.type_uid(), 502302);
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn cloud_resources_inventory_info_at_least_one_constraint_enforced() {
    let ev = CloudResourcesInventoryInfo::new(
        1_752_000_000_000,
        CloudResourcesInventoryInfoActivityId::Collect,
        SeverityId::Informational,
        Metadata::new(Product::named("test")),
    );
    // None of cloud/container/database/databucket/idp/resources/table present.
    let report = ev.validate();
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|e| e.attribute.contains("cloud")));

    // Satisfy the constraint via `container` instead.
    let mut ev = ev;
    ev.container = Some(Container {
        name: Some("web-1".into()),
        ..Default::default()
    });
    assert!(
        ev.validate().is_valid(),
        "errors: {:?}",
        ev.validate().errors
    );
}

#[test]
fn cloud_resources_inventory_info_validates_against_oracle_jsonschema() {
    let ev = sample_cloud_resources_inventory_info();
    let value = serde_json::to_value(&ev).unwrap();
    assert_valid_against_oracle_schema(&value, "cloud_resources_inventory_info", "base");
}

#[test]
fn cloud_resources_inventory_info_roundtrips_through_json() {
    let ev = sample_cloud_resources_inventory_info();
    let value = serde_json::to_value(&ev).unwrap();
    let back: CloudResourcesInventoryInfo = serde_json::from_value(value).unwrap();
    assert_eq!(ev, back);
}
