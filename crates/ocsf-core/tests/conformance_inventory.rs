mod conformance;
use conformance::*;
use ocsf_core::enums::SeverityId;
use ocsf_core::objects::*;

#[test]
fn device_matches() {
    assert_object_matches::<Device>("device");
}
#[test]
fn os_matches() {
    assert_object_matches::<Os>("os");
}
#[test]
fn user_matches() {
    assert_object_matches::<User>("user");
}
#[test]
fn group_matches() {
    assert_object_matches::<Group>("group");
}
#[test]
fn account_matches() {
    assert_object_matches::<Account>("account");
}
#[test]
fn organization_matches() {
    assert_object_matches::<Organization>("organization");
}
#[test]
fn cloud_matches() {
    assert_object_matches::<Cloud>("cloud");
}
#[test]
fn container_matches() {
    assert_object_matches::<Container>("container");
}
#[test]
fn image_matches() {
    assert_object_matches::<Image>("image");
}
#[test]
fn finding_info_matches() {
    assert_object_matches::<FindingInfo>("finding_info");
}
#[test]
fn resource_details_matches() {
    assert_object_matches::<ResourceDetails>("resource_details");
}
#[test]
fn compliance_matches() {
    assert_object_matches::<Compliance>("compliance");
}
#[test]
fn check_matches() {
    assert_object_matches::<Check>("check");
}

#[test]
fn device_type_id_matches() {
    assert_enum_matches(
        DeviceTypeId::KNOWN,
        &Oracle::object_full("device"),
        "type_id",
    );
}

/// `risk_level_id` is shared byte-for-byte between `device` and `user`
/// (verified against both oracle files); `device` is the representative
/// owning object for this vocabulary test.
#[test]
fn risk_level_id_matches() {
    assert_enum_matches(
        RiskLevelId::KNOWN,
        &Oracle::object_full("device"),
        "risk_level_id",
    );
}

#[test]
fn os_type_id_matches() {
    assert_enum_matches(OsTypeId::KNOWN, &Oracle::object_full("os"), "type_id");
}

#[test]
fn user_type_id_matches() {
    assert_enum_matches(UserTypeId::KNOWN, &Oracle::object_full("user"), "type_id");
}

#[test]
fn account_type_id_matches() {
    assert_enum_matches(
        AccountTypeId::KNOWN,
        &Oracle::object_full("account"),
        "type_id",
    );
}

#[test]
fn role_id_matches() {
    assert_enum_matches(
        RoleId::KNOWN,
        &Oracle::object_full("resource_details"),
        "role_id",
    );
}

/// `status_id` is shared byte-for-byte between `compliance` and `check`
/// (verified against both oracle files); `compliance` is the
/// representative owning object for this vocabulary test.
#[test]
fn status_id_matches() {
    assert_enum_matches(
        StatusId::KNOWN,
        &Oracle::object_full("compliance"),
        "status_id",
    );
}

/// `check.severity_id` reuses the crate-wide `SeverityId` enum (its
/// oracle vocabulary is byte-for-byte identical to the one `SeverityId`
/// was already defined against), so this proves that reuse rather than
/// duplication is still correct.
#[test]
fn check_severity_id_matches() {
    assert_enum_matches(
        SeverityId::KNOWN,
        &Oracle::object_full("check"),
        "severity_id",
    );
}
