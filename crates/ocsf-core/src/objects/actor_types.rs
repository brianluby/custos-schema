use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::enums::ocsf_enum;
use crate::objects::RiskLevelId;
use crate::validation::{Validate, ValidationReport, check_nested, check_other_collisions};

ocsf_enum! {
    /// Normalized user type (OCSF `user.type_id`).
    pub enum UserTypeId {
        User = 1,
        Admin = 2,
        System = 3,
        Service = 4,
    }
}

ocsf_enum! {
    /// Normalized account type (OCSF `account.type_id`).
    pub enum AccountTypeId {
        LdapAccount = 1,
        WindowsAccount = 2,
        AwsIamUser = 3,
        AwsIamRole = 4,
        GcpAccount = 5,
        AzureAdAccount = 6,
        MacOsAccount = 7,
        AppleAccount = 8,
        LinuxAccount = 9,
        AwsAccount = 10,
        GcpProject = 11,
        OciCompartment = 12,
        AzureSubscription = 13,
        SalesforceAccount = 14,
        GoogleWorkspace = 15,
        ServicenowInstance = 16,
        M365Tenant = 17,
        EmailAccount = 18,
        ActiveDirectoryAccount = 19,
    }
}

/// OCSF `group` object: the grouping of individuals with similar rights,
/// interests, or objectives, such as an administrative or membership group.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Group {
    /// The group description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The domain where the group is defined, e.g. the LDAP or Active
    /// Directory domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The group name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The group privileges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,
    /// The type of the group.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The unique identifier of the group, e.g. a Windows SID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The alternate unique identifier of the group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_alt: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Group {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "desc",
        "domain",
        "name",
        "privileges",
        "type",
        "uid",
        "uid_alt",
    ];
}

impl Validate for Group {
    /// Enforces the oracle's `group` constraint (`at_least_one` of `name`,
    /// `uid`) and the extension-key collision check.
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("name", self.name.is_some()), ("uid", self.uid.is_some())]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        r
    }
}

/// OCSF `account` object: a user account, cloud account, subscription, or
/// billing unit, e.g. an AWS account or a GCP project.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Account {
    /// Indicates if the account is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_disabled: Option<bool>,
    /// Indicates if the account is locked, e.g. due to too many failed logins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_locked: Option<bool>,
    /// Indicates whether synchronization with an on-premises directory
    /// service is enabled, e.g. Microsoft Entra Connect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_on_premises_sync_enabled: Option<bool>,
    /// The list of labels associated with the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The name of the account, e.g. a GCP project name or an AWS account name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The list of key:value tags associated with the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The account type, normalized to the caption of `type_id`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The normalized account type identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<AccountTypeId>,
    /// The unique identifier of the account, e.g. an AWS Account ID or a
    /// GCP Project ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Account {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "is_disabled",
        "is_locked",
        "is_on_premises_sync_enabled",
        "labels",
        "name",
        "tags",
        "type",
        "type_id",
        "uid",
    ];
}

impl Validate for Account {
    /// Enforces the oracle's `account` constraint (`at_least_one` of `name`,
    /// `uid`) and the extension-key collision check.
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("name", self.name.is_some()), ("uid", self.uid.is_some())]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        r
    }
}

/// OCSF `organization` object: describes characteristics of an organization
/// or a Cloud tenant/organizational unit, e.g. an AWS Organization or a
/// Google Cloud Organization.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Organization {
    /// The name of the organization, e.g. `Widget, Inc.`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The name of an organizational unit, Google Cloud Folder, or AWS Org Unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ou_name: Option<String>,
    /// The unique identifier of an organizational unit, Google Cloud
    /// Folder, or AWS Org Unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ou_uid: Option<String>,
    /// The unique identifier of the organization, e.g. an AWS Org ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl Organization {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &["name", "ou_name", "ou_uid", "uid"];
}

impl Validate for Organization {
    /// Enforces the oracle's `organization` constraint (`at_least_one` of
    /// `name`, `uid`) and the extension-key collision check.
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("name", self.name.is_some()), ("uid", self.uid.is_some())]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        r
    }
}

/// OCSF `user` object: describes the user identity and characteristics.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct User {
    /// The user's account or the account associated with the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    /// The unique identifier of the user's credential, e.g. an AWS Access
    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_uid: Option<String>,
    /// The display name of the user, as reported by the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The domain where the user is defined, e.g. the LDAP or Active
    /// Directory domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The user's primary email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_addr: Option<String>,
    /// The user's forwarding email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_addr: Option<String>,
    /// The full name of the user, as reported by the product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// The administrative groups to which the user belongs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Group>>,
    /// The user has a multi-factor or secondary-factor device assigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_mfa: Option<bool>,
    /// The additional LDAP attributes that describe a person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap_person: Option<serde_json::Value>,
    /// The username, e.g. `janedoe1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Organization and org unit related to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<Organization>,
    /// The telephone number of the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Details about the programmatic credentials (API keys, access
    /// tokens, certificates, etc.) associated with the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programmatic_credentials: Option<Vec<serde_json::Value>>,
    /// The risk level, normalized to the caption of `risk_level_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// The normalized risk level id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level_id: Option<RiskLevelId>,
    /// The risk score as reported by the event source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    /// The type of the user, e.g. `System`, `AWS IAM User`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The normalized user type identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<UserTypeId>,
    /// The unique user identifier, e.g. the Windows user SID, ActiveDirectory
    /// DN, or AWS user ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The alternate user identifier, e.g. the Active Directory user GUID
    /// or AWS user Principal ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_alt: Option<String>,
    /// Unknown/future fields, preserved losslessly. Collision-checked at
    /// [`Validate::validate`].
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl User {
    /// Modeled wire-name set, pinned to the schemars property set by the
    /// conformance harness.
    #[doc(hidden)]
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "account",
        "credential_uid",
        "display_name",
        "domain",
        "email_addr",
        "forward_addr",
        "full_name",
        "groups",
        "has_mfa",
        "ldap_person",
        "name",
        "org",
        "phone_number",
        "programmatic_credentials",
        "risk_level",
        "risk_level_id",
        "risk_score",
        "type",
        "type_id",
        "uid",
        "uid_alt",
    ];
}

impl Validate for User {
    /// Enforces the oracle's `user` constraint (`at_least_one` of `account`,
    /// `name`, `uid`) and the extension-key collision check, then recurses
    /// into the constrained typed children (`account`, `org`, `groups`).
    fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::new();
        r.at_least_one(&[
            ("account", self.account.is_some()),
            ("name", self.name.is_some()),
            ("uid", self.uid.is_some()),
        ]);
        check_other_collisions(&self.other, Self::FIELD_NAMES, "", &mut r);
        if let Some(account) = &self.account {
            check_nested(account, "account", &mut r);
        }
        if let Some(org) = &self.org {
            check_nested(org, "org", &mut r);
        }
        if let Some(groups) = &self.groups {
            for (i, group) in groups.iter().enumerate() {
                check_nested(group, &format!("groups[{i}]"), &mut r);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::Validate;

    #[test]
    fn user_type_id_roundtrips_known_and_unrecognized() {
        assert_eq!(UserTypeId::from(2), UserTypeId::Admin);
        assert_eq!(UserTypeId::from(0), UserTypeId::Unknown);
        assert_eq!(UserTypeId::from(1234), UserTypeId::Unrecognized(1234));
    }

    #[test]
    fn user_recurses_into_invalid_account() {
        // Parent's own `at_least_one` is satisfied (name set) so only the
        // nested account's failure can invalidate it.
        let user = User {
            name: Some("alice".into()),
            account: Some(Account::default()), // invalid: no name/uid
            ..Default::default()
        };
        let report = user.validate();
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.attribute.starts_with("account."))
        );
    }

    #[test]
    fn user_recurses_into_invalid_org() {
        let user = User {
            name: Some("alice".into()),
            org: Some(Organization::default()), // invalid: no name/uid
            ..Default::default()
        };
        let report = user.validate();
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.attribute.starts_with("org."))
        );
    }

    #[test]
    fn user_recurses_into_invalid_group_entry() {
        let user = User {
            name: Some("alice".into()),
            groups: Some(vec![Group::default()]), // invalid: no name/uid
            ..Default::default()
        };
        let report = user.validate();
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.attribute.starts_with("groups[0]."))
        );
    }

    #[test]
    fn group_roundtrips_unknown_fields() {
        let json = r#"{"name":"Engineering","future_field":1}"#;
        let group: Group = serde_json::from_str(json).unwrap();
        assert_eq!(group.other["future_field"], 1);
        let out = serde_json::to_value(&group).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }

    #[test]
    fn account_roundtrips_unknown_fields() {
        let json = r#"{"uid":"123456789012","future_field":1}"#;
        let account: Account = serde_json::from_str(json).unwrap();
        assert_eq!(account.other["future_field"], 1);
        let out = serde_json::to_value(&account).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("name").is_none());
    }

    #[test]
    fn organization_roundtrips_unknown_fields() {
        let json = r#"{"name":"Widget, Inc.","future_field":1}"#;
        let org: Organization = serde_json::from_str(json).unwrap();
        assert_eq!(org.other["future_field"], 1);
        let out = serde_json::to_value(&org).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }

    #[test]
    fn user_roundtrips_unknown_fields() {
        let json = r#"{"name":"janedoe1","future_field":1}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.other["future_field"], 1);
        let out = serde_json::to_value(&user).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }

    #[test]
    fn actor_type_at_least_one_constraints_enforced() {
        assert!(!Group::default().validate().is_valid());
        assert!(!Account::default().validate().is_valid());
        assert!(!Organization::default().validate().is_valid());
        assert!(!User::default().validate().is_valid());

        let g = Group {
            name: Some("Engineering".into()),
            ..Default::default()
        };
        assert!(g.validate().is_valid());
        let a = Account {
            uid: Some("123".into()),
            ..Default::default()
        };
        assert!(a.validate().is_valid());
        let o = Organization {
            name: Some("Widget, Inc.".into()),
            ..Default::default()
        };
        assert!(o.validate().is_valid());
        // `user` is satisfied by `account` alone (neither name nor uid).
        let u = User {
            account: Some(Account {
                uid: Some("123".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(u.validate().is_valid());
    }

    #[test]
    fn actor_type_extension_key_collision_is_invalid() {
        let mut g = Group {
            name: Some("E".into()),
            ..Default::default()
        };
        g.other.insert("uid".to_string(), serde_json::Value::Null);
        assert!(g.validate().errors.iter().any(|e| e.attribute == "other"));

        let mut u = User {
            name: Some("j".into()),
            ..Default::default()
        };
        u.other.insert("uid".to_string(), serde_json::Value::Null);
        assert!(u.validate().errors.iter().any(|e| e.attribute == "other"));
    }
}
