//! Oracle conformance for the four OCSF Findings (category 2) event classes.
//!
//! Each class is gated three ways: `assert_class_matches` (property names both
//! directions vs the FULL compile, required set vs the BASE compile, coarse
//! types), `assert_enum_matches` for every `ocsf_enum!` we generated against
//! its oracle vocabulary. A fully constructed sample for every class is
//! validated against the vendored JSON-Schema oracle.

mod conformance;
use conformance::*;
use ocsf_core::base::OcsfClass;
use ocsf_core::enums::SeverityId;
use ocsf_core::findings::*;
use ocsf_core::objects::{Cloud, Cve, FindingInfo, Metadata, Product, RiskLevelId, Vulnerability};
use ocsf_core::validation::Validate;

// ---------------------------------------------------------------------------
// Structural conformance: schema shape vs the API-compile oracle.
// ---------------------------------------------------------------------------

#[test]
fn vulnerability_finding_matches_oracle() {
    assert_class_matches::<VulnerabilityFinding>("vulnerability_finding");
    assert_enum_matches(
        VulnerabilityFindingActivityId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "activity_id",
    );
}

#[test]
fn compliance_finding_matches_oracle() {
    assert_class_matches::<ComplianceFinding>("compliance_finding");
    assert_enum_matches(
        ComplianceFindingActivityId::KNOWN,
        &Oracle::class_full("compliance_finding"),
        "activity_id",
    );
}

#[test]
fn detection_finding_matches_oracle() {
    assert_class_matches::<DetectionFinding>("detection_finding");
    assert_enum_matches(
        DetectionFindingActivityId::KNOWN,
        &Oracle::class_full("detection_finding"),
        "activity_id",
    );
}

#[test]
fn application_security_posture_finding_matches_oracle() {
    assert_class_matches::<ApplicationSecurityPostureFinding>(
        "application_security_posture_finding",
    );
    assert_enum_matches(
        ApplicationSecurityPostureFindingActivityId::KNOWN,
        &Oracle::class_full("application_security_posture_finding"),
        "activity_id",
    );
}

/// `FIELD_NAMES` (read by the extension-key collision check) must stay in
/// lockstep with the schemars property set for all four Findings classes.
#[test]
fn field_names_match_schema() {
    assert_field_names_match::<VulnerabilityFinding>(
        "class",
        "vulnerability_finding",
        VulnerabilityFinding::FIELD_NAMES,
    );
    assert_field_names_match::<ComplianceFinding>(
        "class",
        "compliance_finding",
        ComplianceFinding::FIELD_NAMES,
    );
    assert_field_names_match::<DetectionFinding>(
        "class",
        "detection_finding",
        DetectionFinding::FIELD_NAMES,
    );
    assert_field_names_match::<ApplicationSecurityPostureFinding>(
        "class",
        "application_security_posture_finding",
        ApplicationSecurityPostureFinding::FIELD_NAMES,
    );
}

// ---------------------------------------------------------------------------
// Shared finding-enum vocabularies. status_id/action_id/confidence_id/
// disposition_id/risk_level_id are byte-for-byte identical across all four
// classes (verified), so every owning class is checked; risk_level_id reuses
// the existing `objects::RiskLevelId`. impact_id occurs only on
// detection_finding.
// ---------------------------------------------------------------------------

const FINDING_CLASSES: &[&str] = &[
    "vulnerability_finding",
    "compliance_finding",
    "detection_finding",
    "application_security_posture_finding",
];

fn assert_finding_enum_matches(known: &[i32], attr: &str) {
    for class in FINDING_CLASSES {
        let oracle = Oracle::class_full(class);
        assert_enum_matches(known, &oracle, attr);
    }
}

#[test]
fn finding_status_id_matches_oracle() {
    assert_finding_enum_matches(FindingStatusId::KNOWN, "status_id");
}

#[test]
fn finding_action_id_matches_oracle() {
    assert_finding_enum_matches(FindingActionId::KNOWN, "action_id");
}

#[test]
fn finding_confidence_id_matches_oracle() {
    assert_finding_enum_matches(FindingConfidenceId::KNOWN, "confidence_id");
}

#[test]
fn finding_disposition_id_matches_oracle() {
    assert_finding_enum_matches(FindingDispositionId::KNOWN, "disposition_id");
}

#[test]
fn finding_risk_level_id_reuses_objects_enum() {
    assert_finding_enum_matches(RiskLevelId::KNOWN, "risk_level_id");
}

#[test]
fn finding_impact_id_matches_oracle() {
    assert_enum_matches(
        FindingImpactId::KNOWN,
        &Oracle::class_full("detection_finding"),
        "impact_id",
    );
}

// ---------------------------------------------------------------------------
// VulnerabilityFinding: full sample lifecycle (construct, validate,
// JSON-Schema oracle, profile-conditional requirement).
// ---------------------------------------------------------------------------

fn sample_vf() -> VulnerabilityFinding {
    VulnerabilityFinding::new(
        1_752_000_000_000,
        VulnerabilityFindingActivityId::Create,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            title: Some("t".into()),
            uid: "f-1".into(),
            ..Default::default()
        },
        vec![Vulnerability {
            cve: Some(Cve {
                uid: "CVE-2021-44228".into(),
                ..Default::default()
            }),
            ..Default::default()
        }],
    )
}

#[test]
fn vulnerability_finding_validates_and_matches_oracle_jsonschema() {
    let vf = sample_vf();
    assert_eq!(vf.type_uid(), 200201);
    let report = vf.validate();
    assert!(report.is_valid(), "errors: {:?}", report.errors);
    let value = serde_json::to_value(&vf).unwrap();
    assert_valid_against_oracle_schema(&value, "vulnerability_finding", "base");
}

#[test]
fn vulnerability_finding_uid_fields_set_from_constants() {
    let vf = sample_vf();
    assert_eq!(vf.class_uid, 2002);
    assert_eq!(vf.category_uid, 2);
    assert_eq!(vf.type_uid, 200201);
}

#[test]
fn vulnerability_finding_uid_mismatch_is_invalid() {
    let mut vf = sample_vf();
    vf.type_uid = 999_999;
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|e| e.attribute == "type_uid"));
}

#[test]
fn vulnerability_finding_empty_vulnerabilities_is_invalid() {
    let mut vf = sample_vf();
    vf.vulnerabilities.clear();
    assert!(!vf.validate().is_valid());
}

#[test]
fn vulnerability_finding_nested_vulnerability_errors_surface() {
    let mut vf = sample_vf();
    // A vulnerability with none of advisory/cve/cwe violates its just_one
    // constraint; the error must surface at the indexed child path.
    vf.vulnerabilities = vec![Vulnerability::default()];
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute == "vulnerabilities[0].advisory, cve, cwe")
    );
}

#[test]
fn profile_requirement_is_conditional() {
    // Without the cloud profile, omitting `cloud` is valid.
    let vf = sample_vf();
    assert!(vf.validate().is_valid());

    // Declaring the cloud profile makes `cloud` required.
    let mut vf = sample_vf();
    vf.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!vf.validate().is_valid());

    // Supplying `cloud` satisfies the conditional requirement.
    vf.cloud = Some(Default::default());
    assert!(
        vf.validate().is_valid(),
        "errors: {:?}",
        vf.validate().errors
    );
}

// ---------------------------------------------------------------------------
// ApplicationSecurityPostureFinding: class-level at_least_one constraint over
// [application, compliance, remediation, vulnerabilities].
// ---------------------------------------------------------------------------

#[test]
fn aspf_at_least_one_constraint_enforced() {
    let mut f = ApplicationSecurityPostureFinding::new(
        1_752_000_000_000,
        ApplicationSecurityPostureFindingActivityId::Create,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            uid: "f-1".into(),
            ..Default::default()
        },
    );
    // None of application/compliance/remediation/vulnerabilities present.
    let report = f.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute.contains("application"))
    );

    // Satisfy the constraint with a vulnerability.
    f.vulnerabilities = Some(vec![Vulnerability {
        cve: Some(Cve {
            uid: "CVE-2021-44228".into(),
            ..Default::default()
        }),
        ..Default::default()
    }]);
    assert!(f.validate().is_valid(), "errors: {:?}", f.validate().errors);
}

#[test]
fn compliance_finding_type_uid_is_correct() {
    let f = ComplianceFinding::new(
        1_752_000_000_000,
        ComplianceFindingActivityId::Update,
        SeverityId::Medium,
        Metadata::new(Product::named("test")),
        FindingInfo {
            uid: "f-1".into(),
            ..Default::default()
        },
        Default::default(),
    );
    assert_eq!(f.type_uid(), 200302);
    assert!(f.validate().is_valid(), "errors: {:?}", f.validate().errors);
}

#[test]
fn detection_finding_type_uid_is_correct() {
    let f = DetectionFinding::new(
        1_752_000_000_000,
        DetectionFindingActivityId::Close,
        SeverityId::Low,
        Metadata::new(Product::named("test")),
        FindingInfo {
            uid: "f-1".into(),
            ..Default::default()
        },
    );
    assert_eq!(f.type_uid(), 200403);
    assert!(f.validate().is_valid(), "errors: {:?}", f.validate().errors);
}

// ---------------------------------------------------------------------------
// ComplianceFinding: full sample lifecycle (profile-conditional requirement,
// serde round-trip), mirroring the VulnerabilityFinding coverage above.
// ---------------------------------------------------------------------------

fn sample_cf() -> ComplianceFinding {
    ComplianceFinding::new(
        1_752_000_000_000,
        ComplianceFindingActivityId::Create,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            title: Some("t".into()),
            uid: "f-1".into(),
            ..Default::default()
        },
        Default::default(),
    )
}

#[test]
fn compliance_finding_validates_and_matches_oracle_jsonschema() {
    let cf = sample_cf();
    let value = serde_json::to_value(&cf).unwrap();
    assert_valid_against_oracle_schema(&value, "compliance_finding", "base");
}

#[test]
fn compliance_finding_profile_requirement_is_conditional() {
    // Without the cloud profile, omitting `cloud` is valid.
    let cf = sample_cf();
    assert!(
        cf.validate().is_valid(),
        "errors: {:?}",
        cf.validate().errors
    );

    // Declaring the cloud profile makes `cloud` required.
    let mut cf = sample_cf();
    cf.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!cf.validate().is_valid());

    // Supplying `cloud` satisfies the conditional requirement.
    cf.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(
        cf.validate().is_valid(),
        "errors: {:?}",
        cf.validate().errors
    );
}

#[test]
fn compliance_finding_roundtrips_through_json() {
    let cf = sample_cf();
    let value = serde_json::to_value(&cf).unwrap();
    let back: ComplianceFinding = serde_json::from_value(value).unwrap();
    assert_eq!(cf, back);
}

// ---------------------------------------------------------------------------
// DetectionFinding: full sample lifecycle (profile-conditional requirement,
// serde round-trip).
// ---------------------------------------------------------------------------

fn sample_df() -> DetectionFinding {
    DetectionFinding::new(
        1_752_000_000_000,
        DetectionFindingActivityId::Create,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            title: Some("t".into()),
            uid: "f-1".into(),
            ..Default::default()
        },
    )
}

#[test]
fn detection_finding_validates_and_matches_oracle_jsonschema() {
    let df = sample_df();
    let value = serde_json::to_value(&df).unwrap();
    assert_valid_against_oracle_schema(&value, "detection_finding", "base");
}

#[test]
fn detection_finding_profile_requirement_is_conditional() {
    // Without the cloud profile, omitting `cloud` is valid.
    let df = sample_df();
    assert!(
        df.validate().is_valid(),
        "errors: {:?}",
        df.validate().errors
    );

    // Declaring the cloud profile makes `cloud` required.
    let mut df = sample_df();
    df.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!df.validate().is_valid());

    // Supplying `cloud` satisfies the conditional requirement.
    df.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(
        df.validate().is_valid(),
        "errors: {:?}",
        df.validate().errors
    );
}

#[test]
fn detection_finding_roundtrips_through_json() {
    let df = sample_df();
    let value = serde_json::to_value(&df).unwrap();
    let back: DetectionFinding = serde_json::from_value(value).unwrap();
    assert_eq!(df, back);
}

// ---------------------------------------------------------------------------
// ApplicationSecurityPostureFinding: full sample lifecycle (profile-
// conditional requirement, serde round-trip). `ApplicationSecurityPostureFinding::new`
// alone is intentionally invalid (its `at_least_one` constraint over
// [application, compliance, remediation, vulnerabilities] is unmet), so the
// sample here also supplies a valid `vulnerabilities` entry.
// ---------------------------------------------------------------------------

fn sample_aspf() -> ApplicationSecurityPostureFinding {
    let mut f = ApplicationSecurityPostureFinding::new(
        1_752_000_000_000,
        ApplicationSecurityPostureFindingActivityId::Create,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            title: Some("t".into()),
            uid: "f-1".into(),
            ..Default::default()
        },
    );
    f.vulnerabilities = Some(vec![Vulnerability {
        cve: Some(Cve {
            uid: "CVE-2021-44228".into(),
            ..Default::default()
        }),
        ..Default::default()
    }]);
    f
}

#[test]
fn application_security_posture_finding_validates_and_matches_oracle_jsonschema() {
    let f = sample_aspf();
    let value = serde_json::to_value(&f).unwrap();
    assert_valid_against_oracle_schema(&value, "application_security_posture_finding", "base");
}

#[test]
fn application_security_posture_finding_profile_requirement_is_conditional() {
    // Without the cloud profile, omitting `cloud` is valid.
    let f = sample_aspf();
    assert!(f.validate().is_valid(), "errors: {:?}", f.validate().errors);

    // Declaring the cloud profile makes `cloud` required.
    let mut f = sample_aspf();
    f.metadata.profiles = Some(vec!["cloud".into()]);
    assert!(!f.validate().is_valid());

    // Supplying `cloud` satisfies the conditional requirement.
    f.cloud = Some(Cloud {
        provider: "AWS".into(),
        ..Default::default()
    });
    assert!(f.validate().is_valid(), "errors: {:?}", f.validate().errors);
}

#[test]
fn application_security_posture_finding_roundtrips_through_json() {
    let f = sample_aspf();
    let value = serde_json::to_value(&f).unwrap();
    let back: ApplicationSecurityPostureFinding = serde_json::from_value(value).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// Unknown-field preservation: the `#[serde(flatten)] other` catch-all must
// losslessly round-trip attributes this codebase doesn't model yet, for
// every Findings event class. Proven here for VulnerabilityFinding, as
// representative of the shared pattern applied identically to all four.
// ---------------------------------------------------------------------------

#[test]
fn vulnerability_finding_roundtrips_unknown_fields() {
    let vf = sample_vf();
    let mut value = serde_json::to_value(&vf).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("x_future".to_string(), serde_json::json!({"a": 1}));

    let back: VulnerabilityFinding = serde_json::from_value(value).unwrap();
    assert_eq!(
        back.other.get("x_future"),
        Some(&serde_json::json!({"a": 1}))
    );

    let out = serde_json::to_value(&back).unwrap();
    assert_eq!(out["x_future"], serde_json::json!({"a": 1}));
}

// ---------------------------------------------------------------------------
// Permanent regression tests for the three verified review reproductions:
// each takes an otherwise-valid event and must make it INVALID.
//   1. an extension key that shadows a modeled field (`other["class_uid"]`),
//   2. an out-of-range `activity_id` (`Unrecognized(100)`), whose `type_uid`
//      must clamp to `class_uid * 100` and never collide with class 2003, and
//   3. a nested `metadata.product` that violates its own `at_least_one`
//      (`Metadata::new(Product::default())`).
// ---------------------------------------------------------------------------

fn vf_with_activity(activity: VulnerabilityFindingActivityId) -> VulnerabilityFinding {
    VulnerabilityFinding::new(
        1_752_000_000_000,
        activity,
        SeverityId::High,
        Metadata::new(Product::named("test")),
        FindingInfo {
            uid: "f-1".into(),
            ..Default::default()
        },
        vec![Vulnerability {
            cve: Some(Cve {
                uid: "CVE-2021-44228".into(),
                ..Default::default()
            }),
            ..Default::default()
        }],
    )
}

#[test]
fn regression_extension_key_collision_is_invalid() {
    let mut vf = sample_vf();
    assert!(vf.validate().is_valid());
    vf.other
        .insert("class_uid".to_string(), serde_json::Value::Null);
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute == "other" && e.message.contains("class_uid"))
    );
}

#[test]
fn regression_out_of_range_activity_is_invalid_and_cannot_collide() {
    let vf = vf_with_activity(VulnerabilityFindingActivityId::Unrecognized(100));
    // type_uid clamps to class_uid * 100 (200200); it must NOT be 200300,
    // which is class 2003 (compliance_finding) at activity 0.
    assert_eq!(vf.type_uid, 200200);
    assert_ne!(vf.type_uid, 200300);
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|e| e.attribute == "activity_id"));
}

#[test]
fn regression_negative_activity_is_invalid() {
    let vf = vf_with_activity(VulnerabilityFindingActivityId::Unrecognized(-5));
    assert_eq!(vf.type_uid, 200200);
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|e| e.attribute == "activity_id"));
}

#[test]
fn boundary_activity_99_other_is_valid() {
    // 99 (Other) is the top of the valid two-digit activity window.
    let vf = vf_with_activity(VulnerabilityFindingActivityId::Other);
    assert_eq!(vf.type_uid, 200299);
    assert!(
        vf.validate().is_valid(),
        "errors: {:?}",
        vf.validate().errors
    );
}

#[test]
fn regression_nested_metadata_product_constraint_is_invalid() {
    // Metadata::new(Product::default()) is no longer a valid sample: the
    // product violates its at_least_one, surfacing under `metadata.product.*`.
    let mut vf = sample_vf();
    vf.metadata = Metadata::new(Product::default());
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute.starts_with("metadata.product"))
    );
}

#[test]
fn regression_nested_finding_info_product_constraint_is_invalid() {
    // finding_info.product must satisfy its at_least_one(name, uid) constraint,
    // and violations must surface under `finding_info.product.*`.
    let mut vf = sample_vf();
    vf.finding_info.product = Some(Product::default());
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute.starts_with("finding_info.product"))
    );
}
