//! Oracle conformance for the four OCSF Findings (category 2) event classes.
//!
//! Each class is gated three ways: `assert_class_matches` (property names both
//! directions vs the FULL compile, required set vs the BASE compile, coarse
//! types), `assert_enum_matches` for every `ocsf_enum!` we generated against
//! its oracle vocabulary, and — for `VulnerabilityFinding` — a fully
//! constructed sample validated against the vendored JSON-Schema oracle.

mod conformance;
use conformance::*;
use ocsf_core::base::OcsfClass;
use ocsf_core::enums::SeverityId;
use ocsf_core::findings::*;
use ocsf_core::objects::{Cve, FindingInfo, Metadata, Product, RiskLevelId, Vulnerability};
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

// ---------------------------------------------------------------------------
// Shared finding-enum vocabularies. status_id/action_id/confidence_id/
// disposition_id/risk_level_id are byte-for-byte identical across all four
// classes (verified), so one shared type is proven against a representative
// class; risk_level_id reuses the existing `objects::RiskLevelId`. impact_id
// occurs only on detection_finding.
// ---------------------------------------------------------------------------

#[test]
fn finding_status_id_matches_oracle() {
    assert_enum_matches(
        FindingStatusId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "status_id",
    );
}

#[test]
fn finding_action_id_matches_oracle() {
    assert_enum_matches(
        FindingActionId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "action_id",
    );
}

#[test]
fn finding_confidence_id_matches_oracle() {
    assert_enum_matches(
        FindingConfidenceId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "confidence_id",
    );
}

#[test]
fn finding_disposition_id_matches_oracle() {
    assert_enum_matches(
        FindingDispositionId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "disposition_id",
    );
}

#[test]
fn finding_risk_level_id_reuses_objects_enum() {
    assert_enum_matches(
        RiskLevelId::KNOWN,
        &Oracle::class_full("vulnerability_finding"),
        "risk_level_id",
    );
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
    // constraint; the error must surface on the parent under `vulnerabilities`.
    vf.vulnerabilities = vec![Vulnerability::default()];
    let report = vf.validate();
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.attribute == "vulnerabilities")
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
