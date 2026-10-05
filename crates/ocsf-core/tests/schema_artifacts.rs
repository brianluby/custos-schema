use std::fs;

use serde_json::Value;

use ocsf_core::discovery::*;
use ocsf_core::enums::SeverityId;
use ocsf_core::findings::*;
use ocsf_core::objects::{
    Cve, Device, FindingInfo, Metadata, Package, Product, ResourceDetails, Sbom, User,
    Vulnerability,
};

#[test]
fn committed_artifacts_encode_ocsf_constraints() {
    // vulnerability_finding has no oracle `constraints`, so this asserts the
    // baseline schemars 0.8 root shape: `class_uid` is a modeled property and
    // `vulnerabilities` (the class's one required nested-object attribute) is
    // in the root `required` array.
    let s: Value = serde_json::from_str(include_str!(
        "../../../schemas/vulnerability_finding.schema.json"
    ))
    .expect("run `cargo xtask schemas` first");
    assert!(s["properties"]["class_uid"].is_object());
    assert!(
        s["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "vulnerabilities")
    );
}

#[test]
fn aspf_artifact_encodes_injected_at_least_one_constraint() {
    // application_security_posture_finding has an oracle
    // `constraints: {"at_least_one": [...]}` that schemars cannot express
    // from the struct alone; `inject_constraints` adds it as
    // `allOf: [{ anyOf: [{ required: [attr] }, ...] }]`. Assert the actual
    // injected shape rather than assuming it — verified directly against the
    // generated artifact.
    let s: Value = serde_json::from_str(include_str!(
        "../../../schemas/application_security_posture_finding.schema.json"
    ))
    .expect("run `cargo xtask schemas` first");

    let all_of = s["allOf"].as_array().expect("allOf must be present");
    assert_eq!(all_of.len(), 1);
    let any_of = all_of[0]["anyOf"]
        .as_array()
        .expect("allOf[0] must contain anyOf");

    let required_attrs: Vec<&str> = any_of
        .iter()
        .map(|clause| {
            clause["required"][0]
                .as_str()
                .expect("each anyOf clause is {required: [attr]}")
        })
        .collect();
    assert_eq!(
        required_attrs,
        vec![
            "application",
            "compliance",
            "remediation",
            "vulnerabilities"
        ]
    );
}

#[test]
fn vulnerability_finding_artifact_encodes_class_uid_const_and_nested_product_constraint() {
    // `inject_class_uid_consts` sets `const` on `class_uid`/`category_uid`
    // from the class's `OcsfClass` trait consts (cross-checked against the
    // oracle at generation time), and `inject_nested_object_constraints`
    // injects the `product` object's oracle `at_least_one: [name, uid]`
    // constraint onto the `Product` definition schemars collects for
    // `vulnerability_finding`.
    let s: Value = serde_json::from_str(include_str!(
        "../../../schemas/vulnerability_finding.schema.json"
    ))
    .expect("run `cargo xtask schemas` first");

    assert_eq!(s["properties"]["class_uid"]["const"], 2002);

    let product_any_of = s["definitions"]["Product"]["allOf"][0]["anyOf"]
        .as_array()
        .expect("Product definition must carry an injected allOf[0].anyOf");
    let required_attrs: Vec<&str> = product_any_of
        .iter()
        .map(|clause| {
            clause["required"][0]
                .as_str()
                .expect("each anyOf clause is {required: [attr]}")
        })
        .collect();
    assert_eq!(required_attrs, vec!["name", "uid"]);
}

#[test]
fn detection_finding_artifact_encodes_impact_score_maximum() {
    // `inject_scalar_ranges` reads `ocsf_core::validation::ranges::IMPACT_SCORE`
    // and injects `minimum`/`maximum` onto `impact_score`, the one property
    // among the 8 supported classes that carries this range (only
    // `detection_finding` has an `impact_score` attribute).
    let s: Value = serde_json::from_str(include_str!(
        "../../../schemas/detection_finding.schema.json"
    ))
    .expect("run `cargo xtask schemas` first");

    assert_eq!(s["properties"]["impact_score"]["maximum"], 100);
    assert_eq!(s["properties"]["impact_score"]["minimum"], 0);
}

// ---------------------------------------------------------------------------
// Sample-event validation against the COMMITTED generated artifacts
// (`schemas/<class>.schema.json`), not the vendored oracle.
//
// `conformance_findings.rs`/`conformance_discovery.rs` already validate
// hand-built samples against `conformance/jsonschema/classes/*.json` (the
// vendored upstream oracle). That never exercises this repo's own generated
// `schemas/` artifacts, so a bug in `xtask/src/schemas.rs`'s injection
// passes (wrong `const`, malformed `anyOf`/`oneOf`, wrong scalar range)
// could ship undetected as long as the hand-modeled Rust types stayed
// correct. These tests close that gap: build a minimal valid sample via the
// class constructor (mirroring the `sample_*` helpers in the conformance
// suites), serialize it, and validate the resulting JSON against the
// artifact this crate actually ships.
// ---------------------------------------------------------------------------

/// Root of the committed generated schema artifacts. Tests run with CWD =
/// `crates/ocsf-core`, so this is resolved from the crate's manifest dir at
/// compile time rather than assumed from the process's working directory.
const SCHEMAS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");

/// Loads and parses the committed JSON Schema artifact for an event class.
///
/// # Panics
///
/// Panics if the schema file cannot be read or contains invalid JSON.
///
/// # Examples
///
/// ```
/// let schema = load_artifact_schema("vulnerability_finding");
/// assert!(schema.is_object());
/// ```
fn load_artifact_schema(class: &str) -> Value {
    let path = format!("{SCHEMAS_DIR}/{class}.schema.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read schema artifact {path}: {e}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse schema artifact {path}: {e}"))
}

/// Validates an event against the committed schema artifact for its class.
///
/// # Panics
///
/// Panics if the schema artifact is invalid or if the event fails validation.
///
/// # Examples
///
/// ```no_run
/// let event = serde_json::json!({ /* valid event fields */ });
/// assert_valid_against_artifact(&event, "vulnerability_finding");
/// ```
fn assert_valid_against_artifact(event: &Value, class: &str) {
    let schema = load_artifact_schema(class);
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|e| panic!("invalid schema artifact {class}.schema.json: {e}"));
    let errors: Vec<String> = validator
        .iter_errors(event)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "sample event failed validation against committed artifact {class}.schema.json:\n{}",
        errors.join("\n")
    );
}

/// Asserts that an event fails validation against a committed class schema artifact.
///
/// # Examples
///
/// ```rust,ignore
/// let event = serde_json::json!({ "invalid": true });
/// assert_invalid_against_artifact(&event, "vulnerability_finding");
/// ```
fn assert_invalid_against_artifact(event: &Value, class: &str) {
    let schema = load_artifact_schema(class);
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|e| panic!("invalid schema artifact {class}.schema.json: {e}"));
    assert!(
        !validator.is_valid(event),
        "expected sample event to FAIL validation against {class}.schema.json, but it validated \
         successfully"
    );
}

// --- sample constructors, mirroring conformance_findings.rs / conformance_discovery.rs ---

/// Creates a representative vulnerability finding for schema validation.
///
/// # Examples
///
/// ```
/// let finding = sample_vf();
/// assert_eq!(finding.finding_info.uid, "f-1");
/// ```
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

/// Creates a representative compliance finding for schema validation tests.
///
/// # Examples
///
/// ```
/// let finding = sample_cf();
/// assert_eq!(finding.finding_info.uid, "f-1");
/// ```
///
/// Returns a compliance finding populated with standard test metadata and finding details.
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

/// Creates a representative detection finding for schema validation tests.
///
/// # Examples
///
/// ```
/// let finding = sample_df();
/// assert_eq!(finding.activity_id, DetectionFindingActivityId::Create);
/// ```
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

/// Creates an application security posture finding sample that satisfies its required finding constraint.
///
/// # Examples
///
/// ```
/// let finding = sample_aspf();
/// assert!(finding.vulnerabilities.is_some());
/// ```
///
/// # Returns
///
/// An application security posture finding with a vulnerability entry.
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

/// Creates a representative user inventory event for schema validation.
///
/// # Examples
///
/// ```
/// let inventory = sample_user_inventory();
/// assert_eq!(inventory.user.unwrap().name.as_deref(), Some("jdoe"));
/// ```
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

/// Builds a software inventory event containing package and SBOM details.
///
/// # Examples
///
/// ```
/// let event = sample_software_info();
/// assert!(event.package.is_some());
/// assert!(event.sbom.is_some());
/// ```
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

/// Builds a cloud resources inventory event containing a sample resource.
///
/// # Examples
///
/// ```
/// let event = sample_cloud_resources_inventory_info();
/// assert!(event.resources.is_some());
/// ```
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

// --- one test per event class (8): sample validates against the committed artifact ---

#[test]
fn vulnerability_finding_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_vf()).unwrap();
    assert_valid_against_artifact(&value, "vulnerability_finding");
}

#[test]
fn compliance_finding_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_cf()).unwrap();
    assert_valid_against_artifact(&value, "compliance_finding");
}

#[test]
fn detection_finding_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_df()).unwrap();
    assert_valid_against_artifact(&value, "detection_finding");
}

#[test]
fn application_security_posture_finding_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_aspf()).unwrap();
    assert_valid_against_artifact(&value, "application_security_posture_finding");
}

#[test]
fn inventory_info_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_inventory_info()).unwrap();
    assert_valid_against_artifact(&value, "inventory_info");
}

#[test]
fn user_inventory_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_user_inventory()).unwrap();
    assert_valid_against_artifact(&value, "user_inventory");
}

#[test]
fn software_info_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_software_info()).unwrap();
    assert_valid_against_artifact(&value, "software_info");
}

#[test]
fn cloud_resources_inventory_info_sample_validates_against_artifact() {
    let value = serde_json::to_value(sample_cloud_resources_inventory_info()).unwrap();
    assert_valid_against_artifact(&value, "cloud_resources_inventory_info");
}

// --- negative case: proves the injected Product anyOf bites non-Rust consumers ---

#[test]
fn sample_with_default_product_fails_artifact_validation() {
    // `Metadata::new(Product::default())` violates the `product` object's
    // `at_least_one: [name, uid]` oracle constraint, which
    // `inject_nested_object_constraints` encodes onto the `Product`
    // definition as `allOf: [{ anyOf: [{required:[name]}, {required:[uid]}] }]`.
    // This proves that constraint actually rejects a non-conforming event
    // when validated by an external JSON-Schema validator against the
    // committed artifact — not just by this crate's own `Validate::validate()`.
    let mut vf = sample_vf();
    vf.metadata = Metadata::new(Product::default());
    let value = serde_json::to_value(&vf).unwrap();
    assert_invalid_against_artifact(&value, "vulnerability_finding");
}

#[test]
fn sample_with_null_product_name_fails_artifact_validation() {
    // A nullable attribute set to `null` (`{"name": null}`) must NOT satisfy
    // the `product` object's `at_least_one: [name, uid]` constraint. A bare
    // `{"required": ["name"]}` clause only checks key presence and would let
    // an explicit null through; the injected `{"not": {"type": "null"}}`
    // predicate closes that hole. Inject `metadata.product.name = null` into
    // an otherwise valid event and assert the external validator rejects it.
    let mut value = serde_json::to_value(sample_vf()).unwrap();
    value["metadata"]["product"]["name"] = Value::Null;
    // Guard: no `uid` present, so the only satisfiable branch is `name`.
    assert!(value["metadata"]["product"].get("uid").is_none());
    assert_invalid_against_artifact(&value, "vulnerability_finding");
}
