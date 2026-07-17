use serde_json::Value;

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
