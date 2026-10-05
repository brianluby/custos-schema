# custos-schema

Rust types for OCSF (Open Cybersecurity Schema Framework) 1.8.0, curated for
ASPM (Application Security Posture Management) use cases: vulnerability
findings, compliance findings, detection findings, and asset/software
inventory.

This is a community project, not an OCSF-affiliated or vendor-affiliated
release. It hand-models the subset of OCSF 1.8.0 that ASPM tooling actually
needs, verified byte-for-byte against the official OCSF server compile (see
[Oracle workflow](#oracle-workflow) below), rather than generating bindings
for the entire schema.

`ocsf-core` is the contract crate: a stable, dependency-light set of Rust
types and validation that downstream format adapters build on. It has no
knowledge of any specific ingest format (CycloneDX, SPDX, SARIF, OSV, VEX) —
that mapping logic lives in separate adapter crates so `ocsf-core` stays a
narrow, auditable contract.

## Crate map

| crate | status | purpose |
| --- | --- | --- |
| `ocsf-core` | available | OCSF 1.8.0 types, validation, and JSON Schema artifacts for the 8 supported event classes |
| `ocsf-cyclonedx` | planned | CycloneDX SBOM/VEX ingest adapter |
| `ocsf-spdx` | planned | SPDX SBOM ingest adapter |
| `ocsf-osv` | planned | OSV vulnerability-database ingest adapter |
| `ocsf-sarif` | planned | SARIF static-analysis ingest adapter |
| `ocsf-vex` | planned | OpenVEX + CycloneDX-VEX exploitability-statement ingest adapter |

The planned adapter crates will each expose an `IngestContext` and a
`MappingReport` and depend on `ocsf-core` for their output types; they are
not part of this crate's API surface and are out of scope until `ocsf-core`'s
API is stable.

### Supported event classes

`ocsf-core` models 8 OCSF 1.8.0 event classes end to end (`findings/` and
`discovery/`):

- `vulnerability_finding` (class 2002)
- `compliance_finding` (class 2003)
- `detection_finding` (class 2004)
- `application_security_posture_finding` (class 2007)
- `inventory_info` (class 5001)
- `user_inventory` (class 5003)
- `software_info` (class 5020)
- `cloud_resources_inventory_info` (class 5023)

Every object each class can reach (123 objects total, per
`conformance/closure-report.json`) is represented — either as a fully typed
Rust struct or as passthrough JSON. The design spec's pre-implementation
estimate was ~119–132 objects (the range reflected uncertainty over profile
inclusions); 123 is the measured count of the realized closure, recorded in
`conformance/closure-report.json`. See [Tier policy](#tier-policy) for which
is which and why.

## Quick example

Build a `VulnerabilityFinding` with `new()`, validate it, and serialize it.
This mirrors `sample_vf()` / `vulnerability_finding_validates_and_matches_oracle_jsonschema`
in `crates/ocsf-core/tests/conformance_findings.rs`. Run it with
`cargo test --workspace --all-features` — this is the gate developers and
(once a pipeline exists) CI should run before merging, and it checks both
the crate's own `Validate` trait and the vendored OCSF JSON-Schema oracle:

```rust
use ocsf_core::base::OcsfClass;
use ocsf_core::enums::SeverityId;
use ocsf_core::findings::{VulnerabilityFinding, VulnerabilityFindingActivityId};
use ocsf_core::objects::{Cve, FindingInfo, Metadata, Product, Vulnerability};
use ocsf_core::validation::Validate;

let finding = VulnerabilityFinding::new(
    1_752_000_000_000, // time: milliseconds since the Unix epoch
    VulnerabilityFindingActivityId::Create,
    SeverityId::High,
    Metadata::new(Product::named("my-scanner")),
    FindingInfo {
        title: Some("Log4Shell in service X".into()),
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
);

assert_eq!(finding.type_uid(), 200201);

let report = finding.validate();
assert!(report.is_valid(), "errors: {:?}", report.errors);

let json = serde_json::to_value(&finding).unwrap();
```

`new()` fills in `class_uid`, `category_uid`, and `type_uid` from the
`OcsfClass` constants and the given `activity_id`; every optional attribute
starts unset. `validate()` enforces the object's OCSF `constraints` (here,
`vulnerability`'s `just_one` rule over `advisory`/`cve`/`cwe`) in addition to
required-field presence. Unknown/future JSON fields round-trip losslessly
through the `#[serde(flatten)] other` field present on every generated
struct.

## Oracle workflow

`ocsf-core`'s types are not hand-verified against the OCSF documentation —
they are checked against a vendored copy of the actual OCSF server compile
output (`conformance/api/` and `conformance/jsonschema/`), pinned to schema
version 1.8.0. Two `xtask` commands drive that workflow:

```bash
# Re-fetch the OCSF 1.8.0 server compile for the 8 supported classes and
# their full object closure, and regenerate conformance/closure-report.json.
cargo xtask sync-oracle

# Regenerate the schemars-derived JSON Schema artifacts under schemas/
# from the current Rust types.
cargo xtask schemas

# CI mode: fail if the checked-in schemas/ artifacts are stale relative
# to the current Rust types, without writing anything.
cargo xtask schemas --check
```

The `crates/ocsf-core/tests/conformance*.rs` suite asserts every typed
struct's field names, set of required fields, and coarse types against the
oracle,
and every `ocsf_enum!` against the oracle's enum vocabulary. `sync-oracle`
should only be re-run on a deliberate OCSF version bump, since it rewrites
the ground truth the conformance tests check against.

## OCSF version policy

`ocsf-core` is pinned to a single OCSF schema version at a time:

```rust
pub const OCSF_VERSION: &str = "1.8.0";
```

(`crates/ocsf-core/src/lib.rs`). There is no multi-version support: bumping
OCSF versions is a deliberate, whole-crate change that re-runs
`cargo xtask sync-oracle`, re-verifies every typed object and enum against
the new oracle, and updates this constant in the same change. Consumers
that need to pin to 1.8.0 semantics indefinitely should pin the
`ocsf-core` crate version, not just the OCSF version string.

## Tier policy

Not every object in the OCSF closure is a hand-modeled Rust struct. Objects
are split into a `typed` tier (dedicated struct, oracle-verified, validated)
and a `json` tier (opaque passthrough `serde_json::Value`), with an additive
promotion path between them. The full rationale, the promotion criteria, and
the tier assignment for all 123 objects in the closure are in
[`docs/typed-objects.md`](docs/typed-objects.md). That table is enforced by
`crates/ocsf-core/tests/tier_policy.rs`: every object in
`conformance/closure-report.json` must have a row.

## License

Licensed under Apache-2.0 (see the `license` field in `Cargo.toml`).
