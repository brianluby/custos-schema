# OCSF Rust Schema Workspace — Design

Status: Approved
Date: 2026-07-17
OCSF target version: 1.8.0 (released 2026-03-18)

## Purpose

A Rust implementation of the OCSF schema focused on the classes an ASPM
platform needs: normalized findings and asset/software inventory, plus ingest
adapters from the security-format ecosystem (CycloneDX, SPDX, OSV, SARIF,
VEX). This is the platform contract for Custos and future projects.

No mature Rust OCSF crate exists (crates.io survey 2026-07-17: `ocsf`
0.0.1-alpha5 stale, `ocsf-schema-rs` abandoned alpha, `ocsf-types` 62
downloads, rest vendor-specific). There is a genuine community gap, so crates
use neutral `ocsf-*` naming — all required names verified unclaimed.

## Decisions (from design review)

| Decision | Choice |
| --- | --- |
| Scope | Curated ASPM core, extensible; not a full 80-class port |
| Type strategy | Hand-modeled, faithful to OCSF names/UIDs/semantics |
| Adapters | Ingest-only; OCSF JSON is the output contract |
| Consumers | Rust-first; JSON Schema artifacts generated for Go/TS/other |
| Naming | Neutral `ocsf-*`; internal git dependency first, publish later |
| Structure | Multi-crate Cargo workspace |
| OCSF version | Pin 1.8.0; expose `OCSF_VERSION` constant |

## Non-Goals

- Export to CycloneDX/SPDX/OSV/SARIF (ingest only; revisit with a consumer).
- Event classes outside the curated set (add on demand).
- Custos-specific concepts (tenant IDs, Postgres mapping, storage URIs) —
  those live in the custos repo on top of these crates.
- Code generation from ocsf-schema JSON (the JSON is used as reference and
  test input, not as a codegen source).

## Workspace Layout

```
crates/
  ocsf-core        # types, serde, validation, schemars; deps: serde,
                   # serde_json, thiserror, schemars (+optional chrono)
  ocsf-cyclonedx   # wraps cyclonedx-bom
  ocsf-spdx        # wraps serde-spdx
  ocsf-osv         # wraps osv
  ocsf-sarif       # wraps serde-sarif
  ocsf-vex         # OpenVEX via openvex; CycloneDX-VEX via ocsf-cyclonedx
xtask/             # cargo xtask schemas; fixture tooling
schemas/           # generated JSON Schema artifacts, committed, CI drift check
docs/              # this spec, mapping documentation
```

If `ocsf-core` outgrows the maintainability bar (files ≤ 800 lines, crate
reasonably navigable), split category crates (`ocsf-findings`,
`ocsf-discovery`); the workspace makes that cheap. Not done preemptively.

## Curated Coverage (verified against ocsf-schema @ 1.8.0)

Event classes — Findings (category_uid 2):

- Vulnerability Finding
- Application Security Posture Finding
- Compliance Finding
- Detection Finding
- Shared base-finding scaffolding (`finding_info`, common attributes)

Event classes — Discovery (category_uid 5):

- Software Inventory Info (carries the `sbom` object)
- Device Inventory Info
- Cloud Resources Inventory Info
- User Inventory

Deferred: Incident Finding, Data Security Finding, IAM Analysis Finding.
Excluded: Security Finding (deprecated upstream).

Objects: the transitive closure referenced by the classes above — expected
~40 of 177 (vulnerability, cve, cvss, cwe, epss, affected_package,
affected_code, package, sbom, remediation, kb_article, compliance, check,
finding_info, resource_details, device, os, product, metadata, observable,
enrichment, cloud, container, image, file, user, group, account, url, ...).
The exact closure is computed from the 1.8.0 schema JSON during
implementation; class_uid/attribute names are taken from the schema files,
never from memory.

Module layout mirrors OCSF: `ocsf_core::findings`, `ocsf_core::discovery`,
`ocsf_core::objects`, `ocsf_core::base` (metadata, observables, shared
enums).

## Modeling Conventions

- **Enum sibling pattern.** OCSF pairs `*_id: i32` (normative) with an
  optional string sibling (source label). Model IDs as Rust enums with known
  variants plus `Other(i32)`, custom serde to/from integers, so unknown
  future IDs deserialize without error. String siblings preserved as
  `Option<String>`.
- **UIDs.** `trait OcsfClass { const CLASS_UID: u32; const CATEGORY_UID: u32; }`
  per event class; `type_uid` computed (`class_uid * 100 + activity_id`);
  `metadata.version` auto-populated from `OCSF_VERSION`.
- **Timestamps.** i64 epoch-milliseconds natively (OCSF wire form). `chrono`
  conversions behind a `chrono` feature flag; core stays dependency-light.
- **Unknown-field preservation.** Every struct carries
  `#[serde(flatten)] other: serde_json::Map<String, Value>` — lenient
  ingest, lossless round-trip. Generated JSON Schemas set
  `additionalProperties: true` accordingly.
- **Construction and validation.** Constructors take OCSF-required fields;
  optional fields via immutable `with_*` builders returning `Self`.
  `validate()` per event class checks required/recommended constraints and
  returns all violations as structured `ValidationError`s (boundary
  validation, fail fast, never silent).
- Rust 2024 edition. No `unsafe`. No panics/`unwrap` in library code paths
  (tests exempt).

## Adapter Design (ingest)

Adapters are thin: parsing is delegated to the mature ecosystem crate;
adapter code is pure mapping into `ocsf-core` types.

Every adapter returns `(output, MappingReport)`. `MappingReport` records
warnings and dropped/unmappable source fields so lossy mappings are visible
and auditable, never silent.

| Adapter | Source crate | Maps to |
| --- | --- | --- |
| ocsf-cyclonedx | cyclonedx-bom | Software Inventory Info (sbom, package objects) |
| ocsf-spdx | serde-spdx | Software Inventory Info (sbom, package objects) |
| ocsf-osv | osv | Advisory records → vulnerability/cve/affected_package objects; OSV-Scanner results → Vulnerability Finding events |
| ocsf-sarif | serde-sarif | Vulnerability Finding with affected_code (default); configurable to Detection Finding for non-vulnerability rules |
| ocsf-vex | openvex (+ ocsf-cyclonedx for CDX-VEX) | `VexAssessment` → Vulnerability Finding status transitions (e.g. not_affected → suppressed); mapping table documented in-crate |

No shared adapter trait upfront; conventions first, extract a trait when the
third adapter proves the shape.

Adapter-populated provenance: `metadata.product` (source tool),
`metadata.original_time` where available, raw source identifiers into
`unmapped`/`other` when they have no OCSF home.

## Contract Artifacts

`cargo xtask schemas` generates JSON Schema files from schemars into
`schemas/`, one per event class plus shared definitions. Artifacts are
committed; CI regenerates and fails on drift (`git diff --exit-code`).
Non-Rust services (Go collectors, TypeScript frontend) validate against
these files.

## Error Handling

- `ocsf_core::ValidationError` — structured constraint violations.
- Per-adapter `MapError` (`thiserror`) wrapping upstream parse errors with
  context; no silent degradation.
- Library code returns `Result`; panics are bugs.

## Testing Strategy

TDD (test first, then implement). Coverage ≥ 80% via cargo-llvm-cov.

- **Unit**: serde round-trips per type (unknown IDs, unknown fields, enum
  siblings); validation rules; uid/type_uid computation.
- **Fixture-based integration**: real tool outputs committed under
  `crates/*/tests/fixtures/` — syft/trivy SBOMs (CycloneDX + SPDX),
  grype/osv-scanner results, semgrep SARIF, OpenVEX documents — plus OCSF's
  own example corpus. Assert mapped output and MappingReport contents.
- **Contract**: every emitted event validates against the generated JSON
  Schemas (jsonschema dev-dependency).

## Versioning & Publishing

- Workspace crates at 0.1.x, versioned together initially.
- Each release pins one OCSF version; `OCSF_VERSION` exposed at crate root.
- Internal consumption via git dependency; crates.io publication deferred
  until API stabilizes (names verified available 2026-07-17).
- Conventional commits; repo may be renamed/open-sourced later without code
  changes (crate names are already neutral).

## Risks

- **OCSF version churn**: 1.9 in development upstream. Mitigation: pinned
  version constant, additive-first curation, unknown-field/ID tolerance
  already built into the model.
- **Upstream adapter crates** vary in quality/maintenance (openvex last
  released 2023). Mitigation: adapters are thin, parser crates are swappable
  per-crate without touching the contract; openvex format is small enough to
  vendor types if the crate proves inadequate.
- **SARIF semantic breadth** (SAST vs IaC vs secrets tools): mitigated by
  configurable target class and MappingReport visibility.
