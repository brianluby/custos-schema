# OCSF Rust Schema Workspace — Design

Status: Approved (rev 2, post-review)
Date: 2026-07-17
OCSF target version: 1.8.0 (released 2026-03-18, tag commit 6fa6499)

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
| Object depth | Two-tier: typed core objects + JSON-value boundary (see Coverage) |
| Adapters | Ingest-only; OCSF JSON is the output contract |
| Consumers | Rust-first; JSON Schema artifacts generated for Go/TS/other |
| Naming | Neutral `ocsf-*`; internal git dependency first, publish later |
| Structure | Multi-crate Cargo workspace |
| OCSF version | Pin 1.8.0; expose `OCSF_VERSION` constant |
| Conformance | Independent oracle: vendored compiled schema from upstream tag |

## Non-Goals

- Export to CycloneDX/SPDX/OSV/SARIF (ingest only; revisit with a consumer).
- Event classes outside the curated set (add on demand).
- Custos-specific concepts (tenant IDs, Postgres mapping, storage URIs) —
  those live in the custos repo on top of these crates.
- Code generation from ocsf-schema JSON (the JSON is used as reference,
  oracle, and test input, not as a codegen source).

## Workspace Layout

```
crates/
  ocsf-core        # types, serde, validation, schemars; deps: serde,
                   # serde_json, thiserror, schemars (+optional chrono)
  ocsf-cyclonedx   # wraps serde-cyclonedx =0.10.0
  ocsf-spdx        # wraps serde-spdx =0.10.0
  ocsf-osv         # wraps osv 0.3 (default-features = false; schema types
                   # only) + adapter-owned OSV-Scanner envelope types
  ocsf-sarif       # wraps serde-sarif =0.8.0
  ocsf-vex         # OpenVEX via openvex; CycloneDX-VEX via ocsf-cyclonedx
xtask/             # cargo xtask schemas; oracle/fixture sync tooling
schemas/           # generated JSON Schema artifacts, committed, CI drift check
conformance/       # vendored compiled OCSF 1.8.0 schema (oracle), pinned
docs/              # this spec, mapping documentation
```

Parser-crate pins follow the Custos
[Rust Tooling Baseline](../../rust-tooling-baseline.md), which supersedes the
earlier crate survey where they differ — notably CycloneDX uses
serde-cyclonedx, not the official cyclonedx-bom (rejected upstream of us:
cannot parse spec 1.6 while mainstream scanners emit 1.6+; ingest detects
declared specVersion and fails closed on >1.6).

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

### Object policy (two tiers)

The full transitive closure of these classes through inheritance and
dictionary object types reaches ~119 objects (~132 with profile includes) —
too many to hand-model with quality. Objects are therefore split into two
explicit tiers:

- **Typed tier (~45–60 objects).** Everything with ASPM semantic value:
  vulnerability, cve, cvss, cwe, epss, advisory/kb_article, affected_package,
  affected_code, package, sbom, remediation, compliance, check, finding_info,
  resource_details, device, os, product, metadata, observable, enrichment,
  cloud, container, image, file, user, group, account, url, api, logger,
  and their directly-load-bearing neighbors. The definitive list is computed
  from the 1.8.0 closure during implementation and recorded in
  `docs/typed-objects.md`; attribute names/requirements come from the schema
  files, never from memory.
- **JSON tier (everything else).** Fields whose object type falls outside
  the typed tier are modeled as `serde_json::Value` (or
  `Map<String, Value>`), preserving data losslessly without a typed struct.
  Promotion from JSON tier to typed tier is an additive, non-breaking
  change. Criteria for typed-tier membership: referenced by an ASPM query
  path, adapter mapping target, or validation constraint.

### Profile policy

OCSF profiles add attributes to classes. Typed support (as optional typed
fields on the classes where OCSF declares them): `cloud`, `container`,
`host`, `datetime`, `security_control`. Not typed in v0.1 (fields land in
the unknown-field map if present on ingest): `osint`, `network_proxy`,
`trace`, `person`, `data_classification`, `incident`. Profile attribute
sets are taken from the 1.8.0 schema files.

Module layout mirrors OCSF: `ocsf_core::findings`, `ocsf_core::discovery`,
`ocsf_core::objects`, `ocsf_core::base` (metadata, observables, shared
enums), `ocsf_core::profiles`.

## Modeling Conventions

- **Enum sibling pattern.** OCSF pairs `*_id: i32` (normative) with an
  optional string sibling (source label). OCSF normatively defines both
  `0 = Unknown` and `99 = Other`; an out-of-vocabulary integer means
  "unrecognized by this library version" — a distinct third case. Rust
  enums therefore carry: `Unknown` (0), the normative variants, `Other`
  (99), and `Unrecognized(i32)` for anything else. Custom serde to/from
  integers; custom `JsonSchema` impl keeps the wire representation an
  integer. String siblings preserved as `Option<String>`.
- **UIDs.** `trait OcsfClass { const CLASS_UID: u32; const CATEGORY_UID: u32; }`
  per event class; `type_uid` computed (`class_uid * 100 + activity_id`);
  `metadata.version` auto-populated from `OCSF_VERSION`.
- **Timestamps.** i64 epoch-milliseconds natively (OCSF wire form). `chrono`
  conversions behind a `chrono` feature flag; core stays dependency-light.
  `_dt` siblings appear with the `datetime` profile.
- **Unknown-field preservation.** Every struct carries
  `#[serde(flatten)] other: serde_json::Map<String, Value>` — lenient
  ingest, lossless round-trip. Generated JSON Schemas set
  `additionalProperties: true` accordingly.
- **Construction.** Constructors take OCSF-required fields; optional fields
  via immutable `with_*` builders returning `Self`.
- **Validation.** `validate()` per event class aggregates all findings into
  a `ValidationReport { errors, warnings }` (no early exit). Errors:
  missing required attributes, datatype violations, explicit OCSF
  constraints (`at_least_one`, `just_one`), and UID invariants
  (class_uid/category_uid/type_uid consistency). Warnings: omitted
  recommended attributes that carry no explicit constraint. Callers at
  system boundaries decide whether warnings block.
- Rust 2024 edition. No `unsafe`. No panics/`unwrap` in library code paths
  (tests exempt).

## Adapter Design (ingest)

Adapters are thin: parsing is delegated to the mature ecosystem crate;
adapter code is mapping into `ocsf-core` types. Each adapter works in two
layers:

1. **Object mapping (context-free).** Source document → OCSF objects, e.g.
   CycloneDX components → `package`/`sbom` objects, OSV records →
   `vulnerability`/`cve`/`affected_package`. Pure functions, no event
   envelope.
2. **Event construction (context-required).** Source inputs generally lack
   required OCSF event fields (`time`, `severity_id`, `metadata`, and e.g.
   the `device` required by Software Inventory Info). Callers supply an
   `IngestContext` — observing product/`metadata` seed, event `time`
   fallback, the inventoried `device`/asset identity, and routing options.
   `to_events(doc, &IngestContext) -> (Vec<Event>, MappingReport)`.

`MappingReport` records warnings and dropped/unmappable source fields so
lossy mappings are visible and auditable, never silent.

| Adapter | Source crate | Maps to |
| --- | --- | --- |
| ocsf-cyclonedx | serde-cyclonedx | Software Inventory Info (sbom, package objects) |
| ocsf-spdx | serde-spdx | Software Inventory Info (sbom, package objects) |
| ocsf-osv | osv + adapter-owned envelope types | Advisory records → vulnerability/cve/affected_package objects; OSV-Scanner results → Vulnerability Finding events |
| ocsf-sarif | serde-sarif | Rule-based routing: Application Security Posture Finding (default for SAST/code-quality results, per OCSF's stated purpose for that class); Vulnerability Finding when results carry CVE/package identity; configurable overrides |
| ocsf-vex | openvex (+ ocsf-cyclonedx for CDX-VEX) | `VexAssessment` → Vulnerability Finding status transitions (e.g. not_affected → suppressed); mapping table documented in-crate |

OSV note: the `osv` crate models advisory records and API data only.
OSV-Scanner output wraps records under `results → packages →
vulnerabilities/groups`; the adapter owns those envelope types (reusing
`osv::schema::Vulnerability` internally) and targets OSV-Scanner 2.x JSON
output; the supported version is asserted in fixture tests.

No shared adapter trait upfront; conventions first, extract a trait when the
third adapter proves the shape.

Adapter-populated provenance: `metadata.product` (source tool),
`metadata.original_time` where available, raw source identifiers into
`unmapped`/`other` when they have no OCSF home.

## Contract Artifacts

`cargo xtask schemas` generates JSON Schema files from schemars into
`schemas/`, one per event class plus shared definitions. Where schemars
cannot express a constraint (`at_least_one`, `just_one`, UID invariants),
xtask post-processes the generated schema to add it, keeping artifacts
authoritative. Artifacts are committed; CI regenerates and fails on drift
(`git diff --exit-code`). Non-Rust services (Go collectors, TypeScript
frontend) validate against these files.

## Error Handling

- `ocsf_core::ValidationReport` — aggregated errors + warnings (see
  Validation above).
- Per-adapter `MapError` (`thiserror`) wrapping upstream parse errors with
  context; no silent degradation.
- Library code returns `Result`; panics are bugs.

## Testing Strategy

TDD (test first, then implement). Runner and gates per the Custos Rust
Tooling Baseline: cargo-nextest (plus a `cargo test --doc` step),
`cargo llvm-cov nextest --fail-under-lines 80` as the coverage gate.
Adapter crates (Plan 2) add cargo-fuzz targets for every untrusted-input
parser surface, per the baseline's fuzzing obligation.

- **Unit**: serde round-trips per type (Unknown/Other/Unrecognized enum
  cases, unknown fields, enum siblings); validation rules; uid/type_uid
  computation.
- **Independent conformance lane (the oracle).** The self-referential trap —
  Rust types generating the schemas that Rust events are validated against —
  is avoided by vendoring the *upstream* compiled OCSF 1.8.0 schema (from
  tag commit 6fa6499, compiled via the official tooling; synced by
  `cargo xtask sync-oracle`) into `conformance/`. Conformance tests assert,
  per class: (a) Rust-emitted events validate against the oracle's class
  schema; (b) our generated JSON Schema agrees with the oracle on attribute
  names, requirement levels, and enum vocabularies. A field misnamed in
  Rust fails here even though schemars output would be self-consistent.
- **Fixture-based integration**: real tool outputs committed under
  `crates/*/tests/fixtures/` — syft/trivy SBOMs (CycloneDX + SPDX),
  grype/osv-scanner results, semgrep SARIF, OpenVEX documents — plus OCSF's
  own example corpus. Assert mapped output and MappingReport contents.
- **Contract**: every emitted event validates against the generated JSON
  Schemas (jsonschema dev-dependency) *and* the oracle.

## Versioning & Publishing

- Workspace crates at 0.1.x, versioned together initially.
- Each release pins one OCSF version; `OCSF_VERSION` exposed at crate root.
- Internal consumption via git dependency; crates.io publication deferred
  until API stabilizes (names verified available 2026-07-17).
- Conventional commits; repo may be renamed/open-sourced later without code
  changes (crate names are already neutral).

## Risks

- **OCSF version churn**: 1.9 in development upstream. Mitigation: pinned
  version constant, additive-first curation, Unrecognized-ID and
  unknown-field tolerance already built into the model.
- **Typed-tier scope creep**: the two-tier object policy caps hand-modeled
  surface; promotions are additive and criteria-gated.
- **Upstream adapter crates** vary in quality/maintenance (openvex last
  released 2023). Mitigation: adapters are thin, parser crates are swappable
  per-crate without touching the contract; openvex format is small enough to
  vendor types if the crate proves inadequate.
- **SARIF semantic breadth** (SAST vs IaC vs secrets tools): mitigated by
  rule-based class routing, configurable overrides, and MappingReport
  visibility.
