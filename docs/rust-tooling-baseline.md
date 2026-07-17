# Rust Tooling Baseline (1.0)

Status: Draft
Last updated: 2026-07-17

## Purpose And Scope

This document finalizes the Rust dependencies Custos builds on for the 1.0
product. It implements the reuse-first decision of
ADR 0005 (custos repo: docs/adrs/0005-adopt-existing-rust-tooling.md) and the
Rust-default language strategy of ADR 0003 (custos repo:
docs/adrs/0003-language-strategy.md), and supersedes the recommendations of
the Rust Tooling Scan, 2026-07-07 (custos repo:
docs/research/rust-tooling-scan-2026-07-07.md) where they differ.

Every adoption below was re-verified live on 2026-07-17 against crates.io,
the upstream repository, and advisory databases (RustSec/OSV): latest
version, license, maintenance state, archived status. Versions are the pins
at finalization; "pin exact" means the workspace pins `=x.y.z` and upgrades
are reviewed changes.

Non-scope: the workflow engine (rusty-flow) is an in-build commitment
recorded in the scan; the secrets manager, deployment stack, and
model-provider tooling are decided by their own ADRs. The policy engine and
the job-processing model have reserved backlog ADRs (per ADR 0005): the
regorus and first-party-job-table selections below are the live-validated
candidates this baseline puts forward for those ADRs to ratify or overturn —
recorded here so implementation is not blocked, not decided over the ADRs'
heads.

## Decision Summary

| Layer | Adopted | Notable rejections |
| --- | --- | --- |
| Service foundations | tokio, serde, serde_json, thiserror 2, anyhow, config 0.15, clap 4, validator 0.20, uuid (v7), chrono, secrecy, zeroize, serde-saphyr (YAML) | figment, eyre, jiff (defer), serde_yml family (ban) |
| HTTP API + OpenAPI | axum 0.8, utoipa 5, utoipa-axum 0.2, tower-http 0.7 | actix-web (defer), aide, poem, dropshot |
| Observability | tracing, tracing-subscriber, tracing-opentelemetry 0.33, opentelemetry 0.32 (+sdk, otlp, semconv) | metrics/prometheus (defer), opentelemetry-jaeger (unmaintained) |
| Authentication | openidconnect 4, jsonwebtoken 10, samael =0.0.22, argon2 0.5.3, subtle | josekit (defer), openid, RustCrypto jose |
| Authorization | regorus 0.10 (sole engine) | cedar (named fallback), biscuit |
| Persistence | sqlx 0.9 (Postgres, rustls, migrate), built-in PgPool + migrations | sea-orm (defer until 2.0 stable), refinery, deadpool-postgres |
| Object storage | object_store 0.14 behind an owned ArtifactStore trait | opendal (defer), raw aws-sdk-s3 |
| Job queue | first-party job table on sqlx (FOR UPDATE SKIP LOCKED) + cron 0.17 | apalis, fang; underway (defer) |
| Schema/format ingest | serde-cyclonedx, serde-sarif, serde-spdx, packageurl, osv, spdx | cyclonedx-bom (defer: no 1.6), spdx-rs (dormant) |
| Enrichment/attestation | cvss 2.2, csaf-walker 0.17 (license-gated, see Open Decisions), sigstore 0.14 (verify-only) | in-toto-rs (defer), scm-rs cvss-rs |
| Connector plumbing | tower 0.5, tower-http 0.7, reqwest 0.13 (rustls), governor 0.10, octocrab 0.54 (isolated) | native-tls (ban), tower_governor (defer), vaultrs (contingent on secrets ADR) |
| Dedup/graph primitives | blake3 1.8, petgraph 0.8, strsim 0.11 | rapidfuzz-rs, textdistance |
| Graph strategy | PostgreSQL relation tables + recursive CTEs; petgraph on bounded subgraphs | oxigraph (defer), cozo, indradb |
| Lifecycle state | hand-rolled enums + transition functions | statig (defer), sm, machine |
| Testing/quality | cargo-nextest, cargo-llvm-cov, testcontainers 0.27, insta, proptest, wiremock 0.6 (fallback: httpmock), cargo-fuzz, criterion, cargo-audit, cargo-deny | quickcheck, cargo-tarpaulin, afl (defer) |

## Service Foundations

- tokio 1.x, serde 1.x, serde_json 1.x, thiserror 2.x (libraries), anyhow 1.x
  (binaries): the proven core, matching Trustify's production workspace.
- Configuration: config 0.15 (layered defaults, file, then environment) plus
  clap 4 with the env feature for entrypoints. figment rejected (dormant
  since 2024).
- Validation at boundaries: validator 0.20; garde is the named escape hatch
  if validator's release stall (none since 2025-01) persists.
- IDs: uuid 1.x with v7 (time-sortable) and serde features.
- Time: chrono 0.4 with default-features off — sqlx maps it natively. jiff
  deferred until 1.0 plus native sqlx support.
- Secret hygiene: secrecy 0.10 + zeroize 1.x for in-memory secrets.
- YAML (untrusted input): serde-saphyr, pin exact =0.0.29 — the only
  maintained pure-Rust serde-YAML path. Isolate behind one adapter module,
  mandatory fuzz target, re-verify monthly. The entire serde_yaml lineage is
  banned (see Banned Crates); serde_yaml_ng is the documented fallback if
  serde-saphyr fails us, accepting its archived unsafe-libyaml dependency —
  exercising that fallback requires a scoped deny.toml exception for
  unsafe-libyaml, made deliberately rather than by dependency drift.

## HTTP API And OpenAPI

- axum 0.8 (pin the 0.8 line): the only healthy tower-native framework —
  tower compatibility is a hard requirement so API and connectors share one
  middleware substrate.
- utoipa 5 + utoipa-axum 0.2: compile-time OpenAPI generation; CI serializes
  `ApiDoc::openapi()` to JSON and diffs it, satisfying the generated-in-CI
  rule. Same generator Trustify runs (with actix bindings there).
- tower-http 0.7: request-id set/propagate, trace, timeout, limit, cors,
  sensitive-headers layers.
- Do not take axum 0.9 until utoipa-axum ships a compatible release.
- actix-web is the named fallback if the tower requirement is ever dropped.

## Observability

- tracing + tracing-subscriber (env-filter, json; floor >=0.3.20 for
  RUSTSEC-2025-0055) for structured JSON logs to stdout.
- tracing-opentelemetry 0.33 bridging into opentelemetry 0.32 +
  opentelemetry_sdk + opentelemetry-otlp (grpc-tonic; traces and metrics
  over one OTLP pipeline) + opentelemetry-semantic-conventions.
- Request IDs are span fields set by middleware; every log line inherits
  them in JSON output.
- No crate prevents secret leakage into logs: budget a custom tracing layer
  that denylists sensitive field names, with tests.
- OTLP log export (opentelemetry-appender-tracing) deferred; 1.0 ships
  stdout JSON logs for collector-side scraping.
- Upgrade the opentelemetry crate family in lockstep; the
  tracing-opentelemetry bridge release lags otel releases.

## Authentication

- OIDC: openidconnect 4.x (pin 4.0.1) — typed, fail-closed ID-token
  validation (issuer, audience, nonce, JWKS). oauth2 5.x rides transitively.
- Custos-issued API tokens and standalone JWKS validation: jsonwebtoken 10.x
  (pin 10.4.0; v11 is imminent and removes deprecated APIs — planned
  migration, not an auto-bump).
- Secret hashing: argon2 0.5.3 (stable line, not the 0.6 RC). Constant-time
  comparison: subtle 2.6 (BSD-3-Clause — allowlist entry required).
- SAML 2.0: samael, pin exact =0.0.22. This is the single highest-risk
  dependency in the 1.0 tree: pre-0.1, effectively one maintainer, and its
  xmlsec feature verifies XML signatures through C libraries (libxml2,
  xmlsec1, OpenSSL) — the classic SAML attack surface in non-memory-safe
  code. Mitigations are mandatory: wrap entirely behind the ADR 0002
  SamlValidator trait, isolate the C dependencies to one leaf crate, fuzz
  the pre-verification XML surface, re-verify maintenance monthly. Named
  contingency if samael stalls: drop native SAML and bridge SAML-to-OIDC
  through an IdP proxy (e.g. Keycloak/Dex pattern), which ADR 0002's
  adapter design permits without API changes. The pure-Rust saml crate
  (v0.0.1-alpha) is on the post-1.0 watchlist as the long-term replacement.

## Authorization

- regorus 0.10 (pin minor) is the sole 1.0 policy engine, behind a
  PolicyEngine trait in route-guard middleware. Rego undefined, evaluation
  error, or non-true result maps to DENY — fail-closed is an integration
  obligation with explicit tests, not an engine property.
- Tenant/data-scope enforcement stays in Rust/SQL (mandatory tenant_id
  predicates in repositories); the engine decides, repositories enforce. Do
  not generate SQL from Rego.
- Rego policies are code: unit tests and coverage in CI (regorus supports
  coverage reporting).
- cedar-policy (4.x line) is the named fallback engine; biscuit rejected
  (capability-token paradigm does not fit centralized server-side authz).

## Persistence

- sqlx 0.9 (features: runtime-tokio, tls-rustls, postgres, uuid, chrono,
  json, migrate) — compile-time checked queries with per-query offline
  prepare files verified in CI.
- Pooling: sqlx built-in PgPool. Migrations: sqlx built-in migrate with
  reversible migrations (`migrate add -r`) and a CI job running
  up -> revert-all -> up against a clean PostgreSQL.
- sqlx-cli pinned explicitly in CI (`--version 0.9.x`); sqlx 0.9 removed its
  lockfile so an unpinned `cargo install --locked` is a supply-chain gap.
- No entity layer at 1.0: raw sqlx keeps tenant-scope predicates visible in
  hand-written SQL, enforced by the repository layer (plus PostgreSQL RLS as
  defense in depth). sea-orm deferred: its stable line pins sqlx 0.8 and the
  sqlx-0.9-compatible 2.0 is still a release candidate — re-evaluate when
  2.0 is stable.

## Object Storage

- object_store 0.14 (pin exact) behind a Custos-owned ArtifactStore trait in
  one adapter crate. `PutMode::Create` gives atomic if-not-exists writes —
  the exact primitive for immutable content-addressed keys (put-by-digest is
  idempotent; overwrites structurally impossible). Streaming get and
  put_multipart bound memory on large artifacts.
- Backends at 1.0: S3-compatible (endpoint-configured) and LocalFileSystem
  for dev; InMemory for tests.
- Integration-test conditional-put against every supported S3-compatible
  target (older MinIO/Ceph builds lack If-None-Match) and fail closed where
  unsupported.
- opendal deferred (breadth of backends unneeded; higher API churn);
  raw aws-sdk-s3 rejected as the abstraction (no local backend, no
  abstraction).

## Job Queue And Orchestration

- First-party job table on sqlx using FOR UPDATE SKIP LOCKED: claim is a
  single UPDATE ... RETURNING with lease_owner/lease_expires_at, heartbeat
  extends the lease, dead-letter is a state transition after max attempts.
  cron 0.17 parses schedule expressions; dispatch is first-party (include
  DST/timezone edge cases in scheduler tests).
- Rationale: rusty-flow's sync core drives the queue through a Backend
  compare-and-set trait; every framework candidate (apalis, fang, underway)
  owns the worker loop and scheduling — control flows the wrong direction.
  The plan already specifies job-table semantics (leases, retries,
  dead-letter, heartbeat).
- Owning queue correctness is the accepted cost: port state-machine and
  schema decisions from River/Oban (publicly documented), property-test the
  claim/heartbeat/expiry invariants, and document the partitioned-table /
  LISTEN-NOTIFY evolution path for scale.
- underway remains the named substrate to re-evaluate post-1.0 if
  first-party maintenance proves expensive.

## Schema And Format Ingest

- CycloneDX: serde-cyclonedx =0.10.0 — the official cyclonedx-bom crate
  cannot parse spec 1.6 (open since 2024) while mainstream scanners emit
  1.6+ by default; serde-cyclonedx is what Trustify runs, normalizing to
  v1.6. Ingest must detect declared specVersion and fail closed on >1.6
  (cdxgen already defaults to 1.7 — track upstream for a 1.7 schema).
- SARIF: serde-sarif =0.8.0 (SARIF 2.1.0 is a frozen OASIS spec; low churn
  expected).
- SPDX documents: serde-spdx =0.10.0, SPDX 2.3 JSON only — what GitHub SBOM
  export and CI tooling emit. Tag-value, RDF, and SPDX 3.0 are documented
  unsupported inputs at 1.0 and fail closed. spdx-rs rejected: dormant
  upstream (Trustify has to pin a personal git fork to keep it working).
- purl: packageurl 0.6 (now maintained under the scm-rs supply-chain org —
  bus factor improved since the scan).
- OSV: osv 0.3 with default-features = false (schema types only; no bundled
  HTTP client in the ingest path).
- License expressions: spdx 0.13 (EmbarkStudios — the parser inside
  cargo-deny).
- Serde-generated types give structural validation only; the ingest layer
  adds semantic validation before persisting (boundary rule).
- All ingest parsers get cargo-fuzz targets (untrusted input).

## Enrichment And Attestation

- CVSS scoring: cvss 2.2 from the RustSec monorepo (v3 and v4).
- CSAF/VEX: csaf-walker 0.17 + walker-common 0.17 as a version-locked pair —
  the only maintained Rust CSAF stack, proven at this version in Trustify.
  BLOCKED on the LGPL decision below before entering the lockfile. The csaf
  model crate rides in transitively (its crates.io release is stale; the
  maintained scm-rs fork is unpublished — a git [patch] mirroring Trustify
  is the contingency for model fixes).
- Attestation: sigstore 0.14 scoped to verification only (cosign
  signature/bundle/DSSE verification, fail-closed). Signing and keyless
  issuance are out of 1.0 scope. in-toto-rs deferred (cooling; Statement
  parsing needed at 1.0 is written in-house, fuzzed, covered).

## Connector Plumbing

- tower 0.5 + tower-http 0.7 shared across API and connectors; reqwest 0.13
  with the rustls default (aws-lc-rs provider — CI images need cmake);
  governor 0.10 for outbound rate limiting; octocrab 0.54 confined to the
  GitHub connector crate behind the connector trait (pre-1.0, breaking
  minors roughly monthly — bumps must not ripple).
- native-tls is banned via cargo-deny: memory-safe TLS only.
- vaultrs stays contingent on the secrets-management ADR and out of the 1.0
  lockfile until that ADR lands.

## Dedup, Correlation, And Graph

- blake3 1.8 for content fingerprints and dedup keys (keyed mode for tenant
  scoping; never for credential hashing — that is argon2's job).
- strsim 0.11 for fuzzy correlation (Levenshtein family, Jaro-Winkler,
  Sorensen-Dice) — replaces the scan's rapidfuzz-rs, which is dormant. Cap
  input lengths before comparison (O(n*m) DoS surface) and fuzz with
  adversarial strings.
- petgraph 0.8 (features: serde-1) for in-memory graph algorithms on
  bounded, tenant-scoped subgraphs. The 0.8 line is fixes-only and 0.9 is a
  core-trait rework: automated bumps must not cross 0.8 -> 0.9.
- Graph persistence is plain PostgreSQL relation tables (dependency_edges,
  asset_relationships) with recursive CTEs (depth limits, cycle guards,
  composite (tenant_id, src/dst) indexes) — one store, one tenancy
  enforcement model. Embedded graph DBs rejected or deferred (cozo stale,
  indradb thin, oxigraph wrong model). Enforce hard caps on loaded subgraph
  size.

## Lifecycle State

- Hand-rolled enums with one pure transition function per lifecycle
  (finding, remediation action, agent-run review), Display/FromStr mapping
  to TEXT status columns, exhaustive transition-matrix tests including
  rejected transitions. CHECK constraints or lookup tables in migrations so
  invalid states cannot be written out-of-band; DB reads parse fail-closed.
- The Rust state-machine crate niche is weak (sm/machine dead, statig
  embedded-oriented and cooling): own this small code permanently.

## Testing And Quality

- cargo-nextest as runner plus a separate `cargo test --doc` CI step
  (nextest does not run doctests).
- cargo-llvm-cov with `cargo llvm-cov nextest --fail-under-lines 80` as the
  coverage gate (unit and integration in one measurement).
- testcontainers 0.27 + testcontainers-modules 0.15 (postgres feature) for
  real-PostgreSQL integration tests; minio/localstack modules cover object
  storage later. Pin the pair together.
- insta + cargo-insta for snapshot tests now and agent-workflow golden tests
  later; proptest 1.11 for property tests (queue claim/lease invariants,
  parser round-trips).
- wiremock 0.6.5 for collector HTTP fixtures — cooling (no release since
  2025-08); httpmock is pre-verified as the drop-in fallback, and a filed
  advisory is the migration trigger.
- cargo-fuzz + libfuzzer-sys for every untrusted-artifact parser (NCSA
  license allowlist entry scoped to the fuzz workspace; not shipped).
- criterion 0.8 for benchmarks (optional, non-gating).
- cargo-audit 0.22 + cargo-deny 0.20 as the CI supply-chain gates.

## Banned Crates (cargo-deny)

- native-tls: banned graph-wide; rustls only.
- openssl / openssl-sys: banned with exactly one scoped deny.toml wrapper
  exception for the isolated SAML leaf crate (samael's xmlsec feature links
  them); no other crate may pull them in, and dropping samael removes the
  exception.
- serde_yaml (deprecated), serde_yml, noyalib, libyml, unsafe-libyaml:
  deprecated/archived lineage and provenance concerns for parsers fed
  untrusted input.
- opentelemetry-jaeger: unmaintained; all trace export via OTLP.
- rapidfuzz, spdx-rs, spdx-expression, cozo, sm, machine: dormant — listed
  to prevent transitive or casual reintroduction.

## License Gate Configuration

- Allowlist: MIT, Apache-2.0, BSD-3-Clause (subtle, regorus component),
  ISC (aws-lc-rs), Unicode-3.0 (ICU transitive deps as needed), CC0-1.0 and
  NCSA only where scoped below.
- OR-expressions must be evaluated correctly: blake3 is
  CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception (accept via the
  Apache-2.0 arm); a naive allowlist that rejects on seeing CC0
  false-positives.
- NCSA: scoped exception for libfuzzer-sys in the fuzz workspace only.
- regorus ships MIT AND Apache-2.0 AND BSD-3-Clause with NOASSERTION in
  GitHub's detection — needs an explicit clarify entry in deny.toml.
- MPL and weak copyleft: review required (none in the 1.0 set).

## Open Decisions

1. csaf-walker LGPL gate (blocking for CSAF/VEX ingest): csaf-walker and
   walker-common unconditionally embed sequoia-openpgp (LGPL-2.0-or-later),
   which fails the permissive-only policy under static linking. Options:
   (a) legal-reviewed cargo-deny exception accepting the LGPL obligations;
   (b) upstream or fork a feature gate that makes PGP verification optional;
   (c) defer CSAF/VEX ingest past 1.0 and drop both crates from the 1.0
   lockfile. Until decided, csaf-walker does not enter the lockfile.
2. vaultrs enters only if the secrets-management ADR selects HashiCorp
   Vault.

## Dependency Watchlist

Monthly: samael (highest-risk), serde-saphyr.
Quarterly: governor, openidconnect, wiremock (migrate on advisory),
validator (migrate to garde if no release within two quarters), secrecy,
utoipa (single maintainer), sqlx (post-governance-move cadence), csaf-walker
(bus factor), packageurl/osv (small orgs), object_store (pin discipline),
sea-orm 2.0 stable (re-evaluate entity layer), jsonwebtoken v11 and argon2
0.6 (planned migrations), jiff and the pure-Rust saml crate (future
replacements), CycloneDX 1.7 schema support upstream.

## CI Obligations Derived From This Baseline

- cargo fmt, clippy, nextest, `cargo test --doc`, llvm-cov gate at 80
  lines-percent.
- cargo-audit and cargo-deny with the license configuration above and the
  ban list enforced.
- OpenAPI JSON generated from code and diffed; sqlx offline prepare files
  checked; migrations run up -> revert-all -> up on clean PostgreSQL.
- Fuzz targets built (smoke run) for every untrusted-input parser:
  CycloneDX, SPDX, SARIF, OSV, YAML adapter, SAML pre-verification XML,
  attestation statements.
- Toolchain and cargo-installed CI tools version-pinned in CI images
  (sqlx-cli, nextest, llvm-cov, audit, deny).
