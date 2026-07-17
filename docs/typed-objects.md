# OCSF Object Tier Policy

`ocsf-core` models OCSF 1.8.0 in two tiers. Every object reachable from the
8 supported event classes (the closure recorded in
`conformance/closure-report.json`, 123 objects) has an explicit tier
decision below — there is no "undecided" state.

## The two tiers

- **`typed`** — a hand-modeled Rust struct in `crates/ocsf-core/src/objects/`
  with full field coverage and oracle-verified shape (name/required/
  coarse-type parity — see `crates/ocsf-core/tests/conformance*.rs`). Where
  the OCSF object defines a `constraints` rule (`at_least_one`, `just_one`,
  etc.), it is enforced via `ocsf_core::validation::Validate`. In addition to
  `vulnerability`'s `just_one`, the nine other typed objects that carry an
  oracle `constraints` rule are now enforced too — `product`, `user`, `group`,
  `account`, `organization`, `container`, `kb_article`, `device`, and
  `resource_details` (all `at_least_one`). Event classes recurse into these
  objects during `validate()` (e.g. every class validates its `metadata`,
  which in turn validates its required `product`), so a constrained typed
  object reachable from a supported class is checked in place.
- **`json`** — represented as opaque `serde_json::Value` (or
  `Vec<serde_json::Value>`) wherever it appears on a typed parent. The bytes
  round-trip losslessly through serde, but there is no dedicated struct, no
  field-level validation, and no oracle shape check beyond what the parent's
  schema already constrains.

Both tiers are members of the same closure and both serialize/deserialize
correctly; `json` is not "unsupported," it is "not yet worth a struct."

## Promotion rule

Promotion is **additive only**: moving an object from `json` to `typed`
adds a struct and gains validation without changing the wire shape (the
`json` representation was already schema-conformant), so it is never a
breaking change for a consumer that was matching on JSON shape. Promotion
runs in one direction — an object never moves from `typed` back to `json`.

An object is a promotion candidate once it meets any one of:

1. **ASPM query path** — a downstream consumer needs to filter, sort, or
   join on the object's fields (e.g. "find all findings with a CVSS score
   above N") rather than treating it as opaque payload.
2. **Adapter mapping target** — a Plan 2 ingest adapter (`ocsf-cyclonedx`,
   `ocsf-spdx`, `ocsf-osv`, `ocsf-sarif`, `ocsf-vex`) needs to populate the
   object's fields from a source format, which requires a typed target to
   map into.
3. **Validation constraint** — the OCSF object defines a `constraints` rule
   (`required`, `at_least_one`, `just_one`, recommended-attribute
   conventions, etc.) that only a typed struct can enforce at compile time
   or via `Validate`.

None of these criteria are exclusive; most `typed` rows below satisfy more
than one.

## The required-⇒-typed rule

Every attribute marked `"requirement": "required"` on one of the 8
supported classes' oracle base compile
(`conformance/api/classes/*.base.json`) that carries an `object_type` must
resolve to a `typed` row. This was verified directly against the oracle
compiles rather than inferred from the table: the required object-valued
attributes across all 8 classes are `metadata` (all 8 classes), `cloud`
(all 8 classes), `finding_info` (application_security_posture_finding,
compliance_finding, detection_finding, vulnerability_finding),
`vulnerabilities` (vulnerability_finding, array of `vulnerability`),
`compliance` (compliance_finding), `device` (inventory_info,
software_info), and `user` (user_inventory) — and, one level down,
`metadata.product` (required on `metadata` itself). All of `metadata`,
`cloud`, `finding_info`, `vulnerability`, `compliance`, `device`, `user`,
and `product` are `typed` below. No class-level required object reference
is `json`-tier, so this task is not blocked.

This rule's stated scope is the 8 classes' own required attributes (plus
the one-level-down `metadata.product` case checked above), matching the
task brief. It does not extend transitively through every `typed` object's
*own* required attributes — but the transitive case is also honored: every
object referenced by a *required* attribute of a supported class **or
typed object** must itself be `typed`. Two `typed` objects had a required
`object_type` child that was still `json`-tier — `affected_code.file` →
`file` (required, oracle `file.base.json`), and
`sbom.software_components` → `software_component` (required array, oracle
`sbom.full.json`). Both `file` and `software_component` have been promoted
to `typed` below; neither has a required `object_type` attribute of its
own (`file`'s required set is `{name, type_id}`, `software_component`'s is
`{name, version}` — both scalar), so the promotion does not cascade
further.

## Tier table

| object | tier | rationale |
| --- | --- | --- |
| account | typed | referenced by user/cloud; cloud-account correlation query path |
| actor | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| advisory | typed | referenced by vulnerability; adapter mapping target for vendor/OSV advisories |
| affected_code | typed | referenced by vulnerability; code-location query path for ASPM triage; required `file` child promoted to typed (see above) |
| affected_package | typed | referenced by vulnerability; package-level ASPM query path |
| agent | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| analysis_target | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| analytic | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| anomaly | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| anomaly_analysis | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| api | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| application | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| assessment | json | per-control compliance assessment detail; promotable when adapters need sub-control records |
| attack | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| auth_factor | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| authorization | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| autonomous_system | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| baseline | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| certificate | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| check | typed | referenced by compliance; compliance control-check query path |
| cis_control | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| cloud | typed | required by all 8 supported classes; cloud-context query surface |
| compliance | typed | required by compliance_finding; compliance-status query surface |
| container | typed | referenced by device/cloud_resources_inventory_info; container-asset query path |
| cve | typed | referenced by vulnerability/advisory; adapter mapping target for OSV/NVD ingestion |
| cvss | typed | referenced by cve; scoring query path for ASPM severity triage |
| cwe | typed | referenced by vulnerability/cve/advisory; weakness-classification query path |
| d3f_tactic | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| d3f_technique | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| d3fend | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| database | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| databucket | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| device | typed | required by inventory_info/software_info; core asset-inventory query surface |
| device_hw_info | json | device hardware detail; no ASPM query path; promotable |
| digital_signature | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| display | json | device hardware detail; no ASPM query path; promotable |
| dns_query | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| edge | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| email | json | auxiliary evidence/reporting detail; no ASPM query path; promotable |
| encryption_details | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| enrichment | json | finding enrichment/linkage detail; no validation constraint on the supported classes; promotable |
| environment_variable | json | filesystem/process detail; no ASPM query path; promotable |
| epss | typed | referenced by cve; exploit-probability query path for prioritization |
| evidences | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| extension | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| feature | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| file | typed | required by typed `affected_code` (required-of-typed promotion rule, see above); filesystem/process query path |
| finding_info | typed | required by 4 finding classes; core finding identity/query surface |
| fingerprint | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| firewall_rule | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| gpu_info | json | device hardware detail; no ASPM query path; promotable |
| graph | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| group | typed | referenced by user/device; entitlement query path |
| http_header | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| http_request | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| http_response | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| idp | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| image | typed | referenced by container/device; image-provenance query path |
| ja4_fingerprint | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| job | json | filesystem/process detail; no ASPM query path; promotable |
| kb_article | typed | referenced by advisory/remediation/vulnerability; patch-reference query path |
| key_value_object | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| keyboard_info | json | device hardware detail; no ASPM query path; promotable |
| kill_chain_phase | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| ldap_person | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| location | json | auxiliary evidence/reporting detail; no ASPM query path; promotable |
| logger | json | auxiliary evidence/reporting detail; no ASPM query path; promotable |
| long_string | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| malware | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| malware_scan_info | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| metadata | typed | required by all 8 supported classes; validation-constraint anchor for the event envelope |
| metric | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| mitigation | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| network_connection_info | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| network_endpoint | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| network_interface | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| network_proxy | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| node | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| object | json | finding enrichment/linkage detail; no validation constraint on the supported classes; promotable |
| observable | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| observation | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| organization | typed | referenced by user/device/cloud; org-scoping query path |
| os | typed | referenced by device; OS-level query path for vulnerability applicability |
| package | typed | referenced by sbom/vulnerability; core SBOM/package query surface |
| policy | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| port_info | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| process | json | filesystem/process detail; no ASPM query path; promotable |
| process_entity | json | filesystem/process detail; no ASPM query path; promotable |
| product | typed | required by metadata on every supported class; adapter mapping target for tool/vendor identity |
| programmatic_credential | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| related_event | json | finding enrichment/linkage detail; no validation constraint on the supported classes; promotable |
| remediation | typed | referenced by vulnerability; fix-guidance query path |
| reporter | json | auxiliary evidence/reporting detail; no ASPM query path; promotable |
| reputation | json | detection/anomaly enrichment detail; outside the vulnerability and compliance query surface; promotable |
| request | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| resource_details | typed | referenced by finding classes; affected-resource query path |
| response | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| rule | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| san | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| sbom | typed | referenced by software_info/application; core SBOM ingestion target; required `software_components` child promoted to typed (see above) |
| scim | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| script | json | filesystem/process detail; no ASPM query path; promotable |
| service | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| session | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| software_component | typed | required by typed `sbom` (required-of-typed promotion rule, see above); core SBOM component query surface |
| sso | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| sub_technique | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| table | json | cloud/infra resource-inventory detail; no adapter mapping target yet; promotable |
| tactic | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| technique | json | MITRE ATT&CK/D3FEND detail; no ASPM query path; promotable if adapters need technique-level enrichment |
| timespan | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| tls | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| tls_extension | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| token | json | identity/session detail beyond the core actor types; no adapter mapping target yet; promotable |
| trait | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| transformation_info | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| url | json | networking detail; no ASPM query path; promotable when an adapter needs endpoint-level mapping |
| user | typed | required by user_inventory; identity query surface for ASPM |
| vendor_attributes | json | SBOM/vulnerability adjunct metadata; not required by any supported class; promotable |
| vulnerability | typed | required by vulnerability_finding; core ASPM vulnerability query surface |
| win/reg_key | json | filesystem/process detail; no ASPM query path; promotable |
| win/reg_value | json | filesystem/process detail; no ASPM query path; promotable |
| win/win_service | json | filesystem/process detail; no ASPM query path; promotable |

29 objects are `typed`, 94 are `json`, covering all 123 objects in the
closure.
