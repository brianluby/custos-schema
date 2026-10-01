# Status

Paused (Custos ADR 0010, 2026-10-01).

Custos keeps its relational data model as the internal contract and treats
OCSF as an interchange format. The design in `docs/superpowers/specs`, the
plan in `docs/superpowers/plans`, and the parked `ocsf-core` implementation
(PR #1, `feat/ocsf-core`) are the starting point for a future OCSF
export/ingest adapter. No further `ocsf-*` crates are built, and PR #1 is not
merged, until a Custos phase needs that adapter.
