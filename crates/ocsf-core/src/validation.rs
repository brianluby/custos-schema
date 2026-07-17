//! Aggregated validation reporting shared by every OCSF event class.
//!
//! [`ValidationReport`] collects every applicable error and warning for one
//! instance rather than failing fast on the first problem, so callers see
//! the full picture in a single pass. [`Validate::validate`] is the entry
//! point each generated class implements.

use thiserror::Error;

use crate::base::OcsfClass;
use crate::objects::Metadata;

/// A single validation finding: the attribute it concerns and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// The attribute(s) the issue concerns. For field-level issues, a single OCSF
    /// attribute name (possibly a nested path like `"vulnerabilities[0].cve"`).
    /// For multi-attribute constraint issues (at_least_one, just_one), a
    /// comma-joined list of candidate attribute names (e.g. `"cve, title"`).
    pub attribute: String,
    /// A human-readable description of the issue.
    pub message: String,
}

/// Aggregated validation errors and warnings for one OCSF event instance.
///
/// Errors are normative violations (missing required attributes, broken
/// constraints); warnings flag recommended-but-absent attributes. Warnings
/// never affect [`ValidationReport::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    /// Normative violations. A non-empty list means the instance is invalid.
    pub errors: Vec<ValidationIssue>,
    /// Non-fatal findings (e.g. recommended attributes left unset).
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationReport {
    /// Construct an empty report (no errors, no warnings).
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the report is free of errors. Warnings don't affect this.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Record an error against `attribute`.
    pub fn error(&mut self, attribute: &str, message: impl Into<String>) {
        self.errors.push(ValidationIssue {
            attribute: attribute.to_string(),
            message: message.into(),
        });
    }

    /// Record a warning against `attribute`.
    pub fn warn(&mut self, attribute: &str, message: impl Into<String>) {
        self.warnings.push(ValidationIssue {
            attribute: attribute.to_string(),
            message: message.into(),
        });
    }

    /// Constraint helper: record an error if none of `present` are set.
    ///
    /// `present` pairs each candidate attribute name with whether it's set
    /// on the instance being validated. No error is recorded once at least
    /// one is set.
    pub fn at_least_one(&mut self, present: &[(&str, bool)]) {
        if present.iter().any(|(_, set)| *set) {
            return;
        }
        let names = joined_names(present);
        self.error(&names, format!("at least one of [{names}] must be present"));
    }

    /// Constraint helper: record an error unless exactly one of `present` is set.
    pub fn just_one(&mut self, present: &[(&str, bool)]) {
        if present.iter().filter(|(_, set)| *set).count() == 1 {
            return;
        }
        let names = joined_names(present);
        self.error(&names, format!("exactly one of [{names}] must be present"));
    }

    /// Consume the report: `Ok(warnings)` when valid, `Err(ValidationError)`
    /// carrying both errors and warnings otherwise.
    pub fn into_result(self) -> Result<Vec<ValidationIssue>, ValidationError> {
        if self.is_valid() {
            Ok(self.warnings)
        } else {
            Err(ValidationError {
                errors: self.errors,
                warnings: self.warnings,
            })
        }
    }
}

/// Join candidate attribute names for `at_least_one`/`just_one` messages,
/// e.g. `[cve, title]` for `&[("cve", _), ("title", _)]`.
fn joined_names(present: &[(&str, bool)]) -> String {
    present
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The error returned by [`ValidationReport::into_result`] when the report
/// contains at least one error.
#[derive(Error, Debug)]
#[error("OCSF validation failed: {0} error(s)", .errors.len())]
pub struct ValidationError {
    /// Normative violations that made the instance invalid.
    pub errors: Vec<ValidationIssue>,
    /// Non-fatal findings recorded alongside the errors.
    pub warnings: Vec<ValidationIssue>,
}

/// Common contract for validating an OCSF event instance against its
/// normative constraints (required attributes, at-least-one/just-one
/// groups, enum-derived recommendations, etc.).
pub trait Validate {
    /// Run every applicable check and return the aggregated report.
    fn validate(&self) -> ValidationReport;
}

// ---------------------------------------------------------------------------
// Shared validation helpers. Kept `pub(crate)`; each class's `Validate` impl
// composes the checks it needs. Neutral home (not `findings` or `discovery`)
// so both modules can depend on them without creating a cross-module
// dependency between the two.
// ---------------------------------------------------------------------------

/// Record UID-consistency errors: `class_uid`/`category_uid` must equal the
/// class constants, and `type_uid` must equal the normative
/// `class_uid * 100 + activity_id`. `ev`'s trait method
/// [`OcsfClass::type_uid`] recomputes the expected value from `activity_id`
/// (disambiguated from the `type_uid` field by call syntax).
///
/// Also records an error when the instance's `activity_id` falls outside the
/// OCSF two-digit activity window `0..=99`. Such a value cannot produce a
/// valid `type_uid` (see [`OcsfClass::type_uid`], which clamps it to activity
/// `0` precisely so it can neither mint a valid uid nor collide with a
/// neighbouring class's), so it is surfaced here rather than passing silently.
/// Constructors derive `type_uid` via the same trait method, so construction
/// and validation stay self-consistent for out-of-range activities.
pub(crate) fn check_uids<C: OcsfClass>(
    ev: &C,
    class_uid: i32,
    category_uid: i32,
    type_uid: i32,
    r: &mut ValidationReport,
) {
    if class_uid != C::CLASS_UID as i32 {
        r.error("class_uid", format!("must be {}", C::CLASS_UID));
    }
    if category_uid != C::CATEGORY_UID as i32 {
        r.error("category_uid", format!("must be {}", C::CATEGORY_UID));
    }
    let activity = ev.activity_id_value();
    if !(0..=99).contains(&activity) {
        r.error(
            "activity_id",
            format!("value {activity} outside the OCSF activity range 0..=99"),
        );
    }
    let expected = OcsfClass::type_uid(ev) as i32;
    if type_uid != expected {
        r.error(
            "type_uid",
            format!("must equal class_uid * 100 + activity_id ({expected})"),
        );
    }
}

/// Report every extension key in `other` that shadows a modeled field.
///
/// Each generated struct carries a `#[serde(flatten)] other` catch-all for
/// forward compatibility. Because `flatten` deserializes into `other` *any*
/// key not matched by a modeled field, and serializes `other`'s entries back
/// out verbatim, inserting a key that names a modeled field (e.g.
/// `other["class_uid"] = null`) is invalid: it round-trips to a document with
/// a duplicate JSON key (`to_string`) or silently overwrites the modeled
/// value (`to_value`). The type system can't prevent it, so it is caught here
/// at `validate()` time. `fields` is the struct's modeled wire-name set
/// (its `FIELD_NAMES` const, which the conformance harness pins to the
/// schemars property set). `attribute_prefix` is prepended to the reported
/// `other` attribute name (normally empty — nested paths are applied by
/// [`check_nested`] as the error bubbles up to the parent).
pub(crate) fn check_other_collisions(
    other: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
    attribute_prefix: &str,
    r: &mut ValidationReport,
) {
    for key in other.keys() {
        if fields.contains(&key.as_str()) {
            r.error(
                &format!("{attribute_prefix}other"),
                format!("extension key '{key}' collides with a modeled field"),
            );
        }
    }
}

/// Recurse into a nested typed object and re-surface each of its validation
/// errors on the parent under a nested-path attribute.
///
/// This is the pinned nested-issue convention: a child error on attribute
/// `child_attr` is re-recorded as `{path}.{child_attr}` (e.g. the `product`
/// object's `name` error, recursed under `metadata`, becomes
/// `metadata.product.name`). Callers recursing a `Vec<T>` pass an indexed
/// `path` per element (e.g. `resources[0]`), yielding `resources[0].name`.
/// Only errors propagate; a child's warnings are intentionally not surfaced
/// on the parent (each type owns its own recommended-attribute set).
pub(crate) fn check_nested<V: Validate>(child: &V, path: &str, r: &mut ValidationReport) {
    for issue in child.validate().errors {
        r.error(&format!("{path}.{}", issue.attribute), issue.message);
    }
}

/// Enforce a documented scalar range on an optional integer attribute.
///
/// `None` (absent) is always accepted; a present value outside `min..=max`
/// records an error naming the range. See the [`ranges`] module for the
/// range constants and the important caveat that these ranges live only in
/// oracle *description* prose, not the upstream JSON Schema.
pub(crate) fn check_scalar_range(
    attribute: &str,
    value: Option<i32>,
    min: i32,
    max: i32,
    r: &mut ValidationReport,
) {
    if let Some(v) = value
        && !(min..=max).contains(&v)
    {
        r.error(
            attribute,
            format!("value {v} outside the documented range {min}..={max}"),
        );
    }
}

/// Documented scalar ranges, as `(attribute, min, max)` inclusive bounds.
///
/// **These ranges are stricter than the upstream OCSF JSON Schema.** OCSF
/// 1.8.0 states them only in an attribute's *description* prose; the
/// structural schema (`integer_t`) encodes no `minimum`/`maximum`. Enforcing
/// them in `validate()` therefore rejects some documents the vendored
/// JSON-Schema oracle would accept — a deliberate, documented divergence.
/// Each constant cites the oracle description it transcribes verbatim.
///
/// Kept `pub` (though `#[doc(hidden)]`) so the `xtask` schema generator can
/// later read these bounds to inject `minimum`/`maximum` into the emitted
/// JSON Schema; nothing in that generator is touched here.
#[doc(hidden)]
pub mod ranges {
    /// `timezone_offset`, present on all 8 supported classes. Oracle
    /// description: "The number of minutes that the reported event time is
    /// ahead or behind UTC, in the range -1,080 to +1,080."
    pub const TIMEZONE_OFFSET: (&str, i32, i32) = ("timezone_offset", -1080, 1080);

    /// `impact_score`, present only on `detection_finding`. Oracle
    /// description: "The impact as an integer value of the finding, valid
    /// range 0-100."
    pub const IMPACT_SCORE: (&str, i32, i32) = ("impact_score", 0, 100);
}

/// Enforce the `cloud`-profile conditional requirement: when `"cloud"` is in
/// `metadata.profiles`, the `cloud` attribute must be present. Used by the
/// four Findings classes and three of the four Discovery classes
/// (`software_info`, `inventory_info`, `user_inventory`); across all seven,
/// `cloud` is the only attribute the FULL (all-profiles) compile marks
/// required that the BASE compile does not. `cloud_resources_inventory_info`
/// is exempt: its oracle `cloud` attribute carries no `profiles` tag, so its
/// presence is governed solely by that class's `at_least_one` constraint,
/// not by `metadata.profiles`.
pub(crate) fn check_cloud_profile(
    metadata: &Metadata,
    cloud_present: bool,
    r: &mut ValidationReport,
) {
    let cloud_profile_active = metadata
        .profiles
        .as_ref()
        .is_some_and(|profiles| profiles.iter().any(|p| p == "cloud"));
    if cloud_profile_active && !cloud_present {
        r.error("cloud", "required when the \"cloud\" profile is active");
    }
}

/// Emit a warning for each recommended attribute that is absent. Callers pass
/// the handful of highest-value recommended attributes for their class.
pub(crate) fn warn_recommended(r: &mut ValidationReport, recommended: &[(&str, bool)]) {
    for (name, present) in recommended {
        if !present {
            r.warn(name, "recommended attribute omitted");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_aggregates_and_distinguishes_errors_from_warnings() {
        let mut r = ValidationReport::new();
        r.warn("severity", "recommended attribute omitted");
        assert!(r.is_valid());
        r.error("time", "required attribute missing");
        assert!(!r.is_valid());
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn at_least_one_and_just_one() {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("cve", false), ("title", false)]);
        assert_eq!(r.errors.len(), 1);

        let mut r = ValidationReport::new();
        r.at_least_one(&[("cve", true), ("title", false)]);
        assert!(r.is_valid());

        let mut r = ValidationReport::new();
        r.just_one(&[("a", true), ("b", true)]);
        assert_eq!(r.errors.len(), 1);
    }

    #[test]
    fn into_result_carries_all_issues() {
        let mut r = ValidationReport::new();
        r.error("time", "missing");
        let err = r.into_result().unwrap_err();
        assert_eq!(err.errors.len(), 1);
    }

    #[test]
    fn constraint_issue_attribute_is_joined_candidate_list() {
        let mut r = ValidationReport::new();
        r.at_least_one(&[("cve", false), ("title", false)]);
        assert_eq!(r.errors[0].attribute, "cve, title");
    }

    #[test]
    fn check_other_collisions_flags_modeled_keys_only() {
        let fields = &["class_uid", "time"];
        let mut other = serde_json::Map::new();
        other.insert("x_future".into(), serde_json::Value::Null);
        let mut r = ValidationReport::new();
        check_other_collisions(&other, fields, "", &mut r);
        assert!(r.is_valid(), "a non-modeled extension key is fine");

        other.insert("class_uid".into(), serde_json::Value::Null);
        let mut r = ValidationReport::new();
        check_other_collisions(&other, fields, "", &mut r);
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.errors[0].attribute, "other");
        assert!(r.errors[0].message.contains("class_uid"));
    }

    #[test]
    fn check_other_collisions_honors_attribute_prefix() {
        let mut other = serde_json::Map::new();
        other.insert("time".into(), serde_json::Value::Null);
        let mut r = ValidationReport::new();
        check_other_collisions(&other, &["time"], "metadata.", &mut r);
        assert_eq!(r.errors[0].attribute, "metadata.other");
    }

    struct NestedFake;
    impl Validate for NestedFake {
        fn validate(&self) -> ValidationReport {
            let mut r = ValidationReport::new();
            r.error("name", "boom");
            r.warn("desc", "recommended"); // must NOT propagate
            r
        }
    }

    #[test]
    fn check_nested_prefixes_child_error_paths_and_drops_warnings() {
        let mut r = ValidationReport::new();
        check_nested(&NestedFake, "metadata.product", &mut r);
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.errors[0].attribute, "metadata.product.name");
        assert_eq!(r.errors[0].message, "boom");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn check_scalar_range_boundaries() {
        let (attr, min, max) = ranges::TIMEZONE_OFFSET;
        // Absent is always fine.
        let mut r = ValidationReport::new();
        check_scalar_range(attr, None, min, max, &mut r);
        assert!(r.is_valid());
        // In-range min and max pass.
        for v in [min, max, 0] {
            let mut r = ValidationReport::new();
            check_scalar_range(attr, Some(v), min, max, &mut r);
            assert!(r.is_valid(), "value {v} should be in range");
        }
        // min-1 and max+1 fail.
        for v in [min - 1, max + 1] {
            let mut r = ValidationReport::new();
            check_scalar_range(attr, Some(v), min, max, &mut r);
            assert!(!r.is_valid(), "value {v} should be out of range");
            assert_eq!(r.errors[0].attribute, "timezone_offset");
        }
    }
}
