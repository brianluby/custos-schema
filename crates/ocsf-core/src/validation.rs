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
    let expected = OcsfClass::type_uid(ev) as i32;
    if type_uid != expected {
        r.error(
            "type_uid",
            format!("must equal class_uid * 100 + activity_id ({expected})"),
        );
    }
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
}
