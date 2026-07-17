//! OCSF Findings (category 2) event classes.
//!
//! The four classes modeled here — [`VulnerabilityFinding`],
//! [`ComplianceFinding`], [`DetectionFinding`], and
//! [`ApplicationSecurityPostureFinding`] — are flat on the wire: every OCSF
//! attribute of a class is a field on that class's struct (no shared base
//! struct, no `serde(flatten)` of a common base, either of which would break
//! the conformance harness's required-set check). Shared logic instead lives
//! in the private helper functions at the bottom of this module.
//!
//! ## Enum vocabularies
//!
//! `activity_id` is per-class (`{Class}ActivityId`), matching the brief and
//! keeping each class's `type_uid` derivation self-contained, even though the
//! `{Create, Update, Close}` vocabulary is identical across the four.
//!
//! `status_id`, `action_id`, `confidence_id`, and `disposition_id` are
//! byte-for-byte identical across all four classes (verified against the
//! oracle), so each is a single shared enum defined here. `risk_level_id`
//! reuses [`crate::objects::RiskLevelId`] (identical vocabulary to `device`);
//! `severity_id` reuses [`crate::enums::SeverityId`]. `impact_id` occurs only
//! on `detection_finding` ([`FindingImpactId`]).

use crate::enums::ocsf_enum;
use crate::objects::Vulnerability;
use crate::validation::{Validate, ValidationReport};

mod application_security_posture_finding;
mod compliance_finding;
mod detection_finding;
mod vulnerability_finding;

pub use application_security_posture_finding::{
    ApplicationSecurityPostureFinding, ApplicationSecurityPostureFindingActivityId,
};
pub use compliance_finding::{ComplianceFinding, ComplianceFindingActivityId};
pub use detection_finding::{DetectionFinding, DetectionFindingActivityId};
pub use vulnerability_finding::{VulnerabilityFinding, VulnerabilityFindingActivityId};

ocsf_enum! {
    /// Normalized finding lifecycle status (`status_id`), shared across all
    /// four Findings classes.
    pub enum FindingStatusId {
        New = 1,
        InProgress = 2,
        Suppressed = 3,
        Resolved = 4,
        Archived = 5,
        Deleted = 6,
    }
}

ocsf_enum! {
    /// Normalized action taken by a control leading to an outcome
    /// (`action_id`), shared across all four Findings classes.
    pub enum FindingActionId {
        Allowed = 1,
        Denied = 2,
        Observed = 3,
        Modified = 4,
    }
}

ocsf_enum! {
    /// Normalized confidence in the finding (`confidence_id`), shared across
    /// all four Findings classes.
    pub enum FindingConfidenceId {
        Low = 1,
        Medium = 2,
        High = 3,
    }
}

ocsf_enum! {
    /// Normalized disposition/outcome of a security control (`disposition_id`),
    /// shared across all four Findings classes.
    pub enum FindingDispositionId {
        Allowed = 1,
        Blocked = 2,
        Quarantined = 3,
        Isolated = 4,
        Deleted = 5,
        Dropped = 6,
        CustomAction = 7,
        Approved = 8,
        Restored = 9,
        Exonerated = 10,
        Corrected = 11,
        PartiallyCorrected = 12,
        Uncorrected = 13,
        Delayed = 14,
        Detected = 15,
        NoAction = 16,
        Logged = 17,
        Tagged = 18,
        Alert = 19,
        Count = 20,
        Reset = 21,
        Captcha = 22,
        Challenge = 23,
        AccessRevoked = 24,
        Rejected = 25,
        Unauthorized = 26,
        Error = 27,
    }
}

ocsf_enum! {
    /// Normalized business impact of a detection (`impact_id`), used by
    /// `detection_finding`.
    pub enum FindingImpactId {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
    }
}

// ---------------------------------------------------------------------------
// Finding-specific validation helper. Kept private to the module; each
// class's `Validate` impl composes the checks it needs (see the module doc
// for why the structs themselves are flat rather than sharing a base type).
// The generic `check_uids`/`check_cloud_profile`/`warn_recommended` helpers
// live in `crate::validation` since `crate::discovery` also depends on them.
// ---------------------------------------------------------------------------

/// Recurse into each reported vulnerability, surfacing its constraint errors
/// on the parent under the `vulnerabilities` attribute with a `[i].attr`
/// path prefix (the nested-issue convention pinned in `validation.rs`).
pub(crate) fn check_vulnerabilities(vulns: &[Vulnerability], r: &mut ValidationReport) {
    for (i, v) in vulns.iter().enumerate() {
        for e in v.validate().errors {
            r.error(
                "vulnerabilities",
                format!("[{i}].{}: {}", e.attribute, e.message),
            );
        }
    }
}
