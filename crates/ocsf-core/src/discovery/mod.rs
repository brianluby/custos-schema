//! OCSF Discovery (category 5) event classes.
//!
//! The four classes modeled here — [`InventoryInfo`], [`UserInventory`],
//! [`SoftwareInfo`], and [`CloudResourcesInventoryInfo`] — are flat on the
//! wire, exactly like the Findings classes in [`crate::findings`]: every OCSF
//! attribute of a class is a field on that class's struct (no shared base
//! struct, no `serde(flatten)` of a common base). Shared UID-consistency and
//! cloud-profile validation logic is reused from [`crate::validation`] rather
//! than duplicated: `check_uids`/`check_cloud_profile`/`warn_recommended` are
//! `pub(crate)` there and fully generic (no Finding-specific coupling), so
//! this module imports them directly instead of redefining byte-identical
//! helpers.
//!
//! ## Enum vocabularies
//!
//! `activity_id` is per-class (`{Class}ActivityId`), matching the brief and
//! keeping each class's `type_uid` derivation self-contained — even though
//! the vocabulary (`{Log, Collect}`) is identical across the four classes and
//! notably *not* the Findings `{Create, Update, Close}` vocabulary.
//!
//! `action_id`, `confidence_id`, `disposition_id`, and `risk_level_id` are
//! byte-for-byte identical (verified against the oracle) to the vocabularies
//! [`crate::findings::FindingActionId`], [`crate::findings::FindingConfidenceId`],
//! [`crate::findings::FindingDispositionId`], and [`crate::objects::RiskLevelId`]
//! were already defined against, so this module reuses those types rather
//! than redefining them (per Task 9's own forward note). `status_id` is a
//! *different* two-value vocabulary here (`{Success, Failure}`, not
//! Findings' six-value lifecycle), so it gets its own shared
//! [`DiscoveryStatusId`] — never a bare `StatusId` (correction 2 precedent).
//! `severity_id` reuses [`crate::enums::SeverityId`].

use crate::enums::ocsf_enum;

mod cloud_resources_inventory_info;
mod inventory_info;
mod software_info;
mod user_inventory;

pub use cloud_resources_inventory_info::{
    CloudResourcesInventoryInfo, CloudResourcesInventoryInfoActivityId,
};
pub use inventory_info::{InventoryInfo, InventoryInfoActivityId};
pub use software_info::{SoftwareInfo, SoftwareInfoActivityId};
pub use user_inventory::{UserInventory, UserInventoryActivityId};

ocsf_enum! {
    /// Normalized status of the discovery event (`status_id`), shared across
    /// all four Discovery classes. Distinct from
    /// [`crate::findings::FindingStatusId`]'s finding-lifecycle vocabulary.
    pub enum DiscoveryStatusId {
        Success = 1,
        Failure = 2,
    }
}
