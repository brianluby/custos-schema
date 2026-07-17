//! OCSF object types reachable from the 8 supported event classes.
//!
//! Every object here carries a `#[serde(flatten)] other` catch-all that
//! losslessly round-trips attributes this codebase does not model yet.
//! Because `flatten` accepts any unmodeled key and re-serializes it verbatim,
//! inserting a key that *names a modeled field* (e.g. `product.other["name"]`)
//! is invalid: it would emit a duplicate JSON key or silently shadow the
//! modeled value.
//!
//! Collision checking is only performed for objects that implement
//! [`crate::validation::Validate`]: the 10 constrained objects
//! (`product`, `user`, `group`, `account`, `organization`, `container`,
//! `kb_article`, `device`, `resource_details`, `vulnerability`), plus
//! `metadata`, plus the 8 event classes. Other typed objects (e.g., `Cloud`,
//! `Cve`, `FindingInfo`) carry an `other` field but do not validate it. See
//! [`crate::validation::check_other_collisions`] for the collision-check
//! implementation. Note that serde never routes modeled keys into `other` on
//! deserialization — the risk of collision exists only from programmatic
//! insertion of values into the `other` map at runtime.

mod actor_types;
mod advisory;
mod cloud;
mod container;
mod cve;
mod device;
mod file;
mod finding_support;
mod metadata;
mod package;
mod product;
mod remediation;
mod software_component;
mod vulnerability;

pub use actor_types::{Account, AccountTypeId, Group, Organization, User, UserTypeId};
pub use advisory::{Advisory, InstallStateId, KbArticle};
pub use cloud::Cloud;
pub use container::{Container, Image};
pub use cve::{Cve, Cvss, Cwe, Epss};
pub use device::{Device, DeviceTypeId, Os, OsTypeId, RiskLevelId};
pub use file::{ConfidentialityId, DriveTypeId, File, FileTypeId};
pub use finding_support::{
    Check, Compliance, ComplianceStatusId, FindingInfo, ResourceDetails, RoleId,
};
pub use metadata::Metadata;
pub use package::{Package, PackageTypeId, Sbom, SbomTypeId};
pub use product::Product;
pub use remediation::Remediation;
pub use software_component::{RelationshipId, SoftwareComponent, SoftwareComponentTypeId};
pub use vulnerability::{AffectedCode, AffectedPackage, FixCoverageId, Vulnerability};
