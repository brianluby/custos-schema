//! Base types shared across every OCSF class.

/// OCSF `timestamp_t`: milliseconds since the Unix epoch.
pub type Timestamp = i64;

/// Common contract for a generated OCSF event class.
///
/// Implemented by each class type (Task 5+). `type_uid` defaults to the
/// normative OCSF formula (`class_uid * 100 + activity_id`), clamping a
/// negative or out-of-range `activity_id_value` to `0` rather than panicking.
pub trait OcsfClass {
    /// The class's unique identifier (e.g. `2002` for `vulnerability_finding`).
    const CLASS_UID: u32;
    /// The category the class belongs to (e.g. `2` for Findings).
    const CATEGORY_UID: u32;
    /// The class's normative name (e.g. `"vulnerability_finding"`).
    const CLASS_NAME: &'static str;

    /// The instance's current `activity_id` as a plain integer, used to
    /// derive the default `type_uid`.
    fn activity_id_value(&self) -> i32;

    /// The event's `type_uid`: `CLASS_UID * 100 + activity_id`.
    fn type_uid(&self) -> u32 {
        Self::CLASS_UID * 100 + u32::try_from(self.activity_id_value()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(i32);
    impl OcsfClass for Fake {
        const CLASS_UID: u32 = 2002;
        const CATEGORY_UID: u32 = 2;
        const CLASS_NAME: &'static str = "vulnerability_finding";
        fn activity_id_value(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn type_uid_is_class_uid_times_100_plus_activity() {
        assert_eq!(Fake(1).type_uid(), 200201);
        assert_eq!(Fake(-5).type_uid(), 200200); // negative clamps to 0, no panic
    }
}
