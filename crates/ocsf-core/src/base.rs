//! Base types shared across every OCSF class.

/// OCSF `timestamp_t`: milliseconds since the Unix epoch.
pub type Timestamp = i64;

/// Common contract for a generated OCSF event class.
///
/// Implemented by each class type (Task 5+). `type_uid` defaults to the
/// normative OCSF formula (`class_uid * 100 + activity_id`), clamping any
/// `activity_id_value` outside the two-digit activity window `0..=99` to
/// `0` rather than panicking.
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

    /// Computes the OCSF type identifier from the class and activity identifiers.
    ///
    /// Activity identifiers outside `0..=99` are treated as `0`.
    ///
    /// # Examples
    ///
    /// ```
    /// struct Event;
    ///
    /// impl OcsfClass for Event {
    ///     const CLASS_UID: u32 = 2002;
    ///     const CATEGORY_UID: u32 = 2;
    ///     const CLASS_NAME: &'static str = "example";
    ///
    ///     fn activity_id_value(&self) -> i32 {
    ///         1
    ///     }
    /// }
    ///
    /// assert_eq!(Event.type_uid(), 200201);
    /// ```
    fn type_uid(&self) -> u32 {
        let activity = self.activity_id_value();
        let activity = if (0..=99).contains(&activity) {
            activity as u32
        } else {
            0
        };
        Self::CLASS_UID * 100 + activity
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
        assert_eq!(Fake(99).type_uid(), 200299); // boundary: still in range
        assert_eq!(Fake(-5).type_uid(), 200200); // negative clamps to 0, no panic
    }

    #[test]
    fn out_of_range_activity_clamps_and_cannot_collide() {
        // Activity 100 on class 2002 must NOT compute 200300 (class 2003's
        // activity 0); it clamps to activity 0 -> class_uid * 100.
        assert_eq!(Fake(100).type_uid(), 200200);
        assert_ne!(Fake(100).type_uid(), 200300);
    }
}
