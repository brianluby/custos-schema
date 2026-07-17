//! Conversions between OCSF `Timestamp` (epoch milliseconds) and
//! `chrono::DateTime<Utc>`.
//!
//! The module is declared unconditionally in `lib.rs` so `ocsf_core::time`
//! is always a valid path; the conversion functions themselves are gated
//! behind the `chrono` feature, so the module is simply empty when the
//! feature is disabled.

#[cfg(feature = "chrono")]
use crate::base::Timestamp;

/// Convert an OCSF millisecond timestamp to a `chrono::DateTime<Utc>`.
///
/// Returns `None` if `ts` falls outside the range `chrono` can represent
/// (e.g. `i64::MAX`) rather than panicking.
#[cfg(feature = "chrono")]
pub fn to_datetime(ts: Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(ts)
}

/// Convert a `chrono::DateTime<Utc>` to an OCSF millisecond timestamp.
#[cfg(feature = "chrono")]
pub fn from_datetime(dt: chrono::DateTime<chrono::Utc>) -> Timestamp {
    dt.timestamp_millis()
}

#[cfg(all(test, feature = "chrono"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_millis() {
        let ts = 1_752_000_000_000_i64;
        assert_eq!(from_datetime(to_datetime(ts).unwrap()), ts);
        assert!(to_datetime(i64::MAX).is_none()); // out of range: None, not panic
    }
}
