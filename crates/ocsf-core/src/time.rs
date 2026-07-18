//! Conversions between OCSF `Timestamp` (epoch milliseconds) and
//! `chrono::DateTime<Utc>`.
//!
//! The module is declared unconditionally in `lib.rs` so `ocsf_core::time`
//! is always a valid path; the conversion functions themselves are gated
//! behind the `chrono` feature, so the module is simply empty when the
//! feature is disabled.

#[cfg(feature = "chrono")]
use crate::base::Timestamp;

/// Converts an OCSF millisecond timestamp to a UTC `chrono::DateTime`.
///
/// Returns `None` when the timestamp is outside the range representable by
/// `chrono`.
///
/// # Examples
///
/// ```
/// let timestamp = 1_752_000_000_000;
/// let datetime = to_datetime(timestamp).unwrap();
///
/// assert_eq!(datetime.timestamp_millis(), timestamp);
/// ```
///
/// ```
/// assert!(to_datetime(i64::MAX).is_none());
/// ```
///
/// # Returns
///
/// `Some` containing the converted datetime when the timestamp is representable,
/// or `None` otherwise.
#[cfg(feature = "chrono")]
pub fn to_datetime(ts: Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(ts)
}

/// Converts a UTC date and time to an OCSF timestamp in milliseconds since the Unix epoch.
///
/// # Returns
///
/// The corresponding OCSF millisecond timestamp.
///
/// # Examples
///
/// ```
/// let dt = chrono::DateTime::from_timestamp_millis(1_752_000_000_000).unwrap();
/// let timestamp = ocsf_core::time::from_datetime(dt);
///
/// assert_eq!(timestamp, 1_752_000_000_000);
/// ```
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
