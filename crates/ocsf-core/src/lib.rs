#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// The OCSF schema version these types are modeled against.
pub const OCSF_VERSION: &str = "1.8.0";

#[cfg(test)]
mod tests {
    #[test]
    fn ocsf_version_is_pinned() {
        assert_eq!(crate::OCSF_VERSION, "1.8.0");
    }
}
