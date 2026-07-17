mod conformance;
use conformance::*;
use ocsf_core::objects::{Metadata, Product};

#[test]
fn product_matches_oracle() {
    assert_object_matches::<Product>("product");
}

#[test]
fn metadata_matches_oracle() {
    assert_object_matches::<Metadata>("metadata");
}
