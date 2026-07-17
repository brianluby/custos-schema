use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// OCSF `image` object: describes the container image used as a template to
/// instantiate a container.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Image {
    /// The list of labels associated with the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The image name, e.g. `elixir`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The full path to the image file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The image tag, e.g. `1.11-alpine`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// The list of key:value tags associated with the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The unique image ID, e.g. `77af4d6b9913`.
    pub uid: String,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// OCSF `container` object: describes an instance of a container, a
/// prepackaged, portable system image that runs isolated on an existing
/// system using a container runtime like `containerd`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Container {
    /// The commit hash of the image, or the SHA256 hash of the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<serde_json::Value>,
    /// The container image used as a template to run the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Image>,
    /// The list of labels associated with the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The container name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The network driver used by the container, e.g. `bridge`, `overlay`, `host`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_driver: Option<String>,
    /// The orchestrator managing the container, e.g. `ECS`, `EKS`, `K8s`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchestrator: Option<String>,
    /// The unique identifier of the pod (or equivalent) that the container
    /// is executing on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_uuid: Option<String>,
    /// The backend running the container, e.g. `containerd` or `cri-o`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// The size of the container image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// The tag used by the container; can indicate version, format, or OS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// The list of key:value tags associated with the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The full container unique identifier for this instantiation of the
    /// container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_roundtrips_unknown_fields() {
        let json = r#"{"uid":"77af4d6b9913","future_field":1}"#;
        let image: Image = serde_json::from_str(json).unwrap();
        assert_eq!(image.other["future_field"], 1);
        let out = serde_json::to_value(&image).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("name").is_none());
    }

    #[test]
    fn container_roundtrips_unknown_fields() {
        let json = r#"{"name":"web-1","future_field":1}"#;
        let container: Container = serde_json::from_str(json).unwrap();
        assert_eq!(container.other["future_field"], 1);
        let out = serde_json::to_value(&container).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }
}
