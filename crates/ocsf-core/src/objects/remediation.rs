use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::objects::KbArticle;

/// OCSF `remediation` object: describes the recommended remediation steps
/// to address identified issue(s).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Remediation {
    /// Center for Internet Security (CIS) Controls mapped to provide
    /// additional remediation detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cis_controls: Option<Vec<serde_json::Value>>,
    /// The description of the remediation strategy.
    pub desc: String,
    /// A list of KB articles or patches related to the remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_article_list: Option<Vec<KbArticle>>,
    /// The KB article(s) related to the entity. Deprecated in favor of
    /// `kb_article_list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_articles: Option<Vec<String>>,
    /// A list of supporting URL(s)/references that help describe the
    /// remediation strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediation_roundtrips_unknown_fields() {
        let json = r#"{"desc":"upgrade to 2.17.1","future_field":1}"#;
        let remediation: Remediation = serde_json::from_str(json).unwrap();
        assert_eq!(remediation.desc, "upgrade to 2.17.1");
        assert_eq!(remediation.other["future_field"], 1);
        let out = serde_json::to_value(&remediation).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("references").is_none());
    }
}
