use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Bundle {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub objects: Vec<Indicator>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Indicator {
    #[serde(rename = "type")]
    pub type_: String,
    pub spec_version: String,
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: Option<String>,
    pub indicator_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<i32>,
    pub custom_properties: Option<std::collections::HashMap<String, String>>,
}
