use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIoc {
    pub value: String,
    pub ioc_type: IocType,
    pub source: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
    pub confidence: f64,
}
