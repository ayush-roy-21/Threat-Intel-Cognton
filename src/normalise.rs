use crate::model::{IocType, RawIoc};
use crate::stix::{Bundle, Indicator};
use uuid::Uuid;

pub fn to_stix(iocs: Vec<RawIoc>) -> Result<Bundle, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    
    for ioc in iocs {
        let pattern = match ioc.ioc_type {
            IocType::Ipv4 => format!("[ipv4-addr:value = '{}']", ioc.value),
            IocType::Ipv6 => format!("[ipv6-addr:value = '{}']", ioc.value),
            IocType::Domain => format!("[domain-name:value = '{}']", ioc.value),
            IocType::Url => format!("[url:value = '{}']", ioc.value),
            IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
        };
        
        objects.push(Indicator {
            type_: "indicator".to_string(),
            spec_version: "2.1".to_string(),
            id: format!("indicator--{}", Uuid::new_v4()),
            created: ioc.first_seen.to_rfc3339(),
            modified: ioc.first_seen.to_rfc3339(),
            name: Some(ioc.value.clone()),
            indicator_types: vec!["malicious-activity".to_string()],
            pattern,
            pattern_type: "stix".to_string(),
            valid_from: ioc.first_seen.to_rfc3339(),
            valid_until: Some(ioc.valid_until.to_rfc3339()),
            confidence: Some(ioc.confidence as i32),
            custom_properties: None,
        });
    }

    Ok(Bundle {
        type_: "bundle".to_string(),
        id: format!("bundle--{}", Uuid::new_v4()),
        objects,
    })
}
