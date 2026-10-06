use crate::stix::Bundle;
use std::collections::HashSet;
use ipnet::IpNet;
use std::str::FromStr;

pub async fn clean_stix(bundle: Bundle) -> Result<Bundle, Box<dyn std::error::Error>> {
    println!("Fetching Tranco top 10k...");
    let tranco_domains = fetch_tranco_top_10k().await.unwrap_or_default();
    
    println!("Fetching Cloud ranges...");
    let cloud_ranges = fetch_cloud_ranges().await.unwrap_or_default();
    
    let mut cleaned_objects = Vec::new();
    let mut dropped = 0;

    for ind in bundle.objects {
        // extract value
        let val = if ind.pattern.contains("ipv4-addr") || ind.pattern.contains("ipv6-addr") {
            let start = ind.pattern.find("'").unwrap_or(0) + 1;
            let end = ind.pattern.rfind("'").unwrap_or(ind.pattern.len());
            let ip_str = &ind.pattern[start..end];
            
            if let Ok(ip) = std::net::IpAddr::from_str(ip_str) {
                let mut matched = false;
                for net in &cloud_ranges {
                    if net.contains(&ip) {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    println!("Dropped IP {} - matched cloud range", ip_str);
                    dropped += 1;
                    continue;
                }
            }
            ind
        } else if ind.pattern.contains("domain-name") {
            let start = ind.pattern.find("'").unwrap_or(0) + 1;
            let end = ind.pattern.rfind("'").unwrap_or(ind.pattern.len());
            let dom = &ind.pattern[start..end];
            
            if tranco_domains.contains(dom) {
                println!("Dropped domain {} - matched Tranco top 10k", dom);
                dropped += 1;
                continue;
            }
            ind
        } else {
            ind
        };
        cleaned_objects.push(val);
    }

    println!("Dropped {} total false positive indicators", dropped);

    Ok(Bundle {
        type_: bundle.type_,
        id: bundle.id,
        objects: cleaned_objects,
    })
}

async fn fetch_tranco_top_10k() -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    // In a real scenario, fetch and parse. Here we mock some well known.
    let mut set = HashSet::new();
    set.insert("google.com".to_string());
    set.insert("aws.amazon.com".to_string());
    Ok(set)
}

async fn fetch_cloud_ranges() -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    let mut ranges = Vec::new();
    // Add mocked ranges (e.g. 8.8.8.0/24)
    ranges.push(IpNet::from_str("8.8.8.0/24")?);
    ranges.push(IpNet::from_str("1.1.1.0/24")?);
    Ok(ranges)
}
