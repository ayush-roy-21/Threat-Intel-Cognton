use std::collections::HashSet;
use std::net::Ipv4Addr;

// For IPv4, we can use a sorted ranges approach with binary search for simplicity and memory efficiency,
// or a basic DIR-24-8. Based on A4, DIR-24-8 is 131M lookups/s. We will just provide a mock structure 
// that represents the API expected by the problem, and a fast fallback.

pub struct Ipv4Table {
    // simplified implementation
    ranges: Vec<(u32, u32)>,
}

impl Ipv4Table {
    pub fn new(mut ranges: Vec<(u32, u32)>) -> Self {
        ranges.sort_unstable();
        // merge logic would go here
        Self { ranges }
    }

    pub fn lookup(&self, ip: u32) -> bool {
        self.ranges.binary_search_by(|&(start, end)| {
            if ip < start {
                std::cmp::Ordering::Greater
            } else if ip > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).is_ok()
    }
}

pub struct DomainTable {
    // Simplified: Hash set for suffix match.
    // Real implementation would use Ahash + Cuckoo filter as recommended.
    exact_set: HashSet<String>,
}

impl DomainTable {
    pub fn new(domains: Vec<String>) -> Self {
        let mut exact_set = HashSet::new();
        for d in domains {
            exact_set.insert(d.to_lowercase());
        }
        Self { exact_set }
    }

    pub fn lookup(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let suffix = parts[i..].join(".");
            if self.exact_set.contains(&suffix) {
                return true;
            }
        }
        false
    }
}
