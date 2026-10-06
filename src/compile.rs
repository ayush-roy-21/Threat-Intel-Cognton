use crate::stix::Bundle;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
pub struct Manifest {
    pub version: u32,
    pub ipv4_counts: usize,
    pub ipv6_counts: usize,
    pub domain_counts: usize,
    pub sha256_hash: String,
    pub signature: String,
}

pub fn compile_and_sign(bundle: Bundle) -> Result<(), Box<dyn std::error::Error>> {
    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();
    let mut domains = Vec::new();

    for ind in bundle.objects {
        if ind.pattern.contains("ipv4-addr") {
            ipv4s.push(extract_val(&ind.pattern));
        } else if ind.pattern.contains("ipv6-addr") {
            ipv6s.push(extract_val(&ind.pattern));
        } else if ind.pattern.contains("domain-name") {
            domains.push(extract_val(&ind.pattern));
        }
    }

    // Binary format: basic bincode of (Vec<String>, Vec<String>, Vec<String>)
    let bin_data = bincode::serialize(&( &ipv4s, &ipv6s, &domains ))?;
    
    // Hash
    let mut hasher = Sha256::new();
    hasher.update(&bin_data);
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);

    // Sign
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let signature = signing_key.sign(&bin_data);

    let manifest = Manifest {
        version: 1,
        ipv4_counts: ipv4s.len(),
        ipv6_counts: ipv6s.len(),
        domain_counts: domains.len(),
        sha256_hash: hash_hex,
        signature: hex::encode(signature.to_bytes()),
    };

    let mut file = fs::File::create("feed.bin")?;
    file.write_all(&bin_data)?;

    let manifest_str = serde_json::to_string_pretty(&manifest)?;
    fs::write("manifest.json", manifest_str)?;

    Ok(())
}

fn extract_val(pattern: &str) -> String {
    let start = pattern.find("'").unwrap_or(0) + 1;
    let end = pattern.rfind("'").unwrap_or(pattern.len());
    pattern[start..end].to_string()
}
