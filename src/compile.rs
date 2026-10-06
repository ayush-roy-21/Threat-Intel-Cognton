use crate::stix::Bundle;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize, serde::Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub ipv4_counts: usize,
    pub ipv6_counts: usize,
    pub domain_counts: usize,
    pub sha256_hash: String,
    pub signature: String, // of the binary hash concatenated with version counts
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

    // Binary format
    let bin_data = bincode::serialize(&( &ipv4s, &ipv6s, &domains ))?;
    
    // Hash
    let mut hasher = Sha256::new();
    hasher.update(&bin_data);
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);

    // Sign
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();
    
    // Write public key to verify later
    fs::write("public_key.bin", verify_key.as_bytes())?;

    // Create manifest string before signature to sign both binary and manifest contents
    let signature_content = format!("v1|ipv4:{}|ipv6:{}|domain:{}|hash:{}", ipv4s.len(), ipv6s.len(), domains.len(), hash_hex);
    let signature = signing_key.sign(signature_content.as_bytes());

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

pub fn verify_and_load() -> Result<(), Box<dyn std::error::Error>> {
    // Demo loader ensuring tampered files are rejected
    let bin_data = fs::read("feed.bin")?;
    let manifest_str = fs::read_to_string("manifest.json")?;
    let pub_key_bytes = fs::read("public_key.bin")?;
    
    let manifest: Manifest = serde_json::from_str(&manifest_str)?;
    
    let mut hasher = Sha256::new();
    hasher.update(&bin_data);
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);
    
    if hash_hex != manifest.sha256_hash {
        return Err("Tamper detected: Binary hash mismatch".into());
    }
    
    let signature_content = format!("v1|ipv4:{}|ipv6:{}|domain:{}|hash:{}", 
        manifest.ipv4_counts, manifest.ipv6_counts, manifest.domain_counts, hash_hex);
        
    let verify_key = VerifyingKey::from_bytes(pub_key_bytes.as_slice().try_into()?)?;
    let sig_bytes = hex::decode(&manifest.signature)?;
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into()?);
    
    if verify_key.verify(signature_content.as_bytes(), &signature).is_err() {
        return Err("Tamper detected: Invalid signature".into());
    }
    
    Ok(())
}

fn extract_val(pattern: &str) -> String {
    let start = pattern.find("'").unwrap_or(0) + 1;
    let end = pattern.rfind("'").unwrap_or(pattern.len());
    pattern[start..end].to_string()
}
