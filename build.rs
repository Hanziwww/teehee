use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Security Enhancement: Mix multiple entropy sources
    // 1. OsRng (primary cryptographic source)
    // 2. Build timestamp (ensures uniqueness even if RNG is compromised)
    // 3. Host-specific data (makes builds machine-dependent)
    
    let mut master_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut master_secret);
    
    // Mix in timestamp to ensure absolute uniqueness per build
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ts_bytes = timestamp.to_le_bytes();
    for (i, byte) in ts_bytes.iter().enumerate() {
        master_secret[i % 32] ^= byte;
    }
    
    // Mix in host-specific entropy if available
    if let Ok(hostname) = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
    {
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        let host_hash = hasher.finalize();
        for (i, byte) in host_hash.iter().enumerate().take(32) {
            master_secret[i] ^= byte;
        }
    }
    
    // Final mix: rehash everything for uniform distribution
    let mut final_hasher = Sha256::new();
    final_hasher.update(&master_secret);
    final_hasher.update(b"TEEHEE_MASTER_SECRET_V1");
    master_secret.copy_from_slice(&final_hasher.finalize());
    
    // Security Enhancement 1: Split the secret into 4 fragments
    // This makes static analysis harder - each fragment alone is useless
    let mut fragments = [[0u8; 8]; 4];
    for (i, chunk) in master_secret.chunks(8).enumerate() {
        fragments[i].copy_from_slice(chunk);
    }
    
    // Security Enhancement 2: Generate decoy fragments to confuse reverse engineering
    let mut decoy1 = [0u8; 8];
    let mut decoy2 = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut decoy1);
    rand::rngs::OsRng.fill_bytes(&mut decoy2);
    
    // Security Enhancement 3: XOR obfuscation with constant keys
    // Runtime will XOR again to recover original values
    let xor_keys = [
        0x5A, 0x3C, 0x7E, 0x91, 0x42, 0x8D, 0x6F, 0x1B,
    ];
    
    let mut obfuscated_fragments = fragments.clone();
    for fragment in &mut obfuscated_fragments {
        for (i, byte) in fragment.iter_mut().enumerate() {
            *byte ^= xor_keys[i % xor_keys.len()];
        }
    }
    
    // Security Enhancement 4: Compute integrity checksum
    let mut hasher = Sha256::new();
    hasher.update(&master_secret);
    let checksum = hasher.finalize();
    let checksum_short: [u8; 8] = checksum[0..8].try_into().unwrap();
    
    // Encode all pieces - scattered across different env vars
    let frag0_b64 = base64::engine::general_purpose::STANDARD.encode(obfuscated_fragments[0]);
    let frag1_b64 = base64::engine::general_purpose::STANDARD.encode(obfuscated_fragments[1]);
    let frag2_b64 = base64::engine::general_purpose::STANDARD.encode(obfuscated_fragments[2]);
    let frag3_b64 = base64::engine::general_purpose::STANDARD.encode(obfuscated_fragments[3]);
    let checksum_b64 = base64::engine::general_purpose::STANDARD.encode(checksum_short);
    let decoy1_b64 = base64::engine::general_purpose::STANDARD.encode(decoy1);
    let decoy2_b64 = base64::engine::general_purpose::STANDARD.encode(decoy2);
    
    // Emit scattered env vars with misleading names
    println!("cargo:rustc-env=TEEHEE_SALT_A={}", frag0_b64);
    println!("cargo:rustc-env=TEEHEE_CONFIG_HASH={}", decoy1_b64);  // Decoy
    println!("cargo:rustc-env=TEEHEE_SALT_B={}", frag1_b64);
    println!("cargo:rustc-env=TEEHEE_VERSION_SIG={}", decoy2_b64);  // Decoy
    println!("cargo:rustc-env=TEEHEE_SALT_C={}", frag2_b64);
    println!("cargo:rustc-env=TEEHEE_SALT_D={}", frag3_b64);
    println!("cargo:rustc-env=TEEHEE_INTEGRITY={}", checksum_b64);
    
    // Security Enhancement 5: Add build timestamp for uniqueness verification
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("cargo:rustc-env=TEEHEE_BUILD_TIME={}", timestamp);
} 