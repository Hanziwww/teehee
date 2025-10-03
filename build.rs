/// Enhanced build script with AEAD-encrypted secret storage
///
/// Security enhancements:
/// 1. ChaCha20Poly1305 AEAD encryption (replaces XOR obfuscation)
/// 2. Multi-fragment distribution to custom ELF/PE sections
/// 3. Randomized fragment count and decoy injection
/// 4. Per-build unique encryption key derived from entropy sources
/// 5. Integrity verification with authentication tags
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Derive a build-unique encryption key from multiple entropy sources
fn derive_build_key() -> [u8; 32] {
    let mut key_material = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut key_material);

    // Mix in build timestamp for absolute uniqueness
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ts_bytes = timestamp.to_le_bytes();
    for (i, byte) in ts_bytes.iter().enumerate() {
        key_material[i % 64] ^= byte;
    }

    // Mix in host-specific entropy
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        let host_hash = hasher.finalize();
        for (i, byte) in host_hash.iter().enumerate() {
            key_material[i % 64] ^= byte;
        }
    }

    // Final KDF: HKDF-like expansion
    let mut hasher = Sha256::new();
    hasher.update(&key_material);
    hasher.update(b"TEEHEE_BUILD_KEY_V2");
    let key: [u8; 32] = hasher.finalize().into();
    key
}

/// Generate the master secret (32 bytes) from cryptographic RNG
fn generate_master_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    // Mix in timestamp to ensure absolute uniqueness per build
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ts_bytes = timestamp.to_le_bytes();
    for (i, byte) in ts_bytes.iter().enumerate() {
        secret[i % 32] ^= byte;
    }

    // Final hash for uniform distribution
    let mut hasher = Sha256::new();
    hasher.update(&secret);
    hasher.update(b"TEEHEE_MASTER_SECRET_V2");
    let final_secret: [u8; 32] = hasher.finalize().into();
    final_secret
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Create output directory for embedded fragments
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let fragments_dir = Path::new(&out_dir).join("fragments");
    fs::create_dir_all(&fragments_dir).unwrap();

    // Step 1: Generate master secret
    let master_secret = generate_master_secret();

    // Step 2: Derive build-unique encryption key
    let build_key = derive_build_key();

    // Step 3: Encrypt master secret with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&build_key).unwrap();
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, master_secret.as_ref())
        .expect("ChaCha20Poly1305 encryption failed");

    // ciphertext = encrypted_secret (32 bytes) + auth_tag (16 bytes) = 48 bytes
    assert_eq!(ciphertext.len(), 48, "AEAD ciphertext should be 48 bytes");

    // Step 4: Randomize fragment count (3-6 fragments)
    let num_real_fragments: usize = 3 + (rand::random::<u8>() % 4) as usize;
    let fragment_size = (ciphertext.len() + num_real_fragments - 1) / num_real_fragments;

    // Step 5: Split ciphertext into fragments with padding
    let mut fragments = Vec::new();
    for i in 0..num_real_fragments {
        let start = i * fragment_size;
        let end = (start + fragment_size).min(ciphertext.len());
        let mut frag = vec![0u8; fragment_size];

        if start < ciphertext.len() {
            let copy_len = end - start;
            frag[..copy_len].copy_from_slice(&ciphertext[start..end]);
            // Remaining bytes are already zero-padded
        }

        fragments.push(frag);
    }

    // Step 6: Generate decoy fragments (2-4 decoys)
    let num_decoys = 2 + (rand::random::<u8>() % 3) as usize;
    let mut decoy_fragments = Vec::new();
    for _ in 0..num_decoys {
        let mut decoy = vec![0u8; fragment_size];
        rand::rngs::OsRng.fill_bytes(&mut decoy);
        decoy_fragments.push(decoy);
    }

    // Step 7: Write fragments to files (custom sections will include these)
    for (i, frag) in fragments.iter().enumerate() {
        let path = fragments_dir.join(format!("real_{}.bin", i));
        fs::write(&path, frag).unwrap();
    }

    for (i, decoy) in decoy_fragments.iter().enumerate() {
        let path = fragments_dir.join(format!("decoy_{}.bin", i));
        fs::write(&path, decoy).unwrap();
    }

    // Step 8: Write metadata (nonce, fragment count, build key)
    fs::write(fragments_dir.join("nonce.bin"), &nonce_bytes).unwrap();
    fs::write(fragments_dir.join("build_key.bin"), &build_key).unwrap();

    // Compute integrity checksum of master secret (for verification)
    let mut hasher = Sha256::new();
    hasher.update(&master_secret);
    let integrity_hash: [u8; 32] = hasher.finalize().into();
    fs::write(
        fragments_dir.join("integrity.bin"),
        &integrity_hash[..16], // Use first 16 bytes
    )
    .unwrap();

    // Step 9: Generate Rust source code for fragment inclusion
    let mut fragment_includes = String::new();
    fragment_includes.push_str("// Auto-generated fragment constants\n\n");

    // Nonce and build key (always present)
    fragment_includes.push_str(
        "static NONCE: [u8; 12] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/fragments/nonce.bin\"));\n"
    );
    fragment_includes.push_str(
        "static BUILD_KEY: [u8; 32] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/fragments/build_key.bin\"));\n"
    );
    fragment_includes.push_str(
        "static INTEGRITY_HASH: [u8; 16] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/fragments/integrity.bin\"));\n\n"
    );

    // Real fragments in custom sections
    for i in 0..num_real_fragments {
        fragment_includes.push_str(&format!("#[link_section = \".tee{}\"]\n", i));
        fragment_includes.push_str(&format!(
            "static FRAGMENT_{}: [u8; {}] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/fragments/real_{}.bin\"));\n\n",
            i, fragment_size, i
        ));
    }

    // Generate a const array of fragment references for easier access
    fragment_includes.push_str("// Fragment array for dynamic access\n");
    fragment_includes.push_str(&format!(
        "const FRAGMENTS: [&[u8]; {}] = [",
        num_real_fragments
    ));
    for i in 0..num_real_fragments {
        if i > 0 {
            fragment_includes.push_str(", ");
        }
        fragment_includes.push_str(&format!("&FRAGMENT_{}", i));
    }
    fragment_includes.push_str("];\n\n");

    // Decoy fragments (in different sections)
    for i in 0..num_decoys {
        fragment_includes.push_str(&format!("#[link_section = \".dec{}\"]\n", i));
        fragment_includes.push_str(&format!(
            "#[allow(dead_code)]\nstatic DECOY_{}: [u8; {}] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/fragments/decoy_{}.bin\"));\n\n",
            i, fragment_size, i
        ));
    }

    // Write fragment metadata for runtime
    fs::write(fragments_dir.join("metadata.rs"), fragment_includes).unwrap();

    // Step 10: Export metadata as env vars for runtime configuration
    println!(
        "cargo:rustc-env=TEEHEE_NUM_FRAGMENTS={}",
        num_real_fragments
    );
    println!("cargo:rustc-env=TEEHEE_FRAGMENT_SIZE={}", fragment_size);
    println!("cargo:rustc-env=TEEHEE_NUM_DECOYS={}", num_decoys);

    // Build timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("cargo:rustc-env=TEEHEE_BUILD_TIME={}", timestamp);

    println!(
        "cargo:warning=Build security: {} real fragments + {} decoys generated",
        num_real_fragments, num_decoys
    );
}
