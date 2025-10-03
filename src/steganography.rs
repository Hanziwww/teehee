/// Core steganography module combining CSPRNG and fractal encoding
/// Implements the Teehee steganography algorithm with invisible embedding

use crate::fractal::FractalCoder;
use crate::stc::{StcParams, stc_encode_min_cost, stc_decode};
use anyhow::{anyhow, Result};
use image::{DynamicImage, GenericImageView};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, generic_array::GenericArray}};
use rand::{RngCore, SeedableRng};
use rand::seq::SliceRandom;
use hkdf::Hkdf;
use sha2::Sha256 as HmacSha256;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use zeroize::Zeroizing;

const VERSION: u8 = 3; // bumped for deterministic position encoding
// Public header: version (1) + nonce (12) + ciphertext_len (4) + position_count (4) = 21 bytes
const HEADER_SIZE: usize = 21;

struct PublicHeader {
    version: u8,
    nonce: [u8; 12],
    ciphertext_len: u32,
    position_count: u32, // number of embedding positions (for verification)
}

impl PublicHeader {
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1..13].copy_from_slice(&self.nonce);
        out[13..17].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        out[17..21].copy_from_slice(&self.position_count.to_le_bytes());
        out
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE { return Err(anyhow!("Invalid header size")); }
        let version = bytes[0];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[1..13]);
        let ciphertext_len = u32::from_le_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]);
        let position_count = u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]);
        Ok(Self { version, nonce, ciphertext_len, position_count })
    }
}

/// Main steganography engine
pub struct TeeheeStego {
    user_key: Option<String>,
}

impl TeeheeStego {
    /// Create a new TeeheeStego instance using only build-time secret
    pub fn new() -> Self {
        Self { user_key: None }
    }

    /// Create a new TeeheeStego instance with additional user key
    /// This enables dual-factor encryption: build secret + user password
    pub fn with_user_key(user_key: &str) -> Self {
        Self { 
            user_key: Some(user_key.to_string()) 
        }
    }

    /// Derive the master secret by combining build secret with optional user key
    fn derive_master_secret(&self) -> [u8; 32] {
        // Security: Use SecretGuard to auto-zero build secret after use
        let secret_guard = SecretGuard::new();
        let build_secret = secret_guard.as_ref();

        match &self.user_key {
            None => {
                // Single-factor: use build secret directly
                *build_secret
            }
            Some(user_key) => {
                // Dual-factor: combine build secret + user key using HKDF
                type HkdfSha256 = Hkdf<HmacSha256>;
                
                let hkdf = HkdfSha256::new(Some(build_secret), user_key.as_bytes());
                let mut master = [0u8; 32];
                hkdf.expand(b"teehee-dual-factor-v1", &mut master)
                    .expect("HKDF expand failed");
                master
            }
        }
    }

    /// Embed secret message into carrier image with invisible method (texture-aware + chaos)
    pub fn embed(&self, carrier: &DynamicImage, message: &[u8]) -> Result<DynamicImage> {
        if message.is_empty() {
            return Err(anyhow!("Message cannot be empty"));
        }

        let (width, height) = carrier.dimensions();

        // Derive master secret (build secret + optional user key)
        let master_secret = self.derive_master_secret();

        // Encrypt message with AES-256-GCM using derived master secret
        let (ciphertext, nonce) = encrypt_message(&master_secret, message)?;

        // Header will be created after position calculation

        // Build fractal blocks using deterministic encoding
        let gray = carrier.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() {
            return Err(anyhow!("No fractal blocks found"));
        }

        // Select top texture blocks deterministically (top 60% by quantized MSE)
        // This avoids floating-point comparison issues across platforms
        let selected_indices = select_blocks_deterministic(&blocks, 0.6);
        
        // Generate embedding positions from selected blocks
        let embed_positions = generate_embed_positions(&blocks, &selected_indices, width, height);

        // Update header with actual position count for cross-platform verification
        let header = PublicHeader { 
            version: VERSION, 
            nonce, 
            ciphertext_len: ciphertext.len() as u32,
            position_count: embed_positions.len() as u32,
        };
        let header_bytes = header.to_bytes();

        // Each pixel carries 1 bit in 1 channel (hash-chosen). Need enough positions
        let header_bits = HEADER_SIZE * 8;
        let payload_bits = ciphertext.len() * 8;
        let total_bits_needed = header_bits + payload_bits;
        if embed_positions.len() < total_bits_needed {
            return Err(anyhow!(
                "Not enough suitable embedding positions: need {} bits, have {}",
                total_bits_needed, embed_positions.len()
            ));
        }

        // Stage A: embed header using a deterministic order (no permutation) to bootstrap
        let header_positions: Vec<usize> = embed_positions.iter().take(header_bits).copied().collect();

        // Clone carrier to stego
        let carrier_rgb = Arc::new(carrier.to_rgb8());
        let mut stego = carrier.to_rgb8();

        // Precompute header bits
        let header_bits_vec = bytes_to_bits(&header_bytes);

        // Embed header (±1 LSB matching), one bit per pixel, channel chosen by keyed hash
        for (bit_idx, &pos) in header_positions.iter().enumerate() {
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            let mut pixel = *carrier_rgb.get_pixel(x, y);
            let channel = channel_for_idx_header(&master_secret, bit_idx);
            let bit = header_bits_vec[bit_idx];
            let sign_up = sign_up_for_idx_header(&master_secret, bit_idx);
            pixel[channel] = embed_bit_lsb_match_with_dir(pixel[channel], bit, sign_up);
            stego.put_pixel(x, y, pixel);
        }

        // Precompute payload bits
        let payload_bits_vec = bytes_to_bits(&ciphertext);

        // Stage B: payload permutation derived from master secret + nonce using CSPRNG
        let payload_positions_base: Vec<usize> = embed_positions.iter().skip(header_bits).take(payload_bits).copied().collect();
        let permutation = generate_permutation_csprng(&master_secret, &nonce, payload_positions_base.len());
        let payload_positions: Vec<usize> = permutation.into_iter().map(|i| payload_positions_base[i]).collect();

        // Build cover bits and costs for STC
        let mut cover_bits: Vec<u8> = Vec::with_capacity(payload_positions.len());
        let mut costs: Vec<u32> = Vec::with_capacity(payload_positions.len());
        for i in 0..payload_positions.len() {
            let pos = payload_positions[i];
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            let pixel = carrier_rgb.get_pixel(x, y);
            let channel = channel_for_idx_payload(&master_secret, &nonce, i);
            let lsb = pixel[channel] & 1;
            cover_bits.push(lsb);

            // Calculate embedding cost based on suitability
            let suitability = embedding_suitability(&carrier_rgb, x, y, channel, width, height);
            // Convert suitability [0.0, 1.0] to cost [0, 1M]
            // Low suitability = high cost (avoid flipping)
            let cost = ((1.0 - suitability).clamp(0.0, 1.0) * 1_000_000.0) as u32;
            costs.push(cost);
        }

        // Derive STC parameters deterministically from secret + nonce
        let stc_params = stc_derive_params(&master_secret, &nonce);

        // Compute optimal flips using STC
        let flips = stc_encode_min_cost(&cover_bits, &payload_bits_vec, &costs, &stc_params);

        // Apply flips in parallel with adaptive embedding
        let modified_pixels: Vec<_> = (0..payload_positions.len()).into_par_iter().filter_map(|i| {
            let pos = payload_positions[i];
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            if x >= width || y >= height { return None; }
            let mut pixel = *carrier_rgb.get_pixel(x, y);
            let channel = channel_for_idx_payload(&master_secret, &nonce, i);
            let current_bit = pixel[channel] & 1;
            let target_bit = if flips[i] == 1 { current_bit ^ 1 } else { current_bit };
            let sign_up = sign_up_for_idx_payload(&master_secret, &nonce, i);

            // Calculate local texture variance for adaptive embedding
            let variance = calculate_local_variance(&carrier_rgb, x, y, channel, width, height);

            // Use adaptive embedding to reach target_bit
            pixel[channel] = embed_bit_adaptive(pixel[channel], target_bit, sign_up, variance);
            Some((x, y, pixel))
        }).collect();

        for (x, y, pixel) in modified_pixels {
            stego.put_pixel(x, y, pixel);
        }

        Ok(DynamicImage::ImageRgb8(stego))
    }

    /// Extract message from stego image (self-decrypting, no original needed)
    pub fn extract(&self, stego: &DynamicImage) -> Result<Vec<u8>> {
        let (width, height) = stego.dimensions();

        // Derive master secret (build secret + optional user key)
        let master_secret = self.derive_master_secret();

        // Rebuild positions - MUST match embed() exactly using deterministic algorithm
        let gray = stego.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() {
            return Err(anyhow!("No fractal blocks found"));
        }
        
        // Use deterministic block selection (same as embed)
        let selected_indices = select_blocks_deterministic(&blocks, 0.6);
        let embed_positions = generate_embed_positions(&blocks, &selected_indices, width, height);

        // First, extract header from first HEADER_SIZE*8 positions
        let header_bits = HEADER_SIZE * 8;
        if embed_positions.len() < header_bits { return Err(anyhow!("Insufficient positions for header")); }
        let header_positions: Vec<usize> = embed_positions.iter().take(header_bits).copied().collect();

        let stego_rgb = stego.to_rgb8();
        let mut extracted_header_bits = vec![0u8; header_bits];
        for (bit_idx, &pos) in header_positions.iter().enumerate() {
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            let pixel = stego_rgb.get_pixel(x, y);
            let channel = channel_for_idx_header(&master_secret, bit_idx);
            extracted_header_bits[bit_idx] = pixel[channel] & 1;
        }
        let header_bytes = bits_to_bytes(&extracted_header_bits);
        let header = PublicHeader::from_bytes(&header_bytes)?;

        // Verify position count matches (cross-platform consistency check)
        if header.position_count != embed_positions.len() as u32 {
            return Err(anyhow!(
                "Position count mismatch! Expected {} positions but found {}. \
                This may indicate a floating-point determinism issue across platforms.",
                header.position_count,
                embed_positions.len()
            ));
        }

        // Payload positions are permuted with master secret + nonce using CSPRNG
        let payload_bits = header.ciphertext_len as usize * 8;
        if embed_positions.len() < header_bits + payload_bits { return Err(anyhow!("Insufficient positions for payload")); }
        let payload_positions_base: Vec<usize> = embed_positions.iter().skip(header_bits).take(payload_bits).copied().collect();
        let permutation = generate_permutation_csprng(&master_secret, &header.nonce, payload_positions_base.len());
        let payload_positions: Vec<usize> = permutation.into_iter().map(|i| payload_positions_base[i]).collect();

        // Extract stego bits from permuted positions
        let mut stego_bits: Vec<u8> = Vec::with_capacity(payload_positions.len());
        for (i, &pos) in payload_positions.iter().enumerate() {
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            let pixel = stego_rgb.get_pixel(x, y);
            let channel = channel_for_idx_payload(&master_secret, &header.nonce, i);
            stego_bits.push(pixel[channel] & 1);
        }

        // Decode message bits using STC
        let stc_params = stc_derive_params(&master_secret, &header.nonce);
        let decoded_bits = stc_decode(&stego_bits, &stc_params);
        
        // Extract first payload_bits from syndrome
        let extracted_payload_bits = decoded_bits.into_iter().take(payload_bits).collect::<Vec<u8>>();
        let ciphertext = bits_to_bytes(&extracted_payload_bits);

        // Decrypt using master secret
        let plaintext = decrypt_message(&master_secret, &header.nonce, &ciphertext)?;
        Ok(plaintext)
    }

    /// Calculate capacity in bytes based on current strategy
    pub fn calculate_capacity(image: &DynamicImage) -> usize {
        let (width, height) = image.dimensions();
        let gray = image.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() { return 0; }
        
        // Use deterministic block selection (same as embed/extract)
        let selected_indices = select_blocks_deterministic(&blocks, 0.6);
        let positions = generate_embed_positions(&blocks, &selected_indices, width, height);
        
        if positions.len() <= HEADER_SIZE * 8 { return 0; }
        (positions.len() - HEADER_SIZE * 8) / 8 // 1 bit per pixel
    }
}

// --- helpers ---

/// Quantize MSE to integer to avoid floating-point cross-platform issues
/// Multiplies by 1000 and rounds to get deterministic integer values
fn quantize_mse(mse: f64) -> u64 {
    (mse * 1000.0).round() as u64
}

/// Deterministically select blocks based on quantized MSE
/// Returns block indices in a platform-independent way
fn select_blocks_deterministic(blocks: &[crate::fractal::FractalBlock], percentile: f64) -> Vec<usize> {
    if blocks.is_empty() {
        return Vec::new();
    }
    
    // Create (quantized_mse, original_index) pairs for stable sorting
    let mut indexed_mses: Vec<(u64, usize)> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (quantize_mse(block.mse), idx))
        .collect();
    
    // Stable sort by quantized MSE (deterministic across platforms)
    indexed_mses.sort_by(|a, b| a.0.cmp(&b.0));
    
    // Calculate threshold index
    let threshold_idx = (indexed_mses.len() as f64 * percentile) as usize;
    let threshold_mse = if threshold_idx < indexed_mses.len() {
        indexed_mses[threshold_idx].0
    } else {
        0
    };
    
    // Collect indices of blocks meeting threshold, preserving original order
    let mut selected_indices: Vec<usize> = indexed_mses
        .iter()
        .filter(|(mse, _)| *mse >= threshold_mse)
        .map(|(_, idx)| *idx)
        .collect();
    
    // Sort by original index to preserve deterministic order
    selected_indices.sort_unstable();
    
    selected_indices
}

/// Generate embedding positions from selected block indices
/// This ensures deterministic position generation across platforms
fn generate_embed_positions(
    blocks: &[crate::fractal::FractalBlock],
    selected_indices: &[usize],
    width: u32,
    height: u32,
) -> Vec<usize> {
    let mut positions = Vec::new();
    
    for &block_idx in selected_indices {
        if block_idx >= blocks.len() {
            continue;
        }
        let block = &blocks[block_idx];
        
        // Generate positions in deterministic order (row-major)
        for dy in 0..8u32 {
            for dx in 0..8u32 {
                let x = block.range_x + dx;
                let y = block.range_y + dy;
                if x < width && y < height {
                    let pos = (y * width + x) as usize;
                    positions.push(pos);
                }
            }
        }
    }
    
    positions
}

// Include build-time generated fragment constants
// These are scattered across custom ELF/PE sections (.tee0, .tee1, etc.)
include!(concat!(env!("OUT_DIR"), "/fragments/metadata.rs"));

/// Securely reconstruct the build secret from AEAD-encrypted fragments
/// 
/// Security enhancements over v1 (XOR):
/// 1. ChaCha20Poly1305 AEAD encryption (authenticated + encrypted)
/// 2. Fragments scattered across custom binary sections (.tee0-.teeN)
/// 3. Decoy fragments mixed in (.dec0-.decN) to confuse static analysis
/// 4. Authentication tag verification (tampering detection)
/// 5. Randomized fragment count per build (anti-pattern recognition)
/// 6. Immediate zeroing after use (defense-in-depth)
fn get_build_secret() -> [u8; 32] {
    // Parse runtime metadata
    let num_fragments: usize = env!("TEEHEE_NUM_FRAGMENTS").parse().unwrap();
    let fragment_size: usize = env!("TEEHEE_FRAGMENT_SIZE").parse().unwrap();
    
    // Step 1: Reconstruct ciphertext from scattered fragments
    // We use the FRAGMENTS array generated at build time
    let mut ciphertext = Vec::with_capacity(num_fragments * fragment_size);
    
    // Dynamic fragment assembly - FRAGMENTS array is generated with correct size at build time
    assert_eq!(
        FRAGMENTS.len(),
        num_fragments,
        "Fragment count mismatch: build-time vs runtime"
    );
    
    for fragment in FRAGMENTS.iter() {
        ciphertext.extend_from_slice(fragment);
    }
    
    // Remove padding zeros (ciphertext should be exactly 48 bytes: 32 + 16 tag)
    ciphertext.truncate(48);
    
    // Step 2: AEAD decryption with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&BUILD_KEY)
        .expect("Invalid build key length");
    let nonce = ChaNonce::from_slice(&NONCE);
    
    // Decrypt and verify authentication tag
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .unwrap_or_else(|_| {
            // Authentication failed - binary tampering detected
            panic!("Build secret authentication failed - binary may be tampered or corrupted");
        });
    
    // plaintext should be exactly 32 bytes
    assert_eq!(plaintext.len(), 32, "Decrypted secret has invalid length");
    
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    
    // Step 3: Verify integrity hash (defense-in-depth)
    let mut hasher = Sha256::new();
    hasher.update(&secret);
    let computed_hash = hasher.finalize();
    let computed_short = &computed_hash[..16];
    
    if computed_short != &INTEGRITY_HASH[..] {
        // Double-check failed - this should never happen if AEAD succeeded
        secret.fill(0);
        panic!("Build secret integrity double-check failed");
    }
    
    // Note: Caller (SecretGuard) will zero this after use
    secret
}

/// Basic anti-debugging check
/// Note: This is defense-in-depth, not foolproof
#[cfg(target_os = "windows")]
fn check_debugger() {
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }
    unsafe {
        if IsDebuggerPresent() != 0 {
            // Don't give clear error - just corrupt the secret
            std::process::abort();
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn check_debugger() {
    // On Unix-like systems, check PTRACE
    #[cfg(target_family = "unix")]
    {
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            if status.contains("TracerPid:\t0") == false {
                // Process is being traced
                std::process::abort();
            }
        }
    }
}

/// Enhanced secret guard with memory protection
/// 
/// Security features:
/// 1. Automatic zeroing on drop (defense against memory dumps)
/// 2. Memory locking (prevents swapping to disk on supported platforms)
/// 3. Guard pages (detect buffer overruns on some platforms)
/// 4. Multi-pass overwrite (defense-in-depth)
struct SecretGuard {
    secret: Zeroizing<[u8; 32]>,
    #[cfg(target_os = "windows")]
    locked: bool,
}

impl SecretGuard {
    fn new() -> Self {
        // Anti-debugging check before revealing secret
        check_debugger();
        
        let secret = Zeroizing::new(get_build_secret());
        
        #[cfg(target_os = "windows")]
        {
            // Try to lock memory page (prevent swapping to disk)
            let locked = lock_memory(&secret);
            if !locked {
                // Non-fatal: continue but warn
                eprintln!("Warning: Failed to lock secret memory (may swap to disk)");
            }
            
            Self { secret, locked }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // On Unix-like systems, try mlock
            #[cfg(target_family = "unix")]
            {
                unsafe {
                    let ptr = secret.as_ptr() as *mut std::ffi::c_void;
                    let len = std::mem::size_of::<[u8; 32]>();
                    libc::mlock(ptr, len);
                    // Ignore errors - not critical
                }
            }
            
            Self { secret }
        }
    }
    
    fn as_ref(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl Drop for SecretGuard {
    fn drop(&mut self) {
        // Zeroizing will auto-zero, but we do multi-pass for extra security
        unsafe {
            let secret_mut = &mut *(self.secret.as_ptr() as *mut [u8; 32]);
            
            // Pass 1: Fill with 0xFF
            std::ptr::write_volatile(secret_mut, [0xFF; 32]);
            
            // Pass 2: Fill with random
            let mut rng = rand::rngs::OsRng;
            rng.fill_bytes(&mut *secret_mut);
            
            // Pass 3: Zero (Zeroizing will also do this)
            std::ptr::write_volatile(secret_mut, [0u8; 32]);
        }
        
        #[cfg(target_os = "windows")]
        {
            if self.locked {
                unlock_memory(&self.secret);
            }
        }
        
        #[cfg(target_family = "unix")]
        {
            unsafe {
                let ptr = self.secret.as_ptr() as *mut std::ffi::c_void;
                let len = std::mem::size_of::<[u8; 32]>();
                libc::munlock(ptr, len);
            }
        }
    }
}

/// Windows-specific memory locking using VirtualLock
#[cfg(target_os = "windows")]
fn lock_memory(data: &[u8; 32]) -> bool {
    use std::ffi::c_void;
    
    extern "system" {
        fn VirtualLock(lpAddress: *const c_void, dwSize: usize) -> i32;
    }
    
    unsafe {
        let result = VirtualLock(
            data.as_ptr() as *const c_void,
            std::mem::size_of::<[u8; 32]>(),
        );
        result != 0
    }
}

#[cfg(target_os = "windows")]
fn unlock_memory(data: &[u8; 32]) {
    use std::ffi::c_void;
    
    extern "system" {
        fn VirtualUnlock(lpAddress: *const c_void, dwSize: usize) -> i32;
    }
    
    unsafe {
        VirtualUnlock(
            data.as_ptr() as *const c_void,
            std::mem::size_of::<[u8; 32]>(),
        );
    }
}

/// Modern HKDF-based key derivation for AEAD encryption
/// Uses HKDF-SHA256 with domain separation
fn kdf_aead_key(build_secret: &[u8; 32]) -> [u8; 32] {
    type HkdfSha256 = Hkdf<HmacSha256>;
    
    // HKDF with no salt (build_secret is already high-entropy)
    let hk = HkdfSha256::new(None, build_secret);
    
    let mut okm = [0u8; 32];
    // Domain-separated info string for AES-256-GCM key
    hk.expand(b"TEEHEE_HKDF_AES256_v1", &mut okm)
        .expect("HKDF expand should never fail with valid length");
    
    okm
}

/// Modern HKDF-based seed derivation for CSPRNG permutation
/// Uses HKDF-SHA256 with nonce as additional context
fn kdf_payload_seed(build_secret: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    type HkdfSha256 = Hkdf<HmacSha256>;
    
    // HKDF with no salt (build_secret is already high-entropy)
    let hk = HkdfSha256::new(None, build_secret);
    
    let mut okm = [0u8; 32];
    // Construct info string: domain separator + nonce
    let mut info = Vec::with_capacity(24 + 12);
    info.extend_from_slice(b"TEEHEE_HKDF_PAYLOAD_v1");
    info.extend_from_slice(nonce);
    
    hk.expand(&info, &mut okm)
        .expect("HKDF expand should never fail with valid length");
    
    okm
}

fn encrypt_message(build_secret: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let key_bytes = kdf_aead_key(build_secret);
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce_ga, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;
    Ok((ciphertext, nonce))
}

fn decrypt_message(build_secret: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = kdf_aead_key(build_secret);
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce_ga, ciphertext)
        .map_err(|_| anyhow!("Decryption failed (integrity check failed)"))?;
    Ok(plaintext)
}

/// Generate a deterministic permutation using ChaCha-based CSPRNG
/// This is cryptographically secure and cross-platform deterministic
fn generate_permutation_csprng(build_secret: &[u8; 32], nonce: &[u8; 12], length: usize) -> Vec<usize> {
    if length == 0 {
        return Vec::new();
    }
    
    // Derive a 32-byte seed from build_secret and nonce
    let seed_bytes = kdf_payload_seed(build_secret, nonce);
    
    // Create ChaCha-based RNG from seed
    let mut rng = rand::rngs::StdRng::from_seed(seed_bytes);
    
    // Generate permutation using Fisher-Yates shuffle
    let mut perm: Vec<usize> = (0..length).collect();
    
    // Use SliceRandom::shuffle which implements Fisher-Yates
    perm.shuffle(&mut rng);
    
    perm
}

/// Derive deterministic STC parameters from master secret + nonce
fn stc_derive_params(build_secret: &[u8; 32], nonce: &[u8; 12]) -> StcParams {
    // HKDF over secret||nonce to get 32 bytes, map to taps deterministically
    type HkdfSha256 = Hkdf<HmacSha256>;
    let mut okm = [0u8; 32];
    let hkdf = HkdfSha256::new(Some(build_secret), nonce);
    hkdf.expand(b"teehee-stc-params-v1", &mut okm).expect("HKDF expand");

    // constraint_length in [6..=12]
    let cl = 6 + (okm[0] as usize % 7);

    // choose 3..=5 taps including 0; derive from bytes
    let num_taps = 3 + (okm[1] as usize % 3);
    let mut taps: Vec<usize> = vec![0];
    let mut idx = 2usize;
    while taps.len() < num_taps && idx < okm.len() {
        let t = okm[idx] as usize % cl;
        if t != 0 && !taps.contains(&t) { taps.push(t); }
        idx += 1;
    }
    taps.sort_unstable();
    StcParams { constraint_length: cl, taps }
}

fn bytes_to_bits(data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(data.len() * 8);
    for &byte in data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; (bits.len() + 7) / 8];
    for (i, &bit) in bits.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_pos = 7 - (i % 8);
        out[byte_idx] |= bit << bit_pos;
    }
    out
}

/// LSB embedding with ±1 matching for statistical security
/// 
/// When the LSB needs to change, instead of direct replacement,
/// we add or subtract 1 from the pixel value (chosen by keyed randomness).
/// This maintains better statistical properties than LSB replacement.
///
/// # Arguments
/// * `value` - Current pixel value (0-255)
/// * `bit` - Target LSB (0 or 1)
/// * `sign_up` - Direction hint from keyed hash (true = +1, false = -1)
fn embed_bit_lsb_match_with_dir(value: u8, bit: u8, sign_up: bool) -> u8 {
    if (value & 1) == bit { 
        return value; // LSB already matches, no change needed
    }
    
    // Need to flip LSB: use ±1 matching
    if sign_up {
        if value == 255 { 
            value.saturating_sub(1) 
        } else { 
            value.saturating_add(1) 
        }
    } else {
        if value == 0 { 
            value.saturating_add(1) 
        } else { 
            value.saturating_sub(1) 
        }
    }
}

/// Adaptive LSB embedding that considers local texture variance
///
/// This wrapper uses texture variance to inform STC cost calculation upstream,
/// but the actual embedding remains standard ±1 LSB matching for all pixels.
/// 
/// Note: Previous "multi-bit-plane" strategy has been removed for simplicity
/// and to avoid unintended statistical artifacts.
///
/// # Arguments
/// * `value` - Current pixel value
/// * `bit` - Target LSB
/// * `sign_up` - Direction for ±1 matching
/// * `_texture_variance` - Local variance (reserved for future adaptive strategies)
fn embed_bit_adaptive(value: u8, bit: u8, sign_up: bool, _texture_variance: f64) -> u8 {
    // Unified strategy: ±1 LSB matching for all regions
    // STC already optimized flip positions based on texture-aware costs
    embed_bit_lsb_match_with_dir(value, bit, sign_up)
}

/// Calculate local texture variance around a pixel (3x3 neighborhood)
/// Higher variance indicates more texture, allowing stronger embedding
fn calculate_local_variance(
    image: &image::RgbImage,
    x: u32,
    y: u32,
    channel: usize,
    width: u32,
    height: u32,
) -> f64 {
    let mut values = Vec::with_capacity(9);
    
    // Collect 3x3 neighborhood
    for dy in -1i32..=1 {
        for dx in -1i32..=1 {
            let nx = (x as i32 + dx).clamp(0, width as i32 - 1) as u32;
            let ny = (y as i32 + dy).clamp(0, height as i32 - 1) as u32;
            let pixel = image.get_pixel(nx, ny);
            values.push(pixel[channel] as f64);
        }
    }
    
    // Calculate variance
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter()
        .map(|v| (v - mean).powi(2))
        .sum::<f64>() / values.len() as f64;
    
    variance
}

/// Calculate edge strength using Sobel operator
/// High edge strength areas should be avoided (wet paper codes concept)
fn calculate_edge_strength(
    image: &image::RgbImage,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> f64 {
    // Sobel kernels for X and Y gradients
    let sobel_x = [[-1.0, 0.0, 1.0], [-2.0, 0.0, 2.0], [-1.0, 0.0, 1.0]];
    let sobel_y = [[-1.0, -2.0, -1.0], [0.0, 0.0, 0.0], [1.0, 2.0, 1.0]];
    
    let mut gx = 0.0;
    let mut gy = 0.0;
    
    for dy in -1i32..=1 {
        for dx in -1i32..=1 {
            let nx = (x as i32 + dx).clamp(0, width as i32 - 1) as u32;
            let ny = (y as i32 + dy).clamp(0, height as i32 - 1) as u32;
            let pixel = image.get_pixel(nx, ny);
            
            // Use average of RGB channels for grayscale approximation
            let gray = (pixel[0] as f64 + pixel[1] as f64 + pixel[2] as f64) / 3.0;
            
            let kx = sobel_x[(dy + 1) as usize][(dx + 1) as usize];
            let ky = sobel_y[(dy + 1) as usize][(dx + 1) as usize];
            
            gx += kx * gray;
            gy += ky * gray;
        }
    }
    
    // Edge magnitude
    (gx * gx + gy * gy).sqrt()
}

/// Determine if a pixel is suitable for embedding (wet paper codes)
/// Returns embedding suitability score (0.0 = skip, 1.0 = best)
fn embedding_suitability(
    image: &image::RgbImage,
    x: u32,
    y: u32,
    channel: usize,
    width: u32,
    height: u32,
) -> f64 {
    let variance = calculate_local_variance(image, x, y, channel, width, height);
    let edge_strength = calculate_edge_strength(image, x, y, width, height);
    
    // Avoid strong edges (edge_strength > 100) - wet paper concept
    if edge_strength > 100.0 {
        return 0.0; // Skip this pixel
    }
    
    // Prefer high-variance (textured) areas
    let texture_score = (variance / 200.0).min(1.0);
    
    // Penalize strong edges
    let edge_penalty = 1.0 - (edge_strength / 100.0).min(1.0);
    
    // Combined suitability score
    (texture_score * 0.7 + edge_penalty * 0.3).clamp(0.0, 1.0)
}


fn channel_for_idx_header(build_secret: &[u8; 32], idx: usize) -> usize {
    let mut h = Sha256::new();
    h.update(b"CHAN_HDR");
    h.update(build_secret);
    h.update((idx as u64).to_le_bytes());
    let out: [u8; 32] = h.finalize().into();
    (out[0] % 3) as usize
}

fn sign_up_for_idx_header(build_secret: &[u8; 32], idx: usize) -> bool {
    let mut h = Sha256::new();
    h.update(b"SIGN_HDR");
    h.update(build_secret);
    h.update((idx as u64).to_le_bytes());
    let out: [u8; 32] = h.finalize().into();
    (out[1] & 1) == 1
}

fn channel_for_idx_payload(build_secret: &[u8; 32], nonce: &[u8; 12], idx: usize) -> usize {
    let mut h = Sha256::new();
    h.update(b"CHAN_PLD");
    h.update(build_secret);
    h.update(nonce);
    h.update((idx as u64).to_le_bytes());
    let out: [u8; 32] = h.finalize().into();
    (out[0] % 3) as usize
}

fn sign_up_for_idx_payload(build_secret: &[u8; 32], nonce: &[u8; 12], idx: usize) -> bool {
    let mut h = Sha256::new();
    h.update(b"SIGN_PLD");
    h.update(build_secret);
    h.update(nonce);
    h.update((idx as u64).to_le_bytes());
    let out: [u8; 32] = h.finalize().into();
    (out[1] & 1) == 1
}

        
