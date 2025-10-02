/// Core steganography module combining chaos and fractal encoding
/// Implements the Teehee steganography algorithm with invisible embedding

use crate::chaos::LogisticMap;
use crate::fractal::FractalCoder;
use anyhow::{anyhow, Result};
use image::{DynamicImage, GenericImageView};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use base64::Engine;

use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, generic_array::GenericArray}};
use rand::RngCore;

const VERSION: u8 = 2; // bumped for new format
// Public header: version (1) + nonce (12) + ciphertext_len (4) = 17 bytes
const HEADER_SIZE: usize = 17;

struct PublicHeader {
    version: u8,
    nonce: [u8; 12],
    ciphertext_len: u32,
}

impl PublicHeader {
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1..13].copy_from_slice(&self.nonce);
        out[13..17].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        out
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE { return Err(anyhow!("Invalid header size")); }
        let version = bytes[0];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[1..13]);
        let ciphertext_len = u32::from_le_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]);
        Ok(Self { version, nonce, ciphertext_len })
    }
}

/// Main steganography engine
pub struct TeeheeStego {
    strength: f64,
}

impl TeeheeStego {
    pub fn new(strength: f64) -> Self {
        let strength = strength.clamp(0.5, 2.0);
        Self { strength }
    }

    /// Embed secret message into carrier image with invisible method (texture-aware + chaos)
    pub fn embed(&self, carrier: &DynamicImage, message: &[u8]) -> Result<DynamicImage> {
        if message.is_empty() {
            return Err(anyhow!("Message cannot be empty"));
        }

        let (width, height) = carrier.dimensions();

        // Derive build-secret based keying material
        let build_secret = get_build_secret();

        // Encrypt message with AES-256-GCM using key derived from build secret
        let (ciphertext, nonce) = encrypt_message(&build_secret, message)?;

        // Prepare public header (minimal, no magic to avoid signatures)
        let header = PublicHeader { version: VERSION, nonce, ciphertext_len: ciphertext.len() as u32 };
        let header_bytes = header.to_bytes();

        // Build fractal blocks and select high-texture positions
        let gray = carrier.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() {
            return Err(anyhow!("No fractal blocks found"));
        }

        // Select top texture blocks by MSE percentile (e.g., top 60%)
        let mut mses: Vec<f64> = blocks.iter().map(|b| b.mse).collect();
        mses.par_sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (mses.len() as f64 * 0.6) as usize;
        let threshold = mses.get(idx).copied().unwrap_or(0.0);

        let selected_blocks: Vec<_> = blocks.into_par_iter().filter(|b| b.mse >= threshold).collect();

        // Construct base positions from selected blocks
        let embed_positions: Vec<usize> = selected_blocks.par_iter().flat_map(|block| {
            let mut positions = Vec::with_capacity(64);
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
            positions
        }).collect();

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
            let channel = channel_for_idx_header(&build_secret, bit_idx);
            let bit = header_bits_vec[bit_idx];
            let sign_up = sign_up_for_idx_header(&build_secret, bit_idx);
            pixel[channel] = embed_bit_lsb_match_with_dir(pixel[channel], bit, sign_up);
            stego.put_pixel(x, y, pixel);
        }

        // Precompute payload bits
        let payload_bits_vec = bytes_to_bits(&ciphertext);

        // Stage B: payload permutation derived from build secret + nonce
        let mut payload_perm_rng = build_logistic_for_payload(&build_secret, &nonce);
        let payload_positions_base: Vec<usize> = embed_positions.iter().skip(header_bits).take(payload_bits).copied().collect();
        let permutation = generate_permutation_from_rng(&mut payload_perm_rng, payload_positions_base.len());
        let payload_positions: Vec<usize> = permutation.into_iter().map(|i| payload_positions_base[i]).collect();

        // Compute modified pixels in parallel and then apply
        let modified_pixels: Vec<_> = (0..payload_positions.len()).into_par_iter().filter_map(|i| {
            let pos = payload_positions[i];
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            if x >= width || y >= height { return None; }
            let mut pixel = *carrier_rgb.get_pixel(x, y);
            let channel = channel_for_idx_payload(&build_secret, &nonce, i);
            let bit = payload_bits_vec[i];
            let sign_up = sign_up_for_idx_payload(&build_secret, &nonce, i);
            pixel[channel] = embed_bit_lsb_match_with_dir(pixel[channel], bit, sign_up);
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

        let build_secret = get_build_secret();

        // Rebuild positions
        let gray = stego.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() {
            return Err(anyhow!("No fractal blocks found"));
        }
        let mut mses: Vec<f64> = blocks.iter().map(|b| b.mse).collect();
        mses.par_sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (mses.len() as f64 * 0.6) as usize;
        let threshold = mses.get(idx).copied().unwrap_or(0.0);
        let selected_blocks: Vec<_> = blocks.into_par_iter().filter(|b| b.mse >= threshold).collect();
        let embed_positions: Vec<usize> = selected_blocks.par_iter().flat_map(|block| {
            let mut positions = Vec::with_capacity(64);
            for dy in 0..8u32 { for dx in 0..8u32 {
                let x = block.range_x + dx; let y = block.range_y + dy;
                if x < width && y < height { positions.push((y * width + x) as usize); }
            }}
            positions
        }).collect();

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
            let channel = channel_for_idx_header(&build_secret, bit_idx);
            extracted_header_bits[bit_idx] = pixel[channel] & 1;
        }
        let header_bytes = bits_to_bytes(&extracted_header_bits);
        let header = PublicHeader::from_bytes(&header_bytes)?;

        // Payload positions are permuted with build secret + nonce
        let payload_bits = header.ciphertext_len as usize * 8;
        if embed_positions.len() < header_bits + payload_bits { return Err(anyhow!("Insufficient positions for payload")); }
        let payload_positions_base: Vec<usize> = embed_positions.iter().skip(header_bits).take(payload_bits).copied().collect();
        let mut payload_perm_rng = build_logistic_for_payload(&build_secret, &header.nonce);
        let permutation = generate_permutation_from_rng(&mut payload_perm_rng, payload_positions_base.len());
        let payload_positions: Vec<usize> = permutation.into_iter().map(|i| payload_positions_base[i]).collect();

        // Extract payload bits
        let mut extracted_payload_bits = vec![0u8; payload_bits];
        for (i, &pos) in payload_positions.iter().enumerate() {
            let x = (pos as u32) % width;
            let y = (pos as u32) / width;
            let pixel = stego_rgb.get_pixel(x, y);
            let channel = channel_for_idx_payload(&build_secret, &header.nonce, i);
            extracted_payload_bits[i] = pixel[channel] & 1;
        }
        let ciphertext = bits_to_bytes(&extracted_payload_bits);

        // Decrypt
        let plaintext = decrypt_message(&build_secret, &header.nonce, &ciphertext)?;
        Ok(plaintext)
    }

    /// Calculate capacity in bytes based on current strategy
    pub fn calculate_capacity(image: &DynamicImage) -> usize {
        let gray = image.to_luma8();
        let fractal_coder = FractalCoder::new();
        let blocks = fractal_coder.encode(&gray);
        if blocks.is_empty() { return 0; }
        let mut mses: Vec<f64> = blocks.iter().map(|b| b.mse).collect();
        mses.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (mses.len() as f64 * 0.6) as usize;
        let threshold = mses.get(idx).copied().unwrap_or(0.0);
        let positions: usize = blocks.iter().filter(|b| b.mse >= threshold).map(|_| 64usize).sum();
        if positions <= HEADER_SIZE * 8 { return 0; }
        (positions - HEADER_SIZE * 8) / 8 // 1 bit per pixel
    }

    fn hash_seed(&self, seed: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.finalize().into()
    }
}

// --- helpers ---

fn get_build_secret() -> [u8; 32] {
    let b64 = env!("TEEHEE_BUILD_SALT_B64");
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).expect("Invalid build salt");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn kdf_aead_key(build_secret: &[u8; 32]) -> [u8; 32] {
    // Simple domain-separated SHA-256 KDF
    let mut hasher = Sha256::new();
    hasher.update(b"TEEHEE_KDF_AES256");
    hasher.update(build_secret);
    hasher.finalize().into()
}

fn kdf_payload_seed(build_secret: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TEEHEE_KDF_PAYLOAD");
    hasher.update(build_secret);
    hasher.update(nonce);
    hasher.finalize().into()
}

fn kdf_header_seed(build_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TEEHEE_KDF_HEADER");
    hasher.update(build_secret);
    hasher.finalize().into()
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

fn build_logistic_for_payload(build_secret: &[u8; 32], nonce: &[u8; 12]) -> LogisticMap {
    let seed = hex_string(kdf_payload_seed(build_secret, nonce));
    LogisticMap::new(&seed)
}

fn hex_string(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
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

fn embed_bit_lsb_match_with_dir(value: u8, bit: u8, sign_up: bool) -> u8 {
    if (value & 1) == bit { return value; }
    if sign_up {
        if value == 255 { value.saturating_sub(1) } else { value.saturating_add(1) }
    } else {
        if value == 0 { value.saturating_add(1) } else { value.saturating_sub(1) }
    }
}

fn generate_permutation_from_rng(rng: &mut LogisticMap, length: usize) -> Vec<usize> {
    // Fisher-Yates with chaotic RNG
    let mut perm: Vec<usize> = (0..length).collect();
    for i in (1..length).rev() {
        let j = ((rng.next() * (i as f64 + 1.0)) as usize).min(i);
        perm.swap(i, j);
    }
    perm
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

        
