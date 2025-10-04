use crate::error::{AppError, Result};
use crate::models::ImageFingerprint;
use img_hash::{HashAlg, HasherConfig, ImageHash};

/// Calculate perceptual hash (pHash) of an image
pub fn calculate_perceptual_hash(image: &image::DynamicImage) -> ImageHash<Box<[u8]>> {
    let hasher = HasherConfig::new()
        .hash_alg(HashAlg::Gradient) // Use gradient hash, robust to compression and minor modifications
        .hash_size(8, 8) // 64-bit hash
        .to_hasher();

    hasher.hash_image(&image.clone())
}

/// Convert ImageHash to byte array
pub fn hash_to_bytes(hash: &ImageHash<Box<[u8]>>) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

/// Reconstruct ImageHash from byte array
pub fn bytes_to_hash(bytes: &[u8]) -> Result<ImageHash<Box<[u8]>>> {
    ImageHash::from_bytes(bytes).map_err(|e| AppError::Internal(format!("Invalid hash: {:?}", e)))
}

/// Calculate Hamming distance between two hashes
pub fn calculate_hamming_distance(
    hash1: &ImageHash<Box<[u8]>>,
    hash2: &ImageHash<Box<[u8]>>,
) -> u32 {
    hash1.dist(hash2)
}

/// Find best match in fingerprint list
/// Returns: (compile_id, Hamming distance)
pub fn find_best_match(
    target_hash: &ImageHash<Box<[u8]>>,
    fingerprints: &[ImageFingerprint],
    max_distance: u32,
) -> Result<Option<(String, u32)>> {
    let mut best_match: Option<(String, u32)> = None;

    for fp in fingerprints {
        let fp_hash = bytes_to_hash(&fp.phash)?;
        let distance = calculate_hamming_distance(target_hash, &fp_hash);

        if distance <= max_distance
            && (best_match.is_none() || distance < best_match.as_ref().unwrap().1)
        {
            best_match = Some((fp.compile_id.clone(), distance));
        }
    }

    Ok(best_match)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, RgbImage};

    #[test]
    fn test_identical_images() {
        let img = DynamicImage::ImageRgb8(RgbImage::new(100, 100));
        let hash1 = calculate_perceptual_hash(&img);
        let hash2 = calculate_perceptual_hash(&img);

        assert_eq!(calculate_hamming_distance(&hash1, &hash2), 0);
    }

    #[test]
    fn test_hash_serialization() {
        let img = DynamicImage::ImageRgb8(RgbImage::new(100, 100));
        let hash = calculate_perceptual_hash(&img);

        let bytes = hash_to_bytes(&hash);
        let recovered = bytes_to_hash(&bytes).unwrap();

        assert_eq!(calculate_hamming_distance(&hash, &recovered), 0);
    }
}
