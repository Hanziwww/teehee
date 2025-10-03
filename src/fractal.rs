/// Fractal-based steganography using affine transformation parameters
/// Embeds data into the fractal compression coefficients
///
/// **Cross-platform determinism**: Uses fixed-point arithmetic and strict rounding
/// to ensure identical results across different platforms, compilers, and FPU modes.
use image::{GrayImage, Luma};
use rayon::prelude::*;

const BLOCK_SIZE: u32 = 8;
const DOMAIN_SIZE: u32 = 16;

// Fixed-point precision: 16 bits for fractional part (Q16.16 format)
const FIXED_POINT_SCALE: i64 = 65536; // 2^16
const FIXED_POINT_BITS: u32 = 16;

/// Deterministic rounding to nearest integer (round-half-to-even / banker's rounding)
/// Ensures consistent behavior across platforms
#[inline]
fn round_to_even(x: f64) -> i64 {
    let floor = x.floor();
    let frac = x - floor;

    if frac < 0.5 {
        floor as i64
    } else if frac > 0.5 {
        (floor + 1.0) as i64
    } else {
        // Exactly 0.5: round to nearest even
        let floor_i = floor as i64;
        if floor_i % 2 == 0 {
            floor_i
        } else {
            floor_i + 1
        }
    }
}

/// Convert floating-point to fixed-point (Q16.16)
#[inline]
fn to_fixed(x: f64) -> i64 {
    round_to_even(x * FIXED_POINT_SCALE as f64)
}

/// Convert fixed-point (Q16.16) to floating-point
#[inline]
fn from_fixed(x: i64) -> f64 {
    x as f64 / FIXED_POINT_SCALE as f64
}

/// Represents an affine transformation: y = s*x + o
///
/// **Deterministic representation**: Uses fixed-point internally for cross-platform consistency.
/// All computation results are quantized to fixed precision to eliminate floating-point variance.
#[derive(Clone, Copy, Debug)]
pub struct AffineTransform {
    // Public interface remains f64 for compatibility
    pub scale: f64,
    pub offset: f64,

    // Internal fixed-point representation (Q16.16)
    scale_fixed: i64,
    offset_fixed: i64,
}

impl AffineTransform {
    /// Create new transform with deterministic quantization
    pub fn new(scale: f64, offset: f64) -> Self {
        let scale_fixed = to_fixed(scale);
        let offset_fixed = to_fixed(offset);

        Self {
            scale: from_fixed(scale_fixed),
            offset: from_fixed(offset_fixed),
            scale_fixed,
            offset_fixed,
        }
    }

    pub fn identity() -> Self {
        Self::new(1.0, 0.0)
    }

    /// Get quantized scale (for deterministic comparison)
    #[inline]
    pub fn scale_fixed(&self) -> i64 {
        self.scale_fixed
    }

    /// Get quantized offset (for deterministic comparison)
    #[inline]
    pub fn offset_fixed(&self) -> i64 {
        self.offset_fixed
    }
}

/// Fractal block representing a range-domain pair
///
/// **Deterministic MSE**: MSE is quantized to fixed-point to ensure stable sorting/selection
#[derive(Clone, Debug)]
pub struct FractalBlock {
    pub range_x: u32,
    pub range_y: u32,
    pub domain_x: u32,
    pub domain_y: u32,
    pub transform: AffineTransform,
    pub mse: f64, // Mean squared error (public interface)

    // Internal quantized MSE for deterministic comparison (Q16.16)
    mse_fixed: i64,
}

impl FractalBlock {
    /// Create new block with quantized MSE
    fn new(
        range_x: u32,
        range_y: u32,
        domain_x: u32,
        domain_y: u32,
        transform: AffineTransform,
        mse: f64,
    ) -> Self {
        let mse_fixed = to_fixed(mse);
        Self {
            range_x,
            range_y,
            domain_x,
            domain_y,
            transform,
            mse: from_fixed(mse_fixed), // Store quantized value
            mse_fixed,
        }
    }

    /// Get quantized MSE for deterministic comparison
    #[inline]
    pub fn mse_fixed(&self) -> i64 {
        self.mse_fixed
    }
}

/// Fractal encoder/decoder for steganography
pub struct FractalCoder {
    block_size: u32,
    domain_size: u32,
}

impl FractalCoder {
    pub fn new() -> Self {
        Self {
            block_size: BLOCK_SIZE,
            domain_size: DOMAIN_SIZE,
        }
    }

    /// Encode image into fractal blocks (multi-threaded, deterministic order)
    pub fn encode(&self, image: &GrayImage) -> Vec<FractalBlock> {
        let (width, height) = image.dimensions();

        // Generate all block positions in deterministic order (row-major)
        let positions: Vec<(u32, u32)> = (0..height)
            .step_by(self.block_size as usize)
            .flat_map(|y| {
                (0..width)
                    .step_by(self.block_size as usize)
                    .map(move |x| (x, y))
            })
            .collect();

        // Process blocks in parallel but preserve deterministic order
        let mut results: Vec<(usize, Option<FractalBlock>)> = positions
            .par_iter()
            .enumerate()
            .map(|(idx, &(x, y))| (idx, self.find_best_match(image, x, y)))
            .collect();

        // Sort by index to restore deterministic order
        results.sort_by_key(|(idx, _)| *idx);

        // Filter out None values
        results.into_iter().filter_map(|(_, block)| block).collect()
    }

    /// Find best matching domain block for a given range block
    ///
    /// **Deterministic search**: Uses fixed-point MSE comparison to ensure
    /// consistent block selection across platforms
    fn find_best_match(
        &self,
        image: &GrayImage,
        range_x: u32,
        range_y: u32,
    ) -> Option<FractalBlock> {
        let (width, height) = image.dimensions();

        // Check boundaries
        if range_x + self.block_size > width || range_y + self.block_size > height {
            return None;
        }

        let range_block = self.extract_block(image, range_x, range_y, self.block_size);

        let mut best_block = None;
        let mut best_mse_fixed = i64::MAX;

        // Search for best domain block (deterministic row-major order)
        for dy in (0..height.saturating_sub(self.domain_size)).step_by(4) {
            for dx in (0..width.saturating_sub(self.domain_size)).step_by(4) {
                let domain_block = self.extract_block(image, dx, dy, self.domain_size);
                let downscaled = self.downsample(&domain_block, self.block_size);

                // Compute affine transformation (quantized)
                let transform = self.compute_affine(&downscaled, &range_block);
                let mse = self.compute_mse(&downscaled, &range_block, &transform);

                // Create block with quantized MSE
                let block = FractalBlock::new(range_x, range_y, dx, dy, transform, mse);

                // Compare using fixed-point MSE for determinism
                if block.mse_fixed < best_mse_fixed {
                    best_mse_fixed = block.mse_fixed;
                    best_block = Some(block);
                }
            }
        }

        best_block
    }

    /// Extract a block from image
    ///
    /// **Note**: Returns exact integer pixel values as f64 (no rounding issues)
    fn extract_block(&self, image: &GrayImage, x: u32, y: u32, size: u32) -> Vec<f64> {
        let mut block = Vec::with_capacity((size * size) as usize);

        // Deterministic row-major order
        for j in 0..size {
            for i in 0..size {
                let px = (x + i).min(image.width() - 1);
                let py = (y + j).min(image.height() - 1);
                let pixel = image.get_pixel(px, py)[0] as f64;
                block.push(pixel);
            }
        }

        block
    }

    /// Downsample a block to target size
    ///
    /// **Deterministic downsampling**: Uses simple nearest-neighbor with integer indexing
    /// to avoid any floating-point rounding variance
    fn downsample(&self, block: &[f64], target_size: u32) -> Vec<f64> {
        let src_size = (block.len() as f64).sqrt() as u32;

        // Use integer-only ratio calculation for determinism
        // ratio_num / ratio_den = src_size / target_size
        let ratio_num = src_size;
        let ratio_den = target_size;

        let mut result = Vec::with_capacity((target_size * target_size) as usize);

        for j in 0..target_size {
            for i in 0..target_size {
                // Integer-only indexing: floor((i * ratio_num) / ratio_den)
                let src_x = (i * ratio_num) / ratio_den;
                let src_y = (j * ratio_num) / ratio_den;
                let idx = (src_y * src_size + src_x) as usize;
                result.push(block[idx]);
            }
        }

        result
    }

    /// Compute affine transformation: range = scale * domain + offset
    ///
    /// **Deterministic regression**: Uses fixed-point arithmetic for all intermediate
    /// calculations to ensure bit-exact results across platforms.
    ///
    /// Algorithm: Linear least-squares with fixed-point numerics
    fn compute_affine(&self, domain: &[f64], range: &[f64]) -> AffineTransform {
        let n = domain.len() as i64;

        // Convert to fixed-point and compute sums (all in i64 to avoid overflow)
        let mut sum_d: i64 = 0;
        let mut sum_r: i64 = 0;
        let mut sum_dd: i64 = 0;
        let mut sum_dr: i64 = 0;

        for (&d, &r) in domain.iter().zip(range.iter()) {
            // Pixels are 0-255, so conversion to fixed-point is safe
            let d_fixed = to_fixed(d);
            let r_fixed = to_fixed(r);

            sum_d += d_fixed;
            sum_r += r_fixed;

            // Products need double precision (Q32.32)
            // We'll scale down to Q16.16 after multiplication
            sum_dd += (d_fixed * d_fixed) >> FIXED_POINT_BITS;
            sum_dr += (d_fixed * r_fixed) >> FIXED_POINT_BITS;
        }

        // Compute means (in fixed-point)
        let mean_d = sum_d / n;
        let mean_r = sum_r / n;

        // Linear regression in fixed-point: scale = Cov(D,R) / Var(D)
        // denominator = sum_dd - n * mean_d^2
        let mean_d_sq = (mean_d * mean_d) >> FIXED_POINT_BITS;
        let denominator = sum_dd - n * mean_d_sq;

        // numerator = sum_dr - n * mean_d * mean_r
        let mean_prod = (mean_d * mean_r) >> FIXED_POINT_BITS;
        let numerator = sum_dr - n * mean_prod;

        // Compute scale = numerator / denominator (both in Q16.16)
        let scale_fixed = if denominator.abs() > 100 {
            // Avoid near-zero division
            // Division in fixed-point: (numerator << 16) / denominator
            (numerator << FIXED_POINT_BITS) / denominator
        } else {
            FIXED_POINT_SCALE // scale = 1.0
        };

        // offset = mean_r - scale * mean_d
        let offset_fixed = mean_r - ((scale_fixed * mean_d) >> FIXED_POINT_BITS);

        // Convert back to f64 via AffineTransform::new (which re-quantizes)
        AffineTransform::new(from_fixed(scale_fixed), from_fixed(offset_fixed))
    }

    /// Compute mean squared error
    ///
    /// **Deterministic MSE**: Uses fixed-point arithmetic to ensure identical results
    fn compute_mse(&self, domain: &[f64], range: &[f64], transform: &AffineTransform) -> f64 {
        let n = domain.len() as i64;
        let mut sum_sq: i64 = 0;

        // Use quantized transform parameters for prediction
        let scale_fixed = transform.scale_fixed;
        let offset_fixed = transform.offset_fixed;

        for (&d, &r) in domain.iter().zip(range.iter()) {
            let d_fixed = to_fixed(d);
            let r_fixed = to_fixed(r);

            // predicted = scale * d + offset (all in Q16.16)
            let predicted = ((scale_fixed * d_fixed) >> FIXED_POINT_BITS) + offset_fixed;

            // diff = predicted - r
            let diff = predicted - r_fixed;

            // diff^2 and accumulate (scale down to avoid overflow)
            let diff_sq = (diff * diff) >> FIXED_POINT_BITS;
            sum_sq += diff_sq;
        }

        // MSE = sum / n (in Q16.16)
        let mse_fixed = sum_sq / n;

        // Convert to f64
        from_fixed(mse_fixed)
    }

    /// Embed data into fractal blocks by modifying offset parameter
    /// Uses LSB-like approach on offset value
    pub fn embed_data(&self, blocks: &mut [FractalBlock], data: &[u8], strength: f64) {
        let total_bits = data.len() * 8;
        let blocks_needed = total_bits.min(blocks.len());

        for (i, block) in blocks.iter_mut().take(blocks_needed).enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            if byte_idx >= data.len() {
                break;
            }

            let bit = (data[byte_idx] >> (7 - bit_idx)) & 1;

            // Modify offset based on bit value
            // Add/subtract a small value proportional to strength
            let delta = if bit == 1 { strength } else { -strength };
            block.transform.offset += delta;
        }
    }

    /// Extract data from fractal blocks
    pub fn extract_data(
        &self,
        blocks: &[FractalBlock],
        original_blocks: &[FractalBlock],
        data_len: usize,
    ) -> Vec<u8> {
        let total_bits = data_len * 8;
        let mut data = vec![0u8; data_len];

        for i in 0..total_bits.min(blocks.len()).min(original_blocks.len()) {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            if byte_idx >= data_len {
                break;
            }

            // Compare offset values
            let diff = blocks[i].transform.offset - original_blocks[i].transform.offset;
            let bit = if diff > 0.0 { 1 } else { 0 };

            data[byte_idx] |= bit << (7 - bit_idx);
        }

        data
    }

    /// Apply fractal blocks back to image
    pub fn decode(&self, blocks: &[FractalBlock], width: u32, height: u32) -> GrayImage {
        let mut image = GrayImage::new(width, height);

        for block in blocks {
            // Create synthetic domain block (simplified)
            for j in 0..self.block_size {
                for i in 0..self.block_size {
                    let x = block.range_x + i;
                    let y = block.range_y + j;

                    if x < width && y < height {
                        // Simplified reconstruction
                        let base_value = block.transform.offset.abs();
                        let pixel_value = base_value.clamp(0.0, 255.0) as u8;
                        image.put_pixel(x, y, Luma([pixel_value]));
                    }
                }
            }
        }

        image
    }
}

impl Default for FractalCoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affine_transform() {
        let coder = FractalCoder::new();
        let domain = vec![10.0, 20.0, 30.0, 40.0];
        let range = vec![15.0, 25.0, 35.0, 45.0];

        let transform = coder.compute_affine(&domain, &range);
        assert!(transform.scale > 0.0);
    }

    #[test]
    fn test_embed_extract() {
        let mut blocks = vec![FractalBlock::new(0, 0, 0, 0, AffineTransform::identity(), 0.0,); 64];

        let original_blocks = blocks.clone();
        let data = vec![0xAB, 0xCD];

        let coder = FractalCoder::new();
        coder.embed_data(&mut blocks, &data, 1.0);

        let extracted = coder.extract_data(&blocks, &original_blocks, 2);
        assert_eq!(extracted, data);
    }

    #[test]
    fn test_fixed_point_determinism() {
        // Test that fixed-point conversion is deterministic
        let test_values = vec![0.0, 1.0, 127.5, 255.0, 123.456789];

        for &val in &test_values {
            let fixed = to_fixed(val);
            let back = from_fixed(fixed);

            // Re-conversion should be identical
            let fixed2 = to_fixed(back);
            assert_eq!(
                fixed, fixed2,
                "Fixed-point conversion not deterministic for {}",
                val
            );
        }
    }

    #[test]
    fn test_round_to_even() {
        // Test banker's rounding
        assert_eq!(round_to_even(0.5), 0); // 0.5 -> 0 (even)
        assert_eq!(round_to_even(1.5), 2); // 1.5 -> 2 (even)
        assert_eq!(round_to_even(2.5), 2); // 2.5 -> 2 (even)
        assert_eq!(round_to_even(3.5), 4); // 3.5 -> 4 (even)
        assert_eq!(round_to_even(0.4), 0);
        assert_eq!(round_to_even(0.6), 1);
    }

    #[test]
    fn test_affine_determinism() {
        let coder = FractalCoder::new();
        let domain = vec![10.0, 20.0, 30.0, 40.0];
        let range = vec![15.0, 25.0, 35.0, 45.0];

        // Compute transform multiple times
        let t1 = coder.compute_affine(&domain, &range);
        let t2 = coder.compute_affine(&domain, &range);

        // Should be bit-exact
        assert_eq!(t1.scale_fixed, t2.scale_fixed);
        assert_eq!(t1.offset_fixed, t2.offset_fixed);
        assert_eq!(t1.scale, t2.scale);
        assert_eq!(t1.offset, t2.offset);
    }
}
