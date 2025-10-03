/// Fractal-based steganography using affine transformation parameters
/// Embeds data into the fractal compression coefficients

use image::{GrayImage, Luma};
use rayon::prelude::*;

const BLOCK_SIZE: u32 = 8;
const DOMAIN_SIZE: u32 = 16;

/// Represents an affine transformation: y = s*x + o
#[derive(Clone, Copy, Debug)]
pub struct AffineTransform {
    pub scale: f64,
    pub offset: f64,
}

impl AffineTransform {
    pub fn new(scale: f64, offset: f64) -> Self {
        Self { scale, offset }
    }
    
    pub fn identity() -> Self {
        Self { scale: 1.0, offset: 0.0 }
    }
}

/// Fractal block representing a range-domain pair
#[derive(Clone, Debug)]
pub struct FractalBlock {
    pub range_x: u32,
    pub range_y: u32,
    pub domain_x: u32,
    pub domain_y: u32,
    pub transform: AffineTransform,
    pub mse: f64, // Mean squared error
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
        results.into_iter()
            .filter_map(|(_, block)| block)
            .collect()
    }
    
    /// Find best matching domain block for a given range block
    fn find_best_match(&self, image: &GrayImage, range_x: u32, range_y: u32) -> Option<FractalBlock> {
        let (width, height) = image.dimensions();
        
        // Check boundaries
        if range_x + self.block_size > width || range_y + self.block_size > height {
            return None;
        }
        
        let range_block = self.extract_block(image, range_x, range_y, self.block_size);
        
        let mut best_block = None;
        let mut best_mse = f64::MAX;
        
        // Search for best domain block
        for dy in (0..height.saturating_sub(self.domain_size)).step_by(4) {
            for dx in (0..width.saturating_sub(self.domain_size)).step_by(4) {
                let domain_block = self.extract_block(image, dx, dy, self.domain_size);
                let downscaled = self.downsample(&domain_block, self.block_size);
                
                // Compute affine transformation
                let transform = self.compute_affine(&downscaled, &range_block);
                let mse = self.compute_mse(&downscaled, &range_block, &transform);
                
                if mse < best_mse {
                    best_mse = mse;
                    best_block = Some(FractalBlock {
                        range_x,
                        range_y,
                        domain_x: dx,
                        domain_y: dy,
                        transform,
                        mse,
                    });
                }
            }
        }
        
        best_block
    }
    
    /// Extract a block from image
    fn extract_block(&self, image: &GrayImage, x: u32, y: u32, size: u32) -> Vec<f64> {
        let mut block = Vec::with_capacity((size * size) as usize);
        
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
    fn downsample(&self, block: &[f64], target_size: u32) -> Vec<f64> {
        let src_size = (block.len() as f64).sqrt() as u32;
        let ratio = src_size as f64 / target_size as f64;
        
        let mut result = Vec::with_capacity((target_size * target_size) as usize);
        
        for j in 0..target_size {
            for i in 0..target_size {
                let src_x = (i as f64 * ratio) as u32;
                let src_y = (j as f64 * ratio) as u32;
                let idx = (src_y * src_size + src_x) as usize;
                result.push(block[idx]);
            }
        }
        
        result
    }
    
    /// Compute affine transformation: range = scale * domain + offset
    fn compute_affine(&self, domain: &[f64], range: &[f64]) -> AffineTransform {
        let n = domain.len() as f64;
        
        let sum_d: f64 = domain.iter().sum();
        let sum_r: f64 = range.iter().sum();
        let sum_dd: f64 = domain.iter().map(|x| x * x).sum();
        let sum_dr: f64 = domain.iter().zip(range.iter()).map(|(d, r)| d * r).sum();
        
        let mean_d = sum_d / n;
        let mean_r = sum_r / n;
        
        // Linear regression: scale = Cov(D,R) / Var(D)
        let denominator = sum_dd - sum_d * mean_d;
        let scale = if denominator.abs() > 1e-10 {
            (sum_dr - sum_d * mean_r) / denominator
        } else {
            1.0
        };
        
        let offset = mean_r - scale * mean_d;
        
        AffineTransform::new(scale, offset)
    }
    
    /// Compute mean squared error
    fn compute_mse(&self, domain: &[f64], range: &[f64], transform: &AffineTransform) -> f64 {
        let mut sum = 0.0;
        for (d, r) in domain.iter().zip(range.iter()) {
            let predicted = transform.scale * d + transform.offset;
            let diff = predicted - r;
            sum += diff * diff;
        }
        sum / domain.len() as f64
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
    pub fn extract_data(&self, blocks: &[FractalBlock], original_blocks: &[FractalBlock], data_len: usize) -> Vec<u8> {
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
        let mut blocks = vec![
            FractalBlock {
                range_x: 0,
                range_y: 0,
                domain_x: 0,
                domain_y: 0,
                transform: AffineTransform::identity(),
                mse: 0.0,
            };
            64
        ];
        
        let original_blocks = blocks.clone();
        let data = vec![0xAB, 0xCD];
        
        let coder = FractalCoder::new();
        coder.embed_data(&mut blocks, &data, 1.0);
        
        let extracted = coder.extract_data(&blocks, &original_blocks, 2);
        assert_eq!(extracted, data);
    }
} 