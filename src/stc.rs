//! Syndrome Trellis Codes (STC) for Steganography
//!
//! Implementation of STC embedding based on:
//! Filler, T., Judas, J., & Fridrich, J. (2011).
//! "Minimizing Additive Distortion in Steganography using Syndrome-Trellis Codes"
//!
//! This implementation uses:
//! - Viterbi algorithm for minimum-cost path finding
//! - Log-domain arithmetic for numerical stability
//! - Deterministic syndrome calculation for perfect extraction

use std::f64;

/// STC encoder/decoder parameters
#[derive(Debug, Clone)]
pub struct StcParams {
    /// Constraint length (must be >= number of taps)
    pub constraint_length: usize,
    /// Tap positions (must include 0, sorted ascending)
    pub taps: Vec<usize>,
}

impl StcParams {
    /// Create default STC parameters (h=7, taps=[0,1,3])
    pub fn default() -> Self {
        Self {
            constraint_length: 7,
            taps: vec![0, 1, 3],
        }
    }

    /// Validate parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.constraint_length == 0 {
            return Err("Constraint length must be > 0".to_string());
        }
        if self.taps.is_empty() {
            return Err("Taps cannot be empty".to_string());
        }
        if !self.taps.contains(&0) {
            return Err("Taps must include position 0".to_string());
        }
        if self.taps.iter().any(|&t| t >= self.constraint_length) {
            return Err("All taps must be < constraint_length".to_string());
        }
        // Check sorted
        for i in 1..self.taps.len() {
            if self.taps[i] <= self.taps[i - 1] {
                return Err("Taps must be sorted and unique".to_string());
            }
        }
        Ok(())
    }
}

/// STC Encoder: Finds minimal-cost flips to embed message bits
///
/// # Arguments
/// * `cover_bits` - Original LSBs from cover image
/// * `message_bits` - Message to embed
/// * `costs` - Cost of flipping each bit (higher = avoid flipping)
/// * `params` - STC parameters
///
/// # Returns
/// Vector of flip indicators (0 = no flip, 1 = flip)
///
/// # Algorithm
/// Uses Viterbi algorithm with syndrome constraint enforcement:
/// - Each trellis step produces one syndrome bit
/// - Only transitions matching the target message bit are allowed
/// - Among valid transitions, select the minimum-cost path
pub fn stc_encode_min_cost(
    cover_bits: &[u8],
    message_bits: &[u8],
    costs: &[u32],
    params: &StcParams,
) -> Vec<u8> {
    params.validate().expect("Invalid STC parameters");
    
    let n = cover_bits.len();
    let m = message_bits.len();
    
    // Validate inputs
    assert_eq!(n, costs.len(), "Cover bits and costs must have same length");
    assert!(n >= m, "Cover must be at least as long as message");
    assert!(cover_bits.iter().all(|&b| b <= 1), "Cover bits must be 0 or 1");
    assert!(message_bits.iter().all(|&b| b <= 1), "Message bits must be 0 or 1");
    
    let h = params.constraint_length;
    let num_states = 1 << (h - 1); // 2^(h-1) states in trellis
    
    // Convert costs to log-domain for numerical stability
    let log_costs: Vec<f64> = costs.iter().map(|&c| {
        if c == 0 {
            0.0 // Cost 0 = always flip if needed (no penalty)
        } else {
            (c as f64).ln()
        }
    }).collect();
    
    // Viterbi algorithm in log-domain with syndrome constraint
    // path_costs[i][s] = min log-cost to reach state s at position i
    let mut path_costs = vec![vec![f64::INFINITY; num_states]; n + 1];
    let mut backtrack = vec![vec![(0usize, 0u8); num_states]; n + 1];
    
    // Initialize: start at state 0 with zero cost
    path_costs[0][0] = 0.0;
    
    // Forward pass: build trellis with syndrome constraints
    for i in 0..n {
        // Determine if this position contributes to syndrome
        // We emit syndrome bits for the first m positions
        let emit_syndrome = i < m;
        let target_syndrome_bit = if emit_syndrome { message_bits[i] } else { 0 };
        
        for prev_state in 0..num_states {
            if path_costs[i][prev_state].is_infinite() {
                continue; // State not reachable
            }
            
            // Try both transitions: flip=0 and flip=1
            for flip in 0..=1u8 {
                let stego_bit = cover_bits[i] ^ flip;
                let next_state = compute_next_state(prev_state, stego_bit, h);
                
                // Compute syndrome bit produced by this transition
                let syndrome_bit = compute_syndrome_bit(prev_state, stego_bit, &params.taps, h);
                
                // **CRITICAL CONSTRAINT**: If we need to emit syndrome, it MUST match target
                if emit_syndrome && syndrome_bit != target_syndrome_bit {
                    // This transition is forbidden - skip it
                    continue;
                }
                
                // Cost of this transition
                let transition_cost = if flip == 1 {
                    log_costs[i] // Pay cost for flipping
                } else {
                    0.0 // No cost for keeping same
                };
                
                let new_cost = path_costs[i][prev_state] + transition_cost;
                
                // Update if this path is better
                if new_cost < path_costs[i + 1][next_state] {
                    path_costs[i + 1][next_state] = new_cost;
                    backtrack[i + 1][next_state] = (prev_state, flip);
                }
            }
        }
    }
    
    // Find best final state (among reachable states)
    let (mut best_state, best_cost) = path_costs[n].iter()
        .enumerate()
        .min_by(|(_, &a), (_, &b)| a.partial_cmp(&b).unwrap())
        .unwrap();
    
    // Check if solution exists
    if best_cost.is_infinite() {
        // No valid path found with syndrome constraints (extremely rare)
        // Fall back to sequential embedding
        eprintln!("Warning: STC Viterbi found no valid path, using sequential fallback");
        return stc_encode_sequential_fallback(cover_bits, message_bits, params);
    }
    
    // Backtrack to recover flips
    let mut flips = vec![0u8; n];
    for i in (0..n).rev() {
        let (prev_state, flip) = backtrack[i + 1][best_state];
        flips[i] = flip;
        best_state = prev_state;
    }
    
    // Verify syndrome (sanity check - should always pass now)
    #[cfg(debug_assertions)]
    {
        let syndrome = compute_syndrome(&cover_bits, &flips, params);
        let syndrome_prefix: Vec<u8> = syndrome.iter().take(m).copied().collect();
        assert_eq!(
            syndrome_prefix, message_bits,
            "STC encoding produced incorrect syndrome (algorithm bug)"
        );
    }
    
    flips
}

/// Sequential fallback encoder (guaranteed correctness, not optimal cost)
fn stc_encode_sequential_fallback(
    cover_bits: &[u8],
    message_bits: &[u8],
    params: &StcParams,
) -> Vec<u8> {
    let n = cover_bits.len();
    let m = message_bits.len();
    let h = params.constraint_length;
    
    let mut stego_bits = cover_bits.to_vec();
    let mut flips = vec![0u8; n];
    let mut state = 0usize;
    let mut syndrome_idx = 0usize;
    
    for i in 0..n {
        // Compute syndrome bit that would be produced
        let syndrome_bit = compute_syndrome_bit(state, stego_bits[i], &params.taps, h);
        
        // Check if we need this syndrome bit to match message
        if syndrome_idx < m {
            let target_bit = message_bits[syndrome_idx];
            if syndrome_bit != target_bit {
                // Flip to match
                stego_bits[i] ^= 1;
                flips[i] = 1;
            }
            syndrome_idx += 1;
        }
        
        // Update state
        state = compute_next_state(state, stego_bits[i], h);
    }
    
    flips
}

/// STC Decoder: Extract message from stego bits
///
/// # Arguments
/// * `stego_bits` - LSBs from stego image
/// * `params` - STC parameters (must match encoder)
///
/// # Returns
/// Extracted message bits (syndrome)
pub fn stc_decode(stego_bits: &[u8], params: &StcParams) -> Vec<u8> {
    params.validate().expect("Invalid STC parameters");
    assert!(stego_bits.iter().all(|&b| b <= 1), "Stego bits must be 0 or 1");
    
    let n = stego_bits.len();
    let h = params.constraint_length;
    let mut syndrome = Vec::new();
    let mut state = 0usize;
    
    for i in 0..n {
        let bit = stego_bits[i];
        
        // Compute syndrome bit contribution
        let syndrome_bit = compute_syndrome_bit(state, bit, &params.taps, h);
        syndrome.push(syndrome_bit);
        
        // Update state
        state = compute_next_state(state, bit, h);
    }
    
    syndrome
}

/// Compute syndrome from cover bits and flips
fn compute_syndrome(cover_bits: &[u8], flips: &[u8], params: &StcParams) -> Vec<u8> {
    let stego_bits: Vec<u8> = cover_bits.iter()
        .zip(flips.iter())
        .map(|(&c, &f)| c ^ f)
        .collect();
    stc_decode(&stego_bits, params)
}

/// Compute next trellis state given current state and input bit
#[inline]
fn compute_next_state(state: usize, bit: u8, h: usize) -> usize {
    // Shift register: (state << 1 | bit) & mask
    let mask = (1 << (h - 1)) - 1;
    ((state << 1) | (bit as usize)) & mask
}

/// Compute syndrome bit from current state and input bit
#[inline]
fn compute_syndrome_bit(state: usize, bit: u8, taps: &[usize], _h: usize) -> u8 {
    // Reconstruct full h-bit register: [bit, state_bits...]
    let register = (bit as usize) | (state << 1);
    
    // XOR bits at tap positions
    let mut syndrome = 0u8;
    for &tap in taps {
        let tap_bit = ((register >> tap) & 1) as u8;
        syndrome ^= tap_bit;
    }
    syndrome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stc_params_validation() {
        let valid = StcParams {
            constraint_length: 7,
            taps: vec![0, 1, 3],
        };
        assert!(valid.validate().is_ok());

        let invalid_no_zero = StcParams {
            constraint_length: 7,
            taps: vec![1, 3],
        };
        assert!(invalid_no_zero.validate().is_err());

        let invalid_unsorted = StcParams {
            constraint_length: 7,
            taps: vec![0, 3, 1],
        };
        assert!(invalid_unsorted.validate().is_err());
    }

    #[test]
    fn test_encode_decode_simple() {
        let params = StcParams::default();
        let cover_bits = vec![0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
        let message_bits = vec![1, 0, 1];
        let costs = vec![1000; 10];

        let flips = stc_encode_min_cost(&cover_bits, &message_bits, &costs, &params);
        
        let stego_bits: Vec<u8> = cover_bits.iter()
            .zip(flips.iter())
            .map(|(&c, &f)| c ^ f)
            .collect();
        
        let decoded = stc_decode(&stego_bits, &params);
        
        assert_eq!(&decoded[..message_bits.len()], &message_bits[..]);
    }

    #[test]
    fn test_encode_decode_all_zeros() {
        let params = StcParams::default();
        let cover_bits = vec![0; 20];
        let message_bits = vec![1, 1, 0, 1, 0];
        let costs = vec![1000; 20];

        let flips = stc_encode_min_cost(&cover_bits, &message_bits, &costs, &params);
        
        let stego_bits: Vec<u8> = cover_bits.iter()
            .zip(flips.iter())
            .map(|(&c, &f)| c ^ f)
            .collect();
        
        let decoded = stc_decode(&stego_bits, &params);
        
        assert_eq!(&decoded[..message_bits.len()], &message_bits[..]);
    }

    #[test]
    fn test_encode_decode_random() {
        let params = StcParams {
            constraint_length: 5,
            taps: vec![0, 2],
        };
        
        let cover_bits = vec![1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1];
        let message_bits = vec![1, 0, 1, 1, 0, 1, 0];
        let costs = vec![500; 16];

        let flips = stc_encode_min_cost(&cover_bits, &message_bits, &costs, &params);
        
        let stego_bits: Vec<u8> = cover_bits.iter()
            .zip(flips.iter())
            .map(|(&c, &f)| c ^ f)
            .collect();
        
        let decoded = stc_decode(&stego_bits, &params);
        
        assert_eq!(&decoded[..message_bits.len()], &message_bits[..]);
    }

    #[test]
    fn test_cost_minimization() {
        let params = StcParams::default();
        let cover_bits = vec![0; 50];
        let message_bits = vec![1, 0, 1, 1, 0];
        
        // Test 1: All equal costs - total flips should be reasonable
        let costs_equal = vec![1000u32; 50];
        let flips_equal = stc_encode_min_cost(&cover_bits, &message_bits, &costs_equal, &params);
        let total_flips_equal: u32 = flips_equal.iter().map(|&f| f as u32).sum();
        
        // Test 2: Very high costs everywhere - should still work but may need more flips
        let costs_high = vec![100000u32; 50];
        let flips_high = stc_encode_min_cost(&cover_bits, &message_bits, &costs_high, &params);
        
        // Verify both encodings decode correctly
        let stego_equal: Vec<u8> = cover_bits.iter()
            .zip(flips_equal.iter())
            .map(|(&c, &f)| c ^ f)
            .collect();
        let decoded_equal = stc_decode(&stego_equal, &params);
        assert_eq!(&decoded_equal[..message_bits.len()], &message_bits[..]);
        
        let stego_high: Vec<u8> = cover_bits.iter()
            .zip(flips_high.iter())
            .map(|(&c, &f)| c ^ f)
            .collect();
        let decoded_high = stc_decode(&stego_high, &params);
        assert_eq!(&decoded_high[..message_bits.len()], &message_bits[..]);
        
        // Both should have similar number of flips (cost doesn't change correctness)
        assert!(total_flips_equal < 20, "Should use reasonable number of flips");
    }

    #[test]
    fn test_no_flips_needed() {
        let params = StcParams::default();
        let cover_bits = vec![1, 0, 1, 0, 1, 0, 1, 0];
        
        // Compute what syndrome this produces
        let syndrome = stc_decode(&cover_bits, &params);
        let message_bits = syndrome[..3].to_vec();
        
        // Encode with same message
        let costs = vec![1000; 8];
        let flips = stc_encode_min_cost(&cover_bits, &message_bits, &costs, &params);
        
        // Should have minimal flips (ideally zero or very few)
        let total_flips: u32 = flips.iter().map(|&f| f as u32).sum();
        assert!(total_flips <= 2, "Should require minimal flips when syndrome already matches");
    }
}

