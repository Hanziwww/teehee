/// Chaos-based cryptographic module using Logistic Map
/// Provides pseudo-random sequence generation with high sensitivity to initial conditions

use sha2::{Digest, Sha256};

/// Logistic Map chaos generator
/// x(n+1) = r * x(n) * (1 - x(n))
/// where r ∈ [3.57, 4.0] for chaotic behavior
pub struct LogisticMap {
    state: f64,
    r: f64,
    iteration: usize,
}

impl LogisticMap {
    /// Create a new LogisticMap with password-derived initial conditions
    /// 
    /// # Arguments
    /// * `password` - Password string for key derivation
    /// 
    /// # Returns
    /// A new LogisticMap instance with cryptographically derived parameters
    pub fn new(password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        
        // Extract initial state and parameter from hash
        // x0 ∈ (0, 1), r ∈ [3.8, 4.0] for strong chaos
        let x0_bytes = u64::from_be_bytes(hash[0..8].try_into().unwrap());
        let r_bytes = u64::from_be_bytes(hash[8..16].try_into().unwrap());
        
        let x0 = (x0_bytes as f64 / u64::MAX as f64) * 0.9 + 0.05; // [0.05, 0.95]
        let r = (r_bytes as f64 / u64::MAX as f64) * 0.2 + 3.8;   // [3.8, 4.0]
        
        // Skip transient period (first 1000 iterations)
        let mut state = x0;
        for _ in 0..1000 {
            state = r * state * (1.0 - state);
        }
        
        Self {
            state,
            r,
            iteration: 0,
        }
    }
    
    /// Generate next chaotic value
    /// Returns value in range [0.0, 1.0]
    pub fn next(&mut self) -> f64 {
        self.state = self.r * self.state * (1.0 - self.state);
        self.iteration += 1;
        self.state
    }
    
    /// Generate a random integer in range [0, max)
    pub fn next_int(&mut self, max: usize) -> usize {
        let value = self.next();
        (value * max as f64) as usize % max
    }
    
    /// Generate a sequence of random positions for embedding
    /// Returns indices without duplicates
    pub fn generate_positions(&mut self, count: usize, max: usize) -> Vec<usize> {
        let mut positions = Vec::with_capacity(count);
        let mut used = vec![false; max];
        
        let mut attempts = 0;
        while positions.len() < count && attempts < count * 10 {
            let pos = self.next_int(max);
            if !used[pos] {
                used[pos] = true;
                positions.push(pos);
            }
            attempts += 1;
        }
        
        positions
    }
    
    /// Generate a permutation sequence for scrambling
    pub fn generate_permutation(&mut self, length: usize) -> Vec<usize> {
        let mut perm: Vec<usize> = (0..length).collect();
        
        // Fisher-Yates shuffle with chaotic randomness
        for i in (1..length).rev() {
            let j = self.next_int(i + 1);
            perm.swap(i, j);
        }
        
        perm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_logistic_map_range() {
        let mut map = LogisticMap::new("test_password");
        for _ in 0..1000 {
            let val = map.next();
            assert!(val >= 0.0 && val <= 1.0);
        }
    }
    
    #[test]
    fn test_password_sensitivity() {
        let mut map1 = LogisticMap::new("password1");
        let mut map2 = LogisticMap::new("password2");
        
        let val1 = map1.next();
        let val2 = map2.next();
        
        assert!((val1 - val2).abs() > 0.001);
    }
    
    #[test]
    fn test_position_generation() {
        let mut map = LogisticMap::new("test");
        let positions = map.generate_positions(100, 1000);
        
        assert_eq!(positions.len(), 100);
        
        // Check uniqueness
        let mut sorted = positions.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), positions.len());
    }
} 