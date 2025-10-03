//! # Teehee~ Steganography Library
//!
//! A sophisticated steganography system combining chaos theory and fractal encoding
//! for secure message hiding within images.
//!
//! ## Quick Start
//!
//! ```no_run
//! use teehee::TeeheeStego;
//! use image::io::Reader;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Load carrier image
//! let carrier = Reader::open("cover.png")?.decode()?;
//!
//! // Create steganography engine
//! let stego = TeeheeStego::new();
//!
//! // Embed secret message
//! let message = b"This is a secret message";
//! let stego_image = stego.embed(&carrier, message)?;
//!
//! // Save the result
//! stego_image.save("stego.png")?;
//!
//! // Extract message (self-decrypting)
//! let extracted = stego.extract(&stego_image)?;
//! assert_eq!(message.as_slice(), extracted.as_slice());
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - **CSPRNG-based position/permutation**: Build-salt keyed ChaCha20 random sequences
//! - **Texture-aware embedding**: Uses fractal analysis to target textured regions
//! - **AES-256-GCM**: Authenticated encryption of payload
//! - **Self-contained**: Single image is sufficient for extraction
//!
//! ## Modules
//!
//! - `fractal`: Fractal analysis and block selection
//! - `steganography`: Main steganography engine

pub mod fractal;
pub mod steganography;
pub mod stc;

// Re-export main types for convenience
pub use fractal::{AffineTransform, FractalBlock, FractalCoder};
pub use steganography::TeeheeStego;
pub use stc::{StcParams, stc_encode_min_cost, stc_decode};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a TeeheeStego instance with optional user key (for dual-factor encryption)
///
/// # Examples
///
/// ```no_run
/// use teehee::TeeheeStego;
/// 
/// // Single-factor: build-time secret only
/// let stego1 = TeeheeStego::new();
///
/// // Dual-factor: build-time secret + user password
/// let stego2 = TeeheeStego::with_user_key("my-secret-password");
/// ```
pub fn with_user_key(user_key: &str) -> TeeheeStego {
    TeeheeStego::with_user_key(user_key)
}

/// Calculate maximum capacity for a given image
///
/// # Examples
///
/// ```no_run
/// use image::io::Reader;
/// # fn main() -> anyhow::Result<()> {
/// let img = Reader::open("photo.png")?.decode()?;
/// let capacity = teehee::calculate_capacity(&img);
/// println!("Image can hold {} bytes", capacity);
/// # Ok(())
/// # }
/// ```
pub fn calculate_capacity(image: &image::DynamicImage) -> usize {
    TeeheeStego::calculate_capacity(image)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use image::{DynamicImage, RgbImage};

    fn create_test_image() -> DynamicImage {
        // Create a 256x256 test image with gradient
        let mut img = RgbImage::new(256, 256);
        for y in 0..256 {
            for x in 0..256 {
                img.put_pixel(x, y, image::Rgb([x as u8, y as u8, 128]));
            }
        }
        DynamicImage::ImageRgb8(img)
    }

    #[test]
    fn test_full_embed_extract_cycle() {
        let carrier = create_test_image();
        let message = b"Hello, this is a secret message for testing!";

        let stego = TeeheeStego::new();

        // Embed
        let stego_image = stego.embed(&carrier, message).unwrap();

        // Extract
        let extracted = stego.extract(&stego_image).unwrap();

        assert_eq!(message.as_slice(), extracted.as_slice());
    }

    #[test]
    fn test_capacity_calculation() {
        let img = create_test_image();
        let capacity = calculate_capacity(&img);
        assert!(capacity > 20); // Depends on texture selection
    }
} 