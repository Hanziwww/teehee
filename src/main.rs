use clap::{Parser, Subcommand};
use image::{DynamicImage, ImageReader};
use std::fs;
use std::path::{Path, PathBuf};
use teehee::TeeheeStego;

/// Teehee~ - Advanced Steganography Tool
#[derive(Parser)]
#[command(name = "teehee")]
#[command(version = "1.0.0")]
#[command(about = "Advanced Steganography Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed a secret message into an image
    Embed {
        /// Input carrier image path
        #[arg(short, long)]
        input: PathBuf,

        /// Output stego image path
        #[arg(short, long)]
        output: PathBuf,

        /// Secret message (text)
        #[arg(short, long, conflicts_with = "file")]
        message: Option<String>,

        /// Secret message file path
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional user key for encryption
        #[arg(short, long)]
        key: Option<String>,

        /// Calculate quality metrics (PSNR, SSIM, KL divergence)
        #[arg(short = 'q', long)]
        quality: bool,
    },
    /// Extract hidden message from stego image
    Extract {
        /// Stego image with hidden data
        #[arg(short, long)]
        stego: PathBuf,

        /// Output file for extracted message (optional)
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,

        /// Optional user key (must match embedding key)
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Show image capacity information
    Info {
        /// Image file path
        #[arg(short, long)]
        image: PathBuf,
    },
}

fn print_banner() {
    println!("╔════════════════════════════════════════════════╗");
    println!("║   Teehee~ Steganography v0.1                   ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
}

/// Validate that the output format is lossless
fn validate_lossless_format(path: &Path) -> anyhow::Result<()> {
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        match ext_lower.as_str() {
            "jpg" | "jpeg" => Err(anyhow::anyhow!(
                "❌ JPEG is lossy and will destroy hidden data!\n\
                     Please use a lossless format:\n\
                     • PNG (recommended) - .png\n\
                     • BMP - .bmp\n\
                     • TIFF - .tif/.tiff"
            )),
            "png" | "bmp" | "tif" | "tiff" => Ok(()),
            _ => {
                eprintln!(
                    "⚠️  Warning: Unknown format '.{}' - use lossless formats",
                    ext_lower
                );
                Ok(())
            }
        }
    } else {
        Err(anyhow::anyhow!(
            "Output file must have an extension (e.g., .png)"
        ))
    }
}

/// Calculate PSNR (Peak Signal-to-Noise Ratio) between two images
fn calculate_psnr(original: &DynamicImage, modified: &DynamicImage) -> f64 {
    let orig_rgb = original.to_rgb8();
    let mod_rgb = modified.to_rgb8();

    let mut mse = 0.0;
    let mut count = 0;

    for (p1, p2) in orig_rgb.pixels().zip(mod_rgb.pixels()) {
        for i in 0..3 {
            let diff = p1[i] as f64 - p2[i] as f64;
            mse += diff * diff;
            count += 1;
        }
    }

    mse /= count as f64;

    if mse == 0.0 {
        f64::INFINITY
    } else {
        20.0 * (255.0_f64).log10() - 10.0 * mse.log10()
    }
}

/// Calculate SSIM (Structural Similarity Index) between two images
fn calculate_ssim(original: &DynamicImage, modified: &DynamicImage) -> f64 {
    let orig_rgb = original.to_rgb8();
    let mod_rgb = modified.to_rgb8();

    const C1: f64 = 6.5025; // (0.01 * 255)^2
    const C2: f64 = 58.5225; // (0.03 * 255)^2

    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xx = 0.0;
    let mut sum_yy = 0.0;
    let mut sum_xy = 0.0;
    let mut count = 0;

    for (p1, p2) in orig_rgb.pixels().zip(mod_rgb.pixels()) {
        for i in 0..3 {
            let x = p1[i] as f64;
            let y = p2[i] as f64;
            sum_x += x;
            sum_y += y;
            sum_xx += x * x;
            sum_yy += y * y;
            sum_xy += x * y;
            count += 1;
        }
    }

    let n = count as f64;
    let mean_x = sum_x / n;
    let mean_y = sum_y / n;
    let var_x = sum_xx / n - mean_x * mean_x;
    let var_y = sum_yy / n - mean_y * mean_y;
    let cov_xy = sum_xy / n - mean_x * mean_y;

    let numerator = (2.0 * mean_x * mean_y + C1) * (2.0 * cov_xy + C2);
    let denominator = (mean_x * mean_x + mean_y * mean_y + C1) * (var_x + var_y + C2);

    numerator / denominator
}

/// Calculate KL divergence between pixel distributions
fn calculate_kl_divergence(original: &DynamicImage, modified: &DynamicImage) -> f64 {
    let orig_rgb = original.to_rgb8();
    let mod_rgb = modified.to_rgb8();

    // Build histograms
    let mut hist_orig = vec![0u32; 256];
    let mut hist_mod = vec![0u32; 256];

    for pixel in orig_rgb.pixels() {
        for &val in pixel.0.iter() {
            hist_orig[val as usize] += 1;
        }
    }

    for pixel in mod_rgb.pixels() {
        for &val in pixel.0.iter() {
            hist_mod[val as usize] += 1;
        }
    }

    let total = hist_orig.iter().sum::<u32>() as f64;

    // Normalize to probabilities with smoothing
    let epsilon = 1e-10;
    let mut kl_div = 0.0;

    for i in 0..256 {
        let p = (hist_orig[i] as f64 / total) + epsilon;
        let q = (hist_mod[i] as f64 / total) + epsilon;
        kl_div += p * (p / q).ln();
    }

    kl_div
}

/// Calculate Mean Absolute Error
fn calculate_mae(original: &DynamicImage, modified: &DynamicImage) -> f64 {
    let orig_rgb = original.to_rgb8();
    let mod_rgb = modified.to_rgb8();

    let mut sum = 0.0;
    let mut count = 0;

    for (p1, p2) in orig_rgb.pixels().zip(mod_rgb.pixels()) {
        for i in 0..3 {
            sum += (p1[i] as f64 - p2[i] as f64).abs();
            count += 1;
        }
    }

    sum / count as f64
}

fn main() -> anyhow::Result<()> {
    print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Embed {
            input,
            output,
            message,
            file,
            key,
            quality,
        } => {
            validate_lossless_format(&output)?;

            // Load carrier image
            println!("┌─ Image Analysis ───────────────────────────────┐");
            println!("│ Loading: {}", input.display());
            let carrier = ImageReader::open(&input)?.decode()?;
            let w = carrier.width();
            let h = carrier.height();
            println!("│ ✓ Dimensions: {}x{} ({} pixels)", w, h, w * h);

            let capacity = TeeheeStego::calculate_capacity(&carrier);
            println!(
                "│ ✓ Capacity: {} bytes ({:.2} KB)",
                capacity,
                capacity as f64 / 1024.0
            );
            println!("└────────────────────────────────────────────────┘");
            println!();

            // Get message
            let message_bytes = if let Some(msg) = message {
                msg.into_bytes()
            } else if let Some(file_path) = file {
                println!("[*] Reading message from file: {}", file_path.display());
                fs::read(file_path)?
            } else {
                return Err(anyhow::anyhow!("Provide --message or --file parameter"));
            };

            println!("┌─ Message Info ─────────────────────────────────┐");
            println!(
                "│ Size: {} bytes ({} bits)",
                message_bytes.len(),
                message_bytes.len() * 8
            );

            if message_bytes.len() > capacity {
                println!("└────────────────────────────────────────────────┘");
                return Err(anyhow::anyhow!(
                    "❌ Message too large! Max capacity: {} bytes, Provided: {} bytes",
                    capacity,
                    message_bytes.len()
                ));
            }

            let usage_percent = (message_bytes.len() as f64 / capacity as f64) * 100.0;
            println!(
                "│ Capacity usage: {:.1}% ({}/{})",
                usage_percent,
                message_bytes.len(),
                capacity
            );
            println!("└────────────────────────────────────────────────┘");
            println!();

            // Create steganography engine
            // Allow passing user key via environment variable to avoid argv exposure
            let effective_key = key.or_else(|| std::env::var("TEEHEE_USER_KEY").ok());
            let stego_engine = if let Some(user_key) = effective_key {
                println!("🔐 Encryption: Enabled (with user key)");
                TeeheeStego::with_user_key(&user_key)
            } else {
                println!("🔐 Encryption: Enabled (build-time key)");
                TeeheeStego::new()
            };
            println!();

            // Embed message
            println!("┌─ Embedding ────────────────────────────────────┐");
            println!("│ [1/2] Encrypting message...");
            println!("│ [2/2] Embedding into image...");

            let start_time = std::time::Instant::now();
            let stego_image = stego_engine.embed(&carrier, &message_bytes)?;
            let elapsed = start_time.elapsed();

            println!("│ ✓ Complete ({:.2}s)", elapsed.as_secs_f64());
            println!("└────────────────────────────────────────────────┘");
            println!();

            // Save result
            println!("💾 Saving stego image: {}", output.display());
            stego_image.save(&output)?;

            // Calculate quality metrics if requested
            if quality {
                println!();
                println!("┌─ Quality Metrics ──────────────────────────────┐");

                let psnr = calculate_psnr(&carrier, &stego_image);
                let ssim = calculate_ssim(&carrier, &stego_image);
                let kl_div = calculate_kl_divergence(&carrier, &stego_image);
                let mae = calculate_mae(&carrier, &stego_image);

                println!("│ PSNR: {:.2} dB", psnr);
                println!("│ SSIM: {:.6}", ssim);
                println!("│ KL Divergence: {:.8}", kl_div);
                println!("│ MAE: {:.4}", mae);
                println!("└────────────────────────────────────────────────┘");

                // Interpretation
                println!();
                println!("Quality Assessment:");
                if psnr > 40.0 {
                    println!("  ✓ Excellent visual quality (PSNR > 40 dB)");
                } else if psnr > 30.0 {
                    println!("  ✓ Good visual quality (PSNR > 30 dB)");
                } else {
                    println!("  ⚠ Noticeable distortion (PSNR < 30 dB)");
                }

                if ssim > 0.99 {
                    println!("  ✓ Nearly identical structure (SSIM > 0.99)");
                } else if ssim > 0.95 {
                    println!("  ✓ Very similar structure (SSIM > 0.95)");
                } else {
                    println!("  ⚠ Structural differences detected");
                }

                if kl_div < 0.001 {
                    println!("  ✓ Excellent distribution match (KL < 0.001)");
                } else if kl_div < 0.01 {
                    println!("  ✓ Good distribution match (KL < 0.01)");
                } else {
                    println!("  ⚠ Statistical differences detected");
                }
            }

            println!();
            println!("╔════════════════════════════════════════════════╗");
            println!("║  ✓ Embedding successful!                       ║");
            println!("╚════════════════════════════════════════════════╝");
        }

        Commands::Extract { stego, output, key } => {
            // Load stego image
            println!("┌─ Loading Stego Image ──────────────────────────┐");
            println!("│ File: {}", stego.display());
            let stego_image = ImageReader::open(&stego)?.decode()?;
            let w = stego_image.width();
            let h = stego_image.height();
            println!("│ ✓ Dimensions: {}x{}", w, h);
            println!("└────────────────────────────────────────────────┘");
            println!();

            // Create steganography engine
            let effective_key = key.or_else(|| std::env::var("TEEHEE_USER_KEY").ok());
            let stego_engine = if let Some(user_key) = effective_key {
                println!("🔓 Decryption: Using user key");
                TeeheeStego::with_user_key(&user_key)
            } else {
                println!("🔓 Decryption: Using build-time key");
                TeeheeStego::new()
            };
            println!();

            // Extract message
            println!("┌─ Extracting ───────────────────────────────────┐");
            println!("│ [1/2] Extracting encrypted data...");
            println!("│ [2/2] Decrypting message...");

            let start_time = std::time::Instant::now();
            let extracted = stego_engine.extract(&stego_image)?;
            let elapsed = start_time.elapsed();

            println!("│ ✓ Complete ({:.2}s)", elapsed.as_secs_f64());
            println!("└────────────────────────────────────────────────┘");
            println!();

            // Output result
            if let Some(out_path) = output {
                println!("💾 Saving extracted message: {}", out_path.display());
                fs::write(out_path, &extracted)?;
                println!("✓ Saved to file");
            } else {
                match String::from_utf8(extracted.clone()) {
                    Ok(text) => {
                        println!("╔════════════════════════════════════════════════╗");
                        println!(
                            "║  Extracted Message ({} bytes):                ",
                            extracted.len()
                        );
                        println!("╚════════════════════════════════════════════════╝");
                        println!();
                        println!("{}", text);
                        println!();
                    }
                    Err(_) => {
                        println!("⚠️  Binary data detected ({} bytes)", extracted.len());
                        println!("💡 Use --output to save to file");
                    }
                }
            }

            println!("╔════════════════════════════════════════════════╗");
            println!("║  ✓ Extraction successful!                      ║");
            println!("╚════════════════════════════════════════════════╝");
        }

        Commands::Info { image } => {
            println!("┌─ Image Analysis ───────────────────────────────┐");
            println!("│ Analyzing: {}", image.display());
            let img = ImageReader::open(&image)?.decode()?;
            let w = img.width();
            let h = img.height();
            let total_pixels = w * h;

            println!("│ ✓ Image loaded");
            println!("└────────────────────────────────────────────────┘");
            println!();

            let start_time = std::time::Instant::now();
            let capacity = TeeheeStego::calculate_capacity(&img);
            let analysis_time = start_time.elapsed();

            let capacity_kb = capacity as f64 / 1024.0;
            let capacity_bits = capacity * 8;
            let bits_per_pixel = capacity_bits as f64 / total_pixels as f64;

            println!("╔════════════════════════════════════════════════╗");
            println!("║  Steganography Capacity Analysis               ║");
            println!("╠════════════════════════════════════════════════╣");
            println!("║  Image Information:                            ║");
            println!(
                "║    Dimensions: {}x{} ({} pixels)       ",
                w, h, total_pixels
            );
            println!("║    Format: {:?}                          ", img.color());
            println!("║                                                ║");
            println!("║  Embedding Capacity:                           ║");
            println!(
                "║    Available: {} bytes ({:.2} KB)     ",
                capacity, capacity_kb
            );
            println!(
                "║    Bit capacity: {} bits                  ",
                capacity_bits
            );
            println!(
                "║    Average BPP: {:.4} bits/pixel         ",
                bits_per_pixel
            );
            println!("║                                                ║");
            println!(
                "║  Performance: {:.2}s analysis time             ║",
                analysis_time.as_secs_f64()
            );
            println!("╚════════════════════════════════════════════════╝");
            println!();
            println!("💡 Note:");
            println!("   • Actual capacity = {} - 21 bytes (overhead)", capacity);
            println!("   • Output must use lossless format (PNG/BMP/TIFF)");
        }
    }

    Ok(())
}
