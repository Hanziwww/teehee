use clap::{Parser, Subcommand};
use image::ImageReader;
use std::fs;
use std::path::PathBuf;
use teehee::TeeheeStego;

/// Teehee~ - Advanced Fractal-Chaos Steganography Tool
/// 
/// A sophisticated steganography system combining chaos theory and fractal encoding
/// to hide secret messages within images with high security and undetectability.
#[derive(Parser)]
#[command(name = "teehee")]
#[command(version = "1.0.0")]
#[command(about = "Advanced Fractal-Chaos Steganography", long_about = None)]
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

        /// Optional user key (combined with build-time secret for dual-factor encryption)
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Extract hidden message from stego image (self-decrypting)
    Extract {
        /// Stego image with hidden data
        #[arg(short, long)]
        stego: PathBuf,

        /// Output file for extracted message (optional)
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,

        /// Optional user key (must match the key used during embedding)
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
    println!("╔══════════════════════════════════════════╗");
    println!("║   Teehee~ Steganography System v1.0.0    ║");
    println!("║   Fractal-Chaos Hybrid Encoder           ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
}

/// Validate that the output format is lossless (not JPEG)
fn validate_lossless_format(path: &PathBuf) -> anyhow::Result<()> {
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        match ext_lower.as_str() {
            "jpg" | "jpeg" => {
                return Err(anyhow::anyhow!(
                    "❌ JPEG is a lossy format and will destroy hidden data!\n\
                     Please use a lossless format instead:\n\
                     • PNG (recommended) - .png\n\
                     • BMP - .bmp\n\
                     • TIFF - .tif or .tiff\n\
                     \n\
                     Example: Change 'stego.jpg' to 'stego.png'"
                ));
            }
            "png" | "bmp" | "tif" | "tiff" => {
                // Lossless formats are OK
                Ok(())
            }
            _ => {
                // Warn about unknown formats
                eprintln!("⚠️  Warning: Unknown format '.{}' - steganography requires lossless formats", ext_lower);
                eprintln!("    Recommended: PNG, BMP, or TIFF");
                Ok(())
            }
        }
    } else {
        Err(anyhow::anyhow!("Output file must have an extension (e.g., .png)"))
    }
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
        } => {
            // Validate output format (must be lossless)
            validate_lossless_format(&output)?;
            
            // Load carrier image
            println!("[*] Loading carrier image: {}", input.display());
            let carrier = ImageReader::open(&input)?.decode()?;
            println!("[✓] Image loaded: {}x{}", carrier.width(), carrier.height());

            // Get message
            let message_bytes = if let Some(msg) = message {
                msg.into_bytes()
            } else if let Some(file_path) = file {
                println!("[*] Reading message from file: {}", file_path.display());
                fs::read(file_path)?
            } else {
                return Err(anyhow::anyhow!(
                    "Please provide either --message or --file"
                ));
            };

            println!(
                "[*] Message size: {} bytes ({} bits)",
                message_bytes.len(),
                message_bytes.len() * 8
            );

            // Create steganography engine with optional user key
            let stego_engine = if let Some(user_key) = key {
                println!("[*] Using dual-factor encryption (build secret + user key)");
                TeeheeStego::with_user_key(&user_key)
            } else {
                println!("[*] Using build-time secret only");
                TeeheeStego::new()
            };

            // Check capacity
            let capacity = TeeheeStego::calculate_capacity(&carrier);
            println!("[*] Estimated image capacity: {} bytes", capacity);

            if message_bytes.len() > capacity {
                return Err(anyhow::anyhow!(
                    "Message too large! Maximum: {} bytes, provided: {} bytes",
                    capacity,
                    message_bytes.len()
                ));
            }

            // Embed message
            println!("[*] Embedding message...");
            let stego_image = stego_engine.embed(&carrier, &message_bytes)?;

            // Save result
            println!("[*] Saving stego image to: {}", output.display());
            stego_image.save(&output)?;

            println!("[✓] Success! Message embedded.");
        }

        Commands::Extract { stego, output, key } => {
            // Load stego image
            println!("[*] Loading stego image: {}", stego.display());
            let stego_image = ImageReader::open(&stego)?.decode()?;
            println!("[✓] Image loaded: {}x{}", stego_image.width(), stego_image.height());

            // Create steganography engine with optional user key
            let stego_engine = if let Some(user_key) = key {
                println!("[*] Using dual-factor decryption (build secret + user key)");
                TeeheeStego::with_user_key(&user_key)
            } else {
                println!("[*] Using build-time secret only");
                TeeheeStego::new()
            };

            // Extract message
            println!("[*] Extracting hidden message...");
            let extracted = stego_engine.extract(&stego_image)?;
            println!("[✓] Extraction successful! {} bytes extracted", extracted.len());

            // Output result
            if let Some(out_path) = output {
                println!("[*] Saving extracted message to: {}", out_path.display());
                fs::write(out_path, &extracted)?;
                println!("[✓] Message saved to file");
            } else {
                // Try to display as text
                match String::from_utf8(extracted.clone()) {
                    Ok(text) => {
                        println!("\n╔═══════════════════════════════════════╗");
                        println!("║         Extracted Message:            ║");
                        println!("╚═══════════════════════════════════════╝");
                        println!("{}", text);
                    }
                    Err(_) => {
                        println!("[!] Message contains binary data ({} bytes)", extracted.len());
                        println!("[!] Use --output to save to file");
                    }
                }
            }

            println!("[✓] Extraction complete!");
        }

        Commands::Info { image } => {
            println!("[*] Analyzing image: {}", image.display());
            let img = ImageReader::open(&image)?.decode()?;

            let capacity = TeeheeStego::calculate_capacity(&img);

            println!("\n╔═══════════════════════════════════════╗");
            println!("║         Image Information:            ║");
            println!("╠═══════════════════════════════════════╣");
            println!("║ Dimensions: {}x{}", img.width(), img.height());
            println!("║ Estimated Capacity:   {} bytes", capacity);
            println!("║ Estimated Capacity:   {} KB", capacity / 1024);
            println!("╚═══════════════════════════════════════╝");
        }
    }

    Ok(())
}
