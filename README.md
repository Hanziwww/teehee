![Before and After Steganography](readme.png)
*Original image vs. steganography-embedded image — yet one contains hidden encrypted data\**

# Teehee~

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange?logo=rust)](https://www.rust-lang.org/)
![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20macos-lightgrey)
[![Status](https://img.shields.io/badge/status-experimental-yellow)](https://github.com)

> This project serves as a practical exploration of Rust's cryptographic ecosystem and systems programming capabilities.

## ✨ Features

- 🔐 **Build-Time Salt Encryption**: Each compiled binary embeds a unique cryptographic salt generated at build time, making every binary cryptographically distinct
- 🎨 **Fractal-Guided Embedding**: Uses fractal dimension analysis to intelligently select high-texture regions for data hiding, minimizing visual artifacts
- 🔑 **Dual-Layer Security**: Combines build-time salt with optional user passwords for multi-factor protection
- 📊 **STC Optimization**: Syndrome-Trellis Codes (STC) minimize embedding distortion while maximizing payload capacity
- 🛡️ **Authenticated Encryption**: AES-256-GCM ensures data integrity and prevents tampering
- 🎯 **Invisible Modifications**: Adaptive ±1 LSB matching preserves statistical properties of the carrier image

## 🚀 Quick Start

### Installation

```bash
cargo build --release
```

The executable will be located at `target/release/teehee` (or `teehee.exe` on Windows).

## 📖 Usage

### 1. Embed a Message

**Embed text message:**
```bash
teehee embed -i cover.png -o stego.png -m "This is a secret message"
```

**Embed from file:**
```bash
teehee embed -i cover.png -o stego.png -f secret.txt
```

**With custom password:**
```bash
teehee embed -i cover.png -o stego.png -m "Secret" -k "my-password"
```

**With quality metrics:**
```bash
teehee embed -i cover.png -o stego.png -m "Secret" -q
```

### 2. Extract a Message

**Extract and display:**
```bash
teehee extract -s stego.png
```

**Extract to file:**
```bash
teehee extract -s stego.png -O output.txt
```

**With custom password:**
```bash
teehee extract -s stego.png -k "my-password"
```

### 3. Check Image Capacity

```bash
teehee info -i photo.png
```

This shows how many bytes of data can be hidden in the image.

## 🔧 Using as a Library

```rust
use teehee::TeeheeStego;
use image::io::Reader;

fn main() -> anyhow::Result<()> {
    // Load carrier image
    let carrier = Reader::open("cover.png")?.decode()?;
    
    // Create steganography engine
    let stego = TeeheeStego::new();
    
    // Embed message
    let message = b"This is a secret message";
    let stego_image = stego.embed(&carrier, message)?;
    stego_image.save("stego.png")?;
    
    // Extract message
    let extracted = stego.extract(&stego_image)?;
    assert_eq!(message.as_slice(), extracted.as_slice());
    
    Ok(())
}
```

## 🧪 Development

### Git Hooks 安装

为确保代码质量，项目提供了与 GitHub CI 对齐的 pre-commit hook。在提交前会自动运行：

1. 代码格式检查（`cargo fmt --check`）
2. Clippy 代码检查（`cargo clippy -- -D warnings`）
3. 运行测试（`cargo test`）

**安装方法**：
```bash
git config core.hooksPath .githooks
```

详见 [`.githooks/README.md`](.githooks/README.md)

### 手动运行检查

```bash
# 格式化代码
cargo fmt --all

# Clippy 检查
cargo clippy --all-targets --all-features -- -D warnings

# 运行测试
cargo test
```

## ⚠️ Disclaimer

This tool is intended for legitimate and legal uses only. Users are responsible for their own actions.


\* The sample image used in the demonstration (`readme.png`) is artwork by [チャイ](https://www.pixiv.net/users/1096811) on pixiv. The hidden message extracted from the steganography example is the artwork URL: https://www.pixiv.net/artworks/131246732. All rights to the original artwork belong to the author.

