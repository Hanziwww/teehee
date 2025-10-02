use base64::Engine;

fn main() {
    // Generate a random 32-byte build salt and export as an env var
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    use rand::RngCore;
    rng.fill_bytes(&mut bytes);

    // Base64 encode to embed into env at compile-time
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);

    println!("cargo:rustc-env=TEEHEE_BUILD_SALT_B64={}", b64);
} 