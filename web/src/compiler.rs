use crate::error::{AppError, Result};
use crate::models::CompilationSession;
use std::path::Path;
use std::process::Command;
use tokio::fs;
use tracing::{debug, error, info};

/// Dynamically compile Teehee binary
///
/// Process:
/// 1. Create isolated workspace directory
/// 2. Copy project template to workspace
/// 3. Modify build.rs to inject new build secret
/// 4. Execute cargo build --release
/// 5. Extract build artifacts
pub async fn compile_with_secret(
    session: &mut CompilationSession,
    workspaces_dir: &Path,
) -> Result<()> {
    let workspace_path = workspaces_dir.join(&session.compile_id);
    debug!("Creating compilation workspace: {:?}", workspace_path);

    // Create workspace directory
    fs::create_dir_all(&workspace_path).await?;

    // Copy project template
    copy_template_to_workspace(&workspace_path).await?;

    // Inject build secret
    inject_build_secret(&workspace_path, &session.build_secret).await?;

    // Execute compilation
    info!("Starting compilation {}...", session.compile_id);
    let binary_path = execute_cargo_build(&workspace_path).await?;

    // Update session info
    session.binary_path = binary_path;
    session.workspace_path = workspace_path.to_string_lossy().to_string();
    // Zeroize build_secret after compilation to reduce memory exposure
    session.build_secret.clear();

    info!("Compilation complete: {}", session.compile_id);
    Ok(())
}

/// Copy project template to workspace
async fn copy_template_to_workspace(workspace: &Path) -> Result<()> {
    // Copy src directory
    let src_dir = Path::new("../src");
    let dest_src = workspace.join("src");
    copy_dir_recursive(src_dir, &dest_src)?;

    // Copy Cargo.toml
    fs::copy("../Cargo.toml", workspace.join("Cargo.toml")).await?;

    // Copy build.rs
    fs::copy("../build.rs", workspace.join("build.rs")).await?;

    // Copy rustfmt.toml (if exists)
    if Path::new("../rustfmt.toml").exists() {
        fs::copy("../rustfmt.toml", workspace.join("rustfmt.toml")).await?;
    }

    Ok(())
}

/// Recursively copy directory
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    use std::fs;

    fs::create_dir_all(dest)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            fs::copy(&src_path, &dest_path)?;
        }
    }

    Ok(())
}

/// Inject build secret into build.rs
async fn inject_build_secret(workspace: &Path, secret: &[u8]) -> Result<()> {
    let build_rs_path = workspace.join("build.rs");
    let mut build_rs_content = fs::read_to_string(&build_rs_path).await?;

    // Find and replace SECRET constant
    // Assumes build.rs has a placeholder like:
    // const SECRET: [u8; 32] = [0u8; 32]; // PLACEHOLDER

    let secret_str = format!(
        "[{}]",
        secret
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Replacement strategy: if PLACEHOLDER marker exists, replace that line
    if build_rs_content.contains("// PLACEHOLDER") {
        let lines: Vec<&str> = build_rs_content.lines().collect();
        let mut new_lines = Vec::new();

        for line in lines {
            if line.contains("// PLACEHOLDER") {
                new_lines.push(format!(
                    "const SECRET: [u8; 32] = {}; // INJECTED",
                    secret_str
                ));
            } else {
                new_lines.push(line.to_string());
            }
        }

        build_rs_content = new_lines.join("\n");
    } else {
        // If no PLACEHOLDER, add at beginning of file
        let injection = format!("const SECRET: [u8; 32] = {};\n\n", secret_str);
        build_rs_content = injection + &build_rs_content;
    }

    fs::write(&build_rs_path, build_rs_content).await?;

    Ok(())
}

/// Execute cargo build
async fn execute_cargo_build(workspace: &Path) -> Result<String> {
    debug!("Executing cargo build in {:?}", workspace);

    let output = Command::new("cargo")
        .args(["build", "--release", "--bin", "teehee"])
        .current_dir(workspace)
        .output()
        .map_err(|e| AppError::Compilation(format!("Failed to execute cargo: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(target: "teehee_web::compile", "Compilation failed: {}", stderr);
        return Err(AppError::Compilation("Compilation failed".to_string()));
    }

    // Determine binary path
    #[cfg(target_os = "windows")]
    let binary_name = "teehee.exe";
    #[cfg(not(target_os = "windows"))]
    let binary_name = "teehee";

    let binary_path = workspace.join("target").join("release").join(binary_name);

    if !binary_path.exists() {
        return Err(AppError::Compilation(
            "Compilation succeeded but binary not found".to_string(),
        ));
    }

    Ok(binary_path.to_string_lossy().to_string())
}

/// Execute encryption operation
pub async fn run_encrypt(
    binary_path: &str,
    input_image: &Path,
    output_image: &Path,
    message: &str,
    user_key: Option<&str>,
) -> Result<()> {
    debug!(
        "Executing encryption: {} -> {}",
        input_image.display(),
        output_image.display()
    );

    // Write message to a temporary file next to output (avoid passing plaintext via argv)
    let msg_path = output_image.with_extension("msg");
    std::fs::write(&msg_path, message.as_bytes())
        .map_err(|e| AppError::Compilation(format!("Failed to write temp message file: {}", e)))?;

    let mut cmd = Command::new(binary_path);
    cmd.args([
        "embed",
        "--input",
        input_image.to_str().unwrap(),
        "--output",
        output_image.to_str().unwrap(),
        "--file",
        msg_path.to_str().unwrap(),
    ]);

    // Pass user key via environment to avoid argv exposure; CLI will read TEEHEE_USER_KEY if --key absent
    if let Some(key) = user_key {
        cmd.env("TEEHEE_USER_KEY", key);
    }

    let output = cmd
        .output()
        .map_err(|e| AppError::Compilation(format!("Failed to execute encryption: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(target: "teehee_web::encrypt", "Encryption failed: {}", stderr);
        return Err(AppError::Compilation("Encryption failed".to_string()));
    }

    // Best-effort cleanup of temp message file
    let _ = std::fs::remove_file(&msg_path);
    Ok(())
}

/// Execute decryption operation
pub async fn run_decrypt(
    binary_path: &str,
    stego_image: &Path,
    user_key: Option<&str>,
) -> Result<Vec<u8>> {
    debug!("Executing decryption: {}", stego_image.display());

    let mut cmd = Command::new(binary_path);
    cmd.args(["extract", "--stego", stego_image.to_str().unwrap()]);

    // Pass user key via environment instead of argv
    if let Some(key) = user_key {
        cmd.env("TEEHEE_USER_KEY", key);
    }

    let output = cmd
        .output()
        .map_err(|e| AppError::Compilation(format!("Failed to execute decryption: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(target: "teehee_web::decrypt", "Decryption failed: {}", stderr);
        return Err(AppError::Compilation("Decryption failed".to_string()));
    }

    // Extract message from stdout (requires CLI to support stdout output)
    // Or use --output parameter to write to file then read
    Ok(output.stdout)
}
