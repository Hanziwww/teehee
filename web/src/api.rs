use crate::compiler::{compile_with_secret, run_decrypt, run_encrypt};
use crate::error::{AppError, Result};
use crate::image_match::{calculate_perceptual_hash, find_best_match, hash_to_bytes};
use crate::models::*;
use crate::state::AppState;
use askama::Template;
use askama_axum::IntoResponse as AskamaIntoResponse;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::{
    extract::{Multipart, Path, State},
    response::{AppendHeaders, IntoResponse},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use image::GenericImageView;
use rand::RngCore;
use std::sync::Arc;
use tracing::{debug, info};
const MIN_TTL: i64 = 60; // 1 minute
const MAX_TTL: i64 = 3600; // 1 hour
const MAX_DIMENSION: u32 = 10000; // max width/height
const MAX_PIXELS: u64 = 20_000_000; // ~20MP cap

/// Index page (rendered via Askama)
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate<'a> {
    pub csrf_token: &'a str,
    pub csp_nonce: &'a str,
}

fn generate_b64_token(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn serve_index(_jar: CookieJar) -> impl IntoResponse {
    // Generate CSRF token and CSP nonce
    let csrf_token = generate_b64_token(32);
    let csp_nonce = generate_b64_token(18);

    let tpl = IndexTemplate {
        csrf_token: &csrf_token,
        csp_nonce: &csp_nonce,
    };
    let mut response = tpl.into_response();

    // Set CSRF cookie (double-submit). HttpOnly + SameSite=Lax.
    let cookie = Cookie::build(("csrf_token", csrf_token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    let set_cookie = HeaderValue::from_str(&cookie.to_string()).unwrap();
    response
        .headers_mut()
        .append(HeaderName::from_static("set-cookie"), set_cookie);

    // Set per-response CSP with nonce
    let csp_value = format!(
        "default-src 'self'; script-src 'self' 'nonce-{}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        csp_nonce
    );
    response.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&csp_value).unwrap(),
    );

    response
}

fn validate_csrf(headers: &HeaderMap, jar: &CookieJar) -> Result<()> {
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cookie_token = jar.get("csrf_token").map(|c| c.value().to_string());
    match (header_token, cookie_token) {
        (Some(h), Some(c)) if h == c => Ok(()),
        _ => Err(AppError::InvalidInput("Invalid CSRF token".to_string())),
    }
}

/// Static files
pub async fn serve_static(Path(path): Path<String>) -> impl IntoResponse {
    // Placeholder until static serving is implemented via tower_http::services::ServeDir
    format!("Static file: {}", path)
}

/// Download file
pub async fn serve_download(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse> {
    // 1) 仅允许简单文件名（禁止路径分隔/.. 等）
    let requested = std::path::Path::new(&filename);
    if requested
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(AppError::InvalidInput("Invalid file path".to_string()));
    }

    // 2) 仅允许 .png
    if requested.extension().and_then(|e| e.to_str()).unwrap_or("") != "png" {
        return Err(AppError::InvalidInput("Unsupported file type".to_string()));
    }

    // 3) 计算规范化路径并校验前缀，防止目录穿越
    let base = match tokio::fs::canonicalize(&state.downloads_dir).await {
        Ok(p) => p,
        Err(_) => {
            return Err(AppError::Internal(
                "Downloads directory not available".to_string(),
            ))
        }
    };
    let joined = state.downloads_dir.join(&filename);
    let canon = match tokio::fs::canonicalize(&joined).await {
        Ok(p) => p,
        Err(_) => return Err(AppError::InvalidInput("File not found".to_string())),
    };
    if !canon.starts_with(&base) {
        return Err(AppError::InvalidInput("Invalid file path".to_string()));
    }

    if !canon.exists() {
        return Err(AppError::InvalidInput("File not found".to_string()));
    }

    // 4) 读取并设置安全响应头
    let data = tokio::fs::read(&canon).await?;
    let mime = mime_guess::from_path(&canon)
        .first_or_octet_stream()
        .to_string();
    let safe_name = requested
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download.png");
    let content_disposition = format!("attachment; filename=\"{}\"", safe_name);

    Ok((
        AppendHeaders([
            ("Content-Type", mime),
            ("Content-Disposition", content_disposition),
            ("X-Content-Type-Options", "nosniff".to_string()),
        ]),
        data,
    ))
}

/// Initialize encryption session
pub async fn init_encryption_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<InitEncryptRequest>,
) -> Result<Json<InitEncryptResponse>> {
    validate_csrf(&headers, &jar)?;
    info!(
        "Initializing encryption session, TTL: {} seconds",
        req.ttl_seconds
    );

    // Enforce TTL range on server side
    if req.ttl_seconds < MIN_TTL || req.ttl_seconds > MAX_TTL {
        return Err(AppError::InvalidInput(format!(
            "ttl_seconds must be between {} and {}",
            MIN_TTL, MAX_TTL
        )));
    }

    // Generate random build secret
    let mut build_secret = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut build_secret);

    // Create session
    let mut session = CompilationSession::new(req.ttl_seconds, build_secret);

    // Acquire compile lock (limit concurrent compilations)
    let _lock = state.compile_lock.lock().await;

    // Execute compilation
    compile_with_secret(&mut session, &state.workspaces_dir).await?;

    // Save to database
    state.db.insert_session(&session).await?;

    info!("Session created successfully: {}", session.id);

    Ok(Json(InitEncryptResponse {
        session_id: session.id.clone(),
        compile_id: session.compile_id.clone(),
        expires_at: chrono::DateTime::from_timestamp(session.expires_at, 0)
            .unwrap()
            .to_rfc3339(),
        remaining_seconds: session.remaining_seconds(),
    }))
}

/// Execute encryption
pub async fn encrypt_embed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    mut multipart: Multipart,
) -> Result<Json<EncryptResponse>> {
    validate_csrf(&headers, &jar)?;
    let mut session_id: Option<String> = None;
    let mut message: Option<String> = None;
    let mut carrier_image: Option<Vec<u8>> = None;
    let mut user_key: Option<String> = None;

    // Parse multipart
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::InvalidInput("Invalid multipart form".to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "session_id" => {
                session_id = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| AppError::InvalidInput("Invalid session_id".to_string()))?,
                );
            }
            "message" => {
                message = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| AppError::InvalidInput("Invalid message".to_string()))?,
                );
            }
            "user_key" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| AppError::InvalidInput("Invalid user_key".to_string()))?;
                if !text.is_empty() {
                    user_key = Some(text);
                }
            }
            "carrier_image" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| AppError::InvalidInput("Invalid carrier_image".to_string()))?;
                carrier_image = Some(bytes.to_vec());
            }
            _ => {}
        }
    }

    let session_id = session_id.ok_or(AppError::InvalidInput("Missing session_id".to_string()))?;
    let message = message.ok_or(AppError::InvalidInput("Missing message".to_string()))?;
    let carrier_data =
        carrier_image.ok_or(AppError::InvalidInput("Missing carrier_image".to_string()))?;

    debug!(
        "Encryption request: session={}, message_len={}",
        session_id,
        message.len()
    );

    // Get session
    let session = state
        .db
        .get_session(&session_id)
        .await?
        .ok_or(AppError::SessionNotFound)?;

    if session.is_expired() {
        return Err(AppError::SessionExpired);
    }

    // Parse carrier image
    let carrier_image = image::load_from_memory(&carrier_data)?;
    validate_image_dimensions(&carrier_image)?;

    // Calculate image fingerprint
    let phash = calculate_perceptual_hash(&carrier_image);
    let phash_bytes = hash_to_bytes(&phash);

    // Generate temporary file paths
    let temp_input = state
        .downloads_dir
        .join(format!("input_{}.png", session_id));
    let temp_output = state
        .downloads_dir
        .join(format!("stego_{}.png", session_id));

    // Save carrier image
    carrier_image.save(&temp_input)?;

    // Execute encryption
    run_encrypt(
        &session.binary_path,
        &temp_input,
        &temp_output,
        &message,
        user_key.as_deref(),
    )
    .await?;

    // Save fingerprint
    state
        .db
        .insert_fingerprint(phash_bytes, &session.compile_id)
        .await?;

    // Clean up temporary input file
    tokio::fs::remove_file(&temp_input).await.ok();

    info!("Encryption successful: session={}", session_id);

    Ok(Json(EncryptResponse {
        stego_image_url: format!("/downloads/stego_{}.png", session_id),
        session_id,
        message_size: message.len(),
    }))
}

/// Decryption
pub async fn decrypt_extract(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    mut multipart: Multipart,
) -> Result<Json<DecryptResponse>> {
    validate_csrf(&headers, &jar)?;
    let mut stego_image: Option<Vec<u8>> = None;
    let mut user_key: Option<String> = None;

    // Parse multipart
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::InvalidInput("Invalid multipart form".to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "stego_image" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| AppError::InvalidInput("Invalid stego_image".to_string()))?;
                stego_image = Some(bytes.to_vec());
            }
            "user_key" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| AppError::InvalidInput("Invalid user_key".to_string()))?;
                if !text.is_empty() {
                    user_key = Some(text);
                }
            }
            _ => {}
        }
    }

    let stego_data =
        stego_image.ok_or(AppError::InvalidInput("Missing stego_image".to_string()))?;

    debug!("Decryption request: image_size={}", stego_data.len());

    // Parse stego image
    let stego_image = image::load_from_memory(&stego_data)?;
    validate_image_dimensions(&stego_image)?;

    // Calculate image fingerprint
    let phash = calculate_perceptual_hash(&stego_image);

    // Find matching compilation
    let fingerprints = state.db.get_active_fingerprints().await?;
    let match_result = find_best_match(&phash, &fingerprints, 10)?;

    let (compile_id, distance) = match_result.ok_or(AppError::NoMatchingCompilation)?;

    info!(
        "Found match: compile_id={}, distance={}",
        compile_id, distance
    );

    // Get session
    let session = state
        .db
        .get_session_by_compile_id(&compile_id)
        .await?
        .ok_or(AppError::NoMatchingCompilation)?;

    if session.is_expired() {
        return Err(AppError::SessionExpired);
    }

    // Generate temporary file path
    let temp_stego = state
        .downloads_dir
        .join(format!("decrypt_input_{}.png", session.id));
    stego_image.save(&temp_stego)?;

    // Execute decryption
    let decrypted_data =
        run_decrypt(&session.binary_path, &temp_stego, user_key.as_deref()).await?;

    // Clean up temporary file
    tokio::fs::remove_file(&temp_stego).await.ok();

    // Try to convert to string
    let (message, is_binary) = match String::from_utf8(decrypted_data.clone()) {
        Ok(text) => (text, false),
        Err(_) => {
            use base64::{engine::general_purpose, Engine as _};
            (general_purpose::STANDARD.encode(&decrypted_data), true)
        }
    };

    info!("Decryption successful: compile_id={}", compile_id);

    Ok(Json(DecryptResponse {
        message,
        matched_distance: distance,
        compile_id,
        is_binary,
    }))
}

fn validate_image_dimensions(img: &image::DynamicImage) -> Result<()> {
    let (w, h) = img.dimensions();
    if w > MAX_DIMENSION || h > MAX_DIMENSION {
        return Err(AppError::InvalidInput(
            "Image dimensions too large".to_string(),
        ));
    }
    let pixels = (w as u64) * (h as u64);
    if pixels > MAX_PIXELS {
        return Err(AppError::InvalidInput(
            "Image pixel count too large".to_string(),
        ));
    }
    Ok(())
}

/// Query session status
pub async fn get_session_status(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>> {
    let session = state
        .db
        .get_session(&session_id)
        .await?
        .ok_or(AppError::SessionNotFound)?;

    let session_id = session.id.clone();
    let status = session.status.to_string();
    let expires_at = chrono::DateTime::from_timestamp(session.expires_at, 0)
        .unwrap()
        .to_rfc3339();
    let remaining_seconds = session.remaining_seconds();

    Ok(Json(SessionStatusResponse {
        session_id,
        status,
        expires_at,
        remaining_seconds,
    }))
}

/// Statistics
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Result<Json<StatsResponse>> {
    let (total, active, expired, fingerprints) = state.db.get_stats().await?;

    Ok(Json(StatsResponse {
        total_sessions: total,
        active_sessions: active,
        expired_sessions: expired,
        total_fingerprints: fingerprints,
    }))
}
