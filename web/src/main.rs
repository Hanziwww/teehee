mod api;
mod cleanup;
mod compiler;
mod db;
mod error;
mod image_match;
mod models;
mod state;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
// Timeout handled via ServiceBuilder::timeout to box error type
use axum::error_handling::HandleErrorLayer;
use axum::BoxError;
use std::time::Duration;
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "teehee_web=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🚀 Starting Teehee Web Server");

    // Initialize application state
    let state = Arc::new(AppState::new().await?);

    // Start background cleanup task
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        cleanup::run_cleanup_task(cleanup_state).await;
    });

    // Configure CORS (only enable when ALLOWED_ORIGINS is explicitly set)
    let cors_opt: Option<CorsLayer> = match std::env::var("ALLOWED_ORIGINS") {
        Ok(val) => {
            let list: Vec<HeaderValue> = val
                .split(',')
                .filter_map(|s| HeaderValue::from_str(s.trim()).ok())
                .collect();
            if !list.is_empty() {
                Some(
                    CorsLayer::new()
                        .allow_origin(AllowOrigin::list(list))
                        .allow_methods([Method::GET, Method::POST])
                        .allow_headers([
                            HeaderName::from_static("content-type"),
                            HeaderName::from_static("x-csrf-token"),
                        ]),
                )
            } else {
                None
            }
        }
        Err(_) => None,
    };

    // Build routes
    let app = Router::new()
        // Index page
        .route("/", get(api::serve_index))
        // API endpoints
        .route("/api/encrypt/init", post(api::init_encryption_session))
        .route("/api/encrypt/embed", post(api::encrypt_embed))
        .route("/api/decrypt", post(api::decrypt_extract))
        .route("/api/session/:session_id", get(api::get_session_status))
        .route("/api/stats", get(api::get_stats))
        // Static resources
        .route("/static/*path", get(api::serve_static))
        .route("/downloads/*file", get(api::serve_download))
        // Middleware
        // CORS (only if explicitly configured)
        .layer(cors_opt.unwrap_or_else(|| {
            // If not configured, apply a no-op CORS layer by allowing no external origins.
            // Same-origin requests不受影响，跨域将被默认拒绝（不返回 CORS 头）。
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(Vec::new()))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    HeaderName::from_static("content-type"),
                    HeaderName::from_static("x-csrf-token"),
                ])
        }))
        // Request body size limit (e.g., 20 MB)
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024))
        // Global concurrency guard
        .layer(GlobalConcurrencyLimitLayer::new(128))
        // Rate limit layer removed due to Clone bound; can reintroduce with a tower-compatible limiter wrapper
        // Global request timeout with error handling mapped to responses
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|err: BoxError| async move {
                    if err.is::<tower::timeout::error::Elapsed>() {
                        (StatusCode::REQUEST_TIMEOUT, "Request timed out")
                    } else {
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                    }
                }))
                .timeout(Duration::from_secs(120)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        // Shared state
        .with_state(state);

    // Listen address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("🌐 Server running at http://{}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
