use crate::state::AppState;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

/// Background cleanup task
///
/// Periodically scans and cleans up expired compilation sessions:
/// 1. Delete workspace directories (including binaries)
/// 2. Delete related files in downloads directory
/// 3. Mark database records as deleted
pub async fn run_cleanup_task(state: Arc<AppState>) {
    info!("🧹 Starting background cleanup task");

    loop {
        // Run cleanup every 5 minutes
        sleep(Duration::from_secs(60)).await;

        if let Err(e) = cleanup_expired_sessions(&state).await {
            error!("Cleanup task failed: {}", e);
        }
    }
}

async fn cleanup_expired_sessions(state: &AppState) -> anyhow::Result<()> {
    let expired_sessions = state.db.get_expired_sessions().await?;

    if expired_sessions.is_empty() {
        return Ok(());
    }

    info!(
        "Found {} expired sessions, starting cleanup",
        expired_sessions.len()
    );

    for session in expired_sessions {
        let session_id = &session.id;
        let mut cleaned_items = Vec::new();

        // 1. Delete workspace directory
        if let Err(e) = tokio::fs::remove_dir_all(&session.workspace_path).await {
            error!(
                "Failed to delete workspace {}: {}",
                session.workspace_path, e
            );
        } else {
            info!("Deleted workspace: {}", session.workspace_path);
            cleaned_items.push("workspace");
        }

        // 2. Delete related files in downloads directory
        let download_patterns = vec![
            format!("input_{}.png", session_id),
            format!("stego_{}.png", session_id),
            format!("decrypt_input_{}.png", session_id),
        ];

        for filename in download_patterns {
            let file_path = state.downloads_dir.join(&filename);
            if file_path.exists() {
                if let Err(e) = tokio::fs::remove_file(&file_path).await {
                    error!("Failed to delete download file {}: {}", filename, e);
                } else {
                    info!("Deleted download file: {}", filename);
                    cleaned_items.push("download file");
                }
            }
        }

        // 3. Mark as deleted
        if let Err(e) = state.db.mark_as_deleted(&session.id).await {
            error!("Failed to mark session as deleted {}: {}", session.id, e);
        } else {
            cleaned_items.push("database record");
        }

        info!(
            "✅ Cleaned up session: {} (cleaned items: {})",
            session.compile_id,
            cleaned_items.join(", ")
        );
    }

    Ok(())
}
