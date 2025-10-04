use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Compilation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationSession {
    pub id: String,
    pub compile_id: String,
    pub binary_path: String,
    pub workspace_path: String,
    pub build_secret: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Expired,
    Deleted,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "active"),
            SessionStatus::Expired => write!(f, "expired"),
            SessionStatus::Deleted => write!(f, "deleted"),
        }
    }
}

/// Image fingerprint record
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ImageFingerprint {
    pub id: i64,
    pub phash: Vec<u8>,
    pub compile_id: String,
    pub created_at: i64,
}

/// Encryption initialization request
#[derive(Debug, Deserialize)]
pub struct InitEncryptRequest {
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i64, // Time-to-live (seconds)
}

fn default_ttl() -> i64 {
    3600 // Default 1 hour
}

/// Encryption initialization response
#[derive(Debug, Serialize)]
pub struct InitEncryptResponse {
    pub session_id: String,
    pub compile_id: String,
    pub expires_at: String,
    pub remaining_seconds: i64,
}

/// Encryption response
#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub stego_image_url: String,
    pub session_id: String,
    pub message_size: usize,
}

/// Decryption response
#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub message: String,
    pub matched_distance: u32,
    pub compile_id: String,
    pub is_binary: bool,
}

/// Session status response
#[derive(Debug, Serialize)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub status: String,
    pub expires_at: String,
    pub remaining_seconds: i64,
}

/// Statistics
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub expired_sessions: i64,
    pub total_fingerprints: i64,
}

impl CompilationSession {
    pub fn new(ttl_seconds: i64, build_secret: Vec<u8>) -> Self {
        let now = chrono::Utc::now().timestamp();
        let id = Uuid::new_v4().to_string();
        let compile_id = format!("compile_{}", &id[..8]);

        Self {
            id: id.clone(),
            compile_id: compile_id.clone(),
            binary_path: String::new(),
            workspace_path: String::new(),
            build_secret,
            created_at: now,
            expires_at: now + ttl_seconds,
            status: SessionStatus::Active,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.expires_at
    }

    pub fn remaining_seconds(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.expires_at - now).max(0)
    }
}
