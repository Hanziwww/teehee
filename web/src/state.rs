use crate::db::Database;
use crate::error::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState {
    pub db: Arc<Database>,
    pub workspaces_dir: PathBuf,
    pub downloads_dir: PathBuf,
    pub compile_lock: Arc<Mutex<()>>, // Limit concurrent compilations
}

impl AppState {
    pub async fn new() -> Result<Self> {
        // Create necessary directories
        let workspaces_dir = PathBuf::from("workspaces");
        let downloads_dir = PathBuf::from("downloads");
        let data_dir = PathBuf::from("data");
        let static_dir = PathBuf::from("static");

        tokio::fs::create_dir_all(&workspaces_dir).await?;
        tokio::fs::create_dir_all(&downloads_dir).await?;
        tokio::fs::create_dir_all(&data_dir).await?;
        tokio::fs::create_dir_all(&static_dir).await.ok();

        // Initialize database (placed in data directory)
        let db_path = data_dir.join("teehee.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let db = Arc::new(Database::new(&db_url).await?);

        Ok(Self {
            db,
            workspaces_dir,
            downloads_dir,
            compile_lock: Arc::new(Mutex::new(())),
        })
    }
}
