use crate::error::Result;
use crate::models::{CompilationSession, ImageFingerprint, SessionStatus};
use sqlx::{sqlite::SqlitePool, Row};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;

        // SQLite safety/reliability PRAGMAs
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 5000;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA journal_mode = WAL;")
            .execute(&pool)
            .await?;

        // Online migration: drop legacy build_secret column if present
        // 1) Detect column
        let rows = sqlx::query("PRAGMA table_info('compilations')")
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

        let has_compilations = !rows.is_empty();
        let has_build_secret = rows.iter().any(|row| {
            row.try_get::<String, _>("name")
                .map(|name| name == "build_secret")
                .unwrap_or(false)
        });

        // Initialize database tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS compilations (
                id TEXT PRIMARY KEY,
                compile_id TEXT NOT NULL UNIQUE,
                binary_path TEXT NOT NULL,
                workspace_path TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS image_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phash BLOB NOT NULL,
                compile_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (compile_id) REFERENCES compilations(compile_id)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // If legacy column exists, rebuild table without it
        if has_compilations && has_build_secret {
            // Use a transaction to be safe
            let mut tx = pool.begin().await?;

            // Temporarily disable foreign keys to allow table drop
            sqlx::query("PRAGMA foreign_keys = OFF;")
                .execute(&mut *tx)
                .await?;

            // Create new table without build_secret
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS compilations_new (
                    id TEXT PRIMARY KEY,
                    compile_id TEXT NOT NULL UNIQUE,
                    binary_path TEXT NOT NULL,
                    workspace_path TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                )
                "#,
            )
            .execute(&mut *tx)
            .await?;

            // Copy data
            sqlx::query(
                r#"
                INSERT INTO compilations_new (id, compile_id, binary_path, workspace_path, created_at, expires_at, status)
                SELECT id, compile_id, binary_path, workspace_path, created_at, expires_at, status FROM compilations
                "#,
            )
            .execute(&mut *tx)
            .await?;

            // Drop old table and rename
            sqlx::query("DROP TABLE compilations")
                .execute(&mut *tx)
                .await?;
            sqlx::query("ALTER TABLE compilations_new RENAME TO compilations")
                .execute(&mut *tx)
                .await?;

            // Re-enable foreign keys
            sqlx::query("PRAGMA foreign_keys = ON;")
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;
        }

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_expires ON compilations(expires_at)")
            .execute(&pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_status ON compilations(status)")
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    // Insert compilation session
    pub async fn insert_session(&self, session: &CompilationSession) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO compilations (id, compile_id, binary_path, workspace_path, created_at, expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&session.id)
        .bind(&session.compile_id)
        .bind(&session.binary_path)
        .bind(&session.workspace_path)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.status.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Get session
    pub async fn get_session(&self, session_id: &str) -> Result<Option<CompilationSession>> {
        let row = sqlx::query(
            r#"
            SELECT id, compile_id, binary_path, workspace_path, created_at, expires_at, status
            FROM compilations
            WHERE id = ?
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| CompilationSession {
            id: r.get("id"),
            compile_id: r.get("compile_id"),
            binary_path: r.get("binary_path"),
            workspace_path: r.get("workspace_path"),
            build_secret: Vec::new(),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            status: match r.get::<String, _>("status").as_str() {
                "expired" => SessionStatus::Expired,
                "deleted" => SessionStatus::Deleted,
                _ => SessionStatus::Active,
            },
        }))
    }

    // Get session by compile_id
    pub async fn get_session_by_compile_id(
        &self,
        compile_id: &str,
    ) -> Result<Option<CompilationSession>> {
        let row = sqlx::query(
            r#"
            SELECT id, compile_id, binary_path, workspace_path, created_at, expires_at, status
            FROM compilations
            WHERE compile_id = ?
            "#,
        )
        .bind(compile_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| CompilationSession {
            id: r.get("id"),
            compile_id: r.get("compile_id"),
            binary_path: r.get("binary_path"),
            workspace_path: r.get("workspace_path"),
            build_secret: Vec::new(),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            status: match r.get::<String, _>("status").as_str() {
                "expired" => SessionStatus::Expired,
                "deleted" => SessionStatus::Deleted,
                _ => SessionStatus::Active,
            },
        }))
    }

    // Update session paths
    #[allow(dead_code)]
    pub async fn update_session_paths(
        &self,
        session_id: &str,
        binary_path: &str,
        workspace_path: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE compilations
            SET binary_path = ?, workspace_path = ?
            WHERE id = ?
            "#,
        )
        .bind(binary_path)
        .bind(workspace_path)
        .bind(session_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Insert image fingerprint
    pub async fn insert_fingerprint(&self, phash: Vec<u8>, compile_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            r#"
            INSERT INTO image_fingerprints (phash, compile_id, created_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(phash)
        .bind(compile_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Get all active fingerprints
    pub async fn get_active_fingerprints(&self) -> Result<Vec<ImageFingerprint>> {
        let rows = sqlx::query(
            r#"
            SELECT f.id, f.phash, f.compile_id, f.created_at
            FROM image_fingerprints f
            INNER JOIN compilations c ON f.compile_id = c.compile_id
            WHERE c.status = 'active' AND c.expires_at > ?
            "#,
        )
        .bind(chrono::Utc::now().timestamp())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ImageFingerprint {
                id: r.get("id"),
                phash: r.get("phash"),
                compile_id: r.get("compile_id"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    // Get expired sessions
    pub async fn get_expired_sessions(&self) -> Result<Vec<CompilationSession>> {
        let now = chrono::Utc::now().timestamp();

        let rows = sqlx::query(
            r#"
            SELECT id, compile_id, binary_path, workspace_path, created_at, expires_at, status
            FROM compilations
            WHERE expires_at <= ? AND status = 'active'
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| CompilationSession {
                id: r.get("id"),
                compile_id: r.get("compile_id"),
                binary_path: r.get("binary_path"),
                workspace_path: r.get("workspace_path"),
                build_secret: Vec::new(),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                status: SessionStatus::Active,
            })
            .collect())
    }

    // Mark session as deleted
    pub async fn mark_as_deleted(&self, session_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE compilations
            SET status = 'deleted'
            WHERE id = ?
            "#,
        )
        .bind(session_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Statistics
    pub async fn get_stats(&self) -> Result<(i64, i64, i64, i64)> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM compilations")
            .fetch_one(&self.pool)
            .await?;

        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compilations WHERE status = 'active' AND expires_at > ?",
        )
        .bind(chrono::Utc::now().timestamp())
        .fetch_one(&self.pool)
        .await?;

        let expired: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compilations WHERE status = 'expired' OR expires_at <= ?",
        )
        .bind(chrono::Utc::now().timestamp())
        .fetch_one(&self.pool)
        .await?;

        let fingerprints: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM image_fingerprints")
            .fetch_one(&self.pool)
            .await?;

        Ok((total, active, expired, fingerprints))
    }
}
