use ferrous_dns_domain::config::DatabaseConfig;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

/// Build base connection options shared by both pools.
fn base_options(database_url: &str) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url).map(|o| {
        o.create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
    })
}

/// Apply per-connection PRAGMAs that improve performance for both reads and writes.
async fn apply_pragmas(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA cache_size = -65536")
        .execute(pool)
        .await?;
    sqlx::query("PRAGMA mmap_size = 268435456")
        .execute(pool)
        .await?;
    sqlx::query("PRAGMA temp_store = MEMORY")
        .execute(pool)
        .await?;
    Ok(())
}

/// Create the **write pool** (used by background flush tasks and admin CRUD).
///
/// This pool:
/// - Runs all pending migrations on startup.
/// - Sets `wal_autocheckpoint` to reduce checkpoint frequency under high write load.
/// - Uses a long `busy_timeout` to avoid `SQLITE_BUSY` errors during write bursts.
/// - Is intentionally small (2–4 connections) because SQLite WAL serialises
///   writers at the file level; more connections only increase contention.
pub async fn create_write_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let options =
        base_options(database_url)?.busy_timeout(Duration::from_secs(cfg.write_busy_timeout_secs));

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.write_pool_max_connections)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(cfg.write_busy_timeout_secs))
        .connect_with(options)
        .await?;

    apply_pragmas(&pool).await?;

    sqlx::query(&format!(
        "PRAGMA wal_autocheckpoint = {}",
        cfg.wal_autocheckpoint
    ))
    .execute(&pool)
    .await?;

    // Migrations run once on the write pool only.
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&pool).await?;

    // Refresh query-planner statistics so new indexes are used optimally
    // from the first query.
    sqlx::query("PRAGMA optimize").execute(&pool).await?;

    Ok(pool)
}

/// Create the **read pool** (used by dashboard stats and API list endpoints).
///
/// SQLite WAL allows multiple concurrent readers while a writer holds an
/// exclusive lock.  Dedicating a separate pool to reads ensures that the
/// background query-log flush task never starves dashboard requests for
/// connection slots.
pub async fn create_read_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let options = base_options(database_url)?.busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.read_pool_max_connections)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;

    apply_pragmas(&pool).await?;

    Ok(pool)
}

/// Convenience wrapper kept for backward-compatibility with tests that still
/// call `create_pool` directly.  Production code should use the split-pool
/// functions above.
pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let cfg = DatabaseConfig::default();
    create_write_pool(database_url, &cfg).await
}
