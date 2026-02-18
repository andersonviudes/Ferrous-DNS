use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        // WAL mode: readers and writers don't block each other
        .journal_mode(SqliteJournalMode::Wal)
        // NORMAL sync: 3x faster than FULL, safe with WAL
        .synchronous(SqliteSynchronous::Normal)
        // Avoid SQLITE_BUSY errors under concurrent load
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        // Increased from 5 → 16 to handle concurrent query log writes
        .max_connections(16)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;

    // Per-connection performance PRAGMAs (applied after pool creation)
    // 64MB page cache in memory — reduces disk reads for hot data
    sqlx::query("PRAGMA cache_size = -65536")
        .execute(&pool)
        .await?;
    // 256MB memory-mapped I/O — sequential reads without syscall overhead
    sqlx::query("PRAGMA mmap_size = 268435456")
        .execute(&pool)
        .await?;
    // Store temp tables and indices in memory
    sqlx::query("PRAGMA temp_store = MEMORY")
        .execute(&pool)
        .await?;

    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&pool).await?;

    Ok(pool)
}
