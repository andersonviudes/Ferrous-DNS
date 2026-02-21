use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,

    #[serde(default = "default_true")]
    pub log_queries: bool,

    #[serde(default = "default_queries_log_stored")]
    pub queries_log_stored: u32,

    /// Minimum seconds between consecutive `update_last_seen` DB writes for
    /// the same client IP. Lower values increase write pressure on SQLite;
    /// higher values reduce it at the cost of less-frequent last-seen updates.
    /// Default: 60 seconds.
    #[serde(default = "default_client_tracking_interval")]
    pub client_tracking_interval: u64,

    // ── Query-log write tuning ────────────────────────────────────────────────
    /// Capacity of the async mpsc channel that buffers query-log entries before
    /// the background flush task writes them to SQLite.
    /// At 100 k q/s with sample_rate = 10 the channel fills at 10 k entries/s;
    /// a capacity of 200 000 gives ~20 s of headroom before entries are dropped.
    /// Default: 10 000.
    #[serde(default = "default_query_log_channel_capacity")]
    pub query_log_channel_capacity: usize,

    /// Maximum number of rows committed in a single INSERT transaction.
    /// Larger values reduce transaction overhead at the cost of higher latency
    /// before entries appear in the DB.  Default: 500.
    #[serde(default = "default_query_log_max_batch_size")]
    pub query_log_max_batch_size: usize,

    /// Interval in milliseconds between flush-timer ticks in the log-writer task.
    /// Controls the maximum latency of a log entry appearing in the DB when the
    /// batch has not yet reached `query_log_max_batch_size`.  Default: 100.
    #[serde(default = "default_query_log_flush_interval_ms")]
    pub query_log_flush_interval_ms: u64,

    /// Log 1 out of every N queries (1 = log all, 10 = 10 %, 50 = 2 %).
    /// Sampling is uniform so statistical accuracy is preserved.
    /// At 100 k q/s a value of 10 logs 10 k entries/s; a value of 50 logs 2 k/s.
    /// Default: 1 (log every query).
    #[serde(default = "default_query_log_sample_rate")]
    pub query_log_sample_rate: u32,

    /// Capacity of the async mpsc channel used by the client-tracking background
    /// task.  Default: 4 096.
    #[serde(default = "default_client_channel_capacity")]
    pub client_channel_capacity: usize,

    // ── Connection-pool tuning ────────────────────────────────────────────────
    /// Maximum connections in the write pool (background flush + admin CRUD).
    /// SQLite WAL serialises writers at the file level, so more than 3–4
    /// connections do not increase write throughput.  Default: 3.
    #[serde(default = "default_write_pool_max_connections")]
    pub write_pool_max_connections: u32,

    /// Maximum connections in the read pool (dashboard stats, query log, API).
    /// WAL allows concurrent readers, so a higher value improves dashboard
    /// responsiveness under concurrent requests.  Default: 8.
    #[serde(default = "default_read_pool_max_connections")]
    pub read_pool_max_connections: u32,

    /// Seconds the write pool will wait for a database lock before returning
    /// `SQLITE_BUSY`.  Increase to avoid errors during write bursts.
    /// Default: 30.
    #[serde(default = "default_write_busy_timeout_secs")]
    pub write_busy_timeout_secs: u64,

    /// Number of WAL pages that trigger an automatic checkpoint.
    /// SQLite default is 1 000 (4 MB at 4 096-byte pages).  Under high write
    /// load a larger value reduces checkpoint frequency.  Default: 10 000.
    #[serde(default = "default_wal_autocheckpoint")]
    pub wal_autocheckpoint: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            log_queries: true,
            queries_log_stored: default_queries_log_stored(),
            client_tracking_interval: default_client_tracking_interval(),
            query_log_channel_capacity: default_query_log_channel_capacity(),
            query_log_max_batch_size: default_query_log_max_batch_size(),
            query_log_flush_interval_ms: default_query_log_flush_interval_ms(),
            query_log_sample_rate: default_query_log_sample_rate(),
            client_channel_capacity: default_client_channel_capacity(),
            write_pool_max_connections: default_write_pool_max_connections(),
            read_pool_max_connections: default_read_pool_max_connections(),
            write_busy_timeout_secs: default_write_busy_timeout_secs(),
            wal_autocheckpoint: default_wal_autocheckpoint(),
        }
    }
}

fn default_db_path() -> String {
    "./ferrous-dns.db".to_string()
}

fn default_true() -> bool {
    true
}

fn default_queries_log_stored() -> u32 {
    30
}

fn default_client_tracking_interval() -> u64 {
    60
}

fn default_query_log_channel_capacity() -> usize {
    10_000
}

fn default_query_log_max_batch_size() -> usize {
    500
}

fn default_query_log_flush_interval_ms() -> u64 {
    100
}

fn default_query_log_sample_rate() -> u32 {
    1
}

fn default_client_channel_capacity() -> usize {
    4_096
}

fn default_write_pool_max_connections() -> u32 {
    3
}

fn default_read_pool_max_connections() -> u32 {
    8
}

fn default_write_busy_timeout_secs() -> u64 {
    30
}

fn default_wal_autocheckpoint() -> u32 {
    10_000
}
