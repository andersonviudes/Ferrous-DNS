use serde::{Deserialize, Serialize};

/// Database configuration for query logging
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Path to SQLite database file (default: "./ferrous-dns.db")
    #[serde(default = "default_db_path")]
    pub path: String,

    /// Enable query logging to database (default: true)
    #[serde(default = "default_true")]
    pub log_queries: bool,

    /// Number of days to keep query logs (default: 30)
    #[serde(default = "default_queries_log_stored")]
    pub queries_log_stored: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            log_queries: true,
            queries_log_stored: default_queries_log_stored(),
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
