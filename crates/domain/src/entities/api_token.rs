use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A named API token for machine-to-machine authentication.
///
/// The raw token is shown only once at creation (like GitHub PATs).
/// Only the SHA-256 hash is stored. The `key_prefix` (first 8 chars)
/// helps users identify which token is which.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub key_prefix: Arc<str>,
    pub key_hash: Arc<str>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl ApiToken {
    pub fn new(name: Arc<str>, key_prefix: Arc<str>, key_hash: Arc<str>) -> Self {
        Self {
            id: None,
            name,
            key_prefix,
            key_hash,
            created_at: None,
            last_used_at: None,
        }
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Token name cannot be empty".to_string());
        }
        if name.len() > 100 {
            return Err("Token name cannot exceed 100 characters".to_string());
        }
        let valid = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
        if !valid {
            return Err(
                "Token name can only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }
        Ok(())
    }
}
