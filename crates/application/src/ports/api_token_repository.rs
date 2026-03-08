use async_trait::async_trait;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Port for managing named API tokens in persistent storage.
///
/// Tokens are stored as SHA-256 hashes — the raw token is returned only
/// once at creation time and never persisted.
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    /// Store a new token (name + hash + prefix). Returns the persisted entity.
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiToken, DomainError>;

    /// List all tokens (without raw keys — only prefix and metadata).
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError>;

    /// Find a token by database ID.
    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError>;

    /// Find a token by name (for duplicate detection).
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError>;

    /// Delete a token by ID (revocation).
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Update the `last_used_at` timestamp when a token is used for auth.
    async fn update_last_used(&self, id: i64) -> Result<(), DomainError>;

    /// Get all token hashes for validation lookup.
    /// Returns `(id, key_hash)` pairs for efficient matching.
    async fn get_all_hashes(&self) -> Result<Vec<(i64, String)>, DomainError>;
}
