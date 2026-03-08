use std::fmt::Write;
use std::sync::Arc;
use tracing::instrument;

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::DomainError;

/// Validates a raw API token against stored hashes.
///
/// On success, updates `last_used_at` and returns the token ID.
pub struct ValidateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl ValidateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    /// Validates the raw token by hashing it and comparing against stored hashes.
    /// Returns `Ok(token_id)` on match, `Err(InvalidCredentials)` otherwise.
    #[instrument(skip(self, raw_token))]
    pub async fn execute(&self, raw_token: &str) -> Result<i64, DomainError> {
        let incoming_hash = hash_token(raw_token);
        let all_hashes = self.repo.get_all_hashes().await?;

        for (id, stored_hash) in &all_hashes {
            if timing_safe_eq(incoming_hash.as_bytes(), stored_hash.as_bytes()) {
                self.repo.update_last_used(*id).await?;
                return Ok(*id);
            }
        }

        Err(DomainError::InvalidCredentials)
    }
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result.as_slice() {
        write!(hex, "{byte:02x}").expect("hex write failed");
    }
    hex
}

/// Constant-time comparison to prevent timing attacks on token validation.
fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
