use std::fmt::Write;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};
use ring::rand::SecureRandom;

/// Response returned when a new API token is created.
/// The raw token is included only in this response — never again.
pub struct CreatedApiToken {
    pub token: ApiToken,
    pub raw_token: String,
}

/// Creates a named API token. The raw token is returned once and never stored.
pub struct CreateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl CreateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, name: &str) -> Result<CreatedApiToken, DomainError> {
        ApiToken::validate_name(name).map_err(DomainError::ConfigError)?;

        if self.repo.get_by_name(name).await?.is_some() {
            return Err(DomainError::DuplicateApiTokenName(name.to_string()));
        }

        let raw_token = generate_token();
        let key_prefix = &raw_token[..8];
        let key_hash = hash_token(&raw_token);

        let token = self.repo.create(name, key_prefix, &key_hash).await?;

        info!(name = name, "API token created");
        Ok(CreatedApiToken { token, raw_token })
    }
}

fn generate_token() -> String {
    let mut buf = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("CSPRNG fill failed");
    let mut hex = String::with_capacity(64);
    for byte in &buf {
        write!(hex, "{byte:02x}").expect("hex write failed");
    }
    hex
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
