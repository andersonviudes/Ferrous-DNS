use std::sync::Arc;
use tracing::{info, instrument, warn};

use crate::ports::{PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError};

/// Authenticates a user and creates a browser session.
pub struct LoginUseCase {
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    auth_config: Arc<AuthConfig>,
}

impl LoginUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            user_provider,
            session_repo,
            password_hasher,
            auth_config,
        }
    }

    /// Authenticate with username + password and create a session.
    ///
    /// Returns the created `AuthSession` with a CSPRNG session ID.
    /// The caller is responsible for setting the `Set-Cookie` header.
    #[instrument(skip(self, password))]
    pub async fn execute(
        &self,
        username: &str,
        password: &str,
        remember_me: bool,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AuthSession, DomainError> {
        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        if !user.enabled {
            return Err(DomainError::InvalidCredentials);
        }

        let valid = self.password_hasher.verify(password, &user.password_hash)?;

        if !valid {
            warn!(username = username, "Failed login attempt");
            return Err(DomainError::InvalidCredentials);
        }

        let session_id = generate_session_id();
        let expires_at = compute_expiry(remember_me, &self.auth_config);

        let session = AuthSession::new(
            Arc::from(session_id.as_str()),
            user.username.clone(),
            Arc::from(user.role.as_str()),
            Arc::from(ip_address),
            Arc::from(user_agent),
            remember_me,
            expires_at,
        );

        self.session_repo.create(&session).await?;

        info!(
            username = username,
            remember_me = remember_me,
            "User logged in"
        );
        Ok(session)
    }
}

fn generate_session_id() -> String {
    use std::fmt::Write;
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

fn compute_expiry(remember_me: bool, config: &AuthConfig) -> String {
    let duration = if remember_me {
        chrono::Duration::days(i64::from(config.remember_me_days))
    } else {
        chrono::Duration::hours(i64::from(config.session_ttl_hours))
    };
    let expires = chrono::Utc::now() + duration;
    expires.format("%Y-%m-%d %H:%M:%S").to_string()
}

use ring::rand::SecureRandom;
