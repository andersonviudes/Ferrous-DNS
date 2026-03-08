use std::sync::Arc;
use tracing::instrument;

use crate::ports::SessionRepository;
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError};

/// Returns authentication status info (no auth required to call).
pub struct GetAuthStatusUseCase {
    auth_config: Arc<AuthConfig>,
}

impl GetAuthStatusUseCase {
    pub fn new(auth_config: Arc<AuthConfig>) -> Self {
        Self { auth_config }
    }

    #[instrument(skip(self))]
    pub fn execute(&self) -> AuthStatus {
        let password_configured = self
            .auth_config
            .admin
            .password_hash
            .as_ref()
            .map(|h| !h.is_empty())
            .unwrap_or(false);

        AuthStatus {
            auth_enabled: self.auth_config.enabled,
            password_configured,
        }
    }
}

/// Auth status returned to the frontend for login/setup flow.
#[derive(Debug, Clone)]
pub struct AuthStatus {
    pub auth_enabled: bool,
    pub password_configured: bool,
}

/// Lists all active (non-expired) browser sessions.
pub struct GetActiveSessionsUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl GetActiveSessionsUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<Vec<AuthSession>, DomainError> {
        self.session_repo.get_all_active().await
    }
}
